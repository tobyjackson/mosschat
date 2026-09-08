//! WO-1.3b integration tests, the cases that need a live QUIC connection
//! rather than a hand-built buffer. Every test lives under `mod punch` so
//! `cargo test -p mosschat-net punch::` (the work order's own verify line)
//! catches this file alongside the unit tests nested under `punch::` inside
//! the library.

#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod punch {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use mosschat_net::authed;
    use mosschat_net::gate::wire::decode_relay;
    use mosschat_net::sock::{PorchSocket, synthetic_addr};
    use quinn::AsyncUdpSocket;
    use quinn::udp::Transmit;

    /// A live QUIC connection standing in for the gate, with the far end
    /// returned so a test can read the `Relay` datagrams that arrive on it.
    struct GateStandIn {
        near: quinn::Connection,
        far: quinn::Connection,
        _endpoints: (quinn::Endpoint, quinn::Endpoint),
    }

    async fn gate_stand_in() -> GateStandIn {
        authed::install_crypto_provider();
        let server_seed = [1u8; 32];
        let client_seed = [2u8; 32];

        let (server_cert, server_key) = authed::self_signed_cert(&server_seed).unwrap();
        let server_tls = authed::server_tls_config(server_cert, server_key, b"moss-gate").unwrap();
        let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let (client_cert, client_key) = authed::self_signed_cert(&client_seed).unwrap();
        let client_tls = authed::client_tls_config(client_cert, client_key, b"moss-gate").unwrap();
        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client)));

        let accept = tokio::spawn(async move {
            let incoming = server.accept().await.expect("an incoming connection");
            let connection = incoming.await.unwrap();
            (server, connection)
        });
        let near = client.connect(server_addr, "gate").unwrap().await.unwrap();
        let (server, far) = accept.await.unwrap();
        GateStandIn {
            near,
            far,
            _endpoints: (client, server),
        }
    }

    fn porch_socket() -> Arc<PorchSocket> {
        let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        std_socket.set_nonblocking(true).unwrap();
        PorchSocket::new(std_socket).unwrap()
    }

    async fn wait_writable(socket: &Arc<PorchSocket>) {
        let mut poller = Arc::clone(socket).create_io_poller();
        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
            .await
            .unwrap();
    }

    /// Section 3's splitting rule, "written out because the failure is
    /// silent": one GSO `Transmit` of three 1200 byte segments leaves as
    /// three `Relay` datagrams of 1205 bytes, in order, never one 3605 byte
    /// payload.
    ///
    /// Deliberate break to fail this test: in `sock.rs::try_send`, change
    /// `transmit.segment_size.unwrap_or(transmit.contents.len())` to
    /// `transmit.contents.len()`, ignoring `segment_size` the way the code
    /// did before Konrad's must 1. The single 3600 byte payload then fails
    /// `encode_relay`'s 1200 byte cap and `try_send` returns an error
    /// instead of sending anything.
    #[tokio::test]
    async fn one_gso_transmit_of_three_segments_relays_as_three_relay_datagrams() {
        let gate = gate_stand_in().await;
        let socket = porch_socket();
        let synthetic = synthetic_addr([1, 2, 3, 4, 5], &[9u8; 32]);
        socket.register_relay_session(4242, synthetic);
        socket.attach_gate(gate.near.clone());

        // The relay's payload cap is 1200 bytes, so a 1205 byte datagram
        // is what a full segment costs; MTU discovery has to have reached
        // that before three of them can go out at all.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while gate.near.max_datagram_size().unwrap_or(0) < 1205
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            gate.near.max_datagram_size().unwrap_or(0) >= 1205,
            "the stand-in gate path never reached the 1205 the relay needs"
        );

        let segment = 1200usize;
        let contents: Vec<u8> = (0..segment * 3).map(|i| (i % 251) as u8).collect();
        wait_writable(&socket).await;
        socket
            .try_send(&Transmit {
                destination: synthetic,
                ecn: None,
                contents: &contents,
                segment_size: Some(segment),
                src_ip: None,
            })
            .unwrap();

        let mut payloads: Vec<Vec<u8>> = Vec::new();
        for index in 0..3 {
            let datagram = tokio::time::timeout(Duration::from_secs(10), gate.far.read_datagram())
                .await
                .unwrap_or_else(|_| panic!("relay datagram {index} never arrived"))
                .unwrap();
            assert_eq!(
                datagram.len(),
                1205,
                "each segment is its own 1200 byte payload behind a 5 byte Relay header"
            );
            let (session, payload) = decode_relay(&datagram).unwrap();
            assert_eq!(session, 4242);
            payloads.push(payload.to_vec());
        }

        assert_eq!(payloads.concat(), contents, "in order and byte for byte");
        assert!(
            tokio::time::timeout(Duration::from_millis(250), gate.far.read_datagram())
                .await
                .is_err(),
            "three segments are exactly three datagrams, not four"
        );
    }

    /// A single-segment transmit is still one `Relay` datagram, which is
    /// the other half of the splitting rule: `segment_size: None` relays
    /// `contents` whole.
    #[tokio::test]
    async fn a_transmit_with_no_segment_size_relays_as_one_datagram() {
        let gate = gate_stand_in().await;
        let socket = porch_socket();
        let synthetic: SocketAddr = synthetic_addr([9, 8, 7, 6, 5], &[3u8; 32]);
        socket.register_relay_session(7, synthetic);
        socket.attach_gate(gate.near.clone());

        let contents = vec![0x5Au8; 900];
        wait_writable(&socket).await;
        socket
            .try_send(&Transmit {
                destination: synthetic,
                ecn: None,
                contents: &contents,
                segment_size: None,
                src_ip: None,
            })
            .unwrap();

        let datagram = tokio::time::timeout(Duration::from_secs(10), gate.far.read_datagram())
            .await
            .expect("the relayed datagram never arrived")
            .unwrap();
        let (session, payload) = decode_relay(&datagram).unwrap();
        assert_eq!(session, 7);
        assert_eq!(payload, &contents[..]);
    }
}
