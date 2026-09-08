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

    // ------------------------------------------------------------------
    // The doorbell end to end (section 2 steps 2 to 7, over a real gate,
    // two real houses and a real porch stream)
    // ------------------------------------------------------------------

    use mosschat_net::gate::MemberList;
    use mosschat_net::gate::client::{GateClient, InMemoryFriendStore, InMemoryInviteStore};
    use mosschat_net::gate::server::{GateServer, GateServerConfig};
    use mosschat_net::punch::{DoorbellControl, DoorbellParams, run_doorbell};
    use rand::RngExt;

    fn random_seed() -> [u8; 32] {
        rand::rng().random()
    }

    fn public_key_of(seed: &[u8; 32]) -> [u8; 32] {
        mosschat_core::identity::AuthorKey::from_bytes(seed).public_bytes()
    }

    /// The transport config every peer connection uses (section 3): MTU
    /// pinned at 1200 with discovery off, and the epoch-resetting
    /// congestion factory, plus this harness's own idle-timeout headroom.
    fn peer_transport_config(
        epoch: Arc<std::sync::atomic::AtomicU64>,
    ) -> Arc<quinn::TransportConfig> {
        let mut transport = mosschat_net::path::peer_transport_config(epoch);
        let mutable = Arc::get_mut(&mut transport).unwrap();
        mutable.max_idle_timeout(Some(Duration::from_secs(120).try_into().unwrap()));
        transport
    }

    /// The address a house's peer actually reaches it at in this test: the
    /// porch socket binds IPv6-unspecified and dual-stack, so the
    /// candidate it offers is its real port on loopback rather than the
    /// unspecified address `local_addr` reports.
    fn loopback_candidate(client: &GateClient) -> SocketAddr {
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            client.porch().local_addr().unwrap().port(),
        )
    }

    /// Section 8's WO-1.3b case, over the real stream: the doorbell opens
    /// relayed from the first packet, upgrades to a direct path once a
    /// candidate has proved itself by the stated count, and falls back to
    /// the relay when that path is killed, with the end to end connection
    /// surviving all three.
    ///
    /// The kill is the peer no longer answering probes and dropping its own
    /// side of the direct path, which is exactly what a dead path looks
    /// like from the other end, and is the only honest way to kill one
    /// in process.
    ///
    /// Deliberate break to fail this test: in `punch.rs::run_doorbell`,
    /// change `if live_misses >= LIVE_PROBES_TO_STALE` to `if false`. The
    /// upgrade and the relayed phases still pass; the fall-back assertion
    /// times out with the path still `Direct`.
    #[tokio::test]
    async fn the_doorbell_starts_relayed_upgrades_on_proof_and_falls_back_when_the_path_dies() {
        let community = random_seed();
        let alice_seed = random_seed();
        let bob_seed = random_seed();
        let alice_key = public_key_of(&alice_seed);
        let bob_key = public_key_of(&bob_seed);

        let gate = GateServer::bind(GateServerConfig {
            community,
            identity_seed: random_seed(),
            members: MemberList::from_keys([alice_key, bob_key]),
            primary_bind: "127.0.0.1:0".parse().unwrap(),
            secondary_bind: "127.0.0.1:0".parse().unwrap(),
            max_registrations: 256,
        })
        .unwrap();

        let alice_friends = Arc::new(InMemoryFriendStore::new());
        let bob_friends = Arc::new(InMemoryFriendStore::new());
        alice_friends.add(bob_key);
        bob_friends.add(alice_key);

        let alice = Arc::new(
            GateClient::connect(
                gate.primary_addr(),
                alice_seed,
                community,
                None,
                alice_friends,
                Arc::new(InMemoryInviteStore::new()),
            )
            .await
            .unwrap(),
        );
        let bob = Arc::new(
            GateClient::connect(
                gate.primary_addr(),
                bob_seed,
                community,
                None,
                bob_friends,
                Arc::new(InMemoryInviteStore::new()),
            )
            .await
            .unwrap(),
        );

        let outcome = alice.introduce(bob_key, 30, None).await.unwrap();
        assert_eq!(outcome.role, 1);
        // The responder registers its relay route from the `Introduction`
        // its reader loop receives, which races the dial by a hair.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Step 2: the initiator dials the end to end connection through the
        // relay session, addressed to the peer's synthetic address, and
        // traffic flows from that moment.
        authed::install_crypto_provider();
        let alice_epoch = alice
            .porch()
            .path_for(&bob_key)
            .expect("alice's path table has bob on the relay")
            .epoch();
        let (alice_cert, alice_key_der) = authed::self_signed_cert(&alice_seed).unwrap();
        let alice_tls = authed::client_tls_config(alice_cert, alice_key_der, b"moss-gate").unwrap();
        let mut alice_client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(alice_tls).unwrap(),
        ));
        alice_client_config.transport_config(peer_transport_config(Arc::clone(&alice_epoch)));

        let bob_endpoint = bob.endpoint();
        let bob_epoch = bob
            .porch()
            .path_for(&alice_key)
            .expect("bob's path table has alice on the relay")
            .epoch();
        let (bob_cert, bob_key_der) = authed::self_signed_cert(&bob_seed).unwrap();
        let bob_tls = authed::server_tls_config(bob_cert, bob_key_der, b"moss-gate").unwrap();
        let mut bob_server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(bob_tls).unwrap(),
        ));
        bob_server_config.transport_config(peer_transport_config(Arc::clone(&bob_epoch)));
        let bob_server_config = Arc::new(bob_server_config);
        let accept = tokio::spawn(async move {
            let incoming = bob_endpoint.accept().await.expect("bob sees the dial");
            incoming
                .accept_with(bob_server_config)
                .unwrap()
                .await
                .unwrap()
        });
        let alice_peer = alice
            .endpoint()
            .connect_with(
                alice_client_config,
                alice.synthetic_addr_for(&bob_key),
                "peer",
            )
            .unwrap()
            .await
            .unwrap();
        let bob_peer = accept.await.unwrap();

        // Both houses are on the relay, epoch zero, before anything is
        // probed: "relayed from the first packet".
        assert_eq!(
            alice.porch().path_for(&bob_key).unwrap().kind(),
            mosschat_net::path::PathKind::Relay
        );
        assert_eq!(alice_epoch.load(std::sync::atomic::Ordering::SeqCst), 0);

        // A data stream carrying a marker per phase, so "the connection
        // survives" is a byte that arrived, not an assumption.
        let (mut data_send, _alice_recv) = alice_peer.open_bi().await.unwrap();
        data_send.write_all(b"relayed.").await.unwrap();
        let (_bob_send, mut data_recv) = bob_peer.accept_bi().await.unwrap();
        let mut marker = [0u8; 8];
        data_recv.read_exact(&mut marker).await.unwrap();
        assert_eq!(&marker, b"relayed.");

        // Steps 3 to 7, both sides at once.
        let alice_control = DoorbellControl::new();
        let bob_control = DoorbellControl::new();
        let alice_candidate = loopback_candidate(&alice);
        let bob_candidate = loopback_candidate(&bob);

        let bob_doorbell = {
            let bob = Arc::clone(&bob);
            let bob_control = Arc::clone(&bob_control);
            let bob_peer = bob_peer.clone();
            let candidates = vec![bob_candidate];
            tokio::spawn(async move {
                run_doorbell(
                    &bob.porch(),
                    &bob,
                    &bob_peer,
                    DoorbellParams {
                        session: outcome.session,
                        role: 2,
                        peer_key: alice_key,
                        candidates,
                    },
                    &bob_control,
                )
                .await
            })
        };
        let alice_doorbell = {
            let alice = Arc::clone(&alice);
            let alice_control = Arc::clone(&alice_control);
            let alice_peer = alice_peer.clone();
            let candidates = vec![alice_candidate];
            tokio::spawn(async move {
                run_doorbell(
                    &alice.porch(),
                    &alice,
                    &alice_peer,
                    DoorbellParams {
                        session: outcome.session,
                        role: 1,
                        peer_key: bob_key,
                        candidates,
                    },
                    &alice_control,
                )
                .await
            })
        };

        // Step 6: alice upgrades to bob's proved candidate. Three
        // consecutive answers at 100 ms is 300 ms after a 200 ms fire
        // delay; 10 seconds is the give-up deadline, so waiting past it
        // would report the wrong failure.
        let upgraded = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if let Some(direct) = alice.porch().path_for(&bob_key).unwrap().direct_addr() {
                    return direct;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("alice must upgrade to bob's candidate");
        assert_eq!(upgraded, bob_candidate);
        assert_eq!(
            alice_epoch.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an upgrade restarts slow start exactly once"
        );

        // The same connection, now over the direct path: it never learned
        // the path moved.
        data_send.write_all(b"direct!!").await.unwrap();
        data_recv.read_exact(&mut marker).await.unwrap();
        assert_eq!(&marker, b"direct!!");

        // Kill bob's side of the direct path.
        tokio::time::timeout(Duration::from_secs(8), async {
            while bob
                .porch()
                .path_for(&alice_key)
                .unwrap()
                .direct_addr()
                .is_none()
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("bob must upgrade too");
        bob_control.stop_answering_probes();
        bob.porch()
            .path_for(&alice_key)
            .unwrap()
            .fall_back_to_relay();

        // Step 7: alice notices and reverts to the relay, keeping the end
        // to end connection.
        let alice_outcome = tokio::time::timeout(Duration::from_secs(20), alice_doorbell)
            .await
            .expect("alice's doorbell must settle")
            .unwrap()
            .unwrap();
        assert_eq!(alice_outcome.upgraded_to, Some(bob_candidate));
        assert!(alice_outcome.fell_back);
        assert_eq!(
            alice.porch().path_for(&bob_key).unwrap().kind(),
            mosschat_net::path::PathKind::Relay
        );
        assert_eq!(
            alice_epoch.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the fall-back restarts slow start again"
        );

        // The connection survived both moves.
        data_send.write_all(b"relayed2").await.unwrap();
        data_recv.read_exact(&mut marker).await.unwrap();
        assert_eq!(&marker, b"relayed2");
        assert!(alice_peer.close_reason().is_none());

        bob_control.stop_answering_probes();
        alice_peer.close(0u32.into(), b"done");
        let _ = tokio::time::timeout(Duration::from_secs(20), bob_doorbell).await;
    }

    /// Section 1 on frame 8: the gate fires a start only for a session the
    /// asker is a party to. A member who guessed or overheard a session id
    /// gets silence, not two other houses' probe bursts, for the same
    /// reason `forward_relay` checks a datagram's sender: the session id is
    /// the authorisation, and an error frame would be an oracle for live
    /// sessions.
    ///
    /// Deliberate break to fail this test: in
    /// `server.rs::handle_start_request`, delete the
    /// `session_state.key_a != registration.key && ...` check. Carol's
    /// request then fires the burst and alice's `await_start` returns a
    /// `Start` instead of timing out.
    #[tokio::test]
    async fn a_start_request_from_a_house_outside_the_session_is_dropped_and_counted() {
        let community = random_seed();
        let alice_seed = random_seed();
        let bob_seed = random_seed();
        let carol_seed = random_seed();
        let alice_key = public_key_of(&alice_seed);
        let bob_key = public_key_of(&bob_seed);
        let carol_key = public_key_of(&carol_seed);

        let gate = GateServer::bind(GateServerConfig {
            community,
            identity_seed: random_seed(),
            members: MemberList::from_keys([alice_key, bob_key, carol_key]),
            primary_bind: "127.0.0.1:0".parse().unwrap(),
            secondary_bind: "127.0.0.1:0".parse().unwrap(),
            max_registrations: 256,
        })
        .unwrap();

        let alice_friends = Arc::new(InMemoryFriendStore::new());
        let bob_friends = Arc::new(InMemoryFriendStore::new());
        alice_friends.add(bob_key);
        bob_friends.add(alice_key);

        let connect = async |seed, friends| {
            GateClient::connect(
                gate.primary_addr(),
                seed,
                community,
                None,
                friends,
                Arc::new(InMemoryInviteStore::new()),
            )
            .await
            .unwrap()
        };
        let alice = connect(alice_seed, alice_friends).await;
        let _bob = connect(bob_seed, bob_friends).await;
        let carol = connect(carol_seed, Arc::new(InMemoryFriendStore::new())).await;

        let outcome = alice.introduce(bob_key, 30, None).await.unwrap();

        // Carol knows the session id but is neither of its two keys.
        carol.request_start(outcome.session).await.unwrap();
        assert!(
            alice
                .await_start(outcome.session, Duration::from_millis(750))
                .await
                .is_err(),
            "a start request from outside the session must reach nobody"
        );
        assert_eq!(
            gate.counters()
                .start_request_wrong_sender
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        // A session id nobody holds is the same silence, counted
        // separately so an operator can tell the two apart.
        carol
            .request_start(outcome.session.wrapping_add(1))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            gate.counters()
                .start_request_unknown_session
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        // And the real party's own request does fire it.
        alice.request_start(outcome.session).await.unwrap();
        let start = alice
            .await_start(outcome.session, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(start.session, outcome.session);
        assert_eq!(start.fire_in_ms, 200);
    }
}
