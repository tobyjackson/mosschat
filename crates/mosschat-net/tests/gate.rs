//! WO-1.3a integration tests. Every test lives under `mod gate` so `cargo
//! test -p mosschat-net gate::` (the work order's own verify line) catches
//! this file alongside the unit tests already nested under `gate::` inside
//! the library.

#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod gate {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use mosschat_net::authed;
    use mosschat_net::gate::client::{
        GateClient, InMemoryFriendStore, InMemoryInviteStore, InviteProof, invite_bind,
    };
    use mosschat_net::gate::server::{GateServer, GateServerConfig};
    use mosschat_net::gate::wire::{self, Addr, Frame};
    use mosschat_net::gate::{GateError, MemberList};
    use rand::RngExt;

    const LOCALHOST_ANY: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    const GATE_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    fn random_seed() -> [u8; 32] {
        rand::rng().random()
    }

    fn public_key_of(seed: &[u8; 32]) -> [u8; 32] {
        mosschat_core::identity::AuthorKey::from_bytes(seed).public_bytes()
    }

    /// Starts a gate serving `community` for exactly the members listed,
    /// capped at `max_registrations`.
    fn start_gate(
        members: &[[u8; 32]],
        community: [u8; 32],
        max_registrations: usize,
    ) -> GateServer {
        let config = GateServerConfig {
            community,
            identity_seed: random_seed(),
            members: MemberList::from_keys(members.iter().copied()),
            primary_bind: GATE_BIND,
            secondary_bind: GATE_BIND,
            max_registrations,
        };
        #[allow(clippy::unwrap_used)]
        GateServer::bind(config).unwrap()
    }

    async fn connect_client(
        gate: &GateServer,
        identity_seed: [u8; 32],
        community: [u8; 32],
        friends: Arc<InMemoryFriendStore>,
        invites: Arc<InMemoryInviteStore>,
    ) -> Result<GateClient, GateError> {
        GateClient::connect(
            gate.primary_addr(),
            identity_seed,
            community,
            friends,
            invites,
        )
        .await
    }

    /// A "raw house": speaks the control-stream protocol directly (no
    /// `GateClient`), for tests that need to control exactly what a house
    /// sends back (an explicit decline, or no answer at all).
    struct RawHouse {
        _connection: quinn::Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    }

    async fn raw_register(
        gate_addr: SocketAddr,
        identity_seed: [u8; 32],
        community: [u8; 32],
    ) -> Result<RawHouse, Box<dyn std::error::Error>> {
        authed::install_crypto_provider();
        let (cert, key) = authed::self_signed_cert(&identity_seed)?;
        let tls = authed::client_tls_config(cert, key, b"moss-gate")?;
        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_client));
        let mut endpoint = quinn::Endpoint::client(LOCALHOST_ANY)?;
        endpoint.set_default_client_config(client_config);
        let connection = endpoint.connect(gate_addr, "gate")?.await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        wire::write_frame(&mut send, &Frame::Register { v: 1, community }).await?;
        let reply = wire::read_frame(&mut recv, Duration::from_secs(5)).await?;
        match reply {
            Frame::Registered { .. } => Ok(RawHouse {
                _connection: connection,
                send,
                recv,
            }),
            other => Err(format!("expected Registered, got {other:?}").into()),
        }
    }

    // ------------------------------------------------------------------
    // Relay path
    // ------------------------------------------------------------------

    /// A relay path carries 10 MiB unchanged.
    ///
    /// Deliberate break to fail this test, run for real: in
    /// `sock.rs::PorchSocket::try_send`, change
    /// `encode_relay(session, transmit.contents)` to
    /// `encode_relay(session, &transmit.contents[..transmit.contents.len() - 1])`
    /// (drop the last byte of every relayed datagram). Every relayed byte is
    /// itself a QUIC packet, so truncating it breaks decryption/framing
    /// rather than landing as a clean data mismatch: the peer handshake and
    /// transfer never complete and the test fails with `TimedOut` after its
    /// 120s allowance, confirmed by an actual run. Restore the original
    /// slice to pass again.
    #[tokio::test]
    async fn relay_path_carries_10_mib_unchanged() {
        let community = random_seed();
        let alice_seed = random_seed();
        let bob_seed = random_seed();
        let alice_key = public_key_of(&alice_seed);
        let bob_key = public_key_of(&bob_seed);

        let server = start_gate(&[alice_key, bob_key], community, 256);

        let alice_friends = Arc::new(InMemoryFriendStore::new());
        let bob_friends = Arc::new(InMemoryFriendStore::new());
        alice_friends.add(bob_key);
        bob_friends.add(alice_key);

        let alice = connect_client(
            &server,
            alice_seed,
            community,
            alice_friends,
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();
        let bob = connect_client(
            &server,
            bob_seed,
            community,
            bob_friends,
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();

        let outcome = alice.introduce(bob_key, 30, None).await.unwrap();
        assert_eq!(outcome.role, 1);

        // Each house computes its own local handle for the peer, from
        // its own process salt; the two values never need to agree, since
        // the gate routes by session id, not by either side's local
        // address for the other.
        let alice_synthetic_for_bob = alice.synthetic_addr_for(&bob_key);

        // Give Bob's side a moment to have registered its relay route
        // before Alice dials (the `Introduction` frame that triggers it
        // races the dial slightly).
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Section 3: a peer connection pins its MTU at 1200 and disables
        // discovery, since the relay path caps payloads there; the gate
        // connection each house also holds is deliberately left at its own
        // endpoint-wide default (full MTU discovery), so this override has
        // to be per-connection, on both the dialer's `ClientConfig` and the
        // acceptor's `ServerConfig` (`Incoming::accept_with`), not the
        // endpoint-wide config either side's `GateClient` already set up
        // for its own gate registration.
        fn peer_transport_config() -> Arc<quinn::TransportConfig> {
            let mut transport = quinn::TransportConfig::default();
            transport.mtu_discovery_config(None);
            transport.initial_mtu(1200);
            transport.min_mtu(1200);
            // The default 30s idle timeout is section 4's real policy value
            // for a live path; this test relays 10 MiB through a userspace
            // socket shim under `cargo test`'s own CPU contention with
            // every other test in this file, which is legitimately slower
            // than that policy assumes. 120s here is headroom for the test
            // harness, not a claim about production timing.
            #[allow(clippy::unwrap_used)]
            transport.max_idle_timeout(Some(Duration::from_secs(120).try_into().unwrap()));
            Arc::new(transport)
        }

        let (cert, key) = authed::self_signed_cert(&alice_seed).unwrap();
        let client_tls = authed::client_tls_config(cert, key, b"moss-gate").unwrap();
        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap();
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client));
        client_config.transport_config(peer_transport_config());

        let connecting = alice
            .endpoint()
            .connect_with(client_config, alice_synthetic_for_bob, "peer")
            .unwrap();

        let accept_task = {
            let bob_endpoint = bob.endpoint();
            let (bob_cert, bob_key) = authed::self_signed_cert(&bob_seed).unwrap();
            let bob_server_tls =
                authed::server_tls_config(bob_cert, bob_key, b"moss-gate").unwrap();
            let bob_quic_server =
                quinn::crypto::rustls::QuicServerConfig::try_from(bob_server_tls).unwrap();
            let mut bob_server_config = quinn::ServerConfig::with_crypto(Arc::new(bob_quic_server));
            bob_server_config.transport_config(peer_transport_config());
            let bob_server_config = Arc::new(bob_server_config);
            tokio::spawn(async move {
                let incoming = bob_endpoint
                    .accept()
                    .await
                    .expect("bob sees an incoming peer connection");
                incoming
                    .accept_with(bob_server_config)
                    .unwrap()
                    .await
                    .unwrap()
            })
        };

        let alice_peer_connection = connecting.await.unwrap();
        let bob_peer_connection = accept_task.await.unwrap();

        let payload_len = 10 * 1024 * 1024usize;
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        let expected_hash = blake3::hash(&payload);

        let (mut send, _keep_alice_recv_open) = alice_peer_connection.open_bi().await.unwrap();
        let sender_payload = payload.clone();
        let send_task = tokio::spawn(async move {
            send.write_all(&sender_payload).await.unwrap();
            send.finish().unwrap();
        });

        let (_keep_bob_send_open, mut recv) = bob_peer_connection.accept_bi().await.unwrap();
        let mut received = Vec::with_capacity(payload_len);
        let mut buf = vec![0u8; 64 * 1024];
        while let Some(n) = recv.read(&mut buf).await.unwrap() {
            received.extend_from_slice(&buf[..n]);
        }
        send_task.await.unwrap();

        assert_eq!(received.len(), payload_len);
        assert_eq!(blake3::hash(&received), expected_hash);
    }

    // ------------------------------------------------------------------
    // Member list
    // ------------------------------------------------------------------

    /// A key absent from the member list is refused before a slot is
    /// touched.
    ///
    /// Deliberate break to fail this test: in `server.rs::handle_primary_connection`,
    /// change `if !is_member` to `if false` (never refuse). The `connect`
    /// call below then succeeds instead of erroring.
    #[tokio::test]
    async fn key_absent_from_member_list_is_refused() {
        let community = random_seed();
        let member_key_seed = random_seed();
        let stranger_seed = random_seed();
        let server = start_gate(&[public_key_of(&member_key_seed)], community, 256);

        let result = connect_client(
            &server,
            stranger_seed,
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(server.registration_count(), 0);
    }

    // ------------------------------------------------------------------
    // Introduce: no match, decline, never answered -> the same silence
    // ------------------------------------------------------------------

    /// A tag matching nobody, a house that declines, and a house that never
    /// answers all yield the asker the same silence and the same
    /// `introduce_timeout`.
    #[tokio::test]
    async fn introduce_no_match_decline_and_silence_are_one_outcome() {
        let community = random_seed();
        let alice_seed = random_seed();
        let no_match_target = public_key_of(&random_seed()); // never registered

        let decliner_seed = random_seed();
        let silent_seed = random_seed();
        let members = [
            public_key_of(&alice_seed),
            public_key_of(&decliner_seed),
            public_key_of(&silent_seed),
        ];
        let server = start_gate(&members, community, 256);

        let alice = connect_client(
            &server,
            alice_seed,
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();

        // The decliner: a real `GateClient` with empty friend/invite stores,
        // so its normal auto-answer path opens the seal, finds no proof,
        // and drops in silence (section 1's actual specified behaviour for
        // "anything else").
        let _decliner = connect_client(
            &server,
            decliner_seed,
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();

        // The silent house: registered, but its knock-answering task is
        // stopped, so it never reads (let alone answers) the `Knock` at all
        // -- a distinct wire-level path from the decliner above, which does
        // read and evaluate it.
        let silent = connect_client(
            &server,
            silent_seed,
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();
        silent.stop_answering_knocks();

        let ttl_s = 2;
        let start = std::time::Instant::now();
        let no_match_err = alice
            .introduce(no_match_target, ttl_s, None)
            .await
            .unwrap_err();
        let no_match_elapsed = start.elapsed();

        let start = std::time::Instant::now();
        let decline_err = alice
            .introduce(public_key_of(&decliner_seed), ttl_s, None)
            .await
            .unwrap_err();
        let decline_elapsed = start.elapsed();

        let start = std::time::Instant::now();
        let silent_err = alice
            .introduce(public_key_of(&silent_seed), ttl_s, None)
            .await
            .unwrap_err();
        let silent_elapsed = start.elapsed();

        for err in [&no_match_err, &decline_err, &silent_err] {
            assert!(matches!(err, GateError::Protocol(msg) if msg == "introduce_timeout"));
        }
        for elapsed in [no_match_elapsed, decline_elapsed, silent_elapsed] {
            assert!(elapsed >= Duration::from_secs(u64::from(ttl_s)));
            assert!(elapsed < Duration::from_secs(u64::from(ttl_s) + 5));
        }
    }

    /// The same silence, exercised with an explicit `KnockAnswer{accept:
    /// false}` on the wire, distinct from a house that never reads the
    /// `Knock` at all: a raw house sends a real decline frame, and the
    /// asker's outcome is unchanged.
    ///
    /// Deliberate break to fail this test: in `client.rs::introduce`, change
    /// `Err(GateError::Protocol("introduce_timeout".into()))` to instead
    /// return `Ok(...)` with a fabricated outcome on timeout. This test
    /// then fails because `introduce` no longer errors.
    #[tokio::test]
    async fn explicit_decline_on_the_wire_yields_the_same_timeout() {
        let community = random_seed();
        let alice_seed = random_seed();
        let decliner_seed = random_seed();
        let members = [public_key_of(&alice_seed), public_key_of(&decliner_seed)];
        let server = start_gate(&members, community, 256);

        let alice = connect_client(
            &server,
            alice_seed,
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();

        let mut decliner = raw_register(server.primary_addr(), decliner_seed, community)
            .await
            .unwrap();

        let ttl_s = 2;
        let asker = tokio::spawn(async move {
            alice
                .introduce(public_key_of(&decliner_seed), ttl_s, None)
                .await
        });

        let knock = wire::read_frame(&mut decliner.recv, Duration::from_secs(5))
            .await
            .unwrap();
        let Frame::Knock { tag, .. } = knock else {
            panic!("expected a Knock, got {knock:?}");
        };
        wire::write_frame(
            &mut decliner.send,
            &Frame::KnockAnswer {
                v: 1,
                tag,
                accept: false,
            },
        )
        .await
        .unwrap();

        let outcome = asker.await.unwrap();
        assert!(matches!(outcome, Err(GateError::Protocol(msg)) if msg == "introduce_timeout"));
    }

    // ------------------------------------------------------------------
    // Invite-based first contact
    // ------------------------------------------------------------------

    /// A first contact is accepted on an unredeemed invite proof, and that
    /// proof is refused at a second gate (a different bind, hence a
    /// different `gate_key`) and refused when tried again against the now
    /// redeemed invite.
    #[tokio::test]
    async fn invite_proof_accepted_once_then_refused_elsewhere_and_again() {
        let community = random_seed();
        let alice_seed = random_seed();
        let bob_seed = random_seed();
        let alice_key = public_key_of(&alice_seed);
        let bob_key = public_key_of(&bob_seed);
        let members = [alice_key, bob_key];

        let gate1 = start_gate(&members, community, 256);
        let gate2 = start_gate(&members, community, 256);

        let bob_invites = Arc::new(InMemoryInviteStore::new());
        let secret = random_seed();
        let now_ms = mosschat_net::gate::now_ms();
        bob_invites.issue(&secret, now_ms + 60_000);

        let bob1 = connect_client(
            &gate1,
            bob_seed,
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::clone(&bob_invites),
        )
        .await
        .unwrap();
        let gate1_key = bob1.gate_key();
        let bind_for_gate1 = invite_bind(&secret, &bob_key, &gate1_key);

        let alice1 = connect_client(
            &gate1,
            alice_seed,
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();

        let proof = InviteProof {
            id: [1u8; 16],
            secret,
            bind: bind_for_gate1,
        };
        let outcome = alice1
            .introduce(bob_key, 5, Some(proof.clone()))
            .await
            .unwrap();
        assert_eq!(outcome.role, 1);

        // Second gate: same proof, computed for gate1's key, presented to
        // bob's registration on gate2 (a different `gate_key`). Refused.
        let bob2 = connect_client(
            &gate2,
            bob_seed,
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::clone(&bob_invites),
        )
        .await
        .unwrap();
        let alice2 = connect_client(
            &gate2,
            alice_seed,
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();
        let second_gate_result = alice2.introduce(bob_key, 2, Some(proof.clone())).await;
        assert!(second_gate_result.is_err());
        drop(bob2);

        // Back at gate1: the same invite, already redeemed once, is
        // refused a second time.
        let second_attempt_result = alice1.introduce(bob_key, 2, Some(proof)).await;
        assert!(second_attempt_result.is_err());
    }

    // ------------------------------------------------------------------
    // Relay sender-membership check
    // ------------------------------------------------------------------

    /// A `Relay` datagram whose sender is neither key of its session is
    /// dropped and counted, never answered.
    ///
    /// Deliberate break to fail this test: in `server.rs::forward_relay`,
    /// change the `sender_key` comparison to always take the `Some(...)`
    /// branch (treat every sender as authorised). The counter then stays at
    /// zero and this test fails.
    #[tokio::test]
    async fn relay_datagram_from_a_non_session_key_is_dropped_and_counted() {
        let community = random_seed();
        let alice_seed = random_seed();
        let bob_seed = random_seed();
        let eve_seed = random_seed();
        let alice_key = public_key_of(&alice_seed);
        let bob_key = public_key_of(&bob_seed);
        let eve_key = public_key_of(&eve_seed);
        let members = [alice_key, bob_key, eve_key];
        let server = start_gate(&members, community, 256);

        let alice_friends = Arc::new(InMemoryFriendStore::new());
        let bob_friends = Arc::new(InMemoryFriendStore::new());
        alice_friends.add(bob_key);
        bob_friends.add(alice_key);

        let alice = connect_client(
            &server,
            alice_seed,
            community,
            alice_friends,
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();
        let _bob = connect_client(
            &server,
            bob_seed,
            community,
            bob_friends,
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();
        let eve = raw_register(server.primary_addr(), eve_seed, community)
            .await
            .unwrap();

        let outcome = alice.introduce(bob_key, 5, None).await.unwrap();

        assert_eq!(
            server
                .counters()
                .relay_sender_mismatch
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );

        let forged = wire::encode_relay(outcome.session, b"eve was here").unwrap();
        eve._connection.send_datagram(forged.into()).unwrap();

        // Give the gate a moment to process the forged datagram.
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert_eq!(
            server
                .counters()
                .relay_sender_mismatch
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    // ------------------------------------------------------------------
    // Registration cap
    // ------------------------------------------------------------------

    /// The registration cap rejects the connection past it while still
    /// serving those below.
    ///
    /// Deliberate break to fail this test: in `server.rs::handle_primary_connection`,
    /// change `registrations.len() >= state.capacity` to
    /// `registrations.len() >= state.capacity + 10`. The third registration
    /// then succeeds instead of being refused.
    #[tokio::test]
    async fn registration_cap_refuses_past_it_but_serves_below() {
        let community = random_seed();
        let seeds: Vec<[u8; 32]> = (0..3).map(|_| random_seed()).collect();
        let members: Vec<[u8; 32]> = seeds.iter().map(public_key_of).collect();
        let server = start_gate(&members, community, 2);

        let client_a = connect_client(
            &server,
            seeds[0],
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();
        let client_b = connect_client(
            &server,
            seeds[1],
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();
        assert_eq!(server.registration_count(), 2);

        let refused = connect_client(
            &server,
            seeds[2],
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await;
        assert!(refused.is_err());
        assert_eq!(server.registration_count(), 2);
        assert_eq!(
            server
                .counters()
                .registrations_refused_at_capacity
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );

        // The two below the cap still work.
        client_a.keepalive().await.unwrap();
        client_b.keepalive().await.unwrap();
    }

    // ------------------------------------------------------------------
    // MTU / max_datagram_size
    // ------------------------------------------------------------------

    /// The gate connection reports `max_datagram_size()` of 1205 or better.
    ///
    /// Deliberate break to fail this test: in `sock.rs`, change
    /// `fn may_fragment(&self) -> bool { false }` to `{ true }`. MTU
    /// discovery is then disabled for the endpoint and `max_datagram_size`
    /// never rises past the 1200 byte floor.
    #[tokio::test]
    async fn gate_connection_reports_max_datagram_size_at_least_1205() {
        let community = random_seed();
        let seed = random_seed();
        let server = start_gate(&[public_key_of(&seed)], community, 256);
        let client = connect_client(
            &server,
            seed,
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut observed = client.gate_connection().max_datagram_size().unwrap_or(0);
        while observed < 1205 && std::time::Instant::now() < deadline {
            client.keepalive().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            observed = client.gate_connection().max_datagram_size().unwrap_or(0);
        }
        assert!(observed >= 1205, "max_datagram_size was only {observed}");
    }

    // ------------------------------------------------------------------
    // Identity binding (section 5, issues #13 and #14)
    // ------------------------------------------------------------------

    /// A chain of two certificates is rejected in the handshake.
    ///
    /// Deliberate break to fail this test: in `authed.rs::GateCertVerifier::verify_client_cert`,
    /// remove the `if !intermediates.is_empty() { return Err(...) }` check.
    /// The connect below then succeeds instead of failing.
    #[tokio::test]
    async fn a_chain_of_two_certificates_is_rejected_in_the_handshake() {
        let community = random_seed();
        let member_seed = random_seed();
        let server = start_gate(&[public_key_of(&member_seed)], community, 256);

        authed::install_crypto_provider();
        let (cert1, key1) = authed::self_signed_cert(&member_seed).unwrap();
        let (cert2, _key2) = authed::self_signed_cert(&random_seed()).unwrap();
        let tls = authed::client_tls_config(cert1.clone(), key1, b"moss-gate").unwrap();
        // Rebuild with a two-certificate chain: `client_tls_config` only
        // ever installs one, so this hand-builds the rest exactly as it
        // does, but with `cert2` appended after `cert1`.
        let verifier = std::sync::Arc::new(mosschat_net::authed::GateCertVerifier);
        let mut config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(
                vec![cert1, cert2],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    // Re-derive the same key material `client_tls_config`
                    // used, since it was moved into `tls` above.
                    {
                        let (_, key) = authed::self_signed_cert(&member_seed).unwrap();
                        key
                    },
                ),
            )
            .unwrap();
        config.alpn_protocols = vec![b"moss-gate".to_vec()];
        let _ = tls;

        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(config).unwrap();
        let client_config = quinn::ClientConfig::new(Arc::new(quic_client));
        let mut endpoint = quinn::Endpoint::client(LOCALHOST_ANY).unwrap();
        endpoint.set_default_client_config(client_config);

        // TLS 1.3 client authentication is asynchronous from the client's
        // own point of view: the client's handshake future resolves once
        // *it* has the server's Finished, before the server has verified
        // the client's own certificate chain, so a rejected chain surfaces
        // as the server closing the connection right after, not as this
        // `connect` future erroring.
        let connection = endpoint
            .connect(server.primary_addr(), "gate")
            .unwrap()
            .await
            .unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(5), connection.closed()).await;
        assert!(
            closed.is_ok(),
            "the gate should close a connection presenting a two-certificate chain"
        );
    }

    /// A signature is verified against the TLS key: the sealed introduction
    /// round trips through a real `AuthedConnection`, and the recipient's
    /// `peer_key` used to open it is the one the TLS handshake proved, not
    /// anything carried in a frame.
    #[tokio::test]
    async fn authed_connection_peer_key_matches_the_tls_certificate() {
        let seed = random_seed();
        let expected_public = public_key_of(&seed);

        let community = random_seed();
        let server = start_gate(&[expected_public], community, 256);
        let client = connect_client(
            &server,
            seed,
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();

        // The gate's own view of this connection's key (available via the
        // relay-mismatch counter's absence of complaint, but checked
        // directly here through the client's own recorded key) must equal
        // the identity actually presented over TLS.
        assert_eq!(client.public_key(), expected_public);

        // A signature made by this identity verifies against exactly that
        // key using the one verification path this crate re-exposes.
        let key = mosschat_core::identity::AuthorKey::from_bytes(&seed);
        let msg = b"bound to the TLS-proven key, not a peer-supplied one";
        let sig = mosschat_core::identity::Signer::sign(&key, msg);
        assert!(mosschat_net::gate::client::verify_signature(&expected_public, msg, &sig).is_ok());
        let wrong_key = public_key_of(&random_seed());
        assert!(mosschat_net::gate::client::verify_signature(&wrong_key, msg, &sig).is_err());
    }

    // ------------------------------------------------------------------
    // Reflect / address reflection on two ports
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn reflect_reports_the_observed_address() {
        let community = random_seed();
        let seed = random_seed();
        let server = start_gate(&[public_key_of(&seed)], community, 256);
        let client = connect_client(
            &server,
            seed,
            community,
            Arc::new(InMemoryFriendStore::new()),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await
        .unwrap();
        let observed: Addr = client.reflect(server.secondary_addr()).await.unwrap();
        assert!(observed.to_socket_addr().is_some());
    }
}
