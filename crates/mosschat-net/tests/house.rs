//! WO-1.5a integration tests: a headless house, a caller holding a visit
//! open against it, and a real gate between them, all in one process.
//!
//! These are the tests that say a live visit is measurable at all, which
//! is what WO-1.5's connectivity matrix and WO-1.6's `blackout-60s` and
//! `gatehouse-killed` rows need before they can be run: something has to
//! be at the other end, and it has to still be there a minute later.
//!
//! Everything is `mod house` so `cargo test -p mosschat-net house::`
//! catches this file alongside the unit tests nested under `house::`
//! inside the library.
//!
//! **They take real seconds, on purpose.** Section 4's stale and dead are
//! defined in wall clock terms against a real path (three probes at 500 ms
//! each lost after `max(4 * srtt, 500 ms)`, then a grace of
//! `4 * srtt + 5 s`), and the paths here are real loopback sockets carrying
//! real QUIC. `tokio::time::pause` would auto-advance past the I/O these
//! timers are timing, so the clock is the real one and the two tests that
//! wait for a path to die budget about 12 seconds each.

#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod house {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use mosschat_net::diag::{DiagRecord, PathChoice, Reason, VisitEventKind};
    use mosschat_net::gate::MemberList;
    use mosschat_net::gate::client::{GateClient, InMemoryFriendStore, InMemoryInviteStore};
    use mosschat_net::gate::server::{GateServer, GateServerConfig};
    use mosschat_net::house::{HouseConfig, HouseEvent};
    use mosschat_net::punch::{
        DoorbellControl, DoorbellParams, Hold, VisitEventSink, run_doorbell,
    };
    use quinn::AsyncUdpSocket as _;
    use rand::RngExt;

    fn random_seed() -> [u8; 32] {
        rand::rng().random()
    }

    fn public_key_of(seed: &[u8; 32]) -> [u8; 32] {
        mosschat_core::identity::AuthorKey::from_bytes(seed).public_bytes()
    }

    /// A unique temporary directory for one test's diagnostics.
    fn diag_dir(name: &str) -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("konrad15a-house-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// Every record written into `dir`.
    fn records_in(dir: &std::path::Path) -> Vec<DiagRecord> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return out;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            for outcome in mosschat_net::diag::read_records(&path).unwrap() {
                if let mosschat_net::diag::ReadOutcome::Record(record) = outcome {
                    out.push(*record);
                }
            }
        }
        out
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

    /// The events a house printed, collected instead of printed.
    #[derive(Clone, Default)]
    struct Collected(Arc<Mutex<Vec<HouseEvent>>>);

    impl Collected {
        fn sink(&self) -> mosschat_net::house::HouseEventSink {
            let held = Arc::clone(&self.0);
            Arc::new(move |event: HouseEvent| {
                // Every line a real house would print is built here too,
                // so a line that cannot be built is a failing test rather
                // than a silent stdout.
                let line = event.to_json_line();
                assert!(line.starts_with('{'), "{line}");
                held.lock().unwrap().push(event);
            })
        }

        fn kinds(&self) -> Vec<VisitEventKind> {
            self.0.lock().unwrap().iter().map(|e| e.kind).collect()
        }

        fn first(&self, kind: VisitEventKind) -> Option<HouseEvent> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .find(|event| event.kind == kind)
                .cloned()
        }

        /// Waits up to `within` for `kind` to appear, returning it.
        async fn wait_for(&self, kind: VisitEventKind, within: Duration) -> Option<HouseEvent> {
            let deadline = tokio::time::Instant::now() + within;
            loop {
                if let Some(event) = self.first(kind) {
                    return Some(event);
                }
                if tokio::time::Instant::now() >= deadline {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }

    /// One gate, one headless house and one caller, all on loopback.
    struct Fixture {
        _gate: GateServer,
        gate_addr: SocketAddr,
        community: [u8; 32],
        house_key: [u8; 32],
        events: Collected,
        house_diagnostics: std::path::PathBuf,
        stop_house: Option<tokio::sync::oneshot::Sender<()>>,
        house_task: tokio::task::JoinHandle<Result<(), mosschat_net::gate::GateError>>,
    }

    impl Fixture {
        /// Starts the gate and the house, and waits for the house to say
        /// it registered.
        async fn start(name: &str, no_punch: bool) -> (Self, [u8; 32]) {
            let community = random_seed();
            let house_seed = random_seed();
            let caller_seed = random_seed();
            let house_key = public_key_of(&house_seed);
            let caller_key = public_key_of(&caller_seed);

            let gate = GateServer::bind(GateServerConfig {
                community,
                identity_seed: random_seed(),
                members: MemberList::from_keys([house_key, caller_key]),
                primary_bind: "127.0.0.1:0".parse().unwrap(),
                secondary_bind: "127.0.0.1:0".parse().unwrap(),
                max_registrations: 256,
            })
            .unwrap();
            let gate_addr = gate.primary_addr();

            let house_diagnostics = diag_dir(name);
            let events = Collected::default();
            let (stop_house, stopped) = tokio::sync::oneshot::channel();
            let config = HouseConfig {
                identity_seed: house_seed,
                community,
                gate: gate_addr,
                gate_key: None,
                friends: {
                    let friends = Arc::new(InMemoryFriendStore::new());
                    friends.add(caller_key);
                    friends
                },
                no_punch,
                diagnostics: Some(house_diagnostics.clone()),
            };
            let sink = events.sink();
            let house_task = tokio::spawn(async move {
                mosschat_net::house::run(config, sink, async move {
                    let _ = stopped.await;
                })
                .await
            });

            let registered = events
                .wait_for(VisitEventKind::Registered, Duration::from_secs(10))
                .await;
            assert!(
                registered.is_some(),
                "the house must register before anything can visit it"
            );

            (
                Self {
                    _gate: gate,
                    gate_addr,
                    community,
                    house_key,
                    events,
                    house_diagnostics,
                    stop_house: Some(stop_house),
                    house_task,
                },
                caller_seed,
            )
        }

        /// Connects a caller, knocks, and opens the end to end connection
        /// through the relay.
        async fn call(&self, caller_seed: [u8; 32]) -> (Arc<GateClient>, quinn::Connection, u32) {
            let friends = Arc::new(InMemoryFriendStore::new());
            friends.add(self.house_key);
            let caller = Arc::new(
                GateClient::connect(
                    self.gate_addr,
                    caller_seed,
                    self.community,
                    None,
                    friends,
                    Arc::new(InMemoryInviteStore::new()),
                )
                .await
                .unwrap(),
            );
            let outcome = caller.introduce(self.house_key, 30, None).await.unwrap();
            assert_eq!(outcome.role, 1, "the caller is the initiator");
            let connection = caller.dial_peer(&self.house_key).await.unwrap();
            (caller, connection, outcome.session)
        }

        async fn stop(mut self) {
            if let Some(stop) = self.stop_house.take() {
                let _ = stop.send(());
            }
            let stopped = tokio::time::timeout(Duration::from_secs(10), self.house_task).await;
            assert!(stopped.is_ok(), "the house must stop when it is asked to");
            let _ = std::fs::remove_dir_all(&self.house_diagnostics);
        }
    }

    /// The caller's half of a held visit: what `doctor --friend --hold`
    /// does, in the shape a test can drive.
    struct Held<'a> {
        caller: &'a Arc<GateClient>,
        connection: &'a quinn::Connection,
        session: u32,
        peer_key: [u8; 32],
        hold: Hold,
        no_punch: bool,
        control: &'a Arc<DoorbellControl>,
        diagnostics: &'a std::path::Path,
        events: Option<VisitEventSink>,
    }

    impl Held<'_> {
        /// Starts the visit and returns a handle to the record it writes.
        fn spawn(self) -> tokio::task::JoinHandle<DiagRecord> {
            let salt = mosschat_net::diag::InstallSalt::load_or_create(self.diagnostics).unwrap();
            let recorder = mosschat_net::diag::Recorder::new(
                mosschat_net::diag::PeerFingerprint::from_key(&salt, &self.peer_key),
                Some(mosschat_net::diag::DiagSink::new(self.diagnostics.to_path_buf()).unwrap()),
            );
            let params = DoorbellParams {
                session: self.session,
                role: 1,
                peer_key: self.peer_key,
                candidates: vec![loopback_candidate(self.caller)],
                peer_observed: self.caller.peer_observed_for(self.session),
                peer_discovered: Vec::new(),
                hold: self.hold,
                no_punch: self.no_punch,
                events: self.events,
                recorder: Some(recorder.clone()),
            };
            let caller = Arc::clone(self.caller);
            let connection = self.connection.clone();
            let control = Arc::clone(self.control);
            tokio::spawn(async move {
                let _ = run_doorbell(&caller.porch(), &caller, &connection, params, &control).await;
                // The doorbell settled the record itself; this is the copy
                // it wrote, not a second one built from a different reason.
                recorder.finish(Reason::Internal).0
            })
        }
    }

    /// The whole of WO-1.5a in one run: a headless house answers a knock,
    /// holds the visit open, upgrades to a direct path, and when that path
    /// stops answering it detects the loss and puts traffic back on the
    /// relay inside section 4's bound, then declares the path dead after
    /// the grace.
    ///
    /// The kill is the caller no longer answering the house's probes,
    /// which is exactly what a dead path looks like from the house's end
    /// and the only honest way to kill one in process. The house is the
    /// side asserted on because the house is the side that detects.
    ///
    /// Deliberate break to fail this test: in `punch.rs::run_doorbell`,
    /// delete the `LivenessChange::WentStale` arm's `fall_back_to_relay`
    /// call and its `FellBack` event. The upgrade still happens and the
    /// fall-back assertion times out.
    #[tokio::test]
    async fn a_held_visit_upgrades_then_falls_back_when_the_direct_path_dies() {
        let (fixture, caller_seed) = Fixture::start("fallback", false).await;
        let (caller, connection, session) = fixture.call(caller_seed).await;

        let knock = fixture
            .events
            .wait_for(VisitEventKind::Knock, Duration::from_secs(5))
            .await
            .expect("the house must answer the knock of a friend on its list");
        assert!(knock.peer.is_some(), "a knock names the peer it came from");

        let visit_open = fixture
            .events
            .wait_for(VisitEventKind::VisitOpen, Duration::from_secs(10))
            .await
            .expect("the visit must open");
        assert!(
            visit_open.detail.contains("relay"),
            "section 2 step 2: relayed from the first packet, not direct: {}",
            visit_open.detail
        );

        let caller_diagnostics = diag_dir("fallback-caller");
        let control = DoorbellControl::new();
        let held = Held {
            caller: &caller,
            connection: &connection,
            session,
            peer_key: fixture.house_key,
            hold: Hold::For(Duration::from_secs(20)),
            no_punch: false,
            control: &control,
            diagnostics: &caller_diagnostics,
            events: None,
        }
        .spawn();

        let upgraded = fixture
            .events
            .wait_for(VisitEventKind::Upgraded, Duration::from_secs(15))
            .await
            .expect("the house must upgrade to the caller's proved candidate");
        assert!(upgraded.detail.contains("direct to"), "{}", upgraded.detail);

        // Kill the house's direct path: the caller stops answering its
        // pings while going on answering everything else, so the house's
        // probes are what fall silent.
        control.stop_answering_probes();

        let stale = fixture
            .events
            .wait_for(VisitEventKind::PathStale, Duration::from_secs(10))
            .await
            .expect("three unanswered probes must make the path stale");
        let fell_back = fixture
            .events
            .wait_for(VisitEventKind::FellBack, Duration::from_secs(5))
            .await
            .expect("a stale path moves traffic back to the relay at once");
        // Section 4's Phase 1 criterion, on the side that moved: detection
        // plus fall-back under 1 s. Detection is measured from the last
        // answered probe, which this test cannot see; what it can assert,
        // and what the criterion's second half is, is that the move
        // follows the detection immediately rather than waiting for dead.
        let fall_back_ms = fell_back.at_ms.saturating_sub(stale.at_ms);
        assert!(
            fall_back_ms < 1_000,
            "traffic moved back {fall_back_ms} ms after detection, past section 4's 1 s"
        );

        let dead = fixture
            .events
            .wait_for(VisitEventKind::PathDead, Duration::from_secs(20))
            .await
            .expect("the stale grace must end in a dead path");
        assert!(
            dead.at_ms >= stale.at_ms,
            "dead follows stale, never precedes it"
        );

        // The order section 4 fixes, and the one a reader of two logs
        // joins on: relayed first, upgraded, detected, moved, dead.
        let kinds = fixture.events.kinds();
        let index = |kind: VisitEventKind| kinds.iter().position(|k| *k == kind).unwrap();
        assert!(index(VisitEventKind::VisitOpen) < index(VisitEventKind::Upgraded));
        assert!(index(VisitEventKind::Upgraded) < index(VisitEventKind::PathStale));
        assert!(index(VisitEventKind::PathStale) < index(VisitEventKind::FellBack));
        assert!(index(VisitEventKind::FellBack) < index(VisitEventKind::PathDead));

        connection.close(0u32.into(), b"test over");
        let record = tokio::time::timeout(Duration::from_secs(30), held)
            .await
            .expect("the caller's hold must end")
            .unwrap();
        assert!(
            record.rtt_samples > 0,
            "a held visit samples its round trip: {record:?}"
        );
        let _ = std::fs::remove_dir_all(&caller_diagnostics);
        fixture.stop().await;
    }

    /// WO-1.5 case (e): with `--no-punch` on both ends nothing is probed,
    /// the visit stays on the relay for its whole hold, and both records
    /// say why in a word a reader can act on.
    ///
    /// Deliberate break to fail this test: ignore `params.no_punch` in
    /// `run_doorbell` and let the probe burst run. Both sides then upgrade
    /// and the `upgraded` assertion fails.
    #[tokio::test]
    async fn no_punch_never_leaves_the_relay() {
        let (fixture, caller_seed) = Fixture::start("nopunch", true).await;
        let (caller, connection, session) = fixture.call(caller_seed).await;

        let caller_diagnostics = diag_dir("nopunch-caller");
        let control = DoorbellControl::new();
        let held = Held {
            caller: &caller,
            connection: &connection,
            session,
            peer_key: fixture.house_key,
            hold: Hold::For(Duration::from_secs(4)),
            no_punch: true,
            control: &control,
            diagnostics: &caller_diagnostics,
            events: None,
        }
        .spawn();

        let visit_open = fixture
            .events
            .wait_for(VisitEventKind::VisitOpen, Duration::from_secs(10))
            .await
            .expect("the visit must open even with no punching");
        assert!(visit_open.detail.contains("relay"), "{}", visit_open.detail);

        let record = tokio::time::timeout(Duration::from_secs(30), held)
            .await
            .expect("the caller's hold must end")
            .unwrap();

        assert!(
            matches!(record.path, PathChoice::Relay(_)),
            "a --no-punch visit ends where it started: {:?}",
            record.path
        );
        assert_eq!(
            record.reason,
            Reason::PunchDisabled,
            "the record names the flag, not a failure that did not happen"
        );
        assert_eq!(
            record.failed_step, None,
            "nothing failed: this run did what it was told"
        );
        let skipped = record
            .steps
            .iter()
            .find(|step| step.step == mosschat_net::diag::Step::ProbeBurst)
            .expect("the record still shows the burst that was skipped");
        assert!(
            skipped.detail.contains("--no-punch"),
            "a reader is told which flag did this: {}",
            skipped.detail
        );
        assert!(
            record.rtt_samples > 0 && record.rtt_source == mosschat_net::diag::RttSource::Quic,
            "a relayed visit still measures a round trip, from the end to end connection: \
             {} samples, source {}",
            record.rtt_samples,
            record.rtt_source.as_str()
        );

        // Neither side ever upgraded.
        assert!(
            !fixture.events.kinds().contains(&VisitEventKind::Upgraded),
            "the house upgraded a visit it was told not to probe: {:?}",
            fixture.events.kinds()
        );
        assert!(
            caller
                .porch()
                .path_for(&fixture.house_key)
                .unwrap()
                .direct_addr()
                .is_none(),
            "the caller's path table left the relay"
        );

        connection.close(0u32.into(), b"test over");
        let _ = std::fs::remove_dir_all(&caller_diagnostics);
        fixture.stop().await;
    }

    /// Section 2 step 7's other half, which only a caller can drive: a
    /// path that dies and then comes back.
    ///
    /// Two plain doorbells rather than a headless house, because the side
    /// that reruns is the initiator (a responder falls back and waits for
    /// the initiator's next `Candidates`), and killing the initiator's
    /// path means the *responder* has to stop answering, which a house
    /// running its own visits gives no handle for. Everything under test
    /// is the same code either role runs.
    ///
    /// Deliberate break to fail this test: in `punch.rs::run_doorbell`,
    /// replace the `WentDead` arm's `continue 'attempts` with
    /// `phase = Phase::Relayed`. The path still dies and the visit still
    /// holds; it never comes back, and the `recovered` wait times out.
    #[tokio::test]
    async fn a_dead_path_that_comes_back_reruns_the_doorbell_and_recovers() {
        let community = random_seed();
        let caller_seed = random_seed();
        let callee_seed = random_seed();
        let caller_key = public_key_of(&caller_seed);
        let callee_key = public_key_of(&callee_seed);

        let gate = GateServer::bind(GateServerConfig {
            community,
            identity_seed: random_seed(),
            members: MemberList::from_keys([caller_key, callee_key]),
            primary_bind: "127.0.0.1:0".parse().unwrap(),
            secondary_bind: "127.0.0.1:0".parse().unwrap(),
            max_registrations: 256,
        })
        .unwrap();

        let connect = async |seed, friend| {
            let friends = Arc::new(InMemoryFriendStore::new());
            friends.add(friend);
            Arc::new(
                GateClient::connect(
                    gate.primary_addr(),
                    seed,
                    community,
                    None,
                    friends,
                    Arc::new(InMemoryInviteStore::new()),
                )
                .await
                .unwrap(),
            )
        };
        let caller = connect(caller_seed, callee_key).await;
        let callee = connect(callee_seed, caller_key).await;

        let outcome = caller.introduce(callee_key, 30, None).await.unwrap();
        // The responder registers its relay route from the `Introduction`
        // its reader loop receives, which races the dial by a hair.
        tokio::time::sleep(Duration::from_millis(150)).await;

        let callee_endpoint = callee.endpoint();
        let callee_for_accept = Arc::clone(&callee);
        let accept = tokio::spawn(async move {
            let incoming = callee_endpoint
                .accept()
                .await
                .expect("the callee sees the dial");
            callee_for_accept.accept_peer(incoming).await.unwrap()
        });
        let caller_connection = caller.dial_peer(&callee_key).await.unwrap();
        let (dialling_key, callee_connection) = accept.await.unwrap();
        assert_eq!(dialling_key, caller_key);

        let caller_control = DoorbellControl::new();
        let callee_control = DoorbellControl::new();
        let caller_events = Collected::default();
        let caller_sink = {
            let collected = caller_events.clone();
            VisitEventSink::new(move |kind, detail| {
                collected.0.lock().unwrap().push(HouseEvent {
                    at_ms: 0,
                    kind,
                    peer: None,
                    detail: detail.to_string(),
                });
            })
        };

        let callee_params = DoorbellParams {
            session: outcome.session,
            role: 2,
            peer_key: caller_key,
            candidates: vec![loopback_candidate(&callee)],
            peer_observed: callee.peer_observed_for(outcome.session),
            peer_discovered: Vec::new(),
            hold: Hold::For(Duration::from_secs(60)),
            no_punch: false,
            events: None,
            recorder: None,
        };
        let callee_doorbell = {
            let callee = Arc::clone(&callee);
            let connection = callee_connection.clone();
            let control = Arc::clone(&callee_control);
            tokio::spawn(async move {
                run_doorbell(
                    &callee.porch(),
                    &callee,
                    &connection,
                    callee_params,
                    &control,
                )
                .await
            })
        };

        let caller_params = DoorbellParams {
            session: outcome.session,
            role: 1,
            peer_key: callee_key,
            candidates: vec![loopback_candidate(&caller)],
            peer_observed: caller.peer_observed_for(outcome.session),
            peer_discovered: Vec::new(),
            hold: Hold::For(Duration::from_secs(60)),
            no_punch: false,
            events: Some(caller_sink),
            recorder: None,
        };
        let caller_doorbell = {
            let caller = Arc::clone(&caller);
            let connection = caller_connection.clone();
            let control = Arc::clone(&caller_control);
            tokio::spawn(async move {
                run_doorbell(
                    &caller.porch(),
                    &caller,
                    &connection,
                    caller_params,
                    &control,
                )
                .await
            })
        };

        caller_events
            .wait_for(VisitEventKind::Upgraded, Duration::from_secs(15))
            .await
            .expect("the caller must upgrade first");

        // The path dies from the caller's point of view: the callee stops
        // answering its probes.
        callee_control.stop_answering_probes();
        caller_events
            .wait_for(VisitEventKind::FellBack, Duration::from_secs(10))
            .await
            .expect("the caller must fall back to the relay");
        caller_events
            .wait_for(VisitEventKind::PathDead, Duration::from_secs(20))
            .await
            .expect("the stale grace must end in a dead path");

        // And then it comes back.
        callee_control.resume_answering_probes();
        let recovered = caller_events
            .wait_for(VisitEventKind::Recovered, Duration::from_secs(20))
            .await;
        let recovered = recovered.unwrap_or_else(|| {
            panic!(
                "a rerun of the doorbell must get the path back; the caller's events were {:?},                  unauthenticated probes {}, caller path {:?}",
                caller_events.kinds(),
                caller.porch().probes_unauthenticated(),
                caller.porch().path_for(&callee_key).map(|p| p.kind()),
            )
        });
        assert!(
            recovered.detail.contains("direct to"),
            "{}",
            recovered.detail
        );
        assert!(
            caller
                .porch()
                .path_for(&callee_key)
                .unwrap()
                .direct_addr()
                .is_some(),
            "the caller's traffic is on a direct path again"
        );

        caller_control.stop();
        callee_control.stop();
        let _ = tokio::time::timeout(Duration::from_secs(10), caller_doorbell).await;
        let _ = tokio::time::timeout(Duration::from_secs(10), callee_doorbell).await;
        caller_connection.close(0u32.into(), b"test over");
        callee_connection.close(0u32.into(), b"test over");
    }

    /// A house asked to stop says goodbye on every open visit (frame 19)
    /// and gives its registration back, rather than vanishing and leaving
    /// a friend probing a path that is gone.
    ///
    /// Deliberate break to fail this test: drop the `control.stop()` loop
    /// in `house::run`. The house still exits, but the caller waits out
    /// its whole hold instead of ending on the peer's goodbye, and the
    /// reason assertion fails.
    #[tokio::test]
    async fn a_stopping_house_says_goodbye_to_its_visits_and_its_gate() {
        let (fixture, caller_seed) = Fixture::start("goodbye", false).await;
        let (caller, connection, session) = fixture.call(caller_seed).await;

        let caller_diagnostics = diag_dir("goodbye-caller");
        let control = DoorbellControl::new();
        let held = Held {
            caller: &caller,
            connection: &connection,
            session,
            peer_key: fixture.house_key,
            // Far longer than this test waits, so an early end can only be
            // the goodbye and never the hold running out.
            hold: Hold::For(Duration::from_secs(600)),
            no_punch: false,
            control: &control,
            diagnostics: &caller_diagnostics,
            events: None,
        }
        .spawn();

        fixture
            .events
            .wait_for(VisitEventKind::VisitOpen, Duration::from_secs(10))
            .await
            .expect("the visit must open");
        fixture.stop().await;

        let record = tokio::time::timeout(Duration::from_secs(30), held)
            .await
            .expect("the caller's visit must end on the goodbye, not on its hold")
            .unwrap();
        assert_eq!(record.reason, Reason::PeerGoodbye);
        assert!(
            record
                .events
                .iter()
                .any(|event| event.event == VisitEventKind::Goodbye),
            "the caller's record says the peer left: {:?}",
            record.events
        );
        assert!(
            !records_in(&caller_diagnostics).is_empty(),
            "the visit wrote its record"
        );

        connection.close(0u32.into(), b"test over");
        let _ = std::fs::remove_dir_all(&caller_diagnostics);
    }
}
