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
        /// A gate member the house has never listed as a friend.
        stranger_seed: [u8; 32],
        /// A second friend, so a test can hold two visits at once.
        second_seed: [u8; 32],
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
            let second_seed = random_seed();
            let stranger_seed = random_seed();
            let house_key = public_key_of(&house_seed);
            let caller_key = public_key_of(&caller_seed);
            let second_key = public_key_of(&second_seed);
            // A member of the community whose knock this house will not
            // answer: on the gate's list, absent from the house's
            // friends.
            let stranger_key = public_key_of(&stranger_seed);

            let gate = GateServer::bind(GateServerConfig {
                community,
                identity_seed: random_seed(),
                members: MemberList::from_keys([house_key, caller_key, second_key, stranger_key]),
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
                    friends.add(second_key);
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
                    stranger_seed,
                    second_seed,
                    events,
                    house_diagnostics,
                    stop_house: Some(stop_house),
                    house_task,
                },
                caller_seed,
            )
        }

        /// Registers one house-side client at the gate, friendly to the
        /// house.
        async fn connect(&self, seed: [u8; 32]) -> Arc<GateClient> {
            let friends = Arc::new(InMemoryFriendStore::new());
            friends.add(self.house_key);
            Arc::new(
                GateClient::connect(
                    self.gate_addr,
                    seed,
                    self.community,
                    None,
                    friends,
                    Arc::new(InMemoryInviteStore::new()),
                )
                .await
                .unwrap(),
            )
        }

        /// Connects a caller, knocks, and opens the end to end connection
        /// through the relay.
        async fn call(&self, caller_seed: [u8; 32]) -> (Arc<GateClient>, quinn::Connection, u32) {
            let caller = self.connect(caller_seed).await;
            let outcome = caller.introduce(self.house_key, 30, None).await.unwrap();
            assert_eq!(outcome.role, 1, "the caller is the initiator");
            let connection = caller.dial_peer(&self.house_key).await.unwrap();
            (caller, connection, outcome.session)
        }

        /// Asks the house to stop without waiting for it or removing its
        /// diagnostics directory, so a test can read the record its
        /// visits settle on the way out.
        fn ask_to_stop(&mut self) {
            if let Some(stop) = self.stop_house.take() {
                let _ = stop.send(());
            }
        }

        async fn stop(mut self) {
            self.ask_to_stop();
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
        /// What this caller offers. `None` is its own loopback address,
        /// which is what makes a same-machine pair upgradeable at all;
        /// `Some(vec![])` is a caller with nothing to offer, which is how
        /// a visit with nothing probeable is produced on purpose.
        candidates: Option<Vec<SocketAddr>>,
        /// Whether the gate's observation of the peer vouches for it. A
        /// test that wants nothing probeable withholds it, since it is
        /// what admits a private or loopback address the peer named.
        vouch_peer: bool,
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
                candidates: self
                    .candidates
                    .clone()
                    .unwrap_or_else(|| vec![loopback_candidate(self.caller)]),
                peer_observed: if self.vouch_peer {
                    self.caller.peer_observed_for(self.session)
                } else {
                    None
                },
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
            candidates: None,
            vouch_peer: true,
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
            candidates: None,
            vouch_peer: true,
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

    /// Run 3, finding 1 of issue 84: section 4 covers the relay path, so a
    /// relayed visit whose relay goes quiet is reported as `path_stale`
    /// then `path_dead` **on both sides**, and both settle with a reason
    /// that names the path death instead of whatever the upgrade had
    /// failed of earlier.
    ///
    /// Both ends run `--no-punch`, which is the shortest way to a visit
    /// that is relayed for its whole life. The blackout is the caller
    /// detaching its gate from its own porch socket, which stops its relay
    /// leg in both directions at once: its probes queue and never leave,
    /// and nothing the house sends arrives. That is what a blackout is,
    /// and it is why both sides are asserted here rather than one: a
    /// one-way silence would leave the silenced side's own probes answered
    /// and prove only half of this. The probes themselves are real
    /// `Relay` payloads through a real gate up to the moment it is
    /// detached; nothing here is simulated but the outage.
    ///
    /// Deliberate break to fail this test: change `Phase::Relayed`'s arm
    /// in `run_doorbell` back to `Phase::Relayed => {}`, which is the code
    /// this fixes. Neither side then sends a relay probe, neither goes
    /// stale or dead, and the first event assertion fails on a visit that
    /// ran for a minute with nothing to say. Second break: move the
    /// `if relay_dead` early return in `end_of_visit_reason` below the
    /// `no_punch` branch, and both reasons read `punch_disabled`.
    #[tokio::test]
    async fn a_relayed_visit_that_goes_quiet_is_reported_stale_then_dead() {
        let (mut fixture, caller_seed) = Fixture::start("relaydead", true).await;
        let (caller, connection, session) = fixture.call(caller_seed).await;

        let caller_diagnostics = diag_dir("relaydead-caller");
        let caller_events = Collected::default();
        let sink = {
            let collected = Arc::clone(&caller_events.0);
            VisitEventSink::new(move |kind, detail| {
                collected.lock().unwrap().push(HouseEvent {
                    at_ms: 0,
                    kind,
                    peer: None,
                    detail: detail.to_string(),
                });
            })
        };
        let control = DoorbellControl::new();
        let held = Held {
            caller: &caller,
            connection: &connection,
            session,
            peer_key: fixture.house_key,
            // Long enough for stale (about 2 s) and dead (5 s of grace
            // after it) with room to spare, short enough that the record
            // this asserts arrives without waiting out a QUIC idle
            // timeout: the hold elapsing is what settles it, the relay it
            // would say goodbye on being gone.
            hold: Hold::For(Duration::from_secs(12)),
            no_punch: true,
            control: &control,
            diagnostics: &caller_diagnostics,
            events: Some(sink),
            candidates: None,
            vouch_peer: true,
        }
        .spawn();

        fixture
            .events
            .wait_for(VisitEventKind::VisitOpen, Duration::from_secs(10))
            .await
            .expect("the visit must open on the relay");
        caller_events
            .wait_for(VisitEventKind::VisitOpen, Duration::from_secs(10))
            .await
            .expect("the caller must see its own visit open");

        // The blackout, both directions at once.
        caller
            .porch()
            .detach_gate(caller.gate_connection().remote_address());

        for (whose, events) in [("callee", &fixture.events), ("caller", &caller_events)] {
            let stale = events
                .wait_for(VisitEventKind::PathStale, Duration::from_secs(15))
                .await
                .unwrap_or_else(|| {
                    panic!("section 4 must notice a relay that stopped answering ({whose})")
                });
            assert!(
                stale.detail.contains("relay"),
                "the {whose}'s event names the path that went quiet: {}",
                stale.detail
            );
            let dead = events
                .wait_for(VisitEventKind::PathDead, Duration::from_secs(30))
                .await
                .unwrap_or_else(|| {
                    panic!("a relay that never answers again is dead, not stale ({whose})")
                });
            assert!(
                dead.detail.contains("relay"),
                "the {whose}'s event names the path that died: {}",
                dead.detail
            );
        }

        // The caller's own record, settled when its hold elapses.
        let caller_record = tokio::time::timeout(Duration::from_secs(30), held)
            .await
            .expect("the caller's hold must end")
            .unwrap();
        assert_eq!(
            caller_record.reason,
            Reason::PathIdleTimeout,
            "the caller's reason names the path death, not the flag it ran under: {:?}",
            caller_record.steps
        );
        assert!(
            caller_record
                .events
                .iter()
                .any(|event| event.event == VisitEventKind::PathDead),
            "the caller's record carries the death as an event too: {:?}",
            caller_record.events
        );

        // The callee's, settled on its way out: its relay is gone, so
        // nothing else will end its visit.
        let house_diagnostics = fixture.house_diagnostics.clone();
        fixture.ask_to_stop();
        let house_record = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(record) = records_in(&house_diagnostics)
                    .into_iter()
                    .find(|record| record.reason != Reason::Internal)
                {
                    return record;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the house must settle its record once its visit ends");
        assert_eq!(
            house_record.reason,
            Reason::PathIdleTimeout,
            "the callee's reason names the same thing from its own side: {:?}",
            house_record.steps
        );

        connection.close(0u32.into(), b"test over");
        let _ = std::fs::remove_dir_all(&caller_diagnostics);
        fixture.stop().await;
    }

    /// Yseult's Medium 2 on PR 89: a relay that comes back after being
    /// declared dead is seen coming back, and the visit's reason stops
    /// naming an outage it survived.
    ///
    /// Dead is absorbing in `PeerLiveness`, which is right for a direct
    /// path, because a dead one is dropped and a rerun builds a fresh one.
    /// The relay is not dropped and there is no rerun, so if probing
    /// stopped at dead a visit would have no liveness at all for the rest
    /// of its life over any outage between the 9 seconds it takes to
    /// declare dead and the 30 seconds quinn takes to close the
    /// connection, and its record would say `path_idle_timeout` whatever
    /// actually ended it.
    ///
    /// Deliberate break to fail this test: make `RelayWatch::due_probe`
    /// return `self.liveness.due_probe(now)` unconditionally, so probing
    /// stops at dead. Nothing is ever answered again, no `recovered`
    /// arrives, and the reason assertion reads `path_idle_timeout` on a
    /// visit that spent its last 8 seconds on a working relay.
    #[tokio::test]
    async fn a_relay_that_comes_back_after_dead_is_recovered_and_the_reason_says_so() {
        let (fixture, caller_seed) = Fixture::start("relayback", true).await;
        let (caller, connection, session) = fixture.call(caller_seed).await;

        let caller_diagnostics = diag_dir("relayback-caller");
        let caller_events = Collected::default();
        let sink = {
            let collected = Arc::clone(&caller_events.0);
            VisitEventSink::new(move |kind, detail| {
                collected.lock().unwrap().push(HouseEvent {
                    at_ms: 0,
                    kind,
                    peer: None,
                    detail: detail.to_string(),
                });
            })
        };
        let control = DoorbellControl::new();
        let held = Held {
            caller: &caller,
            connection: &connection,
            session,
            peer_key: fixture.house_key,
            hold: Hold::For(Duration::from_secs(18)),
            no_punch: true,
            control: &control,
            diagnostics: &caller_diagnostics,
            events: Some(sink),
            candidates: None,
            vouch_peer: true,
        }
        .spawn();

        caller_events
            .wait_for(VisitEventKind::VisitOpen, Duration::from_secs(10))
            .await
            .expect("the visit must open on the relay");

        // Out, then back inside quinn's own 30 s idle timeout, so the
        // connection under the visit survives the outage that the liveness
        // above it declares dead.
        let gate_addr = caller.gate_connection().remote_address();
        caller.porch().detach_gate(gate_addr);
        caller_events
            .wait_for(VisitEventKind::PathDead, Duration::from_secs(20))
            .await
            .expect("the caller must declare the relay dead first");
        caller.porch().attach_gate(caller.gate_connection().clone());

        let recovered = caller_events
            .wait_for(VisitEventKind::Recovered, Duration::from_secs(15))
            .await
            .expect("a relay that answers again must be seen answering again");
        assert!(
            recovered.detail.contains("relay"),
            "the event names the path that came back: {}",
            recovered.detail
        );

        let record = tokio::time::timeout(Duration::from_secs(40), held)
            .await
            .expect("the caller's hold must end")
            .unwrap();
        assert_eq!(
            record.reason,
            Reason::PunchDisabled,
            "a visit that outlived its outage is not reported by it: {:?}",
            record.steps
        );

        connection.close(0u32.into(), b"test over");
        let _ = std::fs::remove_dir_all(&caller_diagnostics);
        fixture.stop().await;
    }

    /// Yseult's High on PR 89: a house holding two relayed visits at once
    /// keeps both of them, and neither doorbell eats the other's pongs.
    ///
    /// There is one porch socket per house and one doorbell per visit.
    /// Before the probe queue was keyed by attempt, each doorbell drained
    /// the one queue to empty and threw away whatever was not its own, so
    /// with section 4 now probing every relayed visit twice a second, two
    /// friends visiting one house took roughly half of each other's
    /// answers. Three misses is stale, dead is absorbing, and on the relay
    /// there is no fall back, so a healthy visit was reported dead and then
    /// stopped being watched at all. Two friends visiting one house is the
    /// product, not an edge case.
    ///
    /// Six seconds is three times the stale deadline and twelve probe
    /// intervals, so a queue either side was stealing from would have gone
    /// stale several times over inside it.
    ///
    /// Deliberate break to fail this test: in `run_doorbell`, replace
    /// `porch.try_recv_probe(&attempt)` with a drain of every attempt
    /// followed by `if probe.attempt != attempt { continue; }`, which is
    /// the code before this fix. Both visits then miss probes and at least
    /// one reports `path_stale` well inside the six seconds.
    #[tokio::test]
    async fn two_relayed_visits_on_one_house_do_not_eat_each_others_probes() {
        let (fixture, first_seed) = Fixture::start("twovisits", true).await;
        let second_seed = fixture.second_seed;
        let (first, first_connection, first_session) = fixture.call(first_seed).await;
        let (second, second_connection, second_session) = fixture.call(second_seed).await;

        let mut held = Vec::new();
        let mut controls = Vec::new();
        let mut dirs = Vec::new();
        for (name, caller, connection, session) in [
            ("twovisits-first", &first, &first_connection, first_session),
            (
                "twovisits-second",
                &second,
                &second_connection,
                second_session,
            ),
        ] {
            let diagnostics = diag_dir(name);
            let control = DoorbellControl::new();
            held.push(
                Held {
                    caller,
                    connection,
                    session,
                    peer_key: fixture.house_key,
                    hold: Hold::For(Duration::from_secs(7)),
                    no_punch: true,
                    control: &control,
                    diagnostics: &diagnostics,
                    events: None,
                    candidates: None,
                    vouch_peer: true,
                }
                .spawn(),
            );
            controls.push(control);
            dirs.push(diagnostics);
        }

        // Both visits open on the callee, which is the only side that runs
        // two doorbells against one socket.
        let opened = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if fixture
                    .events
                    .kinds()
                    .iter()
                    .filter(|kind| **kind == VisitEventKind::VisitOpen)
                    .count()
                    >= 2
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            opened.is_ok(),
            "both visits must open: {:?}",
            fixture.events.kinds()
        );

        tokio::time::sleep(Duration::from_secs(6)).await;

        assert!(
            !fixture.events.kinds().contains(&VisitEventKind::PathStale),
            "neither of the callee's two visits may go stale while both relays answer: {:?}",
            fixture.events.kinds()
        );
        assert!(
            !fixture.events.kinds().contains(&VisitEventKind::PathDead),
            "and certainly neither may be called dead: {:?}",
            fixture.events.kinds()
        );

        for handle in held {
            let record = tokio::time::timeout(Duration::from_secs(20), handle)
                .await
                .expect("each hold must end")
                .unwrap();
            assert_eq!(
                record.reason,
                Reason::PunchDisabled,
                "a visit nobody interrupted ends on the flag it ran under: {:?}",
                record.steps
            );
        }

        first_connection.close(0u32.into(), b"test over");
        second_connection.close(0u32.into(), b"test over");
        for dir in dirs {
            let _ = std::fs::remove_dir_all(&dir);
        }
        drop(controls);
        fixture.stop().await;
    }

    /// Yseult's uncovered case: a knock from a member of the community
    /// who is not on this house's friend list produces nothing at all.
    ///
    /// Not a decline, not a line on stdout, not a record: section 1 makes
    /// a decline, a tag that matched nobody and a house that never
    /// answered one silence, and the house's own stdout must not be the
    /// oracle the protocol refuses to be.
    ///
    /// Deliberate break to fail this test: emit `KnockAccepted` in
    /// `answer_knock` before the `friends.is_friend(&body.from)` decision
    /// rather than after it. The house then prints a `knock` line for a
    /// stranger and the event assertion fails.
    #[tokio::test]
    async fn a_knock_from_a_member_who_is_not_a_friend_says_nothing_at_all() {
        let (fixture, _caller_seed) = Fixture::start("stranger", false).await;
        let stranger = fixture.connect(fixture.stranger_seed).await;

        // The gate forwards the knock (this key is a member); the house
        // opens the seal, finds no friend, and stays silent, so the
        // asker's only answer is its own `ttl_s` elapsing.
        let refused = stranger.introduce(fixture.house_key, 3, None).await;
        assert!(
            refused.is_err(),
            "a stranger must get silence, which reads as introduce_timeout"
        );

        assert_eq!(
            fixture.events.kinds(),
            vec![VisitEventKind::Registered],
            "the house said it registered and nothing else"
        );
        assert!(
            records_in(&fixture.house_diagnostics).is_empty(),
            "a knock that was never accepted is not an attempt, so it is not a record"
        );
        fixture.stop().await;
    }

    /// Yseult's Medium 1: one friend cannot fill every slot this house
    /// has, and a refusal says so out loud.
    ///
    /// One relay session carries as many end to end connections as its
    /// peer opens, so the cap that matters is on visits and not on
    /// sessions. The third connection from one peer is refused, and the
    /// two before it go on running.
    ///
    /// Deliberate break to fail this test: remove the
    /// `MAX_VISITS_PER_PEER` check from `Visit::serve`. The third dial
    /// then becomes a third visit and no `refused` line is printed.
    #[tokio::test]
    async fn one_peer_cannot_take_more_than_its_share_of_the_visits() {
        let (fixture, caller_seed) = Fixture::start("percap", false).await;
        let (caller, first, _session) = fixture.call(caller_seed).await;

        // Two more end to end connections over the same relay session,
        // which is what a peer opening connections in a loop looks like.
        let second = caller.dial_peer(&fixture.house_key).await.unwrap();
        let third = caller.dial_peer(&fixture.house_key).await.unwrap();

        let refused = fixture
            .events
            .wait_for(VisitEventKind::Refused, Duration::from_secs(15))
            .await
            .expect("the third visit from one peer must be refused");
        assert!(
            refused.detail.contains("no room for this peer"),
            "the refusal says which cap it hit: {}",
            refused.detail
        );
        assert!(
            refused.peer.is_some(),
            "a refusal after the handshake names the peer it refused"
        );
        let opened = fixture
            .events
            .kinds()
            .into_iter()
            .filter(|kind| *kind == VisitEventKind::VisitOpen)
            .count();
        assert_eq!(opened, mosschat_net::house::MAX_VISITS_PER_PEER, "{opened}");

        for connection in [&first, &second, &third] {
            connection.close(0u32.into(), b"test over");
        }
        fixture.stop().await;
    }

    /// Yseult's other uncovered case: `accept_peer` refuses a dial from a
    /// key this house never had introduced to it.
    ///
    /// This deliberately steps past the *first* gate to exercise the
    /// second. Section 3's porch socket drops a datagram whose source is
    /// in no peer's candidate table, so an uninvited dial normally never
    /// reaches quinn at all; the test hands that source a lease
    /// (`allow_source`) so the handshake happens and `accept_peer`'s own
    /// check is the thing under test.
    ///
    /// The other half of that check, a proven key with no relay path, is
    /// not reachable from outside: it needs a gate that forwards a
    /// session's datagrams for a third key, which `forward_relay` refuses.
    /// It stays as belt to this braces.
    ///
    /// Deliberate break to fail this test: return the connection from
    /// `accept_peer` without the `path_by_synthetic` check. The dial then
    /// becomes a visit from a house nobody introduced.
    #[tokio::test]
    async fn accept_peer_refuses_a_dial_from_a_key_it_never_introduced() {
        let (fixture, caller_seed) = Fixture::start("uninvited", false).await;
        // A house-side client of our own, so the refusal is observed
        // directly rather than through the headless house's task.
        let victim = fixture.connect(caller_seed).await;
        let victim_addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            victim.porch().local_addr().unwrap().port(),
        );

        mosschat_net::authed::install_crypto_provider();
        let stranger_seed = random_seed();
        let (cert, key) = mosschat_net::authed::self_signed_cert(&stranger_seed).unwrap();
        let tls = mosschat_net::authed::client_tls_config(cert, key, b"moss-gate").unwrap();
        let mut stranger = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        stranger.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        )));
        let stranger_addr = stranger.local_addr().unwrap();

        // Past the first gate, on purpose and only for this test.
        let _lease = victim.porch().allow_source(stranger_addr);
        let dial = tokio::spawn(async move {
            let _ = stranger.connect(victim_addr, "peer").unwrap().await;
            stranger
        });

        let incoming = tokio::time::timeout(Duration::from_secs(10), victim.endpoint().accept())
            .await
            .expect("the dial must arrive")
            .expect("the endpoint is open");
        let refused = victim.accept_peer(incoming).await;
        assert!(
            refused.is_err(),
            "a dial from a key with no relay path must be refused"
        );

        let _ = tokio::time::timeout(Duration::from_secs(5), dial).await;
        fixture.stop().await;
    }

    /// Yseult's Medium 3 and the wire flag that answers it: `--no-punch`
    /// on one side alone leaves the *other* side honest.
    ///
    /// Before frame 16 carried the intent, a `--no-punch` caller left its
    /// peer waiting out the whole 10 s start window for a `Start` nobody
    /// asked for, recording `start_signal / fail` and settling
    /// `internal`, which amendment 4's own words call the opposite of a
    /// path taken on purpose. WO-1.5's case (e) row puts the flag on the
    /// caller, so this is the row's own shape.
    ///
    /// Deliberate break to fail this test: stop reading `no_upgrade` in
    /// `run_doorbell` (treat it as `false`). The house then waits out the
    /// start window and its record names a failed step.
    #[tokio::test]
    async fn one_sided_no_punch_leaves_the_peer_honest_too() {
        let (fixture, caller_seed) = Fixture::start("onesided", false).await;
        let (caller, connection, session) = fixture.call(caller_seed).await;

        let caller_diagnostics = diag_dir("onesided-caller");
        let control = DoorbellControl::new();
        let held = Held {
            caller: &caller,
            connection: &connection,
            session,
            peer_key: fixture.house_key,
            hold: Hold::For(Duration::from_secs(3)),
            // Only this side is told not to punch. The house was started
            // without the flag.
            no_punch: true,
            control: &control,
            diagnostics: &caller_diagnostics,
            events: None,
            candidates: None,
            vouch_peer: true,
        }
        .spawn();

        let record = tokio::time::timeout(Duration::from_secs(30), held)
            .await
            .expect("the caller's hold must end")
            .unwrap();
        assert_eq!(record.reason, Reason::PunchDisabled);
        connection.close(0u32.into(), b"test over");

        // The house's own record for the same visit, once its side has
        // settled. It is written when the visit ends, which is the peer's
        // goodbye arriving.
        let house_record = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(record) = records_in(&fixture.house_diagnostics).into_iter().next() {
                    return record;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the house must write its own record for the visit");

        assert_eq!(
            house_record.reason,
            Reason::PunchDisabled,
            "the peer names the flag, not a failure of its own: {:?}",
            house_record.steps
        );
        assert_eq!(
            house_record.failed_step, None,
            "nothing failed on the house's side: {:?}",
            house_record.steps
        );
        assert!(
            !house_record.steps.iter().any(|step| {
                step.step == mosschat_net::diag::Step::StartSignal
                    && step.outcome == mosschat_net::diag::StepOutcome::Fail
            }),
            "the house waited out a start signal nobody asked for: {:?}",
            house_record.steps
        );
        assert!(
            !fixture.events.kinds().contains(&VisitEventKind::Upgraded),
            "neither side probed"
        );

        let _ = std::fs::remove_dir_all(&caller_diagnostics);
        fixture.stop().await;
    }

    /// Wystan's D1, end to end: a hold shorter than section 2 step 5's ten
    /// second give-up must name the same reason a longer one does.
    ///
    /// The visit here has nothing probeable on purpose: this caller
    /// offers no candidates and withholds the gate's observation of its
    /// peer, so the peer's own private-range address is refused
    /// (`Attempt::add_candidate`) and the table is empty. A three second
    /// hold ends the visit long before the burst gives up, and the record
    /// must still say `no_candidates` rather than `path_idle_timeout`,
    /// whose own doc means a path that was had and lost.
    ///
    /// Deliberate break to fail this test: delete the `if !ever_upgraded`
    /// arm from `end_of_visit_reason`.
    #[tokio::test]
    async fn a_hold_shorter_than_the_give_up_still_names_what_happened() {
        let (fixture, caller_seed) = Fixture::start("shorthold", false).await;
        let (caller, connection, session) = fixture.call(caller_seed).await;

        let caller_diagnostics = diag_dir("shorthold-caller");
        let control = DoorbellControl::new();
        let held = Held {
            caller: &caller,
            connection: &connection,
            session,
            peer_key: fixture.house_key,
            hold: Hold::For(Duration::from_secs(3)),
            no_punch: false,
            control: &control,
            diagnostics: &caller_diagnostics,
            events: None,
            candidates: Some(Vec::new()),
            vouch_peer: false,
        }
        .spawn();

        let record = tokio::time::timeout(Duration::from_secs(30), held)
            .await
            .expect("the caller's hold must end")
            .unwrap();
        assert_ne!(
            record.reason,
            Reason::PathIdleTimeout,
            "a visit that never had a direct path cannot have lost one: {:?}",
            record.steps
        );
        assert_eq!(
            record.reason,
            Reason::NoCandidates,
            "nothing was probeable, and that is what the record must say. \
             (A machine whose own primary address is globally routable would \
             see probe_timeout here instead, since the peer's address would \
             then be admissible: {:?})",
            record.steps
        );
        assert!(record.failed_step.is_some(), "the burst had nothing to do");

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
            candidates: None,
            vouch_peer: true,
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
