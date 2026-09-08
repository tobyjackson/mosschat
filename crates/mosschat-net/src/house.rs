//! The house role, headless: `mosschat house --headless` (D1's second of
//! three roles), in the smallest honest form WO-1.5a needs.
//!
//! **What it is for.** WO-1.5 measures a live visit: RTT median and p95
//! over a hold, recovery after a 60 second drop, detection and fall-back
//! times when a direct path dies. None of those can be measured against a
//! peer that does not exist, and before this module nothing in the
//! workspace stayed running and answered a knock: `doctor --friend` is
//! one-shot and is always the caller. This is the callee, and nothing
//! more.
//!
//! **What it is not.** No store, no door socket, no messages, no presence,
//! no discovery: those are Phase 2 and later, and a house that grew them
//! here would be a house nobody designed. It holds an identity, registers
//! at a gate, answers knocks from a friend list, runs section 2's doorbell
//! and section 4's liveness on every visit, prints what happened, and
//! leaves.
//!
//! **What it prints.** One JSON object per line on stdout, one line per
//! event, in the vocabulary [`crate::diag::VisitEventKind`] fixes, so a
//! two-machine run's two sides can be read against each other without a
//! translation table. Section 7's redaction applies to every line: a peer
//! is the 8 hex characters of its salted fingerprint and never a key, and
//! addresses are kept because they are the thing being diagnosed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::diag::{
    self, DiagSink, InstallSalt, PeerFingerprint, Recorder, Step, StepOutcome, VisitEventKind,
};
use crate::gate::GateError;
use crate::gate::client::{FriendStore, GateClient, GateEvent, InMemoryInviteStore};
use crate::lockext::LockExt as _;
use crate::punch::{DoorbellControl, DoorbellParams, Hold, VisitEventSink, run_doorbell};

/// How long a visit waits for the introduction that explains it.
///
/// A peer's dial and the `Introduction` that names its session arrive on
/// two different connections, so either can win the race. Five seconds is
/// far past the milliseconds the two are normally apart and well under the
/// gate's own `Introduce.ttl_s` cap of 60, so a dial with no introduction
/// behind it is refused rather than held.
const SESSION_WAIT: Duration = Duration::from_secs(5);

/// How many visits this house holds at once.
///
/// Section 1 caps a registration at 8 live sessions at the gate, so 8 is
/// the ceiling the protocol already imposes on how many peers can have
/// been introduced to this house at one time. It is not a ceiling on
/// *connections*: one relay session carries as many end to end QUIC
/// connections as its peer opens, quinn demultiplexes them by connection
/// id, and the porch presents every one of them at the same synthetic
/// address, so without this an accepted friend could spawn a task, a
/// recorder and a stdout line per connection for as long as it liked
/// (Yseult's Medium 1). Past it a dial is refused, said so on stdout, and
/// the connection closed.
pub const MAX_LIVE_VISITS: usize = crate::gate::limits::MAX_SESSIONS_PER_REGISTRATION;

/// How many visits one peer holds at once.
///
/// 2, not 1: a peer that reconnects while its previous visit is still
/// tearing down is ordinary, and refusing that would make a flapping
/// friend unreachable. More than that is not something this design has a
/// use for, and letting one friend fill all [`MAX_LIVE_VISITS`] slots is
/// letting it lock every other friend out of a house that is home.
pub const MAX_VISITS_PER_PEER: usize = 2;

/// How long a stopping house gives its visits to say goodbye.
///
/// Each visit writes one frame and waits for its acknowledgement on the
/// one second budget [`crate::punch`] gives it, so two seconds covers
/// that plus the record each one writes; past it the process leaves
/// anyway, because a house that will not exit on `SIGTERM` is worse than
/// one whose last goodbye was late.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// What a headless house needs to run.
pub struct HouseConfig {
    /// This house's ed25519 identity seed.
    pub identity_seed: [u8; 32],
    /// The community this house registers for.
    pub community: [u8; 32],
    /// The gate's primary address.
    pub gate: SocketAddr,
    /// The gate's public key, pinned if given (`None` is
    /// trust-on-first-connect, the same rule [`GateClient::connect`] has).
    pub gate_key: Option<[u8; 32]>,
    /// Whose knocks this house answers.
    pub friends: Arc<dyn FriendStore>,
    /// WO-1.5 case (e): answer knocks and hold visits, but never probe, so
    /// every visit stays on the relay.
    pub no_punch: bool,
    /// Where this house writes one diagnostics record per visit, or `None`
    /// to write none. The install salt beside it is what redacts every
    /// peer this house names, on stdout as well as in the log, so a house
    /// with no directory prints the all-zero fingerprint rather than a key.
    pub diagnostics: Option<PathBuf>,
}

/// One line of a house's stdout.
#[derive(Debug, Clone)]
pub struct HouseEvent {
    /// Milliseconds since the Unix epoch, UTC, when this happened.
    pub at_ms: u64,
    /// What happened.
    pub kind: VisitEventKind,
    /// The peer it happened with, redacted (section 7), or `None` for a
    /// house-wide event with no peer.
    pub peer: Option<PeerFingerprint>,
    /// The path, the address, the round trip: whatever the event carries,
    /// in the same words the record's own `events[]` entry uses.
    pub detail: String,
}

impl HouseEvent {
    /// This event as one line of JSON, no trailing newline.
    ///
    /// Four fields, always the same four, because a reader that has to ask
    /// which keys an event carries is a reader that will get it wrong:
    /// `ts_ms`, `event`, `peer` (null for a house-wide event) and
    /// `detail`.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        let value = serde_json::json!({
            "ts_ms": self.at_ms,
            "event": self.kind.as_str(),
            "peer": self.peer.map(|peer| peer.as_hex()),
            "detail": self.detail,
        });
        // The same reasoning as `DiagRecord::to_json_line`: `to_string`
        // fails only on a non-finite float or a non-string map key,
        // neither of which this value can contain, and the fallback keeps
        // this function panic-free (invariant 1) rather than asserting
        // that stays true forever.
        serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Where a house's events go. The binary prints them; a test collects
/// them.
pub type HouseEventSink = Arc<dyn Fn(HouseEvent) + Send + Sync>;

/// A sink that prints one JSON line per event on stdout.
///
/// Line buffered by `println!`'s own lock and flushed by the newline, so a
/// harness reading this process's stdout through a pipe sees each event as
/// it happens rather than a block of them at exit.
#[must_use]
pub fn print_events() -> HouseEventSink {
    Arc::new(|event: HouseEvent| {
        println!("{}", event.to_json_line());
    })
}

/// Runs a headless house until `shutdown` completes.
///
/// Registers at the gate, answers knocks from the friend list by itself
/// (the gate client does that against [`HouseConfig::friends`]), and runs
/// one visit per peer that is introduced and dials: section 2's doorbell
/// and section 4's liveness, held open until the peer leaves.
///
/// On `shutdown` every open visit is asked to stop, which sends frame 19
/// on its own porch stream, and the registration is given back with frame
/// 11, so neither the gate nor a friend is left believing this house is
/// home.
///
/// # Errors
///
/// Returns a [`GateError`] if the identity cannot be presented, the gate
/// cannot be reached, or it refuses the registration. Once registered,
/// nothing a single visit does ends the house.
pub async fn run(
    config: HouseConfig,
    events: HouseEventSink,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), GateError> {
    let salt = match config.diagnostics.as_ref() {
        Some(dir) => InstallSalt::load_or_create(dir)
            .map_err(|e| GateError::Protocol(format!("diagnostics directory: {e}")))?,
        // No directory, so no salt file to persist one in: this run's
        // peers are named consistently within it and differently after a
        // restart, which is the honest cost of keeping no state. Section
        // 7's redaction still holds either way, which is what the
        // fingerprint is for.
        None => InstallSalt::ephemeral(),
    };
    let sink = match config.diagnostics.as_ref() {
        Some(dir) => Some(
            DiagSink::new(dir.clone())
                .map_err(|e| GateError::Protocol(format!("diagnostics directory: {e}")))?,
        ),
        None => None,
    };

    let client = Arc::new(
        GateClient::connect(
            config.gate,
            config.identity_seed,
            config.community,
            config.gate_key,
            Arc::clone(&config.friends),
            Arc::new(InMemoryInviteStore::new()),
        )
        .await?,
    );
    let mut gate_events = client
        .events()
        .ok_or_else(|| GateError::Protocol("this client's events were already taken".into()))?;

    emit(
        &events,
        VisitEventKind::Registered,
        None,
        format!(
            "house {house}, gate {gate}, observed {observed}, secondary port {secondary}",
            // This house's own public key, in full, because a friend
            // needs it to knock and nothing else prints it. Section 7's
            // redaction is about naming *peers* in a log that gets pasted
            // into an issue; a house's own public key is the thing it
            // hands out, the gatehouse prints its community id for the
            // same reason, and this line is stdout only, never a record.
            house = hex32(&client.public_key()),
            gate = config.gate,
            observed = client.registered_observed(),
            secondary = client.registered_secondary_port(),
        ),
    );

    // The session a peer was introduced under, so the visit its dial
    // starts knows which relay session it belongs to. One entry per peer,
    // overwritten by each introduction, bounded by section 1's own cap on
    // how many sessions a registration may hold.
    let sessions: Arc<Mutex<HashMap<[u8; 32], u32>>> = Arc::new(Mutex::new(HashMap::new()));
    // Every live visit's control, so a stopping house can say goodbye on
    // all of them. Keyed by a counter rather than by peer: the same friend
    // can be visiting twice, and a visit removes its own entry when it
    // ends, so this does not grow with uptime.
    let controls: Arc<Mutex<HashMap<u64, Arc<DoorbellControl>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // How many visits each peer currently holds, so one friend cannot
    // fill every slot. Counted once its key is proven, which is the first
    // moment there is a peer to count, and given back when the visit ends
    // however it ends.
    let peers: Arc<Mutex<HashMap<[u8; 32], usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut next_visit = 0u64;
    let mut visits = tokio::task::JoinSet::new();
    let endpoint = client.endpoint();

    let shutdown = std::pin::pin!(shutdown);
    let mut shutdown = shutdown;
    loop {
        tokio::select! {
            // Biased so a stop is taken before another visit is started:
            // an accept that wins the race would be a visit opened by a
            // house already on its way out.
            biased;
            () = &mut shutdown => break,
            event = gate_events.recv() => {
                let Some(event) = event else { break };
                match event {
                    GateEvent::KnockAccepted { peer_key } => {
                        emit(
                            &events,
                            VisitEventKind::Knock,
                            Some(PeerFingerprint::from_key(&salt, &peer_key)),
                            "accepted: a friend on this house's list",
                        );
                    }
                    GateEvent::Introduced { session, peer_key, .. } => {
                        sessions.lock_or_recover().insert(peer_key, session);
                    }
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let live = controls.lock_or_recover().len();
                if live >= MAX_LIVE_VISITS {
                    // Refused before a handshake is spent on it, and said
                    // out loud: a house that quietly stopped answering
                    // would look to its friends exactly like a house that
                    // had gone away.
                    incoming.refuse();
                    emit(
                        &events,
                        VisitEventKind::Refused,
                        None,
                        format!(
                            "no room: this house already holds {live} visits, the most it will \
                             ({MAX_LIVE_VISITS})"
                        ),
                    );
                    continue;
                }
                let control = DoorbellControl::new();
                let id = next_visit;
                next_visit = next_visit.saturating_add(1);
                controls.lock_or_recover().insert(id, Arc::clone(&control));
                let visit = Visit {
                    id,
                    client: Arc::clone(&client),
                    sessions: Arc::clone(&sessions),
                    peers: Arc::clone(&peers),
                    controls: Arc::clone(&controls),
                    events: Arc::clone(&events),
                    sink: sink.clone(),
                    salt,
                    no_punch: config.no_punch,
                    control,
                    counted: Mutex::new(None),
                };
                visits.spawn(async move { visit.run(incoming).await });
            }
            Some(_) = visits.join_next(), if !visits.is_empty() => {}
        }
    }

    // Every open visit says goodbye on its own porch stream (frame 19),
    // then the registration goes back (frame 11). In that order: a friend
    // that learns this house left before the gate does is a friend that
    // stops probing a path that is gone, and section 4 makes the goodbye
    // the difference between dead at once and dead after the grace.
    for control in controls.lock_or_recover().values() {
        control.stop();
    }
    let _ = tokio::time::timeout(SHUTDOWN_GRACE, async {
        while visits.join_next().await.is_some() {}
    })
    .await;
    visits.shutdown().await;
    let _ = client.goodbye(GOODBYE_HOUSE_STOPPING).await;
    Ok(())
}

/// The `Goodbye.reason` a house leaving on purpose sends. Section 1
/// defines no enum of values for the field, so 0 is the plain clean exit
/// every caller in this workspace uses.
const GOODBYE_HOUSE_STOPPING: u8 = 0;

/// One visit, from a peer's dial to its end.
struct Visit {
    id: u64,
    client: Arc<GateClient>,
    sessions: Arc<Mutex<HashMap<[u8; 32], u32>>>,
    peers: Arc<Mutex<HashMap<[u8; 32], usize>>>,
    controls: Arc<Mutex<HashMap<u64, Arc<DoorbellControl>>>>,
    events: HouseEventSink,
    sink: Option<Arc<DiagSink>>,
    salt: InstallSalt,
    no_punch: bool,
    control: Arc<DoorbellControl>,
    /// The peer this visit charged a slot to, once its key was proven, so
    /// [`Visit::run`] gives back exactly what [`Visit::serve`] took and
    /// nothing when it took nothing.
    counted: Mutex<Option<[u8; 32]>>,
}

impl Visit {
    /// Accepts `incoming`, runs the doorbell for it as the responder, and
    /// takes its control and its peer's slot out of the house's tables
    /// however it ends.
    async fn run(self, incoming: quinn::Incoming) {
        let outcome = self.serve(incoming).await;
        if let Err(err) = outcome {
            // A failed visit is one visit, never the house: a peer that
            // dials and cannot finish a handshake must not take the
            // registration down with it.
            //
            // The text is capped and stripped (Yseult's Low 5): a
            // `GateError::Connection` renders the peer's own QUIC close
            // reason, which is up to a packet's worth of bytes it chose,
            // and this line goes on a stdout the harness tells an
            // operator to keep.
            emit(
                &self.events,
                VisitEventKind::Refused,
                None,
                format!(
                    "the visit ended without opening: {}",
                    diag::safe_text(&err.to_string())
                ),
            );
        }
        self.controls.lock_or_recover().remove(&self.id);
        if let Some(peer_key) = self.counted.lock_or_recover().take() {
            let mut peers = self.peers.lock_or_recover();
            if let Some(held) = peers.get_mut(&peer_key) {
                *held = held.saturating_sub(1);
                if *held == 0 {
                    peers.remove(&peer_key);
                }
            }
        }
    }

    async fn serve(&self, incoming: quinn::Incoming) -> Result<(), GateError> {
        let (peer_key, connection) = self.client.accept_peer(incoming).await?;
        let peer = PeerFingerprint::from_key(&self.salt, &peer_key);
        // The per-peer cap, taken the moment there is a proven key to
        // charge it to. One friend must not be able to fill every slot
        // this house has (Yseult's Medium 1).
        {
            let mut peers = self.peers.lock_or_recover();
            let held = peers.entry(peer_key).or_insert(0);
            if *held >= MAX_VISITS_PER_PEER {
                let held = *held;
                drop(peers);
                connection.close(0u32.into(), b"too many visits from this peer");
                emit(
                    &self.events,
                    VisitEventKind::Refused,
                    Some(peer),
                    format!(
                        "no room for this peer: it already holds {held} visits, the most one \
                         peer will ({MAX_VISITS_PER_PEER})"
                    ),
                );
                return Ok(());
            }
            *held = held.saturating_add(1);
        }
        *self.counted.lock_or_recover() = Some(peer_key);
        let Some(session) = self.wait_for_session(&peer_key).await else {
            // The introduction never arrived. It is worth saying how many
            // the client had to drop, because a full event queue is the
            // one way this happens with nothing else wrong, and it was
            // silent before (Yseult's Low 6).
            connection.close(0u32.into(), b"no introduction for this dial");
            emit(
                &self.events,
                VisitEventKind::Refused,
                Some(peer),
                format!(
                    "no introduction arrived for this dial inside {} s ({} gate events dropped \
                     so far)",
                    SESSION_WAIT.as_secs(),
                    self.client.events_dropped(),
                ),
            );
            return Ok(());
        };

        let recorder = Recorder::new(peer, self.sink.clone());
        diag::record(
            Some(&recorder),
            Step::RelayOpen,
            StepOutcome::Ok,
            format!("relay session {session}, as the responder"),
        );
        diag::record(
            Some(&recorder),
            Step::PeerHandshake,
            StepOutcome::Ok,
            "the peer's end to end connection is open over the relay",
        );

        let events = Arc::clone(&self.events);
        let visit_events = VisitEventSink::new(move |kind, detail| {
            events(HouseEvent {
                at_ms: crate::gate::now_ms(),
                kind,
                peer: Some(peer),
                detail: detail.to_string(),
            });
        });

        // Section 2 step 1: every local address plus the gate's reflection
        // of this house, de-duplicated and capped at 16. No discovery:
        // section 6 is not wired into this role, so a same-LAN pair
        // upgrades through its ordinary local candidates or not at all.
        let local = crate::punch::local_addresses(self.client.local_port().unwrap_or_default());
        let reflections = [self.client.registered_observed()];
        let candidates = crate::punch::gather(&local, &reflections, &[])
            .into_iter()
            .map(|(addr, _source)| addr)
            .collect();

        let params = DoorbellParams {
            session,
            role: 2,
            peer_key,
            candidates,
            peer_observed: self.client.peer_observed_for(session),
            peer_discovered: Vec::new(),
            hold: Hold::UntilPeerLeaves,
            no_punch: self.no_punch,
            events: Some(visit_events),
            recorder: Some(recorder),
        };
        let result = run_doorbell(
            &self.client.porch(),
            &self.client,
            &connection,
            params,
            &self.control,
        )
        .await;
        connection.close(0u32.into(), b"visit over");
        result.map(|_outcome| ())
    }

    /// Waits for the introduction that names this peer's session, up to
    /// [`SESSION_WAIT`].
    ///
    /// Polled rather than woken: the introduction arrives on the gate
    /// client's own reader task and this is the one place that cares,
    /// once per visit.
    async fn wait_for_session(&self, peer_key: &[u8; 32]) -> Option<u32> {
        let deadline = tokio::time::Instant::now() + SESSION_WAIT;
        loop {
            if let Some(session) = self.sessions.lock_or_recover().get(peer_key).copied() {
                return Some(session);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

/// 32 bytes as lowercase hex.
fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hands one house-level event to the sink with the clock read at the
/// moment it happened.
fn emit(
    events: &HouseEventSink,
    kind: VisitEventKind,
    peer: Option<PeerFingerprint>,
    detail: impl Into<String>,
) {
    events(HouseEvent {
        at_ms: crate::gate::now_ms(),
        kind,
        peer,
        detail: detail.into(),
    });
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    /// Section 7's redaction, on stdout as much as in the log: a house's
    /// event line names a peer by its 8 character fingerprint and carries
    /// no key.
    ///
    /// Deliberate break to fail this test: put `hex(peer_key)` in
    /// `HouseEvent::peer` instead of a [`PeerFingerprint`], which the type
    /// system already refuses; this test is what says the printed form is
    /// the redacted one.
    #[test]
    fn an_event_line_names_a_peer_by_fingerprint_and_carries_no_key() {
        let dir = std::env::temp_dir().join(format!("konrad15a-house-{}", std::process::id()));
        let salt = InstallSalt::load_or_create(&dir).unwrap();
        let key = [7u8; 32];
        let event = HouseEvent {
            at_ms: 1_757_000_000_000,
            kind: VisitEventKind::VisitOpen,
            peer: Some(PeerFingerprint::from_key(&salt, &key)),
            detail: "relay through 203.0.113.1:443".to_string(),
        };
        let line = event.to_json_line();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["event"], "visit_open");
        assert_eq!(value["ts_ms"], 1_757_000_000_000u64);
        assert_eq!(
            value["peer"].as_str().unwrap().len(),
            8,
            "a peer is 8 hex characters, never a key: {line}"
        );
        let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!line.contains(&key_hex), "{line}");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A house-wide event carries no peer at all rather than a made-up
    /// one.
    #[test]
    fn a_house_wide_event_has_a_null_peer() {
        let event = HouseEvent {
            at_ms: 1,
            kind: VisitEventKind::Registered,
            peer: None,
            detail: "gate 203.0.113.1:443".to_string(),
        };
        let value: serde_json::Value = serde_json::from_str(&event.to_json_line()).unwrap();
        assert!(value["peer"].is_null());
        assert_eq!(value["event"], "registered");
    }
}
