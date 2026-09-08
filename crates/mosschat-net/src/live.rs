//! Liveness: `docs/dev/gatehouse-design.md` section 4.
//!
//! quinn does not know a router's UDP timer, so this policy is ours
//! (research lesson 8, Reticulum lesson 4). The firewall assumption is
//! research B's 30 seconds, and every `srtt` here is the path table's own
//! ([`crate::path::PathEntry::srtt`]), never `quinn::Connection::rtt()`,
//! for the reason section 3 gives: quinn's estimator stays stale for
//! several samples after a fall-back and would stretch the very timers
//! meant to catch it.
//!
//! What this module holds: section 4's intervals as functions of that
//! `srtt` ([`keepalive_interval`], [`probe_loss_deadline`],
//! [`dead_grace`]), the live/stale/dead state machine and the last-seen
//! reason it produces ([`PeerLiveness`], [`LastSeen`]), the explicit
//! goodbye of frame 19 ([`send_goodbye`], [`apply_porch_frame`]), and the
//! cached-address expiry whose failed dial triggers rediscovery rather
//! than a retry ([`AddressCache`]). quinn's own idle timeout and keepalive,
//! set so the two policies do not fight, are [`MAX_IDLE_TIMEOUT`] and
//! [`KEEP_ALIVE_INTERVAL`], applied in [`crate::path::peer_transport_config`].
//!
//! Like [`crate::punch::Attempt`], nothing here owns a clock: every method
//! takes the `now` its caller read, so section 4's whole timing is
//! exercised below without a sleep, a timer or any load.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::gate::GateError;
use crate::punch::{CandidateSource, PorchFrame, write_porch_frame};

// ----------------------------------------------------------------------
// Section 4's numbers
// ----------------------------------------------------------------------

/// Research B's firewall assumption: the UDP mapping a router is assumed
/// to drop an idle flow after. Every keepalive number below is derived
/// from it rather than chosen next to it.
pub const FIREWALL_ASSUMPTION: Duration = Duration::from_secs(30);

/// Section 4: the keepalive on an idle direct path is `8 * srtt`, clamped.
/// srtt scaling backs a slow path off before a fast one.
pub const KEEPALIVE_SRTT_MULTIPLIER: u32 = 8;

/// The keepalive floor: below 5 s we spend packets and radio wakeups for
/// no gain, and it matches Reticulum's clamp.
pub const KEEPALIVE_FLOOR: Duration = Duration::from_secs(5);

/// The keepalive ceiling: half [`FIREWALL_ASSUMPTION`], so two consecutive
/// losses still cannot let the mapping expire. The real timeout is WO-1.5
/// item 3, so this is a starting value.
pub const KEEPALIVE_CEILING: Duration = Duration::from_secs(15);

/// Section 4, during a live visit: one probe every 500 ms, because death
/// detection beats packet count while people talk.
pub const VISIT_PROBE_INTERVAL: Duration = Duration::from_millis(500);

/// Section 4: three consecutive probes unanswered make a path stale.
/// Three because at 5 percent loss that is a 1 in 8000 false alarm.
pub const PROBES_TO_STALE: u32 = 3;

/// The floor on how long a probe waits before it counts as lost, section
/// 4's `max(4 * srtt, 500 ms)`. At 500 ms, three of them land in about
/// 1.5 s.
pub const PROBE_LOSS_FLOOR: Duration = Duration::from_millis(500);

/// The `4 * srtt` half of both `max(4 * srtt, 500 ms)` and the dead grace.
pub const LOSS_SRTT_MULTIPLIER: u32 = 4;

/// The fixed part of section 4's dead grace, `4 * srtt + 5 s`
/// (Reticulum's shape).
pub const DEAD_GRACE_BASE: Duration = Duration::from_secs(5);

/// Section 4: the grace between stale and dead is probed at one probe per
/// second, slower than a visit because the traffic has already moved to
/// the relay and this is only asking whether the path came back.
pub const DEAD_PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// Section 4, cached addresses: a candidate unanswered for 10 minutes
/// expires.
pub const CACHED_ADDRESS_TTL: Duration = Duration::from_secs(600);

/// Section 6: a discovery-sourced candidate carries a 5 minute expiry
/// instead, half the general one, because a machine that has left the
/// network stops announcing and its address is the one most likely to be
/// reissued to somebody else.
pub const DISCOVERED_ADDRESS_TTL: Duration = Duration::from_secs(300);

/// quinn's `max_idle_timeout`, set explicitly to 30 s, which is also its
/// default (`quinn-proto/src/config/transport.rs:369`), so it is stated
/// rather than inherited.
pub const MAX_IDLE_TIMEOUT: Duration = FIREWALL_ASSUMPTION;

/// quinn's `keep_alive_interval`, `None` by default (`:385`), set to 15 s,
/// below both peers' idle timeouts as that setter's doc requires
/// (`:255-258`).
///
/// The two do different jobs and this is why they do not fight: our probes
/// are not QUIC packets, so without quinn's keepalive an idle connection
/// would hit the idle timer on a perfectly live path, and quinn's keepalive
/// covers neither candidate paths carrying no traffic nor death detection
/// inside a second.
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Section 4's keepalive on an idle direct path: `clamp(8 * srtt, 5 s, 15 s)`.
///
/// `None`, a path with no round trip sample yet, takes the floor rather
/// than the ceiling: an unmeasured path is the one we know least about, and
/// the cost of being early is a packet while the cost of being late is a
/// dead mapping.
#[must_use]
pub fn keepalive_interval(srtt: Option<Duration>) -> Duration {
    match srtt {
        None => KEEPALIVE_FLOOR,
        Some(srtt) => (srtt * KEEPALIVE_SRTT_MULTIPLIER).clamp(KEEPALIVE_FLOOR, KEEPALIVE_CEILING),
    }
}

/// Section 4: a probe is lost after `max(4 * srtt, 500 ms)`.
#[must_use]
pub fn probe_loss_deadline(srtt: Option<Duration>) -> Duration {
    match srtt {
        None => PROBE_LOSS_FLOOR,
        Some(srtt) => (srtt * LOSS_SRTT_MULTIPLIER).max(PROBE_LOSS_FLOOR),
    }
}

/// Section 4: dead is stale plus a grace of `4 * srtt + 5 s`.
#[must_use]
pub fn dead_grace(srtt: Option<Duration>) -> Duration {
    match srtt {
        None => DEAD_GRACE_BASE,
        Some(srtt) => srtt.saturating_mul(LOSS_SRTT_MULTIPLIER) + DEAD_GRACE_BASE,
    }
}

// ----------------------------------------------------------------------
// The state machine (section 4, stale before dead)
// ----------------------------------------------------------------------

/// Whether this peer is being talked to right now, which is the only input
/// to the probe interval on a live path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Activity {
    /// No visit in progress: the path is kept open by section 4's
    /// keepalive, [`keepalive_interval`].
    #[default]
    Idle,
    /// A live visit: one probe every [`VISIT_PROBE_INTERVAL`], because
    /// death detection beats packet count while people talk.
    Visit,
}

/// A peer's path state, section 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// Answering.
    Live,
    /// [`PROBES_TO_STALE`] probes unanswered in a row: stop sending on
    /// this path, move traffic to the relay at once, keep probing.
    Stale,
    /// Stale plus [`dead_grace`], or a goodbye: drop the path and rerun the
    /// doorbell.
    Dead,
}

/// Why a peer was last seen when it was (D8): the two ways a path ends
/// look identical in a timestamp and are not the same event, so each
/// friend's last seen records which it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastSeenReason {
    /// Frame 19 arrived: a clean exit, and the peer said so.
    Goodbye,
    /// Nothing arrived: the path timed out through stale into dead.
    Timeout,
}

/// When a peer was last seen and why it stopped being seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastSeen {
    /// The last moment this peer answered, for a timeout; the moment the
    /// goodbye arrived, for a goodbye.
    pub at: Instant,
    /// Which of the two it was.
    pub reason: LastSeenReason,
}

/// What a [`PeerLiveness::poll`] or a goodbye changed, if anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessChange {
    /// Section 4: stop sending on this path, move traffic to the relay at
    /// once, keep probing.
    WentStale,
    /// Section 4: drop the path and rerun the doorbell.
    WentDead,
}

/// One peer's liveness, section 4: live, stale, dead, and the last seen
/// that outlives all three.
///
/// The caller drives it: [`PeerLiveness::due_probe`] says when to send,
/// [`PeerLiveness::on_pong`] feeds answers back in, and
/// [`PeerLiveness::poll`] is what moves the state. Nothing here sends a
/// packet or reads a clock.
#[derive(Debug)]
pub struct PeerLiveness {
    activity: Activity,
    state: Liveness,
    srtt: Option<Duration>,
    /// When the oldest unanswered probe went out, which is what
    /// [`probe_loss_deadline`] is measured from.
    outstanding: Option<Instant>,
    misses: u32,
    last_sent: Option<Instant>,
    last_answer: Instant,
    stale_since: Option<Instant>,
    last_seen: Option<LastSeen>,
}

impl PeerLiveness {
    /// A live peer that has just been heard from, which is what an
    /// upgraded path is: it won by answering three probes in a row.
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self {
            activity: Activity::Idle,
            state: Liveness::Live,
            srtt: None,
            outstanding: None,
            misses: 0,
            last_sent: None,
            last_answer: now,
            stale_since: None,
            last_seen: None,
        }
    }

    /// Seeds the smoothed round trip from the winning probe's, so the
    /// first keepalive is scaled by a real measurement rather than taking
    /// the floor (section 3: the path table's own srtt, never quinn's).
    #[must_use]
    pub fn with_srtt(mut self, srtt: Duration) -> Self {
        self.srtt = Some(srtt);
        self
    }

    /// Whether a visit is in progress, which sets the probe interval on a
    /// live path.
    pub fn set_activity(&mut self, activity: Activity) {
        self.activity = activity;
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> Liveness {
        self.state
    }

    /// This path's smoothed round trip time, an EWMA over probe pong round
    /// trips seeded by its first sample.
    #[must_use]
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// When this peer was last seen and why it stopped, once it is dead
    /// (D8). `None` while it is live or stale: a peer that is still being
    /// probed has not stopped being seen.
    #[must_use]
    pub fn last_seen(&self) -> Option<LastSeen> {
        self.last_seen
    }

    /// How long this state waits between probes: [`keepalive_interval`] on
    /// an idle live path, [`VISIT_PROBE_INTERVAL`] during a visit, and
    /// [`DEAD_PROBE_INTERVAL`] through the stale grace.
    #[must_use]
    pub fn probe_interval(&self) -> Duration {
        match (self.state, self.activity) {
            (Liveness::Stale, _) => DEAD_PROBE_INTERVAL,
            (_, Activity::Visit) => VISIT_PROBE_INTERVAL,
            (_, Activity::Idle) => keepalive_interval(self.srtt),
        }
    }

    /// Whether a probe is due at `now`, recording it as sent if it is.
    ///
    /// Deciding and recording are one call because they cannot come apart:
    /// a probe the caller was told to send and did not send would leave
    /// this state machine timing a packet that never left, which is a false
    /// death rather than a missed one. A dead peer is never probed again;
    /// the doorbell rerun builds a fresh attempt and a fresh
    /// [`PeerLiveness`].
    pub fn due_probe(&mut self, now: Instant) -> bool {
        if self.state == Liveness::Dead {
            return false;
        }
        if self
            .last_sent
            .is_some_and(|last| now.duration_since(last) < self.probe_interval())
        {
            return false;
        }
        self.last_sent = Some(now);
        // The oldest unanswered probe is the one the loss deadline runs
        // from: a second probe sent while the first is outstanding does not
        // restart the clock, or a fast probe interval would postpone the
        // loss it exists to detect.
        if self.outstanding.is_none() {
            self.outstanding = Some(now);
        }
        true
    }

    /// An answer arrived at `now`, `rtt` being its measured round trip.
    ///
    /// **A stale path is not restored by an answer.** Section 4 says stale
    /// keeps probing and says nothing about coming back, so this takes the
    /// smaller reading: the answers are recorded, and only a fresh doorbell
    /// attempt (section 2 step 7) puts traffic back on a direct path. A
    /// path that silently un-staled would move traffic back without either
    /// side sending `PathUp`, so the two houses would disagree about where
    /// the traffic is.
    pub fn on_pong(&mut self, now: Instant, rtt: Duration) -> bool {
        if self.state == Liveness::Dead {
            return false;
        }
        // The same 1/8 weighting QUIC's own estimator uses, seeded by the
        // first sample rather than by zero.
        self.srtt = Some(match self.srtt {
            None => rtt,
            Some(previous) => (previous * 7 + rtt) / 8,
        });
        self.outstanding = None;
        self.misses = 0;
        self.last_answer = now;
        true
    }

    /// Advances the state machine to `now`, returning what changed.
    ///
    /// Call it as often as convenient: it is idempotent between changes and
    /// every transition it can make is reported exactly once.
    pub fn poll(&mut self, now: Instant) -> Option<LivenessChange> {
        if self.state == Liveness::Dead {
            return None;
        }
        if let Some(sent) = self.outstanding
            && now.duration_since(sent) >= probe_loss_deadline(self.srtt)
        {
            self.misses = self.misses.saturating_add(1);
            self.outstanding = None;
        }
        match self.state {
            Liveness::Live => {
                if self.misses >= PROBES_TO_STALE {
                    self.state = Liveness::Stale;
                    self.stale_since = Some(now);
                    return Some(LivenessChange::WentStale);
                }
                None
            }
            Liveness::Stale => {
                let since = self.stale_since?;
                if now.duration_since(since) >= dead_grace(self.srtt) {
                    self.state = Liveness::Dead;
                    self.last_seen = Some(LastSeen {
                        at: self.last_answer,
                        reason: LastSeenReason::Timeout,
                    });
                    return Some(LivenessChange::WentDead);
                }
                None
            }
            Liveness::Dead => None,
        }
    }

    /// Frame 19 arrived: "the receiver marks dead at once and skips stale"
    /// (section 4), and the last seen records that it was a goodbye and not
    /// a timeout (D8).
    ///
    /// Returns [`LivenessChange::WentDead`] unless this peer was dead
    /// already, so a goodbye following a timeout does not report a second
    /// death or overwrite the timeout that already happened.
    pub fn on_goodbye(&mut self, now: Instant) -> Option<LivenessChange> {
        if self.state == Liveness::Dead {
            return None;
        }
        self.state = Liveness::Dead;
        self.last_seen = Some(LastSeen {
            at: now,
            reason: LastSeenReason::Goodbye,
        });
        Some(LivenessChange::WentDead)
    }
}

/// Sends frame 19, the explicit goodbye, on this peer's porch stream, so
/// the far side goes straight to dead without passing through stale.
///
/// `reason` is section 7's reason enum, passed through rather than
/// interpreted here.
///
/// # Errors
///
/// Returns a [`GateError`] if the stream write fails, which a caller on its
/// way out is entitled to ignore: a goodbye is a courtesy, and its absence
/// is exactly what [`PeerLiveness::poll`] handles.
pub async fn send_goodbye(stream: &mut quinn::SendStream, reason: u8) -> Result<(), GateError> {
    write_porch_frame(stream, &PorchFrame::Goodbye { v: 1, reason }).await
}

/// Applies one received porch frame to a peer's liveness, which is frame
/// 19 and nothing else: `PathUp` and `PathDown` describe the *sender's*
/// path choice and say nothing about whether this house can still reach it,
/// and `Candidates` is the opening frame of an attempt.
pub fn apply_porch_frame(
    liveness: &mut PeerLiveness,
    frame: &PorchFrame,
    now: Instant,
) -> Option<LivenessChange> {
    match frame {
        PorchFrame::Goodbye { .. } => liveness.on_goodbye(now),
        PorchFrame::Candidates { .. } | PorchFrame::PathUp { .. } | PorchFrame::PathDown { .. } => {
            None
        }
    }
}

// ----------------------------------------------------------------------
// Cached addresses (section 4)
// ----------------------------------------------------------------------

/// What to do after a dial to a cached address failed.
///
/// One variant, deliberately: section 4 says a failed dial "expires its
/// address at once and triggers rediscovery rather than a retry (research
/// lesson 6), which would spend the same timeout twice". There is no
/// `Retry`, so nothing can accidentally return one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum AfterDialFailure {
    /// Gather and discover again (section 2 step 1, section 6). The address
    /// that failed is gone from the cache by the time this is returned.
    Rediscover,
}

/// One remembered address for one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachedAddress {
    /// The address itself.
    pub addr: SocketAddr,
    /// Where it came from, which sets how long it lives.
    pub source: CandidateSource,
    /// The last time anything at this address answered, or when it was
    /// first remembered if nothing has.
    pub last_answer: Instant,
}

impl CachedAddress {
    /// How long this address lives unanswered: 10 minutes in general
    /// ([`CACHED_ADDRESS_TTL`]), 5 for a discovered one
    /// ([`DISCOVERED_ADDRESS_TTL`], section 6).
    #[must_use]
    pub fn ttl(&self) -> Duration {
        match self.source {
            CandidateSource::Discovery => DISCOVERED_ADDRESS_TTL,
            CandidateSource::Local
            | CandidateSource::GateReflected
            | CandidateSource::PeerReported => CACHED_ADDRESS_TTL,
        }
    }
}

/// The addresses this house holds for its friends between attempts, with
/// section 4's expiry: unanswered for its TTL and it is gone, and a failed
/// dial expires it at once.
#[derive(Debug, Default)]
pub struct AddressCache {
    entries: HashMap<[u8; 32], Vec<CachedAddress>>,
}

impl AddressCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Remembers `addr` for `peer`, or refreshes it if it is already held
    /// (a second sighting of an address is a sighting, not a duplicate).
    pub fn remember(
        &mut self,
        peer: [u8; 32],
        addr: SocketAddr,
        source: CandidateSource,
        now: Instant,
    ) {
        let addr = crate::sock::unmap_v4(addr);
        let held = self.entries.entry(peer).or_default();
        if let Some(existing) = held.iter_mut().find(|held| held.addr == addr) {
            existing.last_answer = now;
            existing.source = source;
            return;
        }
        held.push(CachedAddress {
            addr,
            source,
            last_answer: now,
        });
    }

    /// Records that `addr` answered, which is what stops it expiring.
    pub fn answered(&mut self, peer: &[u8; 32], addr: SocketAddr, now: Instant) {
        let addr = crate::sock::unmap_v4(addr);
        if let Some(held) = self.entries.get_mut(peer)
            && let Some(entry) = held.iter_mut().find(|held| held.addr == addr)
        {
            entry.last_answer = now;
        }
    }

    /// The addresses held for `peer`, newest sighting last.
    #[must_use]
    pub fn addresses(&self, peer: &[u8; 32]) -> Vec<SocketAddr> {
        self.entries
            .get(peer)
            .map(|held| held.iter().map(|entry| entry.addr).collect())
            .unwrap_or_default()
    }

    /// The addresses held for `peer` that came from same-network discovery
    /// (section 6), which are the ones that vouch for themselves in an
    /// attempt (issue #37).
    #[must_use]
    pub fn discovered(&self, peer: &[u8; 32]) -> Vec<SocketAddr> {
        self.entries
            .get(peer)
            .map(|held| {
                held.iter()
                    .filter(|entry| entry.source == CandidateSource::Discovery)
                    .map(|entry| entry.addr)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether `addr` is still held for `peer`.
    #[must_use]
    pub fn holds(&self, peer: &[u8; 32], addr: SocketAddr) -> bool {
        let addr = crate::sock::unmap_v4(addr);
        self.entries
            .get(peer)
            .is_some_and(|held| held.iter().any(|entry| entry.addr == addr))
    }

    /// Section 4: a candidate unanswered for its TTL expires. Returns how
    /// many went.
    pub fn expire(&mut self, now: Instant) -> usize {
        let mut expired = 0;
        self.entries.retain(|_, held| {
            held.retain(|entry| {
                let alive = now.duration_since(entry.last_answer) < entry.ttl();
                if !alive {
                    expired += 1;
                }
                alive
            });
            !held.is_empty()
        });
        expired
    }

    /// Section 4: a failed dial expires its address at once and triggers
    /// rediscovery rather than a retry, which would spend the same timeout
    /// twice (research lesson 6).
    pub fn on_dial_failed(&mut self, peer: &[u8; 32], addr: SocketAddr) -> AfterDialFailure {
        let addr = crate::sock::unmap_v4(addr);
        if let Some(held) = self.entries.get_mut(peer) {
            held.retain(|entry| entry.addr != addr);
            if held.is_empty() {
                self.entries.remove(peer);
            }
        }
        AfterDialFailure::Rediscover
    }
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

    fn peer() -> [u8; 32] {
        [11u8; 32]
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9)),
            port,
        )
    }

    /// Section 4's keepalive is a function of the measured RTT with a floor
    /// and a ceiling, and the ceiling is half the 30 s firewall assumption
    /// so two consecutive losses still cannot let the mapping expire.
    ///
    /// Deliberate break to fail this test: in `keepalive_interval`, change
    /// the `clamp(KEEPALIVE_FLOOR, KEEPALIVE_CEILING)` to
    /// `clamp(KEEPALIVE_FLOOR, FIREWALL_ASSUMPTION)`. The 5 second RTT then
    /// returns 30 s instead of 15 and the ceiling assertion fails.
    #[test]
    fn the_keepalive_is_eight_srtt_clamped_between_five_and_fifteen_seconds() {
        // Scaling, in the band where the clamp does not bite.
        assert_eq!(
            keepalive_interval(Some(Duration::from_millis(1000))),
            Duration::from_secs(8)
        );
        assert_eq!(
            keepalive_interval(Some(Duration::from_millis(1500))),
            Duration::from_secs(12)
        );
        // The floor: a fast LAN path does not spend a packet every 40 ms.
        assert_eq!(
            keepalive_interval(Some(Duration::from_millis(5))),
            KEEPALIVE_FLOOR
        );
        // The ceiling, and its reason.
        assert_eq!(
            keepalive_interval(Some(Duration::from_secs(5))),
            KEEPALIVE_CEILING
        );
        assert_eq!(
            KEEPALIVE_CEILING * 2,
            FIREWALL_ASSUMPTION,
            "the ceiling is half the firewall assumption, so two losses still cannot expire it"
        );
        // Unmeasured takes the floor, not the ceiling.
        assert_eq!(keepalive_interval(None), KEEPALIVE_FLOOR);

        // And quinn's own timers, set so the two policies do not fight.
        assert_eq!(MAX_IDLE_TIMEOUT, FIREWALL_ASSUMPTION);
        assert!(
            KEEP_ALIVE_INTERVAL < MAX_IDLE_TIMEOUT,
            "quinn's keepalive must be below both peers' idle timeouts"
        );
    }

    #[test]
    fn the_loss_deadline_and_the_dead_grace_are_the_stated_functions_of_srtt() {
        assert_eq!(probe_loss_deadline(None), PROBE_LOSS_FLOOR);
        assert_eq!(
            probe_loss_deadline(Some(Duration::from_millis(10))),
            PROBE_LOSS_FLOOR,
            "max(4 * srtt, 500 ms)"
        );
        assert_eq!(
            probe_loss_deadline(Some(Duration::from_millis(400))),
            Duration::from_millis(1600)
        );
        assert_eq!(dead_grace(None), DEAD_GRACE_BASE);
        assert_eq!(
            dead_grace(Some(Duration::from_millis(250))),
            Duration::from_secs(6),
            "4 * srtt + 5 s"
        );
    }

    /// Section 8's WO-1.3b case, first half: a peer killed without a
    /// goodbye reaches stale before dead. Three probes unanswered at the
    /// loss deadline make it stale, traffic moves to the relay there, and
    /// only the grace after that makes it dead, with a last seen naming the
    /// timeout.
    ///
    /// Deliberate break to fail this test: in `PeerLiveness::poll`, change
    /// `if self.misses >= PROBES_TO_STALE` to `if self.misses >= 1`. The
    /// peer goes stale after the first lost probe and the "still live after
    /// two" assertion fails.
    #[test]
    fn a_peer_killed_without_a_goodbye_reaches_stale_before_dead() {
        let t0 = Instant::now();
        let mut peer = PeerLiveness::new(t0).with_srtt(Duration::from_millis(20));
        peer.set_activity(Activity::Visit);
        let loss = probe_loss_deadline(peer.srtt());
        assert_eq!(
            loss, PROBE_LOSS_FLOOR,
            "a 20 ms path takes the 500 ms floor"
        );

        // It answers once, so "last seen" has something real to name.
        let mut now = t0;
        assert!(peer.due_probe(now));
        now += Duration::from_millis(20);
        peer.on_pong(now, Duration::from_millis(20));
        let last_answer = now;
        assert_eq!(peer.state(), Liveness::Live);

        // Then it stops. Each probe goes out at the visit interval and is
        // lost `loss` after it left; two losses are not yet stale.
        for _ in 0..2 {
            now += VISIT_PROBE_INTERVAL;
            assert!(peer.due_probe(now));
            now += loss;
            assert_eq!(peer.poll(now), None);
            assert_eq!(peer.state(), Liveness::Live);
        }

        now += VISIT_PROBE_INTERVAL;
        assert!(peer.due_probe(now));
        now += loss;
        assert_eq!(peer.poll(now), Some(LivenessChange::WentStale));
        assert_eq!(peer.state(), Liveness::Stale);
        assert_eq!(
            peer.last_seen(),
            None,
            "a stale peer is still being probed, so it has not stopped being seen"
        );
        assert_eq!(
            peer.probe_interval(),
            DEAD_PROBE_INTERVAL,
            "the grace is probed once a second"
        );
        let stale_at = now;

        // Dead is stale plus the grace, and not before it.
        assert_eq!(peer.poll(stale_at + dead_grace(peer.srtt()) / 2), None);
        assert_eq!(peer.state(), Liveness::Stale);
        assert_eq!(
            peer.poll(stale_at + dead_grace(peer.srtt())),
            Some(LivenessChange::WentDead)
        );
        assert_eq!(peer.state(), Liveness::Dead);
        let seen = peer.last_seen().expect("a dead peer has a last seen");
        assert_eq!(seen.reason, LastSeenReason::Timeout);
        assert_eq!(
            seen.at, last_answer,
            "last seen is the last answer, not the death"
        );

        // A dead peer is not probed again and reports nothing further.
        assert!(!peer.due_probe(stale_at + Duration::from_secs(60)));
        assert_eq!(peer.poll(stale_at + Duration::from_secs(60)), None);
    }

    /// Section 8's WO-1.3b case, second half: a goodbye reaches dead at
    /// once, skipping stale, and its last seen names the goodbye rather
    /// than a timeout. The two halves are asserted against the same clock,
    /// so "at once" is measured against what the silent peer had reached by
    /// the same instant, which is still live.
    ///
    /// Deliberate break to fail this test: in `PeerLiveness::on_goodbye`,
    /// replace the two assignments with `self.state = Liveness::Stale;`.
    /// The goodbye then goes through stale and both the state and the
    /// last-seen assertions fail.
    #[test]
    fn a_goodbye_reaches_dead_at_once_while_a_silent_peer_is_still_live() {
        let t0 = Instant::now();
        let mut said_goodbye = PeerLiveness::new(t0);
        let mut went_silent = PeerLiveness::new(t0);
        said_goodbye.set_activity(Activity::Visit);
        went_silent.set_activity(Activity::Visit);

        let now = t0 + Duration::from_millis(1);
        assert!(said_goodbye.due_probe(t0));
        assert!(went_silent.due_probe(t0));

        assert_eq!(
            said_goodbye.on_goodbye(now),
            Some(LivenessChange::WentDead),
            "the receiver marks dead at once and skips stale"
        );
        assert_eq!(said_goodbye.state(), Liveness::Dead);
        let seen = said_goodbye.last_seen().unwrap();
        assert_eq!(seen.reason, LastSeenReason::Goodbye);
        assert_eq!(seen.at, now);

        // At the same instant the silent peer has not even lost a probe.
        assert_eq!(went_silent.poll(now), None);
        assert_eq!(went_silent.state(), Liveness::Live);

        // A second goodbye reports nothing and changes nothing.
        assert_eq!(said_goodbye.on_goodbye(now + Duration::from_secs(1)), None);
        assert_eq!(said_goodbye.last_seen().unwrap().at, now);
    }

    /// Frame 19 is the only porch frame that touches liveness: `PathUp` and
    /// `PathDown` describe the sender's own path choice.
    #[test]
    fn only_frame_nineteen_marks_a_peer_dead() {
        let t0 = Instant::now();
        let mut peer = PeerLiveness::new(t0);
        let path_up = PorchFrame::PathUp {
            v: 1,
            attempt: [4u8; 16],
            addr: crate::gate::wire::Addr::from_socket_addr(addr(4433)),
            rtt_us: 900,
        };
        assert_eq!(apply_porch_frame(&mut peer, &path_up, t0), None);
        assert_eq!(peer.state(), Liveness::Live);

        // Over the wire and back, so the frame that is applied is the frame
        // that was decoded rather than one built beside it.
        let goodbye = PorchFrame::from_cbor(&PorchFrame::Goodbye { v: 1, reason: 0 }.to_cbor())
            .expect("frame 19 round trips");
        assert_eq!(
            apply_porch_frame(&mut peer, &goodbye, t0),
            Some(LivenessChange::WentDead)
        );
        assert_eq!(peer.last_seen().unwrap().reason, LastSeenReason::Goodbye);
    }

    /// The goodbye of section 4 over a real QUIC stream, so what is applied
    /// is a frame that actually crossed a connection rather than one built
    /// beside the assertion. Frame 19 is 3 CBOR fields behind a 4 byte
    /// length prefix; if either end of that disagreed, this is where it
    /// would show.
    ///
    /// Deliberate break to fail this test: in `send_goodbye`, change
    /// `PorchFrame::Goodbye` to `PorchFrame::PathDown` with any address.
    /// The frame still crosses and still decodes, and the receiver stays
    /// live, so the `Dead` assertion fails.
    #[tokio::test]
    async fn a_goodbye_sent_on_a_real_porch_stream_marks_its_sender_dead() {
        crate::authed::install_crypto_provider();
        let (server_cert, server_key) = crate::authed::self_signed_cert(&[5u8; 32]).unwrap();
        let server_tls =
            crate::authed::server_tls_config(server_cert, server_key, b"moss-gate").unwrap();
        let server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
        ));
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server.local_addr().unwrap();

        let (client_cert, client_key) = crate::authed::self_signed_cert(&[6u8; 32]).unwrap();
        let client_tls =
            crate::authed::client_tls_config(client_cert, client_key, b"moss-gate").unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(std::sync::Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        )));

        let accept = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (_send, mut recv) = connection.accept_bi().await.unwrap();
            let frame = crate::punch::read_porch_frame(&mut recv, Duration::from_secs(10))
                .await
                .unwrap();
            (server, frame)
        });
        let connection = client.connect(server_addr, "peer").unwrap().await.unwrap();
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        send_goodbye(&mut send, 0).await.unwrap();
        send.finish().unwrap();

        let (_server, frame) = accept.await.unwrap();
        let mut peer = PeerLiveness::new(Instant::now());
        let now = Instant::now();
        assert_eq!(
            apply_porch_frame(&mut peer, &frame, now),
            Some(LivenessChange::WentDead),
            "the frame that crossed the wire is the one that kills the path"
        );
        assert_eq!(peer.state(), Liveness::Dead);
        assert_eq!(peer.last_seen().unwrap().reason, LastSeenReason::Goodbye);
    }

    /// Section 8's WO-1.3b case: a failed dial to a cached address triggers
    /// rediscovery rather than a retry. The address is gone from the cache
    /// before the caller is told what to do next, so a retry is not
    /// something a caller has to decline; it has nothing to retry with.
    ///
    /// Deliberate break to fail this test: in
    /// `AddressCache::on_dial_failed`, delete the
    /// `held.retain(|entry| entry.addr != addr);` line. The address is
    /// still cached after the failure and the `holds` assertion fails.
    #[test]
    fn a_failed_dial_expires_its_address_at_once_and_asks_for_rediscovery() {
        let t0 = Instant::now();
        let mut cache = AddressCache::new();
        let cached = addr(4433);
        let other = addr(4434);
        cache.remember(peer(), cached, CandidateSource::Discovery, t0);
        cache.remember(peer(), other, CandidateSource::GateReflected, t0);
        assert!(cache.holds(&peer(), cached));

        assert_eq!(
            cache.on_dial_failed(&peer(), cached),
            AfterDialFailure::Rediscover
        );
        assert!(
            !cache.holds(&peer(), cached),
            "the failed address expires at once, so nothing can dial it again"
        );
        assert_eq!(
            cache.addresses(&peer()),
            vec![other],
            "and only that address: the peer's other addresses are untouched"
        );
        assert!(cache.discovered(&peer()).is_empty());

        // The last address going leaves no empty entry behind.
        assert_eq!(
            cache.on_dial_failed(&peer(), other),
            AfterDialFailure::Rediscover
        );
        assert!(cache.addresses(&peer()).is_empty());
    }

    /// Section 4's ten minutes, and section 6's five for a discovered
    /// address: unanswered is what expires, so an address that keeps
    /// answering keeps living.
    #[test]
    fn a_cached_address_expires_unanswered_and_a_discovered_one_expires_sooner() {
        let t0 = Instant::now();
        let mut cache = AddressCache::new();
        let discovered = addr(4433);
        let reflected = addr(4434);
        cache.remember(peer(), discovered, CandidateSource::Discovery, t0);
        cache.remember(peer(), reflected, CandidateSource::GateReflected, t0);

        assert_eq!(cache.expire(t0 + DISCOVERED_ADDRESS_TTL / 2), 0);
        assert_eq!(cache.expire(t0 + DISCOVERED_ADDRESS_TTL), 1);
        assert_eq!(cache.addresses(&peer()), vec![reflected]);
        assert!(cache.discovered(&peer()).is_empty());

        // The reflected one is still inside its own ten minutes, and an
        // answer moves the clock rather than resetting the entry.
        cache.answered(&peer(), reflected, t0 + CACHED_ADDRESS_TTL / 2);
        assert_eq!(cache.expire(t0 + CACHED_ADDRESS_TTL), 0);
        assert_eq!(
            cache.expire(t0 + CACHED_ADDRESS_TTL + CACHED_ADDRESS_TTL / 2),
            1
        );
        assert!(cache.addresses(&peer()).is_empty());
    }

    /// The mapped spelling of a cached address is the same cached address,
    /// the same rule `Attempt::add_candidate` applies (issue #37).
    #[test]
    fn a_cached_address_has_one_spelling() {
        let t0 = Instant::now();
        let mut cache = AddressCache::new();
        cache.remember(
            peer(),
            "[::ffff:192.168.4.21]:4433".parse().unwrap(),
            CandidateSource::Discovery,
            t0,
        );
        let unmapped: SocketAddr = "192.168.4.21:4433".parse().unwrap();
        assert_eq!(cache.addresses(&peer()), vec![unmapped]);
        assert!(cache.holds(&peer(), "[::ffff:192.168.4.21]:4433".parse().unwrap()));
        cache.remember(peer(), unmapped, CandidateSource::Discovery, t0);
        assert_eq!(cache.addresses(&peer()).len(), 1, "one address, one entry");
    }
}
