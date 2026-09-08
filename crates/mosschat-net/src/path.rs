//! The path table and the epoch-resetting congestion controller factory of
//! `docs/dev/gatehouse-design.md` section 3.
//!
//! WO-1.3a's slice: one path kind, `Relay`, and no probes at all (those are
//! WO-1.3b's doorbell). What lands now is the machinery a direct path will
//! need without changing its shape later: an `Arc<AtomicU64>` epoch per
//! peer, bumped on every path switch (never, yet, since there is only one
//! kind of path this WO), and a `ControllerFactory` that rebuilds the inner
//! congestion controller from scratch whenever the epoch it last saw has
//! moved, so a real switch in WO-1.3b restarts slow start rather than
//! carrying stale window state across paths that share nothing
//! (quinn-proto has no `path_changed` hook exposed at 0.11.11, per section
//! 3's citation).

use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Waker;
use std::time::{Duration, Instant};

use std::time::Instant as ProtoInstant;

use tokio::sync::Notify;

use crate::lockext::LockExt;

use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics, CubicConfig};

/// Builds the `TransportConfig` every peer (house to house) connection must
/// use (section 3): MTU discovery disabled and pinned at QUIC's 1200 byte
/// floor, since the relay path's payload cap is 1200 bytes and an
/// undiscovered direct path silently negotiating a larger one would fall
/// back to `relay_stream_fallback` on every switch; and the
/// epoch-resetting congestion controller factory installed from the start,
/// sharing `epoch` with that peer's [`PathEntry`], so a future path switch
/// (WO-1.3b) restarts slow start rather than carrying stale window state
/// across paths that share nothing. Previously this lived only in the test
/// file's own `peer_transport_config`, so nothing outside a test ever
/// actually shipped it (Konrad finding 9).
#[must_use]
pub fn peer_transport_config(epoch: Arc<AtomicU64>) -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.mtu_discovery_config(None);
    transport.initial_mtu(1200);
    transport.min_mtu(1200);
    transport.congestion_controller_factory(Arc::new(EpochControllerFactory::new(epoch)));
    // Section 4's "quinn's timers, set so they do not fight ours". The
    // idle timeout is stated rather than inherited even though 30 s is
    // also quinn's default, and the keepalive, `None` by default, is set
    // below both peers' idle timeouts as its setter's doc requires: our
    // probes are not QUIC packets, so without it an idle connection would
    // hit the idle timer on a perfectly live path. Built from
    // `VarInt::from_u32` rather than `IdleTimeout::try_from(Duration)`,
    // which is fallible and would need an unwrap in library code.
    transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
        idle_timeout_ms(),
    ))));
    transport.keep_alive_interval(Some(crate::live::KEEP_ALIVE_INTERVAL));
    Arc::new(transport)
}

/// [`crate::live::MAX_IDLE_TIMEOUT`] in milliseconds, saturating, which is
/// the form `quinn::VarInt::from_u32` takes.
fn idle_timeout_ms() -> u32 {
    u32::try_from(crate::live::MAX_IDLE_TIMEOUT.as_millis()).unwrap_or(u32::MAX)
}

/// The kind of path a peer is currently using.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// Traffic for this peer rides `Relay` datagrams through the gate.
    Relay,
    /// Traffic for this peer leaves on the wire to this address, a
    /// candidate that proved itself by section 2 step 6's three consecutive
    /// answers.
    Direct(SocketAddr),
}

/// The mutable half of one peer's path, shared by every clone of its
/// [`PathEntry`] so the porch socket's send path and the doorbell's upgrade
/// decision are looking at the same value rather than at two copies that
/// drift.
#[derive(Debug)]
struct PathInner {
    kind: Mutex<PathKind>,
    epoch: Arc<AtomicU64>,
    /// This path's own smoothed round trip time, an EWMA over probe pong
    /// round trips, **reset to `None` on every switch** so the first sample
    /// on the new path seeds it afresh (section 3, "RTT, out of quinn's
    /// hands"). Section 4's `8 * srtt` and `4 * srtt` read this and never
    /// `quinn::Connection::rtt()`, which stays stale for several samples
    /// after a fall-back and would stretch the very timers meant to catch
    /// it.
    srtt: Mutex<Option<Duration>>,
    /// This peer's half of section 1's shaper: the queue every datagram
    /// relayed *to* this peer waits in, drained at the house rate. It
    /// lives here, beside the path, because section 1 puts it here ("per
    /// session and in the path table beside its path, so a full one
    /// refuses only its own session") and because the send path already
    /// has this entry in hand when it decides relay or direct.
    ///
    /// A direct path bypasses it entirely: shaping exists to keep the
    /// gate's own 24 deep queue from overflowing, and a direct path has no
    /// gate in it.
    egress: RelayShaper,
}

/// One peer's entry in the path table: its current path kind, that peer's
/// own smoothed RTT, and the congestion-reset epoch shared with its
/// [`EpochControllerFactory`].
///
/// Cloning shares the state rather than copying it, so an entry handed to
/// the doorbell and the copy the table holds are one thing.
#[derive(Debug, Clone)]
pub struct PathEntry {
    inner: Arc<PathInner>,
}

impl PathEntry {
    /// Builds a fresh entry starting on the relay path, epoch zero.
    ///
    /// Every peer starts here: section 2 step 2 has traffic flowing through
    /// the relay from the first packet, and an upgrade is something that
    /// happens to a connection already carrying data.
    #[must_use]
    pub fn new_relay() -> Self {
        Self {
            inner: Arc::new(PathInner {
                kind: Mutex::new(PathKind::Relay),
                epoch: Arc::new(AtomicU64::new(0)),
                srtt: Mutex::new(None),
                egress: RelayShaper::house(),
            }),
        }
    }

    /// The current path kind.
    #[must_use]
    pub fn kind(&self) -> PathKind {
        *self.inner.kind.lock_or_recover()
    }

    /// This peer's shaped relay egress queue (section 1). Shared with
    /// every clone of this entry, so the porch socket's send path, the
    /// drain task and a diagnostics read are all one queue.
    #[must_use]
    pub fn egress(&self) -> &RelayShaper {
        &self.inner.egress
    }

    /// The address this peer's traffic currently leaves to, or `None` while
    /// it is relayed. This is the one question the porch socket's send path
    /// asks, on every transmit.
    #[must_use]
    pub fn direct_addr(&self) -> Option<SocketAddr> {
        match self.kind() {
            PathKind::Relay => None,
            PathKind::Direct(addr) => Some(addr),
        }
    }

    /// The epoch counter, shared with this peer's congestion controller
    /// factory so a path switch forces a fresh controller by incrementing
    /// it.
    #[must_use]
    pub fn epoch(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.inner.epoch)
    }

    /// Bumps the epoch, forcing the next congestion controller call to
    /// rebuild from scratch.
    pub fn bump_epoch(&self) {
        self.inner.epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// Section 2 step 6: a candidate proved itself, so move this peer's
    /// outbound traffic to `addr`.
    ///
    /// **What a switch must reset, and why it is done here rather than left
    /// to quinn** (section 3): quinn rebuilds the congestion controller,
    /// pacer, RTT estimator and MTU discovery per path in `PathData::new`,
    /// but our peer connection never migrates, because it only ever sees
    /// one synthetic address, so it would otherwise carry one path's state
    /// across two paths that share nothing. `Connection::path_changed`
    /// exists in quinn-proto for exactly this and is not re-exported by
    /// quinn 0.11.11, so the three are handled separately: congestion and
    /// pacing by the epoch bumped here, RTT by the `srtt` cleared here, and
    /// MTU by not having one to reset, every peer connection being pinned
    /// at QUIC's 1200 byte floor with discovery off (see
    /// [`peer_transport_config`]) precisely so that the number that is safe
    /// on a LAN is the number that is safe on the relay.
    ///
    /// Returns `false` if this peer was already direct to `addr`, in which
    /// case nothing is reset: re-upgrading to the path already in use would
    /// throw away a healthy congestion window for nothing.
    pub fn upgrade_to(&self, addr: SocketAddr) -> bool {
        {
            let mut kind = self.inner.kind.lock_or_recover();
            if *kind == PathKind::Direct(addr) {
                return false;
            }
            *kind = PathKind::Direct(addr);
        }
        *self.inner.srtt.lock_or_recover() = None;
        self.bump_epoch();
        true
    }

    /// Section 2 step 7: the direct path failed, so revert this peer to the
    /// relay session, resetting the same three things
    /// [`PathEntry::upgrade_to`] resets and for the same reason.
    ///
    /// **The end to end QUIC connection is kept**, which is section 3's
    /// whole premise: it never learns the path moved, the porch stream
    /// stays open, and neither the dial nor the peer handshake reruns.
    ///
    /// Returns the address that was dropped, or `None` if this peer was
    /// already relayed.
    pub fn fall_back_to_relay(&self) -> Option<SocketAddr> {
        let previous = {
            let mut kind = self.inner.kind.lock_or_recover();
            match *kind {
                PathKind::Relay => return None,
                PathKind::Direct(addr) => {
                    *kind = PathKind::Relay;
                    addr
                }
            }
        };
        *self.inner.srtt.lock_or_recover() = None;
        self.bump_epoch();
        Some(previous)
    }

    /// Folds one round trip sample into this path's smoothed RTT, seeded by
    /// the first sample rather than by zero, with the same 1/8 weighting
    /// QUIC's own estimator uses.
    pub fn record_rtt(&self, sample: Duration) {
        let mut srtt = self.inner.srtt.lock_or_recover();
        *srtt = Some(match *srtt {
            None => sample,
            Some(previous) => (previous * 7 + sample) / 8,
        });
    }

    /// This path's smoothed RTT, `None` until the first sample after the
    /// most recent switch.
    #[must_use]
    pub fn srtt(&self) -> Option<Duration> {
        *self.inner.srtt.lock_or_recover()
    }
}

// ---------------------------------------------------------------------
// The relay shaper (section 1, "The relay is shaped, not policed", issue
// #19)
// ---------------------------------------------------------------------

/// The house side queue depth: 100 datagrams, 50 ms of
/// [`crate::gate::limits::RELAY_DATAGRAMS_PER_SECOND`] (section 1).
///
/// Deep enough for a congestion window, because this queue never drops: a
/// full one refuses the transmit instead, which quinn sees as
/// `poll_writable` staying `Pending` until the next drain rather than as
/// loss.
pub const HOUSE_RELAY_QUEUE_DEPTH: usize = 100;

/// The gate side queue depth: 24 datagrams, 12 ms of the house rate
/// (section 1). 28 KiB a direction, so 56 MiB with all 1024 sessions the
/// gate's caps permit full at once, which is the gate-wide bound entire.
pub const GATE_RELAY_QUEUE_DEPTH: usize = 24;

/// The gate drains 10 percent over the house rate (section 1): two
/// independently timed buckets never converge, and without headroom 0.26
/// percent of mismatch fills 24 across a 9119 datagram run, while 10
/// percent absorbs a thousand times a quartz clock's 100 ppm.
pub const GATE_RELAY_RATE_HEADROOM: f64 = 1.1;

/// The most datagrams one drain pass hands over at once on the house side.
///
/// Chosen, not measured, and it is the house's half of section 1's
/// occupancy argument: the gate queue is 24 deep, so a house that has been
/// starved of CPU for a while must not release its whole accrued budget in
/// one go. Tokens accrue continuously and are never discarded by this cap,
/// so the average rate is unaffected; a backlog leaves as several batches
/// back to back with a yield between them instead of one burst.
const HOUSE_DRAIN_BURST: usize = 8;

/// The most unspent budget the house side accumulates while idle, in
/// datagrams. Two batches, so a session that has just been idle can still
/// answer promptly without handing the gate more than its 24 deep queue
/// absorbs.
const HOUSE_TOKEN_CAP: f64 = 16.0;

/// How many recent shaped delays a shaper keeps for its p50. Chosen, not
/// measured: enough that the median describes current behaviour rather
/// than a long-finished burst, small enough to be a fixed 4 KiB per
/// direction.
const DELAY_SAMPLES: usize = 1024;

/// The shaper counters section 7 records, as a plain value type.
///
/// Deliberately no dependency on `diag`: WO-1.4b's `diag::record` calls
/// read this struct, so the shaper must not know what a diagnostics record
/// is (and `diag.rs` is not this work order's to touch).
///
/// `relay_queued` counts every datagram that entered the queue, which is
/// every relayed datagram: each one waits for its own token, so the
/// population `relay_shaped_delay_us` describes and the population
/// `relay_queued` counts are the same one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShaperStats {
    /// Datagrams that entered this direction's queue.
    pub relay_queued: u64,
    /// The median time a datagram waited, over the last
    /// [`DELAY_SAMPLES`] drained, in microseconds.
    pub relay_shaped_delay_p50_us: u64,
    /// The longest any datagram waited, in microseconds, over the life of
    /// this direction.
    pub relay_shaped_delay_max_us: u64,
    /// Datagrams dropped because the queue was already full. Zero on the
    /// house side by construction (it refuses rather than dropping); on
    /// the gate side it is the abuse cap in the open, and 0 for a shaping
    /// house.
    pub relay_dropped_at_full: u64,
    /// Transmits refused with `WouldBlock` because the queue was full.
    /// The last resort, since a `WouldBlock` out of `try_send` clears
    /// write readiness endpoint-wide (`quinn/src/runtime.rs:54-59`);
    /// `poll_writable` returning `Pending` until the next drain is the
    /// intended back-pressure, so WO-1.3c asserts this stays 0.
    pub relay_socket_backpressure: u64,
}

impl ShaperStats {
    /// Folds `other` into `self` for a whole-endpoint summary: counts add,
    /// the maximum delay is the larger of the two, and the reported p50 is
    /// the larger of the two per-direction medians (a median of medians
    /// would be arithmetic on a statistic that does not support it).
    #[must_use]
    pub fn merged(self, other: Self) -> Self {
        Self {
            relay_queued: self.relay_queued.saturating_add(other.relay_queued),
            relay_shaped_delay_p50_us: self
                .relay_shaped_delay_p50_us
                .max(other.relay_shaped_delay_p50_us),
            relay_shaped_delay_max_us: self
                .relay_shaped_delay_max_us
                .max(other.relay_shaped_delay_max_us),
            relay_dropped_at_full: self
                .relay_dropped_at_full
                .saturating_add(other.relay_dropped_at_full),
            relay_socket_backpressure: self
                .relay_socket_backpressure
                .saturating_add(other.relay_socket_backpressure),
        }
    }
}

/// What a shaper did with a datagram offered to it.
///
/// A bool cannot say this: "full" and "closed" are different events with
/// different counters and different answers to quinn, and returning one
/// value for both made a session teardown race count as
/// `relay_dropped_at_full`, a number CI asserts is 0 (Konrad's finding 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueued {
    /// Queued, and it will leave at the rate.
    Accepted,
    /// The queue was already at its depth.
    Full,
    /// This direction has ended; there is nothing to queue onto.
    Closed,
}

#[derive(Debug)]
struct ShaperState {
    items: VecDeque<(Instant, Vec<u8>)>,
    tokens: f64,
    last_refill: Instant,
    delays_us: VecDeque<u64>,
    /// Wakers of `poll_writable` callers parked on a full queue, woken as
    /// soon as a drain pass has popped, before it has sent anything.
    wakers: Vec<Waker>,
    closed: bool,
}

#[derive(Debug)]
struct ShaperInner {
    depth: usize,
    per_second: f64,
    token_cap: f64,
    burst: usize,
    state: Mutex<ShaperState>,
    arrivals: Notify,
    queued: AtomicU64,
    dropped_at_full: AtomicU64,
    backpressure: AtomicU64,
    delay_max_us: AtomicU64,
}

/// One direction of one relay session's queue, drained at a fixed rate
/// (section 1: "the relay is shaped, not policed").
///
/// A policer's drops are invisible to the peer connection's congestion
/// control, so a bulk sender bursts and stalls; that is issue #19's stall.
/// A queue drained at the rate instead delays rather than discards, and it
/// is per session and per direction so a full one refuses only its own
/// session.
///
/// Cloning shares the queue rather than copying it, exactly as
/// [`PathEntry`] does: the sender, the drain task and the diagnostics
/// reader are all looking at one thing.
#[derive(Debug, Clone)]
pub struct RelayShaper {
    inner: Arc<ShaperInner>,
}

impl RelayShaper {
    /// The house side of one session's egress: [`HOUSE_RELAY_QUEUE_DEPTH`]
    /// datagrams drained at [`crate::gate::limits::RELAY_DATAGRAMS_PER_SECOND`],
    /// refusing rather than dropping when full.
    #[must_use]
    pub fn house() -> Self {
        Self::new(
            HOUSE_RELAY_QUEUE_DEPTH,
            f64::from(crate::gate::limits::RELAY_DATAGRAMS_PER_SECOND),
            HOUSE_DRAIN_BURST,
            HOUSE_TOKEN_CAP,
        )
    }

    /// The gate side of one session's direction: [`GATE_RELAY_QUEUE_DEPTH`]
    /// datagrams drained at [`GATE_RELAY_RATE_HEADROOM`] times the house
    /// rate, dropping the newest and counting it when full, since the gate
    /// cannot push back on unreliable datagrams.
    #[must_use]
    pub fn gate() -> Self {
        let per_second =
            f64::from(crate::gate::limits::RELAY_DATAGRAMS_PER_SECOND) * GATE_RELAY_RATE_HEADROOM;
        Self::new(
            GATE_RELAY_QUEUE_DEPTH,
            per_second,
            GATE_RELAY_QUEUE_DEPTH,
            #[allow(clippy::cast_precision_loss)]
            {
                GATE_RELAY_QUEUE_DEPTH as f64
            },
        )
    }

    fn new(depth: usize, per_second: f64, burst: usize, token_cap: f64) -> Self {
        Self {
            inner: Arc::new(ShaperInner {
                depth,
                per_second,
                token_cap,
                burst,
                state: Mutex::new(ShaperState {
                    items: VecDeque::new(),
                    // No budget at creation, so a queue's drain time is
                    // exactly its depth over its rate, which is the
                    // arithmetic section 1 states (100 datagrams, 50 ms;
                    // 24 datagrams, 12 ms). Budget accrues while idle up
                    // to `token_cap`, so the first datagram of a quiet
                    // session waits one token time (half a millisecond at
                    // the house rate) and no longer.
                    tokens: 0.0,
                    last_refill: Instant::now(),
                    delays_us: VecDeque::new(),
                    wakers: Vec::new(),
                    closed: false,
                }),
                arrivals: Notify::new(),
                queued: AtomicU64::new(0),
                dropped_at_full: AtomicU64::new(0),
                backpressure: AtomicU64::new(0),
                delay_max_us: AtomicU64::new(0),
            }),
        }
    }

    /// This direction's queue depth.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.inner.depth
    }

    /// How many datagrams are queued right now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.state.lock_or_recover().items.len()
    }

    /// Whether the queue is currently empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Queues one whole transmit, all of its segments or none of them,
    /// returning `false` if the queue has no room for all of them.
    ///
    /// All or nothing because a partial enqueue would be loss: quinn
    /// retries a refused transmit whole (`quinn/src/connection.rs:1041-1052`
    /// buffers it and re-polls), so a half-queued one would go out twice.
    /// A refusal counts [`ShaperStats::relay_socket_backpressure`] once,
    /// however many segments it carried.
    pub fn try_enqueue_all(&self, payloads: Vec<Vec<u8>>) -> Enqueued {
        if payloads.is_empty() {
            return Enqueued::Accepted;
        }
        let now = Instant::now();
        let mut state = self.inner.state.lock_or_recover();
        if state.closed {
            return Enqueued::Closed;
        }
        if state.items.len().saturating_add(payloads.len()) > self.inner.depth {
            drop(state);
            self.inner.backpressure.fetch_add(1, Ordering::Relaxed);
            return Enqueued::Full;
        }
        let count = payloads.len() as u64;
        for payload in payloads {
            state.items.push_back((now, payload));
        }
        drop(state);
        self.inner.queued.fetch_add(count, Ordering::Relaxed);
        self.inner.arrivals.notify_one();
        Enqueued::Accepted
    }

    /// Queues one datagram, dropping this newest arrival and counting it in
    /// [`ShaperStats::relay_dropped_at_full`] if the queue is already full.
    ///
    /// The gate's policy, and only the gate's: it forwards unreliable
    /// datagrams and has nothing to push back on, so section 1 has it drop
    /// the newest and count it, but only when full. The *newest* rather
    /// than the oldest so that a fast sender cannot always win the queue,
    /// and counted so the drop is never invisible, which is the whole of
    /// issue #19.
    ///
    /// Returns `false` if the datagram was dropped.
    pub fn enqueue_or_drop(&self, payload: Vec<u8>) -> Enqueued {
        let now = Instant::now();
        let mut state = self.inner.state.lock_or_recover();
        if state.closed {
            // Not a drop at full: the session this direction belonged to
            // has ended, and counting that as an overflow would put a
            // number in a diagnostics record that names the wrong cause.
            return Enqueued::Closed;
        }
        if state.items.len() >= self.inner.depth {
            drop(state);
            self.inner.dropped_at_full.fetch_add(1, Ordering::Relaxed);
            return Enqueued::Full;
        }
        state.items.push_back((now, payload));
        drop(state);
        self.inner.queued.fetch_add(1, Ordering::Relaxed);
        self.inner.arrivals.notify_one();
        Enqueued::Accepted
    }

    /// Whether there is room for `wanted` more datagrams, registering
    /// `waker` to be woken by the next drain pass if there is not.
    ///
    /// `wanted` is a whole transmit's worth of segments rather than one
    /// datagram, because [`RelayShaper::try_enqueue_all`] takes a transmit
    /// whole or not at all: reporting room for one and then refusing eight
    /// is how a `WouldBlock` reaches quinn despite the `Pending` this
    /// exists to give it.
    ///
    /// This is the back-pressure section 1 asks for: a full queue must
    /// reach quinn as `poll_writable` staying `Pending` until the next
    /// drain, not as a `WouldBlock` out of `try_send`, which clears write
    /// readiness endpoint-wide (`quinn/src/runtime.rs:54-59`) and would
    /// spin the retry loop at `quinn/src/connection.rs:1031-1052`.
    ///
    /// The waker is registered *before* the second look at the queue, so a
    /// drain landing in between wakes it rather than being missed.
    pub fn poll_room(&self, wanted: usize, waker: &Waker) -> bool {
        let mut state = self.inner.state.lock_or_recover();
        if state.closed || state.items.len().saturating_add(wanted) <= self.inner.depth {
            return true;
        }
        // The lock is held across the check and the registration, so
        // nothing can free room in between and a second look could only
        // return false (Konrad's nit 4). A closed queue answers true and
        // lets the caller find out from `try_enqueue_all`, which reports
        // `Closed` rather than `Full`, so a close cannot spin the retry
        // loop.
        if !state.wakers.iter().any(|w| w.will_wake(waker)) {
            state.wakers.push(waker.clone());
        }
        false
    }

    /// Waits until this direction's rate allows one or more queued
    /// datagrams out, and hands them over in order.
    ///
    /// Returns `None` once [`RelayShaper::close`] has been called, which is
    /// the drain task's exit path (no task without one).
    ///
    /// **Tokens accrue, batches are capped.** A drain pass hands over at
    /// most `burst` datagrams even when more budget has accrued, so a task
    /// that was starved of CPU catches up as several batches back to back
    /// rather than as one burst the next queue along cannot absorb. No
    /// budget is discarded by that cap, so the average rate is exactly the
    /// configured one.
    pub async fn drain(&self) -> Option<Vec<Vec<u8>>> {
        loop {
            enum Next {
                Ready(Vec<Vec<u8>>, Vec<Waker>),
                Sleep(Duration),
                Idle,
                Closed,
            }
            let next = {
                let mut state = self.inner.state.lock_or_recover();
                if state.closed {
                    Next::Closed
                } else {
                    self.refill(&mut state);
                    if state.items.is_empty() {
                        Next::Idle
                    } else if state.tokens >= 1.0 {
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        let budget = state.tokens.floor() as usize;
                        let take = budget.min(state.items.len()).min(self.inner.burst).max(1);
                        #[allow(clippy::cast_precision_loss)]
                        {
                            state.tokens -= take as f64;
                        }
                        let now = Instant::now();
                        let mut payloads = Vec::with_capacity(take);
                        for _ in 0..take {
                            let Some((queued_at, payload)) = state.items.pop_front() else {
                                break;
                            };
                            let waited = now
                                .saturating_duration_since(queued_at)
                                .as_micros()
                                .min(u128::from(u64::MAX));
                            #[allow(clippy::cast_possible_truncation)]
                            let waited = waited as u64;
                            state.delays_us.push_back(waited);
                            while state.delays_us.len() > DELAY_SAMPLES {
                                state.delays_us.pop_front();
                            }
                            self.inner.delay_max_us.fetch_max(waited, Ordering::Relaxed);
                            payloads.push(payload);
                        }
                        let wakers = std::mem::take(&mut state.wakers);
                        Next::Ready(payloads, wakers)
                    } else {
                        let deficit = 1.0 - state.tokens;
                        Next::Sleep(Duration::from_secs_f64(deficit / self.inner.per_second))
                    }
                }
            };
            match next {
                Next::Closed => return None,
                // Popping is what frees room, so the parked `poll_writable`
                // callers are woken here rather than after the send: a
                // waiter that had to wait for the send would be waiting on
                // the very connection whose driver it is.
                Next::Ready(payloads, wakers) => {
                    for waker in wakers {
                        waker.wake();
                    }
                    return Some(payloads);
                }
                Next::Sleep(delay) => tokio::time::sleep(delay).await,
                Next::Idle => self.inner.arrivals.notified().await,
            }
        }
    }

    fn refill(&self, state: &mut ShaperState) {
        let now = Instant::now();
        let elapsed = now
            .saturating_duration_since(state.last_refill)
            .as_secs_f64();
        state.last_refill = now;
        state.tokens = (state.tokens + elapsed * self.inner.per_second).min(self.inner.token_cap);
    }

    /// Ends this direction, which is the gate's session teardown and
    /// nothing else: the route that would feed this queue is removed in
    /// the same operation, so no sender is left holding a queue that
    /// refuses. The drain task's next [`RelayShaper::drain`]
    /// returns `None` and exits, anything still queued is discarded, and
    /// every parked waker is woken so no `poll_writable` caller is left
    /// waiting on a queue nobody will drain again.
    pub fn close(&self) {
        let wakers = {
            let mut state = self.inner.state.lock_or_recover();
            state.closed = true;
            state.items.clear();
            std::mem::take(&mut state.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
        self.inner.arrivals.notify_one();
    }

    /// This direction's counters, as section 7 records them.
    #[must_use]
    pub fn stats(&self) -> ShaperStats {
        let p50 = {
            let state = self.inner.state.lock_or_recover();
            let mut samples: Vec<u64> = state.delays_us.iter().copied().collect();
            samples.sort_unstable();
            samples.get(samples.len() / 2).copied().unwrap_or(0)
        };
        ShaperStats {
            relay_queued: self.inner.queued.load(Ordering::Relaxed),
            relay_shaped_delay_p50_us: p50,
            relay_shaped_delay_max_us: self.inner.delay_max_us.load(Ordering::Relaxed),
            relay_dropped_at_full: self.inner.dropped_at_full.load(Ordering::Relaxed),
            relay_socket_backpressure: self.inner.backpressure.load(Ordering::Relaxed),
        }
    }
}

/// A per peer table of [`PathEntry`] values, indexed both by the peer's
/// ed25519 public key (how the doorbell names a peer) and by that peer's
/// synthetic address (how the porch socket's send path names it, section
/// 3). Both indexes hold the same shared entry, never two copies.
#[derive(Debug, Default)]
pub struct PathTable {
    by_peer: HashMap<[u8; 32], PathEntry>,
    by_synthetic: HashMap<SocketAddr, PathEntry>,
}

impl PathTable {
    /// Builds an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a fresh relay-path entry for `peer`, reachable by its key
    /// and by `synthetic`, returning it.
    ///
    /// An entry already held under `synthetic` (from
    /// [`PathTable::ensure_by_synthetic`], which the relay session
    /// registration makes before the peer key is known) is adopted rather
    /// than replaced, so the shaper queue that registration started a drain
    /// task for stays the one the send path fills.
    pub fn insert_relay(&mut self, peer: [u8; 32], synthetic: SocketAddr) -> PathEntry {
        let entry = self
            .by_synthetic
            .get(&synthetic)
            .cloned()
            .unwrap_or_else(PathEntry::new_relay);
        self.by_peer.insert(peer, entry.clone());
        self.by_synthetic.insert(synthetic, entry.clone());
        entry
    }

    /// The entry for `synthetic`, inserting a fresh relayed one if there is
    /// none.
    ///
    /// A relay session is registered against a synthetic address before the
    /// peer key that address was derived from reaches the path table, and
    /// the session's shaper queue has to exist from the first datagram, so
    /// this is how registration reaches it.
    pub fn ensure_by_synthetic(&mut self, synthetic: SocketAddr) -> PathEntry {
        self.by_synthetic
            .entry(synthetic)
            .or_insert_with(PathEntry::new_relay)
            .clone()
    }

    /// The entry for `peer`, if any.
    #[must_use]
    pub fn get(&self, peer: &[u8; 32]) -> Option<&PathEntry> {
        self.by_peer.get(peer)
    }

    /// The entry whose synthetic address is `synthetic`, if any.
    #[must_use]
    pub fn get_by_synthetic(&self, synthetic: &SocketAddr) -> Option<&PathEntry> {
        self.by_synthetic.get(synthetic)
    }

    /// The synthetic address an inbound packet from real address `direct`
    /// must be presented to quinn as, if any peer has proved that path.
    ///
    /// Allocation-free and on the receive hot path: every received datagram
    /// asks this question, so the `Vec` [`PathTable::direct_addrs`] builds
    /// would be one allocation per packet, which is a real cost against
    /// section 3's reversing condition (b), the porch socket adding no more
    /// than 20 microseconds at the median per received datagram.
    #[must_use]
    pub fn synthetic_for_direct(&self, direct: SocketAddr) -> Option<SocketAddr> {
        self.by_synthetic.iter().find_map(|(synthetic, entry)| {
            (entry.direct_addr() == Some(direct)).then_some(*synthetic)
        })
    }

    /// Every peer's shaper counters folded into one summary, which is what
    /// a diagnostics record for this endpoint reports (section 7).
    #[must_use]
    pub fn shaper_stats(&self) -> ShaperStats {
        self.by_synthetic
            .values()
            .fold(ShaperStats::default(), |acc, entry| {
                acc.merged(entry.egress().stats())
            })
    }

    /// Every direct address currently in use, for tests and diagnostics.
    /// The receive path uses [`PathTable::synthetic_for_direct`] instead,
    /// which allocates nothing.
    #[must_use]
    pub fn direct_addrs(&self) -> Vec<(SocketAddr, SocketAddr)> {
        self.by_synthetic
            .iter()
            .filter_map(|(synthetic, entry)| entry.direct_addr().map(|direct| (direct, *synthetic)))
            .collect()
    }
}

/// A `quinn_proto::congestion::ControllerFactory` that builds a `Cubic`
/// controller wrapped so that, once `epoch` has moved past the value it was
/// built under, the next call replaces the inner controller with a freshly
/// built one (section 3, "Congestion and pacing, a real hook, ours").
pub struct EpochControllerFactory {
    epoch: Arc<AtomicU64>,
    inner: CubicConfig,
}

impl EpochControllerFactory {
    /// Builds a factory sharing `epoch` with a [`PathEntry`].
    #[must_use]
    pub fn new(epoch: Arc<AtomicU64>) -> Self {
        Self {
            epoch,
            inner: CubicConfig::default(),
        }
    }
}

impl ControllerFactory for EpochControllerFactory {
    fn build(self: Arc<Self>, now: ProtoInstant, current_mtu: u16) -> Box<dyn Controller> {
        let observed_epoch = self.epoch.load(Ordering::SeqCst);
        let inner = Arc::new(self.inner.clone()).build(now, current_mtu);
        Box::new(EpochResettingController {
            factory: self,
            observed_epoch,
            current_mtu,
            inner,
        })
    }
}

/// The wrapper `Controller`: on every call, compares the shared epoch
/// against the value it was last built under, and if it has moved, replaces
/// the inner `Cubic` controller with a fresh one before delegating (section
/// 3: "restarts slow start from the initial window, which is correct").
struct EpochResettingController {
    factory: Arc<EpochControllerFactory>,
    observed_epoch: u64,
    current_mtu: u16,
    inner: Box<dyn Controller>,
}

impl EpochResettingController {
    fn maybe_reset(&mut self, now: ProtoInstant) {
        let current = self.factory.epoch.load(Ordering::SeqCst);
        if current != self.observed_epoch {
            self.observed_epoch = current;
            self.inner = Arc::new(self.factory.inner.clone()).build(now, self.current_mtu);
        }
    }
}

impl Controller for EpochResettingController {
    fn on_sent(&mut self, now: ProtoInstant, bytes: u64, last_packet_number: u64) {
        self.maybe_reset(now);
        self.inner.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: ProtoInstant,
        sent: ProtoInstant,
        bytes: u64,
        app_limited: bool,
        rtt: &quinn_proto::RttEstimator,
    ) {
        self.maybe_reset(now);
        self.inner.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: ProtoInstant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.maybe_reset(now);
        self.inner
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: ProtoInstant,
        sent: ProtoInstant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.maybe_reset(now);
        self.inner
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu;
        self.inner.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        self.inner.window()
    }

    fn metrics(&self) -> ControllerMetrics {
        self.inner.metrics()
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            factory: Arc::clone(&self.factory),
            observed_epoch: self.observed_epoch,
            current_mtu: self.current_mtu,
            inner: self.inner.clone_box(),
        })
    }

    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
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

    /// Section 1's arithmetic on the house queue, measured: 100 datagrams
    /// at 2000 a second is 50 ms, and a full queue refuses rather than
    /// dropping, counting the refusal in `relay_socket_backpressure`.
    ///
    /// The floor is the real assertion, and it cannot be beaten: a shaper
    /// that hands 100 datagrams over in less than 45 ms is not shaping at
    /// the rate. The ceiling is deliberately loose, since a loaded runner
    /// can only add scheduling delay, never remove it.
    ///
    /// Deliberate break to fail this test: in `RelayShaper::drain`, replace
    /// the `Next::Sleep` arm's duration with `Duration::ZERO`. The queue
    /// then empties in about a millisecond and the 45 ms floor fails.
    #[tokio::test]
    async fn a_full_house_queue_drains_at_the_house_rate() {
        let shaper = RelayShaper::house();
        assert_eq!(shaper.depth(), HOUSE_RELAY_QUEUE_DEPTH);
        for index in 0..HOUSE_RELAY_QUEUE_DEPTH {
            let payload = vec![u8::try_from(index % 256).unwrap_or(0)];
            assert_eq!(
                shaper.try_enqueue_all(vec![payload]),
                Enqueued::Accepted,
                "queue {index}"
            );
        }
        assert_eq!(
            shaper.try_enqueue_all(vec![vec![0xFF]]),
            Enqueued::Full,
            "a full house queue refuses the transmit"
        );
        assert_eq!(shaper.stats().relay_socket_backpressure, 1);
        assert_eq!(
            shaper.stats().relay_dropped_at_full,
            0,
            "the house queue refuses, it never drops"
        );

        let started = Instant::now();
        let mut drained: Vec<Vec<u8>> = Vec::new();
        while drained.len() < HOUSE_RELAY_QUEUE_DEPTH {
            let Some(batch) = shaper.drain().await else {
                panic!("the shaper closed mid drain");
            };
            drained.extend(batch);
        }
        let elapsed = started.elapsed();

        let expected: Vec<Vec<u8>> = (0..HOUSE_RELAY_QUEUE_DEPTH)
            .map(|index| vec![u8::try_from(index % 256).unwrap_or(0)])
            .collect();
        assert_eq!(drained, expected, "in order, byte for byte");
        assert!(
            elapsed >= Duration::from_millis(45),
            "100 datagrams at 2000 a second is 50 ms, not {elapsed:?}"
        );
        assert!(
            elapsed <= Duration::from_millis(200),
            "the queue took {elapsed:?} to drain, far past 50 ms"
        );
        let stats = shaper.stats();
        assert_eq!(
            stats.relay_queued, HOUSE_RELAY_QUEUE_DEPTH as u64,
            "every datagram queued"
        );
        assert!(
            stats.relay_shaped_delay_max_us >= 40_000,
            "the last datagram out of a full queue waited nearly the whole 50 ms, not {}us",
            stats.relay_shaped_delay_max_us
        );
    }

    /// Section 1 on the gate queue: 24 deep, and unable to push back on
    /// unreliable datagrams the gate drops the *newest* arrival and counts
    /// it, the 24 already queued leaving in order.
    ///
    /// Deliberate break to fail this test: in
    /// `RelayShaper::enqueue_or_drop`, change the full-queue branch to
    /// `state.items.pop_front();` before the push (drop the oldest
    /// instead). `relay_dropped_at_full` then stays 0 and the queue's
    /// front becomes datagram 8 rather than datagram 0.
    #[tokio::test]
    async fn a_datagram_arriving_on_a_full_gate_queue_is_dropped_and_counted() {
        let shaper = RelayShaper::gate();
        assert_eq!(shaper.depth(), GATE_RELAY_QUEUE_DEPTH);
        for index in 0..GATE_RELAY_QUEUE_DEPTH {
            let payload = vec![u8::try_from(index % 256).unwrap_or(0)];
            assert_eq!(
                shaper.enqueue_or_drop(payload),
                Enqueued::Accepted,
                "queue {index}"
            );
        }
        let overflow = 8;
        for _ in 0..overflow {
            assert_eq!(
                shaper.enqueue_or_drop(vec![0xFF]),
                Enqueued::Full,
                "past the depth the newest is dropped"
            );
        }
        assert_eq!(shaper.stats().relay_dropped_at_full, overflow);
        assert_eq!(shaper.len(), GATE_RELAY_QUEUE_DEPTH);

        let mut drained: Vec<Vec<u8>> = Vec::new();
        while drained.len() < GATE_RELAY_QUEUE_DEPTH {
            let Some(batch) = shaper.drain().await else {
                panic!("the shaper closed mid drain");
            };
            drained.extend(batch);
        }
        let expected: Vec<Vec<u8>> = (0..GATE_RELAY_QUEUE_DEPTH)
            .map(|index| vec![u8::try_from(index % 256).unwrap_or(0)])
            .collect();
        assert_eq!(
            drained, expected,
            "the rest leave in order, none of them displaced by the drops"
        );
    }

    /// The back-pressure path of section 1: a full house queue parks the
    /// caller's waker rather than refusing, and the next drain pass wakes
    /// it as soon as it has *popped*, before it has sent anything.
    ///
    /// Deliberate break to fail this test: delete the
    /// `std::mem::take(&mut state.wakers)` from `RelayShaper::drain` and
    /// return an empty waker list. The waker is then never woken and the
    /// wake count stays 0.
    #[tokio::test]
    async fn a_full_queue_parks_a_waker_and_the_next_drain_wakes_it() {
        #[derive(Default)]
        struct CountingWaker(AtomicU64);
        impl std::task::Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let counter = Arc::new(CountingWaker::default());
        let waker = std::task::Waker::from(Arc::clone(&counter));

        let shaper = RelayShaper::gate();
        assert!(shaper.poll_room(1, &waker), "an empty queue has room");
        for index in 0..GATE_RELAY_QUEUE_DEPTH {
            assert_eq!(
                shaper.enqueue_or_drop(vec![u8::try_from(index % 256).unwrap_or(0)]),
                Enqueued::Accepted
            );
        }
        assert!(!shaper.poll_room(1, &waker), "a full queue has no room");
        assert_eq!(counter.0.load(Ordering::SeqCst), 0);

        let drained = shaper.drain().await.expect("a batch");
        assert!(!drained.is_empty());
        assert!(counter.0.load(Ordering::SeqCst) >= 1, "the pop wakes it");
        assert!(shaper.poll_room(1, &waker), "popping made room");
    }

    /// A closed direction ends its drain task rather than leaving it parked
    /// on a queue nobody will fill again (no task without an exit path).
    #[tokio::test]
    async fn closing_a_shaper_ends_its_drain() {
        let shaper = RelayShaper::house();
        shaper.close();
        assert!(shaper.drain().await.is_none());
        assert_eq!(
            shaper.try_enqueue_all(vec![vec![1]]),
            Enqueued::Closed,
            "a closed queue reports closed, never a drop at full"
        );
        assert_eq!(shaper.enqueue_or_drop(vec![1]), Enqueued::Closed);
        assert_eq!(
            shaper.stats().relay_dropped_at_full,
            0,
            "a teardown is not an overflow"
        );
    }

    #[test]
    fn epoch_bump_rebuilds_the_inner_controller_on_the_next_call() {
        let epoch = Arc::new(AtomicU64::new(0));
        let factory = Arc::new(EpochControllerFactory::new(Arc::clone(&epoch)));
        let now = ProtoInstant::now();
        let mut controller = factory.build(now, 1200);
        let initial = controller.initial_window();
        assert_eq!(controller.window(), initial);

        // A congestion event shrinks the window below its initial value,
        // with no `RttEstimator` needed for this call.
        controller.on_congestion_event(now, now, false, 6000);
        assert!(controller.window() < initial);

        // Bumping the epoch and making any further call must rebuild the
        // inner controller from scratch, observable as the window returning
        // to its initial value rather than staying shrunk.
        epoch.fetch_add(1, Ordering::SeqCst);
        controller.on_sent(now, 1, 2);
        assert_eq!(controller.window(), initial);
    }

    fn synthetic() -> SocketAddr {
        "[fd00::1]:1".parse().unwrap()
    }

    #[test]
    fn path_table_insert_and_bump() {
        let mut table = PathTable::new();
        let peer = [1u8; 32];
        let entry = table.insert_relay(peer, synthetic());
        assert_eq!(entry.kind(), PathKind::Relay);
        assert_eq!(table.get(&peer).unwrap().epoch().load(Ordering::SeqCst), 0);
        entry.bump_epoch();
        assert_eq!(table.get(&peer).unwrap().epoch().load(Ordering::SeqCst), 1);
    }

    /// Section 2 steps 6 and 7 on the table: an upgrade and a fall-back
    /// each bump the congestion epoch exactly once and each clear the
    /// smoothed RTT, so slow start restarts and section 4's timers reseed
    /// from the new path's own first sample rather than the old path's
    /// average.
    ///
    /// Deliberate break to fail this test: delete the `self.bump_epoch()`
    /// line from `PathEntry::fall_back_to_relay`. The epoch then stays at 1
    /// after the fall-back instead of reaching 2.
    #[test]
    fn upgrade_and_fall_back_reset_congestion_and_rtt() {
        let mut table = PathTable::new();
        let peer = [2u8; 32];
        let entry = table.insert_relay(peer, synthetic());
        let direct: SocketAddr = "203.0.113.7:4433".parse().unwrap();

        entry.record_rtt(Duration::from_millis(40));
        assert_eq!(entry.srtt(), Some(Duration::from_millis(40)));

        assert!(entry.upgrade_to(direct));
        assert_eq!(entry.kind(), PathKind::Direct(direct));
        assert_eq!(entry.direct_addr(), Some(direct));
        assert_eq!(entry.srtt(), None, "srtt must reseed on the new path");
        assert_eq!(entry.epoch().load(Ordering::SeqCst), 1);

        // Re-upgrading to the path already in use resets nothing: throwing
        // away a healthy congestion window for no change of path would be
        // a cost with no purchase.
        assert!(!entry.upgrade_to(direct));
        assert_eq!(entry.epoch().load(Ordering::SeqCst), 1);

        entry.record_rtt(Duration::from_millis(4));
        assert_eq!(entry.srtt(), Some(Duration::from_millis(4)));

        assert_eq!(entry.fall_back_to_relay(), Some(direct));
        assert_eq!(entry.kind(), PathKind::Relay);
        assert_eq!(entry.srtt(), None);
        assert_eq!(entry.epoch().load(Ordering::SeqCst), 2);
        assert_eq!(entry.fall_back_to_relay(), None);
        assert_eq!(entry.epoch().load(Ordering::SeqCst), 2);

        // Both indexes name the one shared entry, not two copies.
        assert_eq!(
            table.get(&peer).unwrap().kind(),
            table.get_by_synthetic(&synthetic()).unwrap().kind()
        );
    }

    #[test]
    fn direct_addrs_lists_only_upgraded_peers() {
        let mut table = PathTable::new();
        let relayed = table.insert_relay([3u8; 32], "[fd00::3]:1".parse().unwrap());
        let upgraded = table.insert_relay([4u8; 32], "[fd00::4]:1".parse().unwrap());
        let direct: SocketAddr = "203.0.113.9:4433".parse().unwrap();
        upgraded.upgrade_to(direct);
        assert_eq!(relayed.direct_addr(), None);
        assert_eq!(
            table.direct_addrs(),
            vec![(direct, "[fd00::4]:1".parse().unwrap())]
        );
    }
}
