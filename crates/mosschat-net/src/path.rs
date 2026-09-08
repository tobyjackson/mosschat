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
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use std::time::Instant as ProtoInstant;

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
    Arc::new(transport)
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
            }),
        }
    }

    /// The current path kind.
    #[must_use]
    pub fn kind(&self) -> PathKind {
        *self.inner.kind.lock_or_recover()
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
    pub fn insert_relay(&mut self, peer: [u8; 32], synthetic: SocketAddr) -> PathEntry {
        let entry = PathEntry::new_relay();
        self.by_peer.insert(peer, entry.clone());
        self.by_synthetic.insert(synthetic, entry.clone());
        entry
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
