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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use std::time::Instant as ProtoInstant;

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

/// The kind of path a peer is currently using. WO-1.3a only ever produces
/// [`PathKind::Relay`]; WO-1.3b adds [`PathKind::Direct`] and the switching
/// logic that bumps a peer's epoch when it changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// Traffic for this peer rides `Relay` datagrams through the gate.
    Relay,
}

/// One peer's entry in the path table: its current path kind and the
/// congestion-reset epoch shared with that peer's [`EpochControllerFactory`].
#[derive(Debug, Clone)]
pub struct PathEntry {
    kind: PathKind,
    epoch: Arc<AtomicU64>,
}

impl PathEntry {
    /// Builds a fresh entry starting on the relay path, epoch zero.
    #[must_use]
    pub fn new_relay() -> Self {
        Self {
            kind: PathKind::Relay,
            epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    /// The current path kind.
    #[must_use]
    pub fn kind(&self) -> PathKind {
        self.kind
    }

    /// The epoch counter, shared with this peer's congestion controller
    /// factory so a future path switch (WO-1.3b) can force a fresh
    /// controller by incrementing it.
    #[must_use]
    pub fn epoch(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.epoch)
    }

    /// Bumps the epoch, forcing the next congestion controller call to
    /// rebuild from scratch. Unused by WO-1.3a (one path kind only) but
    /// exercised directly by this module's tests, since WO-1.3b's real path
    /// switch is out of scope here.
    pub fn bump_epoch(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }
}

/// A per peer table of [`PathEntry`] values, keyed by the peer's ed25519
/// public key.
#[derive(Debug, Default)]
pub struct PathTable {
    entries: std::collections::HashMap<[u8; 32], PathEntry>,
}

impl PathTable {
    /// Builds an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a fresh relay-path entry for `peer`, returning it.
    pub fn insert_relay(&mut self, peer: [u8; 32]) -> PathEntry {
        let entry = PathEntry::new_relay();
        self.entries.insert(peer, entry.clone());
        entry
    }

    /// The entry for `peer`, if any.
    #[must_use]
    pub fn get(&self, peer: &[u8; 32]) -> Option<&PathEntry> {
        self.entries.get(peer)
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

    #[test]
    fn path_table_insert_and_bump() {
        let mut table = PathTable::new();
        let peer = [1u8; 32];
        let entry = table.insert_relay(peer);
        assert_eq!(entry.kind(), PathKind::Relay);
        assert_eq!(table.get(&peer).unwrap().epoch().load(Ordering::SeqCst), 0);
        entry.bump_epoch();
        assert_eq!(table.get(&peer).unwrap().epoch().load(Ordering::SeqCst), 1);
    }
}
