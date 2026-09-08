//! The porch socket (`docs/dev/gatehouse-design.md` section 3): one real
//! UDP socket, wrapped as a `quinn::AsyncUdpSocket`, that relays a peer
//! connection's datagrams through an already-registered gate session,
//! sends them straight to a proved direct path once the doorbell has found
//! one, and carries the doorbell's own probes on the same socket.
//!
//! **Probes share this socket, they do not get their own** (section 3, and
//! it is a decision rather than a convenience): a NAT mapping is per
//! socket, so a hole punched on a second socket is punched on a public port
//! that is not QUIC's. Telling the two apart on receive is the first byte:
//! every QUIC header carries the fixed bit `0x40`, every endpoint here sets
//! `grease_quic_bit(false)` so quinn rejects a first byte with it clear,
//! and a probe's `0x2A` has it clear. The split is **by segment, not by
//! buffer**, because UDP GRO can coalesce a probe behind QUIC into one
//! buffer with a `stride` (see [`PorchSocket::demultiplex`]).
//!
//! **`may_fragment` must return `false`.** Its `true` default becomes
//! `allow_mtud = !socket.may_fragment()` in `Endpoint::new_with_abstract_socket`
//! (`quinn/src/endpoint.rs:140`), so leaving it at the default silently
//! disables MTU discovery for every connection on the endpoint, including
//! the gate connection, and the gate connection would then never discover
//! the `max_datagram_size() >= 1205` the relay needs.
//!
//! **Design note.** `quinn::Connection::send_datagram` is synchronous and
//! never reports a transient "try again" condition (it queues onto the
//! connection's own datagram send buffer, dropping the oldest queued
//! datagram if that buffer is full, and only ever fails with `TooLarge`,
//! `Disabled`, `UnsupportedByPeer` or a lost connection); `try_send` treats
//! every one of those as a hard I/O error for the relayed transmit rather
//! than `WouldBlock`, since none of them resolve by waiting.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use quinn::udp::{RecvMeta, Transmit, UdpSocketState};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::Interest;

use crate::gate::limits::{INBOUND_PROBE_QUEUE_CAP, INBOUND_RELAY_QUEUE_CAP};
use crate::gate::wire::{decode_relay, encode_relay};
use crate::lockext::LockExt;
use crate::path::{Enqueued, PathEntry, PathTable, RelayShaper, ShaperStats};
use crate::punch::{PROBE_LEN, Probe, is_probe};

/// Builds the stable synthetic address for `peer_key` (section 3): `fd`, 5
/// bytes randomised per process (`process_salt`), 10 bytes of
/// `BLAKE3(peer_key)`, port 1.
#[must_use]
pub fn synthetic_addr(process_salt: [u8; 5], peer_key: &[u8; 32]) -> SocketAddr {
    let hash = blake3::hash(peer_key);
    let mut octets = [0u8; 16];
    octets[0] = 0xfd;
    octets[1..6].copy_from_slice(&process_salt);
    #[allow(clippy::indexing_slicing)]
    octets[6..16].copy_from_slice(&hash.as_bytes()[..10]);
    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), 1)
}

/// Normalises an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its plain
/// IPv4 form, leaving every other address alone.
///
/// A dual-stack socket reports an IPv4 peer's source address in the mapped
/// form, while every address this crate holds from elsewhere (the gate
/// address dialled, a candidate from frame 16, a reflection from frame 2)
/// is plain IPv4. Both forms name one host and port, so both must compare
/// equal wherever a source address is matched against a known one.
#[must_use]
pub(crate) fn unmap_v4(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

/// A handle to one connection's entry in the live gate-address set
/// (section 3). Returned by [`PorchSocket::allow_source`] and given back
/// to [`PorchSocket::forget_source`], so a connection can only withdraw
/// what it itself added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceLease(u64);

/// The live gate-address set of section 3: "a packet is matched against
/// the union of the live sets", one set per live connection.
///
/// **Why the union is refcounted rather than recomputed.** Section 3's
/// check runs on every received datagram against reversing condition (b)'s
/// 20 microsecond budget, so the membership question has to stay one hash
/// lookup; walking every connection's set per packet would make it linear
/// in connections. `refcounts` is that union, maintained as a multiset,
/// and `by_lease` records what each connection put into it so a close can
/// take back exactly its own contributions.
///
/// **What this fixes** (Yseult's latent gap): this used to be a single
/// `HashSet` with an unconditional `forget_source`, so two live
/// connections on one address, which a gate naming a `secondary_port`
/// equal to its primary port produces, collapsed into one entry and the
/// first close blinded the survivor.
#[derive(Debug, Default)]
struct AllowedSources {
    by_lease: HashMap<u64, Vec<SocketAddr>>,
    refcounts: HashMap<SocketAddr, usize>,
}

impl AllowedSources {
    /// Adds `addr` to `lease`'s set and to the union.
    fn allow(&mut self, lease: SourceLease, addr: SocketAddr) {
        self.by_lease.entry(lease.0).or_default().push(addr);
        *self.refcounts.entry(addr).or_insert(0) += 1;
    }

    /// Drops `lease`'s whole set, taking each of its addresses out of the
    /// union only when no other live connection still holds it.
    fn forget(&mut self, lease: SourceLease) {
        let Some(addrs) = self.by_lease.remove(&lease.0) else {
            return;
        };
        for addr in addrs {
            if let Some(count) = self.refcounts.get_mut(&addr) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.refcounts.remove(&addr);
                }
            }
        }
    }

    /// Whether any live connection's set holds `addr`.
    fn contains(&self, addr: &SocketAddr) -> bool {
        self.refcounts.contains_key(addr)
    }

    /// How many addresses the union holds, for tests.
    #[cfg(test)]
    fn union_len(&self) -> usize {
        self.refcounts.len()
    }
}

struct RelayRoutes {
    /// The gate control connection whose `Relay` datagrams carry this
    /// socket's peer traffic. WO-1.3a supports exactly one gate at a time.
    gate: Option<quinn::Connection>,
    /// The gate connection's own entry in the live gate-address set, so
    /// its close withdraws exactly that connection's address and not an
    /// address another live connection still needs.
    gate_lease: Option<SourceLease>,
    by_synthetic: HashMap<SocketAddr, u32>,
    by_session: HashMap<u32, SocketAddr>,
    /// Synthetic peer addresses whose shaper already has a drain task, so
    /// a repeated registration never starts a second one on the same
    /// queue.
    drained: HashSet<SocketAddr>,
}

/// A `quinn::AsyncUdpSocket` backed by a real UDP socket for the gate
/// connection (and, in WO-1.3b, direct peer paths), that also relays any
/// transmit addressed to a registered synthetic peer address through the
/// attached gate connection's `Relay` datagrams instead of the network.
pub struct PorchSocket {
    udp: tokio::net::UdpSocket,
    /// Real socket configuration and send/recv (dual-stack IPv4/IPv6
    /// handling, GRO/GSO segment counts, ECN), built the same way
    /// `quinn`'s own tokio runtime does (`quinn/src/runtime/tokio.rs:29-31`)
    /// rather than hand-rolled: this is what lets one socket carry both a
    /// real IPv4 or IPv6 gate address and this house's IPv6 synthetic peer
    /// addresses (section 3).
    state: UdpSocketState,
    /// Whether the real socket is bound IPv6 (and therefore dual-stack).
    /// Cached at construction because every send consults it: a V4
    /// destination has to be handed to a V6 socket in its IPv4-mapped
    /// form, which is what quinn does for its own transmits
    /// (`ensure_ipv6`, `quinn/src/endpoint.rs:222` and `:631-636`) and
    /// what a probe or a direct-path send has to do for itself.
    local_is_ipv6: bool,
    relay: Mutex<RelayRoutes>,
    /// The per peer path table of section 3, indexed by synthetic address
    /// on the send path. A peer with a direct path leaves on the wire; a
    /// peer without one is relayed. quinn sees neither: it always sends to
    /// the synthetic address and always receives from it.
    paths: Mutex<PathTable>,
    inbound_synthetic: Mutex<VecDeque<(SocketAddr, Vec<u8>)>>,
    /// Probe segments lifted out of the inbound stream by their first byte
    /// before quinn ever sees them (section 3, "telling probes from
    /// QUIC"), with the real source address they arrived from, which is the
    /// address the doorbell scores.
    ///
    /// **Authenticated before it is queued, and bounded** (Yseult's High,
    /// Konrad's must 1). A probe segment never reaches quinn, so section
    /// 3's drop rule cannot protect this queue; and a probe's source
    /// address deliberately cannot be checked against anything, since the
    /// whole point of the burst is to hear from a mapping nobody has seen
    /// yet. What can be checked is the thing section 2 says authenticates a
    /// probe: the keyed hash. So a segment is queued only if it verifies
    /// under a currently armed attempt key, which is stronger than a source
    /// check rather than weaker, and the queue is capped at
    /// [`INBOUND_PROBE_QUEUE_CAP`] on top of that.
    inbound_probes: Mutex<VecDeque<(SocketAddr, Probe)>>,
    /// The probe keys currently armed, by attempt id. Empty means no
    /// attempt is running, and then every probe segment is dropped and
    /// counted rather than queued for a consumer that does not exist.
    probe_keys: Mutex<HashMap<[u8; 16], [u8; 32]>>,
    /// Probe segments dropped because no armed key authenticated them.
    probes_unauthenticated: AtomicU64,
    /// Authenticated probes dropped because the queue was already at
    /// [`INBOUND_PROBE_QUEUE_CAP`]: the newest is dropped and counted, the
    /// same policy and the same reasoning as the relay queue's.
    inbound_probes_dropped: AtomicU64,
    probe_waker: Mutex<Option<Waker>>,
    /// The real source addresses whose QUIC packets may reach quinn
    /// unchanged: the gate addresses this house itself dialled. See
    /// [`PorchSocket::allow_source`].
    allowed_sources: Mutex<AllowedSources>,
    /// Source of the next [`SourceLease`] id.
    next_source_lease: AtomicU64,
    /// Whether section 3's drop rule is in force.
    ///
    /// Set by [`PorchSocket::arm`] and by [`PorchSocket::attach_gate`], and
    /// **never cleared**. It used to be inferred from `allowed_sources`
    /// being empty, which fails *open*: `forget_source` takes a
    /// caller-supplied address, and a gate naming a `secondary_port` equal
    /// to its primary port would empty the set and disable the rule for the
    /// life of the process (Yseult's Medium, Konrad's must 2). An explicit
    /// flag fails closed instead: once armed, an unknown source is dropped
    /// whatever the allow-list happens to hold.
    armed: std::sync::atomic::AtomicBool,
    /// Count of inbound QUIC segments dropped for arriving from an address
    /// in neither the path table nor the allow-list (section 3).
    unknown_source_dropped: AtomicU64,
    waker: Mutex<Option<Waker>>,
    /// Count of inbound relayed datagrams dropped because
    /// [`crate::gate::limits::INBOUND_RELAY_QUEUE_CAP`] was already full
    /// (amended section 3: the newest is dropped and counted, the queue
    /// already holding as much as it is allowed to).
    inbound_relay_dropped: AtomicU64,
    /// Flipped on every `poll_recv` call that has only one buffer slot to
    /// fill (no GRO batching available), so consecutive such calls
    /// alternate which of the queue and the real socket goes first. Without
    /// this, a fixed order starves one side outright rather than merely
    /// slowing it: real-socket-always-first stalls the queue completely
    /// under heavy relay volume (the real socket is never idle, since the
    /// relay payloads themselves arrive as real-socket reads on the gate
    /// connection), and queue-always-first stalls the gate connection's own
    /// reads completely under the same load, which is section 3's original
    /// anti-starvation complaint.
    poll_recv_prefer_socket: std::sync::atomic::AtomicBool,
    /// The synthetic destination of each connection driver task's most
    /// recent relayed transmit, which is how a [`PorchPoller`] learns which
    /// peer it is polling for.
    ///
    /// **Why this indirection exists.** A full shaper queue has to reach
    /// quinn as `poll_writable` returning `Pending` (section 1), but
    /// `poll_writable` is called before quinn knows a transmit's
    /// destination (`quinn/src/connection.rs:1031`), and a `UdpPoller` is
    /// per connection while `try_send` is per socket, so nothing quinn
    /// hands us says which peer a given poller is for. What is true is that
    /// one connection's driver calls both from its own task
    /// (`drive_transmit`, `:1031-1052`), so the task id ties them together
    /// exactly, with no chance of one connection's poller adopting
    /// another's queue.
    ///
    /// An entry is removed as soon as the poller adopts it, and a
    /// non-relayed transmit removes its task's entry, so this holds at most
    /// one address per live connection driver.
    relay_intent: Mutex<HashMap<tokio::task::Id, SocketAddr>>,
}

impl fmt::Debug for PorchSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PorchSocket").finish()
    }
}

impl PorchSocket {
    /// Wraps `std_socket` (already bound) as a porch socket with no gate
    /// attached and no relay routes registered yet.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be set to non-blocking mode or
    /// adopted by the tokio reactor.
    pub fn new(std_socket: std::net::UdpSocket) -> io::Result<Arc<Self>> {
        let state = UdpSocketState::new((&std_socket).into())?;
        std_socket.set_nonblocking(true)?;
        let udp = tokio::net::UdpSocket::from_std(std_socket)?;
        let local_is_ipv6 = matches!(udp.local_addr()?, SocketAddr::V6(_));
        Ok(Arc::new(Self {
            udp,
            state,
            local_is_ipv6,
            relay: Mutex::new(RelayRoutes {
                gate: None,
                gate_lease: None,
                by_synthetic: HashMap::new(),
                by_session: HashMap::new(),
                drained: HashSet::new(),
            }),
            paths: Mutex::new(PathTable::new()),
            inbound_synthetic: Mutex::new(VecDeque::new()),
            inbound_probes: Mutex::new(VecDeque::new()),
            probe_keys: Mutex::new(HashMap::new()),
            probes_unauthenticated: AtomicU64::new(0),
            inbound_probes_dropped: AtomicU64::new(0),
            probe_waker: Mutex::new(None),
            allowed_sources: Mutex::new(AllowedSources::default()),
            next_source_lease: AtomicU64::new(0),
            armed: std::sync::atomic::AtomicBool::new(false),
            unknown_source_dropped: AtomicU64::new(0),
            waker: Mutex::new(None),
            inbound_relay_dropped: AtomicU64::new(0),
            poll_recv_prefer_socket: std::sync::atomic::AtomicBool::new(false),
            relay_intent: Mutex::new(HashMap::new()),
        }))
    }

    /// The number of inbound relayed datagrams dropped because the queue was
    /// full, for tests and diagnostics.
    #[must_use]
    pub fn inbound_relay_dropped(&self) -> u64 {
        self.inbound_relay_dropped.load(Ordering::Relaxed)
    }

    /// Attaches the gate control connection this socket relays peer traffic
    /// through, and spawns the background task that demultiplexes its
    /// inbound `Relay` datagrams by session into the registered synthetic
    /// addresses.
    ///
    /// **The gate's address enters the live set here and leaves when this
    /// connection closes** (section 3: "an address entering it at its
    /// connection's registration and leaving when that connection
    /// closes"). The leaving half is what this reader task does on its way
    /// out: until it did, a closed gate connection's address stayed
    /// admissible for the life of the process, so anything that later
    /// answered from that address, an unrelated service on the reused port
    /// or a host that took it over, was still shown to quinn.
    pub fn attach_gate(self: &Arc<Self>, gate: quinn::Connection) {
        let gate_addr = gate.remote_address();
        let gate_lease = self.allow_source(gate_addr);
        self.arm();
        // Sessions registered before a gate was attached have a shaper
        // queue but no drain task, since there was nothing to drain onto;
        // they get one here, so the order the two calls are made in cannot
        // leave a queue that fills and never empties.
        let undrained: Vec<SocketAddr> = {
            let mut routes = self.relay.lock_or_recover();
            routes.gate = Some(gate.clone());
            routes.gate_lease = Some(gate_lease);
            routes
                .by_synthetic
                .keys()
                .copied()
                .filter(|synthetic| !routes.drained.contains(synthetic))
                .collect()
        };
        for synthetic in undrained {
            let shaper = self
                .paths
                .lock_or_recover()
                .ensure_by_synthetic(synthetic)
                .egress()
                .clone();
            if self.relay.lock_or_recover().drained.insert(synthetic) {
                self.spawn_relay_drain(gate.clone(), shaper);
            }
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match gate.read_datagram().await {
                    Ok(datagram) => {
                        if let Ok((session, payload)) = decode_relay(&datagram) {
                            this.deliver_synthetic(session, payload);
                        }
                    }
                    Err(_) => {
                        this.detach_gate(gate_addr);
                        return;
                    }
                }
            }
        });
    }

    /// Ends this socket's use of the gate connection at `gate_addr`: its
    /// address leaves the live gate-address set, so a datagram arriving
    /// from it afterwards is dropped and counted in
    /// [`PorchSocket::unknown_source_dropped`], and no further relayed
    /// transmit is accepted for it.
    ///
    /// Section 3's rule is a check on the packet and not a lifetime, and
    /// the set stays armed: an emptied set fails closed.
    pub fn detach_gate(&self, gate_addr: SocketAddr) {
        let lease = {
            let mut routes = self.relay.lock_or_recover();
            if routes
                .gate
                .as_ref()
                .is_none_or(|gate| gate.remote_address() != gate_addr)
            {
                return;
            }
            routes.gate = None;
            // Every drain task for this gate exits with it, so the
            // bookkeeping that stops a second one being started must be
            // cleared too: without this, a later `attach_gate` on the same
            // socket would leave those queues with no drainer at all, and a
            // queue that fills and never empties parks `poll_writable`
            // forever, which is issue #19's own shape (Konrad's finding 1).
            routes.drained.clear();
            routes.gate_lease.take()
        };
        if let Some(lease) = lease {
            self.forget_source(lease);
        }
    }

    /// Whether a QUIC packet arriving from `addr` would be admitted to
    /// quinn unchanged, which is the live gate-address set of section 3.
    #[must_use]
    pub fn is_source_allowed(&self, addr: SocketAddr) -> bool {
        self.allowed_sources
            .lock_or_recover()
            .contains(&unmap_v4(addr))
    }

    /// Registers a live relay session: datagrams sent to `synthetic_peer`
    /// go into that peer's shaped egress queue and leave it as
    /// `Relay{session, ..}` over the attached gate connection at section
    /// 1's rate, and `Relay{session, ..}` datagrams received from the gate
    /// are delivered to quinn tagged as arriving from `synthetic_peer`.
    ///
    /// This is also where the queue's drain task starts, once per synthetic
    /// address however often the session is re-registered.
    pub fn register_relay_session(self: &Arc<Self>, session: u32, synthetic_peer: SocketAddr) {
        let shaper = self
            .paths
            .lock_or_recover()
            .ensure_by_synthetic(synthetic_peer)
            .egress()
            .clone();
        // No gate attached yet means nothing to drain onto; `attach_gate`
        // starts this queue's drain task when one arrives, so the two
        // calls may be made in either order.
        let gate = {
            let mut routes = self.relay.lock_or_recover();
            routes.by_synthetic.insert(synthetic_peer, session);
            routes.by_session.insert(session, synthetic_peer);
            match routes.gate.clone() {
                Some(gate) if routes.drained.insert(synthetic_peer) => Some(gate),
                _ => None,
            }
        };
        if let Some(gate) = gate {
            self.spawn_relay_drain(gate, shaper);
        }
    }

    /// Records that the calling connection driver's latest transmit was
    /// relayed to `destination`, or, with `None`, that it was not relayed
    /// at all (see [`PorchSocket::relay_intent`]).
    fn note_relay_intent(&self, destination: Option<SocketAddr>) {
        let Some(task) = tokio::task::try_id() else {
            return;
        };
        let mut intent = self.relay_intent.lock_or_recover();
        match destination {
            Some(destination) => {
                intent.insert(task, destination);
            }
            None => {
                intent.remove(&task);
            }
        }
    }

    /// Takes the calling task's noted relay destination, if it has one.
    fn take_relay_intent(&self) -> Option<SocketAddr> {
        let task = tokio::task::try_id()?;
        self.relay_intent.lock_or_recover().remove(&task)
    }

    /// This peer's shaped egress queue, if it has a path table entry.
    fn shaper_for(&self, synthetic_peer: SocketAddr) -> Option<RelayShaper> {
        self.paths
            .lock_or_recover()
            .get_by_synthetic(&synthetic_peer)
            .map(|entry| entry.egress().clone())
    }

    /// The shaper counters of every peer this socket relays for, folded
    /// into one summary (section 7).
    #[must_use]
    pub fn relay_stats(&self) -> ShaperStats {
        self.paths.lock_or_recover().shaper_stats()
    }

    /// Runs one session's shaped queue: waits for the rate to release a
    /// batch, then writes it onto the gate connection.
    ///
    /// `send_datagram_wait` rather than `send_datagram`, because the latter
    /// silently discards the *oldest* queued datagram when the connection's
    /// own datagram buffer is full (`quinn/src/connection.rs:436`), which
    /// is another invisible loss of exactly the kind issue #19 is about;
    /// waiting instead lets the shaper's own bounded queue and its counters
    /// be the one place a relayed datagram can be delayed or refused.
    ///
    /// Exit paths, since no task may run without one: the shaper closing
    /// (`drain` returns `None`), the socket being dropped (the `Weak`
    /// fails to upgrade), the gate connection being lost, or the gate
    /// having been detached.
    fn spawn_relay_drain(self: &Arc<Self>, gate: quinn::Connection, shaper: RelayShaper) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Some(payloads) = shaper.drain().await else {
                    return;
                };
                let Some(socket) = weak.upgrade() else {
                    return;
                };
                let still_attached = socket.relay.lock_or_recover().gate.is_some();
                drop(socket);
                if !still_attached {
                    return;
                }
                for payload in payloads {
                    if gate.send_datagram_wait(payload.into()).await.is_err() {
                        return;
                    }
                }
                // A backlog leaves as several capped batches rather than
                // one burst; yielding between them lets the gate
                // connection's own driver, and every other session's
                // drain, run in between.
                tokio::task::yield_now().await;
            }
        });
    }

    /// Queues one inbound relayed datagram for delivery to quinn as if it
    /// arrived from `session`'s registered synthetic peer address.
    ///
    /// **Drop policy** (Yseult finding 3, amended section 3: the queue was
    /// previously unbounded, letting a session peer that sends faster than
    /// this endpoint drains exhaust memory and starve the gate connection
    /// sharing this socket). Bounded at
    /// [`crate::gate::limits::INBOUND_RELAY_QUEUE_CAP`]; a full queue drops
    /// the *newest* arrival and counts it in
    /// [`Self::inbound_relay_dropped`], never the oldest queued entry: an
    /// uncounted drop is invisible to an operator, and evicting the oldest
    /// to make room for the newest lets a fast sender always win the queue,
    /// which is the opposite of fair sharing between the relay path and the
    /// gate connection's own reads (see `poll_recv`, which reads both in one
    /// call for the same reason).
    fn deliver_synthetic(&self, session: u32, payload: &[u8]) {
        let addr = {
            let routes = self.relay.lock_or_recover();
            routes.by_session.get(&session).copied()
        };
        let Some(addr) = addr else { return };
        // Section 3's split, applied to the relay leg as well as the wire:
        // a probe is not a QUIC packet, and handing one to quinn would put
        // 81 bytes of nothing into a connection that has no idea what it
        // is. The discriminator is unambiguous here for the same reason it
        // is on the wire (`is_probe`), since what a relay carries for this
        // peer is that same end to end connection's packets. The source is
        // the synthetic address, which is what the relay path's own
        // liveness probes are addressed to and therefore what a pong from
        // one must compare equal to.
        if is_probe(payload)
            && let Some(segment) = payload.get(..PROBE_LEN)
        {
            let mut probe = [0u8; PROBE_LEN];
            probe.copy_from_slice(segment);
            self.queue_probes(addr, &[probe]);
            return;
        }
        let pushed = {
            let mut queue = self.inbound_synthetic.lock_or_recover();
            if queue.len() >= INBOUND_RELAY_QUEUE_CAP {
                false
            } else {
                queue.push_back((addr, payload.to_vec()));
                true
            }
        };
        if !pushed {
            self.inbound_relay_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if let Some(waker) = self.waker.lock_or_recover().take() {
            waker.wake();
        }
    }

    /// Puts section 3's drop rule in force, from this call onwards and
    /// permanently. Called before the gate is dialled, so the rule is armed
    /// from the first packet, and again by
    /// [`PorchSocket::attach_gate`]. Nothing un-arms it.
    pub fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    /// Whether the drop rule is in force.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }

    /// Arms `attempt`'s probe key, so probes authenticating under it are
    /// queued for the doorbell instead of dropped.
    pub fn arm_probe_key(&self, attempt: [u8; 16], key: [u8; 32]) {
        self.probe_keys.lock_or_recover().insert(attempt, key);
    }

    /// Disarms `attempt`'s probe key and discards anything of that
    /// attempt's still queued, which is what ends a doorbell attempt as far
    /// as this socket is concerned.
    pub fn disarm_probe_key(&self, attempt: &[u8; 16]) {
        self.probe_keys.lock_or_recover().remove(attempt);
        self.inbound_probes
            .lock_or_recover()
            .retain(|(_, probe)| probe.attempt != *attempt);
    }

    /// Probe segments dropped because no armed key authenticated them,
    /// which includes every probe-shaped packet arriving while no attempt
    /// is running.
    #[must_use]
    pub fn probes_unauthenticated(&self) -> u64 {
        self.probes_unauthenticated.load(Ordering::Relaxed)
    }

    /// Authenticated probes dropped because the queue was full.
    #[must_use]
    pub fn inbound_probes_dropped(&self) -> u64 {
        self.inbound_probes_dropped.load(Ordering::Relaxed)
    }

    /// The form `addr` must take to be sent from this socket: a V4
    /// destination on an IPv6 (dual-stack) socket becomes its IPv4-mapped
    /// form, and everything else is unchanged.
    ///
    /// Not cosmetic. A raw `sendmsg` with an `AF_INET` address on an
    /// `AF_INET6` socket does not reach the destination, and the send
    /// reports success, so a probe sent without this mapping is silently
    /// never delivered and a direct path never proves itself.
    fn map_destination(&self, addr: SocketAddr) -> SocketAddr {
        match addr {
            SocketAddr::V4(v4) if self.local_is_ipv6 => {
                SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
            }
            other => other,
        }
    }

    /// Allows QUIC packets from `addr` to reach quinn unchanged.
    ///
    /// **This is the exception section 3's drop rule needs, and the design
    /// does not name it.** Section 3 says "direct packets from an address
    /// in no peer's candidate table are dropped, which is a feature: nobody
    /// publishes where a house is (D3), so every real path came from a
    /// ticket, discovery or a candidate exchange". It is written about
    /// *peer* paths, and it is silent about the house's own connections to
    /// its gate, which ride this same socket and whose addresses are in no
    /// peer's candidate table: the primary address the house dialled, and
    /// the secondary reflection port the gate names in `Registered`
    /// (frame 2). Implementing the rule without that exception drops the
    /// gate's reflection replies and `Reflect` never completes, which is
    /// how this was found.
    ///
    /// The smaller reading, taken here: an address the house itself
    /// deliberately dialled is allowed, and nothing else is. That keeps the
    /// property the rule exists for, since a stranger's address is one the
    /// house never dialled and never proved, while letting the two gate
    /// connections work. Recorded as a design gap in the pull request.
    /// Returns the lease that connection must give back to
    /// [`PorchSocket::forget_source`] when it closes; one call, one live
    /// set, so two connections on one address are two entries and the
    /// first close leaves the second's packets admitted.
    pub fn allow_source(&self, addr: SocketAddr) -> SourceLease {
        let lease = SourceLease(self.next_source_lease.fetch_add(1, Ordering::Relaxed));
        self.allowed_sources
            .lock_or_recover()
            .allow(lease, unmap_v4(addr));
        lease
    }

    /// Withdraws one connection's set, for a short-lived connection such
    /// as a `Reflect` that has finished.
    ///
    /// It takes the lease rather than an address on purpose: an address is
    /// not a connection, and withdrawing by address withdrew it for
    /// everyone. An address another live connection still holds stays in
    /// the union.
    pub fn forget_source(&self, lease: SourceLease) {
        self.allowed_sources.lock_or_recover().forget(lease);
    }

    /// The number of inbound QUIC segments dropped for arriving from an
    /// address this house has neither dialled nor proved, for tests and
    /// diagnostics.
    #[must_use]
    pub fn unknown_source_dropped(&self) -> u64 {
        self.unknown_source_dropped.load(Ordering::Relaxed)
    }

    /// Registers `peer` in the path table on the relay path, reachable by
    /// its key and by `synthetic`, and returns the shared entry the
    /// doorbell upgrades and falls back on.
    ///
    /// Section 2 step 2: every peer starts relayed, so this is called when
    /// the relay session is registered, not when a path is proved.
    pub fn insert_relay_path(&self, peer: [u8; 32], synthetic: SocketAddr) -> PathEntry {
        self.paths.lock_or_recover().insert_relay(peer, synthetic)
    }

    /// The path entry for `peer`, if it has one.
    #[must_use]
    pub fn path_for(&self, peer: &[u8; 32]) -> Option<PathEntry> {
        self.paths.lock_or_recover().get(peer).cloned()
    }

    /// The path entry behind a synthetic address, if one is registered.
    ///
    /// The one question a house answering an incoming peer dial can ask
    /// before the handshake proves who it is: quinn reports the dial as
    /// coming from the synthetic address this socket rewrote it to
    /// (section 3), and that address is what names the peer's path table
    /// entry and so its congestion epoch.
    #[must_use]
    pub fn path_by_synthetic(&self, synthetic: &SocketAddr) -> Option<PathEntry> {
        self.paths
            .lock_or_recover()
            .get_by_synthetic(synthetic)
            .cloned()
    }

    /// Sends one already-encoded probe straight to `to` on the real socket,
    /// bypassing the relay and the path table both.
    ///
    /// A probe is how a candidate is proved, so it must go to the candidate
    /// itself even while this peer's traffic is still relayed; and it rides
    /// this socket rather than a second one because a NAT mapping is per
    /// socket, so anything punched on another socket is punched on a public
    /// port that is not QUIC's (section 3).
    ///
    /// # Errors
    ///
    /// Returns whatever the underlying send returns, including
    /// [`io::ErrorKind::WouldBlock`] if the socket is not writable; a probe
    /// is cheap and repeated every 100 ms, so a caller may simply drop it.
    pub fn send_probe(&self, to: SocketAddr, probe: &[u8; PROBE_LEN]) -> io::Result<()> {
        // Section 4 applies to whichever path is carrying the visit, and a
        // relayed visit's path is the relay session. A probe addressed to
        // the peer's synthetic address is therefore wrapped as a `Relay`
        // payload and shaped like any other relayed datagram rather than
        // written to the wire, where a ULA that names nothing would go
        // nowhere. There is no ambiguity to resolve: a synthetic address is
        // a `fd00::/8` address this house invented and can never be a
        // candidate, so a real candidate probe still takes the branch
        // below.
        if let Some(session) = self.relay_session_for(to) {
            return self.send_probe_relayed(session, to, probe);
        }
        let transmit = Transmit {
            destination: self.map_destination(to),
            ecn: None,
            contents: probe,
            segment_size: None,
            src_ip: None,
        };
        self.udp.try_io(Interest::WRITABLE, || {
            self.state.send((&self.udp).into(), &transmit)
        })
    }

    /// The relay session registered for `synthetic_peer`, if that address
    /// is one.
    fn relay_session_for(&self, synthetic_peer: SocketAddr) -> Option<u32> {
        self.relay
            .lock_or_recover()
            .by_synthetic
            .get(&synthetic_peer)
            .copied()
    }

    /// Sends one probe through `session`'s shaped queue.
    ///
    /// The same queue every relayed QUIC packet for this peer goes through,
    /// so a relay probe is delayed and counted exactly as the traffic it is
    /// measuring is, which is the only way its round trip means anything.
    /// No gate-attached check, unlike [`PorchSocket::try_send`]'s relay
    /// branch: that one exists so quinn gets a hard error to back off on,
    /// while `register_relay_session` already documents that registering a
    /// session and attaching a gate may happen in either order and that the
    /// drain task starts with whichever arrives second. A probe queued
    /// before a gate attaches therefore leaves when one does, and the only
    /// caller is a visit already carrying its traffic through that gate.
    fn send_probe_relayed(
        &self,
        session: u32,
        synthetic_peer: SocketAddr,
        probe: &[u8; PROBE_LEN],
    ) -> io::Result<()> {
        let payload = encode_relay(session, probe).map_err(|e| io::Error::other(e.to_string()))?;
        let Some(shaper) = self.shaper_for(synthetic_peer) else {
            return Err(io::Error::other(
                "no path table entry for a registered relay session",
            ));
        };
        match shaper.enqueue_or_drop(payload) {
            Enqueued::Accepted => Ok(()),
            // A probe is cheap and repeated, so a full queue drops this one
            // rather than blocking: the caller documents exactly that.
            Enqueued::Full => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            Enqueued::Closed => Err(io::Error::other("relay session closed")),
        }
    }

    /// Takes the next probe lifted out of the inbound stream, if one is
    /// waiting, with the real source address it arrived from.
    #[must_use]
    pub fn try_recv_probe(&self) -> Option<(SocketAddr, Probe)> {
        self.inbound_probes.lock_or_recover().pop_front()
    }

    /// Waits for the next inbound probe.
    ///
    /// One waiter at a time: the doorbell is a single task per house, and a
    /// second waiter would silently displace the first, which is the very
    /// shape issue #19 was.
    pub async fn recv_probe(&self) -> (SocketAddr, Probe) {
        std::future::poll_fn(|cx| {
            if let Some(probe) = self.try_recv_probe() {
                return Poll::Ready(probe);
            }
            *self.probe_waker.lock_or_recover() = Some(cx.waker().clone());
            match self.try_recv_probe() {
                Some(probe) => Poll::Ready(probe),
                None => Poll::Pending,
            }
        })
        .await
    }

    /// Rewrites one received buffer in place, dropping every probe segment
    /// into the probe queue and repacking what is left.
    ///
    /// Section 3 requires the split to be **by segment, not by buffer**:
    /// quinn-udp opportunistically enables UDP GRO, and `RecvMeta::stride`
    /// documents that one buffer may hold several datagrams with the last
    /// shorter, so a probe can arrive coalesced behind QUIC. Returns the
    /// number of bytes of QUIC left in the buffer, which is zero if the
    /// whole buffer was probes.
    fn filter_probes(&self, buf: &mut [u8], meta: &RecvMeta) -> usize {
        let stride = if meta.stride == 0 {
            meta.len
        } else {
            meta.stride
        };
        let len = meta.len.min(buf.len());
        let mut read = 0usize;
        let mut write = 0usize;
        let mut probes = Vec::new();
        while read < len {
            let end = read.saturating_add(stride).min(len);
            let Some(segment) = buf.get(read..end) else {
                break;
            };
            if is_probe(segment) {
                let mut probe = [0u8; PROBE_LEN];
                if let Some(source) = segment.get(..PROBE_LEN) {
                    probe.copy_from_slice(source);
                    probes.push(probe);
                }
            } else {
                let segment_len = end.saturating_sub(read);
                if write != read {
                    buf.copy_within(read..end, write);
                }
                write = write.saturating_add(segment_len);
            }
            read = end;
        }
        if !probes.is_empty() {
            // The source is unmapped before it is queued: a dual-stack
            // socket reports an IPv4 peer as `::ffff:a.b.c.d`, while the
            // candidate the doorbell scores came from frame 16 as plain
            // IPv4, and a pong whose source does not compare equal to the
            // candidate it answers proves nothing at all.
            let source = unmap_v4(meta.addr);
            self.queue_probes(source, &probes);
        }
        write
    }

    /// Authenticates each extracted probe segment against every armed
    /// attempt key and queues what verifies, bounded and counted.
    ///
    /// Nothing unauthenticated is ever queued, so a stranger reaching the
    /// porch port cannot grow this queue at all, which is the property the
    /// cap alone would not give: with no attempt running there is no armed
    /// key, so every probe-shaped packet is dropped here and the queue
    /// stays empty rather than filling with 81 bytes per packet for a
    /// consumer that does not exist. A probe's *source* deliberately is not
    /// checked, since the whole point of the burst is to hear from a
    /// mapping nobody has seen yet; the keyed hash section 2 specifies is
    /// the check, and it is the stronger of the two.
    fn queue_probes(&self, source: SocketAddr, segments: &[[u8; PROBE_LEN]]) {
        let keys: Vec<[u8; 32]> = {
            let armed = self.probe_keys.lock_or_recover();
            if armed.is_empty() {
                self.probes_unauthenticated
                    .fetch_add(segments.len() as u64, Ordering::Relaxed);
                return;
            }
            armed.values().copied().collect()
        };
        let mut woke = false;
        for segment in segments {
            let Some(probe) = keys.iter().find_map(|key| Probe::decode(segment, key)) else {
                self.probes_unauthenticated.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let pushed = {
                let mut queue = self.inbound_probes.lock_or_recover();
                if queue.len() >= INBOUND_PROBE_QUEUE_CAP {
                    false
                } else {
                    queue.push_back((source, probe));
                    true
                }
            };
            if pushed {
                woke = true;
            } else {
                self.inbound_probes_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        if woke && let Some(waker) = self.probe_waker.lock_or_recover().take() {
            waker.wake();
        }
    }

    /// What quinn may be shown of a packet from real source `addr`
    /// (section 3).
    ///
    /// An address a peer proved is presented as that peer's stable
    /// synthetic address, which is the indirection that lets an upgrade
    /// happen without quinn migrating and without a **client** connection
    /// hitting `panic!("packets from unknown remote should be dropped by
    /// clients")` (`quinn-proto/src/connection/mod.rs:3016-3018`). An
    /// address this house dialled itself (see
    /// [`PorchSocket::allow_source`]) is shown unchanged. Anything else is
    /// dropped before quinn sees it, which is section 3's rule.
    fn classify_source(&self, addr: SocketAddr) -> SourceVerdict {
        // The porch socket is bound IPv6-unspecified and dual-stack, so an
        // IPv4 peer's packets are reported with an IPv4-mapped source
        // (`::ffff:a.b.c.d`) while the address the house dialled and the
        // address a candidate exchange named are plain IPv4. Comparing the
        // two forms unmapped is not cosmetic: without it every gate
        // connection over IPv4 is dropped by the rule below, which is
        // exactly what happened when this landed.
        let addr = unmap_v4(addr);
        // The allow-list is asked first because it is the common case by a
        // wide margin (the gate connection carries every relayed byte) and
        // because a proved direct address is never on it, so the order
        // changes nothing but the cost. Both lookups are allocation-free:
        // this runs once per received datagram, against section 3's
        // reversing condition (b), so the `Vec` an
        // "every direct address" call would build is one allocation per
        // packet and is not used here.
        if self.allowed_sources.lock_or_recover().contains(&addr) {
            return SourceVerdict::Keep;
        }
        if let Some(synthetic) = self.paths.lock_or_recover().synthetic_for_direct(addr) {
            return SourceVerdict::Rewrite(synthetic);
        }
        if !self.armed.load(Ordering::SeqCst) {
            // A porch socket that has not been armed has dialled nothing
            // and can hold no peer connection, so the rule below has
            // nothing to guard yet; without this arm the section 3
            // benchmark, which measures exactly a bare porch socket, hung
            // for 53 minutes on 0.05 s of CPU with every packet dropped.
            // Keyed on an explicit flag that nothing clears, rather than on
            // the allow-list being empty, which fails *open* the moment
            // `forget_source` empties it (Konrad's must 2, Yseult's
            // Medium). The rewrite above is deliberately ahead of it: a
            // proved direct path must be presented as its synthetic address
            // whether or not the rule is in force, or quinn's client
            // connection meets a remote it has never heard of.
            return SourceVerdict::Keep;
        }
        SourceVerdict::Drop
    }

    /// Splits one batch of received buffers into what quinn may see and
    /// what it may not: probe segments go to the probe queue, QUIC segments
    /// stay, and a source address in no peer's path table is dropped.
    ///
    /// Returns how many of the `count` buffers still carry QUIC bytes. A
    /// buffer emptied here keeps its slot with `len` zero rather than being
    /// compacted out, because quinn reads exactly `buf[0..meta.len]` and
    /// then loops `while !data.is_empty()`
    /// (`quinn/src/endpoint.rs:795-799`), so a zero-length entry costs one
    /// skipped iteration and nothing else, while shuffling the slots would
    /// have to move the buffers to match.
    fn demultiplex(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
        count: usize,
    ) -> usize {
        let mut carrying = 0usize;
        let limit = count.min(bufs.len()).min(meta.len());
        for index in 0..limit {
            let Some(original) = meta.get(index).copied() else {
                break;
            };
            let Some(buf) = bufs.get_mut(index) else {
                break;
            };
            let kept = self.filter_probes(buf, &original);
            let verdict = if kept == 0 {
                SourceVerdict::Drop
            } else {
                self.classify_source(original.addr)
            };
            let Some(slot) = meta.get_mut(index) else {
                break;
            };
            match verdict {
                SourceVerdict::Drop => {
                    if kept > 0 {
                        self.unknown_source_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                    slot.len = 0;
                }
                SourceVerdict::Keep => {
                    slot.len = kept;
                    carrying = carrying.saturating_add(1);
                }
                SourceVerdict::Rewrite(synthetic) => {
                    slot.len = kept;
                    slot.addr = synthetic;
                    carrying = carrying.saturating_add(1);
                }
            }
        }
        carrying
    }

    /// Fills up to `budget` leading slots of `bufs`/`meta` from the inbound
    /// relay queue, returning how many it filled.
    fn drain_queue_into(
        &self,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
        budget: usize,
    ) -> usize {
        let mut filled = 0usize;
        let mut queue = self.inbound_synthetic.lock_or_recover();
        while filled < budget {
            let Some((addr, payload)) = queue.pop_front() else {
                break;
            };
            #[allow(clippy::indexing_slicing)]
            let buf = &mut bufs[filled];
            let n = payload.len().min(buf.len());
            #[allow(clippy::indexing_slicing)]
            buf[..n].copy_from_slice(&payload[..n]);
            #[allow(clippy::indexing_slicing)]
            {
                meta[filled] = RecvMeta {
                    addr,
                    len: n,
                    stride: n,
                    ecn: None,
                    dst_ip: None,
                };
            }
            filled += 1;
        }
        filled
    }
}

/// One task's write-readiness registration on a [`PorchSocket`] (issue #19).
///
/// `AsyncUdpSocket::create_io_poller`'s contract is that *each* poller
/// "can store a separate `Waker`", so that "any number of interested tasks"
/// wait on the same socket and "be notified concurrently"
/// (`quinn/src/runtime.rs:44-52`). That is not decoration: every
/// `quinn::Connection` on one endpoint builds its own poller
/// (`quinn/src/connection.rs:907`) and calls `poll_writable` before every
/// transmit (`:1031`), so a house with a gate connection and a peer
/// connection on the same porch socket has two tasks waiting at once.
///
/// So this holds its own `writable()` future rather than calling
/// `tokio::net::UdpSocket::poll_send_ready`, which is what it used to do.
/// `poll_send_ready` funnels every caller into tokio's *single* per
/// direction waker slot (`tokio-1.53.1/src/runtime/io/scheduled_io.rs:316-326`
/// stores into one `waiters.writer`, overwriting whatever was there), so
/// the second connection's driver silently evicted the first one's waker
/// and the first was never woken when the socket drained. An owned
/// `writable()` future instead pushes a node onto tokio's intrusive waiter
/// list (`:111-131`), one per poller, and every waiter is woken. This is
/// exactly the shape quinn's own tokio socket uses
/// (`quinn/src/runtime/tokio.rs:58-62` through `UdpPollHelper`,
/// `quinn/src/runtime.rs:130-153`), reproduced here rather than reused
/// because `UdpPollHelper` is crate-private to quinn.
/// What the porch socket does with a received buffer's real source address
/// before quinn sees it (section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceVerdict {
    /// Show it to quinn unchanged: the house dialled this address itself.
    Keep,
    /// Show it as this peer's synthetic address.
    Rewrite(SocketAddr),
    /// Never let quinn see it.
    Drop,
}

struct PorchPoller {
    socket: Arc<PorchSocket>,
    /// The synthetic peer address this poller's connection relays to, once
    /// it has adopted one from [`LAST_RELAY_DESTINATION`]. `None` for a
    /// connection that has never sent a relayed transmit, chiefly the gate
    /// connection itself, which is therefore never gated on a shaper.
    relay_destination: Option<SocketAddr>,
    /// The in-flight `writable()` future, kept across `poll_writable` calls
    /// so its waiter-list node stays registered, and dropped as soon as it
    /// resolves because polling a `Future` after it is ready is a logic
    /// error.
    writable: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl fmt::Debug for PorchPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PorchPoller").finish()
    }
}

impl UdpPoller for PorchPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A relay send never blocks on socket writability at all (see the
        // module doc's design note on `send_datagram`), but quinn calls
        // this before it knows a transmit's destination, so a relayed peer
        // connection waits on the real socket too; all the more reason its
        // wakeup must not be lost.
        //
        // `Self` is `Unpin` (an `Arc` and a boxed future), so `get_mut` is
        // free of the pin gymnastics `UdpPollHelper` needs for an unboxed
        // future.
        let Self {
            socket,
            writable,
            relay_destination,
        } = self.get_mut();
        if let Some(destination) = socket.take_relay_intent() {
            *relay_destination = Some(destination);
        }
        // Section 1's back-pressure: a full queue is `Pending` here, not a
        // `WouldBlock` out of `try_send`, which would clear write
        // readiness endpoint-wide and spin the retry loop. A peer already
        // upgraded to a direct path is not shaped at all, so its entry is
        // asked whether it is still relayed first.
        if let Some(destination) = *relay_destination {
            let shaped = socket
                .paths
                .lock_or_recover()
                .get_by_synthetic(&destination)
                .filter(|entry| entry.direct_addr().is_none())
                .map(|entry| entry.egress().clone());
            // Room for a whole batch, not for one datagram: quinn may hand
            // `try_send` a GSO transmit of up to `max_transmit_segments`
            // segments, each of which is its own `Relay` datagram, and the
            // shaper takes a transmit whole or not at all.
            if let Some(shaper) = shaped
                && !shaper.poll_room(socket.max_transmit_segments().max(1), cx.waker())
            {
                return Poll::Pending;
            }
        }
        let future = writable.get_or_insert_with(|| {
            let socket = Arc::clone(socket);
            Box::pin(async move { socket.udp.writable().await })
                as Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>
        });
        let result = future.as_mut().poll(cx);
        if result.is_ready() {
            *writable = None;
        }
        result
    }
}

impl AsyncUdpSocket for PorchSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(PorchPoller {
            socket: self,
            writable: None,
            relay_destination: None,
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        // Section 2 step 6: once a candidate has proved itself, this peer's
        // traffic leaves on the wire to it. The batch passes through
        // untouched, GSO intact, with only the destination rewritten from
        // the synthetic address quinn addressed it to; splitting it the way
        // the relay must would throw away the one advantage a direct path
        // has.
        let direct = self
            .paths
            .lock_or_recover()
            .get_by_synthetic(&transmit.destination)
            .and_then(crate::path::PathEntry::direct_addr);
        if let Some(direct) = direct {
            // Not relayed, so this poller's connection must not stay
            // adopted onto a shaper queue.
            self.note_relay_intent(None);
            let rewritten = Transmit {
                destination: self.map_destination(direct),
                ecn: transmit.ecn,
                contents: transmit.contents,
                segment_size: transmit.segment_size,
                src_ip: transmit.src_ip,
            };
            return self.udp.try_io(Interest::WRITABLE, || {
                self.state.send((&self.udp).into(), &rewritten)
            });
        }
        let session = {
            let routes = self.relay.lock_or_recover();
            routes.by_synthetic.get(&transmit.destination).copied()
        };
        if let Some(session) = session {
            let gate_attached = self.relay.lock_or_recover().gate.is_some();
            if !gate_attached {
                return Err(io::Error::other(
                    "no gate connection attached to relay through",
                ));
            }
            // Section 3: quinn sets `Transmit::segment_size` whenever it
            // wrote more than one datagram into `contents` (GSO), and each
            // segment is its own inner QUIC packet needing its own `Relay`
            // header. Splitting on anything but `segment_size` (or ignoring
            // it, as this used to) wraps the whole batch as one over-cap
            // `Relay` payload: `encode_relay` errors past
            // `RELAY_PAYLOAD_CAP` for anything beyond a single segment, and
            // even where it does not, the far side would receive one
            // unparseable blob instead of N QUIC packets.
            let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
            if segment_size == 0 {
                return Ok(());
            }
            let mut payloads = Vec::new();
            for segment in transmit.contents.chunks(segment_size) {
                payloads.push(
                    encode_relay(session, segment).map_err(|e| io::Error::other(e.to_string()))?,
                );
            }
            // Section 1: the datagrams go into this session's shaped queue
            // and leave it at the rate, rather than straight onto the gate
            // connection. Nothing is dropped here; a full queue refuses the
            // whole transmit, which quinn buffers and retries after the
            // `poll_writable` above has gone `Pending` and been woken.
            let shaper = self.shaper_for(transmit.destination);
            self.note_relay_intent(Some(transmit.destination));
            let Some(shaper) = shaper else {
                return Err(io::Error::other(
                    "no path table entry for a registered relay session",
                ));
            };
            return match shaper.try_enqueue_all(payloads) {
                Enqueued::Accepted => Ok(()),
                // The last resort: a `WouldBlock` here clears write
                // readiness endpoint-wide, so `poll_writable` going
                // `Pending` above is what should have caught this.
                Enqueued::Full => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                // Not transient, so not `WouldBlock`: retrying a queue
                // whose session has ended would spin.
                Enqueued::Closed => Err(io::Error::other("relay session closed")),
            };
        }
        self.note_relay_intent(None);
        self.udp.try_io(Interest::WRITABLE, || {
            self.state.send((&self.udp).into(), transmit)
        })
    }

    /// Amended section 3's anti-starvation rule: this call draws from the
    /// inbound relay queue *and* the real socket, rather than draining
    /// either one first regardless of the other. Two shapes were tried and
    /// rejected during development, each starving one side completely
    /// rather than merely slowing it, because the real socket is what
    /// feeds the queue in the first place (every `Relay` datagram arrives
    /// as a real-socket read on the gate connection, decoded and queued by
    /// the background task `attach_gate` spawns): queue-always-first (the
    /// original shape) can leave the real socket never polled while the
    /// queue stays non-empty, which is the load-dependent stall a cold
    /// `ci/check.sh` run reproduced; socket-always-first starves the queue
    /// outright under real relay volume instead, since the real socket is
    /// then essentially never idle, which failed
    /// `relay_path_carries_10_mib_unchanged` outright (`ConnectionLost`)
    /// when tried here. With more than one buffer slot available (GRO
    /// batching), the queue fills every slot but the last, always leaving
    /// the real socket a slot in the same call. With exactly one slot
    /// available (no batching, the case on a platform without GRO), a
    /// fixed order cannot serve both in one call, so consecutive calls
    /// alternate which one goes first, and if the first choice has nothing,
    /// the other is still tried before returning `Pending`.
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() {
            return Poll::Ready(Ok(0));
        }
        *self.waker.lock_or_recover() = Some(cx.waker().clone());

        let queue_first = bufs.len() > 1
            || !self
                .poll_recv_prefer_socket
                .fetch_xor(true, Ordering::Relaxed);
        let queue_budget = if queue_first {
            if bufs.len() > 1 { bufs.len() - 1 } else { 1 }
        } else {
            0
        };

        let mut filled = 0usize;
        if queue_budget > 0 {
            filled = self.drain_queue_into(bufs, meta, queue_budget);
        }
        if filled == bufs.len() {
            return Poll::Ready(Ok(filled));
        }

        #[allow(clippy::indexing_slicing)]
        let remaining_bufs = &mut bufs[filled..];
        #[allow(clippy::indexing_slicing)]
        let remaining_meta = &mut meta[filled..];
        let socket_result = loop {
            match self.udp.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {
                    let result = self.udp.try_io(Interest::READABLE, || {
                        self.state
                            .recv((&self.udp).into(), remaining_bufs, remaining_meta)
                    });
                    match result {
                        Ok(n) => {
                            let carrying = self.demultiplex(remaining_bufs, remaining_meta, n);
                            // Section 3: "if a whole batch was probes it
                            // loops and re-polls rather than returning
                            // `Ok(0)`, which quinn's driver would treat as
                            // progress". Only when this call has nothing
                            // else to hand back, for the same reason the
                            // `WouldBlock` arm below is guarded: once the
                            // queue has served something, looping here
                            // would discard it by never returning.
                            if carrying == 0 && filled == 0 {
                                continue;
                            }
                            break Some(Ok(n));
                        }
                        // `poll_recv_ready` can report ready and then have
                        // the non-blocking read turn up `WouldBlock` anyway
                        // (a spurious or already-consumed readiness event);
                        // the fix, matching `quinn`'s own tokio runtime
                        // (`quinn/src/runtime/tokio.rs:71-79`), is to loop
                        // back and call `poll_recv_ready` again immediately
                        // rather than returning early, since a bare
                        // `Pending` here without re-arming it can miss the
                        // next real wakeup. Only safe to retry when this
                        // call has filled nothing yet: once the queue has
                        // served something, a busy-loop here would discard
                        // it by never returning.
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock && filled == 0 => continue,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break None,
                        Err(e) => break Some(Err(e)),
                    }
                }
                Poll::Ready(Err(e)) => break Some(Err(e)),
                Poll::Pending => break None,
            }
        };
        match socket_result {
            Some(Ok(n)) => return Poll::Ready(Ok(filled + n)),
            Some(Err(e)) => {
                if filled > 0 {
                    return Poll::Ready(Ok(filled));
                }
                return Poll::Ready(Err(e));
            }
            None => {}
        }
        if filled > 0 {
            return Poll::Ready(Ok(filled));
        }

        // This call's chosen order had nothing (queue was empty and given
        // first turn, or it was the socket's turn and it had nothing): try
        // whichever source has not been tried yet before giving up, so a
        // queue with data waiting is never left for a later call while
        // this one returns `Pending`.
        if queue_budget == 0 {
            filled = self.drain_queue_into(bufs, meta, 1);
            if filled > 0 {
                return Poll::Ready(Ok(filled));
            }
        }
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    fn may_fragment(&self) -> bool {
        // The real socket state's own `may_fragment()` is ignored on
        // purpose: this override to `false` is what disables quinn's MTU
        // discovery for every connection on this endpoint (see the module
        // doc), which the gate connection's `max_datagram_size() >= 1205`
        // requirement depends on.
        false
    }

    fn max_transmit_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.state.gro_segments()
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
    fn synthetic_addr_is_stable_and_a_ula() {
        let salt = [1, 2, 3, 4, 5];
        let key = [7u8; 32];
        let a = synthetic_addr(salt, &key);
        let b = synthetic_addr(salt, &key);
        assert_eq!(a, b);
        let SocketAddr::V6(v6) = a else {
            panic!("expected an IPv6 synthetic address");
        };
        assert_eq!(v6.ip().octets()[0], 0xfd);
        assert_eq!(v6.port(), 1);
    }

    #[test]
    fn different_peers_get_different_synthetic_addresses() {
        let salt = [1, 2, 3, 4, 5];
        let a = synthetic_addr(salt, &[1u8; 32]);
        let b = synthetic_addr(salt, &[2u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn may_fragment_is_always_false() {
        let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let socket = PorchSocket::new(std_socket).unwrap();
        assert!(!socket.may_fragment());
    }

    /// Amended section 3's drop policy: once the inbound relay queue is
    /// full, the *newest* arrival is dropped and counted, the queue itself
    /// (its oldest entries) left untouched.
    ///
    /// Deliberate break to fail this test: in `deliver_synthetic`, swap the
    /// full-queue branch back to `queue.pop_front()` then `push_back` (drop
    /// the oldest, uncounted). The dropped count then stays 0 and the
    /// queue's front entry becomes a later payload instead of the first
    /// one ever delivered.
    #[test]
    fn full_queue_drops_the_newest_arrival_and_counts_it() {
        let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let socket = PorchSocket::new(std_socket).unwrap();
        let synthetic = synthetic_addr([1, 2, 3, 4, 5], &[9u8; 32]);
        socket.register_relay_session(1, synthetic);

        let overflow = 5;
        for i in 0..(INBOUND_RELAY_QUEUE_CAP + overflow) {
            #[allow(clippy::cast_possible_truncation)]
            socket.deliver_synthetic(1, &[i as u8]);
        }

        assert_eq!(socket.inbound_relay_dropped(), overflow as u64);
        let queue = socket.inbound_synthetic.lock_or_recover();
        assert_eq!(queue.len(), INBOUND_RELAY_QUEUE_CAP);
        assert_eq!(queue.front().unwrap().1, vec![0u8]);
    }

    /// Section 4 reaches the relay path: a probe addressed to a registered
    /// relay session's synthetic address is wrapped as a `Relay` payload
    /// and put on that session's shaped queue, not written to the wire
    /// where a `fd00::/8` address that names nothing would go nowhere.
    ///
    /// Deliberate break to fail this test: delete the `relay_session_for`
    /// branch from `send_probe`, which is exactly the code before this fix.
    /// The probe then takes the raw-socket path, the shaper stays empty,
    /// and the length assertion below fails. That is the bug: a relayed
    /// visit could not be probed at all, so it had no liveness and died in
    /// silence.
    #[test]
    fn a_probe_to_a_synthetic_address_goes_through_the_relay_not_the_wire() {
        let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let socket = PorchSocket::new(std_socket).unwrap();
        let synthetic = synthetic_addr([1, 2, 3, 4, 5], &[9u8; 32]);
        socket.register_relay_session(7, synthetic);
        let shaper = socket.shaper_for(synthetic).unwrap();
        assert_eq!(shaper.len(), 0);

        let probe = Probe {
            kind: crate::punch::PROBE_PING,
            attempt: [3u8; 16],
            tx: [4u8; 8],
            observed: crate::gate::wire::Addr::default(),
        }
        .encode(&[5u8; 32]);

        // Queued on the peer's own shaper, one relayed datagram like any
        // other, and nothing was written to the real socket.
        assert!(socket.send_probe(synthetic, &probe).is_ok());
        assert_eq!(shaper.len(), 1);

        // A real address still takes the wire, which is the branch the
        // doorbell's candidate burst uses: whether the send itself
        // succeeds is the reactor's business, but it must not have gone
        // anywhere near this peer's relay queue.
        let elsewhere: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let _ = socket.send_probe(elsewhere, &probe);
        assert_eq!(shaper.len(), 1);
    }

    /// The receive half of the same split: a probe arriving over the relay
    /// is lifted into the probe queue with the synthetic address as its
    /// source, never handed to quinn, which has no idea what an 81 byte
    /// non-QUIC packet is.
    ///
    /// Deliberate break to fail this test: delete the `is_probe` branch
    /// from `deliver_synthetic`. The probe then lands in
    /// `inbound_synthetic` and the two assertions below swap.
    #[test]
    fn a_probe_arriving_over_the_relay_is_lifted_into_the_probe_queue() {
        let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let socket = PorchSocket::new(std_socket).unwrap();
        let synthetic = synthetic_addr([1, 2, 3, 4, 5], &[9u8; 32]);
        socket.register_relay_session(7, synthetic);
        let key = [5u8; 32];
        socket.arm_probe_key([3u8; 16], key);

        let probe = Probe {
            kind: crate::punch::PROBE_PONG,
            attempt: [3u8; 16],
            tx: [4u8; 8],
            observed: crate::gate::wire::Addr::default(),
        }
        .encode(&key);
        socket.deliver_synthetic(7, &probe);

        assert_eq!(socket.inbound_synthetic.lock_or_recover().len(), 0);
        let (from, received) = socket.try_recv_probe().expect("the probe was queued");
        assert_eq!(from, synthetic);
        assert_eq!(received.tx, [4u8; 8]);

        // A relayed QUIC packet still goes where it always went.
        socket.deliver_synthetic(7, &[0x40u8; 32]);
        assert_eq!(socket.inbound_synthetic.lock_or_recover().len(), 1);
    }

    /// Section 3's per-packet gate-address check, the leaving half: an
    /// address is in the live gate-address set from its connection's
    /// registration and leaves it when that connection closes, after which
    /// a datagram from it is dropped and counted rather than shown to
    /// quinn.
    ///
    /// This drives the real receive-path function, `demultiplex`, which is
    /// what `poll_recv` calls, rather than the classification alone, so it
    /// asserts both halves: dropped (the slot is emptied and the buffer
    /// count excludes it) and counted (`unknown_source_dropped`).
    ///
    /// Deliberate break to fail this test: make `AllowedSources::forget` a
    /// no-op, which is what an address staying admissible after its
    /// connection closed looks like. The packet is then kept and both
    /// assertions below fail.
    #[test]
    fn a_datagram_from_a_closed_gate_connections_address_is_dropped_and_counted() {
        let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let socket = PorchSocket::new(std_socket).unwrap();
        let gate_addr: SocketAddr = "203.0.113.11:4433".parse().unwrap();

        // Registration: the address enters the live set and the rule is
        // armed.
        let lease = socket.allow_source(gate_addr);
        socket.arm();
        assert!(socket.is_source_allowed(gate_addr));

        // One QUIC-shaped packet (fixed bit set, so the probe filter
        // leaves it alone) from that address, while the connection is
        // live.
        let mut storage = [0x40u8; 64];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut meta = [RecvMeta {
            addr: gate_addr,
            len: 64,
            stride: 64,
            ecn: None,
            dst_ip: None,
        }];
        assert_eq!(socket.demultiplex(&mut bufs, &mut meta, 1), 1);
        assert_eq!(meta[0].len, 64);
        assert_eq!(socket.unknown_source_dropped(), 0);

        // The connection closes. `detach_gate`, which `attach_gate`'s
        // reader task runs on its way out, hands back exactly this
        // connection's lease; that a real close reaches it is asserted in
        // `gate::a_closed_gate_connections_address_leaves_the_live_set`,
        // which has a real gate connection to close.
        socket.forget_source(lease);
        assert!(!socket.is_source_allowed(gate_addr));

        meta[0] = RecvMeta {
            addr: gate_addr,
            len: 64,
            stride: 64,
            ecn: None,
            dst_ip: None,
        };
        assert_eq!(
            socket.demultiplex(&mut bufs, &mut meta, 1),
            0,
            "a datagram from a closed gate connection's address reaches nobody"
        );
        assert_eq!(meta[0].len, 0);
        assert_eq!(
            socket.unknown_source_dropped(),
            1,
            "and it is counted, never silently discarded"
        );
    }

    /// Section 3's live gate-address set is "the union of the live sets",
    /// one per connection, so two connections on one address are two
    /// entries and closing the first leaves the second's packets admitted.
    ///
    /// This is the shape a gate naming a `secondary_port` equal to its
    /// primary port produces: `reflect` dials the same address the
    /// registration is already on, and its short connection closing used to
    /// withdraw the address the live registration still needed.
    ///
    /// Deliberate break to fail this test: in `AllowedSources::forget`,
    /// replace the refcount decrement with an unconditional
    /// `self.refcounts.remove(&addr);`, which is the single-set behaviour
    /// this replaced. The first close then blinds the survivor and the
    /// middle assertion fails.
    #[test]
    fn one_connection_closing_does_not_withdraw_an_address_another_still_holds() {
        let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let socket = PorchSocket::new(std_socket).unwrap();
        let shared: SocketAddr = "203.0.113.12:4433".parse().unwrap();
        socket.arm();

        // Two live connections, one address: the registration and a
        // `Reflect` whose secondary port is the primary port.
        let registration = socket.allow_source(shared);
        let reflect = socket.allow_source(shared);
        assert_eq!(
            socket.allowed_sources.lock_or_recover().union_len(),
            1,
            "the union holds one address, however many connections named it"
        );

        let admitted = |socket: &Arc<PorchSocket>| {
            let mut storage = [0x40u8; 32];
            let mut bufs = [IoSliceMut::new(&mut storage)];
            let mut meta = [RecvMeta {
                addr: shared,
                len: 32,
                stride: 32,
                ecn: None,
                dst_ip: None,
            }];
            socket.demultiplex(&mut bufs, &mut meta, 1) == 1
        };

        assert!(admitted(&socket));

        // The reflect connection closes. The registration is still live, so
        // its packets must still be admitted.
        socket.forget_source(reflect);
        assert!(socket.is_source_allowed(shared));
        assert!(
            admitted(&socket),
            "closing one connection must not blind the other"
        );
        assert_eq!(socket.unknown_source_dropped(), 0);

        // The registration closes too, and now nothing holds the address.
        socket.forget_source(registration);
        assert!(!socket.is_source_allowed(shared));
        assert!(!admitted(&socket));
        assert_eq!(socket.unknown_source_dropped(), 1);
        assert_eq!(socket.allowed_sources.lock_or_recover().union_len(), 0);

        // Handing back a lease twice takes nothing extra out of the union.
        socket.forget_source(registration);
        assert_eq!(socket.allowed_sources.lock_or_recover().union_len(), 0);
    }

    /// A waker that counts how many times it was woken, for the
    /// write-readiness registration test below.
    #[derive(Debug, Default)]
    struct CountingWaker {
        wakes: AtomicU64,
    }

    impl CountingWaker {
        fn wakes(&self) -> u64 {
            self.wakes.load(Ordering::SeqCst)
        }
    }

    impl std::task::Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Issue #19: every `UdpPoller` handed out by one porch socket must be
    /// woken when the socket becomes writable, not just the one that
    /// registered last.
    ///
    /// This is the wakeup race behind the stall Yseult measured (4 of 11
    /// isolated `relay_path_carries_10_mib_unchanged` runs, ~123 s of wall
    /// on ~1 s of CPU: parked, not spinning). A house holds two
    /// `quinn::Connection`s on one porch socket, the gate connection and
    /// the peer connection, and each one's driver builds its own poller and
    /// calls `poll_writable` before every transmit. Whichever registered
    /// second used to evict the first's waker from tokio's single
    /// `waiters.writer` slot, so under enough send pressure for the socket
    /// to actually report not-writable, the evicted driver slept until an
    /// unrelated timer happened to wake it.
    ///
    /// The test is deterministic and needs no load: `try_io` with a closure
    /// returning `WouldBlock` clears the socket's write readiness through
    /// tokio's own public API, which is precisely the state a real full
    /// send buffer produces, and the reactor then re-reports writability on
    /// its own.
    ///
    /// Deliberate break to fail this test: in `PorchPoller::poll_writable`,
    /// replace the body with `self.socket.udp.poll_send_ready(cx)` (what it
    /// was before this commit). `first_waker` then stays at 0 wakes while
    /// `second_waker` is woken.
    #[tokio::test]
    async fn every_io_poller_on_one_socket_is_woken_when_it_becomes_writable() {
        let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket = PorchSocket::new(std_socket).unwrap();

        let mut first = Arc::clone(&socket).create_io_poller();
        let mut second = Arc::clone(&socket).create_io_poller();
        let first_waker = Arc::new(CountingWaker::default());
        let second_waker = Arc::new(CountingWaker::default());

        let _ = socket.udp.try_io(Interest::WRITABLE, || {
            Err::<(), io::Error>(io::ErrorKind::WouldBlock.into())
        });

        let w1 = Waker::from(Arc::clone(&first_waker));
        let w2 = Waker::from(Arc::clone(&second_waker));
        assert!(
            first
                .as_mut()
                .poll_writable(&mut Context::from_waker(&w1))
                .is_pending()
        );
        assert!(
            second
                .as_mut()
                .poll_writable(&mut Context::from_waker(&w2))
                .is_pending()
        );

        for _ in 0..200 {
            if first_waker.wakes() > 0 && second_waker.wakes() > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(second_waker.wakes() > 0, "second poller never woken");
        assert!(first_waker.wakes() > 0, "first poller never woken");
    }

    // ------------------------------------------------------------------
    // WO-1.3b, the doorbell's half of the porch socket (section 3). Nested
    // under `punch` so `cargo test -p mosschat-net punch::` catches these
    // alongside `punch.rs`'s own tests, which is the work order's verify
    // line: these cases are the doorbell's, not WO-1.3a's.
    // ------------------------------------------------------------------
    #[allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    mod punch {
        use super::super::*;
        use crate::punch::{PROBE_LEN, PROBE_PING, Probe};
        use std::time::Duration;

        const PROBE_KEY: [u8; 32] = [11u8; 32];
        const ATTEMPT: [u8; 16] = [12u8; 16];

        fn ping() -> Probe {
            Probe {
                kind: PROBE_PING,
                attempt: ATTEMPT,
                tx: [1u8; 8],
                observed: crate::gate::wire::Addr::default(),
            }
        }

        fn a_probe() -> [u8; PROBE_LEN] {
            ping().encode(&PROBE_KEY)
        }

        /// A porch socket with this test module's probe key armed, since a
        /// probe is queued only if it authenticates under an armed key.
        fn porch_with_probe_key() -> Arc<PorchSocket> {
            let socket = porch();
            socket.arm_probe_key(ATTEMPT, PROBE_KEY);
            socket
        }

        /// Waits until the real socket is writable, through the same
        /// `UdpPoller` quinn uses, because `try_io` reports `WouldBlock`
        /// until the reactor has first observed writability.
        async fn wait_writable(socket: &Arc<PorchSocket>) {
            let mut poller = Arc::clone(socket).create_io_poller();
            std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                .await
                .unwrap();
        }

        fn porch() -> Arc<PorchSocket> {
            let std_socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            std_socket.set_nonblocking(true).unwrap();
            PorchSocket::new(std_socket).unwrap()
        }

        /// Section 3: "The filter lives in the porch socket's `poll_recv`
        /// and must split by segment, not by buffer". One GRO batch
        /// carrying a QUIC packet and a probe delivers the QUIC packet to
        /// quinn, unaltered and re-addressed to the peer's synthetic
        /// address, and the probe to the doorbell, with the real source
        /// address the doorbell scores.
        ///
        /// Deliberate break to fail this test: in
        /// `PorchSocket::filter_probes`, replace the `while read < len`
        /// segment walk with a single `is_probe(&buf[..len])` check on the
        /// whole buffer. The coalesced probe is then never seen, the QUIC
        /// packet's length stays 1281, and `try_recv_probe` returns `None`.
        #[tokio::test]
        async fn probe_and_quic_in_one_gro_batch_each_reach_their_own_consumer() {
            let socket = porch_with_probe_key();
            let synthetic = synthetic_addr([1, 2, 3, 4, 5], &[9u8; 32]);
            let direct: SocketAddr = "203.0.113.4:4433".parse().unwrap();
            let entry = socket.insert_relay_path([9u8; 32], synthetic);
            entry.upgrade_to(direct);
            let stride = 1200usize;
            let quic: Vec<u8> = (0..stride).map(|i| (i % 251) as u8).collect();
            let probe = a_probe();

            let mut storage = vec![0u8; stride + PROBE_LEN];
            storage[..stride].copy_from_slice(&quic);
            storage[stride..].copy_from_slice(&probe);
            let mut bufs = [IoSliceMut::new(&mut storage)];
            let mut meta = [RecvMeta {
                addr: direct,
                len: stride + PROBE_LEN,
                stride,
                ecn: None,
                dst_ip: None,
            }];

            assert_eq!(socket.demultiplex(&mut bufs, &mut meta, 1), 1);
            assert_eq!(meta[0].len, stride, "the probe segment is removed");
            assert_eq!(
                meta[0].addr, synthetic,
                "quinn sees the synthetic address, never the real one"
            );
            assert_eq!(
                &bufs[0][..stride],
                &quic[..],
                "the QUIC packet is unaltered"
            );
            assert_eq!(socket.try_recv_probe(), Some((direct, ping())));
            assert_eq!(socket.try_recv_probe(), None);
        }

        /// The probe can equally arrive first, which makes the stride 81:
        /// GRO coalesces same-size datagrams with only the last shorter.
        /// And a batch that was nothing but probes leaves quinn nothing,
        /// which is what makes `poll_recv` loop and re-poll rather than
        /// return `Ok(0)`.
        #[tokio::test]
        async fn a_batch_of_only_probes_leaves_quinn_nothing_to_read() {
            let socket = porch_with_probe_key();
            let probe = a_probe();
            let source: SocketAddr = "203.0.113.8:4433".parse().unwrap();
            let mut storage = [0u8; PROBE_LEN * 3];
            for slot in 0..3 {
                storage[slot * PROBE_LEN..(slot + 1) * PROBE_LEN].copy_from_slice(&probe);
            }
            let mut bufs = [IoSliceMut::new(&mut storage)];
            let mut meta = [RecvMeta {
                addr: source,
                len: PROBE_LEN * 3,
                stride: PROBE_LEN,
                ecn: None,
                dst_ip: None,
            }];
            assert_eq!(socket.demultiplex(&mut bufs, &mut meta, 1), 0);
            assert_eq!(meta[0].len, 0);
            for _ in 0..3 {
                assert_eq!(socket.try_recv_probe(), Some((source, ping())));
            }
            assert_eq!(socket.try_recv_probe(), None);
        }

        /// A probe still reaches the doorbell when it arrives before the
        /// QUIC packet in the same buffer, and the surviving QUIC segment
        /// is moved to the front rather than left where it lay.
        #[tokio::test]
        async fn a_leading_probe_is_removed_and_what_follows_is_repacked() {
            let socket = porch_with_probe_key();
            let probe = a_probe();
            let source: SocketAddr = "203.0.113.8:4433".parse().unwrap();
            let quic = [0xC3u8; PROBE_LEN];
            let mut storage = [0u8; PROBE_LEN * 2];
            storage[..PROBE_LEN].copy_from_slice(&probe);
            storage[PROBE_LEN..].copy_from_slice(&quic);
            let mut bufs = [IoSliceMut::new(&mut storage)];
            let mut meta = [RecvMeta {
                addr: source,
                len: PROBE_LEN * 2,
                stride: PROBE_LEN,
                ecn: None,
                dst_ip: None,
            }];
            assert_eq!(socket.demultiplex(&mut bufs, &mut meta, 1), 1);
            assert_eq!(meta[0].len, PROBE_LEN);
            assert_eq!(&bufs[0][..PROBE_LEN], &quic);
            assert_eq!(socket.try_recv_probe(), Some((source, ping())));
        }

        /// Yseult's High, Konrad's must 1: a stranger reaching the porch
        /// port cannot grow the probe queue. Nothing unauthenticated is
        /// queued at all, and even an authenticated flood stops at
        /// [`INBOUND_PROBE_QUEUE_CAP`], the newest dropped and counted.
        ///
        /// Deliberate break to fail this test: in
        /// `PorchSocket::queue_probes`, replace the `keys.iter().find_map`
        /// authentication with `Probe::decode(segment, &[0u8; 32])`
        /// unconditionally queued, and delete the `queue.len() >=
        /// INBOUND_PROBE_QUEUE_CAP` branch. The queue then grows past the
        /// cap and both counters stay 0.
        #[tokio::test]
        async fn an_unknown_source_cannot_grow_the_probe_queue_past_its_cap() {
            let socket = porch();
            socket.arm();
            let stranger: SocketAddr = "203.0.113.77:4433".parse().unwrap();
            let flood = 64usize;

            // With no attempt running there is no armed key, so every
            // probe-shaped packet from anywhere is dropped and counted and
            // the queue stays empty: the case that had nothing draining it.
            for _ in 0..flood {
                deliver_one_probe(&socket, stranger, &a_probe());
            }
            assert_eq!(socket.probes_unauthenticated(), flood as u64);
            assert!(socket.try_recv_probe().is_none());
            assert_eq!(socket.inbound_probes.lock_or_recover().len(), 0);

            // A key armed for a different attempt does not authenticate
            // this one either: the check is the keyed hash, not the shape.
            socket.arm_probe_key([0xAAu8; 16], [0xBBu8; 32]);
            for _ in 0..flood {
                deliver_one_probe(&socket, stranger, &a_probe());
            }
            assert_eq!(socket.probes_unauthenticated(), (flood * 2) as u64);
            assert!(socket.try_recv_probe().is_none());

            // With the right key armed the queue fills to the cap and not
            // one past it, and every further arrival is counted.
            socket.arm_probe_key(ATTEMPT, PROBE_KEY);
            let overflow = 5usize;
            for _ in 0..(INBOUND_PROBE_QUEUE_CAP + overflow) {
                deliver_one_probe(&socket, stranger, &a_probe());
            }
            assert_eq!(
                socket.inbound_probes.lock_or_recover().len(),
                INBOUND_PROBE_QUEUE_CAP
            );
            assert_eq!(socket.inbound_probes_dropped(), overflow as u64);
            assert_eq!(socket.probes_unauthenticated(), (flood * 2) as u64);

            // Disarming ends the attempt as far as the socket is concerned
            // and takes its queued probes with it.
            socket.disarm_probe_key(&ATTEMPT);
            assert_eq!(socket.inbound_probes.lock_or_recover().len(), 0);
        }

        /// Feeds one probe-shaped datagram through the real receive path.
        fn deliver_one_probe(
            socket: &Arc<PorchSocket>,
            source: SocketAddr,
            probe: &[u8; PROBE_LEN],
        ) {
            let mut storage = *probe;
            let mut bufs = [IoSliceMut::new(&mut storage)];
            let mut meta = [RecvMeta {
                addr: source,
                len: PROBE_LEN,
                stride: PROBE_LEN,
                ecn: None,
                dst_ip: None,
            }];
            socket.demultiplex(&mut bufs, &mut meta, 1);
        }

        /// Konrad's must 2 and Yseult's Medium: once armed, emptying the
        /// allow-list must not reopen the rule. It used to, because the
        /// bare-socket hatch was keyed on `allowed_sources.is_empty()` and
        /// `forget_source` takes a caller-supplied address.
        ///
        /// Deliberate break to fail this test: in
        /// `PorchSocket::classify_source`, replace
        /// `!self.armed.load(Ordering::SeqCst)` with
        /// `self.allowed_sources.lock_or_recover().is_empty()`. The
        /// stranger's packet is then kept and the count stays 0.
        #[tokio::test]
        async fn emptying_the_allow_list_does_not_disarm_the_drop_rule() {
            let socket = porch();
            let gate: SocketAddr = "203.0.113.1:4433".parse().unwrap();
            let stranger: SocketAddr = "203.0.113.99:4433".parse().unwrap();
            let lease = socket.allow_source(gate);
            socket.arm();
            assert!(socket.is_armed());

            // The exact shape of the hole: a gate naming a `secondary_port`
            // equal to its primary port would have `reflect` withdraw the
            // only allowed address when that short connection closed.
            socket.forget_source(lease);
            assert_eq!(socket.allowed_sources.lock_or_recover().union_len(), 0);
            assert!(socket.is_armed(), "nothing clears the armed flag");

            let mut storage = [0xC3u8; 40];
            let mut bufs = [IoSliceMut::new(&mut storage)];
            let mut meta = [RecvMeta {
                addr: stranger,
                len: 40,
                stride: 40,
                ecn: None,
                dst_ip: None,
            }];
            assert_eq!(socket.demultiplex(&mut bufs, &mut meta, 1), 0);
            assert_eq!(meta[0].len, 0);
            assert_eq!(socket.unknown_source_dropped(), 1);
        }

        /// A porch socket that has dialled nothing and proved nothing
        /// keeps everything: the rule guards peer connections, and none
        /// can exist before a gate is dialled. Without this the section 3
        /// benchmark, which measures exactly a bare porch socket, receives
        /// nothing at all and hangs.
        ///
        /// Deliberate break to fail this test: delete the `if bare` arm in
        /// `PorchSocket::classify_source`. Every packet is then dropped and
        /// the assertion on `len` fails at the first iteration.
        #[tokio::test]
        async fn a_porch_socket_that_has_dialled_nothing_keeps_everything() {
            let socket = porch();
            let source: SocketAddr = "203.0.113.55:4433".parse().unwrap();
            let mut storage = [0xC3u8; 40];
            let mut bufs = [IoSliceMut::new(&mut storage)];
            let mut meta = [RecvMeta {
                addr: source,
                len: 40,
                stride: 40,
                ecn: None,
                dst_ip: None,
            }];
            assert_eq!(socket.demultiplex(&mut bufs, &mut meta, 1), 1);
            assert_eq!(meta[0].len, 40);
            assert_eq!(socket.unknown_source_dropped(), 0);
        }

        /// Section 3: a QUIC packet from an address this house has neither
        /// dialled nor proved never reaches quinn, and is counted.
        ///
        /// Deliberate break to fail this test: in
        /// `PorchSocket::classify_source`, change the final
        /// `SourceVerdict::Drop` to `SourceVerdict::Keep`. The stranger's
        /// packet is then handed to quinn and the count stays 0.
        #[tokio::test]
        async fn a_quic_packet_from_an_undialled_unproved_source_is_dropped_and_counted() {
            let socket = porch();
            socket.arm();
            let dialled: SocketAddr = "203.0.113.1:4433".parse().unwrap();
            let stranger: SocketAddr = "203.0.113.99:4433".parse().unwrap();
            let lease = socket.allow_source(dialled);

            for (source, expected_len) in [(dialled, 40usize), (stranger, 0usize)] {
                let mut storage = [0xC3u8; 40];
                let mut bufs = [IoSliceMut::new(&mut storage)];
                let mut meta = [RecvMeta {
                    addr: source,
                    len: 40,
                    stride: 40,
                    ecn: None,
                    dst_ip: None,
                }];
                socket.demultiplex(&mut bufs, &mut meta, 1);
                assert_eq!(meta[0].len, expected_len, "source {source}");
            }
            assert_eq!(socket.unknown_source_dropped(), 1);

            // Withdrawing the address (a `Reflect` connection closing) puts
            // it back outside the rule, and emptying the allow-list
            // altogether does not reopen it: the rule is keyed on the armed
            // flag, not on the set being non-empty.
            socket.forget_source(lease);
            let mut storage = [0xC3u8; 40];
            let mut bufs = [IoSliceMut::new(&mut storage)];
            let mut meta = [RecvMeta {
                addr: dialled,
                len: 40,
                stride: 40,
                ecn: None,
                dst_ip: None,
            }];
            socket.demultiplex(&mut bufs, &mut meta, 1);
            assert_eq!(meta[0].len, 0);
            assert_eq!(socket.unknown_source_dropped(), 2);
        }

        /// Section 2 step 6 and step 7 at the socket: once a candidate has
        /// proved itself the peer's traffic leaves on the wire to it, with
        /// the GSO batch passed through untouched; once that path is
        /// killed it goes back to the relay, and the end to end connection
        /// is not touched by either move.
        ///
        /// Deliberate break to fail this test: in `PorchSocket::try_send`,
        /// delete the `if let Some(direct) = direct` block, so an upgraded
        /// peer keeps being relayed. The direct receiver then reads
        /// nothing and the first `recv_from` times out.
        #[tokio::test]
        async fn a_proved_candidate_takes_traffic_off_the_relay_and_a_kill_puts_it_back() {
            let socket = porch();
            let synthetic = synthetic_addr([1, 2, 3, 4, 5], &[9u8; 32]);
            let entry = socket.insert_relay_path([9u8; 32], synthetic);
            socket.register_relay_session(77, synthetic);

            // The "peer", a plain UDP socket standing in for the far side
            // of a proved direct path.
            let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer_addr = peer.local_addr().unwrap();

            // Relayed: with no gate attached there is nowhere to relay to,
            // which is exactly the observable difference from a direct
            // path and needs no gate to assert.
            let payload = [0x42u8; 300];
            let transmit = Transmit {
                destination: synthetic,
                ecn: None,
                contents: &payload,
                segment_size: None,
                src_ip: None,
            };
            assert!(
                socket.try_send(&transmit).is_err(),
                "a relayed peer with no gate attached has nowhere to send"
            );

            assert!(entry.upgrade_to(peer_addr));
            assert_eq!(entry.epoch().load(Ordering::SeqCst), 1);
            wait_writable(&socket).await;
            socket.try_send(&transmit).unwrap();
            let mut buf = [0u8; 1500];
            let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
                .await
                .expect("the direct path must carry the packet")
                .unwrap();
            assert_eq!(&buf[..n], &payload);
            assert_eq!(from, socket.local_addr().unwrap());

            assert_eq!(entry.fall_back_to_relay(), Some(peer_addr));
            assert_eq!(entry.epoch().load(Ordering::SeqCst), 2);
            assert!(
                socket.try_send(&transmit).is_err(),
                "a killed path puts this peer back on the relay"
            );
            // The relay session was never deregistered by either move: the
            // end to end connection rides the same session it always did.
            assert_eq!(
                socket.relay.lock_or_recover().by_synthetic.get(&synthetic),
                Some(&77)
            );
        }

        /// A direct path passes a GSO batch through untouched, which is the
        /// advantage a direct path has and the reason the relay's splitting
        /// rule is not applied to it.
        #[tokio::test]
        async fn a_direct_path_passes_a_gso_batch_through_untouched() {
            let socket = porch();
            let synthetic = synthetic_addr([1, 2, 3, 4, 5], &[9u8; 32]);
            let entry = socket.insert_relay_path([9u8; 32], synthetic);
            let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            entry.upgrade_to(peer.local_addr().unwrap());

            let segment = 400usize;
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

            let mut seen = Vec::new();
            let mut buf = [0u8; 2000];
            while seen.len() < segment * 3 {
                let n = tokio::time::timeout(Duration::from_secs(5), peer.recv(&mut buf))
                    .await
                    .expect("every segment must arrive")
                    .unwrap();
                seen.extend_from_slice(&buf[..n]);
            }
            assert_eq!(seen, contents);
        }
    }
}
