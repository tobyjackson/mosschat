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

use crate::gate::limits::INBOUND_RELAY_QUEUE_CAP;
use crate::gate::wire::{decode_relay, encode_relay};
use crate::lockext::LockExt;
use crate::path::{PathEntry, PathTable};
use crate::punch::{PROBE_LEN, is_probe};

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
fn unmap_v4(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

struct RelayRoutes {
    /// The gate control connection whose `Relay` datagrams carry this
    /// socket's peer traffic. WO-1.3a supports exactly one gate at a time.
    gate: Option<quinn::Connection>,
    by_synthetic: HashMap<SocketAddr, u32>,
    by_session: HashMap<u32, SocketAddr>,
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
    inbound_probes: Mutex<VecDeque<(SocketAddr, [u8; PROBE_LEN])>>,
    probe_waker: Mutex<Option<Waker>>,
    /// The real source addresses whose QUIC packets may reach quinn
    /// unchanged: the gate addresses this house itself dialled. See
    /// [`PorchSocket::allow_source`].
    allowed_sources: Mutex<HashSet<SocketAddr>>,
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
                by_synthetic: HashMap::new(),
                by_session: HashMap::new(),
            }),
            paths: Mutex::new(PathTable::new()),
            inbound_synthetic: Mutex::new(VecDeque::new()),
            inbound_probes: Mutex::new(VecDeque::new()),
            probe_waker: Mutex::new(None),
            allowed_sources: Mutex::new(HashSet::new()),
            unknown_source_dropped: AtomicU64::new(0),
            waker: Mutex::new(None),
            inbound_relay_dropped: AtomicU64::new(0),
            poll_recv_prefer_socket: std::sync::atomic::AtomicBool::new(false),
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
    pub fn attach_gate(self: &Arc<Self>, gate: quinn::Connection) {
        self.allow_source(gate.remote_address());
        {
            let mut routes = self.relay.lock_or_recover();
            routes.gate = Some(gate.clone());
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
                    Err(_) => return,
                }
            }
        });
    }

    /// Registers a live relay session: datagrams sent to `synthetic_peer`
    /// leave as `Relay{session, ..}` over the attached gate connection, and
    /// `Relay{session, ..}` datagrams received from the gate are delivered
    /// to quinn tagged as arriving from `synthetic_peer`.
    pub fn register_relay_session(&self, session: u32, synthetic_peer: SocketAddr) {
        let mut routes = self.relay.lock_or_recover();
        routes.by_synthetic.insert(synthetic_peer, session);
        routes.by_session.insert(session, synthetic_peer);
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
    pub fn allow_source(&self, addr: SocketAddr) {
        self.allowed_sources
            .lock_or_recover()
            .insert(unmap_v4(addr));
    }

    /// Withdraws an address added by [`PorchSocket::allow_source`], for a
    /// short-lived connection such as a `Reflect` that has finished.
    pub fn forget_source(&self, addr: &SocketAddr) {
        self.allowed_sources
            .lock_or_recover()
            .remove(&unmap_v4(*addr));
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

    /// Takes the next probe lifted out of the inbound stream, if one is
    /// waiting, with the real source address it arrived from.
    #[must_use]
    pub fn try_recv_probe(&self) -> Option<(SocketAddr, [u8; PROBE_LEN])> {
        self.inbound_probes.lock_or_recover().pop_front()
    }

    /// Waits for the next inbound probe.
    ///
    /// One waiter at a time: the doorbell is a single task per house, and a
    /// second waiter would silently displace the first, which is the very
    /// shape issue #19 was.
    pub async fn recv_probe(&self) -> (SocketAddr, [u8; PROBE_LEN]) {
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
            let mut queue = self.inbound_probes.lock_or_recover();
            for probe in probes {
                queue.push_back((source, probe));
            }
            drop(queue);
            if let Some(waker) = self.probe_waker.lock_or_recover().take() {
                waker.wake();
            }
        }
        write
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
        let direct = {
            let paths = self.paths.lock_or_recover();
            paths
                .direct_addrs()
                .into_iter()
                .find(|(direct, _)| unmap_v4(*direct) == addr)
                .map(|(_, synthetic)| synthetic)
        };
        if let Some(synthetic) = direct {
            return SourceVerdict::Rewrite(synthetic);
        }
        if self.allowed_sources.lock_or_recover().contains(&addr) {
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
        let Self { socket, writable } = self.get_mut();
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
            let gate = {
                let routes = self.relay.lock_or_recover();
                routes.gate.clone()
            };
            let Some(gate) = gate else {
                return Err(io::Error::other(
                    "no gate connection attached to relay through",
                ));
            };
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
            for segment in transmit.contents.chunks(segment_size) {
                let payload =
                    encode_relay(session, segment).map_err(|e| io::Error::other(e.to_string()))?;
                // `quinn::Connection::send_datagram` (unlike quinn-proto's
                // lower-level API) has no `Blocked` case: it queues up to
                // the connection's own datagram buffer and only ever
                // reports `TooLarge`, `Disabled`, `UnsupportedByPeer` or the
                // connection being lost, none of which are a transient "try
                // again" condition this socket can usefully retry on.
                if let Err(e) = gate.send_datagram(payload.into()) {
                    return Err(io::Error::other(e.to_string()));
                }
            }
            return Ok(());
        }
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

        fn a_probe() -> [u8; PROBE_LEN] {
            Probe {
                kind: PROBE_PING,
                attempt: ATTEMPT,
                tx: [1u8; 8],
                observed: crate::gate::wire::Addr::default(),
            }
            .encode(&PROBE_KEY)
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
            let socket = porch();
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
            assert_eq!(socket.try_recv_probe(), Some((direct, probe)));
            assert_eq!(socket.try_recv_probe(), None);
        }

        /// The probe can equally arrive first, which makes the stride 81:
        /// GRO coalesces same-size datagrams with only the last shorter.
        /// And a batch that was nothing but probes leaves quinn nothing,
        /// which is what makes `poll_recv` loop and re-poll rather than
        /// return `Ok(0)`.
        #[tokio::test]
        async fn a_batch_of_only_probes_leaves_quinn_nothing_to_read() {
            let socket = porch();
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
                assert_eq!(socket.try_recv_probe(), Some((source, probe)));
            }
            assert_eq!(socket.try_recv_probe(), None);
        }

        /// A probe still reaches the doorbell when it arrives before the
        /// QUIC packet in the same buffer, and the surviving QUIC segment
        /// is moved to the front rather than left where it lay.
        #[tokio::test]
        async fn a_leading_probe_is_removed_and_what_follows_is_repacked() {
            let socket = porch();
            let probe = a_probe();
            let source: SocketAddr = "203.0.113.8:4433".parse().unwrap();
            socket.allow_source(source);
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
            assert_eq!(socket.try_recv_probe(), Some((source, probe)));
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
            let dialled: SocketAddr = "203.0.113.1:4433".parse().unwrap();
            let stranger: SocketAddr = "203.0.113.99:4433".parse().unwrap();
            socket.allow_source(dialled);

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
            // it back outside the rule.
            socket.forget_source(&dialled);
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
