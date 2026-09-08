//! The porch socket (`docs/dev/gatehouse-design.md` section 3), WO-1.3a's
//! slice: one real UDP socket, wrapped as a `quinn::AsyncUdpSocket`, that
//! also relays a peer connection's datagrams through an already-registered
//! gate session rather than sending them on the wire directly. No probes
//! (WO-1.3b), so `may_fragment` is the only override this WO needs on the
//! send/receive path, plus the relay indirection itself.
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

use std::collections::{HashMap, VecDeque};
use std::fmt;
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
    relay: Mutex<RelayRoutes>,
    inbound_synthetic: Mutex<VecDeque<(SocketAddr, Vec<u8>)>>,
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
        Ok(Arc::new(Self {
            udp,
            state,
            relay: Mutex::new(RelayRoutes {
                gate: None,
                by_synthetic: HashMap::new(),
                by_session: HashMap::new(),
            }),
            inbound_synthetic: Mutex::new(VecDeque::new()),
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

struct PorchPoller {
    socket: Arc<PorchSocket>,
}

impl fmt::Debug for PorchPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PorchPoller").finish()
    }
}

impl UdpPoller for PorchPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // A relay send never blocks on socket writability at all (see the
        // module doc's design note on `send_datagram`); a real-address send
        // is writable exactly when the underlying UDP socket is.
        self.socket.udp.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for PorchSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(PorchPoller { socket: self })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
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
                        Ok(n) => break Some(Ok(n)),
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
}
