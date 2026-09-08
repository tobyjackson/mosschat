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
        }))
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
    /// **Drop policy** (Yseult finding 3: the queue was previously
    /// unbounded, letting a session peer that sends faster than this
    /// endpoint drains exhaust memory and starve the gate connection
    /// sharing this socket). Bounded at
    /// [`crate::gate::limits::INBOUND_RELAY_QUEUE_CAP`]; a full queue drops
    /// its oldest entry to make room for the new one, since QUIC's own loss
    /// recovery already treats an unacknowledged packet as retransmittable
    /// and a stale queued packet is worth less than a fresh one.
    fn deliver_synthetic(&self, session: u32, payload: &[u8]) {
        let addr = {
            let routes = self.relay.lock_or_recover();
            routes.by_session.get(&session).copied()
        };
        let Some(addr) = addr else { return };
        {
            let mut queue = self.inbound_synthetic.lock_or_recover();
            if queue.len() >= INBOUND_RELAY_QUEUE_CAP {
                queue.pop_front();
            }
            queue.push_back((addr, payload.to_vec()));
        }
        if let Some(waker) = self.waker.lock_or_recover().take() {
            waker.wake();
        }
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

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        {
            let mut queue = self.inbound_synthetic.lock_or_recover();
            if let Some((addr, payload)) = queue.pop_front() {
                if let (Some(buf), Some(m)) = (bufs.first_mut(), meta.first_mut()) {
                    let n = payload.len().min(buf.len());
                    #[allow(clippy::indexing_slicing)]
                    buf[..n].copy_from_slice(&payload[..n]);
                    *m = RecvMeta {
                        addr,
                        len: n,
                        stride: n,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                return Poll::Ready(Err(io::Error::other("no receive buffer provided")));
            }
        }
        {
            *self.waker.lock_or_recover() = Some(cx.waker().clone());
        }
        // `poll_recv_ready` can report ready and then have the non-blocking
        // read turn up `WouldBlock` anyway (a spurious or already-consumed
        // readiness event); the fix, matching `quinn`'s own tokio runtime
        // (`quinn/src/runtime/tokio.rs:71-79`), is to loop back and call
        // `poll_recv_ready` again immediately rather than returning
        // `Pending` without re-arming it, since the latter can miss the
        // next real wakeup. Observed directly: with a second connection
        // sharing this socket, a bare `Pending` here stalled a fresh
        // `connect()` for tens of seconds.
        loop {
            match self.udp.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {
                    let result = self.udp.try_io(Interest::READABLE, || {
                        self.state.recv((&self.udp).into(), bufs, meta)
                    });
                    match result {
                        Ok(n) => return Poll::Ready(Ok(n)),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
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
}
