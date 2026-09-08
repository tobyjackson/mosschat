//! The doorbell: `docs/dev/gatehouse-design.md` section 2, on WO-1.3a's
//! porch socket and path table.
//!
//! ICE shaped per research lesson 9: gather, exchange, probe all at once,
//! start relayed, upgrade once a candidate proves itself, fall back on
//! failure. Nothing waits on a hole punch, so every type here is driven by
//! an explicit `now: Instant` rather than by a timer of its own: the
//! caller owns the clock, and the tests below own it exactly.
//!
//! What this module holds: section 2's fixed 81 byte probe packet and its
//! keyed authentication ([`Probe`]), the `probe_key` derivation, the porch
//! stream frames 16 to 19 of section 1 ([`PorchFrame`]), candidate
//! gathering ([`gather`]), and the per attempt candidate table and upgrade
//! rule ([`Attempt`]). The socket-level half, telling a probe from a QUIC
//! packet on receive and routing a transmit to a direct path or the relay
//! on send, lives in [`crate::sock`]; the path kinds and the congestion
//! epoch live in [`crate::path`].

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use minicbor::{Decoder, Encoder, decode::Error as DecodeError};
use rand::RngExt as _;

use crate::diag::{self, Reason, Recorder, Step, StepOutcome};
use crate::gate::GateError;
use crate::gate::wire::Addr;
use crate::lockext::LockExt as _;

/// The probe packet's first byte (section 3's discriminator). `0x2A` has
/// both `0x80` and `0x40` clear, so it is not a valid QUIC first byte under
/// either header form once `grease_quic_bit(false)` stops a peer clearing
/// the fixed bit at random (`quinn-proto/src/packet.rs:876-877`).
pub const PROBE_DISCRIMINATOR: u8 = 0x2A;

/// The fixed on-wire size of a probe, section 2: not CBOR, so it needs no
/// allocator and no parser.
pub const PROBE_LEN: usize = 81;

/// Probe type byte: a ping.
pub const PROBE_PING: u8 = 0x01;
/// Probe type byte: a pong.
pub const PROBE_PONG: u8 = 0x02;

/// Section 2's candidate cap: "capped at 16, because the probe burst costs
/// bandwidth per candidate".
pub const MAX_CANDIDATES: usize = 16;

/// Section 2 step 5: the probe interval for the first
/// [`PROBE_FAST_WINDOW`], fast enough that the two sides' first packets
/// cross well inside a firewall's state window.
pub const PROBE_FAST_INTERVAL: Duration = Duration::from_millis(100);
/// How long [`PROBE_FAST_INTERVAL`] lasts before the slow phase.
pub const PROBE_FAST_WINDOW: Duration = Duration::from_secs(3);
/// Section 2 step 5: the probe interval for the remaining 7 seconds.
pub const PROBE_SLOW_INTERVAL: Duration = Duration::from_secs(1);
/// Section 2 step 5: after 3 seconds fast plus 7 seconds slow a candidate
/// is given up. This is also the deadline a symmetric NAT hits, after which
/// the attempt stays on the relay for good.
pub const PROBE_GIVE_UP: Duration = Duration::from_secs(10);

/// How many of an attempt's [`MAX_CANDIDATES`] slots discovery may take
/// (Yseult's High 2).
///
/// The design states no number, so this is the smallest one that does the
/// job: 4, because a house has at most one address per family per
/// interface on a network it shares with a peer, and two of each is
/// already generous. Discovery is the one candidate source a stranger on
/// the LAN can drive, so uncapped it fills all 16 slots and the peer's own
/// list never enters the attempt at all, which leaves a pair that could
/// have gone direct on the relay for good. Peer-listed and gate-reflected
/// candidates are added first and are never evicted by a discovery.
pub const DISCOVERY_CANDIDATE_SLOTS: usize = 4;

/// Section 2 step 6: the first candidate to answer this many *consecutive*
/// probes wins. Three because one answer can be a duplicate or a
/// reflection while three in a row show a mapping that persists, and at
/// [`PROBE_FAST_INTERVAL`] that is 300 ms, inside the burst.
pub const CONSECUTIVE_PONGS_TO_WIN: u32 = 3;

/// Section 2 step 4: `Start.fire_in_ms`. Each side fires this long after
/// receiving `Start`; no clock is synchronised, the skew being the
/// difference in the two one way delays from the gate.
pub const FIRE_IN_MS: u16 = 200;

/// Derives the shared probe key of section 2 step 3:
/// `BLAKE3("mosschat-probe-v1" || attempt || half_initiator ||
/// half_responder)`. Both sides pass the halves in the same order, the
/// initiator's first, so both derive the same key from the two `Candidates`
/// frames without either side's ordering mattering on the wire.
#[must_use]
pub fn probe_key(
    attempt: &[u8; 16],
    half_initiator: &[u8; 32],
    half_responder: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"mosschat-probe-v1");
    hasher.update(attempt);
    hasher.update(half_initiator);
    hasher.update(half_responder);
    *hasher.finalize().as_bytes()
}

/// A parsed probe packet, section 2's fixed 81 byte layout: byte 0
/// [`PROBE_DISCRIMINATOR`], 1..4 `"MSP"`, 4 version `0x01`, 5 type, 6..22
/// attempt id, 22..30 an 8 byte tx id echoed unchanged in the pong, 30..49
/// an [`Addr`] (all zero in a ping, the source address of the ping being
/// answered in a pong), 49..81 the first 32 bytes of BLAKE3 keyed with
/// `probe_key` over bytes 0..49.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// [`PROBE_PING`] or [`PROBE_PONG`].
    pub kind: u8,
    /// The attempt this probe belongs to (frame 16's `attempt`).
    pub attempt: [u8; 16],
    /// 8 random bytes drawn per ping and echoed unchanged in its pong, so a
    /// pong is matched to the ping it answers and its round trip timed.
    pub tx: [u8; 8],
    /// All zero in a ping; in a pong, the source address the ping arrived
    /// from, which is how a peer behind a NAT learns its own mapping.
    pub observed: Addr,
}

impl Probe {
    /// Encodes this probe and authenticates it under `key`.
    ///
    /// A keyed hash, not an ed25519 signature (section 2): probes are
    /// frequent, and 64 bytes plus a scalar multiplication buys nothing.
    /// Both halves of `key` crossed the gate inside the end to end TLS, and
    /// a probe never grants trust anyway, the direct path carrying the same
    /// mutually authenticated connection, so a forged probe wastes at worst
    /// one upgrade attempt. `mosschat_core::identity::verify` is therefore
    /// not reachable from here and no ed25519 verification is written here
    /// either: this module contains no ed25519 call at all, which is the
    /// invariant that rule protects.
    #[must_use]
    pub fn encode(&self, key: &[u8; 32]) -> [u8; PROBE_LEN] {
        let mut out = [0u8; PROBE_LEN];
        #[allow(clippy::indexing_slicing)]
        {
            out[0] = PROBE_DISCRIMINATOR;
            out[1..4].copy_from_slice(b"MSP");
            out[4] = 0x01;
            out[5] = self.kind;
            out[6..22].copy_from_slice(&self.attempt);
            out[22..30].copy_from_slice(&self.tx);
            out[30..49].copy_from_slice(&addr_to_raw(self.observed));
            let mac = blake3::keyed_hash(key, &out[..49]);
            out[49..81].copy_from_slice(mac.as_bytes());
        }
        out
    }

    /// Parses and authenticates a probe under `key`, returning `None` for
    /// anything that is not a well-formed probe with a valid keyed hash.
    ///
    /// Every field is read from a fixed offset inside a length-checked 81
    /// byte buffer, so no attacker-controlled length or index exists here.
    /// The keyed hash is compared with
    /// [`blake3::Hash`]'s constant-time equality, not `==` on the raw
    /// bytes.
    #[must_use]
    pub fn decode(bytes: &[u8], key: &[u8; 32]) -> Option<Self> {
        if bytes.len() != PROBE_LEN {
            return None;
        }
        #[allow(clippy::indexing_slicing)]
        {
            if bytes[0] != PROBE_DISCRIMINATOR || &bytes[1..4] != b"MSP" || bytes[4] != 0x01 {
                return None;
            }
            let kind = bytes[5];
            if kind != PROBE_PING && kind != PROBE_PONG {
                return None;
            }
            let expected = blake3::keyed_hash(key, &bytes[..49]);
            let mut got = [0u8; 32];
            got.copy_from_slice(&bytes[49..81]);
            // `blake3::Hash`'s `PartialEq` is documented constant time.
            if expected != blake3::Hash::from(got) {
                return None;
            }
            let mut attempt = [0u8; 16];
            attempt.copy_from_slice(&bytes[6..22]);
            let mut tx = [0u8; 8];
            tx.copy_from_slice(&bytes[22..30]);
            let observed = addr_from_raw(&bytes[30..49])?;
            Some(Self {
                kind,
                attempt,
                tx,
                observed,
            })
        }
    }
}

/// Whether `first_byte` starts a probe rather than a QUIC packet (section
/// 3, "telling probes from QUIC"). Every QUIC header carries the fixed bit
/// `0x40`, and every endpoint here sets `grease_quic_bit(false)` so quinn
/// rejects a first byte with it clear, which makes `0x2A` unambiguous in
/// both directions.
#[must_use]
pub fn is_probe(segment: &[u8]) -> bool {
    segment.first() == Some(&PROBE_DISCRIMINATOR) && segment.len() == PROBE_LEN
}

fn addr_to_raw(addr: Addr) -> [u8; 19] {
    let mut out = [0u8; 19];
    #[allow(clippy::indexing_slicing)]
    {
        out[0] = addr.family;
        out[1..17].copy_from_slice(&addr.bytes);
        out[17..19].copy_from_slice(&addr.port.to_be_bytes());
    }
    out
}

fn addr_from_raw(raw: &[u8]) -> Option<Addr> {
    if raw.len() != 19 {
        return None;
    }
    let mut bytes = [0u8; 16];
    #[allow(clippy::indexing_slicing)]
    {
        bytes.copy_from_slice(&raw[1..17]);
        Some(Addr {
            family: raw[0],
            bytes,
            port: u16::from_be_bytes([raw[17], raw[18]]),
        })
    }
}

// ----------------------------------------------------------------------
// Porch stream frames 16 to 19 (section 1)
// ----------------------------------------------------------------------

const T_CANDIDATES: u8 = 16;
const T_PATH_UP: u8 = 17;
const T_PATH_DOWN: u8 = 18;
const T_PORCH_GOODBYE: u8 = 19;

/// A frame on the porch stream: one bidirectional stream inside the two
/// houses' end to end QUIC connection, mutually authenticated to both
/// pinned keys and forwarded by the gate as opaque `Relay` payloads. Same
/// deterministic CBOR array shape as [`crate::gate::wire::Frame`], and the
/// same 4 byte big-endian length prefix on the wire (D7).
#[derive(Clone, PartialEq, Eq)]
pub enum PorchFrame {
    /// Frame 16, both ways, the first frame each way on the porch stream.
    Candidates {
        /// Protocol version, currently always `1`.
        v: u8,
        /// The attempt id both sides' diagnostics records join on.
        attempt: [u8; 16],
        /// This side's candidate addresses, capped at [`MAX_CANDIDATES`].
        addrs: Vec<Addr>,
        /// This side's 32 random bytes of the [`probe_key`] input.
        probe_half: [u8; 32],
        /// This side will not probe this attempt and asks the peer not to
        /// either: `--no-punch`, WO-1.5 case (e) (design amendment 4).
        ///
        /// It rides `Candidates` rather than a frame of its own because
        /// this is the moment the peer needs it: the start signal comes
        /// next, and a peer told afterwards has already spent 10 seconds
        /// waiting for a `Start` that was never asked for and recorded a
        /// failure that did not happen. The candidate lists are still
        /// exchanged both ways, so both records still show what would have
        /// been probed.
        no_upgrade: bool,
    },
    /// Frame 17, both ways: the sender has moved its outbound traffic for
    /// this peer to `addr`.
    PathUp {
        v: u8,
        attempt: [u8; 16],
        addr: Addr,
        /// The winning candidate's round trip time in microseconds.
        rtt_us: u32,
    },
    /// Frame 18, both ways: the sender has moved back to the relay.
    PathDown {
        v: u8,
        attempt: [u8; 16],
        addr: Addr,
        /// Section 7's reason enum, as a byte.
        reason: u8,
    },
    /// Frame 19, both ways: a clean exit, so the peer goes straight to dead
    /// without passing through stale (section 4).
    Goodbye { v: u8, reason: u8 },
}

/// Redacted by hand rather than derived (Yseult's Note): `probe_half` is
/// half of a shared secret, and this type is formatted into an error string
/// on the porch stream's first-frame path. The crate has no logging call
/// today, so nothing leaks yet; WO-1.4 is when it would.
impl std::fmt::Debug for PorchFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Candidates {
                v,
                attempt,
                addrs,
                no_upgrade,
                ..
            } => f
                .debug_struct("Candidates")
                .field("v", v)
                .field("attempt", &hex16(attempt))
                .field("addrs", &addrs.len())
                .field("probe_half", &"<redacted>")
                .field("no_upgrade", no_upgrade)
                .finish(),
            Self::PathUp {
                v,
                attempt,
                addr,
                rtt_us,
            } => f
                .debug_struct("PathUp")
                .field("v", v)
                .field("attempt", &hex16(attempt))
                .field("addr", addr)
                .field("rtt_us", rtt_us)
                .finish(),
            Self::PathDown {
                v,
                attempt,
                addr,
                reason,
            } => f
                .debug_struct("PathDown")
                .field("v", v)
                .field("attempt", &hex16(attempt))
                .field("addr", addr)
                .field("reason", reason)
                .finish(),
            Self::Goodbye { v, reason } => f
                .debug_struct("Goodbye")
                .field("v", v)
                .field("reason", reason)
                .finish(),
        }
    }
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl PorchFrame {
    /// Encodes this frame as a deterministic CBOR array: definite length,
    /// shortest-form integers, the frame type first.
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        // Every call below is over a `Vec<u8>` sink, which is infallible
        // I/O; a failure here can only be a logic error in the sequence of
        // calls, never allocation or I/O failure. Same reasoning, and the
        // same local allow, as `gate::wire::Frame::to_cbor`.
        #[allow(clippy::unwrap_used)]
        match self {
            Self::Candidates {
                v,
                attempt,
                addrs,
                probe_half,
                no_upgrade,
            } => {
                enc.array(6).unwrap();
                enc.u8(T_CANDIDATES).unwrap();
                enc.u8(*v).unwrap();
                enc.bytes(attempt).unwrap();
                enc.array(addrs.len() as u64).unwrap();
                for addr in addrs {
                    enc.bytes(&addr_to_raw(*addr)).unwrap();
                }
                enc.bytes(probe_half).unwrap();
                enc.bool(*no_upgrade).unwrap();
            }
            Self::PathUp {
                v,
                attempt,
                addr,
                rtt_us,
            } => {
                enc.array(5).unwrap();
                enc.u8(T_PATH_UP).unwrap();
                enc.u8(*v).unwrap();
                enc.bytes(attempt).unwrap();
                enc.bytes(&addr_to_raw(*addr)).unwrap();
                enc.u32(*rtt_us).unwrap();
            }
            Self::PathDown {
                v,
                attempt,
                addr,
                reason,
            } => {
                enc.array(5).unwrap();
                enc.u8(T_PATH_DOWN).unwrap();
                enc.u8(*v).unwrap();
                enc.bytes(attempt).unwrap();
                enc.bytes(&addr_to_raw(*addr)).unwrap();
                enc.u8(*reason).unwrap();
            }
            Self::Goodbye { v, reason } => {
                enc.array(3).unwrap();
                enc.u8(T_PORCH_GOODBYE).unwrap();
                enc.u8(*v).unwrap();
                enc.u8(*reason).unwrap();
            }
        }
        buf
    }

    /// Decodes one porch frame.
    ///
    /// Every length is checked against its cap before anything is
    /// allocated: `addrs` past [`MAX_CANDIDATES`] is refused before the
    /// `Vec` is built, not after (invariant 4).
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] for a frame that is not a definite-length
    /// array, an unknown frame type, a wrong arity, a malformed [`Addr`] or
    /// a candidate list past its cap.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut dec = Decoder::new(bytes);
        let len = dec
            .array()?
            .ok_or_else(|| DecodeError::message("porch frame must be a definite-length array"))?;
        let frame_type = dec.u8()?;
        let frame = match (frame_type, len) {
            (T_CANDIDATES, 6) => {
                let v = dec.u8()?;
                let attempt = read_16(&mut dec)?;
                let count = dec.array()?.ok_or_else(|| {
                    DecodeError::message("Candidates.addrs must be a definite-length array")
                })?;
                if count > MAX_CANDIDATES as u64 {
                    return Err(DecodeError::message("Candidates.addrs exceeds its cap"));
                }
                let mut addrs = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    addrs.push(read_addr(&mut dec)?);
                }
                let probe_half = read_32(&mut dec)?;
                let no_upgrade = dec.bool()?;
                Self::Candidates {
                    v,
                    attempt,
                    addrs,
                    probe_half,
                    no_upgrade,
                }
            }
            (T_PATH_UP, 5) => Self::PathUp {
                v: dec.u8()?,
                attempt: read_16(&mut dec)?,
                addr: read_addr(&mut dec)?,
                rtt_us: dec.u32()?,
            },
            (T_PATH_DOWN, 5) => Self::PathDown {
                v: dec.u8()?,
                attempt: read_16(&mut dec)?,
                addr: read_addr(&mut dec)?,
                reason: dec.u8()?,
            },
            (T_PORCH_GOODBYE, 3) => Self::Goodbye {
                v: dec.u8()?,
                reason: dec.u8()?,
            },
            _ => return Err(DecodeError::message("unknown or mis-sized porch frame")),
        };
        Ok(frame)
    }
}

fn read_16(dec: &mut Decoder<'_>) -> Result<[u8; 16], DecodeError> {
    dec.bytes()?
        .try_into()
        .map_err(|_| DecodeError::message("expected a 16 byte string"))
}

fn read_32(dec: &mut Decoder<'_>) -> Result<[u8; 32], DecodeError> {
    dec.bytes()?
        .try_into()
        .map_err(|_| DecodeError::message("expected a 32 byte string"))
}

fn read_addr(dec: &mut Decoder<'_>) -> Result<Addr, DecodeError> {
    addr_from_raw(dec.bytes()?).ok_or_else(|| DecodeError::message("Addr must be exactly 19 bytes"))
}

// ----------------------------------------------------------------------
// Gathering (section 2 step 1)
// ----------------------------------------------------------------------

/// Where a candidate address came from, kept because section 7's record
/// names it and section 4 expires a `Discovery` candidate on its own
/// schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSource {
    /// A local interface address of this machine.
    Local,
    /// A gate reflection: `Registered.observed` (frame 2) or
    /// `Reflected.observed` (frame 4).
    GateReflected,
    /// An address the peer listed in its own `Candidates` frame.
    PeerReported,
    /// Same-network discovery (section 6, a later work order).
    Discovery,
}

/// This machine's own source address for each family, at `port`.
///
/// **Partial against section 2 step 1, deliberately and with the reason
/// stated.** The design asks for "every non-loopback address on every up
/// interface, both families". Enumerating interfaces means `getifaddrs`,
/// which this crate can reach only through a new dependency (none is named
/// by the work order) or through `unsafe` (invariant 2 forbids it crate
/// wide). What is available without either is a route lookup: a UDP socket
/// `connect`ed to a documentation address sends nothing at all, but its
/// `local_addr` is the source address the kernel would use to reach that
/// family, which is the address that matters for all but the
/// multiple-uplink case. IPv6 is gathered the same way and is not an
/// afterthought: it removes NAT but not the stateful firewall, so it needs
/// the same dance. A machine with no route for a family contributes
/// nothing for it rather than failing.
#[must_use]
pub fn local_addresses(port: u16) -> Vec<SocketAddr> {
    const PROBE_TARGETS: [(&str, &str); 2] = [
        // RFC 5737 TEST-NET-1 and RFC 3849 documentation prefix: routable
        // in form, assigned to nobody, and never contacted, since `connect`
        // on a UDP socket only resolves a route.
        ("0.0.0.0:0", "192.0.2.1:9"),
        ("[::]:0", "[2001:db8::1]:9"),
    ];
    let mut out = Vec::new();
    for (bind, target) in PROBE_TARGETS {
        let Ok(socket) = std::net::UdpSocket::bind(bind) else {
            continue;
        };
        if socket.connect(target).is_err() {
            continue;
        }
        let Ok(local) = socket.local_addr() else {
            continue;
        };
        if local.ip().is_loopback() || local.ip().is_unspecified() {
            continue;
        }
        out.push(SocketAddr::new(local.ip(), port));
    }
    out
}

/// Section 2 step 1: the local addresses, the gate reflections and anything
/// from same-network discovery, de-duplicated, loopback and unspecified
/// addresses dropped, capped at [`MAX_CANDIDATES`] in that order of
/// preference.
///
/// Order matters only because of the cap: a machine with more than 16
/// plausible addresses keeps the ones it is surest of first. Nothing later
/// depends on the order, since every candidate is probed at once (lesson
/// 9).
#[must_use]
pub fn gather(
    local: &[SocketAddr],
    reflections: &[SocketAddr],
    discovered: &[SocketAddr],
) -> Vec<(SocketAddr, CandidateSource)> {
    let mut out: Vec<(SocketAddr, CandidateSource)> = Vec::new();
    let groups = [
        (local, CandidateSource::Local),
        (reflections, CandidateSource::GateReflected),
        (discovered, CandidateSource::Discovery),
    ];
    for (addrs, source) in groups {
        for addr in addrs {
            if out.len() >= MAX_CANDIDATES {
                return out;
            }
            if !is_gatherable(*addr) {
                continue;
            }
            if out.iter().any(|(existing, _)| existing == addr) {
                continue;
            }
            out.push((*addr, source));
        }
    }
    out
}

/// Whether an address may be **offered** as one of this house's own
/// candidates (section 2 step 1: "every non-loopback address on every up
/// interface"). Loopback is excluded here and only here: telling a peer to
/// probe 127.0.0.1 tells it to probe itself.
fn is_gatherable(addr: SocketAddr) -> bool {
    if addr.ip().is_loopback() {
        return false;
    }
    is_probeable(addr)
}

/// Whether an address is worth **probing**, which is a weaker test than
/// [`is_gatherable`] on purpose.
///
/// Step 1 constrains what a house gathers and offers; step 5 probes "every
/// candidate" the exchange produced. A house does not get to second-guess
/// which of its peer's addresses are real, because the peer knows its own
/// interfaces and this house does not, and probing a wrong one costs one
/// 81 byte packet every 100 ms for at most 10 seconds. What is refused is
/// what cannot be a peer at all: port 0, port 1 (which every synthetic
/// address carries, section 3, and no real peer listens on), and the
/// unspecified, multicast and broadcast addresses.
fn is_probeable(addr: SocketAddr) -> bool {
    if addr.port() == 0 || addr.port() == 1 {
        return false;
    }
    match addr.ip() {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_broadcast() && !v4.is_multicast(),
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast(),
    }
}

/// Whether `addr` is an address the wider internet could have routed to
/// this house, as opposed to one that names something on this machine or
/// inside this house's own network.
///
/// The distinction exists because of what a peer can do with a candidate
/// list (Yseult's Medium): a peer names up to 16 addresses and this house
/// then aims about 37 packets at each, so a peer naming `127.0.0.1:631` or
/// `192.168.1.1:53` turns the doorbell into a scanner of its correspondent's
/// own machine and LAN. Loopback and link-local can never be right coming
/// from a peer. Private ranges *can* be right, since two houses on one LAN
/// are the case section 6 exists for, but only when something other than
/// the peer's own say-so vouches for the address; see
/// [`Attempt::add_candidate`].
fn is_globally_routable(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_private()
                && !v4.is_unspecified()
                && !v4.is_broadcast()
                && !v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && !is_link_local_v6(v6)
                && !is_unique_local_v6(v6)
        }
    }
}

/// `fe80::/10`, hand-rolled because `Ipv6Addr::is_unicast_link_local` is
/// unstable.
fn is_link_local_v6(addr: std::net::Ipv6Addr) -> bool {
    let segments = addr.segments();
    segments
        .first()
        .is_some_and(|first| first & 0xffc0 == 0xfe80)
}

/// `fc00::/7`, hand-rolled because `Ipv6Addr::is_unique_local` is unstable.
fn is_unique_local_v6(addr: std::net::Ipv6Addr) -> bool {
    addr.octets()
        .first()
        .is_some_and(|first| first & 0xfe == 0xfc)
}

// ----------------------------------------------------------------------
// The candidate table and the upgrade rule (section 2 steps 4 to 7)
// ----------------------------------------------------------------------

/// One candidate address under probe.
#[derive(Debug)]
struct Candidate {
    addr: SocketAddr,
    source: CandidateSource,
    /// How many probes in a row this candidate has answered. Reset to zero
    /// the moment a probe is sent while an earlier one is still
    /// unanswered, which is what makes the three of section 2 step 6
    /// consecutive rather than merely cumulative.
    consecutive: u32,
    /// The round trip times of the most recent [`CONSECUTIVE_PONGS_TO_WIN`]
    /// answers, newest last, for step 6's tie-break.
    recent: Vec<Duration>,
    /// The smoothed round trip time section 4's timers read, an EWMA over
    /// probe pong round trips, seeded by the first sample.
    srtt: Option<Duration>,
    /// Pings sent and not yet answered, by their tx id.
    outstanding: HashMap<[u8; 8], Instant>,
    last_sent: Option<Instant>,
    given_up: bool,
}

impl Candidate {
    fn record_rtt(&mut self, rtt: Duration) {
        self.recent.push(rtt);
        while self.recent.len() > CONSECUTIVE_PONGS_TO_WIN as usize {
            self.recent.remove(0);
        }
        // The same 1/8 weighting QUIC's own RTT estimator uses, seeded by
        // the first sample rather than by zero so one slow path is not
        // reported as fast for its first several probes.
        self.srtt = Some(match self.srtt {
            None => rtt,
            Some(previous) => (previous * 7 + rtt) / 8,
        });
    }

    /// The mean of the answers that won this candidate its streak, which is
    /// what step 6's "lowest RTT of the three" compares.
    fn winning_rtt(&self) -> Option<Duration> {
        if self.recent.is_empty() {
            return None;
        }
        let total: Duration = self.recent.iter().sum();
        u32::try_from(self.recent.len()).ok().map(|n| total / n)
    }
}

/// The winning candidate of one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Winner {
    /// The address traffic moves to.
    pub addr: SocketAddr,
    /// The mean round trip of the three answers that won it, for frame 17's
    /// `rtt_us` and for section 7's `path_rtt_us`.
    pub rtt: Duration,
}

/// One doorbell attempt's candidate table, probe schedule and upgrade rule
/// (section 2 steps 4 to 7).
///
/// It owns no clock and no socket: every method takes the `now` the caller
/// read and returns what to send, so the whole of section 2's timing is
/// exercised by the tests below without a sleep, a timer or any load.
pub struct Attempt {
    id: [u8; 16],
    key: [u8; 32],
    /// The addresses something other than this peer's own say-so vouches
    /// for **in this attempt**, and so the only addresses outside the
    /// globally routable range its `Candidates` frame may name: the gate's
    /// reflection of that peer (frame 6's `peer_observed`), and every
    /// address this house heard that peer announce from on its own network
    /// (section 6). Held unmapped, so one address has one spelling here
    /// and cannot be vouched for in a form the classifier does not read
    /// (issue #37). See [`Attempt::add_candidate`].
    vouched: Vec<SocketAddr>,
    fire_at: Option<Instant>,
    candidates: Vec<Candidate>,
    /// How many of the table's slots discovery has taken, capped at
    /// [`DISCOVERY_CANDIDATE_SLOTS`] (Yseult's High 2).
    discovery_candidates: usize,
    winner: Option<Winner>,
}

/// Redacted by hand rather than derived (Yseult's Note): `key` is the
/// shared `probe_key`.
impl std::fmt::Debug for Attempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attempt")
            .field("id", &hex16(&self.id))
            .field("key", &"<redacted>")
            .field("candidates", &self.candidates.len())
            .field("winner", &self.winner)
            .finish()
    }
}

impl Attempt {
    /// A fresh attempt with no candidates and no start signal yet.
    ///
    /// `gate_reflected_peer` is the peer's address as the gate observed it
    /// for this attempt (frame 6's `peer_observed`). It is one of the
    /// non-globally-routable addresses the peer is allowed to name,
    /// because the gate saw a packet arrive from it rather than taking the
    /// peer's word; the others are whatever [`Attempt::add_discovered`]
    /// puts in. `None` means the gate vouches for nothing here.
    #[must_use]
    pub fn new(id: [u8; 16], key: [u8; 32], gate_reflected_peer: Option<SocketAddr>) -> Self {
        Self {
            id,
            key,
            vouched: gate_reflected_peer
                .map(crate::sock::unmap_v4)
                .into_iter()
                .collect(),
            fire_at: None,
            candidates: Vec::new(),
            discovery_candidates: 0,
            winner: None,
        }
    }

    /// This attempt's id, the value both sides' diagnostics records join on.
    #[must_use]
    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    /// Adds a candidate, returning `false` if it is a duplicate, the
    /// [`MAX_CANDIDATES`] cap is already reached, or the address is one a
    /// peer may not point this house at.
    ///
    /// **What a peer may name** (Yseult's Medium, issue #37). An address
    /// this house gathered for itself, or discovered on its own network,
    /// is trusted because this house found it. An address the *peer* named
    /// is trusted only if the wider internet could have routed it here, or
    /// if it is one of this attempt's vouched addresses: the address the
    /// gate observed that peer at, or an address this house itself heard
    /// that peer announce from on its own network (section 6). That
    /// second one is the relaxation issue #37 asks for, and it is exactly
    /// as wide as the design allows: a private-range, link-local or
    /// IPv4-mapped LAN address is admissible when local discovery or the
    /// gate's reflection produced it **for this attempt**, and never
    /// because a peer's candidate list said so. Anything else, a peer
    /// naming `127.0.0.1:631` or a router on this house's LAN, is refused:
    /// 16 candidates at about 37 probes each is a scan, and a keyed hash
    /// does not make it not one.
    pub fn add_candidate(&mut self, addr: SocketAddr, source: CandidateSource) -> bool {
        // Unmapped first, and before anything classifies it (Yseult's
        // remaining Medium). `Addr` family 6 decodes `::ffff:a.b.c.d`
        // unchanged, no V6 predicate matches that form, and
        // `PorchSocket::map_destination` passes a V6 destination through,
        // so on a dual-stack porch socket a peer naming
        // `[::ffff:127.0.0.1]:631` had its probes land on loopback while
        // `127.0.0.1:631` was refused. One address, two spellings, one
        // verdict. Storing the unmapped form also makes a candidate compare
        // equal to the pong source the socket reports, which is unmapped
        // for the same reason.
        let addr = crate::sock::unmap_v4(addr);
        if self.candidates.len() >= MAX_CANDIDATES
            || !is_probeable(addr)
            || self.candidates.iter().any(|c| c.addr == addr)
        {
            return false;
        }
        if source == CandidateSource::PeerReported
            && !is_globally_routable(addr)
            && !self.vouched.contains(&addr)
        {
            return false;
        }
        self.candidates.push(Candidate {
            addr,
            source,
            consecutive: 0,
            recent: Vec::new(),
            srtt: None,
            outstanding: HashMap::new(),
            last_sent: None,
            given_up: false,
        });
        true
    }

    /// Adds an address this house heard the peer announce from on its own
    /// network (section 6), which both makes it a [`CandidateSource::Discovery`]
    /// candidate and vouches for it for the rest of this attempt.
    ///
    /// Vouching and adding are one call on purpose (issue #37): the whole
    /// relaxation rests on the address having come from a multicast
    /// announce this house received itself, whose source address the
    /// kernel wrote and whose key `mosschat_core::identity::verify`
    /// checked, so there is no way to vouch for an address without also
    /// naming where it came from. A peer's `Candidates` frame reaches
    /// [`Attempt::add_peer_candidates`] instead, which cannot produce a
    /// `Discovery` candidate and cannot vouch for anything.
    ///
    /// Returns `false` on a duplicate or past the cap, exactly as
    /// [`Attempt::add_candidate`] does; the address is vouched for either
    /// way, since a peer naming an address this house already discovered
    /// is naming a discovered address.
    pub fn add_discovered(&mut self, addr: SocketAddr) -> bool {
        self.vouch(addr);
        // Yseult's High 2: discovery gets its own slot count and never
        // takes a slot from anything else. The vouching above is
        // deliberately outside the cap, since hearing a peer at an address
        // is a fact about this network whether or not there is room to
        // probe it, and vouching costs one address in a `Vec` bounded by
        // the same [`MAX_CANDIDATES`] the table is.
        if self.discovery_candidates >= DISCOVERY_CANDIDATE_SLOTS {
            return false;
        }
        if self.add_candidate(addr, CandidateSource::Discovery) {
            self.discovery_candidates = self.discovery_candidates.saturating_add(1);
            return true;
        }
        false
    }

    /// Records that something other than the peer's own say-so vouches for
    /// `addr` in this attempt, without adding it as a candidate.
    ///
    /// `pub(crate)` rather than `pub` (Konrad's nit 7): "a property of the
    /// type" is only true if nothing outside this crate can vouch for an
    /// address without having heard the announce itself.
    ///
    /// The two halves are separable because they can genuinely come apart:
    /// an announce that arrives once the table is already at
    /// [`MAX_CANDIDATES`] still means this house heard the peer at that
    /// address, so the peer naming it is not the peer inventing it. The
    /// address is unmapped first, so one address is vouched for in one
    /// spelling and cannot slip through the classifier in the other
    /// (Yseult, issue #37).
    pub(crate) fn vouch(&mut self, addr: SocketAddr) {
        let addr = crate::sock::unmap_v4(addr);
        if !self.vouched.contains(&addr) {
            self.vouched.push(addr);
        }
    }

    /// Adds every address a peer's `Candidates` frame (frame 16) named, as
    /// [`CandidateSource::PeerReported`] and nothing else.
    ///
    /// The one entry point the porch stream's decoded frame takes, so
    /// "never from a peer's candidate list" (issue #37) is a property of
    /// the type rather than of a call site remembering to pass the right
    /// source: nothing a peer sends can reach this house's candidate table
    /// as `Discovery`, `Local` or `GateReflected`, and so nothing a peer
    /// sends can vouch for a private-range address.
    ///
    /// Returns how many were accepted.
    pub fn add_peer_candidates(&mut self, addrs: &[Addr]) -> usize {
        addrs
            .iter()
            .filter_map(|addr| addr.to_socket_addr())
            .filter(|addr| self.add_candidate(*addr, CandidateSource::PeerReported))
            .count()
    }

    /// How many candidates are under probe.
    #[must_use]
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Whether this attempt holds something other than the peer's word for
    /// `addr`, which is the whole of the test [`Attempt::add_candidate`]
    /// applies to a peer-named address outside the globally routable range
    /// (issue #37). Either spelling of one address answers the same.
    #[must_use]
    pub fn vouched_for(&self, addr: SocketAddr) -> bool {
        self.vouched.contains(&crate::sock::unmap_v4(addr))
    }

    /// The source recorded for `addr`, if it is a candidate.
    #[must_use]
    pub fn source_of(&self, addr: SocketAddr) -> Option<CandidateSource> {
        self.candidates
            .iter()
            .find(|c| c.addr == addr)
            .map(|c| c.source)
    }

    /// Section 2 step 4: `Start` has arrived, so fire [`FIRE_IN_MS`] later.
    /// No clock is synchronised; `received_at` is this side's own reading.
    pub fn start_signal_received(&mut self, received_at: Instant) {
        self.fire_at = Some(received_at + Duration::from_millis(u64::from(FIRE_IN_MS)));
    }

    /// The winning candidate, once one exists.
    #[must_use]
    pub fn winner(&self) -> Option<Winner> {
        self.winner
    }

    /// Whether every candidate has been given up: 3 seconds of fast probes
    /// and 7 of slow ones with nothing proved (section 2 step 5). An
    /// attempt with no candidates at all is given up the moment it fires,
    /// since there is nothing left to wait for. This is the state a
    /// symmetric NAT reaches, and it means the relay carries this peer for
    /// good until something reruns the doorbell.
    #[must_use]
    pub fn given_up(&self, now: Instant) -> bool {
        if self.winner.is_some() {
            return false;
        }
        match self.fire_at {
            None => false,
            Some(fire_at) => now >= fire_at + PROBE_GIVE_UP,
        }
    }

    /// The probes due to be sent at `now`, each already encoded and
    /// authenticated, with the address to send it to.
    ///
    /// `tx_ids` supplies the 8 random bytes per ping; it is a parameter
    /// rather than a call into `rand` so a test can make the whole schedule
    /// reproducible. Sending a probe while an earlier one to the same
    /// candidate is still unanswered resets that candidate's streak, which
    /// is what makes step 6's three answers consecutive.
    pub fn due_probes(
        &mut self,
        now: Instant,
        mut tx_ids: impl FnMut() -> [u8; 8],
    ) -> Vec<(SocketAddr, [u8; PROBE_LEN])> {
        let Some(fire_at) = self.fire_at else {
            return Vec::new();
        };
        if now < fire_at || self.winner.is_some() {
            return Vec::new();
        }
        let elapsed = now.duration_since(fire_at);
        if elapsed >= PROBE_GIVE_UP {
            for candidate in &mut self.candidates {
                candidate.given_up = true;
            }
            return Vec::new();
        }
        let interval = if elapsed < PROBE_FAST_WINDOW {
            PROBE_FAST_INTERVAL
        } else {
            PROBE_SLOW_INTERVAL
        };
        let mut out = Vec::new();
        for candidate in &mut self.candidates {
            if candidate.given_up {
                continue;
            }
            if candidate
                .last_sent
                .is_some_and(|last| now.duration_since(last) < interval)
            {
                continue;
            }
            if !candidate.outstanding.is_empty() {
                candidate.consecutive = 0;
                candidate.recent.clear();
                candidate.outstanding.clear();
            }
            let tx = tx_ids();
            let probe = Probe {
                kind: PROBE_PING,
                attempt: self.id,
                tx,
                observed: Addr::default(),
            };
            candidate.outstanding.insert(tx, now);
            candidate.last_sent = Some(now);
            out.push((candidate.addr, probe.encode(&self.key)));
        }
        out
    }

    /// Builds the pong answering `ping`, which arrived from `from`: the
    /// same tx id echoed unchanged, and `from` in the `observed` field so
    /// the far side learns the mapping this ping came out of.
    ///
    /// Answering costs nothing and grants nothing, so a ping from an
    /// address that is not a candidate is still answered: it is how a
    /// peer whose port a symmetric NAT rewrote is ever heard from at all.
    /// The keyed hash is what limits this to the two houses that exchanged
    /// halves inside the end to end TLS.
    #[must_use]
    pub fn pong_for(&self, ping: &Probe, from: SocketAddr) -> [u8; PROBE_LEN] {
        Probe {
            kind: PROBE_PONG,
            attempt: ping.attempt,
            tx: ping.tx,
            observed: Addr::from_socket_addr(from),
        }
        .encode(&self.key)
    }

    /// Records a pong that arrived from `from` at `now`, returning whether
    /// it counted for anything.
    ///
    /// Recording and deciding are deliberately separate calls: section 2
    /// step 6 breaks a tie at three "by lowest RTT of the three", and a tie
    /// only exists across the pongs of one probe round. A decision taken
    /// inside this method would always fire on whichever pong happened to
    /// be dequeued first, which is arrival order on a socket, so the
    /// tie-break would never run at all and the slower path would win
    /// whenever its pong was read first. The caller drains its inbound
    /// probes, then calls [`Attempt::decide`] once.
    ///
    /// A pong for an unknown tx id, from a non-candidate address, or for a
    /// different attempt, changes nothing at all.
    pub fn on_pong(&mut self, from: SocketAddr, pong: &Probe, now: Instant) -> bool {
        if self.winner.is_some() || pong.kind != PROBE_PONG || pong.attempt != self.id {
            return false;
        }
        let mut counted = false;
        for candidate in &mut self.candidates {
            if candidate.addr != from {
                continue;
            }
            let Some(sent) = candidate.outstanding.remove(&pong.tx) else {
                continue;
            };
            candidate.record_rtt(now.duration_since(sent));
            candidate.consecutive = candidate.consecutive.saturating_add(1);
            counted = true;
        }
        counted
    }

    /// Section 2 step 6: the first candidate to answer
    /// [`CONSECUTIVE_PONGS_TO_WIN`] consecutive probes wins, ties broken by
    /// the lowest mean round trip of those three.
    ///
    /// Call once after each batch of pongs. Returns the winner if this call
    /// decided one, and `None` while nothing has proved itself yet.
    pub fn decide(&mut self) -> Option<Winner> {
        if self.winner.is_some() {
            return None;
        }
        // A remaining exact tie is broken by address so two runs of the
        // same trace choose the same path.
        let (rtt, addr) = self
            .candidates
            .iter()
            .filter(|c| c.consecutive >= CONSECUTIVE_PONGS_TO_WIN)
            .filter_map(|c| c.winning_rtt().map(|rtt| (rtt, c.addr)))
            .min_by(|(left_rtt, left_addr), (right_rtt, right_addr)| {
                left_rtt
                    .cmp(right_rtt)
                    .then_with(|| left_addr.to_string().cmp(&right_addr.to_string()))
            })?;
        let winner = Winner { addr, rtt };
        self.winner = Some(winner);
        Some(winner)
    }

    /// The smoothed round trip time for `addr`, which is what section 4's
    /// `8 * srtt` and `4 * srtt` read: this table's own estimate from probe
    /// pongs, never `quinn::Connection::rtt()`, which stays stale for
    /// several samples after a fall-back and would stretch the very timers
    /// meant to catch it (section 3).
    #[must_use]
    pub fn srtt(&self, addr: SocketAddr) -> Option<Duration> {
        self.candidates
            .iter()
            .find(|c| c.addr == addr)
            .and_then(|c| c.srtt)
    }

    /// Section 2 step 7: the winning path failed, so this attempt is over
    /// and the caller reverts to the relay. Losers are deliberately not
    /// re-evaluated; a better path is looked for only by a fresh attempt
    /// with a fresh id, which is gathering, exchange and probing rerun.
    pub fn path_failed(&mut self) -> Option<Winner> {
        self.winner.take()
    }
}

// ----------------------------------------------------------------------
// Running the doorbell (section 2 end to end)
// ----------------------------------------------------------------------

/// The ceiling on pongs one attempt will emit per second (Yseult's Medium).
///
/// A ping carries no timestamp and its tx id is meaningful only to the side
/// that drew it, so one captured ping replays for the life of the attempt
/// from any spoofed source, and `pong_for` answers a non-candidate by
/// design, since that is how a peer behind a symmetric NAT is heard from at
/// all. Answering is 1:1 so there is no amplification, but it is an
/// uncapped source-laundering reflector without a ceiling. Legitimate load
/// is one ping per 100 ms per attempt, so ten a second; 64 is six times
/// that and still a hard ceiling.
pub const PONG_ANSWERS_PER_SECOND: u32 = 64;

/// How many answered tx ids one attempt remembers, so a replayed ping is
/// answered once and not again. 4096 covers every ping a legitimate attempt
/// can send (10 a second for 10 seconds, per candidate, is 1600 at the
/// 16-candidate cap for the far side's whole burst) and bounds the set at
/// 4096 * 8 bytes.
pub const ANSWERED_TX_MEMORY: usize = 4096;

/// A token bucket over one-second windows, and the set of tx ids already
/// answered, which together stop a captured ping being replayed into an
/// unbounded reflector.
#[derive(Debug)]
struct PongLimiter {
    window_start: Instant,
    answered_in_window: u32,
    seen: std::collections::HashSet<[u8; 8]>,
    order: std::collections::VecDeque<[u8; 8]>,
}

impl PongLimiter {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            answered_in_window: 0,
            seen: std::collections::HashSet::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    /// Whether a ping with this tx id may be answered now: once per tx id,
    /// and at most [`PONG_ANSWERS_PER_SECOND`] in any one-second window.
    fn may_answer(&mut self, tx: [u8; 8], now: Instant) -> bool {
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.answered_in_window = 0;
        }
        if self.answered_in_window >= PONG_ANSWERS_PER_SECOND {
            return false;
        }
        if !self.seen.insert(tx) {
            return false;
        }
        self.order.push_back(tx);
        while self.order.len() > ANSWERED_TX_MEMORY {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        self.answered_in_window = self.answered_in_window.saturating_add(1);
        true
    }
}

/// What a house needs to know before it can run the doorbell for one peer.
#[derive(Debug, Clone)]
pub struct DoorbellParams {
    /// The relay session the gate assigned, which `StartRequest` names.
    pub session: u32,
    /// `1` if this house is the initiator (frame 6's `role`), `2` if the
    /// responder. The initiator opens the porch stream, chooses the
    /// attempt id and asks the gate to start.
    pub role: u8,
    /// The peer this attempt is for, which names its path table entry.
    pub peer_key: [u8; 32],
    /// This house's own candidate addresses, already gathered
    /// ([`gather`]).
    pub candidates: Vec<SocketAddr>,
    /// The peer's address as the gate observed it for this attempt (frame
    /// 6's `peer_observed`), which is the one address outside the globally
    /// routable range the peer may name. See [`Attempt::add_candidate`].
    pub peer_observed: Option<SocketAddr>,
    /// The addresses this house has heard this peer announce from on its
    /// own network (section 6), each already verified there against
    /// `mosschat_core::identity::verify` and each carrying the source
    /// address the kernel wrote rather than one the peer chose.
    ///
    /// They enter the attempt as [`CandidateSource::Discovery`] and vouch
    /// for themselves for the length of the attempt, which is what lets a
    /// same-LAN pair upgrade to a private-range address at all (issue
    /// #37). Empty is the ordinary case: no discovery, no relaxation.
    pub peer_discovered: Vec<SocketAddr>,
    /// How long to hold the visit open once the doorbell has answered
    /// (WO-1.5a). [`Hold::UntilAttemptSettles`], the default, is what
    /// every caller did before that order.
    pub hold: Hold,
    /// Skips the probe burst entirely, so the visit stays relayed and the
    /// record says `punch_disabled` (WO-1.5 case (e)). Candidates are
    /// still gathered and exchanged, so both sides' records still show
    /// what would have been probed.
    pub no_punch: bool,
    /// Where this visit's events go as they happen, for a house that
    /// prints them. `None` puts them in the record and nowhere else.
    pub events: Option<VisitEventSink>,
    /// This attempt's diagnostics recorder (section 7), or `None` for a
    /// house running without a diagnostics directory. The same handle the
    /// gate client holds, so one attempt's gate steps and doorbell steps
    /// land in one record: [`crate::gate::client::GateClient::recorder`].
    pub recorder: Option<Recorder>,
}

/// A live doorbell's two controls: whether it still answers pings, and
/// whether it has been asked to end the visit.
///
/// A path that has died and a peer that has stopped answering are the same
/// thing seen from the other side, which is what makes
/// [`DoorbellControl::stop_answering_probes`] the honest way to exercise
/// section 2 step 7 without unplugging a cable.
/// [`DoorbellControl::stop`] is the other half, and the one a headless
/// house needs: a visit asked to end says goodbye on its own porch stream
/// (frame 19) rather than vanishing, so the peer marks it dead at once
/// instead of waiting out stale (section 4).
#[derive(Debug, Default)]
pub struct DoorbellControl {
    answer_probes: std::sync::atomic::AtomicBool,
    stopping: std::sync::atomic::AtomicBool,
}

impl DoorbellControl {
    /// A control that answers pings, which is every live doorbell.
    #[must_use]
    pub fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            answer_probes: std::sync::atomic::AtomicBool::new(true),
            stopping: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Ends this visit at the next turn of its loop, with a goodbye.
    pub fn stop(&self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether this visit has been asked to end.
    #[must_use]
    pub fn stopping(&self) -> bool {
        self.stopping.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Stops answering pings from this moment, which is what the peer sees
    /// when this house's path to it dies.
    pub fn stop_answering_probes(&self) {
        self.answer_probes
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Answers pings again, which is what the peer sees when a path that
    /// died comes back: a blackout lifted, a cable back in, a hotspot
    /// reconnected.
    ///
    /// The other half of [`DoorbellControl::stop_answering_probes`], and
    /// the only honest way to bring a path back in process, since the
    /// path never left the machine in the first place.
    pub fn resume_answering_probes(&self) {
        self.answer_probes
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn answering(&self) -> bool {
        self.answer_probes.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// How one doorbell attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoorbellOutcome {
    /// The attempt id both sides' records join on.
    pub attempt: [u8; 16],
    /// The address this house upgraded to, if any candidate proved itself.
    pub upgraded_to: Option<SocketAddr>,
    /// Whether that path later failed and this house went back to the
    /// relay.
    pub fell_back: bool,
}

/// Reads one length-prefixed porch frame, bounded by
/// [`crate::gate::wire::CONTROL_FRAME_LEN_CAP`] checked before allocating
/// and by `deadline` (section 5: "every read on the control and porch
/// streams carries a deadline").
///
/// # Errors
///
/// Returns [`GateError::FrameTooLarge`], [`GateError::Timeout`] or a
/// protocol error.
pub async fn read_porch_frame(
    stream: &mut quinn::RecvStream,
    deadline: Duration,
) -> Result<PorchFrame, GateError> {
    let read = async {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf);
        if len > crate::gate::wire::CONTROL_FRAME_LEN_CAP {
            return Err(GateError::FrameTooLarge(len));
        }
        let mut body = vec![0u8; len as usize];
        stream.read_exact(&mut body).await?;
        PorchFrame::from_cbor(&body).map_err(|e| GateError::Protocol(e.to_string()))
    };
    tokio::time::timeout(deadline, read)
        .await
        .map_err(|_| GateError::Timeout)?
}

/// Writes one length-prefixed porch frame.
///
/// # Errors
///
/// Returns a [`GateError`] if the stream write fails.
pub async fn write_porch_frame(
    stream: &mut quinn::SendStream,
    frame: &PorchFrame,
) -> Result<(), GateError> {
    let body = frame.to_cbor();
    let len = u32::try_from(body.len()).map_err(|_| GateError::FrameTooLarge(u32::MAX))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&body).await?;
    Ok(())
}

/// Reads this peer's shaper counters out of the path table and into the
/// record (section 7: "recorded on every connection, success or not").
///
/// This peer's own entry rather than the endpoint-wide fold: an attempt's
/// record describes one relay leg, and a second peer's traffic over the
/// same gate connection is not this attempt's.
fn record_relay_counters(recorder: Option<&Recorder>, path: Option<&crate::path::PathEntry>) {
    if let (Some(recorder), Some(path)) = (recorder, path) {
        recorder.set_relay_stats(&path.egress().stats());
    }
}

/// Closes the attempt's record with `reason` and writes it.
///
/// A failed write is deliberately not propagated: a diagnostics log that
/// cannot be written is no reason to fail a connection that worked, and
/// `doctor`, the one caller that must know, holds the record itself and
/// checks the write there.
fn settle(recorder: Option<&Recorder>, reason: Reason) {
    if let Some(recorder) = recorder {
        let (_record, _written) = recorder.finish(reason);
    }
}

/// How long a caller wants the visit held open once the doorbell has
/// answered (WO-1.5a).
///
/// The doorbell was one-shot before this order: it upgraded, watched the
/// path, and returned the moment that path died. WO-1.5 needs a visit that
/// is still there a minute later, because the numbers it asks for (RTT
/// median and p95, recovery after a 60 second drop, detection and
/// fall-back times) are properties of a visit under way and not of a
/// connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Hold {
    /// One attempt, then done: upgrade, watch, and settle the record as
    /// soon as the path is lost or every candidate is given up. This is
    /// what `doctor --friend` did before `--hold` existed, and it stays
    /// the default so no existing caller changes behaviour.
    #[default]
    UntilAttemptSettles,
    /// Hold the visit open for this long, then say goodbye
    /// (`doctor --friend --hold <seconds>`), clamped at [`MAX_HOLD`].
    For(Duration),
    /// Hold it open until the peer leaves or this house is asked to stop
    /// (`mosschat house --headless`).
    UntilPeerLeaves,
}

/// Where a visit's live events go besides the diagnostics record: a
/// headless house prints one JSON line per event on stdout as it happens,
/// and a record is only written when the attempt ends.
///
/// A closure rather than a channel because the two consumers want
/// different things: the house formats and prints, and a test collects.
/// The doorbell calls it from its own task, so it must not block.
#[derive(Clone)]
pub struct VisitEventSink(EventFn);

/// The closure behind a [`VisitEventSink`], named so the type is one word
/// wherever it appears.
type EventFn = std::sync::Arc<dyn Fn(diag::VisitEventKind, &str) + Send + Sync>;

impl VisitEventSink {
    /// Wraps `sink`, which is called once per event with its detail.
    pub fn new(sink: impl Fn(diag::VisitEventKind, &str) + Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(sink))
    }

    /// Hands one event to the wrapped closure.
    pub fn emit(&self, kind: diag::VisitEventKind, detail: &str) {
        (self.0)(kind, detail);
    }
}

impl std::fmt::Debug for VisitEventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VisitEventSink(..)")
    }
}

/// Records one visit event in both places it belongs: the attempt's record
/// (section 7's `events[]`) and the caller's live sink, if it has one.
fn emit(
    recorder: Option<&Recorder>,
    sink: Option<&VisitEventSink>,
    kind: diag::VisitEventKind,
    detail: impl Into<String>,
) {
    let detail = detail.into();
    if let Some(recorder) = recorder {
        recorder.event(kind, detail.clone());
    }
    if let Some(sink) = sink {
        sink.emit(kind, &detail);
    }
}

/// How many porch frames the reader task may hold for the doorbell loop.
///
/// Chosen, not measured. The porch stream carries a handful of frames per
/// attempt (`Candidates` each way, `PathUp`, `PathDown`, `Goodbye`), so 16
/// is several attempts of headroom; past it the newest frame is dropped
/// and counted rather than growing a queue a peer controls the length of.
/// The peer is already inside the mutually authenticated tunnel, so this
/// is a bound and not a defence.
pub const PORCH_FRAME_QUEUE: usize = 16;

/// How often a held visit takes a round trip sample (WO-1.5a: "sample RTT
/// once a second").
pub const RTT_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// How many round trip samples one visit keeps.
///
/// 4096 is 68 minutes at one a second. Past it sampling stops and the
/// record says how many it holds, because the alternative for a house that
/// keeps one visit open for a day is a `Vec` that grows with uptime, and
/// a reservoir would make the p95 a number nobody can reproduce from the
/// events beside it.
pub const MAX_RTT_SAMPLES: usize = 4096;

/// The longest a visit may be held open by [`Hold::For`], and the value a
/// longer one is clamped to.
///
/// A day. Chosen, not measured, and generous for the thing it bounds: a
/// measurement holds a visit for tens of seconds (WO-1.5's rows hold 90),
/// and anything that wants a visit open for longer wants a house, which
/// holds one until its peer leaves. The clamp is what stops a
/// `Hold::For(Duration::MAX)` from overflowing the deadline arithmetic
/// this hold is measured against, which is a panic in a crate that
/// forbids them, or from degrading into "hold forever" through a
/// `checked_add` that quietly returned `None` (Yseult's Low 1 on PR 80).
/// `doctor` refuses a larger `--hold` at the command line, before any
/// network work; this is the library's own floor under that.
pub const MAX_HOLD: Duration = Duration::from_secs(86_400);

/// The `Goodbye.reason` a visit ending on its own terms sends (frame 19).
/// Section 1 defines no enum of values for the field, so 0 is the plain
/// clean exit every caller in this workspace already uses.
const GOODBYE_VISIT_OVER: u8 = 0;

/// How long a departing visit waits for the peer to acknowledge its
/// `Goodbye`. Chosen, not measured: one frame on an open stream is one
/// round trip away on any path this design measures, and a second is long
/// enough for a bad one without holding up an exit.
const GOODBYE_ACK_DEADLINE: Duration = Duration::from_secs(1);

/// The round trip samples one held visit took, and what they measure.
///
/// Two sources, never averaged blindly (see [`diag::RttSource`]): a probe
/// pong's round trip while the path is direct, and
/// `quinn::Connection::rtt()` while it is relayed, which is the only end
/// to end number a relayed visit has, probes being addressed to a
/// candidate and a relayed peer having none.
#[derive(Debug)]
struct RttSamples {
    samples: Vec<Duration>,
    last_sample: Option<Instant>,
    source: diag::RttSource,
    /// The most recent probe round trip on a live direct path, taken by
    /// the next sample tick and cleared by it, so a sample is a fresh
    /// measurement rather than a stale one repeated.
    latest_probe: Option<Duration>,
    full: bool,
}

impl RttSamples {
    /// A fresh set, whose first sample falls one [`RTT_SAMPLE_INTERVAL`]
    /// after `started` rather than at once.
    ///
    /// Seeded rather than left `None` (Wystan's precision note): an
    /// immediate first sample on a relayed visit reads
    /// `Connection::rtt()` while the handshake's own estimate is all it
    /// has, which is not a steady-state round trip and not what "sampled
    /// once a second" promises. A 20 second hold therefore takes about 20
    /// samples starting at 1 s, not 20 starting at 0.
    fn new(started: Instant) -> Self {
        Self {
            samples: Vec::new(),
            last_sample: Some(started),
            source: diag::RttSource::NotSampled,
            latest_probe: None,
            full: false,
        }
    }

    /// A probe answered on a path that is live and direct.
    fn observe_probe(&mut self, rtt: Duration) {
        self.latest_probe = Some(rtt);
    }

    /// Takes at most one sample per [`RTT_SAMPLE_INTERVAL`].
    fn tick(&mut self, now: Instant, quic_rtt: Duration) {
        if self
            .last_sample
            .is_some_and(|last| now.duration_since(last) < RTT_SAMPLE_INTERVAL)
        {
            return;
        }
        let (sample, source) = match self.latest_probe.take() {
            Some(probe) => (probe, diag::RttSource::Probe),
            None => (quic_rtt, diag::RttSource::Quic),
        };
        self.last_sample = Some(now);
        if self.samples.len() >= MAX_RTT_SAMPLES {
            self.full = true;
            return;
        }
        self.samples.push(sample);
        self.source = self.source.joined(source);
    }

    /// Nearest-rank percentiles in microseconds: `median`, `p95`, and how
    /// many samples they are over.
    ///
    /// Nearest rank (`ceil(p * n)`), not interpolated, so every value
    /// reported is a round trip that was actually measured; on an even
    /// count the median is the lower of the two middle samples.
    fn percentiles(&self) -> (u32, u32, u32) {
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let n = sorted.len();
        let at = |fraction: f64| -> u32 {
            if n == 0 {
                return 0;
            }
            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
            let rank = (fraction * n as f64).ceil() as usize;
            let index = rank.max(1).min(n).saturating_sub(1);
            sorted
                .get(index)
                .and_then(|d| u32::try_from(d.as_micros()).ok())
                .unwrap_or(u32::MAX)
        };
        (at(0.5), at(0.95), u32::try_from(n).unwrap_or(u32::MAX))
    }

    /// Writes the percentiles into the attempt's record.
    fn write_into(&self, recorder: Option<&Recorder>) {
        if let Some(recorder) = recorder {
            let (median, p95, count) = self.percentiles();
            recorder.set_rtt(median, p95, count, self.source);
        }
    }
}

/// Which part of section 2 a visit is in right now.
enum Phase {
    /// Step 5: probing every candidate, nothing proved yet.
    Probing,
    /// Steps 6 and 7: a candidate won and section 4 is watching it.
    Watching(Watch),
    /// On the relay with nothing under probe: hole punching was switched
    /// off, every candidate was given up, or a dead path's rerun is this
    /// side's to wait for rather than to start.
    ///
    /// Carrying a [`RelayWatch`], because section 4 is about the path a
    /// visit is on and a relayed visit is on the relay session. Before
    /// this, a relayed visit had no liveness at all: it died in silence,
    /// with no `path_stale`, no `path_dead` and a reason naming whatever
    /// the upgrade had failed of ten seconds earlier.
    Relayed(RelayWatch),
}

/// One upgraded path under section 4's liveness policy.
struct Watch {
    addr: SocketAddr,
    liveness: crate::live::PeerLiveness,
    /// The tx id of the probe in flight, so a pong is matched to the ping
    /// it answers rather than to whatever arrived.
    outstanding: Option<[u8; 8]>,
    sent_at: Option<Instant>,
}

/// The relay session under section 4's liveness, for a visit whose traffic
/// is on the relay.
///
/// The probe is section 2's own 81 byte packet, authenticated under the
/// same attempt key and answered by the same `pong_for`, addressed to the
/// peer's synthetic address so [`crate::sock::PorchSocket::send_probe`]
/// wraps it as a `Relay` payload. Nothing new goes on the wire: the gate
/// sees one more opaque relay datagram every
/// [`crate::live::VISIT_PROBE_INTERVAL`], and the peer needs no code it
/// does not already run, since a ping is answered in every phase.
///
/// **Detection, not fall-back.** A direct path that goes stale has
/// somewhere to go; the relay does not. So this reports, and the visit
/// ends when its connection does, with a reason that now names the path
/// death rather than the old probe timeout. What it deliberately does not
/// do is notice a relay that comes back after `dead`: probing stops there,
/// and re-establishing a visit across a dead relay is the redial question
/// of issue 84.
struct RelayWatch {
    /// The peer's synthetic address (section 3), which is both what quinn
    /// addresses this peer at and what a relayed probe is sent to.
    addr: SocketAddr,
    liveness: crate::live::PeerLiveness,
    /// The tx id of the probe in flight, so a pong is matched to the ping
    /// it answers rather than to whatever arrived.
    outstanding: Option<[u8; 8]>,
    sent_at: Option<Instant>,
}

impl RelayWatch {
    /// A relay path assumed live at `now`, which is what a visit carrying
    /// traffic through the gate is.
    fn new(addr: SocketAddr, recorder: Option<Recorder>, now: Instant) -> Self {
        let mut liveness = crate::live::PeerLiveness::new(now).with_recorder(recorder);
        liveness.set_activity(crate::live::Activity::Visit);
        Self {
            addr,
            liveness,
            outstanding: None,
            sent_at: None,
        }
    }
}

/// Reads porch frames off `recv` into `queue` until the stream ends.
///
/// **Why a task rather than a read in the loop's `select!`.** A held visit
/// has to answer pings while it waits for a frame that may not come for a
/// minute, and `RecvStream::read_exact` is not cancellation safe: a
/// `select!` arm dropped mid-frame loses the bytes it had already taken
/// and desynchronises the stream. So the read lives in one task that never
/// cancels, and the loop takes whole frames out of a bounded queue.
///
/// Exit paths, since no task may run without one: the stream ends or
/// errors (including the connection closing), or the queue's other end is
/// dropped, which is [`ReaderGuard`] aborting it when the doorbell returns.
async fn read_porch_frames(
    mut recv: quinn::RecvStream,
    queue: std::sync::Arc<Mutex<VecDeque<Result<PorchFrame, GateError>>>>,
) {
    loop {
        // The deadline is the connection's, not this read's: a porch
        // stream carrying no frame for a minute is an ordinary quiet
        // visit, and the peer connection's own idle timeout (section 4's
        // `MAX_IDLE_TIMEOUT`, with quinn's keepalive under it) is what
        // ends a visit whose peer has gone. An hour is the same number
        // `gate::client`'s own reader loop uses for the same reason.
        let frame = read_porch_frame(&mut recv, Duration::from_secs(3600)).await;
        let ended = frame.is_err();
        {
            let mut queue = queue.lock_or_recover();
            if queue.len() < PORCH_FRAME_QUEUE {
                queue.push_back(frame);
            }
        }
        if ended {
            return;
        }
    }
}

/// Aborts the porch reader task when the doorbell returns, whichever way
/// it returns.
struct ReaderGuard(tokio::task::JoinHandle<()>);

impl Drop for ReaderGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs section 2 for one peer, end to end, on an already-open end to end
/// QUIC connection that is already carrying traffic through the relay.
///
/// The order is the design's: exchange candidates on the porch stream
/// inside the sealed connection so the gate sees them as ciphertext (step
/// 3), ask the gate to fire both sides together (step 4), probe every
/// candidate at once (step 5), upgrade the first to answer three
/// consecutive probes (step 6), and revert to the relay if that path later
/// dies (step 7). The end to end connection is never touched by any of it:
/// it addresses the peer's synthetic address throughout and never learns
/// the path moved, which is section 3's whole premise.
///
/// **Holding the visit open** ([`DoorbellParams::hold`], WO-1.5a). With
/// [`Hold::UntilAttemptSettles`] this returns when the attempt settles:
/// every candidate given up, or a path upgraded and later lost, or the
/// peer connection closed. With a hold it keeps going instead, under
/// section 4's own policy driven by [`crate::live::PeerLiveness`]: one
/// probe every 500 ms while the visit is live, traffic back on the relay
/// the moment three in a row go unanswered, and the path dropped after the
/// stale grace. A dropped path is what reruns the doorbell, with a fresh
/// attempt id on the same porch stream, which is section 2 step 7's own
/// rule.
///
/// **A rerun is the initiator's to start.** Both sides detect a dead path,
/// but only role 1 writes the next `Candidates`; role 2 falls back to the
/// relay and waits for it. Two sides opening an attempt at once would put
/// two `Candidates` frames on one stream with no rule for which is the
/// attempt, and the initiator is already the side that names the attempt
/// id and asks the gate to fire.
///
/// # Errors
///
/// Returns a [`GateError`] if the porch stream cannot be opened, a frame
/// is malformed, the gate never sends `Start`, or the peer connection
/// fails.
#[allow(clippy::too_many_lines)]
pub async fn run_doorbell(
    porch: &std::sync::Arc<crate::sock::PorchSocket>,
    gate: &crate::gate::client::GateClient,
    peer: &quinn::Connection,
    params: DoorbellParams,
    control: &std::sync::Arc<DoorbellControl>,
) -> Result<DoorbellOutcome, GateError> {
    let initiator = params.role == 1;
    let rec = params.recorder.as_ref();
    let sink = params.events.as_ref();
    let held = params.hold != Hold::UntilAttemptSettles;

    let path = porch.path_for(&params.peer_key);
    // The address quinn addresses this peer at, which never changes for
    // the life of the connection (section 3: the end to end connection
    // never learns the path moved). It is also the address a relayed
    // liveness probe is sent to, and the source a relayed pong arrives
    // from.
    let synthetic = peer.remote_address();
    let gate_addr = gate.gate_connection().remote_address();
    // A relay path's address is the gate's: that is where this house's
    // traffic for this peer actually leaves to while it is relayed. The
    // peer's synthetic address (section 3) never leaves the machine and
    // would tell a reader of the record nothing.
    let relay_addr = Addr::from_socket_addr(gate_addr);
    if let Some(recorder) = rec {
        // Section 2 step 2: traffic is on the relay from before this
        // function was called, so the record says relay until an upgrade
        // changes it.
        recorder.set_path(diag::PathChoice::Relay(relay_addr), 0);
    }
    // Before the porch stream, not after: the end to end connection is
    // open and relayed by the time this function is called, which is what
    // makes the visit open, and the responder's own `accept_bi` below
    // does not return until the initiator opens its side. Announcing the
    // visit after that would mean a house could not say it had a visitor
    // until the visitor got round to the doorbell.
    emit(
        rec,
        sink,
        diag::VisitEventKind::VisitOpen,
        format!("relay through {gate_addr}"),
    );
    if held {
        // A held visit is carrying traffic from this moment whichever path
        // has it, so `live` is recorded here rather than only on an
        // upgrade: WO-1.5 case (e) is a visit that is meant to stay
        // relayed, and section 7's "exit 0 only if it reached live" has to
        // be true of a run that did exactly what it was asked to.
        diag::record(
            rec,
            Step::Live,
            StepOutcome::Ok,
            "the visit is open on the relay path",
        );
    }

    // Step 3. The initiator opens the porch stream and names the attempt;
    // the responder accepts and adopts it, so one id names the attempt in
    // both houses' records without either having to agree on a draw. The
    // stream is opened once per visit and outlives every rerun (step 7:
    // "the porch stream stays open").
    let opened = if initiator {
        peer.open_bi().await
    } else {
        peer.accept_bi().await
    };
    let (mut send, recv) = match opened {
        Ok(stream) => stream,
        Err(e) => {
            diag::record(
                rec,
                Step::CandidateExchange,
                StepOutcome::Fail,
                e.to_string(),
            );
            settle(rec, Reason::PeerHandshakeFailed);
            return Err(e.into());
        }
    };
    let deadline = crate::authed::control_read_deadline();
    let frames = std::sync::Arc::new(Mutex::new(VecDeque::new()));
    let _reader_guard = ReaderGuard(tokio::spawn(read_porch_frames(
        recv,
        std::sync::Arc::clone(&frames),
    )));

    let started = Instant::now();
    let hold_until = match params.hold {
        // Clamped, then added: `MAX_HOLD` is a day, so the sum is
        // representable on every platform this builds for and the `None`
        // arm below cannot be reached by a caller asking for too much.
        Hold::For(duration) => started.checked_add(duration.min(MAX_HOLD)),
        Hold::UntilAttemptSettles | Hold::UntilPeerLeaves => None,
    };
    let mut outcome = DoorbellOutcome {
        attempt: [0u8; 16],
        upgraded_to: None,
        fell_back: false,
    };
    let mut rtt = RttSamples::new(started);
    let mut pongs = PongLimiter::new(started);
    // The `Candidates` frame that started a rerun, when this side read it
    // out of the queue rather than being the side that wrote it.
    let mut adopted: Option<Exchanged> = None;
    // The reason a visit that never proved a candidate ends with. Cleared
    // at the top of every attempt: a rerun that upgrades has undone
    // whatever the last one gave up on, and a visit that ended healthy
    // must not be reported by the reason of an attempt it recovered from
    // (Yseult's Low 4).
    let mut give_up_reason: Option<Reason>;
    // Whether the relay session this visit was carried on went dead under
    // section 4. It outlives an attempt on purpose: it is a fact about the
    // visit, not about the attempt that happened to be running, and it is
    // what makes the record's reason name what ended the visit rather than
    // what the upgrade had failed of earlier.
    let mut relay_dead = false;
    let mut attempts = 0u32;

    'attempts: loop {
        give_up_reason = None;
        // Section 2 step 7: "what reruns, with a fresh attempt id, is
        // gathering, exchange and probing, steps 1 and 3 to 6". Gathering
        // is step 1, so a rerun gathers again rather than re-offering the
        // list the caller built before the path died: WO-1.5 case (f) is a
        // local address change, and a stale list cannot contain the
        // address the machine now has (Yseult's Medium 2). The first
        // attempt keeps the caller's own list, which the caller gathered
        // moments ago and which may hold what only it knows (a discovered
        // peer, a test's chosen candidate).
        let candidates = if attempts == 0 {
            params.candidates.clone()
        } else {
            regather(gate, &params.candidates, &params.peer_discovered)
        };
        attempts = attempts.saturating_add(1);
        let mut half = [0u8; 32];
        rand::rng().fill(&mut half);
        let exchanged = match adopted.take() {
            // A rerun this side is joining: the peer's `Candidates` is
            // already in hand, so only this side's own half goes out.
            Some(exchanged) => {
                match write_candidates(
                    &mut send,
                    exchanged.attempt,
                    &candidates,
                    half,
                    params.no_punch,
                )
                .await
                {
                    Ok(()) => Ok(exchanged),
                    Err(e) => Err(e),
                }
            }
            None => {
                exchange_candidates(
                    initiator,
                    &mut send,
                    &frames,
                    &candidates,
                    half,
                    params.no_punch,
                    deadline,
                )
                .await
            }
        };
        let Exchanged {
            attempt,
            peer_addrs,
            peer_half,
            peer_no_upgrade,
        } = match exchanged {
            Ok(exchanged) => exchanged,
            Err(e) => {
                diag::record(
                    rec,
                    Step::CandidateExchange,
                    StepOutcome::Fail,
                    e.to_string(),
                );
                settle(rec, Reason::PeerHandshakeFailed);
                return Err(e);
            }
        };
        outcome.attempt = attempt;
        if let Some(recorder) = rec {
            recorder.set_attempt(attempt);
        }

        let (half_initiator, half_responder) = if initiator {
            (half, peer_half)
        } else {
            (peer_half, half)
        };
        let key = probe_key(&attempt, &half_initiator, &half_responder);

        // Arming the key is what lets the porch socket queue this attempt's
        // probes at all: anything not authenticating under an armed key is
        // dropped and counted there rather than queued (Yseult's High). The
        // guard disarms on every exit, including an error return and the
        // next turn of this loop.
        let _attempt_guard = AttemptGuard::arm(porch, gate, attempt, key, params.session);

        let mut state = Attempt::new(attempt, key, params.peer_observed);
        // Vouching first, candidates in priority order after it (Yseult's
        // High 2). Vouching has to come first for issue #37: an address
        // this house heard the peer announce on its own network must
        // already be vouched for by the time that peer's own list is read,
        // or the same LAN address arrives as a private range nobody but
        // the peer stands behind. Taking *slots* is the other way round:
        // the peer's list and the gate's reflection go in first and
        // discovery fills what is left, up to its own
        // `DISCOVERY_CANDIDATE_SLOTS`, so a LAN stranger replaying
        // announces cannot crowd the real candidates out of the attempt.
        for addr in &params.peer_discovered {
            state.vouch(*addr);
        }
        state.add_peer_candidates(&peer_addrs);
        for addr in &params.peer_discovered {
            state.add_discovered(*addr);
        }

        // Section 7 names no `gather` step, so section 2 step 1's result is
        // recorded as the detail of the exchange that carried it: how many
        // addresses this house offered, how many the peer offered, and how
        // many survived into the candidate table to be probed.
        diag::record(
            rec,
            Step::CandidateExchange,
            StepOutcome::Ok,
            format!(
                "{local} local, {peer} from the peer, {discovered} discovered, {probed} probed",
                local = candidates.len(),
                peer = peer_addrs.len(),
                discovered = params.peer_discovered.len(),
                probed = state.candidate_count(),
            ),
        );

        let mut phase = Phase::Probing;
        if params.no_punch || peer_no_upgrade {
            // WO-1.5 case (e), and the one thing this flag does: the
            // candidates were still exchanged, so both sides' records show
            // what would have been probed, and nothing is probed. Recorded
            // as an `ok` step, because nothing failed here: one side or
            // the other was told not to.
            //
            // **Both sides stop, and both say the same word.** Frame 16
            // carries the intent (design amendment 4), so a peer running
            // `--no-punch` is not left waiting out the 10 s start window
            // for a `Start` nobody asked for and recording an `internal`
            // failure that did not happen, which is what this did before
            // the flag was on the wire.
            let whose = if params.no_punch {
                "this run"
            } else {
                "the peer's run"
            };
            diag::record(
                rec,
                Step::ProbeBurst,
                StepOutcome::Ok,
                format!(
                    "skipped: hole punching is off for {whose} (--no-punch), \
                     {probed} candidates not probed",
                    probed = state.candidate_count()
                ),
            );
            give_up_reason = Some(Reason::PunchDisabled);
            phase = Phase::Relayed(RelayWatch::new(
                synthetic,
                params.recorder.clone(),
                Instant::now(),
            ));
        } else if state.candidate_count() == 0 {
            // Nothing to probe: the attempt stays on the relay for good,
            // and section 7's `no_candidates` says why.
            diag::record(
                rec,
                Step::ProbeBurst,
                StepOutcome::Fail,
                "no candidates to probe",
            );
        }

        // Step 4. Either side may ask; the initiator does, so exactly one
        // request is sent for the ordinary case and the 4 per session
        // budget is not spent on a race.
        if !matches!(phase, Phase::Relayed(_))
            && initiator
            && let Err(e) = gate.request_start(params.session).await
        {
            diag::record(rec, Step::StartSignal, StepOutcome::Fail, e.to_string());
            if !held {
                settle(rec, Reason::Internal);
                return Err(e);
            }
            give_up_reason = Some(Reason::Internal);
            phase = Phase::Relayed(RelayWatch::new(
                synthetic,
                params.recorder.clone(),
                Instant::now(),
            ));
        }
        if !matches!(phase, Phase::Relayed(_)) {
            match gate
                .await_start(params.session, Duration::from_secs(10))
                .await
            {
                Ok(start) => {
                    if let Some(recorder) = rec {
                        // Frame 7's `gate_ms`, the one shared timestamp: it
                        // is written into both houses' records so two logs
                        // align, and is never a time to act on.
                        recorder.set_gate_ms(start.gate_ms);
                        recorder.set_session(params.session);
                    }
                    diag::record(
                        rec,
                        Step::StartSignal,
                        StepOutcome::Ok,
                        format!("firing in {} ms", start.fire_in_ms),
                    );
                    state.start_signal_received(start.received_at);
                }
                Err(e) => {
                    // Section 7's reason enum names no missing-`Start`
                    // case, so this is `internal`, its own stated
                    // catch-all, with the step saying which one it was. A
                    // held visit keeps going on the relay rather than
                    // ending: a rerun that cannot get a start signal (the
                    // 4 per session budget spent, say) has lost its chance
                    // at a direct path, not its visit.
                    diag::record(rec, Step::StartSignal, StepOutcome::Fail, e.to_string());
                    if !held {
                        settle(rec, Reason::Internal);
                        return Err(e);
                    }
                    give_up_reason = Some(Reason::Internal);
                    phase = Phase::Relayed(RelayWatch::new(
                        synthetic,
                        params.recorder.clone(),
                        Instant::now(),
                    ));
                }
            }
        }

        loop {
            let now = Instant::now();

            // The visit's own end: the hold ran out, or this house was
            // asked to stop. Frame 19 goes out first so the peer marks
            // this side dead at once and skips stale (section 4).
            if control.stopping() || hold_until.is_some_and(|until| now >= until) {
                let _ = write_porch_frame(
                    &mut send,
                    &PorchFrame::Goodbye {
                        v: 1,
                        reason: GOODBYE_VISIT_OVER,
                    },
                )
                .await;
                // Stamped where the decision was taken, before the wait
                // below (Wystan's D2): a peer that cannot acknowledge is
                // exactly the case a reader correlates this event against
                // the other side's log for, and charging it the whole
                // acknowledgement budget put the timestamp up to a second
                // after the visit actually ended.
                emit(
                    rec,
                    sink,
                    diag::VisitEventKind::Goodbye,
                    if control.stopping() {
                        "this house is stopping"
                    } else {
                        "the hold elapsed"
                    },
                );
                // A goodbye that never left is not a goodbye: `close`
                // abandons data not yet transmitted and the caller closes
                // this connection as soon as this returns, so the frame is
                // finished and its receipt waited for on a bounded budget,
                // the same shape `GateClient::goodbye` uses for frame 11.
                // Running out of that budget is not an error: section 4
                // makes the goodbye a courtesy whose absence the peer is
                // entitled to handle, and it does, through stale and dead.
                let _ = send.finish();
                let _ = tokio::time::timeout(GOODBYE_ACK_DEADLINE, send.stopped()).await;
                let reason = end_of_visit_reason(
                    &params,
                    give_up_reason,
                    path.as_ref(),
                    &state,
                    rec,
                    outcome.upgraded_to.is_some() || outcome.fell_back,
                    relay_dead,
                );
                finish_visit(rec, &rtt, path.as_ref(), reason);
                return Ok(outcome);
            }

            match &mut phase {
                Phase::Probing => {
                    for (to, bytes) in state.due_probes(now, || {
                        let mut tx = [0u8; 8];
                        rand::rng().fill(&mut tx);
                        tx
                    }) {
                        let _ = porch.send_probe(to, &bytes);
                    }
                    if state.given_up(now) {
                        diag::record(
                            rec,
                            Step::ProbeBurst,
                            StepOutcome::Fail,
                            format!(
                                "0 of {count} candidates answered",
                                count = state.candidate_count()
                            ),
                        );
                        record_relay_counters(rec, path.as_ref());
                        // Section 7's inference, so the Phase 1 gate's
                        // named reason for case (d) is a rule and not a
                        // guess. The counters are read first because the
                        // hairpin rule asks whether the relay worked.
                        let reason = rec.map_or(Reason::ProbeTimeout, |recorder| {
                            if state.candidate_count() == 0 {
                                Reason::NoCandidates
                            } else {
                                recorder.probe_failure_reason()
                            }
                        });
                        if !held {
                            settle(rec, reason);
                            return Ok(outcome);
                        }
                        // Held: the visit carries on relayed. Nothing
                        // re-probes on its own, because section 2 looks
                        // for a better path only after a failure of one
                        // that worked, and a burst every ten seconds for
                        // the length of a hold is a burst nobody asked
                        // for.
                        give_up_reason = Some(reason);
                        phase = Phase::Relayed(RelayWatch::new(
                            synthetic,
                            params.recorder.clone(),
                            now,
                        ));
                    }
                }
                Phase::Watching(watch) => {
                    if watch.liveness.due_probe(now) {
                        let mut tx = [0u8; 8];
                        rand::rng().fill(&mut tx);
                        let ping = Probe {
                            kind: PROBE_PING,
                            attempt,
                            tx,
                            observed: Addr::default(),
                        };
                        let _ = porch.send_probe(watch.addr, &ping.encode(&key));
                        watch.outstanding = Some(tx);
                        watch.sent_at = Some(now);
                    }
                    match watch.liveness.poll(now) {
                        Some(crate::live::LivenessChange::WentStale) => {
                            // Section 4: stop sending on this path, move
                            // traffic to the relay at once, keep probing.
                            // The move happens here and not at dead,
                            // which is what makes the Phase 1 criterion
                            // (detection plus fall-back under 1 s on the
                            // side that moved) reachable at all.
                            let probes = crate::live::PROBES_TO_STALE;
                            emit(
                                rec,
                                sink,
                                diag::VisitEventKind::PathStale,
                                format!(
                                    "{probes} consecutive probes unanswered on {addr}",
                                    addr = watch.addr
                                ),
                            );
                            if let Some(path) = path.as_ref() {
                                path.fall_back_to_relay();
                            }
                            outcome.fell_back = true;
                            if let Some(recorder) = rec {
                                recorder.set_path(diag::PathChoice::Relay(relay_addr), 0);
                            }
                            diag::record(
                                rec,
                                Step::RelayFallback,
                                StepOutcome::Ok,
                                "traffic moved back to the relay session",
                            );
                            emit(
                                rec,
                                sink,
                                diag::VisitEventKind::FellBack,
                                format!("traffic moved back to the relay through {gate_addr}"),
                            );
                            let _ = write_porch_frame(
                                &mut send,
                                &PorchFrame::PathDown {
                                    v: 1,
                                    attempt,
                                    addr: Addr::from_socket_addr(watch.addr),
                                    // Section 7's reason enum:
                                    // `path_idle_timeout`.
                                    reason: 16,
                                },
                            )
                            .await;
                            if !held {
                                record_relay_counters(rec, path.as_ref());
                                settle(rec, Reason::PathIdleTimeout);
                                return Ok(outcome);
                            }
                        }
                        Some(crate::live::LivenessChange::WentDead) => {
                            emit(
                                rec,
                                sink,
                                diag::VisitEventKind::PathDead,
                                format!(
                                    "the stale grace elapsed with no answer from {addr}",
                                    addr = watch.addr
                                ),
                            );
                            if held && initiator {
                                // Section 2 step 7: gathering, exchange
                                // and probing rerun with a fresh attempt
                                // id, on the same porch stream and the
                                // same end to end connection. Only for a
                                // held visit: a one-shot attempt has
                                // already returned at stale, and a rerun
                                // there would be a loop with nothing to
                                // end it.
                                continue 'attempts;
                            }
                            phase = Phase::Relayed(RelayWatch::new(
                                synthetic,
                                params.recorder.clone(),
                                now,
                            ));
                        }
                        None => {}
                    }
                }
                Phase::Relayed(watch) => {
                    // Section 4 on the relay session. The probe goes to the
                    // peer's synthetic address, so the porch socket wraps
                    // it as a `Relay` payload and the gate forwards it
                    // opaquely; the peer answers it in whatever phase it is
                    // in, because a ping is always answered.
                    if watch.liveness.due_probe(now) {
                        let mut tx = [0u8; 8];
                        rand::rng().fill(&mut tx);
                        let ping = Probe {
                            kind: PROBE_PING,
                            attempt,
                            tx,
                            observed: Addr::default(),
                        };
                        let _ = porch.send_probe(watch.addr, &ping.encode(&key));
                        watch.outstanding = Some(tx);
                        watch.sent_at = Some(now);
                    }
                    match watch.liveness.poll(now) {
                        Some(crate::live::LivenessChange::WentStale) => {
                            let probes = crate::live::PROBES_TO_STALE;
                            emit(
                                rec,
                                sink,
                                diag::VisitEventKind::PathStale,
                                format!(
                                    "{probes} consecutive probes unanswered on the relay \
                                     through {gate_addr}"
                                ),
                            );
                        }
                        Some(crate::live::LivenessChange::WentDead) => {
                            // Reported once per watch: `PeerLiveness::poll`
                            // returns each transition exactly once and a
                            // dead path is never probed again.
                            relay_dead = true;
                            emit(
                                rec,
                                sink,
                                diag::VisitEventKind::PathDead,
                                format!(
                                    "the stale grace elapsed with no answer over the relay \
                                     through {gate_addr}"
                                ),
                            );
                            // A one-shot run has nothing left to wait for:
                            // the path it was on is gone and there is no
                            // other. A held visit stays, because its
                            // connection may still close with something
                            // more to say and the record is written once.
                            if !held {
                                record_relay_counters(rec, path.as_ref());
                                settle(rec, Reason::PathIdleTimeout);
                                return Ok(outcome);
                            }
                        }
                        None => {}
                    }
                }
            }

            // Drain whatever has arrived, then wait a short tick. The tick
            // is 20 ms rather than the probe interval so a pong is timed
            // at roughly its true round trip rather than rounded up to the
            // next schedule point.
            // Only this attempt's probes: the queue is keyed by attempt
            // inside the socket, so a house holding two visits at once
            // never has one doorbell consume the other's pongs (Yseult's
            // High on PR 89). The attempt filter that used to stand here
            // discarded them instead, which with section 4 probing every
            // relayed visit is a false `path_dead` on a healthy path.
            while let Some((from, probe)) = porch.try_recv_probe(&attempt) {
                let arrived = Instant::now();
                match probe.kind {
                    PROBE_PING => {
                        // Answered once per tx id and at most
                        // `PONG_ANSWERS_PER_SECOND`, so a captured ping
                        // cannot be replayed into a reflector (Yseult's
                        // Medium).
                        if control.answering() && pongs.may_answer(probe.tx, arrived) {
                            let _ = porch.send_probe(from, &state.pong_for(&probe, from));
                        }
                    }
                    _ => match &mut phase {
                        Phase::Watching(watch) => {
                            // The source must be the live path itself
                            // (Yseult's Low): a pong arriving over the
                            // relay, or from anywhere else, would hold a
                            // dead direct path up indefinitely.
                            if from == watch.addr && watch.outstanding == Some(probe.tx) {
                                let live = watch.liveness.state() == crate::live::Liveness::Live;
                                if let Some(sent) = watch.sent_at {
                                    let sample = arrived.duration_since(sent);
                                    if let Some(path) = path.as_ref() {
                                        path.record_rtt(sample);
                                    }
                                    watch.liveness.on_pong(arrived, sample);
                                    // Only while the path is still live:
                                    // a pong answered during the stale
                                    // grace measures a path traffic has
                                    // already left, and labelling that a
                                    // probe sample would make the
                                    // record's `rtt_source` say the
                                    // opposite of where the bytes went.
                                    if live {
                                        rtt.observe_probe(sample);
                                    }
                                }
                                watch.outstanding = None;
                            }
                        }
                        Phase::Probing => {
                            state.on_pong(from, &probe, arrived);
                        }
                        Phase::Relayed(watch) => {
                            // The relay path's own pong, matched the same
                            // way a direct path's is: the source must be
                            // the path being watched, which for a relayed
                            // visit is the peer's synthetic address.
                            if from == watch.addr && watch.outstanding == Some(probe.tx) {
                                if let Some(sent) = watch.sent_at {
                                    // Fed to the liveness only, never to
                                    // `rtt`: section 7's `rtt_source` says
                                    // `probe` for a direct path measured by
                                    // its own probes and `quic` for a
                                    // relayed visit, and quietly changing
                                    // what a shipped measurement means is
                                    // not this fix's to do.
                                    watch
                                        .liveness
                                        .on_pong(arrived, arrived.duration_since(sent));
                                }
                                watch.outstanding = None;
                            }
                        }
                    },
                }
            }

            if matches!(phase, Phase::Probing)
                && let Some(winner) = state.decide()
            {
                // Step 6. The winner goes into the path table, `PathUp`
                // goes out, and the relay session stays open but idle.
                if let Some(path) = path.as_ref() {
                    path.upgrade_to(winner.addr);
                    // Section 3: the new path's smoothed RTT is seeded
                    // from its own first sample, which is the winning
                    // probe's, rather than left `None` until the first
                    // live probe answers (Konrad's should 4).
                    path.record_rtt(winner.rtt);
                }
                let rtt_us = u32::try_from(winner.rtt.as_micros()).unwrap_or(u32::MAX);
                diag::record(
                    rec,
                    Step::ProbeBurst,
                    StepOutcome::Ok,
                    format!(
                        "{winner_addr} answered {CONSECUTIVE_PONGS_TO_WIN} consecutive probes",
                        winner_addr = winner.addr
                    ),
                );
                diag::record(
                    rec,
                    Step::Upgrade,
                    StepOutcome::Ok,
                    format!("direct to {addr} at {rtt_us} us", addr = winner.addr),
                );
                if let Some(recorder) = rec {
                    recorder.set_path(
                        diag::PathChoice::Direct(Addr::from_socket_addr(winner.addr)),
                        rtt_us,
                    );
                }
                diag::record(
                    rec,
                    Step::Live,
                    StepOutcome::Ok,
                    "traffic on the direct path",
                );
                let recovered = outcome.fell_back;
                emit(
                    rec,
                    sink,
                    if recovered {
                        diag::VisitEventKind::Recovered
                    } else {
                        diag::VisitEventKind::Upgraded
                    },
                    format!("direct to {addr} at {rtt_us} us", addr = winner.addr),
                );
                outcome.upgraded_to = Some(winner.addr);
                // Section 4 owns the path from here: one probe every 500
                // ms while a visit is under way, stale after three
                // unanswered in a row, dead after the grace. The srtt is
                // seeded from the winning probe so the first timer is
                // scaled by a real measurement rather than the floor.
                let mut liveness = crate::live::PeerLiveness::new(Instant::now())
                    .with_srtt(winner.rtt)
                    .with_recorder(params.recorder.clone());
                liveness.set_activity(crate::live::Activity::Visit);
                phase = Phase::Watching(Watch {
                    addr: winner.addr,
                    liveness,
                    outstanding: None,
                    sent_at: None,
                });
                write_porch_frame(
                    &mut send,
                    &PorchFrame::PathUp {
                        v: 1,
                        attempt,
                        addr: Addr::from_socket_addr(winner.addr),
                        rtt_us,
                    },
                )
                .await?;
            }

            // The peer's own frames.
            loop {
                let frame = frames.lock_or_recover().pop_front();
                let Some(frame) = frame else { break };
                match frame {
                    Ok(PorchFrame::Goodbye { .. }) => {
                        emit(
                            rec,
                            sink,
                            diag::VisitEventKind::Goodbye,
                            "the peer said goodbye",
                        );
                        diag::record(rec, Step::Closed, StepOutcome::Ok, "the peer said goodbye");
                        // How the visit ended is `peer_goodbye`, and for
                        // an ordinary visit that is the whole answer. The
                        // one exception is a visit nobody probed by
                        // instruction: WO-1.5 case (e) cites this field
                        // for why the visit stayed relayed, and which
                        // side hung up first must not change that answer
                        // from row to row. The goodbye is still in the
                        // record twice over, as a `closed` step and as an
                        // event.
                        let reason = if give_up_reason == Some(Reason::PunchDisabled) {
                            Reason::PunchDisabled
                        } else {
                            Reason::PeerGoodbye
                        };
                        finish_visit(rec, &rtt, path.as_ref(), reason);
                        return Ok(outcome);
                    }
                    Ok(PorchFrame::Candidates {
                        attempt: peer_attempt,
                        addrs,
                        probe_half,
                        no_upgrade,
                        ..
                    }) => {
                        // The other side reran the doorbell (step 7). Only
                        // the responder ever sees this, since only the
                        // initiator writes it.
                        if peer_attempt != attempt {
                            note_superseded_path(rec, sink, &phase, path.as_ref());
                            adopted = Some(Exchanged {
                                attempt: peer_attempt,
                                peer_addrs: addrs,
                                peer_half: probe_half,
                                peer_no_upgrade: no_upgrade,
                            });
                            continue 'attempts;
                        }
                    }
                    Ok(PorchFrame::PathDown {
                        attempt: peer_attempt,
                        ..
                    }) if peer_attempt == attempt => {
                        // **A fall-back is mutual, and it has to be.**
                        // Section 4 says `PathUp` and `PathDown` describe
                        // the sender's own choice and say nothing about
                        // this house's liveness, which is true of
                        // liveness and false of reachability: section 3's
                        // porch socket drops any datagram whose source is
                        // in no peer's candidate table, and a peer that
                        // has fallen back has dropped this house's
                        // address from its path table, so nothing this
                        // house sends direct is delivered any more. A
                        // house that kept sending there would put the
                        // porch stream one way and hang the rerun that
                        // follows, which is exactly what it did before
                        // this arm existed.
                        if let Some(path) = path.as_ref()
                            && let Some(dropped) = path.fall_back_to_relay()
                        {
                            outcome.fell_back = true;
                            if let Some(recorder) = rec {
                                recorder.set_path(diag::PathChoice::Relay(relay_addr), 0);
                            }
                            diag::record(
                                rec,
                                Step::RelayFallback,
                                StepOutcome::Ok,
                                format!("the peer left {dropped}, so this house did too"),
                            );
                            emit(
                                rec,
                                sink,
                                diag::VisitEventKind::FellBack,
                                format!(
                                    "the peer moved back to the relay, so traffic for it \
                                     leaves through {gate_addr} again"
                                ),
                            );
                        }
                        // The attempt is over for both sides. A
                        // one-shot attempt ends here, exactly as it ends
                        // on its own stale; a held visit carries on, the
                        // initiator starting the next attempt and the
                        // responder waiting for it, which is the same
                        // rule a dead path follows.
                        if !held {
                            record_relay_counters(rec, path.as_ref());
                            settle(rec, Reason::PathIdleTimeout);
                            return Ok(outcome);
                        }
                        if initiator {
                            note_superseded_path(rec, sink, &phase, path.as_ref());
                            continue 'attempts;
                        }
                        phase = Phase::Relayed(RelayWatch::new(
                            synthetic,
                            params.recorder.clone(),
                            Instant::now(),
                        ));
                    }
                    Ok(PorchFrame::PathUp { .. } | PorchFrame::PathDown { .. }) => {}
                    Err(_) => {
                        // The stream ended. `peer.closed()` below is the
                        // exit that says why.
                    }
                }
            }

            rtt.tick(now, peer.rtt());

            tokio::select! {
                () = tokio::time::sleep(Duration::from_millis(20)) => {}
                _ = peer.closed() => {
                    diag::record(
                        rec,
                        Step::Closed,
                        StepOutcome::Ok,
                        "the peer connection closed",
                    );
                    // An attempt that reached a direct path and then had
                    // its connection closed ended the way it should; a
                    // held visit that was carrying traffic did too. One
                    // closed before either did not, and `internal` is
                    // section 7's own catch-all for a failure it does not
                    // name.
                    let reason = if held || outcome.upgraded_to.is_some() {
                        end_of_visit_reason(
                            &params,
                            give_up_reason,
                            path.as_ref(),
                            &state,
                            rec,
                            outcome.upgraded_to.is_some() || outcome.fell_back,
                            relay_dead,
                        )
                    } else {
                        Reason::Internal
                    };
                    finish_visit(rec, &rtt, path.as_ref(), reason);
                    return Ok(outcome);
                }
            }
        }
    }
}

/// Says that a path this visit had already left is now dropped for good,
/// because the attempt watching it has been superseded by a rerun.
///
/// Section 4 reaches `dead` two ways: the stale grace elapses, or the
/// attempt that owned the path is replaced, which is the same "drop the
/// path" with the rerun already under way. Without this, a fall-back that
/// the peer answered by rerunning would leave a record that went stale and
/// never said what became of the path.
///
/// Only for a path traffic has already left: a house that adopts a rerun
/// while its own direct path is still carrying bytes has not lost
/// anything, and saying it had would be the record inventing a failure.
fn note_superseded_path(
    recorder: Option<&Recorder>,
    sink: Option<&VisitEventSink>,
    phase: &Phase,
    path: Option<&crate::path::PathEntry>,
) {
    let watching = matches!(phase, Phase::Watching(_));
    let left = path.is_none_or(|path| path.direct_addr().is_none());
    if watching && left {
        emit(
            recorder,
            sink,
            diag::VisitEventKind::PathDead,
            "the path is dropped: a rerun of the doorbell supersedes the attempt that held it",
        );
    }
}

/// The reason a visit that ran its course ends with.
///
/// **It describes what happened, not which timer won** (Wystan's D1). A
/// held visit ends when its hold elapses or its peer leaves, and that can
/// land anywhere in an attempt: before the probe burst has given up,
/// during it, or long after. The reason must read the same either way, so
/// this asks what the visit actually did rather than which branch it left
/// through:
///
/// - `punch_disabled` for a run told not to punch, whatever else happened;
/// - the reason a give-up already named, where the burst ran out first;
/// - `path_idle_timeout` only for a visit that **had** a direct path and
///   ended without it, which is what that reason's own doc says it means;
///   a visit that never upgraded at all is the opposite of it;
/// - the probe burst's own inference (`no_candidates` with nothing to
///   probe, otherwise section 7's `probe_timeout`/`hairpin_failure`/
///   `endpoint_dependent_mapping` rule) for a visit that was still
///   probing when it ended;
/// - `ok` for a visit that ended on a direct path.
///
/// Before this, a `--hold 5` run against a friend with nothing probeable
/// reported `path_idle_timeout` while the identical `--hold 0` run
/// reported `no_candidates`, because 5 seconds is under section 2 step
/// 5's 10 second give-up and nothing else had set a reason.
fn end_of_visit_reason(
    params: &DoorbellParams,
    give_up_reason: Option<Reason>,
    path: Option<&crate::path::PathEntry>,
    state: &Attempt,
    recorder: Option<&Recorder>,
    ever_upgraded: bool,
    relay_dead: bool,
) -> Reason {
    // What ended the visit outranks why it never upgraded. A relayed visit
    // whose relay went dead under section 4 ended because its path did,
    // and saying `probe_timeout` there reports a failure that happened ten
    // seconds into a ninety second visit as the cause of its death.
    if relay_dead {
        return Reason::PathIdleTimeout;
    }
    if params.no_punch {
        return Reason::PunchDisabled;
    }
    if let Some(reason) = give_up_reason {
        return reason;
    }
    if !ever_upgraded {
        // Still probing when the visit ended, or never able to: the same
        // inference the give-up branch makes, so the two agree whichever
        // of them the run reaches.
        if state.candidate_count() == 0 {
            return Reason::NoCandidates;
        }
        return recorder.map_or(Reason::ProbeTimeout, Recorder::probe_failure_reason);
    }
    match path {
        Some(path) if path.direct_addr().is_none() => Reason::PathIdleTimeout,
        _ => Reason::Ok,
    }
}

/// Section 2 step 1, run again for a rerun: what the caller offered for
/// the first attempt, plus every local address of this machine, the gate's
/// reflection of it, and anything discovery has heard, de-duplicated and
/// capped at [`MAX_CANDIDATES`].
///
/// **A union, not a replacement.** The new half is the point: WO-1.5 case
/// (f) is a local address change, and a list gathered before the change
/// cannot contain the address the machine now has. Keeping the old half
/// costs one 81 byte packet every 100 ms for at most 10 seconds against an
/// address that has stopped answering, and it keeps two things a fresh
/// gather cannot produce: an address the caller knew and this code does
/// not (a test's chosen candidate, a peer heard on a network this house
/// only learns about from its caller), and a loopback address, which
/// [`gather`] drops by design because offering one to a peer usually tells
/// it to probe itself.
///
/// The cost of the fresh half is two UDP sockets bound and `connect`ed for
/// a route lookup (see [`local_addresses`]), once per rerun, which is
/// nothing against the 10 second probe burst that follows it.
fn regather(
    gate: &crate::gate::client::GateClient,
    original: &[SocketAddr],
    discovered: &[SocketAddr],
) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = original.to_vec();
    out.truncate(MAX_CANDIDATES);
    let local = local_addresses(gate.local_port().unwrap_or_default());
    let reflections = [gate.registered_observed()];
    for (addr, _source) in gather(&local, &reflections, discovered) {
        if out.len() >= MAX_CANDIDATES {
            break;
        }
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// Closes a held visit: the shaper counters, the round trip percentiles
/// and the record, in that order, so every number the record carries was
/// read after the last thing that could change it.
fn finish_visit(
    recorder: Option<&Recorder>,
    rtt: &RttSamples,
    path: Option<&crate::path::PathEntry>,
    reason: Reason,
) {
    record_relay_counters(recorder, path);
    rtt.write_into(recorder);
    settle(recorder, reason);
}

/// What one attempt's candidate exchange (frame 16 each way) produced.
struct Exchanged {
    attempt: [u8; 16],
    peer_addrs: Vec<Addr>,
    peer_half: [u8; 32],
    /// The peer said it will not probe this attempt (`--no-punch` on its
    /// side), so this house does not either and neither side waits on a
    /// start signal nobody will ask for.
    peer_no_upgrade: bool,
}

/// Writes this house's own `Candidates` (frame 16).
async fn write_candidates(
    send: &mut quinn::SendStream,
    attempt: [u8; 16],
    candidates: &[SocketAddr],
    half: [u8; 32],
    no_upgrade: bool,
) -> Result<(), GateError> {
    write_porch_frame(
        send,
        &PorchFrame::Candidates {
            v: 1,
            attempt,
            addrs: candidates
                .iter()
                .copied()
                .map(Addr::from_socket_addr)
                .collect(),
            probe_half: half,
            no_upgrade,
        },
    )
    .await
}

/// Section 2 step 3: `Candidates` each way on the porch stream, inside the
/// sealed connection, so the gate sees candidate lists as ciphertext.
///
/// The initiator writes first and names the attempt; the responder reads,
/// adopts that id and answers, so one id names the attempt in both houses'
/// records without either having to agree on a draw.
async fn exchange_candidates(
    initiator: bool,
    send: &mut quinn::SendStream,
    frames: &std::sync::Arc<Mutex<VecDeque<Result<PorchFrame, GateError>>>>,
    candidates: &[SocketAddr],
    half: [u8; 32],
    no_upgrade: bool,
    deadline: Duration,
) -> Result<Exchanged, GateError> {
    if initiator {
        let mut attempt = [0u8; 16];
        rand::rng().fill(&mut attempt);
        write_candidates(send, attempt, candidates, half, no_upgrade).await?;
        let exchanged = expect_candidates(frames, deadline).await?;
        if exchanged.attempt != attempt {
            return Err(GateError::Protocol(
                "the responder's Candidates named a different attempt".into(),
            ));
        }
        Ok(exchanged)
    } else {
        let exchanged = expect_candidates(frames, deadline).await?;
        write_candidates(send, exchanged.attempt, candidates, half, no_upgrade).await?;
        Ok(exchanged)
    }
}

/// Holds an attempt's live state for as long as `run_doorbell` runs: the
/// probe key armed on the porch socket, and the session marked live on the
/// gate client. Both are released on drop, whichever way the function
/// leaves, including an error return.
struct AttemptGuard<'a> {
    porch: &'a std::sync::Arc<crate::sock::PorchSocket>,
    gate: &'a crate::gate::client::GateClient,
    attempt: [u8; 16],
    session: u32,
}

impl<'a> AttemptGuard<'a> {
    fn arm(
        porch: &'a std::sync::Arc<crate::sock::PorchSocket>,
        gate: &'a crate::gate::client::GateClient,
        attempt: [u8; 16],
        key: [u8; 32],
        session: u32,
    ) -> Self {
        porch.arm_probe_key(attempt, key);
        Self {
            porch,
            gate,
            attempt,
            session,
        }
    }
}

impl Drop for AttemptGuard<'_> {
    fn drop(&mut self) {
        self.porch.disarm_probe_key(&self.attempt);
        // The attempt is over, so its session entry is the first the client
        // evicts when it needs room (Konrad's new must): a house that has
        // finished with eight peers must not refuse the ninth.
        self.gate.attempt_finished(self.session);
    }
}

/// Waits for the peer's `Candidates` (frame 16) on the porch stream,
/// bounded by `deadline` (section 5: every read on the porch stream
/// carries one).
///
/// It takes the frame out of [`read_porch_frames`]'s queue rather than
/// reading the stream itself, because the stream has exactly one reader
/// for the life of a visit and this is not it.
async fn expect_candidates(
    frames: &std::sync::Arc<Mutex<VecDeque<Result<PorchFrame, GateError>>>>,
    deadline: Duration,
) -> Result<Exchanged, GateError> {
    let waiting = async {
        loop {
            let next = frames.lock_or_recover().pop_front();
            match next {
                Some(Ok(PorchFrame::Candidates {
                    attempt,
                    addrs,
                    probe_half,
                    no_upgrade,
                    ..
                })) => {
                    return Ok(Exchanged {
                        attempt,
                        peer_addrs: addrs,
                        peer_half: probe_half,
                        peer_no_upgrade: no_upgrade,
                    });
                }
                Some(Ok(other)) => {
                    return Err(GateError::Protocol(format!(
                        "expected Candidates as the first porch frame, got {other:?}"
                    )));
                }
                Some(Err(e)) => return Err(e),
                // Polled rather than woken: the queue is filled by a task
                // this one cannot be woken by without a second waker
                // beside the socket's, and this wait happens once per
                // attempt against a deadline measured in seconds.
                None => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
    };
    tokio::time::timeout(deadline, waiting)
        .await
        .map_err(|_| GateError::Timeout)?
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

    const KEY: [u8; 32] = [7u8; 32];
    const ID: [u8; 16] = [3u8; 16];

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 5)), port)
    }

    // ------------------------------------------------------------------
    // The probe packet (section 2)
    // ------------------------------------------------------------------

    #[test]
    fn a_probe_is_81_bytes_with_the_layout_section_2_states() {
        let probe = Probe {
            kind: PROBE_PING,
            attempt: ID,
            tx: [9u8; 8],
            observed: Addr::default(),
        };
        let bytes = probe.encode(&KEY);
        assert_eq!(bytes.len(), 81);
        assert_eq!(bytes[0], 0x2A);
        assert_eq!(&bytes[1..4], b"MSP");
        assert_eq!(bytes[4], 0x01);
        assert_eq!(bytes[5], PROBE_PING);
        assert_eq!(&bytes[6..22], &ID);
        assert_eq!(&bytes[22..30], &[9u8; 8]);
        assert_eq!(&bytes[30..49], &[0u8; 19]);
        assert_eq!(
            &bytes[49..81],
            blake3::keyed_hash(&KEY, &bytes[..49]).as_bytes()
        );
        // Section 3: the first byte has 0x80 and 0x40 both clear, so it is
        // no valid QUIC first byte under either header form.
        assert_eq!(bytes[0] & 0x80, 0);
        assert_eq!(bytes[0] & 0x40, 0);
        assert_eq!(Probe::decode(&bytes, &KEY), Some(probe));
        assert!(is_probe(&bytes));
    }

    /// A probe authenticated under a different key, or with any byte of it
    /// altered, is not a probe at all.
    ///
    /// Deliberate break to fail this test: in `Probe::decode`, delete the
    /// `if expected != blake3::Hash::from(got) { return None; }` check. A
    /// probe under the wrong key then decodes, and a forged pong could
    /// drive an upgrade to an address the peer never offered.
    #[test]
    fn a_probe_under_the_wrong_key_or_with_a_flipped_bit_is_rejected() {
        let probe = Probe {
            kind: PROBE_PONG,
            attempt: ID,
            tx: [1u8; 8],
            observed: Addr::from_socket_addr(addr(4433)),
        };
        let bytes = probe.encode(&KEY);
        assert_eq!(Probe::decode(&bytes, &[8u8; 32]), None);
        for index in [0usize, 4, 5, 6, 22, 30, 49, 80] {
            let mut tampered = bytes;
            tampered[index] ^= 0x01;
            assert_eq!(
                Probe::decode(&tampered, &KEY),
                None,
                "byte {index} must be covered"
            );
        }
        assert_eq!(Probe::decode(&bytes[..80], &KEY), None);
        assert_eq!(Probe::decode(&[], &KEY), None);
        assert!(!is_probe(&bytes[..80]));
    }

    #[test]
    fn probe_key_is_order_sensitive_and_derived_from_all_four_inputs() {
        let base = probe_key(&ID, &[1u8; 32], &[2u8; 32]);
        assert_ne!(base, probe_key(&ID, &[2u8; 32], &[1u8; 32]));
        assert_ne!(base, probe_key(&[4u8; 16], &[1u8; 32], &[2u8; 32]));
        assert_eq!(base, probe_key(&ID, &[1u8; 32], &[2u8; 32]));
    }

    // ------------------------------------------------------------------
    // Porch stream frames 16 to 19 (section 1)
    // ------------------------------------------------------------------

    #[test]
    fn every_porch_frame_round_trips() {
        let frames = [
            PorchFrame::Candidates {
                v: 1,
                attempt: ID,
                addrs: vec![
                    Addr::from_socket_addr(addr(4433)),
                    Addr::from_socket_addr("[2001:db8::5]:4433".parse().unwrap()),
                ],
                probe_half: [5u8; 32],
                no_upgrade: false,
            },
            // The same frame carrying the intent of `--no-punch` (design
            // amendment 4), which a peer reads before it waits on a start
            // signal nobody will ask for.
            PorchFrame::Candidates {
                v: 1,
                attempt: ID,
                addrs: Vec::new(),
                probe_half: [6u8; 32],
                no_upgrade: true,
            },
            PorchFrame::PathUp {
                v: 1,
                attempt: ID,
                addr: Addr::from_socket_addr(addr(4433)),
                rtt_us: 1234,
            },
            PorchFrame::PathDown {
                v: 1,
                attempt: ID,
                addr: Addr::from_socket_addr(addr(4433)),
                reason: 16,
            },
            PorchFrame::Goodbye { v: 1, reason: 0 },
        ];
        for frame in frames {
            let encoded = frame.to_cbor();
            assert_eq!(PorchFrame::from_cbor(&encoded).unwrap(), frame);
        }
    }

    /// Invariant 4: a cap is checked before anything is allocated against
    /// it. A `Candidates` frame claiming 17 addresses is refused on the
    /// declared count, without building a `Vec` for it.
    #[test]
    fn a_candidates_frame_past_its_cap_is_refused_on_the_declared_count() {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.array(6).unwrap();
        enc.u8(16).unwrap();
        enc.u8(1).unwrap();
        enc.bytes(&ID).unwrap();
        enc.array(MAX_CANDIDATES as u64 + 1).unwrap();
        assert!(PorchFrame::from_cbor(&buf).is_err());
    }

    #[test]
    fn a_malformed_porch_frame_is_an_error_not_a_panic() {
        for bytes in [
            vec![],
            vec![0x00],
            vec![0x9f],
            PorchFrame::Goodbye { v: 1, reason: 0 }.to_cbor()[..1].to_vec(),
        ] {
            assert!(PorchFrame::from_cbor(&bytes).is_err());
        }
        let mut goodbye = PorchFrame::Goodbye { v: 1, reason: 0 }.to_cbor();
        goodbye[1] = 99;
        assert!(PorchFrame::from_cbor(&goodbye).is_err());
    }

    // ------------------------------------------------------------------
    // Gathering (section 2 step 1)
    // ------------------------------------------------------------------

    #[test]
    fn gather_dedupes_drops_the_unprobeable_and_caps_at_sixteen() {
        let local: Vec<SocketAddr> = (0..20).map(|i| addr(5000 + i)).collect();
        let gathered = gather(&local, &[addr(5000)], &[]);
        assert_eq!(gathered.len(), MAX_CANDIDATES);
        assert!(gathered.iter().all(|(_, s)| *s == CandidateSource::Local));

        let gathered = gather(
            &["127.0.0.1:4433".parse().unwrap(), addr(0), addr(4433)],
            &[addr(4433), "[2001:db8::1]:4433".parse().unwrap()],
            &["[fd00::9]:1".parse().unwrap()],
        );
        assert_eq!(
            gathered,
            vec![
                (addr(4433), CandidateSource::Local),
                (
                    "[2001:db8::1]:4433".parse().unwrap(),
                    CandidateSource::GateReflected
                ),
            ],
            "loopback, port 0, a duplicate and a synthetic address are all dropped"
        );
    }

    #[test]
    fn local_addresses_are_real_host_addresses_of_both_families_or_none() {
        for candidate in local_addresses(4433) {
            assert!(is_gatherable(candidate));
            assert_eq!(candidate.port(), 4433);
        }
    }

    // ------------------------------------------------------------------
    // The probe schedule and the upgrade rule (section 2 steps 4 to 7)
    // ------------------------------------------------------------------

    fn tx_counter() -> impl FnMut() -> [u8; 8] {
        let mut n = 0u64;
        move || {
            n += 1;
            n.to_be_bytes()
        }
    }

    /// Section 2 step 4: nothing is sent before `Start` arrives, and then
    /// the first probes fire exactly `FIRE_IN_MS` later, not on receipt.
    #[test]
    fn nothing_fires_before_the_start_signal_plus_fire_in_ms() {
        let mut attempt = Attempt::new(ID, KEY, None);
        let mut tx = tx_counter();
        assert!(attempt.add_candidate(addr(4433), CandidateSource::Local));
        let t0 = Instant::now();
        assert!(attempt.due_probes(t0, &mut tx).is_empty());

        attempt.start_signal_received(t0);
        assert!(
            attempt
                .due_probes(t0 + Duration::from_millis(199), &mut tx)
                .is_empty()
        );
        assert_eq!(
            attempt
                .due_probes(t0 + Duration::from_millis(200), &mut tx)
                .len(),
            1
        );
    }

    /// Section 2 step 5's schedule: every 100 ms for 3 seconds, then every
    /// 1 second for 7 more, then the candidate is given up.
    ///
    /// Deliberate break to fail this test: change `PROBE_FAST_WINDOW` to
    /// `Duration::from_secs(10)`. The probe at fire + 3.1 s then fires
    /// again at 3.2 s instead of waiting until 4.1 s, and the assertion on
    /// the slow phase fails.
    #[test]
    fn the_probe_schedule_is_fast_for_three_seconds_then_slow_then_given_up() {
        let mut attempt = Attempt::new(ID, KEY, None);
        let mut tx = tx_counter();
        attempt.add_candidate(addr(4433), CandidateSource::Local);
        let t0 = Instant::now();
        attempt.start_signal_received(t0);
        let fire = t0 + Duration::from_millis(u64::from(FIRE_IN_MS));

        assert_eq!(attempt.due_probes(fire, &mut tx).len(), 1);
        assert!(
            attempt
                .due_probes(fire + Duration::from_millis(99), &mut tx)
                .is_empty()
        );
        assert_eq!(
            attempt
                .due_probes(fire + Duration::from_millis(100), &mut tx)
                .len(),
            1
        );

        // Into the slow phase: 100 ms is no longer enough.
        let slow = fire + Duration::from_millis(3100);
        assert_eq!(attempt.due_probes(slow, &mut tx).len(), 1);
        assert!(
            attempt
                .due_probes(slow + Duration::from_millis(999), &mut tx)
                .is_empty()
        );
        assert_eq!(
            attempt
                .due_probes(slow + Duration::from_secs(1), &mut tx)
                .len(),
            1
        );

        assert!(!attempt.given_up(fire + PROBE_GIVE_UP - Duration::from_millis(1)));
        assert!(attempt.due_probes(fire + PROBE_GIVE_UP, &mut tx).is_empty());
        assert!(attempt.given_up(fire + PROBE_GIVE_UP));
    }

    /// Section 2 step 6: three consecutive answers win, and a probe sent
    /// while an earlier one is still unanswered resets the streak, which is
    /// what "consecutive" means.
    ///
    /// Deliberate break to fail this test: in `Attempt::due_probes`, delete
    /// the `candidate.consecutive = 0;` line in the outstanding-probe
    /// branch. The two answers either side of the lost probe then count
    /// together and the candidate wins on a path that dropped a probe.
    #[test]
    fn three_consecutive_answers_win_and_a_lost_probe_resets_the_streak() {
        let mut attempt = Attempt::new(ID, KEY, None);
        let mut tx = tx_counter();
        let candidate = addr(4433);
        attempt.add_candidate(candidate, CandidateSource::PeerReported);
        let t0 = Instant::now();
        attempt.start_signal_received(t0);
        let mut now = t0 + Duration::from_millis(u64::from(FIRE_IN_MS));

        // Two answers, then a probe that is never answered, which resets.
        for _ in 0..2 {
            let sent = attempt.due_probes(now, &mut tx);
            let probe = Probe::decode(&sent[0].1, &KEY).unwrap();
            now += Duration::from_millis(5);
            assert!(answer(&mut attempt, candidate, &probe, now).is_none());
            now += Duration::from_millis(95);
        }
        let _lost = attempt.due_probes(now, &mut tx);
        now += Duration::from_millis(100);

        // Three answers in a row from here, and the third wins.
        let mut winner = None;
        for round in 0..3 {
            let sent = attempt.due_probes(now, &mut tx);
            assert_eq!(sent.len(), 1, "round {round} must send one probe");
            let probe = Probe::decode(&sent[0].1, &KEY).unwrap();
            now += Duration::from_millis(5);
            winner = answer(&mut attempt, candidate, &probe, now);
            now += Duration::from_millis(95);
        }
        let winner = winner.expect("three consecutive answers must win");
        assert_eq!(winner.addr, candidate);
        assert_eq!(winner.rtt, Duration::from_millis(5));
        assert_eq!(attempt.winner(), Some(winner));
        assert!(!attempt.given_up(now + PROBE_GIVE_UP));
        assert!(
            attempt.due_probes(now, &mut tx).is_empty(),
            "a decided attempt stops probing"
        );
    }

    /// Answers `ping` from `from` the way the peer would, through the real
    /// pong builder and the real decode, and feeds it back in.
    fn answer(
        attempt: &mut Attempt,
        from: SocketAddr,
        ping: &Probe,
        now: Instant,
    ) -> Option<Winner> {
        let pong_bytes = attempt.pong_for(ping, from);
        let pong = Probe::decode(&pong_bytes, &KEY).unwrap();
        assert_eq!(pong.kind, PROBE_PONG);
        assert_eq!(pong.tx, ping.tx);
        assert_eq!(pong.observed.to_socket_addr(), Some(from));
        attempt.on_pong(from, &pong, now);
        attempt.decide()
    }

    /// Section 2 step 6's tie-break: when two candidates stand at three in
    /// the same probe round, the lowest round trip of the three wins, even
    /// though the slower one's pong was read off the socket first.
    ///
    /// Deliberate break to fail this test: in `Attempt::decide`, replace
    /// the `min_by(...)` with `next()` on the same filtered iterator, so
    /// the first candidate at three wins rather than the fastest. The slow
    /// candidate, which is first in the table, then takes the path.
    #[test]
    fn a_tie_at_three_is_broken_by_the_lowest_round_trip() {
        let mut attempt = Attempt::new(ID, KEY, None);
        let mut tx = tx_counter();
        let slow = addr(4433);
        let fast = addr(4434);
        attempt.add_candidate(slow, CandidateSource::Local);
        attempt.add_candidate(fast, CandidateSource::GateReflected);
        let t0 = Instant::now();
        attempt.start_signal_received(t0);
        let mut now = t0 + Duration::from_millis(u64::from(FIRE_IN_MS));

        let mut winner = None;
        for round in 0..3 {
            let sent = attempt.due_probes(now, &mut tx);
            assert_eq!(sent.len(), 2, "round {round} probes both candidates");
            let slow_probe = Probe::decode(&sent[0].1, &KEY).unwrap();
            let fast_probe = Probe::decode(&sent[1].1, &KEY).unwrap();
            // Both answers belong to this round; the slow one is dequeued
            // first, so only the tie-break can pick the right winner.
            assert!(attempt.on_pong(
                slow,
                &decode_pong(&attempt, &slow_probe, slow),
                now + Duration::from_millis(20),
            ));
            assert!(attempt.on_pong(
                fast,
                &decode_pong(&attempt, &fast_probe, fast),
                now + Duration::from_millis(2),
            ));
            winner = attempt.decide().or(winner);
            now += Duration::from_millis(100);
        }
        let winner = winner.expect("both candidates answered three in a row");
        assert_eq!(winner.addr, fast);
        assert_eq!(winner.rtt, Duration::from_millis(2));
    }

    fn decode_pong(attempt: &Attempt, ping: &Probe, from: SocketAddr) -> Probe {
        Probe::decode(&attempt.pong_for(ping, from), &KEY).unwrap()
    }

    /// A symmetric NAT rewrites the source port of every packet per
    /// destination, so the peer's pongs never come back from the address it
    /// was probed at. Nothing can prove itself, and section 2 step 5's
    /// deadline passes with the peer still on the relay.
    ///
    /// The rewrite is the whole simulation: `nat_rewrite` stands in for the
    /// address-rewriting socket, mapping every reply's source to a port the
    /// candidate table never heard of.
    ///
    /// Deliberate break to fail this test: in `Attempt::on_pong`, change
    /// `if candidate.addr != from` to `if false`, so any source address
    /// credits the first candidate. The attempt then upgrades to a path
    /// that does not exist.
    #[test]
    fn a_symmetric_nat_forces_the_relay_inside_the_probe_deadline() {
        let mut attempt = Attempt::new(ID, KEY, None);
        let mut tx = tx_counter();
        for port in 0..4u16 {
            attempt.add_candidate(addr(4433 + port), CandidateSource::PeerReported);
        }
        let t0 = Instant::now();
        attempt.start_signal_received(t0);
        let fire = t0 + Duration::from_millis(u64::from(FIRE_IN_MS));
        let nat_rewrite =
            |sent_to: SocketAddr| SocketAddr::new(sent_to.ip(), sent_to.port() + 1000);

        let mut now = fire;
        let mut sent_total = 0usize;
        while now < fire + PROBE_GIVE_UP {
            for (to, bytes) in attempt.due_probes(now, &mut tx) {
                sent_total += 1;
                let ping = Probe::decode(&bytes, &KEY).unwrap();
                let observed = nat_rewrite(to);
                let pong = decode_pong(&attempt, &ping, observed);
                assert!(
                    !attempt.on_pong(observed, &pong, now + Duration::from_millis(5)),
                    "a pong from a rewritten source proves nothing"
                );
            }
            assert_eq!(attempt.decide(), None);
            now += Duration::from_millis(50);
        }
        assert!(sent_total > 0, "the burst must actually have run");
        assert_eq!(attempt.winner(), None);
        assert!(attempt.given_up(fire + PROBE_GIVE_UP));

        // The path table is what carries the consequence: still relayed,
        // and never switched, so the connection has been riding the relay
        // from its first packet without interruption.
        let mut table = crate::path::PathTable::new();
        let entry = table.insert_relay([1u8; 32], "[fd00::1]:1".parse().unwrap());
        assert_eq!(entry.kind(), crate::path::PathKind::Relay);
        assert_eq!(entry.epoch().load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn a_failed_path_clears_the_winner_so_a_fresh_attempt_reruns_everything() {
        let mut attempt = Attempt::new(ID, KEY, None);
        let mut tx = tx_counter();
        let candidate = addr(4433);
        attempt.add_candidate(candidate, CandidateSource::Local);
        let t0 = Instant::now();
        attempt.start_signal_received(t0);
        let mut now = t0 + Duration::from_millis(u64::from(FIRE_IN_MS));
        for _ in 0..3 {
            let sent = attempt.due_probes(now, &mut tx);
            let probe = Probe::decode(&sent[0].1, &KEY).unwrap();
            now += Duration::from_millis(5);
            answer(&mut attempt, candidate, &probe, now);
            now += Duration::from_millis(95);
        }
        assert!(attempt.winner().is_some());
        assert_eq!(attempt.path_failed().map(|w| w.addr), Some(candidate));
        assert_eq!(attempt.winner(), None);
        assert_eq!(attempt.path_failed(), None);
    }

    #[test]
    fn the_candidate_table_caps_at_sixteen_and_refuses_duplicates() {
        let mut attempt = Attempt::new(ID, KEY, None);
        for port in 0..MAX_CANDIDATES as u16 {
            assert!(attempt.add_candidate(addr(4433 + port), CandidateSource::Local));
        }
        assert!(!attempt.add_candidate(addr(4433), CandidateSource::Local));
        assert!(!attempt.add_candidate(addr(9999), CandidateSource::Local));
        assert_eq!(attempt.candidate_count(), MAX_CANDIDATES);
        assert_eq!(attempt.source_of(addr(4433)), Some(CandidateSource::Local));
        assert_eq!(attempt.source_of(addr(9999)), None);
    }

    /// Yseult's Medium: a peer may not aim this house's probe burst at
    /// this house's own machine or its LAN. What it may name is what the
    /// internet could have routed here, plus exactly the address the gate
    /// observed it at for this attempt, which the gate vouches for and the
    /// peer does not.
    ///
    /// Deliberate break to fail this test: in `Attempt::add_candidate`,
    /// delete the `source == CandidateSource::PeerReported && ...` block.
    /// The loopback, link-local, RFC1918 and ULA addresses are then all
    /// accepted from the peer.
    #[test]
    fn a_peer_may_not_name_a_loopback_link_local_or_private_candidate() {
        let reflected: SocketAddr = "192.168.7.7:4433".parse().unwrap();
        let mut attempt = Attempt::new(ID, KEY, Some(reflected));
        for refused in [
            "127.0.0.1:631",
            "169.254.1.1:4433",
            "192.168.1.1:53",
            "10.0.0.1:4433",
            "172.16.0.1:4433",
            "[::1]:4433",
            "[fe80::1]:4433",
            "[fd00::1]:4433",
        ] {
            let addr: SocketAddr = refused.parse().unwrap();
            assert!(
                !attempt.add_candidate(addr, CandidateSource::PeerReported),
                "{refused} must be refused from a peer"
            );
        }
        // The gate's own reflection of this peer for this attempt is the
        // exception, which is the same-LAN case section 6 exists for.
        assert!(attempt.add_candidate(reflected, CandidateSource::PeerReported));
        // A globally routable address the peer names is fine.
        assert!(attempt.add_candidate(addr(4433), CandidateSource::PeerReported));
        // And this house's own gathering is trusted, because this house
        // found it rather than being told it.
        assert!(
            attempt.add_candidate("192.168.1.50:4433".parse().unwrap(), CandidateSource::Local)
        );
        assert!(attempt.add_candidate(
            "[fd00::9]:4433".parse().unwrap(),
            CandidateSource::Discovery
        ));
        assert_eq!(attempt.candidate_count(), 4);

        // With no gate reflection to vouch for anything, a peer gets only
        // globally routable addresses.
        let mut bare = Attempt::new(ID, KEY, None);
        assert!(!bare.add_candidate(reflected, CandidateSource::PeerReported));
    }

    /// Issue #37, the relaxation and its limit in one test. A private-range
    /// LAN address is admissible from a peer's `Candidates` frame when, and
    /// only when, this house itself heard that peer announce from it on
    /// this network for this attempt (section 6) or the gate reflected it
    /// for this attempt. The same address named by a peer this house has
    /// discovered nothing about is still refused.
    ///
    /// Deliberate break to fail this test: in `Attempt::add_discovered`,
    /// delete the `self.vouch(addr)` line, keeping the `add_candidate`
    /// call. The discovered address is still a candidate,
    /// so the first half passes, and the peer's own naming of it is refused
    /// again, so the second assertion fails.
    #[test]
    fn a_discovered_lan_address_is_vouched_for_and_an_undiscovered_one_is_not() {
        let announced: SocketAddr = "192.168.4.21:4433".parse().unwrap();
        let unheard: SocketAddr = "192.168.4.99:4433".parse().unwrap();

        let mut attempt = Attempt::new(ID, KEY, None);
        assert!(attempt.add_discovered(announced));
        assert_eq!(
            attempt.source_of(announced),
            Some(CandidateSource::Discovery),
            "a discovered address is a discovery-sourced candidate, never a peer-reported one"
        );

        // The peer naming the same address adds nothing new (it is already
        // a candidate) but is not refused for being private: discovery
        // vouched for it.
        assert!(
            attempt.vouched_for(announced),
            "hearing the announce is what vouches for the address"
        );
        assert_eq!(
            attempt.add_peer_candidates(&[Addr::from_socket_addr(announced)]),
            0,
            "already a candidate, so the peer naming it adds nothing"
        );
        // A duplicate, not a rejection: on a fresh attempt with the same
        // vouching, the peer's own naming of it is accepted outright.
        let mut fresh = Attempt::new(ID, KEY, None);
        fresh.vouch(announced);
        assert_eq!(
            fresh.add_peer_candidates(&[Addr::from_socket_addr(announced)]),
            1,
            "a vouched private address is admissible from the peer's list"
        );
        assert_eq!(
            fresh.source_of(announced),
            Some(CandidateSource::PeerReported)
        );

        // Nothing vouched for this one, so it is refused exactly as before.
        assert_eq!(
            fresh.add_peer_candidates(&[Addr::from_socket_addr(unheard)]),
            0,
            "an undiscovered private address is still refused from a peer"
        );

        // And link-local and IPv4-mapped LAN forms travel the same road:
        // vouched, admissible; unvouched, refused.
        let link_local: SocketAddr = "169.254.7.7:4433".parse().unwrap();
        let mut mapped = Attempt::new(ID, KEY, None);
        assert_eq!(
            mapped.add_peer_candidates(&[Addr::from_socket_addr(link_local)]),
            0
        );
        assert!(mapped.add_discovered("[::ffff:169.254.7.7]:4433".parse().unwrap()));
        assert!(
            mapped.vouched_for(link_local),
            "the mapped spelling vouches for the IPv4 form and no other"
        );
        assert_eq!(
            mapped.source_of(link_local),
            Some(CandidateSource::Discovery),
            "vouched and stored in its IPv4 form, so one address has one verdict"
        );
    }

    /// Wystan's D3: the nearest-rank percentiles the record reports, over
    /// vectors small enough to check by hand.
    ///
    /// The contract, in one place: nearest rank (`ceil(p * n)`) over the
    /// samples this visit took, so every number reported is a round trip
    /// that was actually measured and never an interpolation between two;
    /// on an even count the median is the lower of the two middle
    /// samples; and no sample is taken before the first full
    /// [`RTT_SAMPLE_INTERVAL`], so the handshake's own estimate is never
    /// one of them.
    ///
    /// Deliberate break to fail this test: use `floor` instead of `ceil`
    /// in `percentiles`, or drop the `.max(1)` clamp. The p95 of ten
    /// samples then reads 900 or the median of one sample panics on an
    /// empty index.
    #[test]
    fn the_percentiles_are_nearest_rank_over_the_samples_actually_taken() {
        let start = Instant::now();
        let take = |values: &[u64]| {
            let mut samples = RttSamples::new(start);
            for (i, us) in values.iter().enumerate() {
                let at = start + RTT_SAMPLE_INTERVAL * (u32::try_from(i).unwrap_or(0) + 1);
                samples.observe_probe(Duration::from_micros(*us));
                samples.tick(at, Duration::from_micros(9_999));
            }
            samples.percentiles()
        };

        // n = 0: nothing measured, nothing claimed.
        assert_eq!(RttSamples::new(start).percentiles(), (0, 0, 0));
        // n = 1: the one sample is both the median and the p95.
        assert_eq!(take(&[400]), (400, 400, 1));
        // n = 2: ceil(0.5 * 2) = 1, so the median is the lower of the two;
        // ceil(0.95 * 2) = 2, so the p95 is the higher.
        assert_eq!(take(&[400, 800]), (400, 800, 2));
        // n = 3, odd: ceil(1.5) = 2, the middle one.
        assert_eq!(take(&[300, 400, 500]), (400, 500, 3));
        // n = 4, even: ceil(2) = 2, the lower middle.
        assert_eq!(take(&[100, 200, 300, 400]), (200, 400, 4));
        // n = 10: ceil(5) = 5 and ceil(9.5) = 10, and the input is
        // deliberately out of order to prove the sort.
        assert_eq!(
            take(&[1000, 100, 900, 200, 800, 300, 700, 400, 600, 500]),
            (500, 1000, 10)
        );

        // The first interval is not sampled: a tick before it takes
        // nothing, so a relayed visit never reports the handshake's own
        // estimate as a round trip.
        let mut early = RttSamples::new(start);
        early.observe_probe(Duration::from_micros(400));
        early.tick(start + Duration::from_millis(999), Duration::from_micros(1));
        assert_eq!(early.percentiles(), (0, 0, 0));
        early.tick(start + RTT_SAMPLE_INTERVAL, Duration::from_micros(1));
        assert_eq!(early.percentiles(), (400, 400, 1));
    }

    /// A relayed visit's samples come from the end to end connection and
    /// say so; a visit that changed path says `mixed`.
    #[test]
    fn the_rtt_source_says_what_the_samples_measured() {
        let start = Instant::now();
        let mut relayed = RttSamples::new(start);
        relayed.tick(start + RTT_SAMPLE_INTERVAL, Duration::from_micros(5_000));
        assert_eq!(relayed.source, diag::RttSource::Quic);
        relayed.observe_probe(Duration::from_micros(400));
        relayed.tick(
            start + RTT_SAMPLE_INTERVAL * 2,
            Duration::from_micros(5_000),
        );
        assert_eq!(relayed.source, diag::RttSource::Mixed);
        assert_eq!(relayed.percentiles(), (400, 5_000, 2));
    }

    /// Wystan's D1: the reason a held visit ends with describes what
    /// happened, not which of the hold and the probe give-up ran out
    /// first.
    ///
    /// Deliberate break to fail this test: delete the `if !ever_upgraded`
    /// arm from `end_of_visit_reason`. A visit that never had a direct
    /// path then reports `path_idle_timeout`, whose own doc says it means
    /// a path that was had and lost, which is what a `--hold 5` run
    /// against a friend with nothing probeable used to say.
    #[test]
    fn the_end_of_visit_reason_never_calls_an_unprobed_visit_an_idle_path() {
        let params = |no_punch: bool| DoorbellParams {
            session: 1,
            role: 1,
            peer_key: [4u8; 32],
            candidates: Vec::new(),
            peer_observed: None,
            peer_discovered: Vec::new(),
            hold: Hold::For(Duration::from_secs(5)),
            no_punch,
            events: None,
            recorder: None,
        };
        let empty = Attempt::new(ID, KEY, None);
        let mut probed = Attempt::new(ID, KEY, None);
        assert!(probed.add_candidate(addr(4433), CandidateSource::PeerReported));
        let relayed = crate::path::PathEntry::new_relay();
        let direct = crate::path::PathEntry::new_relay();
        direct.upgrade_to(addr(4433));

        // Never upgraded, nothing to probe: the same answer the give-up
        // branch gives, whichever of them the hold beat.
        assert_eq!(
            end_of_visit_reason(
                &params(false),
                None,
                Some(&relayed),
                &empty,
                None,
                false,
                false
            ),
            Reason::NoCandidates
        );
        // Never upgraded, candidates that never answered.
        assert_eq!(
            end_of_visit_reason(
                &params(false),
                None,
                Some(&relayed),
                &probed,
                None,
                false,
                false
            ),
            Reason::ProbeTimeout
        );
        // Upgraded and lost: this is what `path_idle_timeout` means.
        assert_eq!(
            end_of_visit_reason(
                &params(false),
                None,
                Some(&relayed),
                &probed,
                None,
                true,
                false
            ),
            Reason::PathIdleTimeout
        );
        // Upgraded and still there.
        assert_eq!(
            end_of_visit_reason(
                &params(false),
                None,
                Some(&direct),
                &probed,
                None,
                true,
                false
            ),
            Reason::Ok
        );
        // Told not to punch, whatever else happened.
        assert_eq!(
            end_of_visit_reason(
                &params(true),
                None,
                Some(&relayed),
                &empty,
                None,
                false,
                false
            ),
            Reason::PunchDisabled
        );
        // A reason a give-up already named wins over the inference.
        assert_eq!(
            end_of_visit_reason(
                &params(false),
                Some(Reason::HairpinFailure),
                Some(&relayed),
                &probed,
                None,
                false,
                false
            ),
            Reason::HairpinFailure
        );
        // A relay that died under section 4 outranks every one of them:
        // what ended the visit is not what it failed to upgrade to.
        //
        // Deliberate break to fail this: move the `if relay_dead` early
        // return in `end_of_visit_reason` below the `give_up_reason`
        // branch. The last two assertions then read back `punch_disabled`
        // and `hairpin_failure`, which is exactly the run 3 record that
        // reported `probe_timeout` for a visit killed by a blackout.
        assert_eq!(
            end_of_visit_reason(
                &params(false),
                None,
                Some(&relayed),
                &probed,
                None,
                false,
                true
            ),
            Reason::PathIdleTimeout
        );
        assert_eq!(
            end_of_visit_reason(
                &params(true),
                None,
                Some(&relayed),
                &empty,
                None,
                false,
                true
            ),
            Reason::PathIdleTimeout
        );
        assert_eq!(
            end_of_visit_reason(
                &params(false),
                Some(Reason::HairpinFailure),
                Some(&relayed),
                &probed,
                None,
                false,
                true
            ),
            Reason::PathIdleTimeout
        );
    }

    /// Yseult's High 2: discovery gets its own bounded slot count and
    /// never takes a slot from a peer-listed or gate-reflected candidate.
    /// With the replay window of section 6 in place a LAN stranger cannot
    /// resend one announce at all, and even if it could, 16 discovered
    /// addresses cannot crowd the attempt: 4 get in and the peer's real
    /// candidates are all still there.
    ///
    /// Deliberate break to fail this test: in `Attempt::add_discovered`,
    /// delete the `if self.discovery_candidates >= DISCOVERY_CANDIDATE_SLOTS`
    /// early return. Discovery then takes every remaining slot and the
    /// peer's candidates that follow are refused, so the count assertions
    /// fail.
    #[test]
    fn discovery_cannot_crowd_out_the_peers_own_candidates() {
        let reflected: SocketAddr = "192.168.7.7:4433".parse().unwrap();
        let mut attempt = Attempt::new(ID, KEY, Some(reflected));

        // The peer's list and the gate's reflection go in first, as
        // `run_doorbell` orders them: 5 globally routable addresses plus
        // the reflected one.
        let peer_named: Vec<Addr> = (0..5)
            .map(|index| {
                Addr::from_socket_addr(SocketAddr::new(
                    IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 5)),
                    4433 + index,
                ))
            })
            .chain(std::iter::once(Addr::from_socket_addr(reflected)))
            .collect();
        assert_eq!(attempt.add_peer_candidates(&peer_named), 6);

        // Then 16 discovered addresses, which is what a flood would look
        // like if it got past section 6 at all.
        let mut discovered_in = 0;
        for index in 0..16u16 {
            let addr = SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 4, 21)),
                5000 + index,
            );
            if attempt.add_discovered(addr) {
                discovered_in += 1;
            }
        }
        assert_eq!(
            discovered_in, DISCOVERY_CANDIDATE_SLOTS,
            "discovery fills its own slots and stops"
        );
        assert_eq!(attempt.candidate_count(), 6 + DISCOVERY_CANDIDATE_SLOTS);

        // Every real candidate is still in the table, which is the thing
        // the cap protects: without it the pair stays on the relay.
        for addr in &peer_named {
            let addr = addr.to_socket_addr().unwrap();
            assert!(
                attempt.source_of(addr).is_some(),
                "{addr} must still be a candidate"
            );
        }
        assert_eq!(
            attempt.source_of(reflected),
            Some(CandidateSource::PeerReported)
        );
        // And a discovery past the cap still vouches, since hearing a peer
        // at an address is a fact about this network either way.
        let past_cap: SocketAddr = "192.168.4.21:5015".parse().unwrap();
        assert!(attempt.vouched_for(past_cap));
        assert_eq!(attempt.source_of(past_cap), None);
    }

    /// The other direction of issue #37, and the invariant the relaxation
    /// rests on: nothing arriving in a peer's `Candidates` frame can enter
    /// the table as anything but [`CandidateSource::PeerReported`], so a
    /// peer cannot vouch for its own private-range address by claiming it
    /// was discovered.
    ///
    /// Deliberate break to fail this test: in
    /// `Attempt::add_peer_candidates`, change `CandidateSource::PeerReported`
    /// to `CandidateSource::Discovery`. Every refused address is then
    /// accepted and the count assertion fails on the first line.
    #[test]
    fn a_peer_candidate_list_can_only_produce_peer_reported_candidates() {
        let mut attempt = Attempt::new(ID, KEY, None);
        let named: Vec<Addr> = [
            "127.0.0.1:631",
            "192.168.1.1:53",
            "[fd00::1]:4433",
            "[::ffff:10.0.0.1]:53",
        ]
        .iter()
        .map(|a| Addr::from_socket_addr(a.parse().unwrap()))
        .collect();
        assert_eq!(
            attempt.add_peer_candidates(&named),
            0,
            "a peer's list vouches for nothing"
        );
        assert_eq!(attempt.candidate_count(), 0);

        // A globally routable one from the same list is accepted, and as
        // peer-reported.
        assert_eq!(
            attempt.add_peer_candidates(&[Addr::from_socket_addr(addr(4433))]),
            1
        );
        assert_eq!(
            attempt.source_of(addr(4433)),
            Some(CandidateSource::PeerReported)
        );
    }

    /// Yseult's remaining Medium: one address, two spellings, one verdict.
    /// `Addr` family 6 decodes `::ffff:a.b.c.d` unchanged and no V6
    /// predicate matches that form, so the mapped spellings of loopback and
    /// of RFC1918 slipped past a rule that refused their IPv4 forms, and a
    /// dual-stack porch socket sends a V6 destination through untouched.
    ///
    /// Deliberate break to fail this test: in `Attempt::add_candidate`,
    /// delete the `let addr = crate::sock::unmap_v4(addr);` line.
    /// `[::ffff:127.0.0.1]:631` and `[::ffff:10.0.0.1]:53` are then both
    /// accepted from a peer.
    #[test]
    fn an_ipv4_mapped_candidate_is_classified_as_its_ipv4_form() {
        let mut attempt = Attempt::new(ID, KEY, None);
        for refused in [
            "[::ffff:127.0.0.1]:631",
            "[::ffff:10.0.0.1]:53",
            "[::ffff:192.168.1.1]:53",
            "[::ffff:169.254.1.1]:4433",
        ] {
            let addr: SocketAddr = refused.parse().unwrap();
            assert!(
                !attempt.add_candidate(addr, CandidateSource::PeerReported),
                "{refused} must be refused exactly as its IPv4 form is"
            );
        }
        // A mapped globally routable address is still fine, and is stored
        // unmapped so it compares equal to the pong source the porch socket
        // reports, which is unmapped for the same reason.
        let mapped: SocketAddr = "[::ffff:203.0.113.5]:4433".parse().unwrap();
        assert!(attempt.add_candidate(mapped, CandidateSource::PeerReported));
        assert_eq!(
            attempt.source_of(addr(4433)),
            Some(CandidateSource::PeerReported),
            "stored in its IPv4 form"
        );
        // And the mapped spelling of an address already held is a duplicate.
        assert!(!attempt.add_candidate(mapped, CandidateSource::PeerReported));
        assert_eq!(attempt.candidate_count(), 1);

        // The gate-reflection exception works through the mapped spelling
        // too, since both sides are unmapped before they are compared.
        let reflected: SocketAddr = "192.168.7.7:4433".parse().unwrap();
        let mut vouched = Attempt::new(ID, KEY, Some(reflected));
        assert!(vouched.add_candidate(
            "[::ffff:192.168.7.7]:4433".parse().unwrap(),
            CandidateSource::PeerReported
        ));
    }

    /// Yseult's Medium: a captured ping replays for the life of an
    /// attempt from any spoofed source, so answering is capped and each tx
    /// id is answered once.
    ///
    /// Deliberate break to fail this test: in `PongLimiter::may_answer`,
    /// change `if !self.seen.insert(tx)` to `self.seen.insert(tx);` with no
    /// early return. The replayed tx id is then answered every time and the
    /// first assertion fails.
    #[test]
    fn a_replayed_ping_is_answered_once_and_answers_are_capped_per_second() {
        let t0 = Instant::now();
        let mut limiter = PongLimiter::new(t0);
        assert!(limiter.may_answer([1u8; 8], t0));
        assert!(
            !limiter.may_answer([1u8; 8], t0 + Duration::from_millis(10)),
            "the same tx id is answered once"
        );

        // The per-second ceiling, counted across distinct tx ids.
        let mut answered = 1u32;
        for i in 0..u32::from(u16::MAX) {
            let mut tx = [0u8; 8];
            tx[..4].copy_from_slice(&(i + 2).to_be_bytes());
            if limiter.may_answer(tx, t0 + Duration::from_millis(500)) {
                answered += 1;
            }
        }
        assert_eq!(answered, PONG_ANSWERS_PER_SECOND);

        // The window rolls, and the budget with it.
        assert!(limiter.may_answer([9u8; 8], t0 + Duration::from_millis(1001)));
    }

    #[test]
    fn srtt_seeds_on_the_first_sample_and_smooths_after_it() {
        let mut attempt = Attempt::new(ID, KEY, None);
        let mut tx = tx_counter();
        let candidate = addr(4433);
        attempt.add_candidate(candidate, CandidateSource::Local);
        let t0 = Instant::now();
        attempt.start_signal_received(t0);
        let mut now = t0 + Duration::from_millis(u64::from(FIRE_IN_MS));
        assert_eq!(attempt.srtt(candidate), None);

        let sent = attempt.due_probes(now, &mut tx);
        let probe = Probe::decode(&sent[0].1, &KEY).unwrap();
        now += Duration::from_millis(80);
        answer(&mut attempt, candidate, &probe, now);
        assert_eq!(attempt.srtt(candidate), Some(Duration::from_millis(80)));

        now += Duration::from_millis(100);
        let sent = attempt.due_probes(now, &mut tx);
        let probe = Probe::decode(&sent[0].1, &KEY).unwrap();
        now += Duration::from_millis(8);
        answer(&mut attempt, candidate, &probe, now);
        assert_eq!(attempt.srtt(candidate), Some(Duration::from_millis(71)));
    }
}
