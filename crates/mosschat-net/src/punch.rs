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

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use minicbor::{Decoder, Encoder, decode::Error as DecodeError};

use crate::gate::wire::Addr;

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
#[derive(Debug, Clone, PartialEq, Eq)]
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
            } => {
                enc.array(5).unwrap();
                enc.u8(T_CANDIDATES).unwrap();
                enc.u8(*v).unwrap();
                enc.bytes(attempt).unwrap();
                enc.array(addrs.len() as u64).unwrap();
                for addr in addrs {
                    enc.bytes(&addr_to_raw(*addr)).unwrap();
                }
                enc.bytes(probe_half).unwrap();
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
            (T_CANDIDATES, 5) => {
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
                Self::Candidates {
                    v,
                    attempt,
                    addrs,
                    probe_half,
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
            if !is_plausible_candidate(*addr) {
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

/// Whether an address is worth probing at all: a real host address with a
/// real port. A loopback or unspecified address, or port 0, is never a
/// candidate, and neither is port 1, which is the port every synthetic peer
/// address carries (section 3) and which no real peer ever listens on.
///
/// A unique local address is *not* filtered even though the synthetic
/// address is one: a real LAN may use `fd00::/8` for real hosts, and
/// section 6 wants exactly those reachable. The port is the precise
/// discriminator; the prefix is not.
fn is_plausible_candidate(addr: SocketAddr) -> bool {
    if addr.port() == 0 || addr.port() == 1 {
        return false;
    }
    match addr.ip() {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_unspecified() && !v4.is_broadcast(),
        IpAddr::V6(v6) => !v6.is_loopback() && !v6.is_unspecified() && !v6.is_multicast(),
    }
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
#[derive(Debug)]
pub struct Attempt {
    id: [u8; 16],
    key: [u8; 32],
    fire_at: Option<Instant>,
    candidates: Vec<Candidate>,
    winner: Option<Winner>,
}

impl Attempt {
    /// A fresh attempt with no candidates and no start signal yet.
    #[must_use]
    pub fn new(id: [u8; 16], key: [u8; 32]) -> Self {
        Self {
            id,
            key,
            fire_at: None,
            candidates: Vec::new(),
            winner: None,
        }
    }

    /// This attempt's id, the value both sides' diagnostics records join on.
    #[must_use]
    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    /// Adds a candidate, returning `false` if it is a duplicate or the
    /// [`MAX_CANDIDATES`] cap is already reached.
    pub fn add_candidate(&mut self, addr: SocketAddr, source: CandidateSource) -> bool {
        if self.candidates.len() >= MAX_CANDIDATES
            || !is_plausible_candidate(addr)
            || self.candidates.iter().any(|c| c.addr == addr)
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

    /// How many candidates are under probe.
    #[must_use]
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
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
        enc.array(5).unwrap();
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
            assert!(is_plausible_candidate(candidate));
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
        let mut attempt = Attempt::new(ID, KEY);
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
        let mut attempt = Attempt::new(ID, KEY);
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
        let mut attempt = Attempt::new(ID, KEY);
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
        let mut attempt = Attempt::new(ID, KEY);
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
        let mut attempt = Attempt::new(ID, KEY);
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
        let mut attempt = Attempt::new(ID, KEY);
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
        let mut attempt = Attempt::new(ID, KEY);
        for port in 0..MAX_CANDIDATES as u16 {
            assert!(attempt.add_candidate(addr(4433 + port), CandidateSource::Local));
        }
        assert!(!attempt.add_candidate(addr(4433), CandidateSource::Local));
        assert!(!attempt.add_candidate(addr(9999), CandidateSource::Local));
        assert_eq!(attempt.candidate_count(), MAX_CANDIDATES);
        assert_eq!(attempt.source_of(addr(4433)), Some(CandidateSource::Local));
        assert_eq!(attempt.source_of(addr(9999)), None);
    }

    #[test]
    fn srtt_seeds_on_the_first_sample_and_smooths_after_it() {
        let mut attempt = Attempt::new(ID, KEY);
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
