//! The gatehouse: `docs/dev/gatehouse-design.md` section 1, WO-1.3a's scope.
//!
//! `server` is the `mosschat gatehouse` role: the member list and slot
//! table, registration, address reflection, introduction by knock, relay by
//! session, keepalive, goodbye, and every cap and rate limit section 1
//! lists. `client` is the house side: sealing a knock and answering one
//! against the local friend list and outstanding invites. `wire` is the
//! frame and `Relay` datagram encoding both share.
//!
//! Design gap (recorded per the work order, not redesigned): the design
//! does not say whether the seen-set eviction sweep and the 4096-entry cap
//! apply per registration or gate-wide; this implementation takes the
//! smaller, safer reading: one seen set per registration, capped at 4096
//! entries each.
//!
//! **Seen-set insert point (issue #16, settled by design amendment 1;
//! supersedes this module's earlier "insert on open, not on accept"
//! reading, which amendment 1 rejected).** The entry is inserted only after
//! the seal opens *and* the body verifies as a friend or as an invite
//! proof -- the accept decision itself, never on receipt and never on an
//! open alone. A recipient's public key is public, so anyone holding it can
//! mint a seal that opens; charging the set on opening alone would let a
//! stranger fill it at whatever rate the gate forwards knocks. Inserting
//! later loses nothing a fresh insert would have caught: a seal dropped in
//! silence (wrong freshness, wrong tag, or no friend/invite match) costs
//! nothing to drop again on a repeat.

pub mod client;
pub mod server;
pub mod wire;

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use thiserror::Error;

/// Errors produced by the gate protocol, both the server and client halves.
#[derive(Debug, Error)]
pub enum GateError {
    /// An underlying I/O failure (stream read/write, socket).
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// A control frame's length prefix exceeded [`wire::CONTROL_FRAME_LEN_CAP`].
    #[error("control frame length {0} exceeds the cap")]
    FrameTooLarge(u32),
    /// A `Relay` payload exceeded [`wire::RELAY_PAYLOAD_CAP`].
    #[error("relay payload of {0} bytes exceeds the cap")]
    RelayPayloadTooLarge(usize),
    /// A read did not complete before its deadline.
    #[error("read did not complete before its deadline")]
    Timeout,
    /// A frame violated the protocol (wrong frame at this point, malformed
    /// contents, or a decode failure).
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The proven TLS key is not on the gate's member list.
    #[error("key is not a member of this gate's community")]
    NotMember,
    /// The gate is at a hard capacity (registrations, connections per key,
    /// sessions per registration).
    #[error("gate at capacity")]
    AtCapacity,
    /// A rate limit was exceeded.
    #[error("rate limited")]
    RateLimited,
    /// The connection was closed with a stated reason.
    #[error("connection closed: {0}")]
    Closed(u8),
    /// The peer certificate failed the section 5 identity binding checks.
    #[error("peer identity binding failed: {0}")]
    InvalidIdentity(String),
    /// A QUIC connection error.
    #[error("connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
    /// A QUIC connect (dialing) error.
    #[error("connect error: {0}")]
    Connect(#[from] quinn::ConnectError),
    /// A TLS configuration error.
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),
    /// The TLS handshake produced no negotiated cipher suite (a malformed
    /// `rustls::ServerConfig`/`ClientConfig`).
    #[error("no initial cipher suite negotiated: {0}")]
    NoInitialCipherSuite(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
    /// A QUIC stream read did not fill the requested exact-size buffer.
    #[error("stream read error: {0}")]
    ReadExact(#[from] quinn::ReadExactError),
    /// A QUIC stream write failed.
    #[error("stream write error: {0}")]
    Write(#[from] quinn::WriteError),
}

/// Section 7's reason enum, WO-1.3a's subset (the rest belongs to `diag.rs`,
/// WO-1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    /// `gate_refused_not_member`.
    RefusedNotMember = 1,
    /// `gate_at_capacity`.
    AtCapacity = 2,
    /// `gate_rate_limited`.
    RateLimited = 3,
    /// `cap_exceeded`.
    CapExceeded = 4,
    /// A protocol violation not covered by a more specific code.
    ProtocolError = 5,
}

/// Section 1's caps and rate limits, WO-1.3a's subset (Start/StartRequest
/// and the porch-stream caps belong to WO-1.3b).
pub mod limits {
    use std::time::Duration;

    /// `min(256, members)`.
    pub const MAX_REGISTRATIONS: usize = 256;
    /// Two live connections per key (amended section 1): a third is refused
    /// in the handshake with `gate_at_capacity` and closed before a slot is
    /// touched; the two already seated are never displaced, silently or
    /// otherwise.
    pub const MAX_CONNECTIONS_PER_KEY: usize = 2;
    /// Eight live sessions per registration.
    pub const MAX_SESSIONS_PER_REGISTRATION: usize = 8;
    /// A registration expires 90s after its last keepalive.
    pub const REGISTRATION_TTL: Duration = Duration::from_secs(90);
    /// `Introduce`: 6 per minute with burst 6.
    pub const INTRODUCE_PER_MINUTE: u32 = 6;
    /// `Introduce`: 60 per hour per registrant.
    pub const INTRODUCE_PER_HOUR: u32 = 60;
    /// `Introduce.ttl_s` cap.
    pub const INTRODUCE_TTL_CAP_S: u16 = 60;
    /// `StartRequest`: 4 per session, then ignored (section 1).
    pub const START_REQUESTS_PER_SESSION: u32 = 4;
    /// `Start.fire_in_ms` (section 2 step 4): each side fires its first
    /// probe this long after receiving `Start`. No clock is synchronised;
    /// the skew is the difference in the two one way delays from the gate.
    pub const START_FIRE_IN_MS: u16 = 200;
    /// `Register`: 4 connection attempts per key per minute.
    pub const REGISTER_ATTEMPTS_PER_MINUTE: u32 = 4;
    /// `Relay`: 2000 datagrams per session each way, and no byte rate
    /// beside it (amended section 1).
    ///
    /// This is a *shaper* rate, not a policer's: it is the rate the house
    /// side queue of `crate::path::HOUSE_RELAY_QUEUE_DEPTH` drains at, and
    /// the gate drains 10 percent over it. It used to say "and 3 MiB/s per
    /// session each way": no per-second byte limiter exists or ever did,
    /// and 2000 x 1200 is 2.29 MiB/s, so 3 MiB/s was unreachable anyway.
    /// The only byte ceiling is [`RELAY_BYTES_PER_HOUR`].
    pub const RELAY_DATAGRAMS_PER_SECOND: u32 = 2000;
    /// `Relay`: 2 GiB per session per hour then `cap_exceeded`.
    pub const RELAY_BYTES_PER_HOUR: u64 = 2 * 1024 * 1024 * 1024;
    /// Any control frame, per connection: 32 per second, burst 64.
    pub const FRAME_RATE_PER_SECOND: u32 = 32;
    /// Any control frame's burst allowance (section 1: "32 frames per
    /// second per connection with burst 64").
    pub const FRAME_RATE_BURST: u32 = 64;
    /// `Reflect`: 2 per connection (amendment 3, 2026-09-08), a hard cap
    /// and not a rate: reconnecting resets it, and the per-key brake is
    /// [`SECONDARY_ATTEMPTS_PER_MINUTE`], the reflection port's own
    /// connection limit, which bounds one key at 8 reflections a minute.
    /// Not [`REGISTER_ATTEMPTS_PER_MINUTE`], which brakes nothing here: its
    /// bucket lives on the primary port, and a key that never registers at
    /// all can still reach the reflection port (Yseult's L1 on PR 73).
    /// Per key, as this cap was, it was stricter than the connection rate
    /// it sits under, so a member allowed 4 connection attempts a minute
    /// could reflect on only 2 of them.
    pub const REFLECT_PER_CONNECTION: u32 = 2;
    /// The secondary (reflection) port's own connection attempt limit, 4
    /// per key per minute (amendment 3, 2026-09-08): a separate bucket from
    /// [`REGISTER_ATTEMPTS_PER_MINUTE`], not a share of it, so one
    /// `mosschat doctor` run (one connection on each port) leaves both
    /// ports at the same count and four runs a minute fit. The secondary
    /// port had no per-key connection limit before it, which left the
    /// per-connection `Reflect` cap bounding how useful a flood of
    /// connections was rather than bounding the flood.
    pub const SECONDARY_ATTEMPTS_PER_MINUTE: u32 = 4;
    /// `Keepalive`: one per `keepalive_s`, 3 per second tolerated, per
    /// connection.
    pub const KEEPALIVE_PER_SECOND: u32 = 3;
    /// The gate-to-house frame channel's bound (Yseult finding 5 remainder:
    /// previously unbounded, so a member's frame flood grew gate memory
    /// without limit). Chosen, not measured: comfortably above
    /// `FRAME_RATE_BURST` so a legitimate burst never trips it, small
    /// enough that the worst case for one connection is a bounded handful
    /// of frames. A full channel drops the newest frame and is silent to
    /// the sender of the frame that no longer fits (the writer task is
    /// already draining it as fast as the stream allows; a full channel
    /// means that house's own connection, not the sender, is the
    /// bottleneck).
    pub const FRAME_TX_QUEUE_CAP: usize = 256;
    /// The window every sealed body's freshness is checked against (section
    /// 1, "so that one captured Introduce would otherwise replay forever").
    pub const SEEN_WINDOW: Duration = Duration::from_secs(120);
    /// The per-registration seen-set cap (design gap noted in this module's
    /// doc comment: taken per registration, not gate-wide).
    pub const SEEN_SET_CAP: usize = 4096;
    /// A frame that should follow immediately.
    pub const CONTROL_READ_DEADLINE: Duration = Duration::from_secs(10);
    /// A cap on connections that have completed the TLS handshake but not
    /// yet completed `Register`, guarding the `accept_bi` plus `Register`
    /// read window (each individually deadlined) against an attacker who
    /// opens many connections and then sends nothing at all. Chosen, not
    /// measured: twice the registration cap, generous headroom for a
    /// legitimate community's reconnect storms without leaving the window
    /// unbounded.
    pub const MAX_PENDING_CONNECTIONS: usize = 2 * MAX_REGISTRATIONS;
    /// The gate-wide bound on the porch socket's inbound relay queue
    /// (`sock.rs`), guarding against a session peer that sends faster than
    /// this house's endpoint drains it. Chosen, not measured: large enough
    /// to absorb a burst well past `RELAY_DATAGRAMS_PER_SECOND` for one
    /// tick of scheduling, small enough that the worst case (every entry at
    /// the 1200 byte relay cap) is a bounded ~1.2 MiB. The drop policy is
    /// stated where it is enforced (amended section 3): the *newest*
    /// arrival is dropped and counted once the queue is full, and one
    /// `poll_recv` call draws from both the queue and the real socket
    /// rather than draining either one first. (This used to say the real
    /// socket is always attempted before the queue; it is not, and must
    /// not be, since the real socket is what feeds the queue. Konrad's
    /// merge review of PR #17 flagged the mismatch.)
    pub const INBOUND_RELAY_QUEUE_CAP: usize = 1024;
    /// The bound on the porch socket's inbound *probe* queue (`sock.rs`).
    ///
    /// Section 3 bounds the relay queue at 1024 and is silent about this
    /// one, which did not exist when it was written; the smaller reading is
    /// the same number, and it is generous here, one probe being 81 bytes
    /// against the relay queue's 1200, so a full probe queue is 81 KiB.
    /// The queue is fed only by probes whose keyed hash already verified
    /// under a currently armed attempt key, so filling it needs the shared
    /// `probe_key`, which crossed the gate inside the end to end TLS; the
    /// cap is the second line, not the first.
    pub const INBOUND_PROBE_QUEUE_CAP: usize = 1024;
}

/// The gate's member list: ed25519 public keys read from a file, one 64
/// hex character key per non-empty, non-`#`-prefixed line, reloadable
/// without dropping live registrations.
#[derive(Debug, Default, Clone)]
pub struct MemberList {
    members: std::collections::HashSet<[u8; 32]>,
}

impl MemberList {
    /// Builds a member list directly from a set of keys (used by tests and
    /// by callers that already hold the keys in memory).
    #[must_use]
    pub fn from_keys(keys: impl IntoIterator<Item = [u8; 32]>) -> Self {
        Self {
            members: keys.into_iter().collect(),
        }
    }

    /// Loads a member list from `path`: one 64 hex character ed25519 public
    /// key per line, blank lines and `#` comments ignored.
    ///
    /// # Errors
    ///
    /// Returns [`GateError::Io`] if the file cannot be read, or
    /// [`GateError::Protocol`] if a non-blank, non-comment line is not 64
    /// hex characters, or if the resulting list exceeds
    /// [`limits::MAX_REGISTRATIONS`] (a configuration error refused at
    /// start, not at 3am, per section 1).
    pub fn load(path: &Path) -> Result<Self, GateError> {
        let text = std::fs::read_to_string(path)?;
        let mut members = std::collections::HashSet::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let key = decode_hex32(line)
                .ok_or_else(|| GateError::Protocol(format!("bad member key line: {line:?}")))?;
            members.insert(key);
        }
        if members.len() > limits::MAX_REGISTRATIONS {
            return Err(GateError::Protocol(format!(
                "member list has {} entries, more than the {} slot table can ever seat",
                members.len(),
                limits::MAX_REGISTRATIONS
            )));
        }
        Ok(Self { members })
    }

    /// Whether `key` is a member.
    #[must_use]
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.members.contains(key)
    }

    /// The number of members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A simple token-bucket rate limiter: `burst` tokens capacity, refilling at
/// `per_minute / 60` tokens per second, checked and consumed at each call.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    capacity: f64,
    tokens: f64,
    refill_per_s: f64,
    last: Instant,
}

impl RateLimiter {
    /// Builds a limiter with the given burst capacity and steady refill
    /// rate over one minute.
    #[must_use]
    pub fn per_minute(burst: u32, per_minute: u32) -> Self {
        Self {
            capacity: f64::from(burst),
            tokens: f64::from(burst),
            refill_per_s: f64::from(per_minute) / 60.0,
            last: Instant::now(),
        }
    }

    /// Builds a limiter with the given burst capacity and steady refill
    /// rate over one hour (section 1's `INTRODUCE_PER_HOUR`, previously
    /// wired through [`Self::per_minute`] by mistake, which refilled 60x too
    /// fast and never let the hourly cap bind).
    #[must_use]
    pub fn per_hour(burst: u32, per_hour: u32) -> Self {
        Self {
            capacity: f64::from(burst),
            tokens: f64::from(burst),
            refill_per_s: f64::from(per_hour) / 3600.0,
            last: Instant::now(),
        }
    }

    /// Builds a limiter with the given burst capacity and steady refill
    /// rate over one second (section 1's per-session `Relay` datagram
    /// rate).
    #[must_use]
    pub fn per_second(burst: u32, per_second: u32) -> Self {
        Self {
            capacity: f64::from(burst),
            tokens: f64::from(burst),
            refill_per_s: f64::from(per_second),
            last: Instant::now(),
        }
    }

    /// Builds a limiter directly from a float capacity and a full-hour
    /// refill rate, for a budget too large to express safely as `u32`
    /// (section 1's per-session `RELAY_BYTES_PER_HOUR`, a `u64`).
    #[must_use]
    pub fn capacity_per_hour(capacity: f64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_per_s: capacity / 3600.0,
            last: Instant::now(),
        }
    }

    /// Attempts to consume one token, refilling first for elapsed time.
    /// Returns whether a token was available.
    pub fn try_take(&mut self) -> bool {
        self.try_take_n(1.0)
    }

    /// Attempts to consume `amount` tokens (fractional units are how a byte
    /// budget, such as section 1's `RELAY_BYTES_PER_HOUR`, is expressed as a
    /// token bucket), refilling first for elapsed time. Returns whether
    /// `amount` was available.
    pub fn try_take_n(&mut self, amount: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_s).min(self.capacity);
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }
}

/// The seen set of section 1: `BLAKE3(sealed)` cut to 16 bytes, held until
/// its window elapses, evicted by expiry alone on insert (never dropping a
/// live entry, which would reopen the replay window).
#[derive(Debug, Default)]
pub struct SeenSet {
    entries: HashMap<[u8; 16], Instant>,
}

impl SeenSet {
    /// Builds an empty seen set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks whether `sealed`'s hash was already seen within the window,
    /// and if not, records it now (per issue #16: insert on acceptance, not
    /// on every seal that merely opens, so an attacker who can mint
    /// openable seals cannot inflate the set on someone else's behalf).
    ///
    /// Returns `true` if this is a fresh seal (never seen, and recorded
    /// now), `false` if it is a repeat (dropped in silence by the caller).
    pub fn accept(&mut self, sealed: &[u8]) -> bool {
        self.sweep();
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&blake3::hash(sealed).as_bytes()[..16]);
        if self.entries.contains_key(&hash) {
            return false;
        }
        if self.entries.len() >= limits::SEEN_SET_CAP {
            // Full set means the gate broke its own rate limit (section 1);
            // refuse rather than evict a live entry.
            return false;
        }
        self.entries.insert(hash, Instant::now());
        true
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        self.entries
            .retain(|_, inserted| now.duration_since(*inserted) < limits::SEEN_WINDOW);
    }

    /// The number of live entries, for tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl RateLimiter {
    /// Whether this limiter is currently at full capacity (as of its last
    /// `try_take*` call): a cheap, approximate signal a periodic sweep can
    /// use to prune per-key limiter maps back down, since a limiter sitting
    /// at capacity carries no state worth keeping.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.tokens >= self.capacity
    }
}

/// Freshness check on a sealed body's `sent_ms` against the gate's/house's
/// own clock, per section 1: opened only within [`limits::SEEN_WINDOW`] of
/// now.
#[must_use]
pub fn within_freshness_window(sent_ms: u64, now_ms: u64) -> bool {
    let window_ms = limits::SEEN_WINDOW.as_millis() as u64;
    now_ms.abs_diff(sent_ms) <= window_ms
}

/// The current time in milliseconds since the Unix epoch, saturating rather
/// than panicking on a clock before 1970 (library code never panics,
/// invariant 1).
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
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
    fn member_list_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("jerome-members-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("members.txt");
        let key = [9u8; 32];
        std::fs::write(&path, format!("# comment\n{}\n\n", hex(&key))).unwrap();
        let list = MemberList::load(&path).unwrap();
        assert!(list.contains(&key));
        assert_eq!(list.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn seen_set_drops_repeats_and_accepts_fresh() {
        let mut seen = SeenSet::new();
        assert!(seen.accept(b"body-a"));
        assert!(!seen.accept(b"body-a"));
        assert!(seen.accept(b"body-b"));
    }

    #[test]
    fn rate_limiter_exhausts_burst_then_refuses() {
        let mut limiter = RateLimiter::per_minute(2, 60);
        assert!(limiter.try_take());
        assert!(limiter.try_take());
        assert!(!limiter.try_take());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
