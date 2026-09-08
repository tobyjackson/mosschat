//! The diagnostics record, its writer, its reader and the redaction rule of
//! `docs/dev/gatehouse-design.md` section 7 (decision 22, invariant 12).
//!
//! One [`DiagRecord`] is written per connection attempt, whether it
//! succeeded, degraded or failed. Records are appended one JSON object per
//! line to a file named for the UTC day, because a person reads this file
//! and pastes it into an issue (section 7's own reason for JSON over CBOR).
//! No dependency in this workspace formats dates or JSON, so both are
//! hand-rolled here rather than adding one; see the `rfc3339` and `json`
//! modules below.
//!
//! This module defines every enum from section 7 (`Step`, `Reason`,
//! `Mapping`) so that WO-1.3b's `punch.rs`/`live.rs` and the `doctor`
//! subcommand, both built after this half lands, import them from here
//! rather than each defining its own copy.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::gate::wire::Addr;

/// One step of a connection attempt, in the order section 7's step enum
/// lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Dialing the gate's QUIC endpoint.
    GateDial,
    /// Sending `Register` and receiving `Registered`.
    GateRegister,
    /// The primary port's address reflection (`Registered.observed`).
    ReflectPrimary,
    /// The secondary port's address reflection (`Reflect`/`Reflected`).
    ReflectSecondary,
    /// Sending `Introduce` and waiting on `Introduction` or `ttl_s`.
    Introduce,
    /// Opening the relay session over the gate connection.
    RelayOpen,
    /// The end to end QUIC handshake with the peer.
    PeerHandshake,
    /// Exchanging `Candidates` on the porch stream.
    CandidateExchange,
    /// `StartRequest` sent and `Start` received.
    StartSignal,
    /// The probe burst of section 2 step 5.
    ProbeBurst,
    /// A candidate answering three consecutive probes and winning.
    Upgrade,
    /// Steady state on the winning path.
    Live,
    /// The winning path going stale then dead (section 4).
    PathLost,
    /// Falling back to the relay session after a path is lost.
    RelayFallback,
    /// Clean shutdown, either side's `Goodbye`.
    Closed,
}

impl Step {
    /// All variants, in section 7's declared order.
    pub const ALL: [Step; 15] = [
        Step::GateDial,
        Step::GateRegister,
        Step::ReflectPrimary,
        Step::ReflectSecondary,
        Step::Introduce,
        Step::RelayOpen,
        Step::PeerHandshake,
        Step::CandidateExchange,
        Step::StartSignal,
        Step::ProbeBurst,
        Step::Upgrade,
        Step::Live,
        Step::PathLost,
        Step::RelayFallback,
        Step::Closed,
    ];

    /// The exact `snake_case` spelling section 7 gives this step, used as
    /// its JSON representation and by `doctor`'s human-readable output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Step::GateDial => "gate_dial",
            Step::GateRegister => "gate_register",
            Step::ReflectPrimary => "reflect_primary",
            Step::ReflectSecondary => "reflect_secondary",
            Step::Introduce => "introduce",
            Step::RelayOpen => "relay_open",
            Step::PeerHandshake => "peer_handshake",
            Step::CandidateExchange => "candidate_exchange",
            Step::StartSignal => "start_signal",
            Step::ProbeBurst => "probe_burst",
            Step::Upgrade => "upgrade",
            Step::Live => "live",
            Step::PathLost => "path_lost",
            Step::RelayFallback => "relay_fallback",
            Step::Closed => "closed",
        }
    }

    /// Parses the `snake_case` spelling back to a [`Step`].
    ///
    /// # Errors
    /// Returns [`DiagError::Malformed`] if `s` names no known step.
    pub fn parse_str(s: &str) -> Result<Self, DiagError> {
        Step::ALL
            .into_iter()
            .find(|step| step.as_str() == s)
            .ok_or_else(|| DiagError::Malformed(format!("unknown step: {s:?}")))
    }
}

/// Whether a step succeeded, from `steps[].outcome` in section 7's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome {
    /// The step completed.
    Ok,
    /// The step failed; `StepRecord::detail` says why.
    Fail,
}

impl StepOutcome {
    /// The JSON representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            StepOutcome::Ok => "ok",
            StepOutcome::Fail => "fail",
        }
    }

    /// Parses the JSON representation back.
    ///
    /// # Errors
    /// Returns [`DiagError::Malformed`] if `s` is neither `"ok"` nor
    /// `"fail"`.
    pub fn parse_str(s: &str) -> Result<Self, DiagError> {
        match s {
            "ok" => Ok(StepOutcome::Ok),
            "fail" => Ok(StepOutcome::Fail),
            other => Err(DiagError::Malformed(format!("unknown outcome: {other:?}"))),
        }
    }
}

/// The reason a connection attempt ended the way it did, section 7's reason
/// enum, in its declared order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Reached `live` normally.
    Ok,
    /// The gate could not be reached at all.
    GateUnreachable,
    /// The gate refused the handshake: the proven key is not a member.
    GateRefusedNotMember,
    /// The gate refused a third live connection for this key.
    GateAtCapacity,
    /// A rate limit was hit; the registration survives.
    GateRateLimited,
    /// The gate path's `max_datagram_size()` fell under 1205, so the
    /// session fell back to a reliable stream.
    RelayStreamFallback,
    /// A `Relay` payload exceeded the 1200 byte cap and was dropped.
    RelayDatagramTooLarge,
    /// `Introduce`'s `ttl_s` elapsed with no `Introduction`.
    IntroduceTimeout,
    /// The end to end QUIC handshake with the peer failed.
    PeerHandshakeFailed,
    /// The peer's TLS-proven key did not match the expected one.
    PeerKeyMismatch,
    /// Candidate gathering produced nothing to probe.
    NoCandidates,
    /// Every candidate's probe burst timed out.
    ProbeTimeout,
    /// The two reflections differed in address or port.
    EndpointDependentMapping,
    /// Both sides share an IP and every direct candidate timed out while
    /// the relay worked.
    HairpinFailure,
    /// Neither gate port could be reached although its name resolved.
    UdpBlocked,
    /// The winning path went idle past its timeout.
    PathIdleTimeout,
    /// The local interface list changed mid-attempt.
    LocalAddressChanged,
    /// The peer sent `Goodbye`.
    PeerGoodbye,
    /// A relay session's byte or datagram cap was exceeded.
    CapExceeded,
    /// Any failure not named by one of the above.
    Internal,
}

impl Reason {
    /// All variants, in section 7's declared order.
    pub const ALL: [Reason; 20] = [
        Reason::Ok,
        Reason::GateUnreachable,
        Reason::GateRefusedNotMember,
        Reason::GateAtCapacity,
        Reason::GateRateLimited,
        Reason::RelayStreamFallback,
        Reason::RelayDatagramTooLarge,
        Reason::IntroduceTimeout,
        Reason::PeerHandshakeFailed,
        Reason::PeerKeyMismatch,
        Reason::NoCandidates,
        Reason::ProbeTimeout,
        Reason::EndpointDependentMapping,
        Reason::HairpinFailure,
        Reason::UdpBlocked,
        Reason::PathIdleTimeout,
        Reason::LocalAddressChanged,
        Reason::PeerGoodbye,
        Reason::CapExceeded,
        Reason::Internal,
    ];

    /// The exact `snake_case` spelling section 7 gives this reason.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Ok => "ok",
            Reason::GateUnreachable => "gate_unreachable",
            Reason::GateRefusedNotMember => "gate_refused_not_member",
            Reason::GateAtCapacity => "gate_at_capacity",
            Reason::GateRateLimited => "gate_rate_limited",
            Reason::RelayStreamFallback => "relay_stream_fallback",
            Reason::RelayDatagramTooLarge => "relay_datagram_too_large",
            Reason::IntroduceTimeout => "introduce_timeout",
            Reason::PeerHandshakeFailed => "peer_handshake_failed",
            Reason::PeerKeyMismatch => "peer_key_mismatch",
            Reason::NoCandidates => "no_candidates",
            Reason::ProbeTimeout => "probe_timeout",
            Reason::EndpointDependentMapping => "endpoint_dependent_mapping",
            Reason::HairpinFailure => "hairpin_failure",
            Reason::UdpBlocked => "udp_blocked",
            Reason::PathIdleTimeout => "path_idle_timeout",
            Reason::LocalAddressChanged => "local_address_changed",
            Reason::PeerGoodbye => "peer_goodbye",
            Reason::CapExceeded => "cap_exceeded",
            Reason::Internal => "internal",
        }
    }

    /// Parses the `snake_case` spelling back to a [`Reason`].
    ///
    /// # Errors
    /// Returns [`DiagError::Malformed`] if `s` names no known reason.
    pub fn parse_str(s: &str) -> Result<Self, DiagError> {
        Reason::ALL
            .into_iter()
            .find(|reason| reason.as_str() == s)
            .ok_or_else(|| DiagError::Malformed(format!("unknown reason: {s:?}")))
    }
}

/// The inferred NAT mapping behaviour, from comparing the two reflections
/// (section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mapping {
    /// Both reflections agreed: the same public address and port regardless
    /// of destination.
    EndpointIndependent,
    /// The two reflections differed in address or port.
    EndpointDependent,
    /// Too few reflections were observed to tell.
    Unknown,
}

impl Mapping {
    /// The JSON representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Mapping::EndpointIndependent => "endpoint_independent",
            Mapping::EndpointDependent => "endpoint_dependent",
            Mapping::Unknown => "unknown",
        }
    }

    /// Parses the JSON representation back.
    ///
    /// # Errors
    /// Returns [`DiagError::Malformed`] if `s` names no known mapping.
    pub fn parse_str(s: &str) -> Result<Self, DiagError> {
        match s {
            "endpoint_independent" => Ok(Mapping::EndpointIndependent),
            "endpoint_dependent" => Ok(Mapping::EndpointDependent),
            "unknown" => Ok(Mapping::Unknown),
            other => Err(DiagError::Malformed(format!("unknown mapping: {other:?}"))),
        }
    }
}

/// The path a connection settled on: the relay session or a direct
/// candidate, each with the address traffic actually flows over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathChoice {
    /// Traffic flows through the gate's relay session.
    Relay(Addr),
    /// Traffic flows directly to the peer.
    Direct(Addr),
}

impl PathChoice {
    /// `"relay"` or `"direct"`, the JSON representation of the path kind.
    #[must_use]
    pub fn kind_str(self) -> &'static str {
        match self {
            PathChoice::Relay(_) => "relay",
            PathChoice::Direct(_) => "direct",
        }
    }

    /// The address traffic flows over, whichever variant this is.
    #[must_use]
    pub fn addr(self) -> Addr {
        match self {
            PathChoice::Relay(addr) | PathChoice::Direct(addr) => addr,
        }
    }
}

/// A public key, reduced to a short fingerprint fit to appear in a
/// diagnostics record.
///
/// Section 7's redaction rule is enforced structurally rather than by
/// convention: this type is 4 bytes wide, so it cannot losslessly hold a 32
/// byte ed25519 key, and its only constructor is [`PeerFingerprint::from_key`],
/// which consumes a key and an install salt and returns only a keyed hash
/// prefix; the key itself is never retained. There is no `From<[u8; 32]>` or
/// other conversion that could place raw key bytes into a [`DiagRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerFingerprint([u8; 4]);

impl PeerFingerprint {
    /// Computes the fingerprint of `key`, salted with `install_salt` (16
    /// random bytes generated once and stored beside the log, per section
    /// 7), as the first 4 bytes (8 hex characters) of
    /// `BLAKE3(install_salt || key)`.
    #[must_use]
    pub fn from_key(install_salt: &[u8], key: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(install_salt);
        hasher.update(key);
        let hash = hasher.finalize();
        let mut out = [0u8; 4];
        if let Some(prefix) = hash.as_bytes().get(..4) {
            out.copy_from_slice(prefix);
        }
        Self(out)
    }

    /// The fingerprint as 8 lowercase hex characters.
    #[must_use]
    pub fn as_hex(&self) -> String {
        hex_encode(&self.0)
    }

    /// Parses 8 lowercase hex characters back into a fingerprint.
    ///
    /// # Errors
    /// Returns [`DiagError::Malformed`] if `s` is not exactly 8 hex
    /// characters.
    pub fn from_hex(s: &str) -> Result<Self, DiagError> {
        let bytes = hex_decode(s)?;
        let array: [u8; 4] = bytes.try_into().map_err(|_| {
            DiagError::Malformed(format!("peer fingerprint must be 4 bytes: {s:?}"))
        })?;
        Ok(Self(array))
    }
}

impl fmt::Display for PeerFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}

/// Encodes `bytes` as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Decodes a lowercase or uppercase hex string.
///
/// # Errors
/// Returns [`DiagError::Malformed`] if `s` has odd length or contains a
/// non-hex character.
fn hex_decode(s: &str) -> Result<Vec<u8>, DiagError> {
    if !s.len().is_multiple_of(2) {
        return Err(DiagError::Malformed(format!(
            "odd length hex string: {s:?}"
        )));
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::with_capacity(chars.len() / 2);
    for pair in chars.chunks(2) {
        let (Some(hi), Some(lo)) = (pair.first(), pair.get(1)) else {
            return Err(DiagError::Malformed(format!("bad hex pair in {s:?}")));
        };
        let hi = hi
            .to_digit(16)
            .ok_or_else(|| DiagError::Malformed(format!("bad hex digit in {s:?}")))?;
        let lo = lo
            .to_digit(16)
            .ok_or_else(|| DiagError::Malformed(format!("bad hex digit in {s:?}")))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// One entry of `DiagRecord::steps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepRecord {
    /// Which step this is.
    pub step: Step,
    /// Milliseconds since the attempt started.
    pub at_ms: u64,
    /// Whether the step succeeded.
    pub outcome: StepOutcome,
    /// Free text: an error message, a candidate count, a timing note. Never
    /// fed raw key material, ticket secrets or payload bytes; callers pass
    /// only text meant to be read.
    pub detail: String,
}

/// One diagnostics record: one connection attempt, section 7's field table
/// in full.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagRecord {
    /// The attempt id shared by both sides (frame 16), so two logs join.
    pub attempt: [u8; 16],
    /// The gate's session id (frame 6), `0` if the attempt never reached
    /// introduction.
    pub session: u32,
    /// The gate's monotonic clock at `Start` (frame 7), so two logs can be
    /// aligned; never a time to act on.
    pub gate_ms: u64,
    /// The peer's key, redacted (see [`PeerFingerprint`]).
    pub peer: PeerFingerprint,
    /// When the attempt started, UTC.
    pub started_at_ms: u64,
    /// When the attempt ended, UTC.
    pub ended_at_ms: u64,
    /// Every step tried, in order.
    pub steps: Vec<StepRecord>,
    /// The step that failed, if any.
    pub failed_step: Option<Step>,
    /// The two gate reflections: primary port, then secondary port.
    pub local_observed: [Addr; 2],
    /// The peer's observed address, from `Introduction` (frame 6).
    pub peer_observed: Addr,
    /// The inferred NAT mapping behaviour.
    pub mapping: Mapping,
    /// Whether the relay session carried any traffic, recorded on every
    /// attempt, success or not (D3).
    pub gate_carried_traffic: bool,
    /// Bytes the relay session carried, either direction.
    pub gate_bytes: u64,
    /// The path chosen and the address it uses.
    pub path: PathChoice,
    /// The chosen path's round trip time in microseconds.
    pub path_rtt_us: u32,
    /// Why the attempt ended the way it did.
    pub reason: Reason,
    /// The running mosschat version.
    pub version: String,
    /// The running platform (`"linux"`, `"macos"`, `"windows"`).
    pub platform: String,
}

/// Errors from encoding, decoding or storing a [`DiagRecord`].
#[derive(Debug, thiserror::Error)]
pub enum DiagError {
    /// A filesystem operation failed.
    #[error("diagnostics I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A line was not valid JSON, or was valid JSON that did not match a
    /// [`DiagRecord`]'s shape.
    #[error("malformed diagnostics record: {0}")]
    Malformed(String),
}

// ---------------------------------------------------------------------
// RFC 3339 timestamps
// ---------------------------------------------------------------------

/// UTC calendar math and RFC 3339 formatting, hand-rolled because no crate
/// in this workspace formats dates (`docs/dev/lints.md`'s dependency
/// discipline: nothing here is added without a named reason, and one whole
/// crate for "print a UTC timestamp" is not proportionate).
mod rfc3339 {
    use super::DiagError;

    /// Howard Hinnant's `civil_from_days` (public domain): days since the
    /// Unix epoch to a proleptic-Gregorian `(year, month, day)`.
    fn civil_from_days(z: i64) -> (i64, u32, u32) {
        let z = z + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        #[allow(clippy::cast_sign_loss)]
        let doe = (z - era * 146_097) as u64;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        #[allow(clippy::cast_possible_wrap)]
        let y = yoe as i64 + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        #[allow(clippy::cast_possible_truncation)]
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        (if m <= 2 { y + 1 } else { y }, m, d)
    }

    /// The inverse of [`civil_from_days`]: a proleptic-Gregorian date to
    /// days since the Unix epoch.
    fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        #[allow(clippy::cast_sign_loss)]
        let yoe = (y - era * 400) as u64;
        let m = u64::from(m);
        let d = u64::from(d);
        let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        #[allow(clippy::cast_possible_wrap)]
        let doe = doe as i64;
        era * 146_097 + doe - 719_468
    }

    /// Formats `epoch_ms` (milliseconds since the Unix epoch, never
    /// negative in this codebase, see `now_ms` in `gate/mod.rs`) as an RFC
    /// 3339 UTC timestamp with millisecond precision.
    #[must_use]
    pub fn format(epoch_ms: u64) -> String {
        #[allow(clippy::cast_possible_wrap)]
        let epoch_s = (epoch_ms / 1000) as i64;
        let ms = epoch_ms % 1000;
        let days = epoch_s.div_euclid(86_400);
        let secs_of_day = epoch_s.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        let h = secs_of_day / 3600;
        let min = (secs_of_day % 3600) / 60;
        let s = secs_of_day % 60;
        format!("{y:04}-{m:02}-{d:02}T{h:02}:{min:02}:{s:02}.{ms:03}Z")
    }

    /// Parses an RFC 3339 UTC timestamp of the exact shape [`format`]
    /// produces back to milliseconds since the Unix epoch.
    ///
    /// # Errors
    /// Returns [`DiagError::Malformed`] if `s` is not that shape.
    pub fn parse(s: &str) -> Result<u64, DiagError> {
        let bad = || DiagError::Malformed(format!("bad RFC 3339 timestamp: {s:?}"));
        let s = s.strip_suffix('Z').ok_or_else(bad)?;
        let (date, time) = s.split_once('T').ok_or_else(bad)?;
        let mut date_parts = date.split('-');
        let y: i64 = date_parts
            .next()
            .ok_or_else(bad)?
            .parse()
            .map_err(|_| bad())?;
        let m: u32 = date_parts
            .next()
            .ok_or_else(bad)?
            .parse()
            .map_err(|_| bad())?;
        let d: u32 = date_parts
            .next()
            .ok_or_else(bad)?
            .parse()
            .map_err(|_| bad())?;
        if date_parts.next().is_some() {
            return Err(bad());
        }
        let (hms, ms) = time.split_once('.').ok_or_else(bad)?;
        let ms: u64 = ms.parse().map_err(|_| bad())?;
        let mut hms_parts = hms.split(':');
        let h: i64 = hms_parts
            .next()
            .ok_or_else(bad)?
            .parse()
            .map_err(|_| bad())?;
        let min: i64 = hms_parts
            .next()
            .ok_or_else(bad)?
            .parse()
            .map_err(|_| bad())?;
        let sec: i64 = hms_parts
            .next()
            .ok_or_else(bad)?
            .parse()
            .map_err(|_| bad())?;
        if hms_parts.next().is_some() {
            return Err(bad());
        }
        let days = days_from_civil(y, m, d);
        let secs_of_day = h * 3600 + min * 60 + sec;
        let epoch_s = days * 86_400 + secs_of_day;
        if epoch_s < 0 {
            return Err(bad());
        }
        #[allow(clippy::cast_sign_loss)]
        let epoch_s = epoch_s as u64;
        Ok(epoch_s * 1000 + ms)
    }

    /// The `YYYY-MM-DD` UTC date `epoch_ms` falls on, used to name a day's
    /// diagnostics file.
    #[must_use]
    pub fn date_only(epoch_ms: u64) -> String {
        #[allow(clippy::cast_possible_wrap)]
        let epoch_s = (epoch_ms / 1000) as i64;
        let days = epoch_s.div_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        format!("{y:04}-{m:02}-{d:02}")
    }
}

// ---------------------------------------------------------------------
// A minimal JSON encoder/decoder scoped to DiagRecord's own shape
// ---------------------------------------------------------------------

/// A tiny JSON value tree, just enough to decode one line back into a
/// [`DiagRecord`] and reject a malformed one. No dependency in this
/// workspace parses JSON (see `rfc3339`'s comment on dates for the same
/// reasoning), and this module is not a general purpose parser: it exists
/// to invert exactly what [`DiagRecord::to_json_line`] emits.
mod json {
    use super::DiagError;

    #[derive(Debug, Clone, PartialEq)]
    pub enum Value {
        Null,
        Bool(bool),
        /// The raw digit sequence, kept as text so integers up to `u64`
        /// round-trip exactly (an `f64` cannot represent every `u64`).
        Number(String),
        String(String),
        Array(Vec<Value>),
        Object(Vec<(String, Value)>),
    }

    impl Value {
        pub fn as_str(&self) -> Result<&str, DiagError> {
            match self {
                Value::String(s) => Ok(s),
                other => Err(DiagError::Malformed(format!(
                    "expected a string, found {other:?}"
                ))),
            }
        }

        pub fn as_bool(&self) -> Result<bool, DiagError> {
            match self {
                Value::Bool(b) => Ok(*b),
                other => Err(DiagError::Malformed(format!(
                    "expected a bool, found {other:?}"
                ))),
            }
        }

        pub fn as_u64(&self) -> Result<u64, DiagError> {
            match self {
                Value::Number(n) => n.parse().map_err(|_| {
                    DiagError::Malformed(format!("expected an unsigned integer: {n:?}"))
                }),
                other => Err(DiagError::Malformed(format!(
                    "expected a number, found {other:?}"
                ))),
            }
        }

        pub fn as_array(&self) -> Result<&[Value], DiagError> {
            match self {
                Value::Array(items) => Ok(items),
                other => Err(DiagError::Malformed(format!(
                    "expected an array, found {other:?}"
                ))),
            }
        }

        pub fn as_object(&self) -> Result<&[(String, Value)], DiagError> {
            match self {
                Value::Object(fields) => Ok(fields),
                other => Err(DiagError::Malformed(format!(
                    "expected an object, found {other:?}"
                ))),
            }
        }

        pub fn get<'a>(&'a self, key: &str) -> Result<&'a Value, DiagError> {
            self.as_object()?
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .ok_or_else(|| DiagError::Malformed(format!("missing field {key:?}")))
        }
    }

    /// Escapes `s` for placement inside a JSON string literal.
    pub fn escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out
    }

    /// Parses one JSON value from `input`, erroring on anything left over
    /// but leading or trailing whitespace.
    pub fn parse(input: &str) -> Result<Value, DiagError> {
        let mut parser = Parser {
            chars: input.chars().peekable(),
        };
        let value = parser.parse_value()?;
        parser.skip_ws();
        if parser.chars.peek().is_some() {
            return Err(DiagError::Malformed(
                "trailing data after JSON value".to_string(),
            ));
        }
        Ok(value)
    }

    struct Parser<'a> {
        chars: std::iter::Peekable<std::str::Chars<'a>>,
    }

    impl Parser<'_> {
        fn skip_ws(&mut self) {
            while matches!(self.chars.peek(), Some(c) if c.is_whitespace()) {
                self.chars.next();
            }
        }

        fn expect(&mut self, expected: char) -> Result<(), DiagError> {
            match self.chars.next() {
                Some(c) if c == expected => Ok(()),
                other => Err(DiagError::Malformed(format!(
                    "expected {expected:?}, found {other:?}"
                ))),
            }
        }

        fn parse_value(&mut self) -> Result<Value, DiagError> {
            self.skip_ws();
            match self.chars.peek() {
                Some('{') => self.parse_object(),
                Some('[') => self.parse_array(),
                Some('"') => self.parse_string().map(Value::String),
                Some('t') | Some('f') => self.parse_bool(),
                Some('n') => self.parse_null(),
                Some(c) if c.is_ascii_digit() || *c == '-' => self.parse_number(),
                other => Err(DiagError::Malformed(format!(
                    "unexpected character starting a value: {other:?}"
                ))),
            }
        }

        fn parse_object(&mut self) -> Result<Value, DiagError> {
            self.expect('{')?;
            let mut fields = Vec::new();
            self.skip_ws();
            if self.chars.peek() == Some(&'}') {
                self.chars.next();
                return Ok(Value::Object(fields));
            }
            loop {
                self.skip_ws();
                let key = self.parse_string()?;
                self.skip_ws();
                self.expect(':')?;
                let value = self.parse_value()?;
                fields.push((key, value));
                self.skip_ws();
                match self.chars.next() {
                    Some(',') => continue,
                    Some('}') => break,
                    other => {
                        return Err(DiagError::Malformed(format!(
                            "expected ',' or '}}' in object, found {other:?}"
                        )));
                    }
                }
            }
            Ok(Value::Object(fields))
        }

        fn parse_array(&mut self) -> Result<Value, DiagError> {
            self.expect('[')?;
            let mut items = Vec::new();
            self.skip_ws();
            if self.chars.peek() == Some(&']') {
                self.chars.next();
                return Ok(Value::Array(items));
            }
            loop {
                let value = self.parse_value()?;
                items.push(value);
                self.skip_ws();
                match self.chars.next() {
                    Some(',') => continue,
                    Some(']') => break,
                    other => {
                        return Err(DiagError::Malformed(format!(
                            "expected ',' or ']' in array, found {other:?}"
                        )));
                    }
                }
            }
            Ok(Value::Array(items))
        }

        fn parse_string(&mut self) -> Result<String, DiagError> {
            self.expect('"')?;
            let mut out = String::new();
            loop {
                match self.chars.next() {
                    Some('"') => return Ok(out),
                    Some('\\') => match self.chars.next() {
                        Some('"') => out.push('"'),
                        Some('\\') => out.push('\\'),
                        Some('/') => out.push('/'),
                        Some('n') => out.push('\n'),
                        Some('r') => out.push('\r'),
                        Some('t') => out.push('\t'),
                        Some('b') => out.push('\u{8}'),
                        Some('f') => out.push('\u{c}'),
                        Some('u') => {
                            let mut code = 0u32;
                            for _ in 0..4 {
                                let digit =
                                    self.chars.next().and_then(|c| c.to_digit(16)).ok_or_else(
                                        || DiagError::Malformed("bad \\u escape".to_string()),
                                    )?;
                                code = code * 16 + digit;
                            }
                            let c = char::from_u32(code).ok_or_else(|| {
                                DiagError::Malformed("bad \\u escape".to_string())
                            })?;
                            out.push(c);
                        }
                        other => {
                            return Err(DiagError::Malformed(format!("bad escape: {other:?}")));
                        }
                    },
                    Some(c) => out.push(c),
                    None => return Err(DiagError::Malformed("unterminated string".to_string())),
                }
            }
        }

        fn parse_bool(&mut self) -> Result<Value, DiagError> {
            for expected in ["true", "false"] {
                if self.try_consume(expected) {
                    return Ok(Value::Bool(expected == "true"));
                }
            }
            Err(DiagError::Malformed("expected true or false".to_string()))
        }

        fn parse_null(&mut self) -> Result<Value, DiagError> {
            if self.try_consume("null") {
                Ok(Value::Null)
            } else {
                Err(DiagError::Malformed("expected null".to_string()))
            }
        }

        fn try_consume(&mut self, literal: &str) -> bool {
            let mut clone = self.chars.clone();
            for expected in literal.chars() {
                if clone.next() != Some(expected) {
                    return false;
                }
            }
            self.chars = clone;
            true
        }

        fn parse_number(&mut self) -> Result<Value, DiagError> {
            let mut digits = String::new();
            if self.chars.peek() == Some(&'-') {
                digits.push('-');
                self.chars.next();
            }
            let mut saw_digit = false;
            while matches!(self.chars.peek(), Some(c) if c.is_ascii_digit()) {
                if let Some(c) = self.chars.next() {
                    digits.push(c);
                    saw_digit = true;
                }
            }
            if !saw_digit {
                return Err(DiagError::Malformed("expected a digit".to_string()));
            }
            Ok(Value::Number(digits))
        }
    }
}

/// Renders an [`Addr`] as `"host:port"`, the human-readable form section 7
/// asks for ("IP addresses are kept, because they are the thing being
/// diagnosed"). Falls back to a hex dump of the raw fields for a family
/// this design never produces, so encoding an unexpected `Addr` can never
/// panic or silently drop data.
fn addr_to_json_string(addr: Addr) -> String {
    match addr.to_socket_addr() {
        Some(socket_addr) => socket_addr.to_string(),
        None => format!(
            "family={} bytes={} port={}",
            addr.family,
            hex_encode(&addr.bytes),
            addr.port
        ),
    }
}

/// The inverse of [`addr_to_json_string`] for the `"host:port"` form.
///
/// # Errors
/// Returns [`DiagError::Malformed`] if `s` does not parse as a socket
/// address.
fn addr_from_json_string(s: &str) -> Result<Addr, DiagError> {
    let socket_addr: std::net::SocketAddr = s
        .parse()
        .map_err(|_| DiagError::Malformed(format!("bad address: {s:?}")))?;
    Ok(Addr::from_socket_addr(socket_addr))
}

impl DiagRecord {
    /// Encodes this record as one line of JSON, no trailing newline.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        let mut steps = String::from("[");
        for (i, step) in self.steps.iter().enumerate() {
            if i > 0 {
                steps.push(',');
            }
            steps.push_str(&format!(
                "{{\"step\":\"{}\",\"at_ms\":{},\"outcome\":\"{}\",\"detail\":\"{}\"}}",
                step.step.as_str(),
                step.at_ms,
                step.outcome.as_str(),
                json::escape(&step.detail)
            ));
        }
        steps.push(']');

        let failed_step = match self.failed_step {
            Some(step) => format!("\"{}\"", step.as_str()),
            None => "null".to_string(),
        };

        format!(
            "{{\"attempt\":\"{}\",\"session\":{},\"gate_ms\":{},\"peer\":\"{}\",\
             \"started_at\":\"{}\",\"ended_at\":\"{}\",\"steps\":{},\"failed_step\":{},\
             \"local_observed\":[\"{}\",\"{}\"],\"peer_observed\":\"{}\",\"mapping\":\"{}\",\
             \"gate_carried_traffic\":{},\"gate_bytes\":{},\"path\":\"{}\",\"path_addr\":\"{}\",\
             \"path_rtt_us\":{},\"reason\":\"{}\",\"version\":\"{}\",\"platform\":\"{}\"}}",
            hex_encode(&self.attempt),
            self.session,
            self.gate_ms,
            self.peer.as_hex(),
            rfc3339::format(self.started_at_ms),
            rfc3339::format(self.ended_at_ms),
            steps,
            failed_step,
            addr_to_json_string(self.local_observed[0]),
            addr_to_json_string(self.local_observed[1]),
            addr_to_json_string(self.peer_observed),
            self.mapping.as_str(),
            self.gate_carried_traffic,
            self.gate_bytes,
            self.path.kind_str(),
            addr_to_json_string(self.path.addr()),
            self.path_rtt_us,
            self.reason.as_str(),
            json::escape(&self.version),
            json::escape(&self.platform),
        )
    }

    /// Parses one line of JSON, as produced by [`DiagRecord::to_json_line`],
    /// back into a record.
    ///
    /// # Errors
    /// Returns [`DiagError::Malformed`] if `line` is not valid JSON or does
    /// not match a [`DiagRecord`]'s shape.
    pub fn from_json_line(line: &str) -> Result<Self, DiagError> {
        let value = json::parse(line)?;

        let attempt_hex = value.get("attempt")?.as_str()?;
        let attempt_bytes = hex_decode(attempt_hex)?;
        let attempt: [u8; 16] = attempt_bytes
            .try_into()
            .map_err(|_| DiagError::Malformed("attempt must be 16 bytes".to_string()))?;

        let session = u32::try_from(value.get("session")?.as_u64()?)
            .map_err(|_| DiagError::Malformed("session out of range".to_string()))?;
        let gate_ms = value.get("gate_ms")?.as_u64()?;
        let peer = PeerFingerprint::from_hex(value.get("peer")?.as_str()?)?;
        let started_at_ms = rfc3339::parse(value.get("started_at")?.as_str()?)?;
        let ended_at_ms = rfc3339::parse(value.get("ended_at")?.as_str()?)?;

        let mut steps = Vec::new();
        for item in value.get("steps")?.as_array()? {
            let step = Step::parse_str(item.get("step")?.as_str()?)?;
            let at_ms = item.get("at_ms")?.as_u64()?;
            let outcome = StepOutcome::parse_str(item.get("outcome")?.as_str()?)?;
            let detail = item.get("detail")?.as_str()?.to_string();
            steps.push(StepRecord {
                step,
                at_ms,
                outcome,
                detail,
            });
        }

        let failed_step = match value.get("failed_step")? {
            json::Value::Null => None,
            other => Some(Step::parse_str(other.as_str()?)?),
        };

        let local_observed_raw = value.get("local_observed")?.as_array()?;
        let [first, second] = local_observed_raw else {
            return Err(DiagError::Malformed(
                "local_observed must have exactly two entries".to_string(),
            ));
        };
        let local_observed = [
            addr_from_json_string(first.as_str()?)?,
            addr_from_json_string(second.as_str()?)?,
        ];

        let peer_observed = addr_from_json_string(value.get("peer_observed")?.as_str()?)?;
        let mapping = Mapping::parse_str(value.get("mapping")?.as_str()?)?;
        let gate_carried_traffic = value.get("gate_carried_traffic")?.as_bool()?;
        let gate_bytes = value.get("gate_bytes")?.as_u64()?;

        let path_kind = value.get("path")?.as_str()?;
        let path_addr = addr_from_json_string(value.get("path_addr")?.as_str()?)?;
        let path = match path_kind {
            "relay" => PathChoice::Relay(path_addr),
            "direct" => PathChoice::Direct(path_addr),
            other => {
                return Err(DiagError::Malformed(format!(
                    "unknown path kind: {other:?}"
                )));
            }
        };

        let path_rtt_us = u32::try_from(value.get("path_rtt_us")?.as_u64()?)
            .map_err(|_| DiagError::Malformed("path_rtt_us out of range".to_string()))?;
        let reason = Reason::parse_str(value.get("reason")?.as_str()?)?;
        let version = value.get("version")?.as_str()?.to_string();
        let platform = value.get("platform")?.as_str()?.to_string();

        Ok(DiagRecord {
            attempt,
            session,
            gate_ms,
            peer,
            started_at_ms,
            ended_at_ms,
            steps,
            failed_step,
            local_observed,
            peer_observed,
            mapping,
            gate_carried_traffic,
            gate_bytes,
            path,
            path_rtt_us,
            reason,
            version,
            platform,
        })
    }
}

// ---------------------------------------------------------------------
// The writer
// ---------------------------------------------------------------------

/// The cap on one day's diagnostics file, section 7: "5 MiB per file".
///
/// Section 7 gives no rule for a day whose records exceed this before the
/// day ends, and the file naming scheme (`YYYY-MM-DD.jsonl`, one per day)
/// leaves no room for a second file the same day. This writer's documented
/// choice: once a day's file has reached the cap, further records for that
/// day are dropped (silently, from the writer's point of view; a caller may
/// count drops if it wants to) rather than started in a new file, so a
/// day's diagnostics never exceed the cap that makes the file cheap to
/// attach to an issue.
pub const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// The number of day files kept, section 7: "7 files kept". Enforced by
/// [`DiagWriter`] deleting the oldest file by name (the `YYYY-MM-DD.jsonl`
/// naming sorts chronologically) whenever a new day's file is opened and
/// more than this many already exist.
pub const MAX_FILES_KEPT: usize = 7;

/// Appends [`DiagRecord`]s to `<dir>/<YYYY-MM-DD>.jsonl`, rotating to a new
/// file when the UTC day changes and pruning to [`MAX_FILES_KEPT`] files,
/// per section 7's "Location" paragraph.
///
/// Buffering is bounded and simple: each record is written and flushed
/// before [`DiagWriter::append`] returns, so a crash loses at most the
/// record currently being appended, never an earlier one sitting in an
/// unflushed buffer. The "bounded" part is the [`std::io::BufWriter`]'s
/// fixed 8 KiB internal capacity, comfortably larger than one record's
/// typical encoded size, kept only to batch the underlying `write` syscall
/// for a multi-write encoding; the `flush` call after every record is what
/// actually bounds data loss, not the buffer size.
pub struct DiagWriter {
    dir: PathBuf,
    open_date: Option<String>,
    file: Option<std::io::BufWriter<std::fs::File>>,
    bytes_written: u64,
}

impl DiagWriter {
    /// Opens a writer rooted at `dir`, creating it if it does not exist.
    /// No file is opened until the first [`DiagWriter::append`] call, so
    /// constructing a writer that is never used creates nothing.
    ///
    /// # Errors
    /// Returns [`DiagError::Io`] if `dir` cannot be created.
    pub fn new(dir: PathBuf) -> Result<Self, DiagError> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            open_date: None,
            file: None,
            bytes_written: 0,
        })
    }

    /// Appends `record`, rotating to a new day's file if `now_ms` (the
    /// caller's clock, injected rather than read from `SystemTime` here so
    /// rotation is testable without waiting for a real day to change) falls
    /// on a different UTC day than the currently open file.
    ///
    /// Returns `Ok(true)` if the record was written, `Ok(false)` if it was
    /// dropped because the day's file has reached [`MAX_FILE_BYTES`] (see
    /// that constant's doc comment for why dropping, not a second file, is
    /// this writer's choice).
    ///
    /// # Errors
    /// Returns [`DiagError::Io`] if opening or writing the file fails.
    pub fn append(&mut self, record: &DiagRecord, now_ms: u64) -> Result<bool, DiagError> {
        let today = rfc3339::date_only(now_ms);
        if self.open_date.as_deref() != Some(today.as_str()) {
            self.rotate(&today)?;
        }

        let mut line = record.to_json_line();
        line.push('\n');
        let line_len = u64::try_from(line.len()).unwrap_or(u64::MAX);

        if self.bytes_written.saturating_add(line_len) > MAX_FILE_BYTES {
            return Ok(false);
        }

        let Some(file) = self.file.as_mut() else {
            return Err(DiagError::Malformed(
                "diagnostics file not open after rotation".to_string(),
            ));
        };
        use std::io::Write;
        file.write_all(line.as_bytes())?;
        file.flush()?;
        self.bytes_written = self.bytes_written.saturating_add(line_len);
        Ok(true)
    }

    /// Closes the currently open file (if any), prunes old day files beyond
    /// [`MAX_FILES_KEPT`], and opens (or reopens, in append mode) `today`'s
    /// file.
    fn rotate(&mut self, today: &str) -> Result<(), DiagError> {
        self.file = None;

        self.prune(today)?;

        let path = self.dir.join(format!("{today}.jsonl"));
        let mut open_options = std::fs::OpenOptions::new();
        open_options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_options.mode(0o600);
        }
        let file = open_options.open(&path)?;
        let existing_len = file.metadata().map(|m| m.len()).unwrap_or(0);

        self.file = Some(std::io::BufWriter::new(file));
        self.open_date = Some(today.to_string());
        self.bytes_written = existing_len;
        Ok(())
    }

    /// Deletes the oldest `*.jsonl` day files in `self.dir` so that, once
    /// `today`'s file is created, at most [`MAX_FILES_KEPT`] remain.
    fn prune(&self, today: &str) -> Result<(), DiagError> {
        let mut day_files: Vec<String> = std::fs::read_dir(&self.dir)?
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.ends_with(".jsonl"))
            .collect();
        day_files.sort();

        // `today` counts toward the cap whether or not its file exists yet.
        let mut names: Vec<String> = day_files
            .into_iter()
            .filter(|name| name != &format!("{today}.jsonl"))
            .collect();
        names.push(format!("{today}.jsonl"));
        names.sort();

        let to_remove = names.len().saturating_sub(MAX_FILES_KEPT);
        for name in names.into_iter().take(to_remove) {
            let path = self.dir.join(name);
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// The reader
// ---------------------------------------------------------------------

/// One line's outcome when reading a diagnostics file back.
#[derive(Debug)]
pub enum ReadOutcome {
    /// The line parsed into a record.
    Record(DiagRecord),
    /// The line (1-indexed) did not parse; the file's remaining lines are
    /// still read.
    Malformed {
        line_number: usize,
        error: DiagError,
    },
}

/// Reads every line of `path`, parsing each into a [`DiagRecord`]. A
/// malformed line is reported as [`ReadOutcome::Malformed`] rather than
/// stopping the read: the file is a log, and one bad line (a torn write
/// from a crash, for instance) must not hide every record around it.
///
/// # Errors
/// Returns [`DiagError::Io`] if `path` cannot be opened or read.
pub fn read_records(path: &Path) -> Result<Vec<ReadOutcome>, DiagError> {
    let contents = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for (i, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match DiagRecord::from_json_line(line) {
            Ok(record) => out.push(ReadOutcome::Record(record)),
            Err(error) => out.push(ReadOutcome::Malformed {
                line_number: i + 1,
                error,
            }),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Per-platform location
// ---------------------------------------------------------------------

/// The platform a diagnostics directory is being resolved for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetPlatform {
    /// `$XDG_STATE_HOME/mosschat/diagnostics/`, default
    /// `~/.local/state/mosschat/diagnostics/`.
    Linux,
    /// `~/Library/Logs/mosschat/`.
    MacOs,
    /// `%LOCALAPPDATA%\mosschat\diagnostics\`.
    Windows,
}

/// The environment inputs [`diagnostics_dir`] needs, injected rather than
/// read from `std::env`/`dirs` so the resolver is testable for all three
/// platforms from any host.
#[derive(Debug, Clone, Copy)]
pub struct LocationEnv<'a> {
    /// The user's home directory.
    pub home: &'a Path,
    /// `$XDG_STATE_HOME`, if set (Linux only).
    pub xdg_state_home: Option<&'a Path>,
    /// `%LOCALAPPDATA%`, if set (Windows only).
    pub local_appdata: Option<&'a Path>,
}

/// Resolves the diagnostics directory for `platform` given `env`, per
/// section 7's "Location" paragraph. Does not create the directory;
/// [`DiagWriter::new`] does that.
#[must_use]
pub fn diagnostics_dir(platform: TargetPlatform, env: &LocationEnv<'_>) -> PathBuf {
    match platform {
        TargetPlatform::Linux => {
            let base = env
                .xdg_state_home
                .map(Path::to_path_buf)
                .unwrap_or_else(|| env.home.join(".local").join("state"));
            base.join("mosschat").join("diagnostics")
        }
        TargetPlatform::MacOs => env.home.join("Library").join("Logs").join("mosschat"),
        TargetPlatform::Windows => {
            let base = env
                .local_appdata
                .map(Path::to_path_buf)
                .unwrap_or_else(|| env.home.join("AppData").join("Local"));
            base.join("mosschat").join("diagnostics")
        }
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

    fn sample_addr(port: u16) -> Addr {
        Addr::from_socket_addr(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7)),
            port,
        ))
    }

    fn sample_record(reason: Reason, failed_step: Option<Step>) -> DiagRecord {
        DiagRecord {
            attempt: [7u8; 16],
            session: 42,
            gate_ms: 123_456,
            peer: PeerFingerprint::from_key(b"install-salt-16b", &[9u8; 32]),
            started_at_ms: 1_700_000_000_000,
            ended_at_ms: 1_700_000_001_500,
            steps: vec![StepRecord {
                step: Step::GateDial,
                at_ms: 0,
                outcome: StepOutcome::Ok,
                detail: "connected".to_string(),
            }],
            failed_step,
            local_observed: [sample_addr(51_820), sample_addr(51_821)],
            peer_observed: sample_addr(51_822),
            mapping: Mapping::EndpointIndependent,
            gate_carried_traffic: true,
            gate_bytes: 4096,
            path: PathChoice::Direct(sample_addr(51_823)),
            path_rtt_us: 15_000,
            reason,
            version: "0.1.0".to_string(),
            platform: "linux".to_string(),
        }
    }

    // --- record round trip -------------------------------------------------

    #[test]
    fn full_record_round_trips_through_json() {
        let record = sample_record(Reason::Ok, None);
        let line = record.to_json_line();
        let parsed = DiagRecord::from_json_line(&line).unwrap();
        assert_eq!(record, parsed);
    }

    #[test]
    fn every_step_can_be_recorded_as_the_failed_step() {
        for step in Step::ALL {
            let mut record = sample_record(Reason::Internal, Some(step));
            record.steps.push(StepRecord {
                step,
                at_ms: 10,
                outcome: StepOutcome::Fail,
                detail: "forced failure".to_string(),
            });
            let line = record.to_json_line();
            let parsed = DiagRecord::from_json_line(&line).unwrap();
            assert_eq!(
                parsed.failed_step,
                Some(step),
                "step {step:?} not preserved"
            );
            assert!(
                parsed
                    .steps
                    .iter()
                    .any(|s| s.step == step && s.outcome == StepOutcome::Fail),
                "no failing step entry naming {step:?}"
            );
        }
    }

    #[test]
    fn every_reason_round_trips() {
        for reason in Reason::ALL {
            let record = sample_record(reason, None);
            let parsed = DiagRecord::from_json_line(&record.to_json_line()).unwrap();
            assert_eq!(parsed.reason, reason);
        }
    }

    // --- reader skips malformed lines ---------------------------------------

    #[test]
    fn malformed_line_in_the_middle_does_not_lose_the_others() {
        let dir =
            std::env::temp_dir().join(format!("jerome14-diag-malformed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("2026-09-07.jsonl");

        let first = sample_record(Reason::Ok, None).to_json_line();
        let third = sample_record(Reason::UdpBlocked, None).to_json_line();
        let contents = format!("{first}\nthis line is not json at all\n{third}\n");
        std::fs::write(&path, contents).unwrap();

        let outcomes = read_records(&path).unwrap();
        assert_eq!(outcomes.len(), 3);
        assert!(matches!(outcomes[0], ReadOutcome::Record(_)));
        assert!(matches!(
            outcomes[1],
            ReadOutcome::Malformed { line_number: 2, .. }
        ));
        assert!(matches!(outcomes[2], ReadOutcome::Record(_)));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // --- redaction -----------------------------------------------------------

    #[test]
    fn peer_fingerprint_cannot_structurally_hold_a_full_key() {
        // The type is 4 bytes; an ed25519 public or private key is 32. No
        // key can be losslessly stored in it, only a hash prefix computed
        // from one and immediately discarded, and `from_key` is the only
        // public constructor: there is no `From<[u8; 32]>` or field
        // accessor that could place raw key bytes into a `DiagRecord`.
        assert_eq!(std::mem::size_of::<PeerFingerprint>(), 4);
    }

    #[test]
    fn peer_fingerprint_differs_from_the_key_it_was_built_from() {
        let key = [0xABu8; 32];
        let fp = PeerFingerprint::from_key(b"salt", &key);
        // The fingerprint's hex is 8 characters; the key's would be 64.
        // They cannot be equal, and the fingerprint never contains a
        // contiguous run of the key's bytes because it is a keyed hash
        // output, not a slice of the input.
        assert_eq!(fp.as_hex().len(), 8);
        assert_ne!(fp.as_hex(), hex_encode(&key));
    }

    #[test]
    fn record_json_never_contains_the_raw_peer_key() {
        let key = [0x42u8; 32];
        let mut record = sample_record(Reason::Ok, None);
        record.peer = PeerFingerprint::from_key(b"another-salt-val", &key);
        let line = record.to_json_line();
        assert!(!line.contains(&hex_encode(&key)));
    }

    // --- per-platform location -------------------------------------------

    #[test]
    fn linux_location_defaults_under_home_when_xdg_state_home_unset() {
        let home = PathBuf::from("/home/toby");
        let env = LocationEnv {
            home: &home,
            xdg_state_home: None,
            local_appdata: None,
        };
        let dir = diagnostics_dir(TargetPlatform::Linux, &env);
        assert_eq!(
            dir,
            PathBuf::from("/home/toby/.local/state/mosschat/diagnostics")
        );
    }

    #[test]
    fn linux_location_honours_xdg_state_home_when_set() {
        let home = PathBuf::from("/home/toby");
        let xdg = PathBuf::from("/mnt/state");
        let env = LocationEnv {
            home: &home,
            xdg_state_home: Some(&xdg),
            local_appdata: None,
        };
        let dir = diagnostics_dir(TargetPlatform::Linux, &env);
        assert_eq!(dir, PathBuf::from("/mnt/state/mosschat/diagnostics"));
    }

    #[test]
    fn macos_location_is_under_library_logs() {
        let home = PathBuf::from("/Users/toby");
        let env = LocationEnv {
            home: &home,
            xdg_state_home: None,
            local_appdata: None,
        };
        let dir = diagnostics_dir(TargetPlatform::MacOs, &env);
        assert_eq!(dir, PathBuf::from("/Users/toby/Library/Logs/mosschat"));
    }

    #[test]
    fn windows_location_defaults_under_home_when_local_appdata_unset() {
        let home = PathBuf::from(r"C:\Users\toby");
        let env = LocationEnv {
            home: &home,
            xdg_state_home: None,
            local_appdata: None,
        };
        let dir = diagnostics_dir(TargetPlatform::Windows, &env);
        assert_eq!(
            dir,
            PathBuf::from(r"C:\Users\toby")
                .join("AppData")
                .join("Local")
                .join("mosschat")
                .join("diagnostics")
        );
    }

    #[test]
    fn windows_location_honours_local_appdata_when_set() {
        let home = PathBuf::from(r"C:\Users\toby");
        let local_appdata = PathBuf::from(r"D:\LocalAppData");
        let env = LocationEnv {
            home: &home,
            xdg_state_home: None,
            local_appdata: Some(&local_appdata),
        };
        let dir = diagnostics_dir(TargetPlatform::Windows, &env);
        assert_eq!(
            dir,
            PathBuf::from(r"D:\LocalAppData")
                .join("mosschat")
                .join("diagnostics")
        );
    }

    // --- writer: rotation and the size cap ---------------------------------

    #[test]
    fn writer_rotates_to_a_new_file_when_the_utc_day_changes() {
        let dir = std::env::temp_dir().join(format!("jerome14-diag-rotate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut writer = DiagWriter::new(dir.clone()).unwrap();

        let day_one_ms = rfc3339::parse("2026-09-07T00:00:00.000Z").unwrap();
        let day_two_ms = rfc3339::parse("2026-09-08T00:00:00.000Z").unwrap();

        let record = sample_record(Reason::Ok, None);
        assert!(writer.append(&record, day_one_ms).unwrap());
        assert!(writer.append(&record, day_two_ms).unwrap());

        assert!(dir.join("2026-09-07.jsonl").exists());
        assert!(dir.join("2026-09-08.jsonl").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn writer_prunes_to_max_files_kept() {
        let dir = std::env::temp_dir().join(format!("jerome14-diag-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut writer = DiagWriter::new(dir.clone()).unwrap();
        let record = sample_record(Reason::Ok, None);

        for day in 1..=(MAX_FILES_KEPT + 3) {
            let ts = format!("2026-09-{day:02}T00:00:00.000Z");
            let ms = rfc3339::parse(&ts).unwrap();
            assert!(writer.append(&record, ms).unwrap());
        }

        let remaining: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        assert_eq!(remaining.len(), MAX_FILES_KEPT);
        // The most recent day must have survived pruning.
        assert!(remaining.contains(&format!("2026-09-{:02}.jsonl", MAX_FILES_KEPT + 3)));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn writer_drops_records_once_the_days_file_reaches_the_size_cap() {
        let dir = std::env::temp_dir().join(format!("jerome14-diag-size-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut writer = DiagWriter::new(dir.clone()).unwrap();

        let mut record = sample_record(Reason::Ok, None);
        // A large detail string so a handful of records blow past a tiny
        // artificial cap without needing to write 5 MiB in a test.
        record.steps[0].detail = "x".repeat(1024);
        let now_ms = rfc3339::parse("2026-09-07T00:00:00.000Z").unwrap();

        // Force the writer past MAX_FILE_BYTES by writing directly to the
        // day's file before the writer ever opens it, so the very first
        // `append` call already sees a file at the cap.
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("2026-09-07.jsonl");
        std::fs::write(&path, vec![b'a'; MAX_FILE_BYTES as usize]).unwrap();

        let wrote = writer.append(&record, now_ms).unwrap();
        assert!(
            !wrote,
            "a record must be dropped once the day's file is at the cap"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn writer_writes_records_under_the_size_cap() {
        let dir =
            std::env::temp_dir().join(format!("jerome14-diag-size-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut writer = DiagWriter::new(dir.clone()).unwrap();
        let record = sample_record(Reason::Ok, None);
        let now_ms = rfc3339::parse("2026-09-07T00:00:00.000Z").unwrap();

        assert!(writer.append(&record, now_ms).unwrap());

        let outcomes = read_records(&dir.join("2026-09-07.jsonl")).unwrap();
        assert_eq!(outcomes.len(), 1);
        assert!(matches!(outcomes[0], ReadOutcome::Record(_)));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // --- hex round trip ------------------------------------------------------

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 2, 253, 254, 255];
        let encoded = hex_encode(&bytes);
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn rfc3339_round_trips() {
        let ms = 1_700_000_123_456;
        let formatted = rfc3339::format(ms);
        let parsed = rfc3339::parse(&formatted).unwrap();
        assert_eq!(parsed, ms);
    }
}
