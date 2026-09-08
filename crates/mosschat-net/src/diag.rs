//! The diagnostics record, its writer, its reader and the redaction rule of
//! `docs/dev/gatehouse-design.md` section 7 (decision 22, invariant 12).
//!
//! One [`DiagRecord`] is written per connection attempt, whether it
//! succeeded, degraded or failed. Records are appended one JSON object per
//! line to a file named for the UTC day, because a person reads this file
//! and pastes it into an issue (section 7's own reason for JSON over CBOR).
//! Dates are formatted with `time` and JSON with `serde_json`, both already
//! present in this workspace's dependency graph before this crate named
//! them directly (Konrad's review of PR #28: the earlier hand-rolled
//! versions duplicated a compiled-in crate and, in the JSON parser's case,
//! had no recursion depth cap).
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

/// Creates the directory at `dir` if it does not exist and sets it to mode
/// `0700` on Unix (no-op on other platforms): both [`InstallSalt`] and
/// [`DiagWriter`] write files here that must not be world- or group-
/// readable, the salt because it defeats redaction if read by another
/// account and the log because it carries IP addresses.
fn ensure_private_dir(dir: &Path) -> Result<(), DiagError> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Opens `path` for exclusive private writing (create, truncate, write),
/// mode `0600` on Unix, set both at creation and unconditionally
/// afterwards so a file that already existed under a looser mode (from a
/// build before this rule) is corrected rather than left as it was.
fn create_private_file(path: &Path) -> Result<std::fs::File, DiagError> {
    let mut open_options = std::fs::OpenOptions::new();
    open_options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.mode(0o600);
    }
    let file = open_options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Opens `path` for private append (create if absent, never truncate),
/// mode `0600` on Unix, same unconditional-correction rule as
/// [`create_private_file`].
fn open_private_append(path: &Path) -> Result<std::fs::File, DiagError> {
    let mut open_options = std::fs::OpenOptions::new();
    open_options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.mode(0o600);
    }
    let file = open_options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// 16 random bytes generated once per install and stored beside the
/// diagnostics log (section 7), used to salt every [`PeerFingerprint`] so
/// the same peer's fingerprint cannot be correlated across two different
/// installs.
///
/// The only ways to obtain one are [`InstallSalt::load_or_create`], which
/// reads a persisted salt or generates and persists a fresh one with the OS
/// CSPRNG, and, in this module's own tests, that same function against a
/// temporary directory. There is no constructor taking caller-supplied
/// bytes, so `b""` (Konrad's review, PR #28 finding 1) cannot compile: the
/// type is a fixed 16 byte array, structurally incapable of holding zero
/// bytes, and its value is never logged (no `Display`, no `Debug` deriving
/// through to the bytes; `Debug` below prints only the type name).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InstallSalt([u8; 16]);

impl fmt::Debug for InstallSalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstallSalt(..)")
    }
}

impl InstallSalt {
    /// The file name the salt is persisted under, beside the diagnostics
    /// log files in the same directory.
    const FILE_NAME: &'static str = "install_salt";

    /// Loads the salt at `dir/install_salt` if it exists and is exactly 16
    /// bytes; otherwise generates 16 bytes from the OS CSPRNG, persists
    /// them there (mode `0600`, directory mode `0700`), and returns those.
    ///
    /// # Errors
    /// Returns [`DiagError::Io`] if `dir` cannot be created or the salt
    /// file cannot be read or written, or [`DiagError::Malformed`] if a
    /// salt file exists but is not exactly 16 bytes.
    pub fn load_or_create(dir: &Path) -> Result<Self, DiagError> {
        ensure_private_dir(dir)?;
        let path = dir.join(Self::FILE_NAME);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let array: [u8; 16] = bytes.try_into().map_err(|_| {
                    DiagError::Malformed(format!(
                        "install salt at {} is not exactly 16 bytes",
                        path.display()
                    ))
                })?;
                Ok(Self(array))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                use rand::RngExt;
                let mut bytes = [0u8; 16];
                rand::rng().fill(&mut bytes);
                use std::io::Write;
                create_private_file(&path)?.write_all(&bytes)?;
                Ok(Self(bytes))
            }
            Err(e) => Err(DiagError::Io(e)),
        }
    }

    /// The salt's raw bytes, for [`PeerFingerprint::from_key`] alone.
    fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// A public key, reduced to a short fingerprint fit to appear in a
/// diagnostics record.
///
/// Section 7's redaction rule is enforced structurally rather than by
/// convention: this type is 4 bytes wide, so it cannot losslessly hold a 32
/// byte ed25519 key, and its only constructor is [`PeerFingerprint::from_key`],
/// which consumes a key and an [`InstallSalt`] and returns only a keyed
/// hash prefix; the key itself is never retained. There is no
/// `From<[u8; 32]>` or other conversion that could place raw key bytes into
/// a [`DiagRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerFingerprint([u8; 4]);

impl PeerFingerprint {
    /// Computes the fingerprint of `key`, salted with `salt` (section 7),
    /// as the first 4 bytes (8 hex characters) of `BLAKE3(salt || key)`.
    #[must_use]
    pub fn from_key(salt: &InstallSalt, key: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(salt.as_bytes());
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
    /// only text meant to be read. Truncated at [`MAX_FREE_TEXT_LEN`] bytes
    /// when written ([`cap_text`], used by `to_json_line`).
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
    /// The running mosschat version. Truncated at [`MAX_FREE_TEXT_LEN`]
    /// bytes when written.
    pub version: String,
    /// The running platform (`"linux"`, `"macos"`, `"windows"`). Truncated
    /// at [`MAX_FREE_TEXT_LEN`] bytes when written.
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

/// RFC 3339 UTC timestamps via `time` (Konrad's review of PR #28: `time`
/// 0.3.55 was already compiled into this binary transitively through
/// x509-parser and rcgen, so the 130 lines of hand-rolled civil-calendar
/// math this module replaced duplicated a crate already in the tree).
mod rfc3339 {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    use super::DiagError;

    /// The fallback timestamp used only on the practically unreachable
    /// path where `epoch_ms` cannot be represented (library code never
    /// panics, invariant 1): the Unix epoch itself, unmistakably wrong to
    /// a reader rather than silently plausible.
    const EPOCH_FALLBACK: &str = "1970-01-01T00:00:00Z";

    /// Formats `epoch_ms` (milliseconds since the Unix epoch, never
    /// negative in this codebase, see `now_ms` in `gate/mod.rs`) as an RFC
    /// 3339 UTC timestamp.
    #[must_use]
    pub fn format(epoch_ms: u64) -> String {
        let nanos = i128::from(epoch_ms) * 1_000_000;
        OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .ok()
            .and_then(|dt| dt.format(&Rfc3339).ok())
            .unwrap_or_else(|| EPOCH_FALLBACK.to_string())
    }

    /// Parses an RFC 3339 UTC timestamp back to milliseconds since the
    /// Unix epoch.
    ///
    /// # Errors
    /// Returns [`DiagError::Malformed`] if `s` is not a valid RFC 3339
    /// timestamp, or names a time before the Unix epoch.
    pub fn parse(s: &str) -> Result<u64, DiagError> {
        let dt = OffsetDateTime::parse(s, &Rfc3339)
            .map_err(|e| DiagError::Malformed(format!("bad RFC 3339 timestamp {s:?}: {e}")))?;
        let nanos = dt.unix_timestamp_nanos();
        if nanos < 0 {
            return Err(DiagError::Malformed(format!(
                "timestamp before the Unix epoch: {s:?}"
            )));
        }
        u64::try_from(nanos / 1_000_000)
            .map_err(|_| DiagError::Malformed(format!("timestamp out of range: {s:?}")))
    }

    /// The `YYYY-MM-DD` UTC date `epoch_ms` falls on, used to name a day's
    /// diagnostics file.
    #[must_use]
    pub fn date_only(epoch_ms: u64) -> String {
        let nanos = i128::from(epoch_ms) * 1_000_000;
        match OffsetDateTime::from_unix_timestamp_nanos(nanos) {
            Ok(dt) => format!(
                "{:04}-{:02}-{:02}",
                dt.year(),
                u8::from(dt.month()),
                dt.day()
            ),
            Err(_) => "1970-01-01".to_string(),
        }
    }
}

// ---------------------------------------------------------------------
// JSON via serde_json
// ---------------------------------------------------------------------

/// The length free-text fields (`detail`, `version`, `platform`) are capped
/// at before being written, so a caller that accidentally formats secret
/// bytes into one of them (Konrad's review of PR #28, should 5: "a 1.4b
/// caller formatting an error over sealed bytes writes them") produces a
/// visibly truncated record rather than a complete leak. Generous against
/// section 7's own wire caps (`Error.detail` 64 bytes, `Introduce.sealed`
/// 512 bytes): an ordinary error message or version string is never cut.
const MAX_FREE_TEXT_LEN: usize = 256;

/// Truncates `s` to at most [`MAX_FREE_TEXT_LEN`] bytes on a `char`
/// boundary, appending a marker so truncation is visible in the record
/// rather than silently changing what it says.
fn cap_text(s: &str) -> std::borrow::Cow<'_, str> {
    if s.len() <= MAX_FREE_TEXT_LEN {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut end = MAX_FREE_TEXT_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    std::borrow::Cow::Owned(format!("{}...[truncated]", s.get(..end).unwrap_or("")))
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

/// Looks up `key` in a `serde_json::Value` expected to be an object.
///
/// # Errors
/// Returns [`DiagError::Malformed`] if `key` is absent.
fn field<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a serde_json::Value, DiagError> {
    value
        .get(key)
        .ok_or_else(|| DiagError::Malformed(format!("missing field {key:?}")))
}

/// [`field`] plus a string type check.
fn field_str<'a>(value: &'a serde_json::Value, key: &str) -> Result<&'a str, DiagError> {
    field(value, key)?
        .as_str()
        .ok_or_else(|| DiagError::Malformed(format!("field {key:?} is not a string")))
}

/// [`field`] plus an unsigned integer type check.
fn field_u64(value: &serde_json::Value, key: &str) -> Result<u64, DiagError> {
    field(value, key)?
        .as_u64()
        .ok_or_else(|| DiagError::Malformed(format!("field {key:?} is not an unsigned integer")))
}

/// [`field`] plus a bool type check.
fn field_bool(value: &serde_json::Value, key: &str) -> Result<bool, DiagError> {
    field(value, key)?
        .as_bool()
        .ok_or_else(|| DiagError::Malformed(format!("field {key:?} is not a bool")))
}

/// [`field`] plus an array type check.
fn field_array<'a>(
    value: &'a serde_json::Value,
    key: &str,
) -> Result<&'a Vec<serde_json::Value>, DiagError> {
    field(value, key)?
        .as_array()
        .ok_or_else(|| DiagError::Malformed(format!("field {key:?} is not an array")))
}

/// A `serde_json::Value`'s own string type check, for an element that is
/// not itself a named object field (an array entry).
fn as_str(value: &serde_json::Value) -> Result<&str, DiagError> {
    value
        .as_str()
        .ok_or_else(|| DiagError::Malformed(format!("expected a string, found {value:?}")))
}

impl DiagRecord {
    /// Encodes this record as one line of JSON, no trailing newline.
    #[must_use]
    pub fn to_json_line(&self) -> String {
        let steps: Vec<serde_json::Value> = self
            .steps
            .iter()
            .map(|step| {
                serde_json::json!({
                    "step": step.step.as_str(),
                    "at_ms": step.at_ms,
                    "outcome": step.outcome.as_str(),
                    "detail": cap_text(&step.detail),
                })
            })
            .collect();

        let [local_first, local_second] = self.local_observed;

        let value = serde_json::json!({
            "attempt": hex_encode(&self.attempt),
            "session": self.session,
            "gate_ms": self.gate_ms,
            "peer": self.peer.as_hex(),
            "started_at": rfc3339::format(self.started_at_ms),
            "ended_at": rfc3339::format(self.ended_at_ms),
            "steps": steps,
            "failed_step": self.failed_step.map(Step::as_str),
            "local_observed": [
                addr_to_json_string(local_first),
                addr_to_json_string(local_second),
            ],
            "peer_observed": addr_to_json_string(self.peer_observed),
            "mapping": self.mapping.as_str(),
            "gate_carried_traffic": self.gate_carried_traffic,
            "gate_bytes": self.gate_bytes,
            "path": self.path.kind_str(),
            "path_addr": addr_to_json_string(self.path.addr()),
            "path_rtt_us": self.path_rtt_us,
            "reason": self.reason.as_str(),
            "version": cap_text(&self.version),
            "platform": cap_text(&self.platform),
        });

        // `to_string` fails only on a non-finite float or a non-string map
        // key, neither of which this value contains; the fallback is
        // unreachable in practice but keeps this function panic-free
        // (invariant 1) rather than relying on that being true forever.
        serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
    }

    /// Parses one line of JSON, as produced by [`DiagRecord::to_json_line`],
    /// back into a record. Recursion depth is bounded by `serde_json`
    /// itself (its `Value` deserializer errors past 128 levels rather than
    /// overflowing the stack; Konrad's review of PR #28, must 2).
    ///
    /// # Errors
    /// Returns [`DiagError::Malformed`] if `line` is not valid JSON or does
    /// not match a [`DiagRecord`]'s shape.
    pub fn from_json_line(line: &str) -> Result<Self, DiagError> {
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| DiagError::Malformed(format!("invalid JSON: {e}")))?;

        let attempt_hex = field_str(&value, "attempt")?;
        let attempt_bytes = hex_decode(attempt_hex)?;
        let attempt: [u8; 16] = attempt_bytes
            .try_into()
            .map_err(|_| DiagError::Malformed("attempt must be 16 bytes".to_string()))?;

        let session = u32::try_from(field_u64(&value, "session")?)
            .map_err(|_| DiagError::Malformed("session out of range".to_string()))?;
        let gate_ms = field_u64(&value, "gate_ms")?;
        let peer = PeerFingerprint::from_hex(field_str(&value, "peer")?)?;
        let started_at_ms = rfc3339::parse(field_str(&value, "started_at")?)?;
        let ended_at_ms = rfc3339::parse(field_str(&value, "ended_at")?)?;

        let mut steps = Vec::new();
        for item in field_array(&value, "steps")? {
            let step = Step::parse_str(field_str(item, "step")?)?;
            let at_ms = field_u64(item, "at_ms")?;
            let outcome = StepOutcome::parse_str(field_str(item, "outcome")?)?;
            let detail = field_str(item, "detail")?.to_string();
            steps.push(StepRecord {
                step,
                at_ms,
                outcome,
                detail,
            });
        }

        let failed_step = match field(&value, "failed_step")? {
            serde_json::Value::Null => None,
            other => Some(Step::parse_str(as_str(other)?)?),
        };

        let local_observed_raw = field_array(&value, "local_observed")?;
        let (first, second) = match local_observed_raw.as_slice() {
            [first, second] => (first, second),
            _ => {
                return Err(DiagError::Malformed(
                    "local_observed must have exactly two entries".to_string(),
                ));
            }
        };
        let local_observed = [
            addr_from_json_string(as_str(first)?)?,
            addr_from_json_string(as_str(second)?)?,
        ];

        let peer_observed = addr_from_json_string(field_str(&value, "peer_observed")?)?;
        let mapping = Mapping::parse_str(field_str(&value, "mapping")?)?;
        let gate_carried_traffic = field_bool(&value, "gate_carried_traffic")?;
        let gate_bytes = field_u64(&value, "gate_bytes")?;

        let path_kind = field_str(&value, "path")?;
        let path_addr = addr_from_json_string(field_str(&value, "path_addr")?)?;
        let path = match path_kind {
            "relay" => PathChoice::Relay(path_addr),
            "direct" => PathChoice::Direct(path_addr),
            other => {
                return Err(DiagError::Malformed(format!(
                    "unknown path kind: {other:?}"
                )));
            }
        };

        let path_rtt_us = u32::try_from(field_u64(&value, "path_rtt_us")?)
            .map_err(|_| DiagError::Malformed("path_rtt_us out of range".to_string()))?;
        let reason = Reason::parse_str(field_str(&value, "reason")?)?;
        let version = field_str(&value, "version")?.to_string();
        let platform = field_str(&value, "platform")?.to_string();

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

/// The cap on one diagnostics file, section 7: "5 MiB per file".
///
/// Section 7 states no rule for a day whose records exceed this before the
/// day ends (a gap Konrad's review of PR #28, must 3, flagged and asked to
/// be raised with Xavier as a section 7 amendment, tracked separately from
/// this fix). Between this writer's two implementable choices — start a
/// numbered overflow file for the rest of the day, or rewrite the current
/// file dropping its oldest lines — [`DiagWriter`] rotates to an overflow
/// file (`YYYY-MM-DD.1.jsonl`, `.2.jsonl`, ...): the newest records, which
/// describe whatever is currently going wrong, are the ones a person reads
/// this file to see, so they are never the ones dropped. Rewriting the
/// current file in place was rejected: it means reading and rewriting up to
/// 5 MiB on every over-cap append, and a writer killed mid-rewrite leaves a
/// truncated or corrupt file, where every other write in this module is a
/// single `write_all` to the end of a file, safe to interrupt at any point.
pub const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// The number of UTC days of diagnostics files kept, section 7: "7 files
/// kept". Enforced by [`DiagWriter`] deleting every file (the day's primary
/// file and any overflow parts) belonging to the oldest days once more than
/// this many distinct days exist, whenever a new day's file is opened.
pub const MAX_FILES_KEPT: usize = 7;

/// The file name for `date`'s diagnostics file: `part` `0` is the primary
/// file section 7 names (`YYYY-MM-DD.jsonl`); `part` `1` and above are
/// overflow files opened once the previous part reaches [`MAX_FILE_BYTES`]
/// (`YYYY-MM-DD.N.jsonl`, [`MAX_FILE_BYTES`]'s doc comment).
fn file_name_for(date: &str, part: u32) -> String {
    if part == 0 {
        format!("{date}.jsonl")
    } else {
        format!("{date}.{part}.jsonl")
    }
}

/// The `YYYY-MM-DD` day prefix of a diagnostics file name, own or overflow
/// part alike, or `None` if `name` does not start with one (so an unrelated
/// file in the same directory is never touched by pruning).
fn day_prefix(name: &str) -> Option<&str> {
    let candidate = name.get(..10)?;
    let bytes = candidate.as_bytes();
    let is_date_shaped = bytes.len() == 10
        && bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit());
    is_date_shaped.then_some(candidate)
}

/// Appends [`DiagRecord`]s to `<dir>/<YYYY-MM-DD>[.N].jsonl`, rotating to a
/// new file when the UTC day changes or the current file reaches
/// [`MAX_FILE_BYTES`], and pruning to [`MAX_FILES_KEPT`] days, per section
/// 7's "Location" paragraph and [`MAX_FILE_BYTES`]'s doc comment.
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
    open_part: u32,
    file: Option<std::io::BufWriter<std::fs::File>>,
    bytes_written: u64,
}

impl DiagWriter {
    /// Opens a writer rooted at `dir`, creating it (mode `0700` on Unix; it
    /// holds [`InstallSalt`] beside these logs) if it does not exist. No
    /// file is opened until the first [`DiagWriter::append`] call, so
    /// constructing a writer that is never used creates nothing beyond the
    /// directory itself.
    ///
    /// # Errors
    /// Returns [`DiagError::Io`] if `dir` cannot be created.
    pub fn new(dir: PathBuf) -> Result<Self, DiagError> {
        ensure_private_dir(&dir)?;
        Ok(Self {
            dir,
            open_date: None,
            open_part: 0,
            file: None,
            bytes_written: 0,
        })
    }

    /// Appends `record`, rotating to a new day's file if `now_ms` (the
    /// caller's clock, injected rather than read from `SystemTime` here so
    /// rotation is testable without waiting for a real day to change) falls
    /// on a different UTC day than the currently open file, or to the next
    /// overflow part if the current file has reached [`MAX_FILE_BYTES`].
    ///
    /// Always returns `Ok(true)` once the record is written; the return
    /// type stays `Result<bool, DiagError>` rather than `Result<(),
    /// DiagError>` because a record is never silently dropped now
    /// (`MAX_FILE_BYTES`'s doc comment), so `false` would never occur, and
    /// a future caller comparing against it would be dead code — kept as
    /// `bool` anyway so a change back to a dropping policy would not be a
    /// signature change.
    ///
    /// # Errors
    /// Returns [`DiagError::Io`] if opening or writing a file fails.
    pub fn append(&mut self, record: &DiagRecord, now_ms: u64) -> Result<bool, DiagError> {
        let today = rfc3339::date_only(now_ms);
        if self.open_date.as_deref() != Some(today.as_str()) {
            self.rotate_to_day(&today)?;
        }

        let mut line = record.to_json_line();
        line.push('\n');
        let line_len = u64::try_from(line.len()).unwrap_or(u64::MAX);

        if self.bytes_written.saturating_add(line_len) > MAX_FILE_BYTES {
            self.open_next_part()?;
        }

        let Some(file) = self.file.as_mut() else {
            return Err(DiagError::Io(std::io::Error::other(
                "diagnostics file not open after rotation",
            )));
        };
        use std::io::Write;
        file.write_all(line.as_bytes())?;
        file.flush()?;
        self.bytes_written = self.bytes_written.saturating_add(line_len);
        Ok(true)
    }

    /// Closes the currently open file (if any), prunes days beyond
    /// [`MAX_FILES_KEPT`], and opens `today`'s primary file (part `0`),
    /// resuming an existing file's byte count rather than assuming it is
    /// empty, so a writer restarted mid-day rolls to an overflow part at
    /// the right point instead of silently growing past the cap.
    fn rotate_to_day(&mut self, today: &str) -> Result<(), DiagError> {
        self.prune(today)?;
        self.open_date = Some(today.to_string());
        self.open_part = 0;
        self.open_part_file(today, 0)
    }

    /// Closes the currently open file and opens the next overflow part for
    /// the same day.
    fn open_next_part(&mut self) -> Result<(), DiagError> {
        let today = self
            .open_date
            .clone()
            .ok_or_else(|| DiagError::Io(std::io::Error::other("no day open to roll over")))?;
        self.open_part = self.open_part.saturating_add(1);
        self.open_part_file(&today, self.open_part)
    }

    /// Opens (creating if absent, appending if present) `date`'s file for
    /// `part`, resuming `bytes_written` from the file's real size.
    fn open_part_file(&mut self, date: &str, part: u32) -> Result<(), DiagError> {
        self.file = None;
        let path = self.dir.join(file_name_for(date, part));
        let file = open_private_append(&path)?;
        let existing_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        self.file = Some(std::io::BufWriter::new(file));
        self.bytes_written = existing_len;
        Ok(())
    }

    /// Deletes every file (primary and overflow parts alike) belonging to
    /// the oldest UTC days in `self.dir`, so that once `today` is counted
    /// at most [`MAX_FILES_KEPT`] distinct days remain.
    fn prune(&self, today: &str) -> Result<(), DiagError> {
        let mut days: std::collections::BTreeSet<String> = std::fs::read_dir(&self.dir)?
            .filter_map(std::result::Result::ok)
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.ends_with(".jsonl"))
            .filter_map(|name| day_prefix(&name).map(str::to_string))
            .collect();
        days.insert(today.to_string());

        let to_remove = days.len().saturating_sub(MAX_FILES_KEPT);
        for old_day in days.iter().take(to_remove) {
            for entry in std::fs::read_dir(&self.dir)? {
                let entry = entry?;
                let Ok(name) = entry.file_name().into_string() else {
                    continue;
                };
                if day_prefix(&name) == Some(old_day.as_str()) {
                    std::fs::remove_file(entry.path())?;
                }
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

    /// A fresh [`InstallSalt`], persisted under a unique temp directory so
    /// parallel test threads (same process, same `std::process::id()`)
    /// never race on the same salt file.
    fn test_salt() -> InstallSalt {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("jerome14-diag-salt-{}-{n}", std::process::id()));
        InstallSalt::load_or_create(&dir).unwrap()
    }

    fn sample_record(reason: Reason, failed_step: Option<Step>) -> DiagRecord {
        DiagRecord {
            attempt: [7u8; 16],
            session: 42,
            gate_ms: 123_456,
            peer: PeerFingerprint::from_key(&test_salt(), &[9u8; 32]),
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
        let fp = PeerFingerprint::from_key(&test_salt(), &key);
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
        record.peer = PeerFingerprint::from_key(&test_salt(), &key);
        let line = record.to_json_line();
        assert!(!line.contains(&hex_encode(&key)));
    }

    // --- install salt (Konrad's review of PR #28, must 1) -------------------

    #[test]
    fn install_salt_cannot_structurally_be_empty() {
        // A fixed 16 byte array cannot hold zero bytes; `b""` (the review's
        // example of the pre-fix bug) is not an `[u8; 16]` and cannot be
        // passed to any constructor this type has.
        assert_eq!(std::mem::size_of::<InstallSalt>(), 16);
    }

    #[test]
    fn install_salt_persists_and_is_stable_across_loads() {
        let dir = std::env::temp_dir().join(format!(
            "jerome14-diag-installsalt-persist-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let first = InstallSalt::load_or_create(&dir).unwrap();
        let second = InstallSalt::load_or_create(&dir).unwrap();
        assert_eq!(
            first, second,
            "a second load must return the persisted salt, not a fresh one"
        );

        let salt_path = dir.join("install_salt");
        assert!(salt_path.exists());
        assert_eq!(std::fs::read(&salt_path).unwrap().len(), 16);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn install_salt_changes_the_fingerprint() {
        let key = [0x11u8; 32];
        let salt_a = test_salt();
        let salt_b = test_salt();
        let fp_a = PeerFingerprint::from_key(&salt_a, &key);
        let fp_b = PeerFingerprint::from_key(&salt_b, &key);
        assert_ne!(
            fp_a, fp_b,
            "the same key salted differently must fingerprint differently, or a peer would be correlatable across installs"
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_salt_file_and_directory_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "jerome14-diag-installsalt-perms-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        InstallSalt::load_or_create(&dir).unwrap();

        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let file_mode = std::fs::metadata(dir.join("install_salt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);

        std::fs::remove_dir_all(&dir).unwrap();
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
    fn writer_rolls_to_an_overflow_file_instead_of_dropping_the_newest_record() {
        // Konrad's review of PR #28, must 3: the previous version dropped
        // the newest record once a day's file hit the cap. This asserts
        // the replacement never drops: every record appended is present
        // somewhere afterward, split across the primary file and one or
        // more numbered overflow files.
        let dir =
            std::env::temp_dir().join(format!("jerome14-diag-overflow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut writer = DiagWriter::new(dir.clone()).unwrap();
        let now_ms = rfc3339::parse("2026-09-07T00:00:00.000Z").unwrap();

        // Force the writer past MAX_FILE_BYTES on its very first append by
        // writing directly to the day's primary file before the writer
        // ever opens it.
        std::fs::write(
            dir.join("2026-09-07.jsonl"),
            vec![b'a'; MAX_FILE_BYTES as usize],
        )
        .unwrap();

        let mut record = sample_record(Reason::Ok, None);
        record.steps[0].detail = "distinguishing-marker".to_string();

        let wrote = writer.append(&record, now_ms).unwrap();
        assert!(wrote, "append must never report a dropped record");

        let overflow_path = dir.join("2026-09-07.1.jsonl");
        assert!(
            overflow_path.exists(),
            "an overflow part must be created once the primary file is at the cap"
        );
        let outcomes = read_records(&overflow_path).unwrap();
        assert_eq!(outcomes.len(), 1);
        let ReadOutcome::Record(recorded) = &outcomes[0] else {
            panic!("expected the record to parse");
        };
        assert_eq!(recorded.steps[0].detail, "distinguishing-marker");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn writer_resumes_the_correct_part_after_reopening_mid_day() {
        let dir = std::env::temp_dir().join(format!(
            "jerome14-diag-overflow-resume-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let now_ms = rfc3339::parse("2026-09-07T00:00:00.000Z").unwrap();
        let record = sample_record(Reason::Ok, None);

        // The primary file already at the cap and a part-1 file already
        // present, simulating a previous process run that had already
        // rolled over once, before this writer ever opens anything.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("2026-09-07.jsonl"),
            vec![b'a'; MAX_FILE_BYTES as usize],
        )
        .unwrap();
        std::fs::write(dir.join("2026-09-07.1.jsonl"), b"not full yet\n").unwrap();

        let mut writer = DiagWriter::new(dir.clone()).unwrap();
        assert!(writer.append(&record, now_ms).unwrap());

        // The new writer must have appended to the existing part-1 file
        // (which was under the cap), not silently overwritten it and not
        // skipped straight to part 2.
        let part_one = std::fs::read_to_string(dir.join("2026-09-07.1.jsonl")).unwrap();
        assert!(part_one.starts_with("not full yet\n"));
        assert!(!dir.join("2026-09-07.2.jsonl").exists());

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

    // --- JSON parser safety (Konrad's review of PR #28, must 2) -------------

    #[test]
    fn deeply_nested_json_is_reported_as_malformed_not_a_crash() {
        // serde_json's `Value` deserializer errors past a fixed recursion
        // depth rather than overflowing the stack; this is the property
        // that made replacing the hand-rolled parser a `must`, not just a
        // style preference. 10,000 nested arrays comfortably exceeds it.
        let nested = "[".repeat(10_000);
        let result = DiagRecord::from_json_line(&nested);
        assert!(matches!(result, Err(DiagError::Malformed(_))));
    }

    #[test]
    fn detail_holding_a_quote_and_newline_round_trips() {
        let mut record = sample_record(Reason::Ok, None);
        record.steps[0].detail = "line one\nline \"two\"\tend".to_string();
        let line = record.to_json_line();
        let parsed = DiagRecord::from_json_line(&line).unwrap();
        assert_eq!(parsed.steps[0].detail, "line one\nline \"two\"\tend");
    }

    #[test]
    fn free_text_over_the_cap_is_truncated_not_dropped_or_left_whole() {
        let mut record = sample_record(Reason::Ok, None);
        record.version = "v".repeat(MAX_FREE_TEXT_LEN * 2);
        let line = record.to_json_line();
        let parsed = DiagRecord::from_json_line(&line).unwrap();
        assert!(parsed.version.len() < record.version.len());
        assert!(parsed.version.starts_with('v'));
        assert!(parsed.version.ends_with("[truncated]"));
    }
}
