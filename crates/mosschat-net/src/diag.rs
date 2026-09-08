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
use crate::lockext::LockExt as _;

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
    /// Hole punching was switched off for this attempt (`--no-punch`), so
    /// the visit stayed relayed by instruction rather than by failure.
    ///
    /// **Not in section 7's own list; added by WO-1.5a** (design amendment
    /// 4). WO-1.5 case (e) is "the same with the gate reachable but hole
    /// punching forced off", and its record has to say why it relayed in a
    /// word its reader can act on. Every existing reason would have lied:
    /// `probe_timeout` and `no_candidates` name failures that did not
    /// happen, and `internal` is this design's catch-all for a failure it
    /// cannot name, which is the opposite of a path taken on purpose.
    PunchDisabled,
    /// Any failure not named by one of the above.
    Internal,
}

impl Reason {
    /// All variants, in section 7's declared order.
    pub const ALL: [Reason; 21] = [
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
        Reason::PunchDisabled,
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
            Reason::PunchDisabled => "punch_disabled",
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

// ---------------------------------------------------------------------
// Visit events (WO-1.5a, design amendment 4)
// ---------------------------------------------------------------------

/// One thing that happened to a live visit, in the vocabulary a house
/// prints and a record keeps.
///
/// **Why the record needs these beside `steps`** (WO-1.5a). A step says
/// how far one attempt got; WO-1.5 asks what happened to a visit *while it
/// was held open*: when the direct path died, how long detection took, how
/// long the fall-back took after it, and whether the path came back. Two
/// of those are section 4 transitions with no step of their own (stale and
/// dead are both `path_lost`), and none of them can be told apart in a
/// `steps` list that names the same step three times. So an attempt with a
/// held visit carries both: `steps` for how it connected, `events` for
/// what the visit then did.
///
/// The same names are what a headless house prints on stdout, one JSON
/// line each, so a two-machine run's two sides can be read against each
/// other without a translation table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisitEventKind {
    /// A house registered at its gate. House stdout only: a record is per
    /// attempt, and registration precedes every attempt.
    Registered,
    /// A knock arrived from a friend and was accepted. House stdout only,
    /// for the same reason.
    Knock,
    /// The visit is open and carrying traffic, on the path named in the
    /// detail (section 2 step 2: relayed from the first packet).
    VisitOpen,
    /// A candidate proved itself and traffic moved to it (section 2 step
    /// 6), with the winning address and its round trip.
    Upgraded,
    /// Section 4: three consecutive probes unanswered. This is the
    /// *detection*, and the moment the fall-back is decided from.
    PathStale,
    /// Section 4: the stale grace elapsed with no answer, so the path is
    /// dropped and the doorbell reruns.
    PathDead,
    /// Traffic is back on the relay session (section 2 step 7). It follows
    /// [`VisitEventKind::PathStale`] immediately, because section 4 moves
    /// traffic at stale and not at dead; the gap between the two is the
    /// fall-back time the Phase 1 criterion bounds at 1 s on the side that
    /// moved.
    FellBack,
    /// A rerun of the doorbell upgraded again after a fall-back.
    Recovered,
    /// The visit ended cleanly: frame 19 out, in, or both.
    Goodbye,
}

impl VisitEventKind {
    /// All variants, in the order a visit produces them.
    pub const ALL: [VisitEventKind; 9] = [
        VisitEventKind::Registered,
        VisitEventKind::Knock,
        VisitEventKind::VisitOpen,
        VisitEventKind::Upgraded,
        VisitEventKind::PathStale,
        VisitEventKind::PathDead,
        VisitEventKind::FellBack,
        VisitEventKind::Recovered,
        VisitEventKind::Goodbye,
    ];

    /// The `snake_case` spelling used in the record and on a house's
    /// stdout.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            VisitEventKind::Registered => "registered",
            VisitEventKind::Knock => "knock",
            VisitEventKind::VisitOpen => "visit_open",
            VisitEventKind::Upgraded => "upgraded",
            VisitEventKind::PathStale => "path_stale",
            VisitEventKind::PathDead => "path_dead",
            VisitEventKind::FellBack => "fell_back",
            VisitEventKind::Recovered => "recovered",
            VisitEventKind::Goodbye => "goodbye",
        }
    }

    /// Parses the `snake_case` spelling back.
    ///
    /// # Errors
    /// Returns [`DiagError::Malformed`] if `s` names no known event.
    pub fn parse_str(s: &str) -> Result<Self, DiagError> {
        VisitEventKind::ALL
            .into_iter()
            .find(|kind| kind.as_str() == s)
            .ok_or_else(|| DiagError::Malformed(format!("unknown visit event: {s:?}")))
    }
}

/// One entry of [`DiagRecord::events`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisitEvent {
    /// What happened.
    pub event: VisitEventKind,
    /// Milliseconds since the attempt started, the same clock
    /// [`StepRecord::at_ms`] uses, so the two lists interleave.
    pub at_ms: u64,
    /// Free text: the path, the winning address, the round trip. Capped at
    /// [`MAX_FREE_TEXT_LEN`] bytes when written, exactly as a step's is.
    pub detail: String,
}

/// Where a visit's round trip samples came from, so a median is read as
/// what it is.
///
/// The two sources are not interchangeable and are deliberately not
/// averaged into one nameless number: a probe round trip is this design's
/// own measurement of one path (section 3, "RTT, out of quinn's hands"),
/// while quinn's is the end to end connection's smoothed estimate over
/// whatever path carries it, updated by its own 15 s keepalive rather than
/// once a second, so consecutive samples of it repeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RttSource {
    /// No sample was taken: the visit was never held open.
    #[default]
    NotSampled,
    /// Every sample is a probe pong round trip on a direct path.
    Probe,
    /// Every sample is `quinn::Connection::rtt()` on a relayed visit,
    /// which is the only end to end number a relayed path has: probes go
    /// to a candidate address, and a relayed peer has none.
    Quic,
    /// Both, because the path changed during the hold. The events say
    /// when.
    Mixed,
}

impl RttSource {
    /// The JSON representation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RttSource::NotSampled => "not_sampled",
            RttSource::Probe => "probe",
            RttSource::Quic => "quic",
            RttSource::Mixed => "mixed",
        }
    }

    /// Parses the JSON representation back.
    ///
    /// # Errors
    /// Returns [`DiagError::Malformed`] if `s` names no known source.
    pub fn parse_str(s: &str) -> Result<Self, DiagError> {
        match s {
            "not_sampled" => Ok(RttSource::NotSampled),
            "probe" => Ok(RttSource::Probe),
            "quic" => Ok(RttSource::Quic),
            "mixed" => Ok(RttSource::Mixed),
            other => Err(DiagError::Malformed(format!(
                "unknown rtt source: {other:?}"
            ))),
        }
    }

    /// The source of a set of samples that already had `self` and then
    /// took one from `next`.
    #[must_use]
    pub fn joined(self, next: RttSource) -> RttSource {
        match (self, next) {
            (RttSource::NotSampled, other) | (other, RttSource::NotSampled) => other,
            (a, b) if a == b => a,
            _ => RttSource::Mixed,
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

    /// A salt for this process alone: 16 bytes from the OS CSPRNG,
    /// written nowhere.
    ///
    /// For a caller with no state directory to persist one in (a headless
    /// house told to keep no diagnostics log). It keeps the property that
    /// matters within one run, one peer being named consistently, and
    /// gives up the one that needs a file, the same peer being named the
    /// same way after a restart. Still no caller-supplied bytes: the only
    /// two ways to obtain an [`InstallSalt`] are this and
    /// [`InstallSalt::load_or_create`], and neither takes any.
    #[must_use]
    pub fn ephemeral() -> Self {
        use rand::RngExt;
        let mut bytes = [0u8; 16];
        rand::rng().fill(&mut bytes);
        Self(bytes)
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
    /// Every visit event, in order (WO-1.5a, design amendment 4). Empty
    /// for an attempt that never held a visit open, which is every
    /// attempt written before that order landed.
    pub events: Vec<VisitEvent>,
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
    /// Bytes this house handed to the relay leg for this peer: its own
    /// egress, not both directions (Konrad's should 6 on PR #49). The
    /// shaper counts what enters its queue, and only the sending side
    /// queues; the other direction's bytes are in the peer's own record.
    pub gate_bytes: u64,
    /// Section 1's shaper, first counter: datagrams that waited in a relay
    /// queue. Added in WO-1.4b, which is the first order with a call site
    /// that can read them ([`Recorder::relay_stats`]); WO-1.4a's record
    /// carried section 7's `gate_carried_traffic` and `gate_bytes` but not
    /// the three counters beside them in the same table row, so this is an
    /// additive format change and `from_json_line` reads a record written
    /// without them as zeroes rather than refusing it.
    pub relay_queued: u64,
    /// Section 1's shaper: the median time a relayed datagram waited, in
    /// microseconds.
    pub relay_shaped_delay_p50_us: u64,
    /// Section 1's shaper: the longest a relayed datagram waited, in
    /// microseconds.
    pub relay_shaped_delay_max_us: u64,
    /// Section 1's shaper: datagrams dropped on a full queue. 0 for a
    /// shaping house.
    pub relay_dropped_at_full: u64,
    /// The path chosen and the address it uses.
    pub path: PathChoice,
    /// The chosen path's round trip time in microseconds.
    pub path_rtt_us: u32,
    /// The median round trip over a held visit, in microseconds, `0` when
    /// nothing was sampled (WO-1.5a). Nearest-rank over the samples this
    /// visit took, one a second; see [`DiagRecord::rtt_source`] for what
    /// they measure.
    pub rtt_median_us: u32,
    /// The 95th percentile of the same samples, nearest-rank
    /// (`ceil(0.95 * n)`), in microseconds.
    pub rtt_p95_us: u32,
    /// How many samples the two percentiles above are over.
    pub rtt_samples: u32,
    /// What those samples measure.
    pub rtt_source: RttSource,
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

/// The cap on how many `steps` or `events` one record holds (WO-1.5a).
///
/// Chosen, not measured. Section 7 has one record per connection attempt
/// and says nothing about its size, which was safe while an attempt was a
/// connect and a probe burst; a headless house holds one attempt open for
/// the life of a visit, and a flapping path writes an entry per
/// transition, so the list would otherwise grow with uptime. 512 is well
/// past what any run this design measures produces (a 90 s hold with two
/// fall-backs writes about 20 entries) and bounds one record at a few tens
/// of kilobytes with [`MAX_FREE_TEXT_LEN`] on every detail.
pub const MAX_RECORD_ENTRIES: usize = 512;

/// What the last entry of a truncated `steps` or `events` list says, so a
/// record that stopped recording says so rather than appearing to end
/// where the run did.
const TRUNCATION_MARKER: &str = "further entries dropped";

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

/// The inverse of [`addr_to_json_string`], for both forms it writes.
///
/// The second form matters: an [`Addr`] whose family is neither 4 nor 6 is
/// how this design spells "not observed" (frame 16's probe carries one, and
/// so does a record whose attempt never reached a reflection), and
/// [`addr_to_json_string`] writes it as the raw-field dump. Reading only
/// `"host:port"` made every such record a malformed line: written by the
/// writer, refused by its own reader.
///
/// # Errors
/// Returns [`DiagError::Malformed`] if `s` is neither form.
fn addr_from_json_string(s: &str) -> Result<Addr, DiagError> {
    if let Ok(socket_addr) = s.parse::<std::net::SocketAddr>() {
        return Ok(Addr::from_socket_addr(socket_addr));
    }
    let malformed = || DiagError::Malformed(format!("bad address: {s:?}"));
    let family = s
        .strip_prefix("family=")
        .and_then(|rest| rest.split(' ').next())
        .ok_or_else(malformed)?;
    let bytes_hex = s
        .split(" bytes=")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .ok_or_else(malformed)?;
    let port = s.split(" port=").nth(1).ok_or_else(malformed)?;
    let bytes: [u8; 16] = hex_decode(bytes_hex)?
        .try_into()
        .map_err(|_| DiagError::Malformed(format!("address bytes must be 16 bytes: {s:?}")))?;
    Ok(Addr {
        family: family.parse().map_err(|_| malformed())?,
        bytes,
        port: port.parse().map_err(|_| malformed())?,
    })
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

/// An optional unsigned integer field: absent reads as `0`, present but of
/// the wrong type is still an error.
///
/// # Errors
/// Returns [`DiagError::Malformed`] if `key` is present and is not an
/// unsigned integer.
fn optional_field_u64(value: &serde_json::Value, key: &str) -> Result<u64, DiagError> {
    match value.get(key) {
        None | Some(serde_json::Value::Null) => Ok(0),
        Some(present) => present.as_u64().ok_or_else(|| {
            DiagError::Malformed(format!("field {key:?} is not an unsigned integer"))
        }),
    }
}

/// [`optional_field_u64`] narrowed to a `u32`.
///
/// # Errors
/// Returns [`DiagError::Malformed`] if `key` is present and is not an
/// unsigned integer inside `u32`'s range.
fn optional_field_u32(value: &serde_json::Value, key: &str) -> Result<u32, DiagError> {
    u32::try_from(optional_field_u64(value, key)?)
        .map_err(|_| DiagError::Malformed(format!("field {key:?} is out of range for u32")))
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

        let events: Vec<serde_json::Value> = self
            .events
            .iter()
            .map(|event| {
                serde_json::json!({
                    "event": event.event.as_str(),
                    "at_ms": event.at_ms,
                    "detail": cap_text(&event.detail),
                })
            })
            .collect();

        let value = serde_json::json!({
            "attempt": hex_encode(&self.attempt),
            "session": self.session,
            "gate_ms": self.gate_ms,
            "peer": self.peer.as_hex(),
            "started_at": rfc3339::format(self.started_at_ms),
            "ended_at": rfc3339::format(self.ended_at_ms),
            "steps": steps,
            "failed_step": self.failed_step.map(Step::as_str),
            "events": events,
            "local_observed": [
                addr_to_json_string(local_first),
                addr_to_json_string(local_second),
            ],
            "peer_observed": addr_to_json_string(self.peer_observed),
            "mapping": self.mapping.as_str(),
            "gate_carried_traffic": self.gate_carried_traffic,
            "gate_bytes": self.gate_bytes,
            "relay_queued": self.relay_queued,
            "relay_shaped_delay_p50_us": self.relay_shaped_delay_p50_us,
            "relay_shaped_delay_max_us": self.relay_shaped_delay_max_us,
            "relay_dropped_at_full": self.relay_dropped_at_full,
            "path": self.path.kind_str(),
            "path_addr": addr_to_json_string(self.path.addr()),
            "path_rtt_us": self.path_rtt_us,
            "rtt_median_us": self.rtt_median_us,
            "rtt_p95_us": self.rtt_p95_us,
            "rtt_samples": self.rtt_samples,
            "rtt_source": self.rtt_source.as_str(),
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

        // `events` and the four `rtt_*` fields arrived in WO-1.5a, after
        // WO-1.4's writer had a released format, so an absent one is a
        // record written before them rather than a malformed line: the
        // same rule, and the same reason, as the shaper counters below.
        let mut events = Vec::new();
        if let Some(raw) = value.get("events") {
            let raw = raw
                .as_array()
                .ok_or_else(|| DiagError::Malformed("field \"events\" is not an array".into()))?;
            for item in raw {
                events.push(VisitEvent {
                    event: VisitEventKind::parse_str(field_str(item, "event")?)?,
                    at_ms: field_u64(item, "at_ms")?,
                    detail: field_str(item, "detail")?.to_string(),
                });
            }
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
        // The four shaper counters arrived in WO-1.4b, after WO-1.4a's
        // writer had a released format: absent means a record written
        // before them, which is a zero rather than a malformed line.
        let relay_queued = optional_field_u64(&value, "relay_queued")?;
        let relay_shaped_delay_p50_us = optional_field_u64(&value, "relay_shaped_delay_p50_us")?;
        let relay_shaped_delay_max_us = optional_field_u64(&value, "relay_shaped_delay_max_us")?;
        let relay_dropped_at_full = optional_field_u64(&value, "relay_dropped_at_full")?;

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
        let rtt_median_us = optional_field_u32(&value, "rtt_median_us")?;
        let rtt_p95_us = optional_field_u32(&value, "rtt_p95_us")?;
        let rtt_samples = optional_field_u32(&value, "rtt_samples")?;
        let rtt_source = match value.get("rtt_source") {
            None | Some(serde_json::Value::Null) => RttSource::NotSampled,
            Some(present) => RttSource::parse_str(as_str(present)?)?,
        };
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
            events,
            failed_step,
            local_observed,
            peer_observed,
            mapping,
            gate_carried_traffic,
            gate_bytes,
            relay_queued,
            relay_shaped_delay_p50_us,
            relay_shaped_delay_max_us,
            relay_dropped_at_full,
            path,
            path_rtt_us,
            rtt_median_us,
            rtt_p95_us,
            rtt_samples,
            rtt_source,
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
    ///
    /// Boxed because a [`DiagRecord`] is several hundred bytes and the
    /// malformed variant is two words: unboxed, every entry of a whole
    /// file's `Vec<ReadOutcome>` would be sized for the record even where
    /// it holds a parse error (`clippy::large_enum_variant`).
    Record(Box<DiagRecord>),
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
            Ok(record) => out.push(ReadOutcome::Record(Box::new(record))),
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

// ---------------------------------------------------------------------
// The recorder (WO-1.4b)
// ---------------------------------------------------------------------

/// The running platform, as section 7's `platform` field spells it.
#[must_use]
pub fn host_platform_name() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        std::env::consts::OS
    }
}

/// The diagnostics directory for the machine this binary is running on,
/// resolved from the environment through [`diagnostics_dir`].
///
/// # Errors
/// Returns [`DiagError::Io`] if the home directory cannot be determined,
/// which is the one input every platform's location needs.
pub fn host_diagnostics_dir() -> Result<PathBuf, DiagError> {
    let home_var = if cfg!(target_os = "windows") {
        "USERPROFILE"
    } else {
        "HOME"
    };
    let home = std::env::var_os(home_var).ok_or_else(|| {
        DiagError::Io(std::io::Error::other(format!(
            "{home_var} is not set, so the diagnostics directory cannot be resolved"
        )))
    })?;
    let home = PathBuf::from(home);
    let xdg = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from);
    let local_appdata = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let platform = if cfg!(target_os = "macos") {
        TargetPlatform::MacOs
    } else if cfg!(target_os = "windows") {
        TargetPlatform::Windows
    } else {
        TargetPlatform::Linux
    };
    Ok(diagnostics_dir(
        platform,
        &LocationEnv {
            home: &home,
            xdg_state_home: xdg.as_deref(),
            local_appdata: local_appdata.as_deref(),
        },
    ))
}

/// A [`DiagWriter`] behind a lock, shared by every [`Recorder`] in a
/// process, so the doorbell, the gate client and the liveness monitor all
/// append to the one day's file without each opening it.
///
/// The lock is a `std::sync::Mutex` and is never held across an `.await`:
/// [`DiagSink::write`] is a synchronous call that returns before the caller
/// touches the network again.
pub struct DiagSink {
    writer: std::sync::Mutex<DiagWriter>,
}

impl DiagSink {
    /// Opens a sink writing into `dir`.
    ///
    /// # Errors
    /// Returns [`DiagError::Io`] if `dir` cannot be created.
    pub fn new(dir: PathBuf) -> Result<std::sync::Arc<Self>, DiagError> {
        Ok(std::sync::Arc::new(Self {
            writer: std::sync::Mutex::new(DiagWriter::new(dir)?),
        }))
    }

    /// Opens a sink at [`host_diagnostics_dir`].
    ///
    /// # Errors
    /// Returns [`DiagError::Io`] if the directory cannot be resolved or
    /// created.
    pub fn for_host() -> Result<std::sync::Arc<Self>, DiagError> {
        Self::new(host_diagnostics_dir()?)
    }

    /// Appends one record, timestamped `now_ms`.
    ///
    /// # Errors
    /// Returns [`DiagError::Io`] if the write fails.
    pub fn write(&self, record: &DiagRecord, now_ms: u64) -> Result<(), DiagError> {
        self.writer.lock_or_recover().append(record, now_ms)?;
        Ok(())
    }
}

impl fmt::Debug for DiagSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DiagSink(..)")
    }
}

/// Everything one attempt has recorded so far.
#[derive(Debug)]
struct RecorderState {
    attempt: [u8; 16],
    session: u32,
    gate_ms: u64,
    steps: Vec<StepRecord>,
    events: Vec<VisitEvent>,
    failed_step: Option<Step>,
    local_observed: [Option<Addr>; 2],
    peer_observed: Option<Addr>,
    mapping: Option<Mapping>,
    /// The reason the protocol itself named, if one did.
    reason_hint: Option<Reason>,
    gate_carried_traffic: bool,
    gate_bytes: u64,
    relay_queued: u64,
    relay_shaped_delay_p50_us: u64,
    relay_shaped_delay_max_us: u64,
    relay_dropped_at_full: u64,
    path: PathChoice,
    path_rtt_us: u32,
    rtt_median_us: u32,
    rtt_p95_us: u32,
    rtt_samples: u32,
    rtt_source: RttSource,
    /// The record as it was written, once [`Recorder::finish`] has run.
    /// Held rather than a bare flag so a second caller (`doctor`, after the
    /// doorbell it started has already settled the attempt) is handed the
    /// record that was actually written, not a second one built from a
    /// different reason.
    finished: Option<DiagRecord>,
}

#[derive(Debug)]
struct RecorderInner {
    peer: PeerFingerprint,
    started: std::time::Instant,
    started_at_ms: u64,
    sink: Option<std::sync::Arc<DiagSink>>,
    state: std::sync::Mutex<RecorderState>,
}

/// One connection attempt's diagnostics record while it is still being
/// built: the steps as they happen, both sides' observed addresses as they
/// are learned, and the shaper counters read at the end.
///
/// Every call site holds the same recorder through an [`std::sync::Arc`],
/// because one attempt crosses the gate client, the doorbell and the
/// liveness monitor and section 7 wants one record out of all three.
/// Cloning shares the state rather than copying it.
///
/// **Redaction is the type's, not the caller's** (section 7). A recorder is
/// built from a [`PeerFingerprint`], so a key cannot enter one, and every
/// step's `detail` is free text capped by [`MAX_FREE_TEXT_LEN`] when
/// written. A call site with a key, a ticket or a sealed body in hand
/// records its fingerprint or its length instead of its bytes.
#[derive(Debug, Clone)]
pub struct Recorder {
    inner: std::sync::Arc<RecorderInner>,
}

impl Recorder {
    /// A recorder for an attempt against `peer`, writing to `sink` when it
    /// finishes. `None` writes nothing, which is what a caller with no
    /// diagnostics directory (a test, or a house whose state directory is
    /// unwritable) gets rather than an error on every step.
    #[must_use]
    pub fn new(peer: PeerFingerprint, sink: Option<std::sync::Arc<DiagSink>>) -> Self {
        Self {
            inner: std::sync::Arc::new(RecorderInner {
                peer,
                started: std::time::Instant::now(),
                started_at_ms: crate::gate::now_ms(),
                sink,
                state: std::sync::Mutex::new(RecorderState {
                    attempt: [0u8; 16],
                    session: 0,
                    gate_ms: 0,
                    steps: Vec::new(),
                    events: Vec::new(),
                    failed_step: None,
                    local_observed: [None, None],
                    peer_observed: None,
                    mapping: None,
                    reason_hint: None,
                    gate_carried_traffic: false,
                    gate_bytes: 0,
                    relay_queued: 0,
                    relay_shaped_delay_p50_us: 0,
                    relay_shaped_delay_max_us: 0,
                    relay_dropped_at_full: 0,
                    // Section 2 step 2: every attempt starts relayed, so
                    // the path is the relay until an upgrade says
                    // otherwise, and an attempt that never got that far
                    // records the truth rather than a default direct path.
                    path: PathChoice::Relay(Addr::default()),
                    path_rtt_us: 0,
                    rtt_median_us: 0,
                    rtt_p95_us: 0,
                    rtt_samples: 0,
                    rtt_source: RttSource::NotSampled,
                    finished: None,
                }),
            }),
        }
    }

    /// The peer this attempt is against, redacted.
    #[must_use]
    pub fn peer(&self) -> PeerFingerprint {
        self.inner.peer
    }

    /// Milliseconds since this attempt started, which is what every
    /// [`StepRecord::at_ms`] is measured in.
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.inner.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Records one step, and the first failing one as `failed_step`.
    ///
    /// The first rather than the last: section 7's `failed_step` is what
    /// `doctor` exits naming, and a later failure is usually a consequence
    /// of the first (a probe burst that never fired because the start
    /// signal never came).
    ///
    /// **Bounded** (WO-1.5a): a house holds one attempt open for as long
    /// as a visit lasts, and a path that flaps writes two entries a
    /// flap, so an unbounded list here is a record that grows with
    /// uptime. Past [`MAX_RECORD_ENTRIES`] one marker entry is written
    /// and the rest are dropped, so a truncated record says it was
    /// truncated instead of quietly ending mid-visit. `failed_step` is
    /// still taken from a dropped failure, since it is one value and
    /// costs nothing to keep true.
    pub fn step(&self, step: Step, outcome: StepOutcome, detail: impl Into<String>) {
        let at_ms = self.elapsed_ms();
        let mut state = self.inner.state.lock_or_recover();
        if outcome == StepOutcome::Fail && state.failed_step.is_none() {
            state.failed_step = Some(step);
        }
        match state.steps.len() {
            len if len < MAX_RECORD_ENTRIES => state.steps.push(StepRecord {
                step,
                at_ms,
                outcome,
                detail: detail.into(),
            }),
            len if len == MAX_RECORD_ENTRIES => state.steps.push(StepRecord {
                step,
                at_ms,
                outcome,
                detail: format!("{TRUNCATION_MARKER} (at {MAX_RECORD_ENTRIES} steps)"),
            }),
            _ => {}
        }
    }

    /// Records one visit event, section 7's `events[]` entry (WO-1.5a).
    ///
    /// Bounded exactly as [`Recorder::step`] is, and for the same reason:
    /// a visit held open for a day is one attempt.
    pub fn event(&self, event: VisitEventKind, detail: impl Into<String>) {
        let at_ms = self.elapsed_ms();
        let mut state = self.inner.state.lock_or_recover();
        match state.events.len() {
            len if len < MAX_RECORD_ENTRIES => state.events.push(VisitEvent {
                event,
                at_ms,
                detail: detail.into(),
            }),
            len if len == MAX_RECORD_ENTRIES => state.events.push(VisitEvent {
                event,
                at_ms,
                detail: format!("{TRUNCATION_MARKER} (at {MAX_RECORD_ENTRIES} events)"),
            }),
            _ => {}
        }
    }

    /// The round trip percentiles measured over a held visit (WO-1.5a).
    pub fn set_rtt(&self, median_us: u32, p95_us: u32, samples: u32, source: RttSource) {
        let mut state = self.inner.state.lock_or_recover();
        state.rtt_median_us = median_us;
        state.rtt_p95_us = p95_us;
        state.rtt_samples = samples;
        state.rtt_source = source;
    }

    /// The attempt id of frame 16, once the porch stream has named it.
    pub fn set_attempt(&self, attempt: [u8; 16]) {
        self.inner.state.lock_or_recover().attempt = attempt;
    }

    /// The gate's session id (frame 6).
    pub fn set_session(&self, session: u32) {
        self.inner.state.lock_or_recover().session = session;
    }

    /// The gate's own clock from frame 7, the one shared timestamp two
    /// logs are aligned on. Never a time to act on.
    pub fn set_gate_ms(&self, gate_ms: u64) {
        self.inner.state.lock_or_recover().gate_ms = gate_ms;
    }

    /// The primary gate reflection (`Registered.observed`, frame 2).
    pub fn set_local_observed_primary(&self, addr: Addr) {
        let mut state = self.inner.state.lock_or_recover();
        state.local_observed[0] = Some(addr);
    }

    /// The secondary port's reflection (`Reflected.observed`, frame 4),
    /// the second observation research D1 asks for.
    pub fn set_local_observed_secondary(&self, addr: Addr) {
        let mut state = self.inner.state.lock_or_recover();
        state.local_observed[1] = Some(addr);
    }

    /// The peer's observed address from frame 6.
    pub fn set_peer_observed(&self, addr: Addr) {
        self.inner.state.lock_or_recover().peer_observed = Some(addr);
    }

    /// The path traffic settled on and its measured round trip.
    pub fn set_path(&self, path: PathChoice, rtt_us: u32) {
        let mut state = self.inner.state.lock_or_recover();
        state.path = path;
        state.path_rtt_us = rtt_us;
    }

    /// The shaper counters of section 1, read from the path table at
    /// attempt end (section 7 records them "on every connection, success or
    /// not").
    ///
    /// `gate_carried_traffic` follows from the same read: a relay queue
    /// that took a datagram is a gate that carried traffic, which is the
    /// only fact the house can state about the relay leg without asking the
    /// gate.
    pub fn set_relay_stats(&self, stats: &crate::path::ShaperStats) {
        let mut state = self.inner.state.lock_or_recover();
        state.gate_carried_traffic = stats.relay_queued > 0;
        state.gate_bytes = stats.relay_bytes;
        state.relay_queued = stats.relay_queued;
        state.relay_shaped_delay_p50_us = stats.relay_shaped_delay_p50_us;
        state.relay_shaped_delay_max_us = stats.relay_shaped_delay_max_us;
        state.relay_dropped_at_full = stats.relay_dropped_at_full;
    }

    /// Records the reason the protocol itself named, for a caller that
    /// decides the record's `reason` later (Konrad's should 3 on PR #49).
    ///
    /// The gate's `Error.code` is section 7's reason enum on the wire, so a
    /// refusal is `gate_refused_not_member`, `gate_at_capacity` or
    /// `gate_rate_limited` and not the `internal` a caller guessing from
    /// the failed step alone would write.
    pub fn set_reason_hint(&self, reason: Reason) {
        self.inner.state.lock_or_recover().reason_hint = Some(reason);
    }

    /// The reason the protocol named, if anything named one.
    #[must_use]
    pub fn reason_hint(&self) -> Option<Reason> {
        self.inner.state.lock_or_recover().reason_hint
    }

    /// Overrides the inferred mapping, for a caller that knows better than
    /// the two reflections do (a `doctor --gate` run that reached neither
    /// port has no reflections at all and its mapping stays `unknown`).
    pub fn set_mapping(&self, mapping: Mapping) {
        self.inner.state.lock_or_recover().mapping = Some(mapping);
    }

    /// The step that failed first, if any has.
    #[must_use]
    pub fn failed_step(&self) -> Option<Step> {
        self.inner.state.lock_or_recover().failed_step
    }

    /// The last step recorded, whatever its outcome, or `None` when nothing
    /// has been recorded yet.
    ///
    /// It says how far an attempt got, and nothing more. It names no
    /// successor: section 7's step enum is the order steps are *listed* in,
    /// not a schedule, and which step follows a given one depends on what
    /// the caller was doing (a `--gate` run stops after the reflections; a
    /// `--friend` run goes on). A caller holding an error that recorded no
    /// step of its own works out what was in flight from this plus its own
    /// knowledge of the sequence it was running.
    #[must_use]
    pub fn last_step(&self) -> Option<Step> {
        self.inner
            .state
            .lock_or_recover()
            .steps
            .last()
            .map(|recorded| recorded.step)
    }

    /// Section 7's inference for a probe burst that answered nothing,
    /// applied to what this attempt has observed:
    /// `endpoint_dependent_mapping` when the two reflections differed,
    /// `hairpin_failure` when both sides' observed addresses share an IP
    /// and the relay carried traffic, and `probe_timeout` otherwise.
    #[must_use]
    pub fn probe_failure_reason(&self) -> Reason {
        let state = self.inner.state.lock_or_recover();
        let mapping = state
            .mapping
            .unwrap_or_else(|| infer_mapping(state.local_observed[0], state.local_observed[1]));
        probe_failure_reason(
            state.local_observed[0],
            state.peer_observed,
            mapping,
            state.gate_carried_traffic,
        )
    }

    /// The record as it stands, without writing it.
    #[must_use]
    pub fn snapshot(&self, reason: Reason) -> DiagRecord {
        let state = self.inner.state.lock_or_recover();
        let mapping = state
            .mapping
            .unwrap_or_else(|| infer_mapping(state.local_observed[0], state.local_observed[1]));
        DiagRecord {
            attempt: state.attempt,
            session: state.session,
            gate_ms: state.gate_ms,
            peer: self.inner.peer,
            started_at_ms: self.inner.started_at_ms,
            ended_at_ms: self.inner.started_at_ms.saturating_add(self.elapsed_ms()),
            steps: state.steps.clone(),
            events: state.events.clone(),
            failed_step: state.failed_step,
            local_observed: [
                state.local_observed[0].unwrap_or_default(),
                state.local_observed[1].unwrap_or_default(),
            ],
            peer_observed: state.peer_observed.unwrap_or_default(),
            mapping,
            gate_carried_traffic: state.gate_carried_traffic,
            gate_bytes: state.gate_bytes,
            relay_queued: state.relay_queued,
            relay_shaped_delay_p50_us: state.relay_shaped_delay_p50_us,
            relay_shaped_delay_max_us: state.relay_shaped_delay_max_us,
            relay_dropped_at_full: state.relay_dropped_at_full,
            path: state.path,
            path_rtt_us: state.path_rtt_us,
            rtt_median_us: state.rtt_median_us,
            rtt_p95_us: state.rtt_p95_us,
            rtt_samples: state.rtt_samples,
            rtt_source: state.rtt_source,
            reason,
            version: env!("CARGO_PKG_VERSION").to_string(),
            platform: host_platform_name().to_string(),
        }
    }

    /// Closes the attempt: builds the record, writes it to the sink if
    /// there is one, and returns it.
    ///
    /// Idempotent, because an attempt can end more than one way in the same
    /// code path (a fall-back that then loses the connection): the second
    /// and later calls return the record without appending a second line,
    /// so one attempt is one record (section 7).
    ///
    /// A failed write is returned rather than swallowed, but the record
    /// comes back either way: `doctor` prints what it observed even when
    /// the log directory is unwritable.
    ///
    /// # Errors
    /// Returns [`DiagError::Io`] if the sink's append failed.
    pub fn finish(&self, reason: Reason) -> (DiagRecord, Result<(), DiagError>) {
        let record = self.snapshot(reason);
        {
            let mut state = self.inner.state.lock_or_recover();
            if let Some(already) = state.finished.as_ref() {
                return (already.clone(), Ok(()));
            }
            state.finished = Some(record.clone());
        }
        let written = match self.inner.sink.as_ref() {
            Some(sink) => sink.write(&record, record.ended_at_ms),
            None => Ok(()),
        };
        (record, written)
    }
}

/// Records one step of an attempt, section 7's `steps[]` entry.
///
/// A free function taking `Option<&Recorder>` because most call sites hold
/// exactly that: a house running without a diagnostics directory, and every
/// test that predates this work order, pass `None` and the call is a no-op.
/// `diag::record(recorder, Step::GateDial, StepOutcome::Ok, detail)` is the
/// one spelling used at every step in `punch.rs`, `live.rs` and
/// `gate/client.rs`.
pub fn record(
    recorder: Option<&Recorder>,
    step: Step,
    outcome: StepOutcome,
    detail: impl Into<String>,
) {
    if let Some(recorder) = recorder {
        recorder.step(step, outcome, detail);
    }
}

/// Section 7's mapping inference: `endpoint_dependent` when the two
/// reflections differ in address or port, `endpoint_independent` when they
/// agree, and `unknown` when fewer than two were observed.
#[must_use]
pub fn infer_mapping(primary: Option<Addr>, secondary: Option<Addr>) -> Mapping {
    match (primary, secondary) {
        (Some(first), Some(second)) => {
            if first.bytes == second.bytes && first.port == second.port {
                Mapping::EndpointIndependent
            } else {
                Mapping::EndpointDependent
            }
        }
        _ => Mapping::Unknown,
    }
}

/// Section 7's `hairpin_failure` rule: both sides' observed addresses share
/// an IP and every direct candidate timed out while the relay worked.
///
/// Stated as a function so the doorbell's fall-back reason is a rule and
/// not a guess, which is what the Phase 1 gate's "named reason" for case
/// (d) needs.
#[must_use]
pub fn probe_failure_reason(
    local_observed: Option<Addr>,
    peer_observed: Option<Addr>,
    mapping: Mapping,
    relay_carried_traffic: bool,
) -> Reason {
    if mapping == Mapping::EndpointDependent {
        return Reason::EndpointDependentMapping;
    }
    if let (Some(local), Some(peer)) = (local_observed, peer_observed)
        && local.bytes == peer.bytes
        && relay_carried_traffic
    {
        return Reason::HairpinFailure;
    }
    Reason::ProbeTimeout
}

// ---------------------------------------------------------------------
// Reading back, for `doctor --last`
// ---------------------------------------------------------------------

/// Every diagnostics file in `dir`, newest day first and, within a day, its
/// highest overflow part first, so a search for the most recent record
/// reads the fewest files.
fn files_newest_first(dir: &Path) -> Result<Vec<PathBuf>, DiagError> {
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(".jsonl") && day_prefix(name).is_some())
        .collect();
    // Lexicographic order is chronological for `YYYY-MM-DD[.N]`, except
    // that `.10` sorts before `.2`; parts are compared numerically for
    // that reason.
    names.sort_by(|a, b| {
        let key = |name: &str| {
            let day = day_prefix(name).unwrap_or("").to_string();
            let part: u32 = name
                .strip_suffix(".jsonl")
                .and_then(|stem| stem.get(10..))
                .and_then(|rest| rest.strip_prefix('.'))
                .and_then(|digits| digits.parse().ok())
                .unwrap_or(0);
            (day, part)
        };
        key(b).cmp(&key(a))
    });
    Ok(names.into_iter().map(|name| dir.join(name)).collect())
}

/// The most recent record in `dir` for `peer`, or for any peer when `peer`
/// is `None`, without running anything: `doctor --last`.
///
/// Malformed lines are skipped, as [`read_records`] reports them: one torn
/// line must not hide the record before it.
///
/// # Errors
/// Returns [`DiagError::Io`] if `dir` cannot be listed or a file in it
/// cannot be read.
pub fn last_record(
    dir: &Path,
    peer: Option<PeerFingerprint>,
) -> Result<Option<DiagRecord>, DiagError> {
    for path in files_newest_first(dir)? {
        let mut best: Option<DiagRecord> = None;
        for outcome in read_records(&path)? {
            let ReadOutcome::Record(record) = outcome else {
                continue;
            };
            if peer.is_some_and(|wanted| wanted != record.peer) {
                continue;
            }
            best = Some(*record);
        }
        if best.is_some() {
            return Ok(best);
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------
// The human-readable report (`doctor` without `--json`)
// ---------------------------------------------------------------------

/// An address for a person to read: `host:port`, or the plain words for
/// one that was never observed, rather than the raw-field dump the JSON
/// form needs in order to round trip (Konrad's nit 10 on PR #49).
fn addr_for_humans(addr: Addr) -> String {
    match addr.to_socket_addr() {
        Some(socket_addr) => socket_addr.to_string(),
        None => "(not observed)".to_string(),
    }
}

/// The first line of every `doctor` report, section 7: "IP addresses are
/// kept, because they are the thing being diagnosed, and the doctor command
/// says so on its first line so nobody sends a file blind."
pub const PRIVACY_NOTICE: &str =
    "This report contains IP addresses: yours, your friend's and your gate's.";

impl DiagRecord {
    /// This record in the human form section 7 gives: the privacy notice,
    /// one line per step (`10 fail probe_burst 10000 ms 0 of 9 candidates
    /// answered`), then mapping, path and RTT, gate bytes and reason.
    ///
    /// The number opening a step line is that step's position in section
    /// 7's step enum, which is what makes `probe_burst` the tenth.
    ///
    /// The duration is derived rather than stored, and derived **backwards**
    /// (Konrad's must 1 on PR #49): every call site stamps `at_ms` when the
    /// step finishes, so a step's duration is the distance from the
    /// previous step's `at_ms`, and the first step's is the distance from
    /// the start of the attempt. Deriving it forwards, to the next step's
    /// `at_ms`, printed each step's neighbour's duration and always 0 for
    /// the last one, so a 10 s gate dial read `0 ms`.
    #[must_use]
    pub fn to_human_report(&self) -> String {
        let mut out = String::new();
        out.push_str(PRIVACY_NOTICE);
        out.push('\n');
        let mut previous_ms = 0u64;
        for step in &self.steps {
            let duration_ms = step.at_ms.saturating_sub(previous_ms);
            previous_ms = step.at_ms;
            let number = Step::ALL
                .iter()
                .position(|candidate| *candidate == step.step)
                .map_or(0, |index| index + 1);
            out.push_str(&format!(
                "{number:>2} {outcome:<4} {name:<18} {duration_ms:>6} ms  {detail}\n",
                outcome = step.outcome.as_str(),
                name = step.step.as_str(),
                detail = step.detail,
            ));
        }
        for event in &self.events {
            out.push_str(&format!(
                "   event {name:<18} {at_ms:>6} ms  {detail}\n",
                name = event.event.as_str(),
                at_ms = event.at_ms,
                detail = event.detail,
            ));
        }
        if let Some(line) = self.path_change_summary() {
            out.push_str(&line);
            out.push('\n');
        }
        if self.rtt_samples > 0 {
            out.push_str(&format!(
                "rtt over the visit: median {} us, p95 {} us over {} samples ({})\n",
                self.rtt_median_us,
                self.rtt_p95_us,
                self.rtt_samples,
                self.rtt_source.as_str(),
            ));
        }
        out.push_str(&format!("mapping {}\n", self.mapping.as_str()));
        out.push_str(&format!(
            "path {} {} rtt {} us\n",
            self.path.kind_str(),
            addr_for_humans(self.path.addr()),
            self.path_rtt_us,
        ));
        out.push_str(&format!(
            "gate carried {} ({} bytes, {} queued, shaped p50 {} us max {} us, dropped {})\n",
            if self.gate_carried_traffic {
                "traffic"
            } else {
                "nothing"
            },
            self.gate_bytes,
            self.relay_queued,
            self.relay_shaped_delay_p50_us,
            self.relay_shaped_delay_max_us,
            self.relay_dropped_at_full,
        ));
        out.push_str(&format!("reason {}\n", self.reason.as_str()));
        if let Some(failed) = self.failed_step {
            out.push_str(&format!("failed step {}\n", failed.as_str()));
        }
        out
    }

    /// The one line WO-1.5 case (f) is read off: when a live direct path
    /// was detected as gone, how long after that traffic was back on the
    /// relay, when the path was declared dead, and when a rerun got it
    /// back.
    ///
    /// Derived from [`DiagRecord::events`] rather than stored, so it can
    /// never disagree with them, and `None` when the visit never lost a
    /// path, which is the ordinary run.
    ///
    /// The first of each event is the one taken: a visit that flapped
    /// twice has its numbers in the event list itself, and a summary line
    /// that silently averaged two flaps would be worse than no line.
    #[must_use]
    pub fn path_change_summary(&self) -> Option<String> {
        let at = |kind: VisitEventKind| {
            self.events
                .iter()
                .find(|event| event.event == kind)
                .map(|event| event.at_ms)
        };
        let stale = at(VisitEventKind::PathStale)?;
        let mut line = format!("path change: detected at {stale} ms");
        if let Some(fell_back) = at(VisitEventKind::FellBack) {
            line.push_str(&format!(
                ", back on the relay {} ms later",
                fell_back.saturating_sub(stale)
            ));
        }
        if let Some(dead) = at(VisitEventKind::PathDead) {
            line.push_str(&format!(", dead at {dead} ms"));
        }
        match at(VisitEventKind::Recovered) {
            Some(recovered) => line.push_str(&format!(
                ", recovered at {recovered} ms ({} ms after detection)",
                recovered.saturating_sub(stale)
            )),
            None => line.push_str(", not recovered"),
        }
        Some(line)
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
            events: vec![
                VisitEvent {
                    event: VisitEventKind::VisitOpen,
                    at_ms: 12,
                    detail: "relay 203.0.113.1:443".to_string(),
                },
                VisitEvent {
                    event: VisitEventKind::Upgraded,
                    at_ms: 512,
                    detail: "direct 203.0.113.5:51823 at 15000 us".to_string(),
                },
            ],
            failed_step,
            local_observed: [sample_addr(51_820), sample_addr(51_821)],
            peer_observed: sample_addr(51_822),
            mapping: Mapping::EndpointIndependent,
            gate_carried_traffic: true,
            gate_bytes: 4096,
            relay_queued: 12,
            relay_shaped_delay_p50_us: 480,
            relay_shaped_delay_max_us: 1200,
            relay_dropped_at_full: 0,
            path: PathChoice::Direct(sample_addr(51_823)),
            path_rtt_us: 15_000,
            rtt_median_us: 15_000,
            rtt_p95_us: 22_000,
            rtt_samples: 88,
            rtt_source: RttSource::Probe,
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

    // --- the recorder (WO-1.4b) ---------------------------------------------

    /// A unique temporary directory for one test's diagnostics log.
    fn test_dir(name: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("jerome14b-diag-{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn records_in(dir: &Path) -> Vec<DiagRecord> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
                continue;
            }
            for outcome in read_records(&path).unwrap() {
                if let ReadOutcome::Record(record) = outcome {
                    out.push(*record);
                }
            }
        }
        out
    }

    /// Section 8's WO-1.4 verify line, first half: "a test forcing each
    /// failure step asserts a record naming that step". Every step of
    /// section 7's enum is forced to fail through the recorder that
    /// `punch.rs`, `live.rs` and `gate/client.rs` all call, and the record
    /// that reaches the log names it.
    ///
    /// Deliberate break to fail this test: in `Recorder::step`, drop the
    /// `if outcome == StepOutcome::Fail && state.failed_step.is_none()`
    /// assignment. Every step is still logged, but `failed_step` stays
    /// null and `doctor` exits 0 on a failed attempt.
    #[test]
    fn forcing_each_step_to_fail_writes_a_record_naming_it() {
        for step in Step::ALL {
            let dir = test_dir(&format!("force-{}", step.as_str()));
            let sink = DiagSink::new(dir.clone()).unwrap();
            let recorder = Recorder::new(
                PeerFingerprint::from_key(&test_salt(), &[3u8; 32]),
                Some(sink),
            );
            record(
                Some(&recorder),
                step,
                StepOutcome::Fail,
                format!("forced failure at {}", step.as_str()),
            );
            let (returned, written) = recorder.finish(Reason::Internal);
            written.unwrap();
            assert_eq!(returned.failed_step, Some(step));

            let written = records_in(&dir);
            assert_eq!(written.len(), 1, "one attempt is one record");
            let record = &written[0];
            assert_eq!(record.failed_step, Some(step), "record must name {step:?}");
            assert!(
                record
                    .steps
                    .iter()
                    .any(|entry| entry.step == step && entry.outcome == StepOutcome::Fail),
                "record must carry the failing step entry for {step:?}"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn one_attempt_writes_one_record_however_often_it_is_finished() {
        let dir = test_dir("finish-once");
        let sink = DiagSink::new(dir.clone()).unwrap();
        let recorder = Recorder::new(PeerFingerprint::default(), Some(sink));
        record(Some(&recorder), Step::GateDial, StepOutcome::Ok, "dialled");
        let (first, _) = recorder.finish(Reason::Ok);
        // A second and third close, which is what a doorbell that falls
        // back and then loses its connection does.
        let (second, _) = recorder.finish(Reason::Internal);
        let (third, _) = recorder.finish(Reason::PathIdleTimeout);
        assert_eq!(first, second);
        assert_eq!(first, third, "later closes return the record written");
        assert_eq!(records_in(&dir).len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An address that was never observed is written as its raw fields
    /// (family 0), and must read back: a record whose attempt never
    /// reached a reflection is exactly the record a person runs `doctor`
    /// to look at.
    #[test]
    fn an_unobserved_address_round_trips_through_the_reader() {
        let mut record = sample_record(Reason::GateUnreachable, Some(Step::GateDial));
        record.local_observed = [Addr::default(), Addr::default()];
        record.peer_observed = Addr::default();
        record.path = PathChoice::Relay(Addr::default());
        let parsed = DiagRecord::from_json_line(&record.to_json_line()).unwrap();
        assert_eq!(parsed, record);
    }

    #[test]
    fn the_mapping_is_inferred_from_the_two_reflections() {
        assert_eq!(
            infer_mapping(Some(sample_addr(1000)), Some(sample_addr(1000))),
            Mapping::EndpointIndependent
        );
        assert_eq!(
            infer_mapping(Some(sample_addr(1000)), Some(sample_addr(1001))),
            Mapping::EndpointDependent
        );
        assert_eq!(
            infer_mapping(Some(sample_addr(1000)), None),
            Mapping::Unknown
        );
        assert_eq!(infer_mapping(None, None), Mapping::Unknown);
    }

    /// Section 7's inference, so case (d)'s named reason is a rule: two
    /// reflections that differ are an endpoint-dependent mapping; a shared
    /// IP with a working relay is a hairpin failure; anything else is a
    /// plain probe timeout.
    #[test]
    fn the_probe_failure_reason_follows_section_sevens_rules() {
        let local = sample_addr(4000);
        assert_eq!(
            probe_failure_reason(
                Some(local),
                Some(sample_addr(4001)),
                Mapping::EndpointDependent,
                true
            ),
            Reason::EndpointDependentMapping
        );
        // Same IP on both sides, relay carried traffic: hairpin.
        assert_eq!(
            probe_failure_reason(
                Some(local),
                Some(sample_addr(4002)),
                Mapping::EndpointIndependent,
                true
            ),
            Reason::HairpinFailure
        );
        // Same IP but the relay carried nothing: not the hairpin rule.
        assert_eq!(
            probe_failure_reason(
                Some(local),
                Some(sample_addr(4002)),
                Mapping::EndpointIndependent,
                false
            ),
            Reason::ProbeTimeout
        );
        let elsewhere = Addr::from_socket_addr(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9)),
            4000,
        ));
        assert_eq!(
            probe_failure_reason(
                Some(local),
                Some(elsewhere),
                Mapping::EndpointIndependent,
                true
            ),
            Reason::ProbeTimeout
        );
    }

    /// `doctor --last` reads the most recent record for one peer without
    /// running anything, and is not confused by another peer's later
    /// record.
    #[test]
    fn last_record_finds_the_newest_for_that_peer() {
        let dir = test_dir("last");
        let salt = test_salt();
        let wanted = PeerFingerprint::from_key(&salt, &[1u8; 32]);
        let other = PeerFingerprint::from_key(&salt, &[2u8; 32]);
        let mut writer = DiagWriter::new(dir.clone()).unwrap();

        let mut first = sample_record(Reason::Ok, None);
        first.peer = wanted;
        first.session = 1;
        let mut second = sample_record(Reason::ProbeTimeout, Some(Step::ProbeBurst));
        second.peer = wanted;
        second.session = 2;
        let mut third = sample_record(Reason::Ok, None);
        third.peer = other;
        third.session = 3;
        for record in [&first, &second, &third] {
            writer.append(record, 1_700_000_000_000).unwrap();
        }

        let found = last_record(&dir, Some(wanted)).unwrap().unwrap();
        assert_eq!(found.session, 2, "the newest record for that peer");
        let any = last_record(&dir, None).unwrap().unwrap();
        assert_eq!(any.session, 3);
        let missing =
            last_record(&dir, Some(PeerFingerprint::from_key(&salt, &[9u8; 32]))).unwrap();
        assert!(missing.is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The human form section 7 gives: a first line saying the report
    /// carries IP addresses, one line per step opening with that step's
    /// number in the enum, then mapping, path, gate bytes and reason.
    #[test]
    fn the_human_report_has_section_sevens_shape() {
        let mut record = sample_record(Reason::ProbeTimeout, Some(Step::ProbeBurst));
        record.steps = vec![
            // Both stamped the way every call site stamps: at the moment
            // the step finished. The dial took 12 ms, the burst the 10 s
            // between its own stamp and the dial's.
            StepRecord {
                step: Step::GateDial,
                at_ms: 12,
                outcome: StepOutcome::Ok,
                detail: "gate at 198.51.100.7:443".to_string(),
            },
            StepRecord {
                step: Step::ProbeBurst,
                at_ms: 10_012,
                outcome: StepOutcome::Fail,
                detail: "0 of 9 candidates answered".to_string(),
            },
        ];
        record.ended_at_ms = record.started_at_ms + 10_012;
        let report = record.to_human_report();
        let mut lines = report.lines();
        assert_eq!(lines.next(), Some(PRIVACY_NOTICE));
        let gate_dial = lines.next().unwrap();
        assert!(gate_dial.starts_with(" 1 ok   gate_dial"), "{gate_dial:?}");
        assert!(gate_dial.contains("12 ms"), "{gate_dial:?}");
        let probe = lines.next().unwrap();
        // `probe_burst` is the tenth step of section 7's enum, and its
        // duration runs from the step before it: 10012 - 12.
        assert!(probe.starts_with("10 fail probe_burst"), "{probe:?}");
        assert!(probe.contains("10000 ms"), "{probe:?}");
        assert!(probe.ends_with("0 of 9 candidates answered"), "{probe:?}");
        assert!(report.contains("mapping endpoint_independent"));
        assert!(report.contains("reason probe_timeout"));
        assert!(report.contains("failed step probe_burst"));
    }

    /// The four shaper counters section 7 puts beside `gate_carried_traffic`
    /// travel into the record, and a record written before they existed
    /// still reads back rather than being rejected as malformed.
    #[test]
    fn the_shaper_counters_round_trip_and_an_older_record_still_reads() {
        let record = sample_record(Reason::Ok, None);
        let parsed = DiagRecord::from_json_line(&record.to_json_line()).unwrap();
        assert_eq!(parsed.relay_queued, 12);
        assert_eq!(parsed.relay_shaped_delay_p50_us, 480);
        assert_eq!(parsed.relay_shaped_delay_max_us, 1200);
        assert_eq!(parsed.relay_dropped_at_full, 0);

        let mut value: serde_json::Value = serde_json::from_str(&record.to_json_line()).unwrap();
        for key in [
            "relay_queued",
            "relay_shaped_delay_p50_us",
            "relay_shaped_delay_max_us",
            "relay_dropped_at_full",
        ] {
            value.as_object_mut().unwrap().remove(key);
        }
        let older = DiagRecord::from_json_line(&serde_json::to_string(&value).unwrap()).unwrap();
        assert_eq!(older.relay_queued, 0);
        assert_eq!(older.gate_bytes, record.gate_bytes);
    }

    /// WO-1.5a: the visit events and the round trip percentiles travel
    /// into the record, a record written before they existed still reads,
    /// and the derived summary line says what WO-1.5 case (f) asks for.
    ///
    /// Deliberate break to fail this test: read `"events"` with `field`
    /// rather than `value.get`, which refuses every record written before
    /// this order as malformed.
    #[test]
    fn visit_events_and_rtt_round_trip_and_an_older_record_still_reads() {
        let mut record = sample_record(Reason::PathIdleTimeout, Some(Step::PathLost));
        record.events.push(VisitEvent {
            event: VisitEventKind::PathStale,
            at_ms: 6_100,
            detail: "3 consecutive probes unanswered".to_string(),
        });
        record.events.push(VisitEvent {
            event: VisitEventKind::FellBack,
            at_ms: 6_101,
            detail: "traffic moved back to the relay session".to_string(),
        });
        record.events.push(VisitEvent {
            event: VisitEventKind::PathDead,
            at_ms: 11_200,
            detail: "the stale grace elapsed".to_string(),
        });

        let parsed = DiagRecord::from_json_line(&record.to_json_line()).unwrap();
        assert_eq!(parsed, record);
        assert_eq!(parsed.rtt_median_us, 15_000);
        assert_eq!(parsed.rtt_p95_us, 22_000);
        assert_eq!(parsed.rtt_samples, 88);
        assert_eq!(parsed.rtt_source, RttSource::Probe);

        let summary = parsed.path_change_summary().unwrap();
        assert!(summary.contains("detected at 6100 ms"), "{summary}");
        assert!(
            summary.contains("back on the relay 1 ms later"),
            "{summary}"
        );
        assert!(summary.contains("dead at 11200 ms"), "{summary}");
        assert!(summary.contains("not recovered"), "{summary}");
        assert!(record.to_human_report().contains("path change:"));
        assert!(
            record
                .to_human_report()
                .contains("rtt over the visit: median 15000 us, p95 22000 us over 88 samples")
        );

        let mut value: serde_json::Value = serde_json::from_str(&record.to_json_line()).unwrap();
        for key in [
            "events",
            "rtt_median_us",
            "rtt_p95_us",
            "rtt_samples",
            "rtt_source",
        ] {
            value.as_object_mut().unwrap().remove(key);
        }
        let older = DiagRecord::from_json_line(&serde_json::to_string(&value).unwrap()).unwrap();
        assert!(older.events.is_empty());
        assert_eq!(older.rtt_samples, 0);
        assert_eq!(older.rtt_source, RttSource::NotSampled);
        assert!(older.path_change_summary().is_none());
    }

    /// A visit that never lost a path has no summary line at all, so the
    /// ordinary report does not carry an empty one.
    #[test]
    fn a_visit_that_never_lost_its_path_has_no_path_change_line() {
        let record = sample_record(Reason::Ok, None);
        assert!(record.path_change_summary().is_none());
        assert!(!record.to_human_report().contains("path change:"));
    }

    /// Every visit event name round trips, so a house's stdout and a
    /// record are the one vocabulary.
    #[test]
    fn every_visit_event_name_round_trips() {
        for kind in VisitEventKind::ALL {
            assert_eq!(VisitEventKind::parse_str(kind.as_str()).unwrap(), kind);
        }
        assert!(VisitEventKind::parse_str("no_such_event").is_err());
        for source in [
            RttSource::NotSampled,
            RttSource::Probe,
            RttSource::Quic,
            RttSource::Mixed,
        ] {
            assert_eq!(RttSource::parse_str(source.as_str()).unwrap(), source);
        }
        assert!(RttSource::parse_str("guessed").is_err());
        assert_eq!(
            RttSource::Probe.joined(RttSource::Quic),
            RttSource::Mixed,
            "a hold that changed path says so"
        );
        assert_eq!(
            RttSource::NotSampled.joined(RttSource::Quic),
            RttSource::Quic
        );
        assert_eq!(RttSource::Probe.joined(RttSource::Probe), RttSource::Probe);
    }

    /// [`MAX_RECORD_ENTRIES`]: a visit long enough to fill the list stops
    /// appending and says so, rather than growing a record with uptime.
    ///
    /// Deliberate break to fail this test: push unconditionally in
    /// `Recorder::step` and `Recorder::event`.
    #[test]
    fn a_record_stops_growing_at_the_entry_cap_and_says_so() {
        let recorder = Recorder::new(PeerFingerprint::from_key(&test_salt(), &[3u8; 32]), None);
        for _ in 0..(MAX_RECORD_ENTRIES + 10) {
            recorder.step(Step::Live, StepOutcome::Ok, "on the direct path");
            recorder.event(VisitEventKind::Upgraded, "direct");
        }
        let (record, _) = recorder.finish(Reason::Ok);
        assert_eq!(record.steps.len(), MAX_RECORD_ENTRIES + 1);
        assert_eq!(record.events.len(), MAX_RECORD_ENTRIES + 1);
        assert!(
            record
                .steps
                .last()
                .unwrap()
                .detail
                .contains("further entries dropped"),
            "{:?}",
            record.steps.last()
        );
        assert!(
            record
                .events
                .last()
                .unwrap()
                .detail
                .contains("further entries dropped"),
            "{:?}",
            record.events.last()
        );
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
