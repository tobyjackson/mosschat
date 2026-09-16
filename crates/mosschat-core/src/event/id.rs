//! [`EventId`], the 32 byte content identifier of one event.

use std::fmt;

/// `event_id = BLAKE3(envelope_bytes)` (`docs/spec/recording.md` section 1).
///
/// A newtype over the raw 32 byte hash so callers cannot confuse an
/// `EventId` with any other 32 byte value in this crate (a public key, a
/// visit id, a `body_hash`) at the type level.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId([u8; 32]);

impl EventId {
    /// Wraps 32 raw bytes as an `EventId` with no further validation: any 32
    /// byte value is a syntactically valid id, whether or not any recording
    /// holds an event that hashes to it.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the 32 raw bytes of this id.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Computes `BLAKE3(envelope_bytes)`, the `event_id` of the event whose
    /// received envelope bytes are `envelope_bytes` (section 1).
    #[must_use]
    pub fn of_envelope(envelope_bytes: &[u8]) -> Self {
        Self(*blake3::hash(envelope_bytes).as_bytes())
    }
}

impl fmt::Debug for EventId {
    /// Prints as lowercase hex, truncated to the first 8 bytes (16 hex
    /// characters) followed by `..`, which is enough to distinguish ids in a
    /// test failure or a log line without a 64 character wall of hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "..")
    }
}
