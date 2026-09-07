//! The D5 envelope: the fixed, frozen-at-version-1 fields every event carries.
//!
//! `envelope_bytes || sig[64] || body_bytes` is the wire and disk layout (D5);
//! this module holds only the envelope half. The signature and the opaque
//! body, `event_id` and ingest checks land in WO-2.4. Encoding is CBOR under
//! the RFC 8949 section 4.2 deterministic profile (D7), using minicbor, the
//! crate picked in WO-1.2 (reasoning and the three-way trial output are in
//! `docs/dev/cbor-pick.md`). The envelope encodes as a definite-length array
//! in field order rather than a map, which meets the deterministic profile's
//! shortest-form-integers and no-floats rules directly and makes the
//! sorted-map-keys rule vacuous, since there are no map keys.

use minicbor::decode::Error as DecodeError;
use minicbor::{Decoder, Encoder};

/// The fixed fields of one event, frozen at version 1 (D5).
///
/// Field order here is the field order on the wire: `v`, `visit`, `author`,
/// `seq`, `prev`, `ts_ms`, `body_hash`, `body_len`. Every build of every
/// version must be able to parse this shape, whether or not it understands
/// the body that follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Envelope format version. Frozen at `1`.
    pub v: u8,
    /// The visit this event belongs to.
    pub visit: [u8; 32],
    /// The author device key that wrote this event.
    pub author: [u8; 32],
    /// The host-assigned sequence number (D5: order is the host's order).
    pub seq: u64,
    /// `event_id` of the previous event in this author's chain, or all
    /// zero bytes for the first event.
    pub prev: [u8; 32],
    /// Display-only timestamp; never used to determine order.
    pub ts_ms: u64,
    /// `BLAKE3(body_bytes)`.
    pub body_hash: [u8; 32],
    /// Length in bytes of the body that follows this envelope.
    pub body_len: u32,
}

impl Envelope {
    /// Encodes this envelope as a deterministic CBOR array: definite length,
    /// shortest-form integers, field order fixed by the struct definition.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        // `Vec<u8>` as a minicbor `Write` is infallible, so these can only
        // fail on a logic error in the sequence of calls below, not on I/O.
        #[allow(clippy::unwrap_used)]
        {
            enc.array(8).unwrap();
            enc.u8(self.v).unwrap();
            enc.bytes(&self.visit).unwrap();
            enc.bytes(&self.author).unwrap();
            enc.u64(self.seq).unwrap();
            enc.bytes(&self.prev).unwrap();
            enc.u64(self.ts_ms).unwrap();
            enc.bytes(&self.body_hash).unwrap();
            enc.u32(self.body_len).unwrap();
        }
        buf
    }

    /// Decodes an envelope from its deterministic CBOR array encoding.
    ///
    /// # Errors
    ///
    /// Returns a [`minicbor::decode::Error`] if `bytes` is not a
    /// definite-length 8-element array of the expected field types.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut dec = Decoder::new(bytes);
        let len = dec.array()?;
        if len != Some(8) {
            return Err(DecodeError::message(
                "envelope must be a definite-length array of 8 elements",
            ));
        }
        let v = dec.u8()?;
        let visit = read_32(&mut dec)?;
        let author = read_32(&mut dec)?;
        let seq = dec.u64()?;
        let prev = read_32(&mut dec)?;
        let ts_ms = dec.u64()?;
        let body_hash = read_32(&mut dec)?;
        let body_len = dec.u32()?;
        Ok(Self {
            v,
            visit,
            author,
            seq,
            prev,
            ts_ms,
            body_hash,
            body_len,
        })
    }
}

fn read_32(dec: &mut Decoder<'_>) -> Result<[u8; 32], DecodeError> {
    let slice = dec.bytes()?;
    slice
        .try_into()
        .map_err(|_| DecodeError::message("expected a 32 byte string"))
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
    use rand::{Rng, RngExt};

    fn random_envelope(rng: &mut impl Rng) -> Envelope {
        Envelope {
            v: 1,
            visit: rng.random(),
            author: rng.random(),
            seq: rng.random(),
            prev: rng.random(),
            ts_ms: rng.random(),
            body_hash: rng.random(),
            body_len: rng.random(),
        }
    }

    /// D7's determinism proof: a round trip over 1000 random envelopes,
    /// decode then re-encode, asserting byte identity every time.
    #[test]
    fn round_trip_1000_random_envelopes_is_byte_identical() {
        let mut rng = rand::rng();
        for _ in 0..1000 {
            let original = random_envelope(&mut rng);
            let bytes = original.to_cbor();
            let decoded = Envelope::from_cbor(&bytes).expect("decode");
            assert_eq!(original, decoded);
            assert_eq!(bytes, decoded.to_cbor());
        }
    }

    /// A fixed sample encoded twice from two independent encoder invocations
    /// must be byte-identical.
    #[test]
    fn fixed_sample_is_stable_across_two_encodes() {
        let sample = Envelope {
            v: 1,
            visit: [1u8; 32],
            author: [2u8; 32],
            seq: 42,
            prev: [3u8; 32],
            ts_ms: 1_757_000_000_000,
            body_hash: [4u8; 32],
            body_len: 128,
        };
        assert_eq!(sample.to_cbor(), sample.to_cbor());
    }

    #[test]
    fn a_tampered_byte_fails_to_round_trip_identically() {
        let sample = Envelope {
            v: 1,
            visit: [1u8; 32],
            author: [2u8; 32],
            seq: 42,
            prev: [3u8; 32],
            ts_ms: 1_757_000_000_000,
            body_hash: [4u8; 32],
            body_len: 128,
        };
        let mut bytes = sample.to_cbor();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        // Either it fails to decode, or it decodes to a different value; both
        // are acceptable here since this is not the ingest re-encoding check
        // (that lands in WO-2.4), only a sanity check that tampering matters.
        if let Ok(decoded) = Envelope::from_cbor(&bytes) {
            assert_ne!(decoded, sample);
        }
    }
}
