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
    /// definite-length 8-element array of the expected field types, if
    /// `bytes` carries anything after the 8th field, or if `bytes` is not
    /// itself the canonical shortest-form encoding of the value it decodes
    /// to (D7's deterministic profile).
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
        if dec.position() != bytes.len() {
            return Err(DecodeError::message(
                "envelope must not carry trailing bytes after its 8 fields",
            ));
        }
        let envelope = Self {
            v,
            visit,
            author,
            seq,
            prev,
            ts_ms,
            body_hash,
            body_len,
        };
        // D7's deterministic profile requires shortest-form integers; rather
        // than hand-audit minicbor's internal `type_len` table field by
        // field, re-encode the decoded value and require a byte-for-byte
        // match against the input. Any non-canonical encoding (e.g. `0x18
        // 0x01` for a value that fits the direct-value form) re-encodes
        // shorter and is caught here.
        if envelope.to_cbor() != bytes {
            return Err(DecodeError::message(
                "envelope is not the canonical shortest-form CBOR encoding",
            ));
        }
        Ok(envelope)
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

    /// minicbor's shortest-form integer width in bytes for `v`, matching the
    /// major-type-0 branches in its own `encoder.rs`/`type_len`: 1 byte for
    /// the direct-value range, then 2, 3, 5 and 9 byte headers as the value
    /// grows past each width's ceiling.
    fn cbor_uint_len(v: u64) -> usize {
        match v {
            0..=23 => 1,
            24..=255 => 2,
            256..=65535 => 3,
            65536..=0xFFFF_FFFF => 5,
            _ => 9,
        }
    }

    /// Draws a `u64` uniformly from one of the five integer-width buckets
    /// Konrad's review named ([0,23], [24,255], [256,65535],
    /// [65536,2^32-1], [2^32,u64::MAX]), rather than uniformly over the
    /// whole range, so every branch of minicbor's shortest-form encoding is
    /// exercised with roughly equal probability instead of one branch
    /// dominating 1000 draws.
    fn random_bucketed_u64(rng: &mut impl Rng) -> u64 {
        match rng.random_range(0..5u8) {
            0 => rng.random_range(0..=23u64),
            1 => rng.random_range(24..=255u64),
            2 => rng.random_range(256..=65535u64),
            3 => rng.random_range(65536..=u64::from(u32::MAX)),
            _ => rng.random_range(u64::from(u32::MAX) + 1..=u64::MAX),
        }
    }

    /// Same idea as [`random_bucketed_u64`], but for `body_len: u32`, which
    /// only has four reachable width buckets.
    fn random_bucketed_u32(rng: &mut impl Rng) -> u32 {
        match rng.random_range(0..4u8) {
            0 => rng.random_range(0..=23u32),
            1 => rng.random_range(24..=255u32),
            2 => rng.random_range(256..=65535u32),
            _ => rng.random_range(65536..=u32::MAX),
        }
    }

    fn random_envelope(rng: &mut impl Rng) -> Envelope {
        Envelope {
            v: 1,
            visit: rng.random(),
            author: rng.random(),
            seq: random_bucketed_u64(rng),
            prev: rng.random(),
            ts_ms: random_bucketed_u64(rng),
            body_hash: rng.random(),
            body_len: random_bucketed_u32(rng),
        }
    }

    /// The fixed portion of an envelope's encoding: the 8-element array
    /// header (1 byte) plus `v` (always `1`, 1 byte) plus the four 32 byte
    /// strings (each a 2 byte header, since 32 > 23, plus 32 bytes of data).
    const FIXED_ENCODING_LEN: usize = 1 + 1 + 4 * (2 + 32);

    fn expected_encoding_len(e: &Envelope) -> usize {
        FIXED_ENCODING_LEN
            + cbor_uint_len(e.seq)
            + cbor_uint_len(e.ts_ms)
            + cbor_uint_len(u64::from(e.body_len))
    }

    /// D7's determinism proof: a round trip over 1000 random envelopes,
    /// decode then re-encode, asserting byte identity every time. `seq`,
    /// `ts_ms` and `body_len` are drawn from [`random_bucketed_u64`] and
    /// [`random_bucketed_u32`] rather than uniformly, so this exercises
    /// every one of minicbor's integer-width branches rather than almost
    /// always taking the 9-byte branch, and the encoded length is checked
    /// against the width each drawn value should produce.
    #[test]
    fn round_trip_1000_random_envelopes_is_byte_identical() {
        let mut rng = rand::rng();
        for _ in 0..1000 {
            let original = random_envelope(&mut rng);
            let bytes = original.to_cbor();
            assert_eq!(bytes.len(), expected_encoding_len(&original));
            let decoded = Envelope::from_cbor(&bytes).expect("decode");
            assert_eq!(original, decoded);
            assert_eq!(bytes, decoded.to_cbor());
        }
    }

    /// Exact width-boundary values named in Konrad's review, checked one at
    /// a time against a fixed envelope so the resulting length change is
    /// attributable to exactly the field under test.
    #[test]
    fn integer_width_boundaries_encode_to_the_expected_length() {
        let boundaries: &[u64] = &[
            0,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            u64::MAX,
        ];
        for &value in boundaries {
            let mut e = Envelope {
                v: 1,
                visit: [0u8; 32],
                author: [0u8; 32],
                seq: value,
                prev: [0u8; 32],
                ts_ms: 0,
                body_hash: [0u8; 32],
                body_len: 0,
            };
            let bytes = e.to_cbor();
            assert_eq!(
                bytes.len(),
                expected_encoding_len(&e),
                "seq={value} encoded to an unexpected length"
            );
            e.seq = 0;
            e.ts_ms = value;
            let bytes = e.to_cbor();
            assert_eq!(
                bytes.len(),
                expected_encoding_len(&e),
                "ts_ms={value} encoded to an unexpected length"
            );
            e.ts_ms = 0;
            if let Ok(body_len) = u32::try_from(value) {
                e.body_len = body_len;
                let bytes = e.to_cbor();
                assert_eq!(
                    bytes.len(),
                    expected_encoding_len(&e),
                    "body_len={value} encoded to an unexpected length"
                );
            }
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

    fn sample_envelope() -> Envelope {
        Envelope {
            v: 1,
            visit: [1u8; 32],
            author: [2u8; 32],
            seq: 42,
            prev: [3u8; 32],
            ts_ms: 1_757_000_000_000,
            body_hash: [4u8; 32],
            body_len: 128,
        }
    }

    /// Yseult's finding: a valid envelope with trailing bytes appended must
    /// be rejected, not silently decoded while ignoring the tail.
    #[test]
    fn rejects_trailing_bytes_after_the_envelope() {
        let mut bytes = sample_envelope().to_cbor();
        bytes.extend(std::iter::repeat_n(0xFFu8, 64));
        assert!(Envelope::from_cbor(&bytes).is_err());
    }

    /// Yseult's finding: `0x18 0x01` (a non-shortest-form encoding of `1`)
    /// in place of the canonical single byte `0x01` for `v` must be
    /// rejected, even though it decodes to the same value `1`.
    #[test]
    fn rejects_non_canonical_integer_encoding() {
        let canonical = sample_envelope().to_cbor();
        // Byte 0 is the array header; byte 1 is `v`'s canonical single-byte
        // encoding of `1` (major type 0, direct value 1: `0x01`).
        assert_eq!(canonical[1], 0x01);
        let mut non_canonical = Vec::with_capacity(canonical.len() + 1);
        non_canonical.push(canonical[0]);
        non_canonical.push(0x18); // one-byte-length-follows marker
        non_canonical.push(0x01); // the same value, 1, in non-shortest form
        non_canonical.extend_from_slice(&canonical[2..]);
        assert!(Envelope::from_cbor(&non_canonical).is_err());
    }

    /// Yseult's finding, and the existing `len != Some(8)` guard: an array
    /// of the wrong length must be rejected rather than partially decoded.
    #[test]
    fn rejects_arrays_of_the_wrong_length() {
        let mut bytes = sample_envelope().to_cbor();
        // Byte 0 is the array header `0x88` (definite length 8); `0x87`
        // claims 7 elements while the same 8 fields of data still follow.
        assert_eq!(bytes[0], 0x88);
        bytes[0] = 0x87;
        assert!(Envelope::from_cbor(&bytes).is_err());
    }

    /// Yseult's finding: a byte-string length prefix must be checked
    /// against the remaining input before any data is read, so a hostile
    /// claim of `u64::MAX` bytes fails immediately instead of allocating or
    /// hanging. minicbor's `read_slice` bounds-checks via `buf.get(range)`
    /// before returning a slice, so this never allocates on the claimed
    /// length; this test pins that behaviour at the envelope boundary.
    #[test]
    fn rejects_an_oversized_length_prefix_before_allocating() {
        let mut bytes = vec![0x88u8, 0x01]; // array(8), v = 1
        bytes.push(0x5B); // byte string, 8-byte length follows
        bytes.extend_from_slice(&u64::MAX.to_be_bytes());
        // No data follows the bogus length; a correct decoder must fail
        // fast on the bounds check rather than attempt to read or allocate
        // `u64::MAX` bytes.
        assert!(Envelope::from_cbor(&bytes).is_err());
    }
}
