//! The signed event: `envelope_bytes || sig[64] || body_bytes` (section 1).

use crate::error::CoreError;
use crate::identity::{Signer, verify};

use super::body::Body;
use super::envelope::Envelope;
use super::id::EventId;

/// The domain separation prefix every event signature is made over
/// (`docs/spec/recording.md` section 1.1): `SIGNING_PREFIX ||
/// envelope_bytes`, and nothing else. Frozen; see section 1.1's discussion
/// of why it can never collide with a TLS 1.3 `CertificateVerify` input or
/// with any other signing context already in this tree.
pub const SIGNING_PREFIX: &[u8] = b"mosschat-event-v1\x00";

const _: () = assert!(SIGNING_PREFIX.len() == 18);
const _: () = assert!(!matches!(SIGNING_PREFIX.first(), Some(0x20)));

/// One verified, parsed event: the received bytes of its envelope and body,
/// kept exactly as they arrived (R-8), plus the decoded envelope and body
/// built from them.
///
/// `envelope_bytes` and `body_bytes` are never reconstructed by
/// re-encoding: `event_id` and the signature check in
/// [`SignedEvent::parse`] are computed over these fields directly, which is
/// what R-8 requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEvent {
    /// The received envelope bytes, unchanged (R-8, R-9).
    pub envelope_bytes: Vec<u8>,
    /// The decoded envelope, built from `envelope_bytes`.
    pub envelope: Envelope,
    /// The 64 raw signature bytes.
    pub sig: [u8; 64],
    /// The received body bytes, unchanged (R-8, and R-14 for an unknown
    /// body type).
    pub body_bytes: Vec<u8>,
    /// The decoded body, built from `body_bytes`.
    pub body: Body,
    /// `BLAKE3(envelope_bytes)` (section 1).
    pub event_id: EventId,
}

/// A received event failed to parse or verify.
#[derive(Debug, thiserror::Error)]
pub enum SignedEventError {
    /// Fewer than 64 + 1 bytes: too short to hold even an empty envelope,
    /// the 64 byte signature and any body.
    #[error("event is too short to hold an envelope, a 64 byte signature and a body")]
    TooShort,
    /// The envelope did not decode (R-2, R-9's canonical check, both
    /// enforced by [`Envelope::from_cbor`]).
    #[error("envelope did not decode: {0}")]
    Envelope(#[source] minicbor::decode::Error),
    /// R-3: `v != 1`. Refused as a protocol error, distinct from R-14's
    /// unknown-body-type carry path.
    #[error("R-3: envelope version {0} is not 1")]
    UnsupportedVersion(u8),
    /// R-4: `body_len` does not match the actual length of the bytes that
    /// follow the signature.
    #[error("R-4: body_len {declared} does not match the actual body length {actual}")]
    BodyLenMismatch {
        /// The envelope's claimed `body_len`.
        declared: u32,
        /// The actual number of bytes present after the signature.
        actual: usize,
    },
    /// R-5: `body_len` exceeds the 130_847 byte cap, checked from the
    /// envelope alone, before the body bytes are read (R-44).
    #[error("R-5: body_len {0} exceeds the 130_847 byte cap")]
    BodyLenOverCap(u32),
    /// R-43: `len(envelope_bytes) + 64 + body_len` exceeds 131_072 bytes.
    #[error("R-43: total event size {0} exceeds the 131_072 byte cap")]
    TotalSizeOverCap(usize),
    /// R-6: `BLAKE3(body_bytes)` does not match the envelope's `body_hash`.
    #[error("R-6: body_hash does not match BLAKE3(body_bytes)")]
    BodyHashMismatch,
    /// The body did not decode as deterministic CBOR (R-10, R-15, R-16 and
    /// the per-type field checks, all enforced by [`Body::from_cbor`]).
    #[error("body did not decode: {0}")]
    Body(#[source] minicbor::decode::Error),
    /// R-1: the signature did not verify over `SIGNING_PREFIX ||
    /// envelope_bytes` under `verify_strict`.
    #[error("R-1: signature did not verify")]
    InvalidSignature(#[source] CoreError),
}

/// Decodes just enough of `bytes` (an 8-element envelope array followed by
/// more bytes, per section 1) to learn where the envelope ends, without
/// requiring `bytes` to contain nothing else. Mirrors
/// [`Envelope::from_cbor`]'s field reads exactly, but does not check R-2's
/// no-trailing-bytes rule (there **is** more after the envelope here: the
/// signature and body) or R-9's canonical re-encoding (left to a second,
/// narrowed call to [`Envelope::from_cbor`] on the returned prefix).
fn envelope_prefix_len(bytes: &[u8]) -> Result<usize, minicbor::decode::Error> {
    use minicbor::Decoder;
    use minicbor::decode::Error as DecodeError;

    let mut dec = Decoder::new(bytes);
    let len = dec.array()?;
    if len != Some(8) {
        return Err(DecodeError::message(
            "envelope must be a definite-length array of 8 elements",
        ));
    }
    let _v = dec.u8()?;
    let _visit = dec.bytes()?;
    let _author = dec.bytes()?;
    let _seq = dec.u64()?;
    let _prev = dec.bytes()?;
    let _ts_ms = dec.u64()?;
    let _body_hash = dec.bytes()?;
    let _body_len = dec.u32()?;
    Ok(dec.position())
}

impl SignedEvent {
    /// Builds and signs a new event from an envelope and a body, through the
    /// [`Signer`] trait rather than a concrete key type, so a caller outside
    /// this crate can depend on the trait alone.
    ///
    /// The envelope's `body_hash` and `body_len` are computed from `body`
    /// here; the caller supplies every other envelope field. The signing
    /// input is exactly `SIGNING_PREFIX || envelope_bytes` (R-1).
    ///
    /// # Panics
    ///
    /// Panics if `body`'s encoded length does not fit in a `u32`. Every
    /// known body type is far under `u32::MAX`, and this crate's own
    /// callers never build a body anywhere near that size; a body this
    /// large is a caller bug, not a runtime condition to recover from.
    #[must_use]
    pub fn sign(mut envelope: Envelope, body: &Body, signer: &impl Signer) -> Self {
        let body_bytes = body.to_cbor();
        envelope.body_hash = *blake3::hash(&body_bytes).as_bytes();
        #[allow(clippy::expect_used)]
        {
            envelope.body_len =
                u32::try_from(body_bytes.len()).expect("body encodes to more than u32::MAX bytes");
        }
        let envelope_bytes = envelope.to_cbor();
        let event_id = EventId::of_envelope(&envelope_bytes);

        let mut signing_input = Vec::with_capacity(SIGNING_PREFIX.len() + envelope_bytes.len());
        signing_input.extend_from_slice(SIGNING_PREFIX);
        signing_input.extend_from_slice(&envelope_bytes);
        let sig = signer.sign(&signing_input);

        Self {
            envelope_bytes,
            envelope,
            sig,
            body_bytes,
            body: body.clone(),
            event_id,
        }
    }

    /// Serialises this event to its wire and disk layout: `envelope_bytes ||
    /// sig || body_bytes` (section 1). Uses the stored, received bytes
    /// directly rather than re-encoding `envelope`/`body` (R-8, R-9).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.envelope_bytes.len() + 64 + self.body_bytes.len());
        out.extend_from_slice(&self.envelope_bytes);
        out.extend_from_slice(&self.sig);
        out.extend_from_slice(&self.body_bytes);
        out
    }

    /// Parses and verifies one event from received bytes.
    ///
    /// Every check in R-1 to R-6, R-9, R-10, R-43 and R-44 that can be
    /// decided from the bytes of one event alone (with no recording state)
    /// is enforced here, in the order the spec gives them, before anything
    /// is returned. Checks that need a recording's state (R-7, R-11 to
    /// R-13, and everything in section 5 that depends on prior events) are
    /// [`super::ingest::Recording::ingest`]'s job, not this function's.
    ///
    /// R-44: `body_len` is read and checked against its cap ([R-5]) from
    /// the envelope alone before any allocation sized by it; the actual
    /// body bytes are only sliced (never separately allocated) once that
    /// check passes, and slicing a claimed-oversized range out of `bytes`
    /// fails immediately rather than allocating the claimed length.
    ///
    /// # Errors
    ///
    /// See [`SignedEventError`] for the specific rejection reasons.
    pub fn parse(bytes: &[u8]) -> Result<Self, SignedEventError> {
        // The envelope is self-delimiting CBOR: find where it ends within
        // `bytes` (which also holds the signature and body that follow it)
        // by decoding its 8 fields and reading the decoder's resulting
        // position, then validate the envelope prefix on its own — R-2's
        // "no trailing bytes after the eighth" and R-9's canonical
        // re-encoding check both apply to the envelope alone, not to
        // `bytes` as a whole, which legitimately has more after it.
        let envelope_len = envelope_prefix_len(bytes).map_err(SignedEventError::Envelope)?;
        let envelope_prefix = bytes
            .get(..envelope_len)
            .ok_or(SignedEventError::TooShort)?;
        let envelope = Envelope::from_cbor(envelope_prefix).map_err(SignedEventError::Envelope)?;

        // R-3: a version other than 1 is a protocol error, refused before
        // any further check, not treated as an unknown body (that is R-14's
        // path, which applies only to the body, never to the envelope).
        if envelope.v != 1 {
            return Err(SignedEventError::UnsupportedVersion(envelope.v));
        }

        // R-5 / R-44: check body_len against its cap from the envelope
        // alone, before touching the bytes it claims to size.
        if envelope.body_len as usize > super::ingest::BODY_LEN_MAX {
            return Err(SignedEventError::BodyLenOverCap(envelope.body_len));
        }

        // R-43: the whole event's size, derivable from the envelope alone
        // (its own length plus a fixed 64 byte signature plus the claimed
        // body_len), before a single byte of signature or body is read.
        let claimed_total = envelope_len + 64 + envelope.body_len as usize;
        if claimed_total > super::ingest::EVENT_TOTAL_MAX {
            return Err(SignedEventError::TotalSizeOverCap(claimed_total));
        }

        if bytes.len() < envelope_len + 64 {
            return Err(SignedEventError::TooShort);
        }
        let envelope_bytes = envelope_prefix.to_vec();
        let sig: [u8; 64] = bytes
            .get(envelope_len..envelope_len + 64)
            .ok_or(SignedEventError::TooShort)?
            .try_into()
            .map_err(|_| SignedEventError::TooShort)?;
        let body_bytes = bytes
            .get(envelope_len + 64..)
            .ok_or(SignedEventError::TooShort)?;

        // R-4: body_len must match the actual length of the bytes present.
        if body_bytes.len() != envelope.body_len as usize {
            return Err(SignedEventError::BodyLenMismatch {
                declared: envelope.body_len,
                actual: body_bytes.len(),
            });
        }

        // R-6: body_hash must match BLAKE3(body_bytes).
        if blake3::hash(body_bytes).as_bytes() != &envelope.body_hash {
            return Err(SignedEventError::BodyHashMismatch);
        }

        // R-1: verify_strict over SIGNING_PREFIX || envelope_bytes, using
        // the received envelope_bytes, never a re-serialisation (R-8).
        let mut signing_input = Vec::with_capacity(SIGNING_PREFIX.len() + envelope_bytes.len());
        signing_input.extend_from_slice(SIGNING_PREFIX);
        signing_input.extend_from_slice(&envelope_bytes);
        verify(&envelope.author, &signing_input, &sig)
            .map_err(SignedEventError::InvalidSignature)?;

        // R-9 is already enforced by Envelope::from_cbor's own canonical
        // re-encoding check. R-10, R-14, R-15, R-16 are enforced by
        // Body::from_cbor.
        let body_bytes_owned = body_bytes.to_vec();
        let body = Body::from_cbor(&body_bytes_owned).map_err(SignedEventError::Body)?;

        // event_id is BLAKE3(envelope_bytes) over the received bytes (R-8).
        let event_id = EventId::of_envelope(&envelope_bytes);

        Ok(Self {
            envelope_bytes,
            envelope,
            sig,
            body_bytes: body_bytes_owned,
            body,
            event_id,
        })
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
    use crate::event::body::Message;
    use crate::identity::AuthorKey;

    fn sample_signed_event() -> (SignedEvent, AuthorKey) {
        let key = AuthorKey::from_bytes(&[0x07u8; 32]);
        let envelope = Envelope {
            v: 1,
            visit: [0x11u8; 32],
            author: key.public_bytes(),
            seq: 7,
            prev: [0x22u8; 32],
            ts_ms: 1_757_000_000_000,
            body_hash: [0u8; 32],
            body_len: 0,
        };
        let body = Body::Message(Message {
            text: "hello from the house".to_owned(),
            reply_to: None,
        });
        (SignedEvent::sign(envelope, &body, &key), key)
    }

    #[test]
    fn sign_then_parse_round_trips() {
        let (signed, key) = sample_signed_event();
        let bytes = signed.to_bytes();
        let parsed = SignedEvent::parse(&bytes).expect("parse");
        assert_eq!(parsed, signed);
        assert_eq!(parsed.envelope.author, key.public_bytes());
    }

    #[test]
    fn a_tampered_signature_byte_is_rejected() {
        let (signed, _key) = sample_signed_event();
        let mut bytes = signed.to_bytes();
        let envelope_len = signed.envelope_bytes.len();
        bytes[envelope_len] ^= 0xFF;
        assert!(matches!(
            SignedEvent::parse(&bytes),
            Err(SignedEventError::InvalidSignature(_))
        ));
    }

    #[test]
    fn a_tampered_body_byte_is_rejected() {
        let (signed, _key) = sample_signed_event();
        let mut bytes = signed.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        // Either the body_hash check fails, or (if the flip lands inside
        // CBOR structure) the body fails to decode/re-encode canonically;
        // either is an acceptable rejection.
        assert!(SignedEvent::parse(&bytes).is_err());
    }
}
