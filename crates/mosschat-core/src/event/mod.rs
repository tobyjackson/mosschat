//! Signed events with an opaque body (D5).
//!
//! `envelope_bytes || sig[64] || body_bytes` is the wire and disk layout
//! (`docs/spec/recording.md` section 1). [`envelope`] holds the frozen
//! version 1 envelope. [`body`] holds the eight known body types (section
//! 5) and the [`body::Body::Unknown`] carrier (R-14). [`signed`] binds an
//! envelope and a body into one signed, verifiable [`signed::SignedEvent`].
//! [`ingest`] is the stateful half: [`ingest::Recording`], an in-memory
//! model of one visit's host sequence, participant set and tombstones,
//! against which every event-level rule in the spec that needs prior state
//! is checked.
//!
//! ## Interfaces for the store and the view module
//!
//! WO-2.4b (views, delete) and WO-2.5 (the store) consume this module
//! through the following surface:
//!
//! - [`id::EventId`] is the 32 byte primary key for an event:
//!   `BLAKE3(envelope_bytes)`.
//! - What a store must persist per event to reconstruct it exactly: the
//!   received `envelope_bytes` and `body_bytes` **verbatim**, byte for
//!   byte — R-8 forbids re-serialising either — plus the 64 raw signature
//!   bytes. `seq`, `visit` and `author` are recoverable from
//!   `envelope_bytes` by decoding it; a store may additionally index them
//!   as separate columns for query performance, but they are not a second
//!   source of truth, `envelope_bytes` is.
//! - [`ingest::Tombstone`] is `(seq, event_id)` and nothing else (R-50): a
//!   store row for a tombstone must not have columns for body, author or
//!   timestamp, because a tombstone carries none of them.
//! - The ingest clock is supplied by the caller as `now_ms` on every call
//!   to [`ingest::Recording::ingest`] (R-32's evaluation instant). Nothing
//!   in `mosschat-core` reads the system clock, so ingest stays
//!   deterministic and testable from fixed inputs; a store or door layer
//!   that drives ingest live is responsible for supplying a real clock
//!   reading.
//! - Rules enforced here, by [`signed::SignedEvent::parse`] and
//!   [`ingest::Recording::ingest`] together: R-1 to R-40, R-43, R-44 and
//!   R-50 (the tombstone shape and its `prev`-matching effect on R-13).
//! - Rules left to the store and view layer, not enforced by this module:
//!   R-41's actual local delete-for-real of stored bytes (this module only
//!   replaces an in-memory slot with a [`ingest::Tombstone`]; a real store
//!   must additionally remove the underlying bytes from its file, which
//!   `mosschat-core` cannot do since it holds no store); R-45 to R-49
//!   (delete-for-real's absence-from-store proof, private-visit
//!   no-row-at-all, privacy fixed at open, and every view-purity and
//!   view-rendering rule) — those need a real store and a real view
//!   renderer, neither of which exists in this crate.

pub mod body;
pub mod envelope;
pub mod id;
pub mod ingest;
pub mod signed;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::body::{Body, Message};
    use super::envelope::Envelope;
    use super::id::EventId;
    use super::ingest::Recording;
    use super::signed::{SIGNING_PREFIX, SignedEvent, SignedEventError};
    use crate::identity::{AuthorKey, verify};

    /// Renders `bytes` as lowercase hex with no `0x` prefix and no
    /// separators, matching `tests/spec_example.rs`'s own `hex` helper.
    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(s, "{b:02x}").expect("write to String cannot fail");
        }
        s
    }

    /// The frozen worked example from `docs/spec/recording.md` section 10,
    /// built through this module's own public API rather than by hand. If
    /// this test's assertions ever stop matching the spec's committed hex,
    /// the encoding in this module is wrong, not the spec.
    #[test]
    fn spec_worked_example_reproduces_frozen_hex_byte_for_byte() {
        let author_secret = [0x07u8; 32];
        let key = AuthorKey::from_bytes(&author_secret);
        let author_public = key.public_bytes();
        assert_eq!(
            hex(&author_public),
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
        );

        let visit = [0x11u8; 32];
        let seq = 7u64;
        let prev = [0x22u8; 32];
        let ts_ms = 1_757_000_000_000u64;

        let body = Body::Message(Message {
            text: "hello from the house".to_owned(),
            reply_to: None,
        });
        let body_bytes = body.to_cbor();
        assert_eq!(
            hex(&body_bytes),
            "a20001017468656c6c6f2066726f6d2074686520686f757365"
        );
        let body_hash = *blake3::hash(&body_bytes).as_bytes();
        assert_eq!(
            hex(&body_hash),
            "2e46b4ea6fc1c74f87cb69e21cface0d5b0986ced5cfe349a52861bc212a3f02"
        );

        let envelope = Envelope {
            v: 1,
            visit,
            author: author_public,
            seq,
            prev,
            ts_ms,
            body_hash,
            body_len: u32::try_from(body_bytes.len()).expect("fits in u32"),
        };

        let signed = SignedEvent::sign(envelope, &body, &key);

        assert_eq!(
            hex(&signed.envelope_bytes),
            "8801582011111111111111111111111111111111111111111111111111111111111111115820ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c07582022222222222222222222222222222222222222222222222222222222222222221b00000199155c620058202e46b4ea6fc1c74f87cb69e21cface0d5b0986ced5cfe349a52861bc212a3f021819"
        );
        assert_eq!(
            hex(signed.event_id.as_bytes()),
            "bc69b01ae86198a6de467fe0aabee03c46ad5aa3c4cf73c56ee2828b677b00cf"
        );
        assert_eq!(
            hex(&signed.sig),
            "156e3104897643f944f228d4dac15bfa92487fe187e2d1e487efee25430d7099f5a8eacd523e7568cde4e8c0acc0c267123325772152071395e61004521d1b00"
        );

        // Parsing the assembled wire bytes back through the public API
        // reproduces the same signed event.
        let bytes = signed.to_bytes();
        let parsed = SignedEvent::parse(&bytes).expect("parse the worked example");
        assert_eq!(parsed, signed);
    }

    /// A tampered byte anywhere in the wire event is rejected: verification
    /// fails, or the body no longer decodes/hashes to match.
    #[test]
    fn a_tampered_byte_is_rejected() {
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
        let signed = SignedEvent::sign(envelope, &body, &key);
        let mut bytes = signed.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert!(SignedEvent::parse(&bytes).is_err());
    }

    /// A non-deterministic re-encoding of an otherwise-verifiable envelope
    /// (a non-shortest-form integer) is rejected (R-9), even though its
    /// signature was made over exactly those non-canonical bytes.
    #[test]
    fn a_non_deterministic_reencoding_is_rejected() {
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
        let signed = SignedEvent::sign(envelope, &body, &key);

        // Hand-build a non-canonical envelope: same 8 fields, but `v`
        // encoded as `0x18 0x01` (two bytes) instead of the canonical
        // single byte `0x01`.
        let canonical = signed.envelope_bytes.clone();
        assert_eq!(canonical[0], 0x88); // array(8)
        assert_eq!(canonical[1], 0x01); // v = 1, canonical
        let mut non_canonical = Vec::with_capacity(canonical.len() + 1);
        non_canonical.push(canonical[0]);
        non_canonical.push(0x18);
        non_canonical.push(0x01);
        non_canonical.extend_from_slice(&canonical[2..]);

        // Confirm the signature was made over the canonical bytes, so a
        // signature check alone (without R-9's byte-for-byte re-encoding
        // check) would not catch this: verify_strict against the
        // non-canonical bytes must fail for this probe to be meaningful.
        let mut signing_input_noncanonical = Vec::new();
        signing_input_noncanonical.extend_from_slice(SIGNING_PREFIX);
        signing_input_noncanonical.extend_from_slice(&non_canonical);
        assert!(
            verify(
                &key.public_bytes(),
                &signing_input_noncanonical,
                &signed.sig
            )
            .is_err()
        );

        // Envelope::from_cbor itself rejects the non-canonical bytes (R-9),
        // so a full event built on them never reaches SignedEvent::parse's
        // later checks; this is the format's actual rejection point.
        assert!(Envelope::from_cbor(&non_canonical).is_err());

        let mut event = Vec::new();
        event.extend_from_slice(&non_canonical);
        event.extend_from_slice(&signed.sig);
        event.extend_from_slice(&body.to_cbor());
        assert!(matches!(
            SignedEvent::parse(&event),
            Err(SignedEventError::Envelope(_))
        ));
    }

    /// A minimal end-to-end smoke test through [`Recording::ingest`],
    /// exercised more thoroughly by `tests/abuse.rs`.
    #[test]
    fn recording_accepts_a_well_formed_first_event() {
        let host = AuthorKey::generate();
        let visit = [0x33u8; 32];
        let mut recording = Recording::new(visit, host.public_bytes()).expect("open");

        let join_body = Body::Join(super::body::Join {
            person: host.public_bytes(),
            devices: vec![host.public_bytes()],
            name: None,
        });
        let envelope = Envelope {
            v: 1,
            visit,
            author: host.public_bytes(),
            seq: 0,
            prev: [0u8; 32],
            ts_ms: 0,
            body_hash: [0u8; 32],
            body_len: 0,
        };
        let signed = SignedEvent::sign(envelope, &join_body, &host);
        let event_id: EventId = recording.ingest(&signed.to_bytes(), 0).expect("ingest");
        assert_eq!(event_id, signed.event_id);
    }
}
