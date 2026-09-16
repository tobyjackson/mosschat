//! Generates the worked hex examples committed in `docs/spec/recording.md`
//! and `docs/spec/door.md`.
//!
//! The hex in those documents must never be typed by hand: it is produced
//! by running the two `#[ignore]`d tests in this file and pasting their
//! `println!` output verbatim. Run with:
//!
//! ```text
//! cargo test -p mosschat-core --test spec_example -- --ignored --nocapture
//! ```
#![forbid(unsafe_code)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::fmt::Write as _;

use minicbor::{Decoder, Encoder};
use mosschat_core::event::envelope::Envelope;
use mosschat_core::identity::{AuthorKey, Signer, verify};

/// The domain separation prefix every event signature is made over,
/// per `docs/spec/recording.md` section 1.1.
const SIGNING_PREFIX: &[u8] = b"mosschat-event-v1\x00";

/// Renders `bytes` as lowercase hex with no `0x` prefix and no separators.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // `write!` into a `String` is infallible.
        write!(s, "{b:02x}").expect("write to String cannot fail");
    }
    s
}

/// Builds one complete Mosschat event from fixed inputs and prints every
/// part of it as hex, for `docs/spec/recording.md`.
///
/// Also proves, as real assertions rather than just printed output, that
/// the signature verifies over `SIGNING_PREFIX || envelope_bytes` and does
/// NOT verify over `envelope_bytes` alone, which is what makes the domain
/// separation prefix load-bearing rather than decorative.
#[test]
#[ignore = "generates the worked hex example for docs/spec/*.md; run with --ignored"]
fn recording_worked_example() {
    assert_eq!(SIGNING_PREFIX.len(), 18);
    // RFC 8446 section 4.4.3: every TLS 1.3 CertificateVerify signing input
    // begins with 64 repetitions of the octet 0x20. A signing input whose
    // first byte is not 0x20 can therefore never collide with one.
    assert_ne!(SIGNING_PREFIX[0], 0x20);

    let author_secret = [0x07u8; 32];
    let key = AuthorKey::from_bytes(&author_secret);
    let author_public = key.public_bytes();

    let visit = [0x11u8; 32];
    let seq = 7u64;
    let prev = [0x22u8; 32];
    let ts_ms = 1_757_000_000_000u64;

    // Deterministic CBOR map body, keys ascending, matching the imperative
    // `Encoder` style used by `Envelope::to_cbor`: key 0 => body type
    // (1 = message), key 1 => text.
    let mut body_bytes = Vec::new();
    {
        let mut enc = Encoder::new(&mut body_bytes);
        enc.map(2).expect("encode map header");
        enc.u8(0).expect("encode key 0");
        enc.u64(1).expect("encode body type");
        enc.u8(1).expect("encode key 1");
        enc.str("hello from the house").expect("encode text");
    }

    let body_hash = *blake3::hash(&body_bytes).as_bytes();
    let body_len = u32::try_from(body_bytes.len()).expect("body fits in u32");

    let envelope = Envelope {
        v: 1,
        visit,
        author: author_public,
        seq,
        prev,
        ts_ms,
        body_hash,
        body_len,
    };
    let envelope_bytes = envelope.to_cbor();
    let event_id = *blake3::hash(&envelope_bytes).as_bytes();

    let mut signing_input = Vec::new();
    signing_input.extend_from_slice(SIGNING_PREFIX);
    signing_input.extend_from_slice(&envelope_bytes);

    let sig = key.sign(&signing_input);

    assert!(verify(&author_public, &signing_input, &sig).is_ok());
    assert!(verify(&author_public, &envelope_bytes, &sig).is_err());
    assert_eq!(body_len as usize, body_bytes.len());
    assert_eq!(blake3::hash(&body_bytes).as_bytes(), &body_hash);
    assert!(envelope_bytes.len() + 64 + body_bytes.len() <= 131_072);

    let mut event = Vec::new();
    event.extend_from_slice(&envelope_bytes);
    event.extend_from_slice(&sig);
    event.extend_from_slice(&body_bytes);

    println!("=== recording.md worked example ===");
    println!("author_secret       (32) {}", hex(&author_secret));
    println!("author_public       (32) {}", hex(&author_public));
    println!("visit               (32) {}", hex(&visit));
    println!("seq                 {seq}");
    println!("prev                (32) {}", hex(&prev));
    println!("ts_ms               {ts_ms}");
    println!("body (message, CBOR map, keys ascending)");
    println!(
        "body_bytes          ({}) {}",
        body_bytes.len(),
        hex(&body_bytes)
    );
    println!("body_hash  BLAKE3   (32) {}", hex(&body_hash));
    println!("body_len            {body_len}");
    println!(
        "envelope_bytes      ({}) {}",
        envelope_bytes.len(),
        hex(&envelope_bytes)
    );
    println!("event_id   BLAKE3   (32) {}", hex(&event_id));
    println!("signing_prefix      (18) {}", hex(SIGNING_PREFIX));
    println!(
        "signing_input = signing_prefix || envelope_bytes  ({} bytes)",
        signing_input.len()
    );
    println!("sig                 (64) {}", hex(&sig));
    println!(
        "event = envelope_bytes || sig || body_bytes  ({} bytes)",
        event.len()
    );
    println!("{}", hex(&event));
}

/// Builds one complete door `Hello` frame from fixed inputs and prints it
/// as hex, for `docs/spec/door.md`.
///
/// Also proves, as real assertions, that the frame's length prefix matches
/// its payload and that the payload's outer shape (a 2 element array whose
/// first element is the frame type and second is a 4 entry map) decodes as
/// specified.
#[test]
#[ignore = "generates the worked hex example for docs/spec/*.md; run with --ignored"]
fn door_worked_example() {
    let nonce: [u8; 16] = [
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90,
    ];
    let client_version = 1u64;
    let client_name = "mosschat-tui";
    let features = ["core.v1", "scope.v1"];

    let mut payload = Vec::new();
    {
        let mut enc = Encoder::new(&mut payload);
        enc.array(2).expect("encode outer array header");
        enc.u64(1).expect("encode frame type"); // 1 = Hello
        enc.map(4).expect("encode body map header");
        enc.u8(0).expect("encode key 0");
        enc.bytes(&nonce).expect("encode nonce");
        enc.u8(1).expect("encode key 1");
        enc.u64(client_version).expect("encode client_version");
        enc.u8(2).expect("encode key 2");
        enc.str(client_name).expect("encode client_name");
        enc.u8(3).expect("encode key 3");
        enc.array(2).expect("encode features array header");
        for feature in &features {
            enc.str(feature).expect("encode feature");
        }
    }

    assert!(payload.len() <= 1_048_576);
    let len_prefix = u32::try_from(payload.len())
        .expect("payload fits in u32")
        .to_be_bytes();
    assert_eq!(u32::from_be_bytes(len_prefix) as usize, payload.len());

    {
        let mut dec = Decoder::new(&payload);
        assert_eq!(dec.array().expect("decode outer array header"), Some(2));
        assert_eq!(dec.u64().expect("decode frame type"), 1);
        assert_eq!(dec.map().expect("decode body map header"), Some(4));
    }

    let mut frame = Vec::new();
    frame.extend_from_slice(&len_prefix);
    frame.extend_from_slice(&payload);

    println!("=== door.md worked example ===");
    println!("frame type          1 (Hello)");
    println!("nonce               (16) {}", hex(&nonce));
    println!("client_version      {client_version}");
    println!("client_name         \"{client_name}\"");
    println!(
        "features            [\"{}\", \"{}\"]",
        features[0], features[1]
    );
    println!("payload             ({}) {}", payload.len(), hex(&payload));
    println!("len prefix (u32 BE) (4) {}", hex(&len_prefix));
    println!("frame = len || payload  ({} bytes)", frame.len());
    println!("{}", hex(&frame));
}
