//! Event bodies (`docs/spec/recording.md` section 5).
//!
//! A body is a definite-length CBOR map with unsigned integer keys in
//! ascending order, key `0` always the body type. Every known type here is
//! encoded and decoded imperatively with `minicbor`'s `Encoder`/`Decoder`,
//! matching `envelope.rs`'s style: no `serde`, no derive.
//!
//! R-10 requires that decoding a body of a **known** type and re-encoding it
//! reproduce the input byte for byte. [`Body::from_cbor`] enforces this by
//! re-encoding every known-type body it decodes and comparing against the
//! input, exactly as [`super::envelope::Envelope::from_cbor`] does for the
//! envelope. An [`Body::Unknown`] body is never re-encoded (R-14): its raw
//! bytes are kept and returned verbatim by [`Body::to_cbor`].

use minicbor::decode::Error as DecodeError;
use minicbor::{Decoder, Encoder};

/// `message.text`'s cap in bytes (R-17, section 6).
pub const MESSAGE_TEXT_MAX: usize = 65_536;
/// `reaction.symbol`'s cap in bytes (R-20, section 6).
pub const REACTION_SYMBOL_MAX: usize = 32;
/// `attachment.name`'s cap in bytes (R-22, section 6).
pub const ATTACHMENT_NAME_MAX: usize = 128;
/// `attachment.media_type`'s cap in bytes (section 5.3's table).
pub const ATTACHMENT_MEDIA_TYPE_MAX: usize = 128;
/// `attachment.size`'s cap (section 5.3's table).
pub const ATTACHMENT_SIZE_MAX: u64 = 1 << 40;
/// `join.name`'s cap in bytes (section 6).
pub const JOIN_NAME_MAX: usize = 128;
/// `join.devices`'s cap in entries (R-26).
pub const JOIN_DEVICES_MAX: usize = 8;
/// `device-add.label`'s cap in bytes (section 6).
pub const DEVICE_ADD_LABEL_MAX: usize = 128;
/// `drop-request.targets`'s cap in entries (R-39).
pub const DROP_REQUEST_TARGETS_MAX: usize = 64;
/// `drop-request.note`'s cap in bytes (section 5.8's table).
pub const DROP_REQUEST_NOTE_MAX: usize = 256;
/// The writer default window length for a `device-add`, 365 days in
/// milliseconds (R-35, section 5.6): `not_after_ms = not_before_ms +
/// DEVICE_ADD_DEFAULT_WINDOW_MS`. A default a writer may use, not a format
/// rule: a conforming reader enforces R-32 against whatever window it is
/// given, whatever its length.
pub const DEVICE_ADD_DEFAULT_WINDOW_MS: u64 = 31_536_000_000;

/// The body type value at map key `0` (section 5's table). Type values `0`
/// to `127` are reserved by the specification; `128` and above are free for
/// private extensions and are never assigned here.
pub mod type_value {
    /// `message` (section 5.1).
    pub const MESSAGE: u64 = 1;
    /// `reaction` (section 5.2).
    pub const REACTION: u64 = 2;
    /// `attachment` (section 5.3).
    pub const ATTACHMENT: u64 = 3;
    /// `join` (section 5.4).
    pub const JOIN: u64 = 4;
    /// `leave` (section 5.5).
    pub const LEAVE: u64 = 5;
    /// `device-add` (section 5.6).
    pub const DEVICE_ADD: u64 = 6;
    /// `device-revoke` (section 5.7).
    pub const DEVICE_REVOKE: u64 = 7;
    /// `drop-request` (section 5.8).
    pub const DROP_REQUEST: u64 = 8;
}

/// A `message` body (section 5.1): a plain text event, optionally a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The message text (R-16, R-17: 1 to 65_536 UTF-8 bytes).
    pub text: String,
    /// `event_id` of the event this replies to, when present (R-18).
    pub reply_to: Option<[u8; 32]>,
}

/// A `reaction` body (section 5.2): adds or withdraws a short reaction to a
/// target event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaction {
    /// `event_id` of the event reacted to (R-19).
    pub target: [u8; 32],
    /// The reaction symbol, 1 to 32 UTF-8 bytes (R-20).
    pub symbol: String,
    /// `true` withdraws a reaction this author previously made; absent
    /// (`false` here) means add (R-21).
    pub remove: bool,
}

/// An `attachment` body (section 5.3): the signed announcement of a file
/// transfer. The file's bytes are never in the recording.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// `BLAKE3` of the whole file.
    pub hash: [u8; 32],
    /// File size in bytes (R-22's table: at most `2^40`).
    pub size: u64,
    /// The sender's filename, as sent (R-22, R-23).
    pub name: String,
    /// An IANA media type, an unverified hint only (R-24).
    pub media_type: Option<String>,
}

/// A `join` body (section 5.4): the host admits a person's device keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Join {
    /// The person's identity key (their first device key, section 5.6).
    pub person: [u8; 32],
    /// The device keys of that person admitted to this visit (R-26: 1 to 8
    /// entries, no duplicate, contains `person`).
    pub devices: Vec<[u8; 32]>,
    /// The display name the host holds for them, when present.
    pub name: Option<String>,
}

/// A `leave` body (section 5.5): the host records a person's departure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leave {
    /// The person leaving.
    pub person: [u8; 32],
    /// Why: 0 left, 1 timed out, 2 removed by the host, 3 the visit ended.
    pub reason: u64,
}

/// A `device-add` body (section 5.6): links a new device key to a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAdd {
    /// The device key being added.
    pub device: [u8; 32],
    /// Unix milliseconds; the grant is invalid before this instant (R-31).
    pub not_before_ms: u64,
    /// Unix milliseconds; the grant is invalid at and after this instant
    /// (R-31, R-32).
    pub not_after_ms: u64,
    /// A human label, "the laptop", when present.
    pub label: Option<String>,
}

/// A `device-revoke` body (section 5.7): a person disowns one of their own
/// device keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevoke {
    /// The device key that is no longer this person (R-36).
    pub device: [u8; 32],
    /// The instant the revoker asserts the device stopped being them.
    pub at_ms: u64,
}

/// A `drop-request` body (section 5.8): a request, not a guarantee, that
/// some or all of this visit be deleted locally by every participant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropRequest {
    /// 0 the whole visit, 1 the events named in `targets` (R-39).
    pub scope: u64,
    /// `event_id`s, required and non-empty when `scope == 1`, absent when
    /// `scope == 0` (R-39, R-40).
    pub targets: Option<Vec<[u8; 32]>>,
    /// A reason shown to the recipient, when present.
    pub note: Option<String>,
}

/// One event body (section 5): a known type, or an opaque carrier for a
/// type this build does not recognise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    /// `message`, type value 1.
    Message(Message),
    /// `reaction`, type value 2.
    Reaction(Reaction),
    /// `attachment`, type value 3.
    Attachment(Attachment),
    /// `join`, type value 4.
    Join(Join),
    /// `leave`, type value 5.
    Leave(Leave),
    /// `device-add`, type value 6.
    DeviceAdd(DeviceAdd),
    /// `device-revoke`, type value 7.
    DeviceRevoke(DeviceRevoke),
    /// `drop-request`, type value 8.
    DropRequest(DropRequest),
    /// R-14: a body type this build does not know, carried whole. `raw` is
    /// the complete received `body_bytes`, byte for byte; it is never
    /// re-encoded (R-10 does not apply to it).
    Unknown {
        /// The body type value at map key `0`.
        type_value: u64,
        /// The complete received body bytes, unchanged.
        raw: Vec<u8>,
    },
}

/// A required map key was absent from a known body type (R-15).
fn missing_key(type_value: u64, key: u64) -> DecodeError {
    DecodeError::message(format!(
        "body type {type_value} is missing required key {key}"
    ))
}

/// A definite-length map header was expected but not found, or a key
/// arrived out of ascending order (R-2's analogue for bodies, and R-10's
/// canonical-key-order requirement, checked structurally during decode by
/// requiring strictly increasing keys).
fn malformed(msg: &'static str) -> DecodeError {
    DecodeError::message(msg)
}

fn read_32(dec: &mut Decoder<'_>) -> Result<[u8; 32], DecodeError> {
    let slice = dec.bytes()?;
    slice
        .try_into()
        .map_err(|_| DecodeError::message("expected a 32 byte string"))
}

/// Reads one map entry's key, enforcing R-10's ascending-key order: `key`
/// must be strictly greater than `last_key`, or `None` on the first call.
/// Unknown keys within a known body type are permitted (section 5: "Unknown
/// keys in a known body type are ignored on read"), so the caller decides
/// whether to consume or skip the paired value.
fn next_key(dec: &mut Decoder<'_>, last_key: Option<u64>) -> Result<u64, DecodeError> {
    let key = dec.u64()?;
    if let Some(last) = last_key
        && key <= last
    {
        return Err(malformed("body map keys must be strictly ascending (R-10)"));
    }
    Ok(key)
}

impl Body {
    /// Encodes this body as deterministic CBOR (R-10): a definite-length map
    /// with unsigned integer keys in ascending order, key `0` the body
    /// type. [`Body::Unknown`] returns its stored raw bytes verbatim,
    /// unchanged, per R-14.
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        match self {
            Body::Unknown { raw, .. } => raw.clone(),
            known => encode_known(known),
        }
    }

    /// Decodes a body from its deterministic CBOR encoding.
    ///
    /// A **known** type (map key `0` in `1..=8`) is decoded field by field,
    /// checked against R-15 (required keys present) and R-16 (text fields
    /// measured in UTF-8 bytes), then re-encoded and compared against
    /// `bytes` byte for byte (R-10): a non-canonical encoding of an
    /// otherwise-valid known body is rejected here, before the caller ever
    /// sees a decoded value built from it.
    ///
    /// An **unknown** type (map key `0` outside `1..=8`, or `0` itself,
    /// which is permanently unassigned) is still required to be a
    /// definite-length CBOR map with an unsigned integer key `0` — that much
    /// structure every build must parse to find the type — but its exact
    /// bytes are kept as [`Body::Unknown::raw`] and never re-encoded (R-14).
    ///
    /// # Errors
    ///
    /// Returns a [`minicbor::decode::Error`] if `bytes` is not a
    /// definite-length CBOR map, if key `0` is missing or not an unsigned
    /// integer, if a known type is missing a required key or carries a
    /// field of the wrong type or over its cap, or if a known type's
    /// canonical re-encoding does not match `bytes`.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut peek = Decoder::new(bytes);
        let len = peek.map()?;
        if len.is_none() {
            return Err(malformed("body must be a definite-length CBOR map"));
        }
        let mut probe = Decoder::new(bytes);
        let _ = probe.map()?;
        let key0 = probe.u64()?;
        if key0 != 0 {
            return Err(malformed("body map's first key must be 0 (the type)"));
        }
        let type_value = probe.u64()?;

        let body = match type_value {
            type_value::MESSAGE => Body::Message(decode_message(bytes)?),
            type_value::REACTION => Body::Reaction(decode_reaction(bytes)?),
            type_value::ATTACHMENT => Body::Attachment(decode_attachment(bytes)?),
            type_value::JOIN => Body::Join(decode_join(bytes)?),
            type_value::LEAVE => Body::Leave(decode_leave(bytes)?),
            type_value::DEVICE_ADD => Body::DeviceAdd(decode_device_add(bytes)?),
            type_value::DEVICE_REVOKE => Body::DeviceRevoke(decode_device_revoke(bytes)?),
            type_value::DROP_REQUEST => Body::DropRequest(decode_drop_request(bytes)?),
            other => {
                return Ok(Body::Unknown {
                    type_value: other,
                    raw: bytes.to_vec(),
                });
            }
        };

        // R-10: a known type's decoded value must re-encode to exactly the
        // received bytes. Anything looser (float values, indefinite length,
        // non-shortest integers, out-of-order keys already caught above by
        // `next_key`) is rejected here.
        if body.to_cbor() != bytes {
            return Err(malformed(
                "known body type is not the canonical deterministic CBOR encoding (R-10)",
            ));
        }
        Ok(body)
    }

    /// The body type value at map key `0` (section 5's table): `1` to `8`
    /// for a known type, or the carried value for [`Body::Unknown`].
    #[must_use]
    pub fn type_value(&self) -> u64 {
        match self {
            Body::Message(_) => type_value::MESSAGE,
            Body::Reaction(_) => type_value::REACTION,
            Body::Attachment(_) => type_value::ATTACHMENT,
            Body::Join(_) => type_value::JOIN,
            Body::Leave(_) => type_value::LEAVE,
            Body::DeviceAdd(_) => type_value::DEVICE_ADD,
            Body::DeviceRevoke(_) => type_value::DEVICE_REVOKE,
            Body::DropRequest(_) => type_value::DROP_REQUEST,
            Body::Unknown { type_value, .. } => *type_value,
        }
    }
}

fn encode_known(body: &Body) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    // Every `Vec<u8>` write below is infallible (matches `envelope.rs`'s
    // rationale for the same pattern).
    #[allow(clippy::unwrap_used)]
    match body {
        Body::Message(m) => {
            let has_reply = m.reply_to.is_some();
            enc.map(if has_reply { 3 } else { 2 }).unwrap();
            enc.u8(0).unwrap();
            enc.u64(type_value::MESSAGE).unwrap();
            enc.u8(1).unwrap();
            enc.str(&m.text).unwrap();
            if let Some(reply_to) = &m.reply_to {
                enc.u8(2).unwrap();
                enc.bytes(reply_to).unwrap();
            }
        }
        Body::Reaction(r) => {
            let has_remove = r.remove;
            enc.map(if has_remove { 4 } else { 3 }).unwrap();
            enc.u8(0).unwrap();
            enc.u64(type_value::REACTION).unwrap();
            enc.u8(1).unwrap();
            enc.bytes(&r.target).unwrap();
            enc.u8(2).unwrap();
            enc.str(&r.symbol).unwrap();
            if has_remove {
                enc.u8(3).unwrap();
                enc.bool(true).unwrap();
            }
        }
        Body::Attachment(a) => {
            let has_media = a.media_type.is_some();
            enc.map(if has_media { 5 } else { 4 }).unwrap();
            enc.u8(0).unwrap();
            enc.u64(type_value::ATTACHMENT).unwrap();
            enc.u8(1).unwrap();
            enc.bytes(&a.hash).unwrap();
            enc.u8(2).unwrap();
            enc.u64(a.size).unwrap();
            enc.u8(3).unwrap();
            enc.str(&a.name).unwrap();
            if let Some(media_type) = &a.media_type {
                enc.u8(4).unwrap();
                enc.str(media_type).unwrap();
            }
        }
        Body::Join(j) => {
            let has_name = j.name.is_some();
            enc.map(if has_name { 4 } else { 3 }).unwrap();
            enc.u8(0).unwrap();
            enc.u64(type_value::JOIN).unwrap();
            enc.u8(1).unwrap();
            enc.bytes(&j.person).unwrap();
            enc.u8(2).unwrap();
            enc.array(j.devices.len() as u64).unwrap();
            for device in &j.devices {
                enc.bytes(device).unwrap();
            }
            if let Some(name) = &j.name {
                enc.u8(3).unwrap();
                enc.str(name).unwrap();
            }
        }
        Body::Leave(l) => {
            enc.map(3).unwrap();
            enc.u8(0).unwrap();
            enc.u64(type_value::LEAVE).unwrap();
            enc.u8(1).unwrap();
            enc.bytes(&l.person).unwrap();
            enc.u8(2).unwrap();
            enc.u64(l.reason).unwrap();
        }
        Body::DeviceAdd(d) => {
            let has_label = d.label.is_some();
            enc.map(if has_label { 5 } else { 4 }).unwrap();
            enc.u8(0).unwrap();
            enc.u64(type_value::DEVICE_ADD).unwrap();
            enc.u8(1).unwrap();
            enc.bytes(&d.device).unwrap();
            enc.u8(2).unwrap();
            enc.u64(d.not_before_ms).unwrap();
            enc.u8(3).unwrap();
            enc.u64(d.not_after_ms).unwrap();
            if let Some(label) = &d.label {
                enc.u8(4).unwrap();
                enc.str(label).unwrap();
            }
        }
        Body::DeviceRevoke(d) => {
            enc.map(3).unwrap();
            enc.u8(0).unwrap();
            enc.u64(type_value::DEVICE_REVOKE).unwrap();
            enc.u8(1).unwrap();
            enc.bytes(&d.device).unwrap();
            enc.u8(2).unwrap();
            enc.u64(d.at_ms).unwrap();
        }
        Body::DropRequest(r) => {
            let field_count = 2 + usize::from(r.targets.is_some()) + usize::from(r.note.is_some());
            enc.map(field_count as u64).unwrap();
            enc.u8(0).unwrap();
            enc.u64(type_value::DROP_REQUEST).unwrap();
            enc.u8(1).unwrap();
            enc.u64(r.scope).unwrap();
            if let Some(targets) = &r.targets {
                enc.u8(2).unwrap();
                enc.array(targets.len() as u64).unwrap();
                for target in targets {
                    enc.bytes(target).unwrap();
                }
            }
            if let Some(note) = &r.note {
                enc.u8(3).unwrap();
                enc.str(note).unwrap();
            }
        }
        Body::Unknown { .. } => unreachable!("encode_known is never called for Body::Unknown"),
    }
    buf
}

/// Measures a decoded text field in UTF-8 bytes (R-16): `str()` already
/// guarantees valid UTF-8, so this is exactly `.len()`, named at each call
/// site to make the "bytes, not chars" rule visible in the code that
/// enforces it.
fn utf8_len(s: &str) -> usize {
    s.len()
}

fn decode_message(bytes: &[u8]) -> Result<Message, DecodeError> {
    let mut dec = Decoder::new(bytes);
    let map_len = dec.map()?;
    if map_len.is_none() {
        return Err(malformed("message body must be a definite-length map"));
    }
    let mut text: Option<String> = None;
    let mut reply_to: Option<[u8; 32]> = None;
    let mut last_key = None;
    let entries = map_len.unwrap_or_default();
    for _ in 0..entries {
        let key = next_key(&mut dec, last_key)?;
        last_key = Some(key);
        match key {
            0 => {
                let t = dec.u64()?;
                if t != type_value::MESSAGE {
                    return Err(malformed("message body's key 0 must be 1"));
                }
            }
            1 => {
                let s = dec.str()?;
                if utf8_len(s) == 0 || utf8_len(s) > MESSAGE_TEXT_MAX {
                    return Err(malformed(
                        "message.text must be 1 to 65_536 UTF-8 bytes (R-17)",
                    ));
                }
                text = Some(s.to_owned());
            }
            2 => reply_to = Some(read_32(&mut dec)?),
            _ => dec.skip()?,
        }
    }
    Ok(Message {
        text: text.ok_or_else(|| missing_key(type_value::MESSAGE, 1))?,
        reply_to,
    })
}

fn decode_reaction(bytes: &[u8]) -> Result<Reaction, DecodeError> {
    let mut dec = Decoder::new(bytes);
    let map_len = dec.map()?;
    if map_len.is_none() {
        return Err(malformed("reaction body must be a definite-length map"));
    }
    let mut target: Option<[u8; 32]> = None;
    let mut symbol: Option<String> = None;
    let mut remove = false;
    let mut last_key = None;
    for _ in 0..map_len.unwrap_or_default() {
        let key = next_key(&mut dec, last_key)?;
        last_key = Some(key);
        match key {
            0 => {
                let t = dec.u64()?;
                if t != type_value::REACTION {
                    return Err(malformed("reaction body's key 0 must be 2"));
                }
            }
            1 => target = Some(read_32(&mut dec)?),
            2 => {
                let s = dec.str()?;
                if utf8_len(s) == 0 || utf8_len(s) > REACTION_SYMBOL_MAX {
                    return Err(malformed(
                        "reaction.symbol must be 1 to 32 UTF-8 bytes (R-20)",
                    ));
                }
                symbol = Some(s.to_owned());
            }
            3 => {
                let b = dec.bool()?;
                if !b {
                    return Err(malformed(
                        "reaction.remove, when present, must be true (absent means add)",
                    ));
                }
                remove = true;
            }
            _ => dec.skip()?,
        }
    }
    Ok(Reaction {
        target: target.ok_or_else(|| missing_key(type_value::REACTION, 1))?,
        symbol: symbol.ok_or_else(|| missing_key(type_value::REACTION, 2))?,
        remove,
    })
}

fn decode_attachment(bytes: &[u8]) -> Result<Attachment, DecodeError> {
    let mut dec = Decoder::new(bytes);
    let map_len = dec.map()?;
    if map_len.is_none() {
        return Err(malformed("attachment body must be a definite-length map"));
    }
    let mut hash: Option<[u8; 32]> = None;
    let mut size: Option<u64> = None;
    let mut name: Option<String> = None;
    let mut media_type: Option<String> = None;
    let mut last_key = None;
    for _ in 0..map_len.unwrap_or_default() {
        let key = next_key(&mut dec, last_key)?;
        last_key = Some(key);
        match key {
            0 => {
                let t = dec.u64()?;
                if t != type_value::ATTACHMENT {
                    return Err(malformed("attachment body's key 0 must be 3"));
                }
            }
            1 => hash = Some(read_32(&mut dec)?),
            2 => {
                let s = dec.u64()?;
                if s > ATTACHMENT_SIZE_MAX {
                    return Err(malformed("attachment.size must be at most 2^40"));
                }
                size = Some(s);
            }
            3 => {
                let s = dec.str()?;
                validate_attachment_name(s)?;
                name = Some(s.to_owned());
            }
            4 => {
                let s = dec.str()?;
                if utf8_len(s) > ATTACHMENT_MEDIA_TYPE_MAX {
                    return Err(malformed("attachment.media_type must be at most 128 bytes"));
                }
                media_type = Some(s.to_owned());
            }
            _ => dec.skip()?,
        }
    }
    Ok(Attachment {
        hash: hash.ok_or_else(|| missing_key(type_value::ATTACHMENT, 1))?,
        size: size.ok_or_else(|| missing_key(type_value::ATTACHMENT, 2))?,
        name: name.ok_or_else(|| missing_key(type_value::ATTACHMENT, 3))?,
        media_type,
    })
}

/// R-22: `name` is at most 128 bytes, not empty, contains no `U+0000`, `/`
/// or `\`, and is not `.` or `..`.
fn validate_attachment_name(name: &str) -> Result<(), DecodeError> {
    if utf8_len(name) == 0 || utf8_len(name) > ATTACHMENT_NAME_MAX {
        return Err(malformed("attachment.name must be 1 to 128 bytes (R-22)"));
    }
    if name.contains('\u{0000}') || name.contains('/') || name.contains('\\') {
        return Err(malformed(
            "attachment.name must not contain NUL, '/' or '\\' (R-22)",
        ));
    }
    if name == "." || name == ".." {
        return Err(malformed("attachment.name must not be '.' or '..' (R-22)"));
    }
    Ok(())
}

fn decode_join(bytes: &[u8]) -> Result<Join, DecodeError> {
    let mut dec = Decoder::new(bytes);
    let map_len = dec.map()?;
    if map_len.is_none() {
        return Err(malformed("join body must be a definite-length map"));
    }
    let mut person: Option<[u8; 32]> = None;
    let mut devices: Option<Vec<[u8; 32]>> = None;
    let mut name: Option<String> = None;
    let mut last_key = None;
    for _ in 0..map_len.unwrap_or_default() {
        let key = next_key(&mut dec, last_key)?;
        last_key = Some(key);
        match key {
            0 => {
                let t = dec.u64()?;
                if t != type_value::JOIN {
                    return Err(malformed("join body's key 0 must be 4"));
                }
            }
            1 => person = Some(read_32(&mut dec)?),
            2 => {
                let len = dec
                    .array()?
                    .ok_or_else(|| malformed("join.devices must be a definite-length array"))?;
                if len == 0 || len > JOIN_DEVICES_MAX as u64 {
                    return Err(malformed("join.devices must have 1 to 8 entries (R-26)"));
                }
                let mut list = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    list.push(read_32(&mut dec)?);
                }
                devices = Some(list);
            }
            3 => {
                let s = dec.str()?;
                if utf8_len(s) > JOIN_NAME_MAX {
                    return Err(malformed("join.name must be at most 128 bytes"));
                }
                name = Some(s.to_owned());
            }
            _ => dec.skip()?,
        }
    }
    let person = person.ok_or_else(|| missing_key(type_value::JOIN, 1))?;
    let devices = devices.ok_or_else(|| missing_key(type_value::JOIN, 2))?;
    let mut seen = std::collections::HashSet::with_capacity(devices.len());
    for device in &devices {
        if !seen.insert(*device) {
            return Err(malformed("join.devices must hold no duplicate (R-26)"));
        }
    }
    if !devices.contains(&person) {
        return Err(malformed("join.devices must contain person (R-26)"));
    }
    Ok(Join {
        person,
        devices,
        name,
    })
}

fn decode_leave(bytes: &[u8]) -> Result<Leave, DecodeError> {
    let mut dec = Decoder::new(bytes);
    let map_len = dec.map()?;
    if map_len.is_none() {
        return Err(malformed("leave body must be a definite-length map"));
    }
    let mut person: Option<[u8; 32]> = None;
    let mut reason: Option<u64> = None;
    let mut last_key = None;
    for _ in 0..map_len.unwrap_or_default() {
        let key = next_key(&mut dec, last_key)?;
        last_key = Some(key);
        match key {
            0 => {
                let t = dec.u64()?;
                if t != type_value::LEAVE {
                    return Err(malformed("leave body's key 0 must be 5"));
                }
            }
            1 => person = Some(read_32(&mut dec)?),
            2 => {
                let r = dec.u64()?;
                if r > 3 {
                    return Err(malformed("leave.reason must be 0 to 3"));
                }
                reason = Some(r);
            }
            _ => dec.skip()?,
        }
    }
    Ok(Leave {
        person: person.ok_or_else(|| missing_key(type_value::LEAVE, 1))?,
        reason: reason.ok_or_else(|| missing_key(type_value::LEAVE, 2))?,
    })
}

fn decode_device_add(bytes: &[u8]) -> Result<DeviceAdd, DecodeError> {
    let mut dec = Decoder::new(bytes);
    let map_len = dec.map()?;
    if map_len.is_none() {
        return Err(malformed("device-add body must be a definite-length map"));
    }
    let mut device: Option<[u8; 32]> = None;
    let mut not_before_ms: Option<u64> = None;
    let mut not_after_ms: Option<u64> = None;
    let mut label: Option<String> = None;
    let mut last_key = None;
    for _ in 0..map_len.unwrap_or_default() {
        let key = next_key(&mut dec, last_key)?;
        last_key = Some(key);
        match key {
            0 => {
                let t = dec.u64()?;
                if t != type_value::DEVICE_ADD {
                    return Err(malformed("device-add body's key 0 must be 6"));
                }
            }
            1 => device = Some(read_32(&mut dec)?),
            2 => not_before_ms = Some(dec.u64()?),
            3 => not_after_ms = Some(dec.u64()?),
            4 => {
                let s = dec.str()?;
                if utf8_len(s) > DEVICE_ADD_LABEL_MAX {
                    return Err(malformed("device-add.label must be at most 128 bytes"));
                }
                label = Some(s.to_owned());
            }
            _ => dec.skip()?,
        }
    }
    let not_before_ms = not_before_ms.ok_or_else(|| missing_key(type_value::DEVICE_ADD, 2))?;
    let not_after_ms = not_after_ms.ok_or_else(|| missing_key(type_value::DEVICE_ADD, 3))?;
    if not_before_ms >= not_after_ms {
        return Err(malformed(
            "device-add.not_before_ms must be strictly less than not_after_ms (R-31)",
        ));
    }
    Ok(DeviceAdd {
        device: device.ok_or_else(|| missing_key(type_value::DEVICE_ADD, 1))?,
        not_before_ms,
        not_after_ms,
        label,
    })
}

fn decode_device_revoke(bytes: &[u8]) -> Result<DeviceRevoke, DecodeError> {
    let mut dec = Decoder::new(bytes);
    let map_len = dec.map()?;
    if map_len.is_none() {
        return Err(malformed(
            "device-revoke body must be a definite-length map",
        ));
    }
    let mut device: Option<[u8; 32]> = None;
    let mut at_ms: Option<u64> = None;
    let mut last_key = None;
    for _ in 0..map_len.unwrap_or_default() {
        let key = next_key(&mut dec, last_key)?;
        last_key = Some(key);
        match key {
            0 => {
                let t = dec.u64()?;
                if t != type_value::DEVICE_REVOKE {
                    return Err(malformed("device-revoke body's key 0 must be 7"));
                }
            }
            1 => device = Some(read_32(&mut dec)?),
            2 => at_ms = Some(dec.u64()?),
            _ => dec.skip()?,
        }
    }
    Ok(DeviceRevoke {
        device: device.ok_or_else(|| missing_key(type_value::DEVICE_REVOKE, 1))?,
        at_ms: at_ms.ok_or_else(|| missing_key(type_value::DEVICE_REVOKE, 2))?,
    })
}

fn decode_drop_request(bytes: &[u8]) -> Result<DropRequest, DecodeError> {
    let mut dec = Decoder::new(bytes);
    let map_len = dec.map()?;
    if map_len.is_none() {
        return Err(malformed("drop-request body must be a definite-length map"));
    }
    let mut scope: Option<u64> = None;
    let mut targets: Option<Vec<[u8; 32]>> = None;
    let mut note: Option<String> = None;
    let mut last_key = None;
    for _ in 0..map_len.unwrap_or_default() {
        let key = next_key(&mut dec, last_key)?;
        last_key = Some(key);
        match key {
            0 => {
                let t = dec.u64()?;
                if t != type_value::DROP_REQUEST {
                    return Err(malformed("drop-request body's key 0 must be 8"));
                }
            }
            1 => {
                let s = dec.u64()?;
                if s > 1 {
                    return Err(malformed("drop-request.scope must be 0 or 1"));
                }
                scope = Some(s);
            }
            2 => {
                let len = dec.array()?.ok_or_else(|| {
                    malformed("drop-request.targets must be a definite-length array")
                })?;
                if len == 0 || len > DROP_REQUEST_TARGETS_MAX as u64 {
                    return Err(malformed(
                        "drop-request.targets must have 1 to 64 entries (R-39)",
                    ));
                }
                let mut list = Vec::with_capacity(len as usize);
                for _ in 0..len {
                    list.push(read_32(&mut dec)?);
                }
                targets = Some(list);
            }
            3 => {
                let s = dec.str()?;
                if utf8_len(s) > DROP_REQUEST_NOTE_MAX {
                    return Err(malformed("drop-request.note must be at most 256 bytes"));
                }
                note = Some(s.to_owned());
            }
            _ => dec.skip()?,
        }
    }
    let scope = scope.ok_or_else(|| missing_key(type_value::DROP_REQUEST, 1))?;
    match scope {
        1 if targets.is_none() => {
            return Err(malformed(
                "drop-request.targets is required when scope == 1 (R-39)",
            ));
        }
        0 if targets.is_some() => {
            return Err(malformed(
                "drop-request.targets must be absent when scope == 0 (R-39)",
            ));
        }
        _ => {}
    }
    Ok(DropRequest {
        scope,
        targets,
        note,
    })
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
    fn message_round_trips_byte_for_byte() {
        let body = Body::Message(Message {
            text: "hello from the house".to_owned(),
            reply_to: None,
        });
        let bytes = body.to_cbor();
        let decoded = Body::from_cbor(&bytes).expect("decode");
        assert_eq!(decoded, body);
        assert_eq!(decoded.to_cbor(), bytes);
    }

    #[test]
    fn message_with_reply_to_round_trips() {
        let body = Body::Message(Message {
            text: "reply".to_owned(),
            reply_to: Some([9u8; 32]),
        });
        let bytes = body.to_cbor();
        assert_eq!(Body::from_cbor(&bytes).expect("decode"), body);
    }

    #[test]
    fn unknown_type_is_carried_whole() {
        let mut raw = Vec::new();
        {
            let mut enc = Encoder::new(&mut raw);
            enc.map(2).unwrap();
            enc.u8(0).unwrap();
            enc.u64(200).unwrap();
            enc.u8(1).unwrap();
            enc.str("future field").unwrap();
        }
        let decoded = Body::from_cbor(&raw).expect("decode unknown");
        match &decoded {
            Body::Unknown { type_value, raw: r } => {
                assert_eq!(*type_value, 200);
                assert_eq!(r, &raw);
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
        assert_eq!(decoded.to_cbor(), raw);
    }

    #[test]
    fn message_missing_text_is_rejected() {
        let mut raw = Vec::new();
        {
            let mut enc = Encoder::new(&mut raw);
            enc.map(1).unwrap();
            enc.u8(0).unwrap();
            enc.u64(type_value::MESSAGE).unwrap();
        }
        assert!(Body::from_cbor(&raw).is_err());
    }

    #[test]
    fn out_of_order_keys_are_rejected() {
        let mut raw = Vec::new();
        {
            let mut enc = Encoder::new(&mut raw);
            enc.map(2).unwrap();
            enc.u8(1).unwrap();
            enc.str("text first, out of order").unwrap();
            enc.u8(0).unwrap();
            enc.u64(type_value::MESSAGE).unwrap();
        }
        assert!(Body::from_cbor(&raw).is_err());
    }
}
