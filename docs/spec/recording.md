# The recording format

Version 1, frozen by WO-2.1. Fixes PLAN.md D5 (signed events with an opaque
body) and D7 (deterministic CBOR), against `decisions.md` 12, 13, 24, 34.
`decisions.md` is the authority; where this document and PLAN.md disagree,
`decisions.md` wins and this document is wrong.

A recording is per visit, append only, written by each participant on their
own machine. It is not a replicated log and not a merged one. Everything an
implementation must reject is a numbered rule below.

**Rule numbering.** Every validity rule in this document is numbered `R-<n>`
and phrased as an assertion: a conforming implementation asserts it, and
rejects the event when the assertion fails. Numbers are stable once merged;
a withdrawn rule keeps its number and is marked withdrawn rather than
reused. Rules are grouped by subject but numbered in one flat sequence, and
a rule added after first merge takes the next free number and sits where it
belongs by subject, so the numbers are not in document order. Cite a rule by
its number, never by its position.

## 1. Layout

One event on the wire and on disk:

```
envelope_bytes || sig[64] || body_bytes
```

Three lengths, all derivable before any byte is trusted: `envelope_bytes` is
self-delimiting CBOR, `sig` is exactly 64 bytes, and `body_bytes` is exactly
`envelope.body_len` bytes. A reader that has the envelope has the total
length of the event.

```
event_id  = BLAKE3(envelope_bytes)
body_hash = BLAKE3(body_bytes)
signature = Ed25519(author_secret, SIGNING_PREFIX || envelope_bytes)
```

The signature covers the envelope alone. The body is bound into it through
`body_hash`, so the body is authenticated without being parsed, which is what
makes R-14 (unknown bodies are carried, not dropped) possible.

### 1.1 The domain separation prefix

```
SIGNING_PREFIX = b"mosschat-event-v1\x00"     (18 bytes)
hex: 6d 6f 73 73 63 68 61 74 2d 65 76 65 6e 74 2d 76 31 00
```

Every event signature in this format is over `SIGNING_PREFIX ||
envelope_bytes` and over nothing else.

Why this cannot collide with anything already signed by the same key. One
ed25519 key signs both the transport handshake and application events, so
the separation has to be structural, not merely conventional:

- **TLS 1.3 CertificateVerify.** RFC 8446 section 4.4.3 computes the
  signature over "a string that consists of octet 32 (0x20) repeated 64
  times", then the context string, then a single 0 byte, then the content.
  Every TLS 1.3 signing input therefore begins with `0x20`. Byte 0 of
  `SIGNING_PREFIX` is `0x6d`. No event signing input can equal any TLS 1.3
  CertificateVerify signing input, at any length, for any transcript.
- **The LAN discovery announce** (`crates/mosschat-net/src/discovery.rs`,
  `ANNOUNCE_SIGNING_CONTEXT`) signs `b"mosschat-discovery-v1" || <80 bytes>`.
  It shares the first 9 bytes `mosschat-` and then differs at byte 9 (`d`
  against `e`), so neither input is a prefix of the other and no input is
  valid under both readings.
- **BLAKE3 contexts already in the tree** (`mosschat-probe-v1`,
  `mosschat-gate-pair-v1`, `mosschat-invite-bind-v1`,
  `mosschat-introduce-seal-v1`) are hash inputs, never signature inputs, and
  none of them is `mosschat-event-v1`.
- **Future prefixes.** The trailing `0x00` terminates the label
  unambiguously, so `mosschat-event-v1` can never be a prefix of a later
  `mosschat-event-v1x...`. Any later Mosschat signing context MUST be
  `b"mosschat-<label>-v<n>\x00"` with a `<label>` no existing context uses.

**R-1.** `verify_strict` over the author's key, the 64 signature bytes, and
exactly `SIGNING_PREFIX || envelope_bytes` succeeds. A signature verified
over any other message, or with non-strict `verify`, is not a verified
event.

## 2. The envelope

Frozen at version 1. Encoded as a definite-length CBOR array of 8 elements
in the field order below, not a map: this satisfies the deterministic
profile's shortest-form-integer and no-float rules directly and makes the
sorted-map-keys rule vacuous, because there are no map keys.
Implementation: `crates/mosschat-core/src/event/envelope.rs` (Phase 1).

| # | Field | CBOR type | Bytes | Meaning |
|---|---|---|---|---|
| 0 | `v` | uint | 1 | Envelope version. Always `1` in this format. |
| 1 | `visit` | byte string | 32 | The visit this event belongs to (section 3). |
| 2 | `author` | byte string | 32 | The ed25519 **device** public key that signed this event. |
| 3 | `seq` | uint | 1-9 | The host-assigned position of this event in the visit (section 4). |
| 4 | `prev` | byte string | 32 | `event_id` of the event at `seq - 1` in the host's sequence, or 32 zero bytes when `seq == 0`. |
| 5 | `ts_ms` | uint | 1-9 | The author's wall clock in milliseconds since the Unix epoch. **Display only.** Never an ordering input. |
| 6 | `body_hash` | byte string | 32 | `BLAKE3(body_bytes)`. |
| 7 | `body_len` | uint | 1-5 | Length of `body_bytes` in bytes. |

**R-2.** `envelope_bytes` decodes as a definite-length CBOR array of exactly
8 elements of the types above, with no trailing bytes after the eighth.

**R-3.** `v == 1`. An envelope carrying any other version is refused, not
skipped: the envelope is the part every build must parse, so a version it
does not know is a protocol error and not an unknown body.

**R-4.** `body_len` equals the actual length of the body bytes that follow.

**R-5.** `body_len <= 130_847`. (Section 6 derives the number.)

**R-6.** `BLAKE3(body_bytes) == body_hash`.

**R-7.** `author` is a device key that the recording's participant set names
for some person in this visit, and that key is not revoked as of this event
(section 5.7).

### 2.1 Bytes are what arrived

**R-8.** `event_id` and the signature check are computed over the received
`envelope_bytes`, never over a re-serialisation of a decoded value.

**R-9.** Re-encoding the decoded envelope produces `envelope_bytes` byte for
byte. An event whose re-encoding differs is rejected at ingest, before the
write transaction, however well it verifies.

**R-10.** The body satisfies the deterministic profile of RFC 8949 section
4.2.1: definite lengths only, shortest-form arguments, map keys sorted in
bytewise lexicographic order of their deterministic encodings, no
floating-point values in any body this document defines. Re-encoding a
decoded body of a **known** type produces `body_bytes` byte for byte. An
unknown body is not re-encoded and R-10 does not apply to it (R-14): it is
stored as the bytes that arrived, and `body_hash` is what binds it.

R-9 and R-10 together are why this format has no canonicalisation step. Two
encodings of the same event are two different events, and one of them is
rejected.

## 3. Visit identity

`visit` is 32 bytes drawn by the host from the OS CSPRNG when it opens the
visit. It is not derived from the participant set: a second visit between
the same people is a different visit, with its own recording and its own
section in every view.

**R-11.** `visit` is identical in every event of one recording. An event
whose `visit` does not match the recording it is offered to is rejected,
which is also the replay-across-visits check: an event signed for visit A
cannot be replayed into visit B, because `visit` is inside the signed
envelope.

**R-12.** The 32 zero bytes are not a valid `visit`.

## 4. Order is the host's order

The host assigns `seq`. `seq` counts events in the visit, from `0` at the
`visit-open` event, and it is dense: there are no gaps in a complete
recording.

The host is the only party that mints a sequence number, and the author
signs the number it was given, so `seq` is inside the signature and cannot
be rewritten by anyone afterwards. Concretely, for a guest's event:

1. The guest sends its intended body to the host over the live visit
   connection.
2. The host assigns the next `seq` and the `prev` that goes with it, and
   returns them.
3. The guest builds the envelope with that `seq` and `prev`, signs it, and
   sends the complete event back.
4. The host forwards the complete event to every participant, itself
   included, and every participant writes it.

The host's own events skip steps 1 to 3: it assigns its own `seq` and signs
directly. The cost of this shape is one host round trip before a guest's
message becomes an event, which is the price of having `seq` inside the
signature; the alternative, a host-side wrapper event, would put the host's
signature on a guest's words. **The guest's client may show its own message
immediately as pending**; it is not an event until step 4 lands.

The precise wire exchange for steps 1 to 4 is WO-3.1's (`docs/spec/visit.md`)
and is not fixed here. What is fixed here is the field's meaning: `seq` is
host-assigned, dense, and signed by the author.

**R-13.** `prev` is the `event_id` of the event at `seq - 1`, and 32 zero
bytes when `seq == 0`. A recording holding two events with the same `seq`,
or an event whose `prev` does not match the event it stored at `seq - 1`, is
a host equivocating or a corrupted store; the second event is rejected and
the visit is marked broken to the user rather than repaired. Where the event
at `seq - 1` was dropped at its author's request, `prev` is matched against
the tombstone R-50 leaves in its place.

R-13 detects equivocation **within one recording**: two events this machine
holds at one `seq`, or a `prev` that does not match what this machine stored.
It does not detect a host that tells two guests different things, because
section 9 forbids reading another participant's recording to compare. That
limit is real and is accepted (WO-2.2 scenario 3): the chain makes a host's
claimed order verifiable after the fact *to the holder of that recording*,
not across holders.

`ts_ms` is display information. It is never compared to another event's
`ts_ms` to decide order, never used to expire an event, and a recording
whose timestamps run backwards is still a valid recording.

## 5. Bodies

A body is a definite-length CBOR **map** with unsigned integer keys. Key `0`
is always the body type, an unsigned integer. Keys are sorted ascending,
which for keys in `0..=255` is exactly the bytewise lexicographic order R-10
requires, because every key in `0..=23` encodes as one byte `0x00..0x17` and
every key in `24..=255` encodes as the two bytes `0x18 0xNN`, which sorts
after all of them.

A map, not an array, so that a version 2 field can be added at a new key and
a version 1 reader skips it. Unknown **keys** in a known body type are
ignored on read and preserved on disk, because the stored bytes are the
bytes that arrived (R-8). Unknown **body types** are carried whole (R-14).

Optional fields are absent, never null: an absent key and a key with a null
value would be two encodings of one meaning, which R-10 forbids.

**R-14.** An event whose body type key `0` is not in the table below still
verifies (R-1), still passes R-2 to R-13, is still stored with its bytes
unchanged, and is displayed as "a message this version cannot read". It is
never dropped, never rewritten, and its `event_id` is unchanged by being
carried. This is what lets a version 1 house sit in a visit with a version 2
house without losing the recording.

**R-15.** A body of a **known** type carries every key marked required in
its table, each of the stated CBOR type and within its stated cap. A known
type missing a required key is rejected; it is not treated as unknown.

**R-16.** Every text field is valid UTF-8 and is measured in bytes, not
characters or grapheme clusters, against its cap.

### Body types

| Value at key `0` | Type | Written by | Section |
|---|---|---|---|
| 1 | `message` | any participant | 5.1 |
| 2 | `reaction` | any participant | 5.2 |
| 3 | `attachment` | any participant | 5.3 |
| 4 | `join` | the host | 5.4 |
| 5 | `leave` | the host | 5.5 |
| 6 | `device-add` | the person gaining the device | 5.6 |
| 7 | `device-revoke` | the person losing the device | 5.7 |
| 8 | `drop-request` | any participant | 5.8 |

Body **type values** `0` to `127` are reserved for this specification, `0`
permanently unassigned so that a zeroed buffer is never a valid body. `128`
and above are free for private extensions and will never be assigned here.
This is the type value at map key `0`, not the map key itself; map keys are
assigned per body type by the tables below.

The visit's own lifecycle events (`visit-open`, `visit-close`) are WO-3.1's
and are deliberately absent from this table; `seq == 0` being `visit-open` is
stated in section 4 as a constraint that specification must satisfy, and its
body type will be assigned from the reserved range there.

### 5.1 `message`

| Key | Field | CBOR type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | type | uint | yes | `== 1` | Body type. |
| 1 | `text` | text string | yes | 65_536 bytes | The message. |
| 2 | `reply_to` | byte string | no | 32 bytes | `event_id` of the event this replies to. |

**R-17.** `text` is at most 65_536 bytes and is not empty. An empty message
is a client bug, not a message.

**R-18.** `reply_to`, when present, is 32 bytes and names an event, **or a
tombstone (R-50)**, already stored in this same visit at a lower `seq`. A
reply to an event this recording does not hold, or holds at a higher `seq`,
is rejected. A tombstone is a valid target: whether this house honoured a
drop-request must not change which events it admits, or a house that
honoured one would reject a reply that a house which declined accepts, and
section 9 would call that difference a defect or an attack.

### 5.2 `reaction`

| Key | Field | CBOR type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | type | uint | yes | `== 2` | Body type. |
| 1 | `target` | byte string | yes | 32 bytes | `event_id` of the event reacted to. |
| 2 | `symbol` | text string | yes | 32 bytes | The reaction, one short UTF-8 string. |
| 3 | `remove` | bool | no | — | `true` withdraws a reaction this author previously made. Absent means add. |

**R-19.** `target` names an event, **or a tombstone (R-50)**, already stored
in this same visit at a lower `seq`. A tombstone is a valid target, for the
reason R-18 gives.

**R-20.** `symbol` is at most 32 bytes and is not empty. It is display data
and is not otherwise interpreted; a client renders what it can and shows the
raw string when it cannot.

**R-21.** A `reaction` with `remove == true` whose `(author, target,
symbol)` triple matches no earlier reaction in this visit is stored and has
no effect on the view. It is not rejected: the event is a fact about what
its author sent, and R-14's carry-don't-drop principle applies to known
types whose effect is a no-op just as it does to unknown ones.

### 5.3 `attachment`

The file's bytes are not in the recording. This body is the signed
announcement of a transfer; D9 and WO-4.3 own the transfer itself.

| Key | Field | CBOR type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | type | uint | yes | `== 3` | Body type. |
| 1 | `hash` | byte string | yes | 32 bytes | `BLAKE3` of the whole file. |
| 2 | `size` | uint | yes | `<= 2^40` | File size in bytes. |
| 3 | `name` | text string | yes | 128 bytes | The sender's filename, **as sent**. |
| 4 | `media_type` | text string | no | 128 bytes | An IANA media type, a hint only. |

**R-22.** `name` is at most 128 bytes, is not empty, contains no `U+0000`,
no `/`, no `\`, and is not `.` or `..`.

**R-23.** `name` is stored and displayed as the sender sent it and is never
used to construct a path. Sanitisation, reserved-name refusal and the
download folder are the receiver's, per WO-4.3; this format carries the
sender's claim and nothing more.

**R-24.** `media_type` is a hint. A receiver decides how to handle a file
from its own inspection, never from this field.

### 5.4 `join`

Written by the host. A guest does not admit itself (decision 35: the host
admits, always).

| Key | Field | CBOR type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | type | uint | yes | `== 4` | Body type. |
| 1 | `person` | byte string | yes | 32 bytes | The person's **identity** key (their first device key, per section 5.6). |
| 2 | `devices` | array of byte string | yes | 8 entries, 32 bytes each | The device keys of that person admitted to this visit. |
| 3 | `name` | text string | no | 128 bytes | The display name the host holds for them. |

**R-25.** A `join` is authored by the host of this visit. A `join` signed by
anyone else is rejected.

**R-26.** `devices` is non-empty, holds at most 8 keys, holds no duplicate,
and contains `person`.

**R-27.** An event whose `author` is not in the `devices` list of an
un-`leave`d `join` earlier in this visit is rejected. This is the concrete
form of R-7.

**`join` is the sole membership authority for a visit.** A key is admitted
because the host put it in a `join`, and for no other reason. A participant
does not check that a key in `join.devices` is backed by a `device-add` in
force, and cannot: a guest's `device-add` events live in that person's own
device log (D4, WO-3.4), not in this visit's recording, so the events that
would prove it are not present to check. The host is the party that vouches,
which is decision 35's "the host admits, always" applied to keys as well as
to people.

**R-32's validity window therefore does not gate the ordinary path**, and
this specification does not pretend otherwise. It governs the one case where
a `device-add` is itself in the recording: a device added to a person
mid-visit (section 5.6), where the grant is present and is checked. For a
key that arrived in a `join`, what fails closed is the host declining to
list it, not the window. What the window buys is that the field exists and
is enforced wherever a grant is visible, so a later version can widen that
enforcement without a format change — which is why it is required now
(research lesson 5), not a claim that it is load-bearing today.

The cost, stated plainly because it is the limit
`research/zero-trust-and-ucan.md` D1 names: a host that never learned of a
revocation will list a revoked key in a `join`, and every participant will
accept that key's events for that visit. R-37 stops the key being re-added
to a person once the revocation is seen; it does not reach back into a visit
a stale host already opened.

### 5.5 `leave`

| Key | Field | CBOR type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | type | uint | yes | `== 5` | Body type. |
| 1 | `person` | byte string | yes | 32 bytes | The person leaving. |
| 2 | `reason` | uint | yes | `0..=3` | 0 left, 1 timed out, 2 removed by the host, 3 the visit ended. |

**R-28.** A `leave` is authored by the host.

**R-29.** `person` names a person with an un-`leave`d `join` earlier in this
visit.

**R-30.** After a `leave` for a person, an event authored by one of that
person's devices at a higher `seq` is rejected, unless a later `join` for
that person precedes it.

### 5.6 `device-add`

A person is a set of device keys linked by signed `device-add` events (D4).
The first device key a person ever holds is their **identity key**, and it
names the person for the life of the account.

| Key | Field | CBOR type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | type | uint | yes | `== 6` | Body type. |
| 1 | `device` | byte string | yes | 32 bytes | The device key being added. |
| 2 | `not_before_ms` | uint | yes | 1-9 bytes | Unix milliseconds. The grant is invalid before this instant. |
| 3 | `not_after_ms` | uint | yes | 1-9 bytes | Unix milliseconds. The grant is invalid at and after this instant. |
| 4 | `label` | text string | no | 128 bytes | A human label, "the laptop". |

**The validity window is required, and it is required now** even though
slice one never ages a grant out. Research lesson 5 and
`research/zero-trust-and-ucan.md` D1: decision 4 makes revoke a signed
message and decision 5 removes every carrier that could bring that message
to someone who was not home, so a grant with no expiry is valid forever to
anyone who missed the revoke. A body with no expiry field can never be aged
out later without a version bump, and this format is freezing. The field
exists so a later version can fail closed; slice one writes a long window
and enforces R-32 against it, and nothing in slice one shortens it.

**R-31.** `not_before_ms < not_after_ms`.

**R-32.** A `device-add` grant is in force for an event when
`not_before_ms <= evaluation_instant < not_after_ms`. Slice one's
**evaluation instant is the moment of ingest, from the receiving machine's
own clock**, never the event's `ts_ms`, which is display data an attacker
sets (section 4). A grant outside its window at ingest does not authorise
the event, and the event is rejected under R-7.

**R-33.** A `device-add` is authored by a device key already in force for
the same person, or it is the person's identity key self-signing its own
first grant. A person cannot add a device to another person.

**R-34.** `device` is not already in force for a different person.

**R-35.** Slice one writes `not_after_ms = not_before_ms + 31_536_000_000`
(365 days). This is a default, not a format rule: a conforming reader
enforces R-32 against whatever window it is given.

### 5.7 `device-revoke`

| Key | Field | CBOR type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | type | uint | yes | `== 7` | Body type. |
| 1 | `device` | byte string | yes | 32 bytes | The device key that is no longer this person. |
| 2 | `at_ms` | uint | yes | 1-9 bytes | The instant the revoker asserts the device stopped being them. |

**R-36.** A `device-revoke` is authored by a device of the same person,
other than `device` itself. A device cannot revoke itself, because a thief
holding it could then revoke the owner's other devices; and a person cannot
revoke another person's device.

**R-37.** A revocation is permanent once seen. A `device-add` for a key this
recording has already seen revoked is rejected whatever its window, so a
thief cannot re-add a key from a stolen device.

**R-38.** Events authored by `device` at a `seq` **lower** than the
revocation's are unaffected. The revocation is not retroactive over the
host's sequence: those events were valid when the host sequenced them, the
signature still verifies, and rewriting the past on the strength of a later
event is exactly the merge this format does not do. `at_ms` is recorded and
displayed so a person can see the claim, and is never used to invalidate a
sequenced event.

R-38 is the honest statement of the limit `research/zero-trust-and-ucan.md`
D1 names: a revocation that never reached you cannot protect you, and one
that reaches you late does not undo what already happened. R-32's window is
the only mechanism in this format that fails closed without delivery.

### 5.8 `drop-request`

A request, not a guarantee (decision 13). It is in the recording so that
both sides can see it was made and honoured.

| Key | Field | CBOR type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | type | uint | yes | `== 8` | Body type. |
| 1 | `scope` | uint | yes | `0..=1` | 0 this whole visit, 1 the events named in `targets`. |
| 2 | `targets` | array of byte string | no | 64 entries, 32 bytes each | `event_id`s, required when `scope == 1`. |
| 3 | `note` | text string | no | 256 bytes | A reason shown to the recipient. |

**R-39.** `targets` is present, non-empty and at most 64 entries when
`scope == 1`, and absent when `scope == 0`.

**R-40.** Every entry in `targets` names an event in this same visit
authored by the **requester's own person**. Nobody may ask for someone
else's words to be dropped; asking for the visit to go (`scope == 0`) is a
request about the whole visit and stands on its own.

**R-41.** Honouring a `drop-request` deletes the named bytes locally
(section 7, kind one) and leaves a visible marker in the view reading
"dropped at their request". The `drop-request` event itself is never
deleted by being honoured: it is the record that the request was made.

**R-50.** Honouring a `drop-request` leaves a **tombstone** at each dropped
`seq`, holding that event's `seq` and `event_id` and nothing else: no
envelope, no signature, no body, no author, no timestamp. R-13 matches a
later event's `prev` against the tombstone's `event_id` exactly as it would
against the event itself, so obeying decision 13 does not break the chain
and does not mark the visit broken. Without this an honest house is punished
for honouring a request: it deletes the bytes at `seq - 1`, then has nothing
for the next event's `prev` to match.

A tombstone is not the event. It carries no content, so it satisfies kind
one's "gone from every view" and the hexdump check of R-45 for the dropped
event's own bytes; a 32 byte hash of bytes that no longer exist reveals
nothing about them. It is what the view renders as the "dropped at their
request" marker of R-41, which is why R-49 says the view shows a marker and
not a gap.

**R-42.** A `drop-request` that a house declines to honour is still stored
and still displayed. Declining is a local choice and produces no event.

## 6. Sizes

| Thing | Cap | Derivation |
|---|---|---|
| `message.text` | 65_536 bytes | D5's "message body 64 KiB". |
| Any name or label (`join.name`, `attachment.name`, `device-add.label`) | 128 bytes | D5's "name 128 bytes". |
| `body_len` | 130_847 bytes | D5's "event 128 KiB" is the whole event, so the body cap is what is left after the envelope and the signature. The envelope's largest possible encoding is 161 bytes: the 8-element array header (1) plus `v` (1) plus four 32 byte strings at a 2 byte header each (136) plus `seq` and `ts_ms` at their 9 byte maximum (18) plus `body_len` at its 5 byte maximum (5). `131_072 - 64 - 161 = 130_847`. A fixed number, checkable from the envelope alone before a byte of body is read; R-43 then checks the actual total, which is looser for a smaller envelope. |
| One whole event | 131_072 bytes | D5's "event 128 KiB". |
| One door or transport frame | 1_048_576 bytes | D5's "frame 1 MiB". Enforced by `docs/spec/door.md` D-6 and by the transport, not here. |
| `attachment.size` | 2^40 bytes | The signed claim's cap. The transfer's own limit is WO-4.3's and is smaller. |

**R-43.** `len(envelope_bytes) + 64 + body_len <= 131_072`.

R-43 is **defence in depth and is provably implied by R-2 and R-5**; it can
never be the sole reason an event is rejected. R-5's cap is derived from the
envelope's *largest* possible encoding, so the worst case
`161 + 64 + 130_847` is exactly 131_072 and any smaller envelope leaves
slack. An implementer looking for a test case that R-43 alone rejects will
not find one, and should not go hunting: R-5 (or R-2, for a malformed
envelope) always fires first or instead. It is stated as its own rule anyway
because the total is the quantity D5 actually caps, and an implementation
that checks only `body_len` would silently stop enforcing the real limit if
the envelope ever grew a field. Found by WO-2.4a.

**R-44.** Every length prefix is checked against its cap before any
allocation sized by it. A claimed length above its cap is refused without
reading or reserving the claimed bytes (invariant 4).

## 7. The three kinds of deleting

Decision 13, all three in from the start.

**Kind one, your own copy for real.** Rows, files and free pages, gone from
every view and gone from the database file. The bytes of a deleted visit are
absent from the store file, not merely unreachable through an index; the
store proves it by hexdump in WO-2.5. Attachments belonging to the visit go
with it (D9). This produces no event and is told to nobody.

**R-45.** After a delete-for-real of a visit, no view names that visit, no
row references it, and the store file contains none of its plaintext.

**Kind two, asking the others to drop theirs.** The `drop-request` body of
section 5.8. Honest software honours it, displays that it did, and the
documentation says plainly that it is a request and not a guarantee. A house
that runs modified software, or a person who remembers, is outside what any
format can reach.

**Kind three, never recorded at all.** A private visit is flagged private
when the host opens it. No event of a private visit is ever written to the
store, by any participant, and a private visit never appears in any view.

**R-46.** A private visit produces no store row of any kind. Its absence is
checked by there being no row, not by a filter over rows that exist.

**R-47.** Privacy is a property of the visit, set at open, and no event
changes it. A visit does not become private partway through, and a private
visit does not become recorded partway through; either would leave half a
recording on disk.

## 8. Views

Views are computed from recordings, never stored (D5). Storing a view would
create a second source of truth that a delete has to chase.

**The contact view** for a person lists every visit that person was in,
one-on-one or group, each visit its own section, ordered by the visit's own
opening. Within a section, events are in `seq` order. A contact's identity
for this purpose is their identity key (section 5.6), so a person who added
a device still has one page.

**The group view** lists visits by **participant set**: the set of identity
keys that appear in any in-force `join`. Two visits with the same
participant set are two sections of one group page. A visit where somebody
joined late has the participant set that includes them, so it groups with
visits of that larger set and not of the smaller one; the recording marks
where they joined.

**R-48.** Every view is a pure function of the recordings on this machine.
The same recordings produce the same view whatever order the events arrived
in and whatever order rows are read back (invariant 6).

**R-49.** A private visit appears in no view (R-46). A visit deleted for
real appears in no view (R-45). A drop-request honoured appears in the view
as a marker where the dropped events were, not as a gap.

## 9. No rule merges two people's recordings

This is the invariant the format exists to protect, and it is stated here so
that a reader implementing this document cannot implement a merge by
accident.

**No rule in this specification combines two people's records of a visit.**
Every event in a recording is written by the machine that received it, from
the bytes it received, in the order the host gave. There is no
reconciliation step, no convergence property, no fork resolution, and no
rule that reads another person's recording. Two participants' recordings of
one visit are related only by both being prefixes of the host's sequence:
same events, same order, and a participant who left holds a **shorter**
recording, never a different one. Nothing repairs a difference, because
nothing is allowed to produce one; a difference is a defect or an attack.
Where it shows up inside one recording, R-13 surfaces it as a broken visit
and shows the person. Where it does not — a host that gave two guests
different orders — no participant detects it, precisely because no
participant may read another's recording. That is the price of this
paragraph and it is paid knowingly (WO-2.2 scenario 3): the alternative is
comparing recordings, which is the merge this format exists to forbid.

**A host replaying its own sequence to a rejoining guest is not a merge**
(decision 34, invariant 7). Inside one live visit, a guest whose connection
dropped and came back may be sent the events of the host's own sequence that
it missed. That is one stream being made reliable. The host is the author of
the order and already held every one of those events; nothing is combined,
nothing is reordered, no second person's record is read, and the guest ends
on the same prefix it would have held had it never dropped. The
distinguishing test, which any implementation can apply to its own code: the
events come from the host of this visit, inside this visit's live session,
at sequence numbers this guest does not yet hold, and the guest writes them
in `seq` order exactly as it would have written them live. Anything that
reads a **participant's** recording to fill a gap in **another
participant's** recording is a merge and is forbidden, whatever it is called.

The one sync that exists is between two devices of **one** person (D4), and
it takes events that person's other device is missing. It is not covered by
this document; WO-3.4 owns it, and invariant 7 binds it.

## 10. Worked example

One `message` event, every byte accounted for. The hex below is produced by
`crates/mosschat-core/tests/spec_example.rs`, an `#[ignore]`d test committed
with this specification, and is not typed by hand. Reproduce it with:

```
cargo test -p mosschat-core --test spec_example -- --ignored --nocapture
```

The test uses a fixed, published signing key (`author_secret` below, 32
bytes of `0x07`) so the signature is reproducible. That key is a test
vector and is not an identity.

<!-- BEGIN WORKED EXAMPLE -->
```
=== recording.md worked example ===
author_secret       (32) 0707070707070707070707070707070707070707070707070707070707070707
author_public       (32) ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c
visit               (32) 1111111111111111111111111111111111111111111111111111111111111111
seq                 7
prev                (32) 2222222222222222222222222222222222222222222222222222222222222222
ts_ms               1757000000000
body (message, CBOR map, keys ascending)
body_bytes          (25) a20001017468656c6c6f2066726f6d2074686520686f757365
body_hash  BLAKE3   (32) 2e46b4ea6fc1c74f87cb69e21cface0d5b0986ced5cfe349a52861bc212a3f02
body_len            25
envelope_bytes      (150) 8801582011111111111111111111111111111111111111111111111111111111111111115820ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c07582022222222222222222222222222222222222222222222222222222222222222221b00000199155c620058202e46b4ea6fc1c74f87cb69e21cface0d5b0986ced5cfe349a52861bc212a3f021819
event_id   BLAKE3   (32) bc69b01ae86198a6de467fe0aabee03c46ad5aa3c4cf73c56ee2828b677b00cf
signing_prefix      (18) 6d6f7373636861742d6576656e742d763100
signing_input = signing_prefix || envelope_bytes  (168 bytes)
sig                 (64) 156e3104897643f944f228d4dac15bfa92487fe187e2d1e487efee25430d7099f5a8eacd523e7568cde4e8c0acc0c267123325772152071395e61004521d1b00
event = envelope_bytes || sig || body_bytes  (239 bytes)
8801582011111111111111111111111111111111111111111111111111111111111111115820ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c07582022222222222222222222222222222222222222222222222222222222222222221b00000199155c620058202e46b4ea6fc1c74f87cb69e21cface0d5b0986ced5cfe349a52861bc212a3f021819156e3104897643f944f228d4dac15bfa92487fe187e2d1e487efee25430d7099f5a8eacd523e7568cde4e8c0acc0c267123325772152071395e61004521d1b00a20001017468656c6c6f2066726f6d2074686520686f757365
```
<!-- END WORKED EXAMPLE -->

## 11. What this document does not fix

- The visit's wire protocol: opening, admitting, the sequencing exchange of
  section 4, closing, and the note queue. `docs/spec/visit.md`, WO-3.1.
- The store's tables, its encryption and its key file. WO-2.5.
- The file transfer an `attachment` announces. WO-4.3.
- The invite ticket and the backup bundle. `docs/spec/invite.md`, WO-4.1.
- Device sync between two devices of one person. WO-3.4.
</content>
