# The door protocol

Version 1, frozen by WO-2.1. Fixes PLAN.md D1, against `decisions.md` 25 and
27 and `research/README.md` cross-cutting lesson 4. `decisions.md` is the
authority; where this document and PLAN.md disagree, `decisions.md` wins and
this document is wrong.

The door is the one interface between a house and anything that wants to use
it. `mosschat-tui` reaches the house through it, a third-party Go client
reaches it through the same protocol, and there is no second path. This
document is written to be sufficient on its own: a Go client can be built
from it with no Rust read.

**Rule numbering.** Every validity rule is numbered `D-<n>` and phrased as
an assertion: a conforming implementation asserts it and refuses the frame
when the assertion fails. Numbers are stable once merged; a withdrawn rule
keeps its number and is marked withdrawn rather than reused. A rule added
after first merge takes the next free number and sits where it belongs by
subject, so the numbers are not in document order. Cite a rule by its
number, never by its position.

Conventions: all integers are unsigned unless stated; all multi-byte lengths
are big-endian; "the house" is the daemon, "the client" is whatever connects
to it. Byte counts are bytes, never characters.

## 1. Transports

Two, speaking the identical frame protocol above the transport.

**Local** is the default and needs no keys.

| Platform | Endpoint |
|---|---|
| Linux, macOS | Unix domain stream socket at `$XDG_RUNTIME_DIR/mosschat/door.sock`, falling back to `$HOME/.local/state/mosschat/door.sock` when `XDG_RUNTIME_DIR` is unset. macOS has no `XDG_RUNTIME_DIR` by default, so macOS normally takes the fallback. |
| Windows | Named pipe `\\.\pipe\mosschat-door-<sid>`, where `<sid>` is the string form of the user's SID. |

**D-1.** The socket's directory is created mode `0700` and the socket itself
is bound mode `0600`, both owned by the user running the house. The house
checks both after binding and refuses to serve if either is wider, because a
socket created under a permissive `umask` is the whole house readable by the
machine.

**D-2.** On Windows the pipe is created with a DACL granting access to the
creating user's SID alone, and to no group, including no administrators
group. The pipe is opened with `FILE_FLAG_FIRST_PIPE_INSTANCE` so a second
process cannot squat an existing name.

The local transport authenticates by file permission alone: any process
running as the user may connect. That is a real trust assumption and it is
why section 6's scope exists.

**Possession of the local socket is total authority over the house.** A
`Hello` with no `grant` gets subject `house` (section 6), which includes
`device.revoke`, `visit.delete` and every recording in the store; so anyone
at an unlocked, logged-in machine — or any program running as that user —
is the house, and reads, sends and deletes as the person. Nothing in the
recording format constrains this: `device-revoke`
(`docs/spec/recording.md` R-36) removes a key's standing with *other*
people's houses, and does not reduce what the local door grants on this
machine. Locking the screen and the disk is the whole defence, exactly as
decision 10 and risk 6 already say for the data key. `docs/honest-limits.md`
(WO-5.5) states this in the user's words.

**Network** is off unless configured, and is decision 27's "the door works
over the network too".

**D-3.** The network door binds nothing unless a listen address is
configured. When configured, it accepts a QUIC connection with mutual TLS
1.3 over raw self-signed Ed25519 certificates, exactly as the house-to-house
transport does (`crates/mosschat-net/src/authed.rs`), with ALPN
`mosschat-door-v1`. The client's key proven in that handshake is checked
against an explicitly configured allow list of client keys. A key not on the
list is refused and the connection is closed before any frame is read. There
is no discovery of a network door, no gate involvement, and no path from an
invite to the door.

**D-4.** The network door is never reachable because a peer is a friend.
Being a friend grants a visit; it does not grant the house.

Over QUIC, the frames of section 2 ride one bidirectional stream opened by
the client immediately after the handshake. Everything from section 2 onward
is identical on both transports.

## 2. Framing

Every frame, both directions:

```
[len: u32 big-endian][payload: len bytes of deterministic CBOR]
```

`len` counts the payload only. The payload is a definite-length CBOR array
whose first element is the frame type, an unsigned integer, and whose second
element is the frame body, a definite-length CBOR map with unsigned integer
keys.

```
payload = [ type: uint, body: { 0: ..., 1: ..., ... } ]
```

**D-5.** The payload is a definite-length CBOR array of exactly 2 elements,
the first an unsigned integer, the second a map, with no trailing bytes.

**D-6.** `len <= 1_048_576` (1 MiB, D5's frame cap). A frame claiming more
is refused and the connection is closed **before** the claimed bytes are read
or any buffer is sized by them.

**D-7.** The payload satisfies the deterministic profile of RFC 8949 section
4.2.1: definite lengths only, shortest-form arguments, map keys sorted in
bytewise lexicographic order of their deterministic encodings, no floats.
A frame whose re-encoding differs is refused. For the integer keys this
document uses, all in `0..=255`, that sort order is exactly ascending
numeric order.

**D-8.** Unknown map keys inside a known frame type are ignored. An unknown
frame **type** is answered with `Error{unknown_frame}` and the connection
stays open; it is not a protocol error, so a version 2 client talking to a
version 1 house degrades instead of dying.

**D-9.** Optional fields are absent, never null. An absent key and a null
value would be two encodings of one meaning, which D-7 forbids.

Frame types `0` to `127` are reserved by this document. `128` and above are
free for private extensions and will never be assigned here.

### Common types

| Name | CBOR | Notes |
|---|---|---|
| `Key` | byte string, 32 bytes | An Ed25519 public key. |
| `Id` | byte string, 32 bytes | A visit id or an `event_id`. |
| `Handle` | byte string, 32 bytes | A scope grant handle (section 6). |
| `Ms` | uint | Unix milliseconds. |
| `Text` | text string | Valid UTF-8, capped in bytes. |

## 3. Frame table

Direction `C→H` is client to house, `H→C` is house to client.

| Type | Name | Dir | Section |
|---|---|---|---|
| 1 | `Hello` | C→H | 4 |
| 2 | `Welcome` | H→C | 4 |
| 3 | `Snapshot` | H→C | 4 |
| 4 | `SnapshotEnd` | H→C | 4 |
| 5 | `Request` | C→H | 5 |
| 6 | `Reply` | H→C | 5 |
| 7 | `Error` | H→C | 8 |
| 8 | `Event` | H→C | 9 |
| 9 | `Subscribe` | C→H | 9 |
| 10 | `Unsubscribe` | C→H | 9 |
| 11 | `Ping` | both | 10 |
| 12 | `Pong` | both | 10 |
| 13 | `QueueStatus` | H→C | 11 |
| 14 | `Disconnect` | both | 12 |

## 4. The nonced hello, and the snapshot

Research lesson 4: a client must be able to ask for everything and know when
it holds it. Guessing at completeness is what makes a client's first screen
wrong.

### `Hello` (1), C→H

| Key | Field | Type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | `nonce` | byte string | yes | 16 bytes | 16 random bytes drawn by the client per connection. |
| 1 | `client_version` | uint | yes | — | The client's own protocol version. |
| 2 | `client_name` | `Text` | yes | 64 bytes | For the house's connection list and logs. Not authentication. |
| 3 | `features` | array of `Text` | no | 32 entries, 32 bytes each | Features this client understands (section 13). |
| 4 | `grant` | `Handle` | no | 32 bytes | A scope grant (section 6). Absent asks for the full-house grant. |
| 5 | `want_snapshot` | bool | no | — | `false` skips the snapshot. Absent means `true`. |

**D-10.** `Hello` is the first frame on a connection and is sent exactly
once. Any other frame before it, or a second `Hello`, closes the connection
with `Error{protocol}`.

**D-11.** `nonce` is exactly 16 bytes and is drawn fresh per connection from
a cryptographic random source. The house echoes it in `Welcome` and in
`SnapshotEnd`, so a client can tell this connection's snapshot from a stale
one it is still draining after a reconnect. It is not a secret and not an
authenticator.

### `Welcome` (2), H→C

| Key | Field | Type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | `nonce` | byte string | yes | 16 bytes | Echo of `Hello.nonce`. |
| 1 | `house_version` | uint | yes | — | The house's own protocol version. |
| 2 | `min_client_version` | uint | yes | — | The oldest client version this house serves (section 13). |
| 3 | `features` | array of `Text` | yes | 64 entries, 32 bytes each | Features this house offers. |
| 4 | `self` | `Key` | yes | 32 bytes | This house's identity key. |
| 5 | `grant_expires_ms` | `Ms` | no | — | When the grant in use expires. Absent means no expiry. |
| 6 | `commands` | array of `Text` | yes | 64 entries, 32 bytes each | The commands this connection's grant permits (section 6). |

**D-12.** The house sends `Welcome` as the first frame after a valid
`Hello`, or `Error` and closes. It never sends anything else in between.

### `Snapshot` (3) and `SnapshotEnd` (4), H→C

When `want_snapshot` is true the house then streams the whole state this
grant can see, as a sequence of `Snapshot` frames, terminated by exactly one
`SnapshotEnd`.

`Snapshot`:

| Key | Field | Type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | `kind` | `Text` | yes | 32 bytes | What this frame carries: `contact`, `visit`, `event`, `note`, `device`, `transfer`. |
| 1 | `items` | array | yes | 917_504 bytes encoded, and at most 256 entries | Items of that kind, shaped as section 7 defines for that kind. The **byte** budget binds first (D-53). |

`SnapshotEnd`:

| Key | Field | Type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | `nonce` | byte string | yes | 16 bytes | Echo of `Hello.nonce`. **This is the completion marker.** |
| 1 | `counts` | map of `Text` to uint | yes | 16 entries | Items sent per kind, so a client can check it received them all. |

**D-13.** Exactly one `SnapshotEnd` follows the `Snapshot` frames, carrying
the `Hello.nonce` of this connection. A client holds the whole state it
asked for at that frame and not before.

**D-14.** `Event` frames (section 9) generated while the snapshot is
streaming are queued by the house and delivered **after** `SnapshotEnd`,
never interleaved. A client therefore never sees an update to a thing it has
not been told about, and never has to hold a reordering buffer.

**D-15.** A snapshot is a consistent read: every `Snapshot` frame of one
connection reflects one instant of the house's state. Two snapshots taken at
different instants may differ; one snapshot is never half of each.

## 5. Requests and replies

### `Request` (5), C→H

| Key | Field | Type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | `id` | uint | yes | — | Client-chosen correlation id, unique among this connection's outstanding requests. |
| 1 | `command` | `Text` | yes | 32 bytes | One of section 7's commands. |
| 2 | `args` | map | no | — | Command arguments, as section 7 defines. |

### `Reply` (6), H→C

| Key | Field | Type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | `id` | uint | yes | — | Echo of `Request.id`. |
| 1 | `result` | map | yes | — | Command result, as section 7 defines. Empty map when the command returns nothing. |

**D-16.** Every `Request` is answered with exactly one `Reply` or exactly
one `Error` carrying the same `id`. A house that cannot answer answers
`Error`; it never drops a request silently.

**D-17.** Requests may be in flight concurrently and replies may arrive in
any order. A client correlates on `id` and never on arrival order.

**D-18.** `id` is unique among a connection's outstanding requests. Reusing
an `id` that is still outstanding is `Error{protocol}` and closes the
connection, because the house cannot tell the two apart.

**D-19.** A connection has at most 64 outstanding requests. The 65th is
answered `Error{too_many_requests}` and the connection stays open.

## 6. Scope: the smallest unit of authority the door can grant

**The smallest unit of authority the door can grant is one command name for
one subject until one expiry** — for example "`visit.send` on visit `X`,
until 18:00". That triple is the grant's atom, and nothing smaller is
expressible. A grant is a set of such atoms.

This is UCAN's shape (subject, command, expiry) in our own CBOR, not UCAN
(`research/zero-trust-and-ucan.md` section C: adopting UCAN would drag in
DAG-CBOR, multiformats, `did:key` and SHA-256 beside our BLAKE3, for
interoperability with an ecosystem Mosschat will never speak to).

A grant is **not signed**. The house mints it, stores it, and is the only
party that verifies it, so a signature would be the house proving something
to itself; and an unsigned stored grant is revocable by deleting a row,
which is the one place in Mosschat where revocation genuinely fails closed.
The cost is that a grant cannot be delegated onward without the house.
See `docs/spec/OPEN-QUESTIONS-wo-2.1.md` Q3.

### Grant shape

| Key | Field | Type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | `handle` | `Handle` | yes | 32 bytes | 32 bytes from the OS CSPRNG. The bearer token. |
| 1 | `subject` | `Text` | yes | 128 bytes | What the grant is over (below). |
| 2 | `commands` | array of `Text` | yes | 64 entries, 32 bytes each | Command names from section 7. |
| 3 | `expires_ms` | `Ms` | no | — | Absent means no expiry. |
| 4 | `label` | `Text` | no | 128 bytes | Shown to the person when they review grants. |

`subject` is one of:

| Form | Covers |
|---|---|
| `house` | Everything. The default when `Hello.grant` is absent on the local transport. |
| `visit:<hex32>` | One visit, by its 32 byte id in lowercase hex. |
| `contact:<hex32>` | Every visit with one person, by their identity key in lowercase hex. |

**D-20.** A `Request` whose `command` is not in this connection's grant is
answered `Error{not_permitted}` and the connection stays open. The error
names the command and never what the command would have returned.

**D-21.** A `Request` naming a visit or a contact outside this connection's
`subject` is answered `Error{not_permitted}`, with the identical error body
it would send for a visit that does not exist. A scoped client cannot use
the door to learn what exists outside its scope.

**D-22.** A grant with `expires_ms` at or before the house's current clock
does not authorise anything. A connection whose grant expires mid-session is
sent `Disconnect{grant_expired}` and closed; the house does not keep serving
a connection on an expired grant until its next request.

**D-23.** `grant.create` and `grant.revoke` are permitted only to a
`house`-subject grant. A scoped client cannot mint itself a wider grant or
revoke the grant that constrains it.

**D-24.** A `Hello` carrying an unknown, revoked or expired `handle` is
answered `Error{not_permitted}` and the connection is closed. It is never
silently downgraded to the full-house grant.

**D-25.** On the **network** transport, `Hello.grant` is required. The
full-house grant is not available by default over the network; it must be
minted explicitly and named by handle.

## 7. Commands

Argument and result shapes are CBOR maps with text-string keys, since these
are named data rather than wire-frozen positions. Every text field is valid
UTF-8 and capped in bytes.

`Kind` shapes, used in both `Snapshot.items` and command results:

- **contact**: `{ "key": Key, "name": Text(128), "presence": Text(16),
  "last_seen_ms": Ms, "last_seen_reason": Text(16), "path": Text(16) }`.
  `presence` is `off`, `dnd` or `home`. `last_seen_reason` is `goodbye` or
  `timeout`. `path` is `direct`, `relay` or `none`, so a status line can show
  the connection path per friend without a second call.
- **visit**: `{ "id": Id, "opened_ms": Ms, "closed_ms": Ms?, "private":
  bool, "host": Key, "participants": [Key], "unread": uint }`.
- **event**: `{ "visit": Id, "event_id": Id, "seq": uint, "author": Key,
  "ts_ms": Ms, "body_type": uint, "body": map, "readable": bool }`.
  `readable` is `false` for a body type the **house** cannot read
  (`docs/spec/recording.md` R-14), in which case `body` carries
  `{ "raw": byte string }` and the client displays "a message this version
  cannot read".
- **note**: `{ "to": Key, "queued_ms": Ms, "bytes": uint, "kind": Text(16) }`.
- **device**: `{ "key": Key, "label": Text(128), "added_ms": Ms,
  "not_after_ms": Ms, "revoked": bool, "this_one": bool }`.
- **transfer**: `{ "visit": Id, "event_id": Id, "hash": Id, "name":
  Text(128), "size": uint, "state": Text(16), "done": uint }`. `state` is
  `offered`, `running`, `complete` or `failed`, which are WO-5.2's four
  states.

| Command | Args | Result | Notes |
|---|---|---|---|
| `contact.list` | — | `{ "contacts": [contact] }` | |
| `contact.get` | `{ "key": Key }` | `{ "contact": contact }` | |
| `visit.list` | `{ "contact": Key? }` | `{ "visits": [visit] }` | Omit `contact` for all visits in scope. |
| `visit.events` | `{ "visit": Id, "from_seq": uint?, "limit": uint? }` | `{ "events": [event], "more": bool }` | `limit` defaults to 256 and is capped at 1024 **entries**, but the byte budget of D-53 binds first and `more` is the truncation signal. |
| `visit.open` | `{ "with": [Key], "private": bool? }` | `{ "visit": Id }` | This house becomes the host. |
| `visit.send` | `{ "visit": Id, "text": Text(65536), "reply_to": Id? }` | `{ "event_id": Id, "seq": uint }` | Returns once the event is sequenced and stored, not when it was typed. |
| `visit.react` | `{ "visit": Id, "target": Id, "symbol": Text(32), "remove": bool? }` | `{ "event_id": Id }` | |
| `visit.leave` | `{ "visit": Id }` | `{}` | |
| `visit.delete` | `{ "visit": Id }` | `{}` | Kind one of `docs/spec/recording.md` section 7. Irreversible. |
| `visit.drop_request` | `{ "visit": Id, "targets": [Id]?, "note": Text(256)? }` | `{ "event_id": Id }` | Kind two. Absent `targets` means the whole visit. |
| `file.send` | `{ "visit": Id, "path": Text(4096) }` | `{ "event_id": Id, "hash": Id }` | The house reads the path; the client never streams bytes through the door. |
| `file.accept` | `{ "event_id": Id }` | `{}` | |
| `note.list` | — | `{ "notes": [note] }` | |
| `note.cancel` | `{ "to": Key, "queued_ms": Ms }` | `{}` | |
| `device.list` | — | `{ "devices": [device] }` | |
| `device.revoke` | `{ "key": Key }` | `{}` | |
| `grant.create` | `{ "subject": Text(128), "commands": [Text(32)], "expires_ms": Ms?, "label": Text(128)? }` | `{ "handle": Handle }` | `house` subject only (D-23). |
| `grant.list` | — | `{ "grants": [grant without handle] }` | Handles are never listed back; a leaked list would be a leaked key ring. |
| `grant.revoke` | `{ "handle": Handle }` | `{}` | `house` subject only (D-23). |
| `presence.set` | `{ "state": Text(16) }` | `{}` | `off`, `dnd` or `home`. |
| `house.status` | — | `{ "version": Text(32), "uptime_s": uint, "gate": Text(64), "connections": uint }` | |
| `doctor.run` | `{ "contact": Key? }` | `{ "steps": [ { "step": Text(32), "ok": bool, "detail": Text(256) } ] }` | |

**D-26.** `visit.send` returns only after the event is sequenced by the host
and written to this house's store. A client showing a message as sent before
its `Reply` is showing a message that may never become an event
(`docs/spec/recording.md` section 4).

**D-27.** `file.send` takes a path the **house** opens. Bytes never cross
the door. A client that cannot hand the house a path cannot send a file, and
that is deliberate: a 1 MiB frame cap is not a file transport, and the house
already has the transfer (D9).

**D-28.** Every command argument is checked against the caps in this table
before anything is read from the store, and a cap breach is
`Error{invalid_argument}` with the connection left open.

**D-53.** **Every multi-item result is capped by bytes, not by items.** The
house accumulates encoded items into a `Reply` or a `Snapshot` frame and
stops at the first item that would carry the frame's encoded payload past
**917_504 bytes** (896 KiB), leaving that item for the next frame or the
next request. An item count, where one is stated, is a second cap that
applies after this one; whichever binds first, binds.

An item cap alone cannot work: one `event` item can approach the 131_072
byte whole-event limit of `docs/spec/recording.md` R-43, so 1024 of them is
about 128 MiB against D-6's 1 MiB frame, over a hundredfold. The byte
budget is set below 1 MiB to leave room for the enclosing array, the map
keys and the 4 byte length prefix, so a conforming house cannot construct a
frame that D-6 would make it illegal to send.

**D-54.** Truncation is always **signalled, never silent**. For
`visit.events`, `more: true` means the house stopped early for either
reason and the client continues from the highest `seq` it received. For a
`Snapshot`, the house emits as many `Snapshot` frames as it needs and the
client knows it holds everything at `SnapshotEnd` (D-13), whose `counts`
give the per-kind totals to check against. A house never drops an item it
did not report, and a client never infers completeness from a short frame.

**D-29.** `visit.delete` is irreversible and the house performs it without a
confirmation round trip. Confirming with the person is the client's job; the
door does not second-guess a command its grant permits.

**D-52.** `visit.delete` is **close-then-delete**, in that order, as one
operation. The house first leaves the visit if it is a guest, or closes it
for everyone if it is the host, and only then deletes. It does not delete a
visit it is still in: events would keep arriving and re-create the rows the
delete just removed, satisfying `docs/spec/recording.md` R-45 at the instant
of the call and violating it a second later. After `visit.delete` the house
is **not** the host of that visit and holds no role in it; there is nothing
left to host, and a later event naming that visit is refused as an event for
a visit this house is not in. The `Reply` is sent after both halves are
done, so a client that got a `Reply` knows the visit is closed and gone, not
merely scheduled.

**D-30.** A **private** visit is live at the door and absent from the store.
`visit.open{private: true}` returns a visit id, `visit.send` works against
it, and `Event` frames for `visit:<its id>` are delivered to a subscribed
client while it is open. It never appears in `visit.list`, never appears in
a `Snapshot`, and its events are never returned by `visit.events`, because
none of that exists to return (`docs/spec/recording.md` R-46). When the
visit closes it is gone, and a client that reconnects has no trace of it.
A client must not persist what it saw of a private visit; the door cannot
enforce that, and `docs/honest-limits.md` (WO-5.5) says so.

## 8. Errors

### `Error` (7), H→C

| Key | Field | Type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | `id` | uint | no | — | The `Request.id` this answers. Absent for connection-level errors. |
| 1 | `code` | `Text` | yes | 32 bytes | From the table below. |
| 2 | `detail` | `Text` | no | 256 bytes | Human-readable. Never machine-parsed by a client. |

| `code` | Meaning | Connection |
|---|---|---|
| `protocol` | Framing, ordering or encoding violation. | closed |
| `unsupported_version` | Client below `min_client_version` (section 13). | closed |
| `unknown_frame` | Frame type not known to this house (D-8). | stays open |
| `unknown_command` | Command name not known to this house. | stays open |
| `not_permitted` | Outside this connection's grant (D-20, D-21, D-24). | stays open, except on `Hello` |
| `invalid_argument` | An argument missing, mistyped or over a cap. | stays open |
| `not_found` | The named thing does not exist in scope. | stays open |
| `too_many_requests` | Over the 64 outstanding limit (D-19). | stays open |
| `busy` | The house cannot serve this right now; retry. | stays open |
| `internal` | A bug in the house. | stays open |

**D-31.** `not_found` and `not_permitted` are **not** distinguishable by a
client for anything outside its scope (D-21). Inside its scope, `not_found`
is used and is not an information leak, because the client is already
entitled to know.

**D-32.** `detail` never carries key material, a whole invite ticket, a
grant handle, or message content.

## 9. Subscriptions

A client tells the house what it wants pushed. Nothing is pushed to a client
that did not ask, so a status-bar widget is not woken by every message.

### `Subscribe` (9), C→H

| Key | Field | Type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | `id` | uint | yes | — | Correlation id, answered with `Reply{}` or `Error`. |
| 1 | `topics` | array of `Text` | yes | 32 entries, 64 bytes each | Topics (below). |

### `Unsubscribe` (10), C→H

Same shape. Removes the named topics.

### `Event` (8), H→C

| Key | Field | Type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | `topic` | `Text` | yes | 64 bytes | The topic that matched. |
| 1 | `kind` | `Text` | yes | 32 bytes | One of section 7's kinds, or `deleted`. |
| 2 | `item` | map | yes | — | The item, shaped per that kind. For `deleted`, `{ "kind": Text, "id": Id }`. |

Topics:

| Topic | Fires on |
|---|---|
| `presence` | Any contact's presence or path changing. |
| `visit:<hex32>` | Any event in that visit, and that visit closing. |
| `visits` | A visit opening, closing or being deleted. Not its events. |
| `notes` | The note queue changing. |
| `transfers` | Any transfer changing state or progressing. |
| `devices` | A device added or revoked. |
| `queue` | Door queue pressure (section 11). |

**D-33.** A `Subscribe` to a topic outside this connection's grant is
`Error{not_permitted}`; the subscription is not created and no partial set
is applied. A `Subscribe` naming 32 topics of which one is refused creates
none of them.

**D-34.** Subscriptions live for the connection and are not persisted. A
reconnecting client re-subscribes, and its `Hello` snapshot is what fills
the gap.

**D-35.** `Event` is never sent before `SnapshotEnd` on a connection that
asked for a snapshot (D-14).

**D-36.** An `Event` is a notification, not a store. A client that missed
one because it was disconnected recovers by reconnecting and reading the
snapshot, never by asking the house to replay events it already sent.

## 10. Heartbeat

### `Ping` (11) and `Pong` (12), both directions

| Key | Field | Type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | `token` | byte string | yes | 8 bytes | Echoed unchanged in the `Pong`. |

**D-37.** Either side may send `Ping` at any time. The receiver answers
`Pong` with the identical `token` before any other frame it has not already
started writing.

**D-38.** The house sends `Ping` every 15 seconds on an otherwise idle
connection and closes the connection with `Disconnect{timeout}` if no frame
of any kind arrives within 45 seconds. The client applies the same rule to
the house. 15 and 45 are chosen, not measured: three missed heartbeats, and
well inside the roughly 30 second idle-UDP timers
`research/nat-traversal-lessons.md` reports for the network transport.

**D-39.** Any frame counts as liveness. A busy connection never needs a
`Ping`.

## 11. Queue status

Research lesson 4, from Meshtastic: a client that cannot see the queue
filling cannot slow down, and an unannounced drop looks like a bug.

### `QueueStatus` (13), H→C

| Key | Field | Type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | `queue` | `Text` | yes | 32 bytes | `door` (frames waiting for this client) or `notes` (the note queue, D8). |
| 1 | `depth` | uint | yes | — | Items currently queued. |
| 2 | `cap` | uint | yes | — | The cap for this queue. |
| 3 | `state` | `Text` | yes | 16 bytes | `ok`, `pressure` or `full`. |
| 4 | `dropped` | uint | no | — | Items dropped since the last `QueueStatus` for this queue. |

**D-40.** The house's per-connection outbound queue holds at most 1024
frames. The house sends `QueueStatus{door, pressure}` when it passes 768 and
`QueueStatus{door, full}` when it reaches 1024.

**D-41.** When the outbound queue is full the house **closes the connection**
with `Disconnect{queue_full}`. It does not drop frames from the middle of a
stream a client is relying on, and it does not block the house's own work on
a client that stopped reading. A client that was too slow reconnects and
takes a fresh snapshot, which is correct by construction (D-36).

**D-42.** The note queue's own cap (D8) is reported through
`QueueStatus{notes}` and is **refused at the limit, never trimmed**: the
house refuses to queue a new note and says so through
`Error{busy}` on the command that tried, rather than silently dropping the
oldest.

**D-43.** `QueueStatus` for the `queue` topic requires a subscription;
`QueueStatus{door, full}` is sent regardless of subscription, because it
immediately precedes a close.

## 12. Disconnect

### `Disconnect` (14), both directions

| Key | Field | Type | Required | Cap | Meaning |
|---|---|---|---|---|---|
| 0 | `reason` | `Text` | yes | 32 bytes | Below. |
| 1 | `detail` | `Text` | no | 256 bytes | Human-readable. |

| `reason` | Sent by | Meaning |
|---|---|---|
| `client_done` | client | Clean exit. |
| `shutdown` | house | The house is stopping. |
| `timeout` | either | Heartbeat lapsed (D-38). |
| `queue_full` | house | D-41. |
| `grant_expired` | house | D-22. |
| `grant_revoked` | house | The grant in use was revoked while connected. |
| `protocol` | either | A violation already reported as `Error{protocol}`. |
| `replaced` | house | Another connection took this grant's exclusive slot. |

**D-44.** `Disconnect` is the last frame its sender writes on that
connection. The sender then closes.

**D-45.** A client that exits without `Disconnect` is not an error and the
house does not log it as one. `Disconnect{client_done}` lets the house
distinguish a clean exit from a crash in its connection list, exactly as the
transport's goodbye packet does for a peer; it is a courtesy, not a
requirement.

**D-46.** Killing a client never affects the house. Closing the door
connection closes no visit, cancels no transfer, and changes no presence
state. The house being home is the house running, not a window being open.

## 13. Feature flags and the minimum client version

Research lesson 4, from Meshtastic: a single wire version number forces a
flag day every time anything is added. Two mechanisms instead.

**Feature flags** are short lowercase ASCII names, `[a-z0-9._-]`, at most 32
bytes. Both sides advertise what they understand; the usable set is the
intersection, and a client computes it from `Welcome.features` against its
own list.

Version 1 defines these, and a house at this specification advertises all of
them:

| Feature | Covers |
|---|---|
| `core.v1` | Sections 2 to 12 of this document. Always present. |
| `scope.v1` | Section 6's grants. |
| `files.v1` | `file.send`, `file.accept`, the `transfer` kind. |
| `voice.v1` | Reserved for Phase 7. Never advertised in slice one. |

**D-47.** A client uses only features present in `Welcome.features`. Sending
a command belonging to a feature the house did not advertise is
`Error{unknown_command}`, not a protocol error.

**D-48.** `core.v1` is advertised by every conforming house. A `Welcome`
without it is not a Mosschat door.

**The minimum client version** replaces the version handshake. `Hello`
carries `client_version`, `Welcome` carries `house_version` and
`min_client_version`, all unsigned integers, all `1` at this specification.

**D-49.** A house receiving `client_version < min_client_version` answers
`Error{unsupported_version}` with `detail` naming the minimum, and closes.
It does not attempt a degraded session.

**D-50.** A house **serves** a client whose `client_version` is greater than
its own `house_version`. The newer client discovers what it can use from
`Welcome.features` and uses that. Refusing a newer client would make every
addition a flag day, which is the failure mode this mechanism exists to
avoid.

**D-51.** `min_client_version` rises only when a change makes older clients
genuinely unserveable, and every such rise is a release note. Adding a
command, a kind, a topic or a field is a **feature flag**, never a version
rise.

## 14. A conforming client, end to end

The minimum a Go client does, in order:

1. Connect: dial the Unix socket or named pipe of section 1, or QUIC with
   ALPN `mosschat-door-v1` and its configured key pair (D-3).
2. Send `Hello` with 16 random bytes, `client_version = 1`, a name, its
   feature list, and its grant handle if it has one.
3. Read `Welcome`. Check `client_version >= min_client_version` locally too,
   so a mismatch is a clear message and not a closed socket. Intersect
   features. Read `commands` to know what it may call.
4. Read `Snapshot` frames until `SnapshotEnd` carrying its own nonce. Only
   then draw a first screen.
5. `Subscribe` to the topics it needs.
6. Loop: read frames; answer `Ping` with `Pong`; correlate `Reply` and
   `Error` by `id`; apply `Event`; act on `QueueStatus`; stop on
   `Disconnect`.
7. Send `Request` frames with unique outstanding `id`s, at most 64 at once.
8. On exit, send `Disconnect{client_done}` and close.

Reconnect is step 1 again. There is no resume, no cursor and no replay: the
snapshot is the recovery mechanism (D-36).

## 15. Worked example

One `Hello` frame, complete with its 4 byte length prefix, every byte
accounted for. The hex below is produced by
`crates/mosschat-core/tests/spec_example.rs`, an `#[ignore]`d test committed
with this specification, and is not typed by hand. Reproduce it with:

```
cargo test -p mosschat-core --test spec_example -- --ignored --nocapture
```

<!-- BEGIN WORKED EXAMPLE -->
```
=== door.md worked example ===
frame type          1 (Hello)
nonce               (16) a1b2c3d4e5f60718293a4b5c6d7e8f90
client_version      1
client_name         "mosschat-tui"
features            ["core.v1", "scope.v1"]
payload             (56) 8201a40050a1b2c3d4e5f60718293a4b5c6d7e8f900101026c6d6f7373636861742d747569038267636f72652e76316873636f70652e7631
len prefix (u32 BE) (4) 00000038
frame = len || payload  (60 bytes)
000000388201a40050a1b2c3d4e5f60718293a4b5c6d7e8f900101026c6d6f7373636861742d747569038267636f72652e76316873636f70652e7631
```
<!-- END WORKED EXAMPLE -->

## 16. What this document does not fix

- What a command does to the visit protocol: opening, admitting,
  sequencing, the note queue. `docs/spec/visit.md`, WO-3.1.
- The store behind the commands. WO-2.5.
- The reference client's own structure. `docs/spec/client.md`, WO-5.1.
- The recording format the `event` kind carries. `docs/spec/recording.md`.
</content>
