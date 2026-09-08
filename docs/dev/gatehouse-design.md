# The gatehouse, the doorbell, liveness and diagnostics

The design WO-1.3 and WO-1.4 are built from. Authority above it: `decisions.md`, then `PLAN.md` revision 3. Read for
it: PLAN D2, D3, D4, D7, D8, WO-1.3 to WO-1.6 and the Phase 1 gate; decisions 7, 21, 22, 30, 32;
`research/nat-traversal-lessons.md` in full; `research/reticulum.md` sections 2 and 5; the WO-1.2 spike and both PR 8
reviews. Every quinn claim cites a file and line under `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`,
abbreviated `quinn/`, `quinn-proto/` and `quinn-udp/` for quinn 0.11.11, quinn-proto 0.11.17 and quinn-udp 0.5.15.
Every number is a stated choice with its reason, marked "measured in WO-1.5" where it is a starting value.

## 1. Roles and wire

The gatehouse is the third role of the one binary (`mosschat gatehouse`, D1), running the same identity code and CBOR
framing as a house but holding no recordings, no store and no friends. Three invariants, and the shape enforcing each:

- **It never sees content.** Relayed bytes reach it only as the opaque payload of a `Relay` datagram, copied buffer to
  buffer and never parsed, and the one introduction field that could carry meaning is sealed to its recipient. The
  binary links the gate module and `mosschat-core`'s identity code and nothing else: no event, no envelope, no store.
- **It never answers "is X home".** No frame asks. `Introduce` is the only frame naming another party, it names a pair
  tag rather than a key, and it yields an introduction to both sides or silence: a tag matching nobody, a house that
  declines and a house that never registered are one outcome, and only the asker's own timeout names a reason
  (decision 32).
- **It stores nothing beyond live registrations.** One entry per live registration (key, address, counters) and one
  per live relay session, in memory, no disk writes at all. Its stdout carries counts and error codes, never a key, an
  address or a payload byte.

Identity is proven once in the TLS handshake (section 5); no frame carries a public key as a claim about its sender.

**Who may register, and the slot table.** The gate holds a member list, a file of ed25519 public keys written by whoever
runs the gate, read at start and on `SIGHUP` so a member can be added without dropping live registrations; a handshake
whose proven key is not on it is refused `gate_refused_not_member` and closed before a slot is touched. The alternative,
a signed community-membership proof carried by the registrant, is right for a gate whose operator cannot enumerate its
community, and is not slice one: it needs a community signing key, issuance and revocation, none of which exist. A list
matches what decision 30 assumes, a gate run by the founder who knows the community. The table is `min(256, members)`
entries, never evicted across keys, since evicting one member to seat another is a denial of service a member could
drive; a longer member list is a configuration error refused at start, not at 3am. Within one key the sub-cap is 2 live
connections: a third is refused in the handshake with `gate_at_capacity` and closed, the two already seated untouched. A
new connection never displaces an existing one, silently or at all: a house evicted without being told would believe it
is registered while its knocks went nowhere. One whose mapping died comes back through expiry instead, a registration
expiring 90 s after its last keepalive, three times the firewall assumption, and `Goodbye` deregistering at once. Both
checks run as soon as the handshake completes, before the gate awaits any stream, so a refusal holds no slot and no
state, and the secondary port runs them too, serving `Reflect` to members alone. Sessions die with their registration,
by goodbye, expiry or lost connection, so the 8 sessions per registration below is a live cap, not a lifetime one.

**Framing.** Control frames ride one bidirectional QUIC stream opened right after the handshake, each a 4 byte
big-endian length then a deterministic CBOR array whose first element is the frame type (D7). Relayed packets ride
QUIC datagrams on the same connection, to keep the inner packet's unreliable, unordered semantics and head of line
blocking off the slow path. `Addr` is a fixed 19 bytes: 1 byte family, 16 byte address (IPv4 in the first four, rest
zero), 2 byte big-endian port.

### The frames

Frames 1 to 15 ride the gate control stream. Frames 16 to 19 ride the porch stream, one bidirectional stream inside
the two houses' end to end QUIC connection, mutually authenticated to both pinned keys and forwarded by the gate as
opaque `Relay` payloads.

| # | Frame | Fields | Direction | When |
|---|---|---|---|---|
| 1 | `Register` | `v: u8`, `community: bytes[32]` | H to G | First frame on the control stream. It carries no friend list: the gate is never told who this house knows. |
| 2 | `Registered` | `v: u8`, `observed: Addr`, `keepalive_s: u8`, `secondary_port: u16` | G to H | Reply to 1. `observed` is address reflection: the source address the gate saw. |
| 3 | `Reflect` | `v: u8` | H to G | Any time; sent once on the secondary port connection to get the second observation research D1 asks for. |
| 4 | `Reflected` | `v: u8`, `observed: Addr` | G to H | Reply to 3. |
| 5 | `Introduce` | `v: u8`, `tag: bytes[32]`, `ttl_s: u16` cap 60, `sealed: bytes` cap 512 | H to G | This house wants to reach the friend that tag names. On demand, one per attempt. `sealed` is opaque to the gate and opened only by the house the tag names. |
| 6 | `Introduction` | `v: u8`, `tag: bytes[32]`, `session: u32`, `peer_observed: Addr`, `role: u8` (1 initiator, 2 responder) | G to H | Sent to **both** houses, and only after the other house accepted the knock. `session` is 32 random bits drawn by the gate here. |
| 7 | `Start` | `v: u8`, `session: u32`, `fire_in_ms: u16`, `gate_ms: u64` | G to H | Sent back to back to both houses on `StartRequest`. `gate_ms` is the gate's monotonic clock, written into both diagnostics records so two logs can be aligned; it is never used as a time to act on. |
| 8 | `StartRequest` | `v: u8`, `session: u32` | H to G | Once both sides have exchanged candidates (frame 16). |
| 9 | `Keepalive` | `v: u8` | H to G | Every `keepalive_s`. |
| 10 | `KeepaliveAck` | `v: u8`, `observed: Addr` | G to H | Reply to 9. Re-reflecting for free means a changed mapping on the gate path is noticed without a separate probe. |
| 11 | `Goodbye` | `v: u8`, `reason: u8` | H to G | Clean exit. Deregisters at once. |
| 12 | `Error` | `v: u8`, `code: u8`, `detail: text` cap 64 | G to H | Any refusal. `code` is the reason enum of section 7. |
| 13 | `Relay` (datagram, not a frame) | `[0x01][session: u32 BE][payload]`, payload cap 1200 bytes | H to G and G to H | Every packet of a relayed peer connection. |
| 14 | `Knock` | `v: u8`, `tag: bytes[32]`, `ttl_s: u16`, `sealed: bytes` | G to H | The gate matched an `Introduce` tag against this registration and forwarded its `sealed` verbatim. It names no key and no address. |
| 15 | `KnockAnswer` | `v: u8`, `tag: bytes[32]`, `accept: bool` | H to G | Reply to 14, decided by the receiving house alone. Decline and timeout look the same to the asker. |
| 16 | `Candidates` | `v: u8`, `attempt: bytes[16]`, `addrs: [Addr]` cap 16, `probe_half: bytes[32]` | both ways | First frame each way on the porch stream. |
| 17 | `PathUp` | `v: u8`, `attempt: bytes[16]`, `addr: Addr`, `rtt_us: u32` | both ways | The sender has moved its outbound traffic for this peer to `addr`. |
| 18 | `PathDown` | `v: u8`, `attempt: bytes[16]`, `addr: Addr`, `reason: u8` | both ways | The sender has moved back to the relay. |
| 19 | `Goodbye` | `v: u8`, `reason: u8` | both ways | Clean exit, so the peer goes straight to dead without passing through stale (section 4). |

`Relay` is addressed by session rather than recipient key on purpose: a session exists only after a mutual
introduction, so the addressing carries the authorisation and a registered house cannot spray datagrams at a key it
was never introduced to. That holds only if the gate checks both halves, so it checks both: `session` is 32 random
bits from the OS CSPRNG, drawn at introduction and redrawn on collision with a live session, so it cannot be guessed
or walked; and on **every** datagram the gate checks the sending connection's TLS-proven key (section 5) against the
two keys introduced into that session before forwarding to the other one and nobody else. A datagram failing either
check is dropped and counted, never answered: an error frame would be an oracle for live sessions. The 5 bytes of
overhead instead of 33 matter too: a peer connection's packets are pinned at 1200 bytes (section 3, QUIC's own
minimum, `quinn-proto/src/lib.rs:332`), so the gate path needs `max_datagram_size()` (`quinn/src/connection.rs:483`)
of at least 1205. MTU discovery there searches on the connection's first transmit, not after the 600 s interval
(`quinn-proto/src/connection/mtud.rs:184-190`), so a 1500 byte gate path clears the floor within round trips of
registering. If it still reports less, that session falls back to a reliable bidirectional stream per pair and the
record says `relay_stream_fallback`; DERP relays over TCP, so a reliable floor is a proven floor.

**Caps and rate limits, per frame.** All chosen, none measured. Over a rate limit the gate answers
`Error{gate_rate_limited}` and keeps the registration; over a hard cap it closes. Any control frame: 64 KiB length
prefix checked before allocating, 32 frames per second per connection with burst 64. `Register`: one per connection, a
second is a protocol error, and 4 connection attempts per key per minute. `Reflect`: one per connection is the intended
use, 2 per minute. `Introduce`: `ttl_s` 60 and `sealed` 512 bytes, 6 per minute with burst 6 and 60 per hour per
registrant. `StartRequest`: 4 per session, then ignored. `Keepalive`: one per `keepalive_s`, 3 per second tolerated.
`Error`: `detail` 64 bytes. `Relay`: payload 1200 bytes, longer dropped and counted, 2000 datagrams and 3 MiB/s per
session each way, 2 GiB per session per hour then `cap_exceeded`. `Knock`: one per matched `Introduce`, `sealed`
forwarded verbatim and never opened. `KnockAnswer`: one per outstanding knock, later ones ignored, bounded by the
`Introduce` limit that caused it. `Candidates`: 16 addresses, once per attempt. Whole gate: 256 registrations, 2 live
connections per key with a third refused, 8 live sessions per registration. 256 is 30 people with a few devices each at
8x headroom and bounds memory at a few hundred KiB; 8 sessions is more friends than one person talks to at once; 2 GiB
per hour bounds the bill on a rented box.

**Pair tag** = `BLAKE3("mosschat-gate-pair-v1" || community || min(kA,kB) || max(kA,kB))`, keys compared as byte
strings. Only someone holding both public keys can compute it, so a stranger who knows a house's key cannot
manufacture an introduction to it, and no key crosses the gate in the clear.

**Introduction is by request, never by standing list.** House A sends `Introduce` with the tag for B and a `sealed` body
only B can open. The gate walks its registrations computing A's tag against each registered key, at most 256 BLAKE3
hashes over 96 bytes, and on a match forwards a `Knock` carrying that body verbatim; on no match it does nothing at all.
B answers accept or decline; the gate introduces both sides only on accept, and a decline, no answer inside `ttl_s` and
no match are one silence. The gate takes that answer only from the registration it knocked, matched on that connection's
proven key and not on the tag alone, since any member holding both keys can compute the same tag and could otherwise
accept or cancel another house's knock.

**`sealed`, so the gate learns nothing but the fact of an ask.** An ephemeral X25519 public key, then ChaCha20-Poly1305
over a small CBOR body under `BLAKE3::derive_key("mosschat-introduce-seal-v1", dh || eph_pub || kB)`, the DH being A's
ephemeral against B's identity key in Montgomery form (`ed25519-dalek-3.0.0/src/verifying.rs:484`, whose doc discourages
reusing a signing key for key exchange and cites eprint 2021/509). It is used anyway because B's identity key is the
only one A holds before any connection exists, and only B's long-term half enters the DH; the clean fix, an encryption
key in the ticket and friend record, is a D4/D7 change this order does not own. Body: `v`, `from: kA`, `sent_ms: u64`,
and for a first contact `invite: {id: bytes[16], secret: bytes[32], bind: bytes[32]}`.

**B decides on two lists, friends then invites.** B opens `sealed`, recomputes the pair tag from `from`, and accepts if
that key is a friend. Otherwise it checks its outstanding invites: it holds `BLAKE3(secret)` per unredeemed invite
(D4/D7), so it accepts when `BLAKE3(secret)` matches one still open and unexpired and `bind` equals
`BLAKE3("mosschat-invite-bind-v1" || secret || kB || gate_key)`. Anything else, a seal that will not open, a stranger
carrying no proof, a spent invite, is dropped in silence with no `KnockAnswer` at all, so neither the gate nor a
stranger gets an oracle. The bind makes a proof useless for another invite, being over that invite's own secret, and
useless at another gate, being over the identity key of the gate A handshook with, which closes the replay a gate could
otherwise mount by carrying A's blob elsewhere. Freshness at that same gate is B's job, and it covers every seal, friend
and invite alike, a friend body proving only that A once sealed to B so that one captured `Introduce` would otherwise
replay forever: every body carries `sent_ms`, B opens one only within 120 s of its own clock, wide enough for skew, and
holds `BLAKE3(sealed)` cut to 16 bytes until that window ends. The entry is inserted only after the seal opens and the
body verifies as a friend or as an invite proof, which is the accept decision itself, never on receipt and never on an
open alone (issue #16): B's public key is public, so anyone holding it can mint a seal that opens, and charging the set
on opening lets a stranger fill it at whatever rate the gate forwards knocks. The later insert loses nothing: a seal
dropped in silence costs nothing to drop again. A repeat is dropped in silence. Eviction is by expiry alone, swept on
insert, since dropping a live entry would reopen the window. The cap is 4096 entries, above the 3072 knocks the gate's
own 6 per minute limit can deliver across 256 registrants in one window, now a bound on knocks offered and not on
entries made, so a full set still means the gate broke its rate and B refuses knocks rather than evicting; 4096 * (16
byte hash + 8 byte expiry) = 98304 bytes, under 256 KiB with the map around it. The invite gains an `expires_ms` of its
own, default 7 days. A cannot bind to a gate session id instead: none exists when A builds the blob, and only the gate
being defended against could supply one. Redemption stays WO-4.1's: the approval where the inviter sees a key and a name
runs inside the end to end tunnel, and only on approve do both sides add each other and mark the invite used.

**What the gate learns**, plainly: that two of its registrants attempted contact, and when, held for the life of that
session. It never receives a friend list, never learns how many friends a house has, never sees a name or an invite,
and never holds the community's friendship graph, because a pair that never calls is a pair it never hears of. What it
does still see, with no cheap fix (private set intersection is not slice one work), is the pairs that do call and
their timing, bounded by decision 30 greying out public gates. Membership cannot be probed through it either: a tag
needs both public keys, so tags are not enumerable by anyone not already holding them, and no match, decline and
timeout are one silence. `Introduce` is rate limited per registrant, 6 per minute and 60 per hour, far too slow to
sweep a key list, and that limit also bounds the knocks A can cause.

## 2. The doorbell

ICE shaped per research lesson 9: gather, exchange, probe all at once, start relayed, upgrade once a candidate proves
itself, fall back on failure. Nothing waits on a hole punch.

1. **Gather.** Every non-loopback address on every up interface, both families, IPv6 included (it removes NAT but not
 the stateful firewall, so it needs the same dance); the reflections from frames 2 and 4; and anything from
 same-network discovery (section 6). Capped at 16, because the probe burst costs bandwidth per candidate.
2. **Relay first.** `Introduce`, `Knock`, `KnockAnswer` accepting, `Introduction` to both, then the initiator dials
 the end to end QUIC connection through the relay session and the responder accepts. Traffic flows from that moment;
 the Phase 1 target is a first relayed packet under 1 second, knock included.
3. **Exchange.** `Candidates` each way on the porch stream, inside the sealed connection, so the gate sees candidate
 lists as ciphertext. Each side contributes 32 random bytes and both derive `probe_key = BLAKE3("mosschat-probe-v1"
 || attempt || half_initiator || half_responder)`.
4. **Start.** Either side sends `StartRequest`; the gate sends `Start` to both back to back with `fire_in_ms = 200`,
 and each fires 200 ms after receiving it. No clock is synchronised: the skew is the difference in the two one way
 delays from the gate, tens of milliseconds, and research B only needs both first packets inside the same few
 seconds.
5. **Probe.** The packet below to every candidate every 100 ms for 3 seconds, then every 1 second for 7 more, then
 that candidate is given up. 100 ms is fast enough that the two sides' first packets cross well inside a firewall's
 state window, and slow enough that 16 candidates at 10 per second is about 104 kbit/s for 3 seconds. Steps 4 and 5
 are measured in WO-1.5 item 2.
6. **Upgrade.** The first candidate to answer **3** consecutive probes wins, ties broken by lowest RTT of the three.
 Three because one answer can be a duplicate or a reflection while three in a row show a mapping that persists, and
 at 100 ms that is 300 ms, inside the burst. The winner goes into the path table (section 3), `PathUp` goes out, the
 relay session stays open but idle. Losers are not re-evaluated: a better path is looked for only after a failure.
7. **Fall back.** On path failure (section 4) the path table reverts that peer to the relay session and `PathDown`
 goes out. **The end to end QUIC connection is kept**, which is section 3's whole premise: it never learns the path
 moved, the porch stream stays open, and neither the dial nor the peer handshake reruns. What reruns, with a
 fresh attempt id, is gathering, exchange and probing, steps 1 and 3 to 6. Only losing the relay session itself,
 which means the gate connection died, costs a new dial and a full rerun.

Probe packet, fixed 81 bytes, not CBOR, so it needs no allocator and no parser. Byte 0 `0x2A` (the discriminator of
section 3), 1..4 `"MSP"`, 4 version `0x01`, 5 type `0x01` ping or `0x02` pong, 6..22 attempt id, 22..30 tx id of 8
random bytes echoed unchanged in the pong, 30..49 `Addr` (all zero in a ping, the source address of the ping being
answered in a pong), 49..81 the first 32 bytes of BLAKE3 keyed with `probe_key` over bytes 0..49.

A keyed hash, not an ed25519 signature: probes are frequent, and 64 bytes plus a scalar multiplication buys nothing.
Both halves crossed the gate inside the end to end TLS, and a probe never grants trust anyway: the direct path carries
the same mutually authenticated connection, so a forged probe wastes at worst one upgrade attempt. Every step is
logged for WO-1.4: one `steps[]` entry per step with outcome, duration and detail, plus step 5's first probe sent and
received per side with timestamps (research D2) and step 6's winner and its RTT (research D5).

## 3. Socket ownership

**Decision: probes share quinn's socket.** `mosschat-net` implements `quinn::AsyncUdpSocket`
(`quinn/src/runtime.rs:42`) as the porch socket (modelled on `quinn/src/runtime/tokio.rs:51-101`), and hands the same
`Arc` to `Endpoint::new_with_abstract_socket` (`quinn/src/endpoint.rs:133`), whose doc names exactly this case:
"Useful when `socket` has additional state (e.g. sidechannels) attached for which shared ownership is needed"
(`:130-132`). `quinn::udp` is re-exported (`quinn/src/lib.rs:75`), so building our own probe `Transmit`
(`quinn-udp/src/lib.rs:134-147`, fields public) needs no extra dependency. A second socket was rejected because a NAT
mapping is per socket, so its public port is not QUIC's and anything punched on it is useless; the only way round
that, two sockets on one local port under SO_REUSEPORT, has inbound distribution that differs by platform, is nowhere
specified to deliver a 4 tuple to the socket that sent from it, and is unmeasured here.

The porch socket owns a per peer path table and presents each peer to quinn at a **stable synthetic address**: `fd`, 5
bytes randomised per process, 10 bytes of `BLAKE3(peer key)`, port 1, an RFC 4193 unique local address that never
leaves the machine. quinn always sends there; the porch socket decides whether the bytes leave as a `Relay` datagram
or straight to the current direct candidate, and rewrites inbound source addresses to the synthetic one first. That
indirection is what makes the upgrade possible at all: quinn routes an inbound datagram by destination connection ID
before it looks at the address (`quinn-proto/src/endpoint.rs:1083-1087`), so a packet from a new remote does reach the
connection, and on a **client** connection a non probing packet from an address other than the current path hits
`panic!("packets from unknown remote should be dropped by clients")` (`quinn-proto/src/connection/mod.rs:3016-3018`),
passive migration being server only (`:3011-3031`). Real addresses would give an upgrade that works one way and panics
the other. Direct packets from an address in no peer's candidate table are dropped, which is a feature: nobody
publishes where a house is (D3), so every real path came from a ticket, discovery or a candidate exchange. The cost is
one seam WO-4.1 needs, a flag accepting unknown sources while an invite stands.

**What quinn therefore does not see.** Hiding the path change hides it from the three subsystems quinn rebuilds per
path: `PathData::new` builds a fresh congestion controller, RTT estimator, pacer and `MtuDiscovery` out of the
`TransportConfig` (`quinn-proto/src/connection/paths.rs:58-108`), and `migrate` reuses the old ones only when the
change looks like a NAT rebinding (`quinn-proto/src/connection/mod.rs:3031-3051`). Our peer connection never migrates,
so it carries one path's state across a switch between two paths that share nothing. quinn-proto has the exact hook,
`Connection::path_changed`, which resets all three and is documented for "when it is known the underlying network path
has changed" (`quinn-proto/src/connection/mod.rs:1385-1397`), but quinn 0.11.11 does not re-export it: `path_changed`
appears nowhere under `quinn-0.11.11/src`.

- **MTU, capped, because no hook exists.** A peer connection sets `mtu_discovery_config(None)`
  (`quinn-proto/src/config/transport.rs:214`) and leaves `initial_mtu` at its 1200 default (`:378`,
  `quinn-proto/src/lib.rs:332`), pinning every packet on it at 1200 bytes: QUIC's own minimum, which every path must
  carry by specification and which is the floor `initial_mtu` and `min_mtu` clamp up to (`:185`, `:207`), so one number
  is safe on the relay, on a LAN and through a 1280 byte IPv6 tunnel. Without it the default `upper_bound` of 1452
  (`:743`), learned direct, would be carried onto the relay, whose payload cap is 1200; packets would die silently and
  `black_hole_cooldown` is 60 s (`:744`), missing the 1 s fall-back criterion by two orders of magnitude. **The cost is
  real:** 1452 / 1200 = 1.21, so 21 percent more packets for the same bytes against a direct path's likely 1452, paid to
  make every fall-back safe and bought back the day quinn exposes `path_changed`. **The porch socket must override
  `AsyncUdpSocket::may_fragment` to return false**, its `true` default (`quinn/src/runtime.rs:86-88`) becoming
  `allow_mtud = !socket.may_fragment()` (`quinn/src/endpoint.rs:140`) and killing MTU discovery for every connection on
  the endpoint, the gate connection among them, since it registers and relays over this same socket. Undiscovered it
  sits at 1200 and never reports the 1205 the relay needs (`Datagrams::max_size` is `current_mtu` less overhead,
  `quinn-proto/src/connection/datagrams.rs:70-76`), so every session silently takes `relay_stream_fallback` while the 10
  MiB test passes. The false is the wrapped `quinn_udp::UdpSocketState`'s own (`quinn-udp/src/unix.rs:281`), false on
  all three platforms.
- **Congestion and pacing, a real hook, ours.** `TransportConfig::congestion_controller_factory` is public
  (`quinn-proto/src/config/transport.rs:326-332`) and `congestion::Controller` and `ControllerFactory` are re-exported
  by quinn (`quinn/src/lib.rs:69`), so a peer connection gets a factory of ours wrapping the default `CubicConfig`
  (`:393`) and holding an `Arc<AtomicU64>` epoch shared with the path table. The path table bumps the epoch on every
  switch; the wrapper compares it on each call and, once it has moved, replaces the inner controller with a freshly
  built one. Pacing follows for free, quinn passing the pacer `congestion.window()` on every call rather than caching
  it (`quinn-proto/src/connection/mod.rs:617-622`). Cost: every switch restarts slow start from the initial window,
  12000 bytes (`quinn-proto/src/congestion/cubic.rs:266` against `quinn-proto/src/congestion.rs:105`), which is
  correct; a LAN window landing on the gate's 3 MiB/s cap is what is being bought out of.
- **RTT, out of quinn's hands.** `RttEstimator` has no hook at all, so section 4's `8 * srtt` and `4 * srtt` read the
  path table's own per path smoothed RTT, an EWMA over probe pong round trips (step 5) reset to the first sample on a
  switch, and never `Connection::rtt()` (`quinn/src/connection.rs:531-534`), which stays stale for several samples
  after a fall-back and would stretch the very timers meant to catch it.

**Telling probes from QUIC.** Every QUIC header must carry the fixed bit 0x40 (`quinn-proto/src/packet.rs:876-877`),
but quinn enforces it on receive only when greasing is off (`:585-586`, from `quinn-proto/src/endpoint.rs:158-161`),
and greasing defaults to on (`quinn-proto/src/config/mod.rs:63`), letting a peer clear the bit at random
(`quinn-proto/src/connection/packet_builder.rs:127-129`). So every endpoint sets
`EndpointConfig::grease_quic_bit(false)` (`quinn-proto/src/config/mod.rs:132`), stopping our own peers greasing and
making quinn reject any first byte with 0x40 clear. The probe's first byte 0x2A has 0x80 and 0x40 both clear, so it is
no valid QUIC first byte either way, and at 81 bytes it is below any legal QUIC datagram anyway
(`quinn-proto/src/endpoint.rs:203-206`).

The filter lives in the porch socket's `poll_recv` and must split by segment, not by buffer: quinn-udp opportunistically
enables UDP GRO on Linux (`quinn-udp/src/unix.rs:128-129`) and `RecvMeta::stride` documents that one buffer may hold
several datagrams with the last shorter (`quinn-udp/src/lib.rs:100-110`), so a probe can arrive coalesced behind QUIC.
The socket walks each buffer in `stride` increments, removes probe segments, repacks the rest, and if a whole batch was
probes it loops and re-polls rather than returning `Ok(0)`, which quinn's driver would treat as progress
(`quinn/src/endpoint.rs:793-835`). The queue of inbound relayed payloads is bounded at 1024 datagrams, 1.2 MiB at the
1200 byte cap, the newest dropped and counted above it, since unbounded it hands a session peer the recipient's memory,
and one `poll_recv` draws from it and the real socket in the same call rather than draining either first, so relay
traffic cannot starve the gate connection carrying it. The send side is the mirror: quinn sets `Transmit::segment_size`
to `Some(n)` whenever it wrote more than one datagram into the buffer (`quinn-proto/src/connection/mod.rs:1004-1006`,
through `quinn/src/lib.rs:106-113`), and each segment is its own inner QUIC packet needing its own 5 byte `Relay`
header. The splitting rule, written out because the failure is silent and GSO batching is on by default on Linux and on
macOS (`quinn-udp/src/unix.rs`), making a multi-segment transmit ordinary: `segment_size: None` relays `contents` as one
`Relay` payload; `segment_size: Some(n)` relays `contents.chunks(n)`, one `Relay` datagram per chunk, in order, the last
shorter than `n` whenever `n` does not divide the length; never the whole buffer as one payload. So 3600 bytes with
`Some(1200)` leaves as three `Relay` datagrams of 1205 bytes, not one 3605 byte payload, which `encode_relay` refuses
against the 1200 byte cap. A direct path passes the batch through untouched with GSO intact. Its test sits beside the
GRO one.

**Reversing condition**, either one flips the decision: (a) one probe delivered into quinn or one QUIC packet eaten by
the filter on any of the three platforms; (b) the porch socket adds more than 20 microseconds at the median per
received datagram against a plain tokio socket, roughly a tenth of a LAN RTT. Half (b) is measured **in WO-1.3a, not
WO-1.5**: it is the riskiest bet here, 1.3b and 1.4 build on it, and the porch socket exists at the end of 1.3a with a
benchmark needing nothing else. Half (a) cannot move, needing probes that WO-1.3b builds; it runs there and again on
all three platforms in WO-1.5/1.6. On either, keep the porch socket for path selection, move probes to a second
socket, and drive the upgrade from QUIC's own PATH_CHALLENGE, giving up pre-validated candidate scoring.

## 4. Liveness

quinn does not know a router's UDP timer, so this policy is ours (research lesson 8, Reticulum lesson 4). The firewall
assumption is research B's 30 seconds, and every `srtt` below is the path table's own per path estimate from probe
pongs, never `Connection::rtt()`, for the reason section 3 gives.

- **Keepalive on an idle direct path.** `K = clamp(8 * srtt, 5 s, 15 s)`. Ceiling 15 s because it is half the assumed
  30 s timer, so two consecutive losses still cannot let the mapping expire; floor 5 s because below that we spend
  packets and radio wakeups for no gain, and it matches Reticulum's clamp; srtt scaling backs a slow path off before a
  fast one. The real timeout is WO-1.5 item 3, so this is a starting value.
- **During a live visit**, one probe every 500 ms: death detection beats packet count while people talk.
- **Stale.** Three consecutive probes unanswered, each lost after `max(4 * srtt, 500 ms)`. Three because at 5 percent
  loss that is a 1 in 8000 false alarm, and at 500 ms it lands in about 1.5 s. Stale means stop sending on that path,
  move traffic to the relay at once, keep probing. **Dead** is stale plus a grace of `4 * srtt + 5 s` at one probe per
  second (Reticulum's shape): drop the path, rerun the doorbell.
- **Goodbye.** Frame 19 to the peer, frame 11 to the gate. The receiver marks dead at once and skips stale, and each
  friend's last seen records which of the two it was (D8).
- **Local address change** is the fast path for case (f): the interface list is polled every 1 s and a send error
  counts as an immediate change. On change every direct path goes stale at once, traffic moves to the relay,
  candidates are regathered.
- **Cached addresses.** A candidate unanswered for 10 minutes expires. A failed dial expires its address at once and
  triggers rediscovery rather than a retry (research lesson 6), which would spend the same timeout twice.
- **quinn's timers, set so they do not fight ours.** `max_idle_timeout` is set explicitly to 30 s, which is also the
  default (`quinn-proto/src/config/transport.rs:369`), so it is stated rather than inherited, and
  `keep_alive_interval`, `None` by default (`:385`), is set to 15 s (`:259`), below both peers' idle timeouts as that
  setter's doc requires (`:255-258`). The two do different jobs: our probes are not QUIC packets, so without quinn's
  keepalive an idle connection would hit the idle timer on a perfectly live path, and quinn's keepalive covers neither
  candidate paths carrying no traffic nor death detection inside a second. `ServerConfig::migration`
  (`quinn-proto/src/config/mod.rs:292`) stays at its default: with section 3's synthetic address quinn never migrates.

**Phase 1 measurement criterion, both sides.** Detection plus fall-back is under **1 s on the side that moved** and
under **2 s on the side that did not**, and WO-1.5 case (f) measures both numbers rather than one. They differ for a
mechanical reason: the mover has a local signal, a send error at once or the 1 s interface poll, so its worst case is
one poll interval plus the switch; the peer has only silence, so it waits three probes at 500 ms each lost after
`max(4 * srtt, 500 ms)`, about 1.5 s, and 2 s is that with room for one late probe. A single number for both sides
would be a criterion we cannot meet without platform specific interface APIs on the peer's machine. The asymmetry is a
result, not something to hide.

## 5. Identity binding

Two review items from PR 8 close here, neither optional.

**The key is the one proven in the TLS handshake, and nothing peer supplied.** After the handshake and before any
application byte is read, the connection is wrapped once. `AuthedConnection::new` calls `Connection::peer_identity()`
(`quinn/src/connection.rs:572`), downcasts to `Vec<CertificateDer<'static>>` as documented at `:569-571` and produced
at `quinn-proto/src/crypto/rustls.rs:79-88`, requires exactly one element, parses its SubjectPublicKeyInfo with
`x509-parser`, checks the algorithm is id-Ed25519 and the key is exactly 32 bytes, and stores that as `peer_key`.
Nothing in `mosschat-net` outside that constructor holds a bare `quinn::Connection`, and every application signature
is verified against `peer_key`. `x509-parser` becomes a real dependency rather than a dev one; it is already licence
cleared and adds no crypto backend.

**The chain is exactly one self-signed certificate.** Both verifiers, each pinning the other side, reject unless
`intermediates` is empty, the SPKI algorithm is id-Ed25519, the SPKI key is 32 bytes, issuer equals subject, and the
certificate's signature verifies under its own SPKI key, that check and every application signature against `peer_key`
going through `mosschat-core`'s strict verification (`verify_strict`), which rejects low-order keys that plain `verify`
accepts. Today intermediates are ignored, not rejected, carrying an unverified input for no reason: the ticket pins a
key, so a chain adds nothing. The check is made twice, in the verifier where it fails closed with a TLS alert
mid-handshake, and again as the length check in `AuthedConnection::new`.

**Recorded as a decision, not an oversight** (Yseult finding 6): validity dates and server name are deliberately not
checked. There is no certificate authority and no clock we trust; the certificate carries a key pinned out of band, its
lifetime is the process, and rotating it does not rotate the identity. A module doc says so in those words so the next
reader does not "fix" it. Also from that review: every read on the control and porch streams carries a deadline
(`tokio::time::timeout`), 10 s for a frame that should follow immediately and 30 s of porch idle; every length prefix is
checked against its cap before allocation (invariant 4); and the identity seed is held in a `Zeroizing` wrapper wherever
it is persisted or copied, read from a file 0600 on Unix, never a command line argument where `ps` would publish it.

## 6. Same-network discovery

No gate involved, so two houses on one LAN work with a local-only community (decision 7).

- **Group and port.** IPv4 `239.255.49.91` (administratively scoped, RFC 2365), IPv6 `ff02::4d:5343` (link-local),
  port `49911`, in IANA's dynamic range and so assigned to nobody. On its own socket, not the porch socket: joining a
  group changes socket options and the porch mapping must stay clean.
- **Frame**, fixed 144 bytes, no CBOR, so a hostile packet needs no parser. Byte 0 `0x2B` (distinct from the probe's
  `0x2A`), 1..4 `"MSD"`, 4 version `0x01`, 5 type `0x01` announce, 6..38 community id, 38..70 announcing public key,
  70..72 QUIC port big-endian, 72..80 8 random bytes against replay, 80..144 ed25519 signature over
  `"mosschat-discovery-v1" || bytes 0..80`. So: public key and port, plus the community id so a machine in two
  communities can tell them apart. No name, no presence state, no address: the source address is the only trustworthy
  one.
- **Rate limit.** One per 30 s, one at start, and one **unicast** reply to a friend's announce when we hold no address
  for them; 30 s because criterion 3 gives 60 seconds from coming home to a note landing. Receive: drop a second
  announce from the same key inside 10 s, and drop everything above 50 announce packets per second, above what a 30
  person community produces and below what costs measurable CPU.
- **Verification and candidacy.** An announce whose key is not already a friend on file is dropped before the
  signature is checked (research lesson 2, cheapest first); a bad signature is dropped and counted. What survives
  becomes a candidate (source address plus announced port, source `discovery`, 5 minute expiry) and is probed like any
  other. On a LAN it usually answers the first probe, so the doorbell upgrades before the gate matters; with no gate
  configured it is the only candidate and the porch socket dials it with no relay path.

## 7. The diagnostics record

One record per connection attempt, written whether it succeeded, degraded or failed (invariant 12, decision 22).

| Field | Type | Note |
|---|---|---|
| `attempt` | 16 byte id, hex | Same value both sides, from frame 16, so two logs join |
| `session`, `gate_ms` | u32, u64 | The gate's session and its clock from frame 7, the one shared timestamp |
| `peer`; `started_at`, `ended_at` | 8 hex chars; RFC 3339 UTC | `peer` is redacted, see below |
| `steps`, `failed_step` | array of `{step, at_ms, outcome, detail}`; step or null | `step` from the fixed enum below, in the order tried |
| `local_observed` | two `Addr`s | Primary and secondary gate reflections |
| `peer_observed` | `Addr` | From frame 6 |
| `mapping` | `endpoint_independent` / `endpoint_dependent` / `unknown` | Inferred, see below |
| `gate_carried_traffic` | bool, plus `gate_bytes` | Recorded on every connection, success or not (D3) |
| `path`, `path_rtt_us` | `relay` or `direct` with its `Addr`; u32 | The chosen path |
| `reason`, `version`, `platform` | fixed enum; strings | |

Step enum: `gate_dial`, `gate_register`, `reflect_primary`, `reflect_secondary`, `introduce`, `relay_open`,
`peer_handshake`, `candidate_exchange`, `start_signal`, `probe_burst`, `upgrade`, `live`, `path_lost`,
`relay_fallback`, `closed`.

Reason enum: `ok`, `gate_unreachable`, `gate_refused_not_member`, `gate_at_capacity`, `gate_rate_limited`,
`relay_stream_fallback`, `relay_datagram_too_large`, `introduce_timeout`, `peer_handshake_failed`,
`peer_key_mismatch`, `no_candidates`, `probe_timeout`, `endpoint_dependent_mapping`, `hairpin_failure`, `udp_blocked`,
`path_idle_timeout`, `local_address_changed`, `peer_goodbye`, `cap_exceeded`, `internal`.

`introduce_timeout` is inferred locally, from `ttl_s` elapsing with no `Introduction`, and is all an unsuccessful
`Introduce` yields; it deliberately does not separate a house not registered, one that declined and a tag that matched
nobody, because the gate does not say and must not (section 1). The rest of the inference, so the Phase 1 gate's
"named reason" for case (d) is a rule and not a guess: `endpoint_dependent_mapping` when the two reflections differ in
address or port; `hairpin_failure` when both sides' observed addresses share an IP and every direct candidate timed
out while the relay worked; `udp_blocked` when neither gate port could be reached although its name resolved, which
cannot be told from "the gate is down" without a second gate or a TCP probe, so the `detail` says so rather than
pretending otherwise.

**Location.** Linux `$XDG_STATE_HOME/mosschat/diagnostics/`, default `~/.local/state/mosschat/diagnostics/` (the XDG
state directory); macOS `~/Library/Logs/mosschat/` (Apple's user log location); Windows
`%LOCALAPPDATA%\mosschat\diagnostics\`, local rather than roaming. One file per UTC day, `YYYY-MM-DD.jsonl`, one
object per line, JSON rather than CBOR because a person reads it and pastes it into an issue. 5 MiB per file, 7 files
kept, mode 0600 on Unix.

**Redaction.** Never written: private key material, the ticket secret, any invite secret, any probe key, any relay
payload byte, any message content. A public key becomes the first 8 hex characters of `BLAKE3(install_salt || key)`,
`install_salt` being 16 random bytes generated once and stored beside the log, so a peer is named consistently within
one install and correlatable neither across users nor back to a key. IP addresses are kept, because they are the thing
being diagnosed, and the doctor command says so on its first line so nobody sends a file blind.

**`mosschat doctor`** takes `--friend <name>` or `--gate`, runs the steps for real, and prints a first line saying the
report contains your IP addresses, your friend's and your gate's, then one line per step (`10 fail probe_burst 10 000
ms 0 of 9 candidates answered`), then mapping, path and RTT, gate bytes and reason. Exit 0 only if it reached `live`;
`--json` prints the log's record.

## 8. Work orders

**WO-1.3a, the gatehouse and the relay path** (Jerome, agent-executable). Scope: the `gatehouse` subcommand and the gate
protocol of section 1 (the member list and slot table, registration, address reflection on two ports, introduction by
knock with the sealed request carried verbatim, relay by session with the sender-membership check, keepalive, goodbye,
and every cap section 1 lists); the house side gate client, including sealing a request and answering a knock from the
local friend list and outstanding invites; the porch socket and the path table of section 3 with one path kind, relay,
and no probes, with the MTU cap and the epoch-resetting congestion factory in place from the start; the identity binding
of section 5. Not touched: `punch.rs`, `live.rs`, `discovery.rs`, `diag.rs`. Files:
`crates/mosschat-net/src/gate/{mod,server,client,wire}.rs`, `src/sock.rs`, `src/path.rs`, `src/authed.rs`, and the
subcommand in `crates/mosschat/src/main.rs`. Verify, from WO-1.3's verify line: `cargo test -p mosschat-net gate::`
passes, including a relay path carrying 10 MiB unchanged; a key absent from the member list refused in the handshake; an
`Introduce` whose tag matches nobody, one the other house declines and one it never answers all yielding the asker the
same silence and the same `introduce_timeout`; a first contact accepted on an unredeemed invite proof, and that proof
refused at a second gate and against a second invite; a `Relay` datagram whose sender is neither key of its session
dropped and counted rather than answered; and the registration cap rejecting the connection past it while still serving
those below; and the gate connection reporting a `max_datagram_size()` of 1205 or better, which fails if the porch
socket leaves `may_fragment` at its default. Plus a chain of two certificates rejected in the handshake, a signature
verified against the TLS key, and section 3's reversing-condition benchmark run and its median recorded.

**WO-1.3b, the doorbell, liveness and discovery** (Jerome, agent-executable). Scope: sections 2, 4 and 6 on WO-1.3a's
path table and porch socket. Files: `crates/mosschat-net/src/{punch.rs,live.rs,discovery.rs}`, edits to `src/sock.rs`
and `src/path.rs`. Verify, from the same line: `cargo test -p mosschat-net punch:: live:: discovery::` passes,
including a symmetric NAT forcing the relay path inside the stated deadline, a proved candidate taking traffic off the
relay and a killed path putting it back with the connection surviving, a peer killed without a goodbye reaching stale
before dead while a goodbye reaches dead at once, and a failed dial to a cached address triggering rediscovery rather
than a retry. Plus, from section 3, a probe and a QUIC packet delivered in one GRO batch each reaching its own
consumer, and one GSO `Transmit` of three segments relayed as three `Relay` datagrams.

**WO-1.4, the diagnostics log and the doctor command** (Jerome), as PLAN writes it, against section 7. Files:
`crates/mosschat-net/src/diag.rs` and the `doctor` subcommand. Verify: a test forcing each failure step asserts a
record naming it, and `doctor` against an unreachable gate exits non-zero naming the failed step.

**Order.** WO-1.3a first and alone, because everything else edits files it creates. Then WO-1.3b and WO-1.4's leaf
half (record type, writer, redaction, per platform location) in parallel, `diag.rs` depending on nothing but section
7's enums and touching no file WO-1.3b touches. WO-1.4's other half, the doctor command and the `diag::record` calls
in `punch.rs` and `live.rs`, is sequential after both. Review each diff before the next starts.
