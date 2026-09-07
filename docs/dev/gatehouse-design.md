# The gatehouse, the doorbell, liveness and diagnostics

The design WO-1.3 and WO-1.4 are built from. Authority above it: `decisions.md`, then `PLAN.md` revision 3. Read for
it: PLAN D2, D3, D4, D8, WO-1.3 to WO-1.6 and the Phase 1 gate; decisions 7, 21, 22, 30, 32;
`research/nat-traversal-lessons.md` in full; `research/reticulum.md` sections 2 and 5; the WO-1.2 spike and both PR 8
reviews.

Every quinn claim cites a file and line under `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`, abbreviated
`quinn/`, `quinn-proto/` and `quinn-udp/` for quinn 0.11.11, quinn-proto 0.11.17 and quinn-udp 0.5.15. Every number is
a stated choice with its reason, marked "measured in WO-1.5" where it is a starting value.

## 1. Roles and wire

The gatehouse is the third role of the one binary (`mosschat gatehouse`, D1), running the same identity code and CBOR
framing as a house but holding no recordings, no store and no friends of its own. Three invariants, and the shape that
enforces each:

- **It never sees content.** Relayed bytes reach it only as the opaque payload of a `Relay` datagram, copied buffer to
  buffer and never parsed. The binary links the gate module and `mosschat-core`'s identity code and nothing else from
  core: no event, no envelope, no store.
- **It never answers "is X home".** No frame asks. `Introduce` is the only frame naming another party, it names a pair
  tag rather than a key, and it yields either an introduction to both sides or silence. Asking about a friend who is
  not registered looks exactly like asking about one who is (decision 32).
- **It stores nothing beyond live registrations.** In memory: one entry per live registration (key, address, pair
  tags, counters) and one per live relay session. No disk writes at all. Its stdout carries counts and error codes,
  never a key, an address or a payload byte.

Identity is proven once in the TLS handshake (section 5); no frame carries a public key as a claim about its sender.

**Framing.** Control frames ride one bidirectional QUIC stream opened right after the handshake, each a 4 byte
big-endian length then a deterministic CBOR array whose first element is the frame type (D7); length cap 64 KiB,
checked before allocating (invariant 4). Relayed packets ride QUIC datagrams on the same connection, because an inner
QUIC packet must keep UDP's unreliable and unordered semantics and a stream would add head of line blocking to the
path we already know is the slow one. `Addr` is a fixed 19 bytes: 1 byte family, 16 byte address (IPv4 in the first
four, rest zero), 2 byte big-endian port.

### House to gate, and gate to house

| # | Frame | Fields | Direction | When |
|---|---|---|---|---|
| 1 | `Register` | `v: u8`, `community: bytes[32]`, `tags: [bytes[32]]` cap 128 | H to G | First frame on the control stream. `tags` are the pair tags (below) for friends this house will accept an introduction with. |
| 2 | `Registered` | `v: u8`, `observed: Addr`, `keepalive_s: u8`, `secondary_port: u16` | G to H | Reply to 1. `observed` is address reflection: the source address the gate saw. |
| 3 | `Reflect` | `v: u8` | H to G | Any time; sent once on the secondary port connection to get the second observation research D1 asks for. |
| 4 | `Reflected` | `v: u8`, `observed: Addr` | G to H | Reply to 3. |
| 5 | `Introduce` | `v: u8`, `tag: bytes[32]`, `ttl_s: u16` cap 60 | H to G | This house wants to reach the friend that tag names. |
| 6 | `Introduction` | `v: u8`, `tag: bytes[32]`, `session: u32`, `peer_observed: Addr`, `role: u8` (1 initiator, 2 responder) | G to H | Sent to **both** houses, and only when both have registered and both listed that tag. |
| 7 | `Start` | `v: u8`, `session: u32`, `fire_in_ms: u16`, `gate_ms: u64` | G to H | Sent back to back to both houses on `StartRequest`. `gate_ms` is the gate's monotonic clock, written into both diagnostics records so two logs can be aligned; it is never used as a time to act on. |
| 8 | `StartRequest` | `v: u8`, `session: u32` | H to G | Once both sides have exchanged candidates (frame 14). |
| 9 | `Keepalive` | `v: u8` | H to G | Every `keepalive_s`. |
| 10 | `KeepaliveAck` | `v: u8`, `observed: Addr` | G to H | Reply to 9. Re-reflecting for free means a changed mapping on the gate path is noticed without a separate probe. |
| 11 | `Goodbye` | `v: u8`, `reason: u8` | H to G | Clean exit. Deregisters at once. |
| 12 | `Error` | `v: u8`, `code: u8`, `detail: text` cap 64 | G to H | Any refusal. `code` is the reason enum of section 7. |
| 13 | `Relay` (datagram, not a frame) | `[0x01][session: u32 BE][payload]`, payload cap 1400 bytes | H to G and G to H | Every packet of a relayed peer connection. |

`Relay` is addressed by session rather than recipient key on purpose: a session exists only after a mutual
introduction, so the addressing carries the authorisation and a registered house cannot spray datagrams at a key it
was never introduced to. It is also 5 bytes of overhead instead of 33, which matters because the inner connection's
minimum packet is 1200 bytes (`quinn-proto/src/lib.rs:332`), so the gate path needs `max_datagram_size()`
(`quinn/src/connection.rs:483`) of at least 1205. If it reports less, that session falls back to a reliable
bidirectional stream per pair and the record says `relay_stream_fallback`; DERP relays over TCP, so a reliable floor
is a proven floor.

### House to house, during the doorbell

These ride one bidirectional stream, the porch stream, inside the end to end QUIC connection between the two houses,
relayed at first and mutually authenticated to both pinned keys. The gate forwards them as opaque `Relay` payloads.

| # | Frame | Fields | Direction | When |
|---|---|---|---|---|
| 14 | `Candidates` | `v: u8`, `attempt: bytes[16]`, `addrs: [Addr]` cap 16, `probe_half: bytes[32]` | both ways | First frame each way on the porch stream. |
| 15 | `PathUp` | `v: u8`, `attempt: bytes[16]`, `addr: Addr`, `rtt_us: u32` | both ways | The sender has moved its outbound traffic for this peer to `addr`. |
| 16 | `PathDown` | `v: u8`, `attempt: bytes[16]`, `addr: Addr`, `reason: u8` | both ways | The sender has moved back to the relay. |
| 17 | `Goodbye` | `v: u8`, `reason: u8` | both ways | Clean exit, so the peer goes straight to dead without passing through stale (section 4). |

**Pair tag** = `BLAKE3("mosschat-gate-pair-v1" || community || min(kA,kB) || max(kA,kB))`, keys compared as byte
strings. Only someone holding both public keys can compute it, so a stranger who knows a house's key cannot
manufacture an introduction to it. The honest cost: when the gate introduces two houses it learns those two keys are
friends, and because tags are standing rather than on demand it also learns how many friends each house has on that
gate. There is no cheap fix (private set intersection is not slice one work). It is bounded by decision 30 greying out
public gates, and by a community gate's founder already knowing the community.

## 2. The doorbell

ICE shaped per research lesson 9: gather, exchange, probe all at once, start relayed, upgrade once a candidate proves
itself, fall back on failure. Nothing waits on a hole punch.

1. **Gather.** Every non-loopback address on every up interface, both families, IPv6 included (IPv6 removes NAT but
   not the stateful firewall, so it needs the same dance); the reflections from frames 2 and 4; and anything from
   same-network discovery (section 6). Capped at 16, because the probe burst costs bandwidth per candidate.
2. **Relay first.** `Introduce`, `Introduction` to both, the initiator dials the end to end QUIC connection through
   the relay session and the responder accepts. Traffic flows from that moment; the Phase 1 gate's target is first
   relayed packet under 1 second.
3. **Exchange.** `Candidates` each way on the porch stream, inside the sealed connection, so the gate sees candidate
   lists as ciphertext. Each side contributes 32 random bytes and both derive `probe_key = BLAKE3("mosschat-probe-v1"
   || attempt || half_initiator || half_responder)`.
4. **Start.** Either side sends `StartRequest`; the gate sends `Start` to both back to back with `fire_in_ms = 200`,
   and each side fires 200 ms after it receives the frame. No clock is synchronised: the skew between the two is the
   difference in their one way delay from the gate, tens of milliseconds, and research B only needs both first packets
   inside the same few seconds. 200 ms is large enough that neither fires before the other has its copy, small enough
   to be invisible. Measured in WO-1.5 item 2.
5. **Probe.** The packet below to every candidate every 100 ms for 3 seconds, then every 1 second for 7 more, then
   that candidate is given up. 100 ms is fast enough that the two sides' first packets cross well inside a firewall's
   state window and slow enough that 16 candidates at 10 per second is about 104 kbit/s for 3 seconds. Measured in
   WO-1.5 item 2.
6. **Upgrade.** The first candidate to answer **3** consecutive probes wins, ties broken by lowest RTT of those three.
   Three because one answer can be a duplicate or a reflection while three in a row show a mapping that persists, and
   at 100 ms that is 300 ms, inside the burst. The winner goes into the path table (section 3), `PathUp` goes out, the
   relay session stays open but idle. Losers are not re-evaluated: a better path is looked for again only after a
   failure.
7. **Fall back.** On path failure (section 4) the path table reverts that peer to the relay session, `PathDown` goes
   out, and the doorbell reruns from step 1 with a fresh attempt id.

Probe packet, fixed 81 bytes, not CBOR, so it needs no allocator and no parser:

```
0        0x2A   discriminator, see section 3
1..4     "MSP"
4        version, 0x01
5        type, 0x01 ping, 0x02 pong
6..22    attempt id, 16 bytes
22..30   tx id, 8 random bytes, echoed unchanged in the pong
30..49   Addr: in a ping all zero, in a pong the source address of the ping being answered
49..81   BLAKE3 keyed with probe_key over bytes 0..49, first 32 bytes
```

A keyed hash rather than an ed25519 signature, because probes are frequent and a signature is 64 bytes plus a scalar
multiplication we do not need. Both halves crossed the gate inside the end to end TLS, so the gate does not hold the
probe key either, and a probe never grants trust anyway: the direct path carries the same mutually authenticated QUIC
connection, so a forged probe could at worst waste an upgrade attempt.

Logged at every step, feeding WO-1.4: one `steps[]` entry per numbered step with its outcome, wall duration and
detail, plus for step 5 the first probe sent and received per side with timestamps (research D2), and for step 6 the
winning candidate and its RTT (research D5).

## 3. Socket ownership

**Decision: probes share quinn's socket.** `mosschat-net` implements `quinn::AsyncUdpSocket`
(`quinn/src/runtime.rs:42`) as the porch socket, modelled on quinn's own tokio implementation
(`quinn/src/runtime/tokio.rs:51-101`, a `tokio::net::UdpSocket` plus a `quinn_udp::UdpSocketState`), and hands the
same `Arc` to `Endpoint::new_with_abstract_socket` (`quinn/src/endpoint.rs:133`) while keeping a typed handle for
itself. quinn's doc for that constructor names exactly this case: "Useful when `socket` has additional state (e.g.
sidechannels) attached for which shared ownership is needed" (`quinn/src/endpoint.rs:130-132`). `quinn::udp` is
re-exported (`quinn/src/lib.rs:75`), so building a `Transmit` for our own probe sends (`quinn-udp/src/lib.rs:134-147`,
all fields public) needs no extra dependency.

The porch socket also owns a per peer path table, and presents each peer to quinn at a **stable synthetic address**
rather than the real one: `fd`, 5 bytes randomised per process, 10 bytes of `BLAKE3(peer key)`, port 1, an RFC 4193
unique local address that never leaves the machine. quinn always sends there; the porch socket decides whether the
bytes leave as a `Relay` datagram or straight to the current direct candidate, and rewrites inbound source addresses
to the synthetic one before quinn sees them.

That indirection is what makes the relay to direct upgrade possible at all. quinn routes an inbound datagram by
destination connection ID before it looks at the address (`quinn-proto/src/endpoint.rs:1083-1087`), so a packet from a
new remote does reach the connection, and on a **client** connection a non probing packet from an address other than
the current path hits `panic!("packets from unknown remote should be dropped by clients")`
(`quinn-proto/src/connection/mod.rs:3016-3018`); passive migration is server only (`:3011-3031`). Letting quinn see
real addresses would therefore give an upgrade that works in one direction and panics in the other. With the synthetic
address quinn never sees a path change at all, and its congestion controller sees only an RTT that improved.

**Telling probes from QUIC.** A QUIC long header has bit 0x80 set and a short header has it clear; both must carry the
fixed bit 0x40 (`quinn-proto/src/packet.rs:876-877`, and the encoders at `:350` and `:835-838` always set it). quinn
enforces that on receive only when greasing is off: `if !grease_quic_bit && first & FIXED_BIT == 0` returns
`InvalidHeader("fixed bit unset")` (`quinn-proto/src/packet.rs:585-586`), reached from
`quinn-proto/src/endpoint.rs:158-161`. The default is on (`quinn-proto/src/config/mod.rs:63`), and with it a peer may
clear the bit at random on send (`quinn-proto/src/connection/packet_builder.rs:127-129`) when we advertised the
transport parameter (`quinn-proto/src/transport_parameters.rs:173`). So every endpoint sets
`EndpointConfig::grease_quic_bit(false)` (`quinn-proto/src/config/mod.rs:132`), which stops our peers greasing (they
are our own binary) and makes quinn reject any first byte with 0x40 clear. The probe's first byte 0x2A has 0x80 and
0x40 both clear, so it is not a valid QUIC first byte either way; and at 81 bytes it is below any legal QUIC datagram,
which quinn would drop silently rather than fatally in any case (`quinn-proto/src/endpoint.rs:203-206`).

The filter lives in the porch socket's `poll_recv` and must split by segment, not by buffer: quinn-udp
opportunistically enables UDP GRO on Linux (`quinn-udp/src/unix.rs:128-129`) and `RecvMeta::stride` documents that one
buffer may hold several datagrams with the last one shorter (`quinn-udp/src/lib.rs:100-110`), so a probe can arrive
coalesced behind QUIC packets. The socket walks each buffer in `stride` increments, removes probe segments, repacks
the rest, and if a whole batch was probes it loops and re-polls the inner socket rather than returning `Ok(0)`, which
quinn's driver would treat as progress (`quinn/src/endpoint.rs:793-835`).

Direct packets from an address in no peer's candidate table are dropped, which is a feature: nobody publishes where a
house is (D3), so every real path was learned from a ticket, from discovery or from a candidate exchange. The cost is
one seam WO-4.1 needs, a flag accepting unknown sources while an invite is outstanding.

**Why not a second socket.** A NAT mapping is per socket, so the public port a second socket gets is not the one QUIC
is using, and anything discovered or punched on it is useless to the connection that matters. The only way round that
is two sockets on one local port under SO_REUSEPORT, whose inbound distribution differs by platform and is nowhere
specified to deliver a 4 tuple to the socket that sent from it. No measurement of it exists here, and building on
unmeasured platform behaviour is how "works on Linux" ships.

**Reversing condition**, either one flips the decision: (a) WO-1.5 or WO-1.6 shows one probe delivered into quinn or
one QUIC packet eaten by the filter on any of the three platforms; or (b) the porch socket adds more than 20
microseconds at the median per received datagram against a plain tokio socket in a local benchmark (roughly a tenth of
a LAN RTT; measured in WO-1.5). On either, keep the porch socket for path selection, move probes to a second socket,
and drive the upgrade from QUIC's own PATH_CHALLENGE, giving up pre-validated candidate scoring.

## 4. Liveness

quinn does not know a router's UDP timer, so this policy is ours (research lesson 8, Reticulum lesson 4). The firewall
assumption is the 30 seconds research B names.

- **Keepalive on an idle direct path.** `K = clamp(8 * srtt, 5 s, 15 s)`. Ceiling 15 s because it is half the assumed
  30 s timer, so two consecutive losses still cannot let the mapping expire; floor 5 s because below that we spend
  packets and radio wakeups for no gain against a 30 s timer, and it matches the clamp Reticulum settled on; srtt
  scaling backs a slow path off before a fast one. The real timeout is WO-1.5 item 3, so this is a starting value.
- **During a live visit**, one probe every 500 ms: death detection matters more than packet count while people are
  talking.
- **Stale.** Three consecutive probes unanswered, each lost after `max(4 * srtt, 500 ms)`. Three because at 5 percent
  loss that is a 1 in 8000 false alarm, and at 500 ms it lands in about 1.5 s. Stale means stop sending on that path,
  move traffic to the relay at once, keep probing.
- **Dead.** Stale plus a grace of `4 * srtt + 5 s` at one probe per second (Reticulum's shape). Drop the path, rerun
  the doorbell.
- **Goodbye.** Frame 17 to the peer, frame 11 to the gate. The receiver marks dead at once and skips stale, and each
  friend's last seen records which of the two it was (D8).
- **Local address change** is the fast path for case (f): the interface list is polled every 1 s and a send error
  counts as an immediate change. On change every direct path goes stale at once, traffic moves to the relay,
  candidates are regathered. It is the only sub-second path change signal available without platform specific APIs,
  and it is how the Phase 1 gate's 1 second criterion is met. The peer finds out by probe loss in about 1.5 s, so the
  two sides are asymmetric; WO-1.5 case (f) measures both, and the asymmetry is a result, not something to hide.
- **Cached addresses.** A candidate unanswered for 10 minutes expires. A failed dial expires its address at once and
  triggers rediscovery rather than a retry (research lesson 6): retrying an address that just failed spends the same
  timeout twice.
- **quinn's timers, set so they do not fight ours.** `max_idle_timeout` is set explicitly to 30 s, which is also the
  default (`quinn-proto/src/config/transport.rs:369`), so it is stated rather than inherited, and
  `keep_alive_interval`, which defaults to `None` (`:385`), is set to 15 s (`:259`), below both peers' idle timeouts
  as that setter's doc requires (`:255-258`). The two do different jobs: our probes are not QUIC packets, so without
  quinn's keepalive an idle connection would hit the 30 s idle timer while the path was perfectly alive, and quinn's
  keepalive in turn covers neither candidate paths carrying no traffic nor death detection inside a second.
  `ServerConfig::migration` (`quinn-proto/src/config/mod.rs:292`) stays at its default, because with the synthetic
  address of section 3 quinn never sees a migration.

## 5. Identity binding

Two review items from PR 8 close here, neither optional.

**The key is the one proven in the TLS handshake, and nothing peer supplied.** After the handshake and before any
application byte is read, the connection is wrapped once. `AuthedConnection::new` calls `Connection::peer_identity()`
(`quinn/src/connection.rs:572`), downcasts to `Vec<CertificateDer<'static>>` as documented at `:569-571` and produced
at `quinn-proto/src/crypto/rustls.rs:79-88`, requires exactly one element, parses its SubjectPublicKeyInfo with
`x509-parser`, checks the algorithm is id-Ed25519 and the key is exactly 32 bytes, and stores that as `peer_key`.
Nothing in `mosschat-net` outside that constructor holds a bare `quinn::Connection`, and every application signature
on the connection is verified against `peer_key`. No frame in section 1 carries a public key, so there is no second
source of truth to get wrong. The spike's responder shape, verifying against a key the peer sent in the same 96 bytes
(`crates/mosschat-net/examples/spike.rs:745`), does not survive into WO-1.3. `x509-parser` moves from a dev dependency
to a real one; it is already licence cleared and adds no crypto backend.

**The chain is exactly one self-signed certificate.** Both verifiers, client side pinning the server and server side
pinning the client, reject unless `intermediates` is empty, the SPKI algorithm is id-Ed25519, the SPKI key is 32
bytes, issuer equals subject, and the certificate's signature verifies under its own SPKI key. Today intermediates are
ignored rather than rejected, which carries an unverified input around for no reason: the ticket pins a key, so a
chain has nothing to add. The check is made twice, in the verifier where it fails closed with a TLS alert
mid-handshake, and again as the length check in `AuthedConnection::new`.

**Recorded as a decision, not an oversight** (Yseult finding 6): validity dates and server name are deliberately not
checked. There is no certificate authority and no clock we trust; the certificate carries a key pinned out of band,
its lifetime is the process, and rotating it does not rotate the identity. A module doc says so in those words so the
next reader does not "fix" it. Also from that review: every read on the control and porch streams carries a deadline
(`tokio::time::timeout`), 10 s for a frame that should follow immediately and 30 s of porch idle; every length prefix
is checked against its cap before allocation (invariant 4); and the identity seed is held in a `Zeroizing` wrapper
wherever it is persisted or copied.

## 6. Same-network discovery

No gate involved, so two houses on one LAN work with a local-only community (decision 7).

- **Group and port.** IPv4 `239.255.49.91` (administratively scoped, RFC 2365), IPv6 `ff02::4d:5343` (link-local
  scope), port `49911`, which sits in IANA's dynamic and private range 49152 to 65535 and so is assigned to nobody. On
  its own socket, not the porch socket: joining a group changes socket options and the porch mapping must stay clean.
- **Frame**, fixed 144 bytes, no CBOR, so a hostile packet needs no parser:

  ```
  0        0x2B   (distinct from the probe's 0x2A)
  1..4     "MSD"
  4        version, 0x01
  5        type, 0x01 announce
  6..38    community id, 32 bytes
  38..70   announcing public key, 32 bytes
  70..72   QUIC port, big-endian u16
  72..80   8 random bytes, anti replay
  80..144  ed25519 signature over "mosschat-discovery-v1" || bytes 0..80
  ```

- **What is announced:** public key and port, plus the community id so a machine in two communities can tell them
  apart. No name, no presence state, no address: the address is the packet's source, the only trustworthy one anyway.
- **Rate limit.** Send one per 30 s, plus one at start, plus one **unicast** reply to a friend's announce when we hold
  no address for them, so a busy LAN does not storm. 30 s because criterion 3 gives 60 seconds from coming home to a
  note landing. Receive: drop a second announce from the same key inside 10 s, and drop everything above 50 announce
  packets per second in total, a counter well above what a 30 person community produces and well below what costs
  measurable CPU.
- **Verification and candidacy.** An announce whose key is not already a friend on file is dropped before the
  signature is checked (research lesson 2 shape, cheapest first); a bad signature is dropped and counted. What
  survives becomes a candidate (source address plus announced port, source `discovery`, 5 minute expiry) and is probed
  like any other. On a LAN it usually answers the first probe, so the doorbell upgrades before the gate matters; with
  no gate configured it is the only candidate and the porch socket dials it with no relay path.

## 7. The diagnostics record

One record per connection attempt, written whether it succeeded, degraded or failed (invariant 12, decision 22).

| Field | Type | Note |
|---|---|---|
| `attempt` | 16 byte id, hex | Same value both sides, from frame 14, so two logs join |
| `session`, `gate_ms` | u32, u64 | The gate's session and its clock from frame 7, the one shared timestamp |
| `peer` | 8 hex chars | Redacted, see below |
| `started_at`, `ended_at` | RFC 3339 UTC | |
| `steps` | array of `{step, at_ms, outcome, detail}` | `step` from the fixed enum below, in the order tried |
| `failed_step` | step or null | |
| `local_observed` | two `Addr`s | Primary and secondary gate reflections |
| `peer_observed` | `Addr` | From frame 6 |
| `mapping` | `endpoint_independent` / `endpoint_dependent` / `unknown` | Inferred, see below |
| `gate_carried_traffic` | bool, plus `gate_bytes` | Recorded on every connection, success or not (D3) |
| `path`, `path_rtt_us` | `relay` or `direct` with its `Addr`; u32 | The chosen path |
| `reason` | fixed enum | |
| `version`, `platform` | strings | |

Step enum: `gate_dial`, `gate_register`, `reflect_primary`, `reflect_secondary`, `introduce`, `relay_open`,
`peer_handshake`, `candidate_exchange`, `start_signal`, `probe_burst`, `upgrade`, `live`, `path_lost`,
`relay_fallback`, `closed`.

Reason enum: `ok`, `gate_unreachable`, `gate_refused_unregistered`, `gate_refused_not_friends`, `gate_at_capacity`,
`gate_rate_limited`, `relay_stream_fallback`, `relay_datagram_too_large`, `peer_not_registered`,
`peer_handshake_failed`, `peer_key_mismatch`, `no_candidates`, `probe_timeout`, `endpoint_dependent_mapping`,
`hairpin_failure`, `udp_blocked`, `path_idle_timeout`, `local_address_changed`, `peer_goodbye`, `cap_exceeded`,
`internal`.

Inference, so the Phase 1 gate's "named reason" for case (d) comes from a rule and not a guess:
`endpoint_dependent_mapping` when the primary and secondary reflections differ in address or port; `hairpin_failure`
when both sides' observed public addresses share an IP and every direct candidate timed out while the relay worked;
`udp_blocked` when neither gate port could be reached although its name resolved. That last cannot be told from "the
gate is down" without a second gate or a TCP probe, and the record says so in its `detail` rather than pretending
otherwise.

**Location.** Linux `$XDG_STATE_HOME/mosschat/diagnostics/`, default `~/.local/state/mosschat/diagnostics/` (the XDG
basedir spec's directory for state and logs); macOS `~/Library/Logs/mosschat/` (Apple's user log location, and what
Console shows); Windows `%LOCALAPPDATA%\mosschat\diagnostics\`, local rather than roaming. One file per UTC day,
`YYYY-MM-DD.jsonl`, one object per line, JSON rather than CBOR because it exists to be read by a person and pasted
into an issue. 5 MiB per file, 7 files kept, mode 0600 on Unix.

**Redaction.** Never written: private key material, the ticket secret, any probe key, any relay payload byte, any
message content. A public key becomes the first 8 hex characters of `BLAKE3(install_salt || key)`, `install_salt`
being 16 random bytes generated once and stored beside the log, which names a peer consistently within one install and
cannot be correlated across users or back to a key. IP addresses are kept, because they are the thing being diagnosed,
and the doctor command says so on its first line so nobody sends a file not knowing what is in it.

**`mosschat doctor`** takes `--friend <name>` or `--gate`, runs the steps for real, and prints:

```
mosschat doctor: this report contains your IP addresses, your friend's and your gate's.
  1 ok    gate_dial            42 ms   gate.example:443
  2 ok    gate_register         8 ms
  3 ok    reflect_primary       1 ms   203.0.113.7:51001
  4 ok    reflect_secondary     1 ms   203.0.113.7:51884
  5 ok    introduce            96 ms
  6 ok    relay_open           31 ms   first relayed packet 0.61 s
  7 ok    peer_handshake       88 ms
  8 ok    candidate_exchange   12 ms   6 local, 2 reflected, 1 discovered
  9 ok    start_signal        204 ms
 10 fail  probe_burst       10 000 ms   0 of 9 candidates answered
 11 skip  upgrade
  mapping       endpoint_dependent (203.0.113.7:51001 vs :51884)
  path          relay, rtt 74 ms
  gate carried  yes, 1.2 MiB
  reason        endpoint_dependent_mapping
```

Exit 0 only if it reached `live`, non-zero otherwise. `--json` prints the same record that went to the log.

## 8. Work orders

**WO-1.3a, the gatehouse and the relay path** (Jerome, agent-executable). Scope: the `gatehouse` subcommand and the
gate protocol of section 1 (registration, address reflection on two ports, introduction gated on both sides having
registered and listed the tag, relay by session, keepalive, goodbye, caps); the house side gate client; the porch
socket and the path table of section 3 with one path kind, relay, and no probes; the identity binding of section 5.
Not touched: `punch.rs`, `live.rs`, `discovery.rs`, `diag.rs`. Files:
`crates/mosschat-net/src/gate/{mod,server,client,wire}.rs`, `src/sock.rs`, `src/path.rs`, `src/authed.rs`, and the
subcommand in `crates/mosschat/src/main.rs`. Caps, all chosen and none measured: 256 registrations per gate (30 people
with a few devices each is 8x headroom, and it bounds memory at a few hundred KiB); 2 connections per key (a key is
one device, and a second connection is only ever a reconnect racing a stale one); 32 control frames per second per
connection, burst 64 (a doorbell needs a handful); 2000 relay datagrams and 3 MiB/s per session each way; 2 GiB per
session per hour, then `cap_exceeded`, which bounds the bill on a rented box; registration expires 90 s after the last
keepalive, three times the firewall assumption. Verify, from WO-1.3's verify line: `cargo test -p mosschat-net gate::`
passes, including a relay path carrying 10 MiB unchanged, an unregistered key refused, an introduction refused between
two keys that are not friends, and the cap rejecting the connection past it while still serving those below. Plus a
chain of two certificates rejected in the handshake, and a signature verified against the TLS key rather than a
peer-supplied one.

**WO-1.3b, the doorbell, liveness and discovery** (Jerome, agent-executable). Scope: sections 2, 4 and 6 on the path
table and porch socket WO-1.3a built. Files: `crates/mosschat-net/src/{punch.rs,live.rs,discovery.rs}`, edits to
`src/sock.rs` and `src/path.rs`. Verify, from the same line: `cargo test -p mosschat-net punch:: live:: discovery::`
passes, including a symmetric NAT forcing the relay path inside the stated deadline, a proved candidate taking traffic
off the relay and a killed path putting it back, a peer killed without a goodbye reaching stale before dead while a
goodbye reaches dead at once, and a failed dial to a cached address triggering rediscovery rather than a retry. Plus,
from section 3, a probe and a QUIC packet delivered in one GRO batch, asserting each reaches its own consumer.

**WO-1.4, the diagnostics log and the doctor command** (Jerome, agent-executable), as PLAN writes it, built against
section 7. Files: `crates/mosschat-net/src/diag.rs` and the `doctor` subcommand. Verify: a test forcing each failure
step asserts a record naming it; `mosschat doctor` against an unreachable gate exits non-zero naming the failed step.

**Order.** WO-1.3a first and alone, because everything else edits files it creates. Then WO-1.3b and the leaf half of
WO-1.4 (record type, writer, redaction, per platform location) in parallel: `diag.rs` depends on nothing but the enums
fixed in section 7 and touches no file WO-1.3b touches. WO-1.4's other half, the doctor command and the `diag::record`
calls inside `punch.rs` and `live.rs`, is sequential after both. Review each diff before the next starts.
