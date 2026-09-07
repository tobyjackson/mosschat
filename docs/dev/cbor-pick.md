# WO-1.2: the CBOR pick

D7 candidates (`versions-v3-notes.md`): minicbor 2.3.0 (BlueOak-1.0.0, 2026-07-23),
cbor4ii 1.2.3 (MIT, 2026-09-07), ciborium 0.2.2 (Apache-2.0, 2024-01-24).

## The trial

A throwaway harness (since deleted; permanent test:
`crates/mosschat-core/src/event/envelope.rs`) encoded the D5 envelope as a
definite-length CBOR array in field order for each: minicbor via its
imperative `Encoder`/`Decoder`, cbor4ii and ciborium via `serde` over a
fixed-order tuple. 1000 random envelopes were encoded, decoded, re-encoded
and checked byte-identical; a fixed sample was encoded twice from
independent encoders and checked byte-identical. All three passed, all
three produced an identical 151-byte encoding of the sample:

```
minicbor: 1000 envelopes round-tripped byte-identical; fixed sample 151 bytes, stable across two encoders
cbor4ii:  1000 envelopes round-tripped byte-identical; fixed sample 151 bytes, stable across two encoders
ciborium: 1000 envelopes round-tripped byte-identical; fixed sample 151 bytes, stable across two encoders
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## The pick: minicbor

All three passed cleanly, so the tiebreak is ceremony and control, not
recency (recency only applies if that criterion is itself tied; it is not).
cbor4ii and ciborium both need a `serde` wrapper newtype around a hand-built
tuple to force array representation, since serde's derive on a named-field
struct produces a CBOR map. minicbor's derive-free API writes the array
directly (`enc.array(8)`, one call per field): least ceremony, and the
caller states the array length and each field's wire type explicitly rather
than trusting a generic tuple serializer, the most direct control over
determinism. No serde dependency in the path either, matching
`versions-v3-notes.md`'s stated reasoning for minicbor as lead candidate.

**Kept:** only minicbor 2.3.0 as a `mosschat-core` dependency. cbor4ii and
ciborium do not appear in `Cargo.toml`. `deny.toml`'s allow list already
carries all three licences from WO-1.1; no change was needed.
