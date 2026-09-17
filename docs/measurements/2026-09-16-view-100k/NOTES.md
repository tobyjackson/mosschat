# View-over-100k-messages benchmark, 2026-09-16 (WO-2.4b)

## Command

```
cargo run --release --example view_100k -p mosschat-core
```

Run twice from a clean build (`crates/mosschat-core/examples/view_100k.rs`,
committed with this PR). Each run creates a fresh tempdir store, appends
100,000 `message` events (plus one `join`) to one visit, drops and reopens
the store, then times the store-replay-into-`Recording` step and the
`visit_section` view-compute step separately.

## Machine

- `uname -a`: `Darwin mbp.local 27.0.0 Darwin Kernel Version 27.0.0: Tue Aug
  11 21:05:27 PDT 2026; root:xnu-13432.1.9~1/RELEASE_ARM64_T8103 arm64`
- `sysctl -n machdep.cpu.brand_string`: `Apple M1`
- `rustc --version`: `rustc 1.89.0 (29483883e 2025-08-04)`
- Date: 2026-09-16

## What was timed

- **write**: opening a fresh store and calling `Store::append_event` once
  per event, 100,001 times total (one `join` at seq 0, then 100,000
  `message` events), each call its own transaction (no explicit batching).
  This is the ordinary live-ingest path, reported for context only; it is
  **not** part of the gated number, since a view is recomputed from an
  already-written recording, not from the act of writing it.
- **replay**: dropping the `Store` (closing the connection, releasing the
  lock) and reopening it, then `mosschat_core::view::recording_from_store`,
  which reads every row via the new bulk `Store::events_for_visit`
  statement (one `SELECT ... ORDER BY seq` for the whole visit) and
  re-ingests each event through `Recording::ingest` — re-verifying every
  signature and every rule per event.
- **view compute**: `mosschat_core::view::visit_section` over the replayed
  `Recording`.
- **TOTAL view path**: replay + view compute together. This is the number
  the plan's gate applies to: "a 100k view over 2 seconds is a no-go."

## Raw numbers

| run | write | replay | view compute | TOTAL view path |
|---|---|---|---|---|
| 1 | 45.553090541s | 4.736470833s | 14.474083ms | **4.750944916s** |
| 2 | 44.273272917s | 4.706102250s | 15.815959ms | **4.721918209s** |

Raw stdout: `run1.txt`, `run2.txt` (this directory).

## Reading the result

**The view path is over the 2 second gate: ~4.7 seconds, roughly 2.4x the
limit.** This is an honest, unpadded, release-build number from two
consecutive runs (they agree within about 0.6%); it is not a debug-build
artifact and not a first-run cold-cache anomaly.

Where the time goes, from the shape of `recording_from_store`: it calls
`Recording::ingest` once per stored row, and `Recording::ingest` does full
ed25519 `verify_strict` plus CBOR decode/re-encode-and-compare (R-9/R-10)
per event — the same cost a live house pays per event as it arrives, just
paid 100,000 times in a tight loop with no I/O in between (the bulk read
already happened). The `view compute` step itself (14-15ms) is not the
bottleneck at all; the cost is entirely in re-verifying 100k signed events,
which is what "replay re-verifies every signature and every rule" (the work
order's own stated design) costs at this machine's ed25519 verify rate.

This is a **finding to escalate, not something this work order tunes
around**: the fix space (batched/parallel signature verification, caching a
verified recording across restarts instead of re-verifying cold, or moving
index/skip-list work into Phase 2 per the plan's own stated gate) is a
design decision outside WO-2.4b's scope. The write path (~44-46 seconds for
100k individual `append_event` calls, no batching) is also slow, but was
not asked to hit any gate and is reported for context only.

## Addendum: where the 4.7 seconds actually goes (Konrad, review)

The paragraph above attributes the cost to per-event re-verification from
the *shape* of `recording_from_store`. On review I measured the split
directly rather than leaving it inferred, with a throwaway probe (not
committed) that timed the bulk SQL read and the re-ingest loop separately
over the same 100k-event store, same machine, same release profile:

| phase | time |
|---|---|
| bulk SQL read (SQLCipher decrypt + `ORDER BY seq` scan of 100,001 rows) | **80.7 ms** |
| re-ingest (ed25519 `verify_strict` + CBOR re-encode compare + rules) | **4.258 s** |
| view compute (`visit_section`) | **14.5 ms** |

So the storage layer is **not** the bottleneck: reading and decrypting every
row of a 100k-event visit in seq order costs 81 ms, and computing the view
from the replayed recording costs 15 ms. **98% of the gated number is
signature verification**, at roughly 42 microseconds per event.

This matters for the remedy. PLAN.md's no-go reads "a 100k view over 2
seconds moves **index work** into Phase 2 first" — but index work cannot
recover this time. The `message` table's `PRIMARY KEY (visit_id, seq)`
already gives an ordered scan, there is no sort and no extra seek to remove,
and the entire read path is 1.7% of the total. Adding an index would change
the 81 ms and leave the 4.26 s untouched.

The real decision is about **when a house re-verifies**: whether a cold
start must re-verify every event it already verified when it first received
it, or whether a recording that this house wrote to its own encrypted store
may be replayed on trust (the store is authenticated per-page by SQLCipher's
HMAC, so tampering with it is already detectable at a different layer), with
verification kept mandatory only for events arriving from the network. That
is a security/design call spanning WO-2.6 (Yseult's crypto review) and the
door's cold-start behaviour, not something to settle inside WO-2.4b.
Escalated rather than decided here.
