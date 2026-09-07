# WO-1.2 spike notes: two open research questions

`research/nat-traversal-lessons.md` section E. Both answers are from reading
`quinn-proto` 0.11.17 and `quinn` 0.11.11 source under
`~/.cargo/registry/src/index.crates.io-*/`; neither was exercised by a live
run in this spike (that is WO-1.3's doorbell and WO-1.5's connectivity
matrix), so both are settled from source only, not demonstrated by a run.

## (a) How a quinn connection survives a path change

Source: `quinn-proto-0.11.17/src/connection/mod.rs`.

- A server passively migrates when a non-probing packet arrives from a new
  remote address (`mod.rs:3011-3018`): it calls `migrate()` (`mod.rs:3031`),
  which switches `self.path` to the new address **immediately**, not after
  validation. The client codepath asserts this handler is server-only
  (`mod.rs:3016`, "packets from unknown remote should be dropped by
  clients"); a client-initiated address change instead calls
  `local_address_changed()` (`mod.rs:3073`).
- The new path starts unvalidated: `migrate()` sets `challenge_pending` and
  arms `Timer::PathValidation` for `now + 3 * max(pto, prev_pto)`
  (`mod.rs:3066-3069`). The old path is kept as `prev_path` so traffic has
  somewhere to fall back to (`mod.rs:3056-3064`).
- If validation doesn't complete before that timer fires, `mod.rs:1197-1203`
  reverts `self.path` to the saved `prev_path`. So "how long the peer takes
  to notice a dead path" after a migration attempt is bounded by
  `3 * max(PTO, previous PTO)`, not by the idle timeout; PTO starts from
  `initial_rtt = 333 ms` (`config/transport.rs:377`) and adapts from there.
- Absent any migration, the ordinary dead-path signal is the idle timer:
  `max_idle_timeout` defaults to 30 000 ms and `keep_alive_interval`
  defaults to `None` (`config/transport.rs:369,385`), so with default
  settings alone a silent peer is not noticed for 30 seconds; WO-1.3's own
  RTT-scaled keepalive policy exists because quinn does not pick one itself.

## (b) Whether hole-punch probes can share the QUIC socket

Source: `quinn-proto-0.11.17/src/endpoint.rs`, `quinn-0.11.11/src/endpoint.rs`.

- A datagram quinn can't parse as QUIC is dropped silently, not fatal: on a
  decode error, `endpoint.rs:203-206` does `trace!("malformed header: {}",
  e); return None;` with no error surfaced to the application. A hole-punch
  probe with a non-QUIC header landing on the same socket would not crash or
  close anything, only fail to match and vanish, logged at `trace` level.
- Quinn's `Endpoint` owns its socket exclusively as `Arc<dyn AsyncUdpSocket>`
  (`quinn/endpoint.rs:474`) with no accessor to send arbitrary bytes through
  it; the only public entry points are `local_addr()` (`:285`), `rebind()`/
  `rebind_abstract()` (`:243,253`, which swap the socket for a different one
  entirely, not share it), and `new_with_abstract_socket()` (`:133`), which
  takes a caller-supplied `Arc<dyn AsyncUdpSocket>`.
- **Unsettled:** whether our own doorbell code can genuinely share the same
  underlying socket by implementing a custom `AsyncUdpSocket` and handing
  the same `Arc` to both quinn and our probe sender, so both read and write
  through one object, is plausible from this API shape but was not built or
  tried in this spike. A second, independently bound socket on the same
  local port would not reliably receive probe replies without `SO_REUSEPORT`
  and is not the same thing as sharing quinn's socket. WO-1.3 settles this
  by building the doorbell against one of these two approaches and recording
  which one it used.
