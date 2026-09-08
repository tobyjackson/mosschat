# hewn-mini harness run 3, 2026-09-08

First matrix run with a live visit per row: `doctor --friend <house-b>
--hold 90 --json` from house-a, `house --headless` in house-b, gatehouse
in `internet`, EIM masquerade NAT on both sides. Binaries: CI run
34277562210, main at e05852e (PRs 79, 80). Runner from PR 86.
REPORT.txt was generated afterwards with `fault-matrix.sh --report-only`
because the mini's copy of fault-matrix.sh predated PR 78; the row
files are unchanged.

## What the run shows

Card: 0 PASS, 12 FAIL. Read past the verdicts:

- 10 rows opened a visit over the relay and held it the full 90 s with
  real RTT statistics that track the applied fault (delay-1000ms median
  981 ms, delay-50ms 49 ms, bandwidth cap 39 ms, unshaped 1.7 ms, 88
  samples each). The relay path works under every fault.
- In those same 10 rows the direct upgrade never happened: candidate
  exchange "2 local, 2 from the peer, 0 discovered, 1 probed", probe
  burst "0 of 1 candidates answered", reason probe_timeout. Both houses
  are behind endpoint-independent NATs on one bridge, where simultaneous
  probing must succeed, so this is a defect in the code or in the lab
  topology, under investigation (Konrad).
- blackout-60s: the visit died in the blackout (record ends at 45 s, the
  30 s idle timeout after the fault landed at 10 s) but neither side
  recorded path_stale, path_dead or a goodbye, and the record's reason
  still says probe_timeout. house-b then lost its gate registration in
  the same blackout and printed nothing, ever again.
- asymmetric-loss and gatehouse-killed: introduce_timeout with no visit,
  because house-b was already dead to the gate. Neither row measured its
  own fault.

house-b.jsonl is the callee's view: twelve knocks accepted, eleven
visits closed by the peer's goodbye, the twelfth (the blackout row) open
at 827.8 s with nothing after it.

## Addendum: house-b's own records (house-b-diagnostics.jsonl)

Copied off the mini's root diagnostics directory after the run (Toby).
50 records; the 11 whose relay_open reads "as the responder" are
house-b's side of the 11 visits. Every one of them: start_signal ok
"firing in 200 ms", then probe_burst fail "0 of 1 candidates answered".
Both sides probed; neither was answered. That moves issue 88 from "did
house-b probe" to "why do the probes not cross two EIM NATs on one
bridge", which the harness capture phase is for.
