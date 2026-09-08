# hewn-mini harness run, 2026-09-08

First live run of the WO-1.6 netns harness and of `mosschat doctor`
under netem. Box: hewn-mini, Ubuntu, kernel 7.0.0-31-generic, nft 1.1,
conntrack-tools 1.4.9. Binaries: CI artifact mosschat-linux-x86_64-a7d2a6d
(run 34247394978), sha256 in the run log. Run by Toby with
`run-harness.sh nat`, `matrix`, `down`; every file here is raw output.

## NAT mode proof (nat-eim.txt, nat-edm.txt)

Two probes from house-a 10.1.0.2:55555 to the gate's 443 and 444,
reply-tuple `dport=` read off nat-a's conntrack table:

| mode | to :443 | to :444 | reading |
|------|---------|---------|---------|
| eim  | 55555   | 55555   | same outside port, endpoint independent |
| edm  | 30671   | 16568   | different outside ports, symmetric |

Both modes behave as the harness intends. The EDM ruleset failed to load
on the first attempt (nft: "transport protocol mapping is only valid
after transport protocol match"); fixed in PR 66 by adding
`meta l4proto { tcp, udp }` before the snat, and rerun.

## Fault matrix (faults/*.txt, matrix-setup.txt)

Row command: house-a's `doctor --gate 203.0.113.1:443 --community ...
--identity-file ... --json`, gate only (no friend is home behind this
gate yet). All 12 rows exited 0, which is NOT a pass:

- 3 rows (loss-1pct, asymmetric-loss, gatehouse-killed) and the unshaped
  smoke run recorded four steps ok and mapping endpoint_independent.
- 9 rows (loss-5pct, loss-20pct, delay-50ms, delay-200ms, delay-1000ms,
  reorder, duplicate, bandwidth-256kbit, blackout-60s) recorded only
  gate_dial ok, then reason "internal", failed_step null, mapping
  unknown, and still exit 0.

Two defects follow, tracked with Konrad's fix:

1. The doctor exits 0 when the gate client fails after a successful dial
   without recording the failing step (`run_doctor_steps`, the `Err(_)`
   branch after `connect_with_recorder`). A doctor that could not
   register must exit 1 and name the step.
2. Registration fails under 50 ms delay and under 5 percent loss while
   1 percent and 10/2 percent asymmetric loss pass. Cause under
   investigation; the error text was discarded by that same branch.

The doctor finishes in about a second, so the blackout-60s and
gatehouse-killed rows here measured a fresh attempt into a broken or
dead path, not a live visit surviving one. That needs a long-lived row
command (a visit), which does not exist yet.

## Log

`run.log` is everything the runner printed, both `nat` attempts, the
`matrix` run and `down`. Community id and the two house public keys in
it are throwaway test values; the seeds were never written outside the
gitignored `.run/` directory, which teardown removed.
