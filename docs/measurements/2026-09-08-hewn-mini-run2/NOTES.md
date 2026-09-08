# hewn-mini harness run 2, 2026-09-08

Rerun of the fault matrix after PRs 69, 72 and 75, binaries from CI run
34262376779 (main at 1852cd4, glibc artifact), one identity per doctor
run (14 minted, all in the members file). Same box and topology as run 1
(docs/measurements/2026-09-08-hewn-mini). Row command: house-a's
`doctor --gate 203.0.113.1:443 --json` behind an EIM NAT, gate only.

## Result

12 of 12 rows: all four steps ok (gate_dial, gate_register,
reflect_primary, reflect_secondary), reason ok, mapping
endpoint_independent, exit 0. Unlike run 1 these are real: no row ended
early, no row reported "internal".

Step completion times (ms from start) track the applied condition:

| row | dial | register | reflect_secondary | note |
|---|---|---|---|---|
| loss-1pct | 1 | 2 | 3 | unaffected |
| loss-5pct | 1 | 2 | 1004 | one retransmit on the secondary |
| loss-20pct | 1003 | 1117 | 1120 | one retransmit on the handshake |
| delay-50ms | 56 | 110 | 223 | one RTT per step |
| delay-200ms | 233 | 435 | 819 | one RTT per step |
| delay-1000ms | 1104 | 4245 | 8471 | 8.5 s total, still completes |
| reorder | 11 | 22 | 44 | |
| duplicate | 1 | 2 | 3 | |
| bandwidth-256kbit | 40 | 132 | 361 | |
| blackout-60s | 1 | 2 | 4 | finished before the blackout began |
| asymmetric-loss | 1 | 56 | 1061 | one retransmit |
| gatehouse-killed | 1 | 2 | 3 | finished before the kill |

The 1000 ms retransmit steps under loss are QUIC's initial probe
timeout, expected.

## Caveats

The doctor completes in milliseconds unshaped, so blackout-60s and
gatehouse-killed still measure nothing about a live visit surviving an
outage; both rows need a long-lived row command, which does not exist
yet. The gatehouse log carried no counter lines after the matrix (it
prints none today), so relay counters were not observed.
