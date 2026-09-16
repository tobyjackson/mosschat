# Connectivity run, 2026-09-16: the no-gate cases and a LAN gate run

WO-1.5 partial. Binaries 9ec424a on every machine (musl static on the two
Hewn boxes, the mac build on the MacBook; SHA256SUMS matched on all three
before anything ran). Machines: hewn-mini 192.168.1.193 (wired), hewn-pc
192.168.1.249 (wired, running a full Hewn rebuild at the time), this
MacBook 192.168.1.117 (wifi). One home router, no NAT between any pair.

Cases (d), (e) and (f) of `wo-1.5-runbook.md` did not run: they need a
gatehouse on the public internet and the MacBook on the T-Mobile hotspot,
neither of which existed today. Everything below is same-network.

## Results

| run | file(s) | what | result |
|-----|---------|------|--------|
| (a) spike | case-a-listen.txt, case-a-dial.txt | two processes on the MacBook, loopback | handshake 2.68 ms; 100 pings rtt median 0.19 ms, p95 0.22 ms |
| (b) spike | case-bc-listen.txt, case-b-dial.txt | hewn-pc dials hewn-mini, wired to wired | handshake 3.25 ms (listener accepted in 3.49 ms); rtt median 0.41 ms, p95 0.62 ms |
| (c) spike | case-bc-listen.txt, case-c-dial.txt | MacBook on wifi dials hewn-mini | handshake 13.67 ms (accepted in 9.04 ms); rtt median 5.32 ms, p95 8.55 ms |
| (a) full | case-a-doctor.json, case-a-house.jsonl, case-a-gatehouse.log | gatehouse, house --headless and doctor --hold 20 on the MacBook over 127.0.0.1 | live on the relay at 7 ms, held 20 s; path stayed `relay`, reason `no_candidates` |
| LAN gate | lan-doctor.json, lan-house.jsonl, lan-gatehouse.log | gatehouse and house on hewn-mini, doctor --hold 30 from the MacBook | live on the relay at 60 ms; `upgraded` to direct 192.168.1.193:59343 at 549 ms; path `direct`, reason `ok`, held 30 s |
| LAN gate, --no-punch | lan-nopunch-doctor.json, lan-nopunch-house.jsonl, lan-nopunch-gatehouse.log | same, --no-punch on both ends, doctor --hold 20 | live on the relay at 60 ms; path `relay`, reason `punch_disabled`, probe_burst says "1 candidates not probed"; held 20 s |

## Reading the records

- The full case (a) staying on the relay is by design, not a defect:
  `punch.rs` excludes loopback from candidates ("Loopback is excluded here
  and only here"), so on one machine the exchange is "1 local, 1 from the
  peer, 0 discovered, 0 probed" and probe_burst fails with
  `no candidates to probe`. The record says so.
- The LAN gate run is the first time the upgrade has been seen to win on
  real machines with real addresses. The house's own log agrees: `upgraded`
  to 192.168.1.117:62436 at 21141 us, 465 ms after `visit_open`.
- Direct-path RTT in lan-doctor.json (`rtt_source: probe`, median 22.8 ms,
  p95 46.1 ms) is higher than the relay's QUIC RTT in the --no-punch run
  (`rtt_source: quic`, median 9.8 ms) and than spike's direct QUIC RTT over
  the same wifi path (5.3 ms). The probe sampler runs once a second, which
  on a wifi client with power save is the worst case for a single UDP
  round trip; the QUIC-measured figures come from a busier connection. The
  gap is a property of how the two sources sample, not evidence that the
  direct path is slower, but it means the doctor's direct-path RTT should
  not be compared against its relay RTT without saying which source each is.
- Mapping came out `endpoint_independent` on every run, which is trivially
  true with no NAT in the path; it says nothing about the home router.

## What was not measured

Recovery after a 60 s drop, first probe sent and received (issue 81), the
idle-path firewall timeout (issue 82), and case (f)'s detection and
fall-back time all wait for the gate cases.

## Two things learned about running this

- Port 443 needs root on macOS; case (a) ran on 4433/4434 instead.
- Launching a nohup'd gatehouse or house over ssh hangs the ssh session
  even with all three fds redirected. The workaround that worked: run the
  launching ssh in the background locally and kill it after two seconds;
  the remote process survives. Stop the remote processes by name
  (`pkill -x mosschat`) from a fresh ssh, and never with a `~` inside a
  single-quoted `sh -c` string, which is why the first stop attempt here
  did nothing.
