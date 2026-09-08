# WO-1.6 NAT harness and fault matrix

These scripts need real Linux network namespaces and `tc` netem, root, and
a Linux kernel. They will not run on macOS. They were written and dry-run
checked on a Mac with no root; they have not been run for real by anyone
yet. Run them on hewn-mini or hewn-pc.

This harness drives two things that exist in the merged code today:

- the `mosschat gatehouse` subcommand (`crates/mosschat/src/main.rs`)
- the `spike` example (`cargo run -p mosschat-net --example spike`), which
  opens one key-authenticated QUIC connection between two processes

There is no doorbell you can drive from outside a test yet. `punch.rs`,
`live.rs` and `discovery.rs` exist in `mosschat-net`'s library, but
`main.rs` wires up only the `gatehouse` subcommand; there is no CLI
command that runs an ICE-style doorbell (gather, relay-first, probe,
upgrade) between two standalone processes. WO-1.4's `doctor` subcommand
will add one; when it lands, point `fault-matrix.sh --` at it instead of
the spike example for a real end-to-end connect-and-report path. Until
then, the commands below use the spike example for a real connection
between the two houses, and the `gatehouse` subcommand as the relay in
the middle.

## Prerequisites

On the Linux box (hewn-mini or hewn-pc):

- `iproute2` (`ip`, `tc`), normally already installed
- `nftables` (`nft`)
- `conntrack-tools` (`conntrack`)
- a mosschat build: `nice -n 10 env CARGO_BUILD_JOBS=3 cargo build -p mosschat -p mosschat-net --examples`
- `iperf3` is not required by anything here; skip it unless you want it
  for your own bandwidth sanity checks outside this harness

Debian/Ubuntu: `sudo apt install iproute2 nftables conntrack`
Arch: `sudo pacman -S iproute2 nftables conntrack-tools`

## The exact sequence

Run these from the repo root, one line at a time, reading the output of
each before the next. All three scripts refuse to run for real without
root; `--dry-run` works without root and runs nothing.

```
nice -n 10 env CARGO_BUILD_JOBS=3 cargo build -p mosschat -p mosschat-net --examples
sudo bash crates/mosschat-net/tests/harness/netns-nat.sh --mode eim
sudo ip netns exec house-a ip addr show veth-ha
sudo ip netns exec nat-a nft list ruleset
```

The first `ip addr show` and `nft list ruleset` are a sanity check, not
part of the harness: confirm `veth-ha` has `10.1.0.2/24` and that
`nat-a`'s `ip nat` table has the rule you expect for the mode you picked
before doing anything traffic-bearing.

Start the gatehouse inside the `internet` namespace, in its own terminal
(it runs in the foreground):

```
sudo ip netns exec internet ./target/debug/mosschat gatehouse \
  --bind 203.0.113.1:443 --secondary-bind 203.0.113.1:444 \
  --community 0000000000000000000000000000000000000000000000000000000000000000 \
  --members /path/to/a/members/file
```

Replace the `--community` hex and `--members` path with real ones; the
gatehouse's own `--help`-equivalent error text
(`mosschat gatehouse: error: --community <64 hex chars> is required`)
tells you what it wants if you get either wrong. Leave it running.

In a second terminal, listen inside house-b (the spike example has no
separate prebuilt binary; run it through cargo, still inside the
namespace, from the repo root):

```
sudo ip netns exec house-b env CARGO_BUILD_JOBS=3 cargo run -p mosschat-net --example spike -- listen --bind 10.2.0.2:7777 --advertise 10.2.0.2:7777
```

It prints a ticket starting `moss1...`. Copy it. In a third terminal,
dial from house-a:

```
sudo ip netns exec house-a env CARGO_BUILD_JOBS=3 cargo run -p mosschat-net --example spike -- dial <the ticket from house-b>
```

This is a direct connection between the two houses' namespaces, not
through the gatehouse yet (WO-1.3b's doorbell is what would route this
through the gate and prove relay fallback; until `doctor` exists, proving
the relay path specifically means watching the gatehouse's own stdout
counts while a connection is attempted through it, per its design doc
section 1, rather than a single command that reports success or failure).

## Confirming which NAT mode is really in effect

Never assume the mode from the flag you passed; `netns-nat.sh` prints the
exact command at the end of its run, repeated here:

```
sudo ip netns exec nat-a conntrack -L -n -s 10.1.0.2
```

Run it after house-a has sent at least one packet through nat-a to two
different destinations (two separate `spike dial` attempts against two
different listeners is the simplest way to get two distinct destinations
in the table; a single dial to one gatehouse address will not
distinguish the modes, since it produces only one destination).

Read the output's `sport=... dport=...` fields on the NAT's outward
address, `203.0.113.11`:

- **Endpoint-independent (EIM):** every conntrack entry for `10.1.0.2`
  shows the *same* mapped port on `203.0.113.11`, no matter which
  destination address or port it went to.
- **Endpoint-dependent, i.e. symmetric (EDM):** entries to *different*
  destination addresses show *different* mapped ports on
  `203.0.113.11`, even though the internal source port never changed.

Do the same for `nat-b` with `-s 10.2.0.2`. Paste the raw `conntrack -L`
output for both modes into `docs/measurements/` (see below): that
output, not the flag name, is what proves the mode.

## Running the fault matrix

`fault-matrix.sh` needs a command to run per row, after `--`. With no
`doctor` command yet, the most useful thing to point it at today is a
`spike dial` from house-a to a listener already running in house-b, so
each row measures how that connection behaves under the row's condition:

```
sudo bash crates/mosschat-net/tests/harness/fault-matrix.sh -- \
  ip netns exec house-a env CARGO_BUILD_JOBS=3 cargo run -p mosschat-net --example spike -- dial <ticket>
```

A ticket is single-use per spike's own design (the listener answers one
dial and exits), so for a full matrix run you will restart `spike listen`
in house-b between rows, or write a small wrapper script that does that
and pass the wrapper as the command instead. `fault-matrix.sh --help`
lists every row id if you want to run a subset with `--rows`.

Each row's raw stdout lands in `docs/measurements/<today's date>-faults/<row-id>.txt`.
When it finishes it prints a summary table naming every file it wrote.

## What to paste back into the repo

Everything under `docs/measurements/<date>-faults/` that `fault-matrix.sh`
just wrote, plus a new file with both `conntrack -L` outputs from the
step above, for example `docs/measurements/<date>-nat-modes.txt` with a
clear heading over each mode's output. Commit these as raw text, not
paraphrased.

## Tearing down

```
sudo bash crates/mosschat-net/tests/harness/teardown.sh
```

Safe to run even if setup only partly completed, or was already torn
down. It removes the five namespaces and everything inside them (veths,
the bridge, the nftables tables). It does not touch anything outside a
namespace, so if `fault-matrix.sh` was killed mid-row, clear its qdisc by
hand: `sudo tc qdisc del dev <iface> root`: `netns-nat.sh` names the
interfaces (`veth-ha`, `veth-hb`) if you need to check which one.

## Known gaps, stated plainly

- No CLI path drives the doorbell yet, so `punch.rs`'s symmetric-NAT
  fallback and PLAN WO-1.6's "endpoint-dependent case forces the relay
  path inside WO-1.3's stated deadline" verification line cannot be
  proved end to end by this harness alone until WO-1.4's `doctor` lands.
  What this harness can prove today: the two NAT modes are genuinely
  different (conntrack evidence above), and that a direct QUIC connection
  and a gatehouse both function under each netem condition.
- The `edm` mode's nftables rule (`snat ... random`) allocates a fresh
  external port for every new conntrack entry, not only for a new
  destination; this is a stricter form of symmetric NAT than some
  consumer routers use, but it reliably produces the property this
  harness needs to prove (different destination, different port), and
  research/network-fault-testing.md section B says the exact rule was
  unverified going in: this document is that verification.
