# WO-1.6 NAT harness and fault matrix

These scripts need real Linux network namespaces and `tc` netem, root, and
a Linux kernel. They will not run on macOS. They were written and dry-run
checked on a Mac with no root; they have not been run for real by anyone
yet. Run them on hewn-mini or hewn-pc.

This harness drives four things that exist in the merged code today:

- the `mosschat gatehouse` subcommand (`crates/mosschat/src/main.rs`)
- `mosschat house --headless`, the callee: it registers at a gate, answers
  knocks from a friend list and holds a visit open, printing one JSON line
  per event (WO-1.5a)
- `mosschat doctor --friend <key> --hold <seconds> --json`, the caller and
  the row command: it runs the doorbell for real and prints the record,
  which is where every number below comes from (WO-1.4b, WO-1.5a)
- the `spike` example (`cargo run -p mosschat-net --example spike`), which
  opens one key-authenticated QUIC connection between two processes, still
  useful for a plain direct-path sanity check with no gate in it

The doorbell is drivable from the command line: see "The long-lived row
command" below, which is what the `blackout-60s` and `gatehouse-killed`
rows need and what every other row should use in preference to a
`spike dial`, since only `doctor` reports a path, a reason and a round
trip.

## Prerequisites

On the Linux box (hewn-mini or hewn-pc), with a one-line check for each:

- `iproute2` (`ip`, `tc`): `command -v ip tc >/dev/null && echo ok`
- `nftables` (`nft`): `command -v nft >/dev/null && echo ok`
- `conntrack-tools` (`conntrack`): `command -v conntrack >/dev/null && echo ok`
- `socat`, for the fixed-source-port NAT-mode probe below: `command -v socat >/dev/null && echo ok`
- GNU coreutils' `timeout`, which every fault-matrix.sh row is bounded by: `command -v timeout >/dev/null && echo ok`
- `openssl`, only for generating the community id and identity seeds below: `command -v openssl >/dev/null && echo ok`
- `gh`, the GitHub CLI, to fetch the prebuilt binaries below: `command -v gh >/dev/null && echo ok`
- `mosschat` and `spike` binaries, built for Linux (`x86_64-unknown-linux-gnu`) -- see
  "Getting the binaries" immediately below
- `iperf3` is not required by anything here; skip it unless you want it
  for your own bandwidth sanity checks outside this harness

Debian/Ubuntu: `sudo apt install iproute2 nftables conntrack socat coreutils openssl gh`
Arch: `sudo pacman -S iproute2 nftables conntrack-tools socat coreutils openssl github-cli`
NixOS or any Nix install: `nix-shell -p iproute2 nftables conntrack-tools socat coreutils openssl gh`
(coreutils and openssl are normally already on the system; the package
names above only matter if either is missing).

### Getting the binaries

CI (`.github/workflows/ci.yml`, job `artifacts-linux`) builds `mosschat`
and `spike` in release mode on every push to `main` and uploads them as
one artifact, `mosschat-linux-x86_64-<short sha>`, retained 14 days. That
job's own comments explain the scope: it only proves the example builds
in release mode and runs on a `glibc` no older than an `ubuntu-latest`
runner's, which is older than Ubuntu 26.04's -- it is the seed of WO-5.4
(pinned baseline, checksummed, multi-target release builds), not a
substitute for it. Download the latest one on any machine with `gh`
authenticated against this repo (does not need to be the Linux test box
itself), then copy the two binaries to the box:

```
gh run download --repo tobyjackson/mosschat -n mosschat-linux-x86_64-$(git rev-parse --short origin/main) -D /tmp/mosschat-artifact
scp /tmp/mosschat-artifact/mosschat /tmp/mosschat-artifact/spike user@linux-box:/path/to/bin/
```

`gh run download` matches the artifact by exact name, so if you do not
have the short SHA handy, list recent runs first
(`gh run list --repo tobyjackson/mosschat --workflow=ci.yml --branch main`)
and copy the name it printed, or omit `-n` to be prompted interactively.
`SHA256SUMS` is in the same artifact; check it after the `scp` if you
want to confirm nothing was altered in transit:

```
cd /path/to/bin && sha256sum -c /tmp/mosschat-artifact/SHA256SUMS
```

On the Linux box:

```
chmod +x /path/to/bin/mosschat /path/to/bin/spike
export MOSSCHAT_BIN=/path/to/bin/mosschat
export SPIKE_BIN=/path/to/bin/spike
```

Every command below uses `$MOSSCHAT_BIN` and `$SPIKE_BIN`; set them once
per shell before running any of the sequence. `fault-matrix.sh` and
`netns-nat.sh` read the same two variables, defaulting to
`./target/release/mosschat` and `./target/release/examples/spike` if
unset, so a developer who would rather build locally can skip all of the
above with one line instead of the Prerequisites' old cargo-toolchain
requirement:

```
nice -n 10 env CARGO_BUILD_JOBS=3 cargo build --release -p mosschat -p mosschat-net --examples
```

## The exact sequence

Run these from the repo root, one line at a time, reading the output of
each before the next. All three scripts refuse to run for real without
root; `--dry-run` works without root and runs nothing (see each script's
`--help` for the full flag list).

```
sudo bash crates/mosschat-net/tests/harness/netns-nat.sh --mode eim
sudo ip netns exec house-a ip addr show veth-ha
sudo ip netns exec nat-a nft list ruleset
```

(`$MOSSCHAT_BIN` and `$SPIKE_BIN` should already be set per "Getting the
binaries" above before this point; neither script here needs them yet,
but every step from "Building a real community" onward does.)

The first `ip addr show` and `nft list ruleset` are a sanity check, not
part of the harness: confirm `veth-ha` has `10.1.0.2/24` and that
`nat-a`'s `ip nat` table has the rule you expect for the mode you picked
before doing anything traffic-bearing.

## Confirming which NAT mode is really in effect

Do this before starting anything application-level; it only needs the
topology above.

Only one address exists past nat-a's outward side, `203.0.113.1` (the
`internet` namespace's bridge), so the only thing that can distinguish
EIM from EDM here is the **destination port**, not the destination
address, and the two probes must share **one fixed local source port**.
Two ordinary processes each picking their own ephemeral source port
would get two different NAT mappings under either mode and prove
nothing (this was wrong in an earlier version of this harness; caught in
PR 48 review).

Run all three lines back to back, with no reading, pausing, or copy-paste
delay between them (issue #52): each `socat` probe's conntrack entry is
an unreplied UDP mapping, which the kernel expires on its own short
timeout (`net.netfilter.nf_conntrack_udp_timeout`, 30s by default), so
if the `conntrack -L` capture is delayed past that window the first
probe's line may already be gone, and the comparison below is then
between one live mapping and nothing, not between two.

```
printf 'x' | sudo ip netns exec house-a socat -T 2 - UDP-DATAGRAM:203.0.113.1:443,bind=10.1.0.2:55555
printf 'x' | sudo ip netns exec house-a socat -T 2 - UDP-DATAGRAM:203.0.113.1:444,bind=10.1.0.2:55555
sudo ip netns exec nat-a conntrack -L -n -s 10.1.0.2
```

Nothing needs to be listening on `203.0.113.1:443` or `:444` for this:
the NAT mapping is created by the outbound packet alone, whether or not
anything answers it, and `socat`'s `-T 2` makes each command give up and
exit after 2 seconds either way.

Read the `conntrack -L` output carefully. Each line shows two tuples:
the original request, and the reply tuple as the NAT itself expects to
see it come back, for example:

```
udp 17 29 src=10.1.0.2 dst=203.0.113.1 sport=55555 dport=443 src=203.0.113.1 dst=203.0.113.11 sport=443 dport=41234 [UNREPLIED] mark=0 use=1
```

The mapped external port is `dport=41234` in the **second** (reply)
tuple, not any `sport=` field, and not part of the address. Compare that
field between the `:443` probe's line and the `:444` probe's line:

- **Endpoint-independent (EIM):** both lines show the **same** reply
  `dport=` value.
- **Endpoint-dependent, i.e. symmetric (EDM):** the two lines show
  **different** reply `dport=` values, even though the request-side
  `sport=55555` never changed.

Do the same for `nat-b` (`bind=10.2.0.2:55555`, then
`ip netns exec nat-b conntrack -L -n -s 10.2.0.2`).

Tear down (`teardown.sh`, below) and re-run `netns-nat.sh --mode edm`
to get the other mode's output. Paste both raw `conntrack -L` outputs
into the repo; see "What to paste back" below.

## Building a real community and members file, and starting the gatehouse

The placeholders in an earlier version of this README (`--community`
all-zero, `--members /path/to/a/members/file`) were not something you
could actually complete without reading source; here is the real
sequence (PR 48 review, Ursula). `MemberList::load`
(`crates/mosschat-net/src/gate/mod.rs`) wants one 64-hex-character
ed25519 public key per line, blank lines and `#` comments ignored.
`spike` prints its identity's public key as `spike: identity <64 hex>`
on both `listen` and `dial` (`crates/mosschat-net/examples/spike.rs`),
before it does anything network-facing, so a short-lived `listen` is
enough to read a fixed identity's public key off.

Every in-namespace step below runs the prebuilt `$SPIKE_BIN` binary,
never `cargo run` (issue #51): `cargo run` inside `ip netns exec` has to
resolve, lock and possibly recompile through cargo's own machinery,
which reaches outside `203.0.113.0/24` and has no route from inside
these namespaces, so it hangs or fails; the plain prebuilt binary is
what actually has the namespace's network access. Set `$SPIKE_BIN` (and
`$MOSSCHAT_BIN`) per "Getting the binaries" above before running any of
these.

```
mkdir -p crates/mosschat-net/tests/harness/.run
HOUSE_A_SEED=$(openssl rand -hex 32)
HOUSE_B_SEED=$(openssl rand -hex 32)
COMMUNITY=$(openssl rand -hex 32)

sudo sh -c "echo \$\$ > crates/mosschat-net/tests/harness/.run/spike-a.pid; exec ip netns exec house-a $SPIKE_BIN listen --identity $HOUSE_A_SEED --bind 10.1.0.2:7777" >/tmp/spike-a-id.log 2>&1 &
sleep 2
HOUSE_A_PUB=$(grep -m1 'spike: identity' /tmp/spike-a-id.log | awk '{print $3}')
SPIKE_A_PID=$(cat crates/mosschat-net/tests/harness/.run/spike-a.pid)
if tr '\0' ' ' </proc/$SPIKE_A_PID/cmdline 2>/dev/null | grep -q spike; then
  kill -TERM "$SPIKE_A_PID" 2>/dev/null
fi
wait

sudo sh -c "echo \$\$ > crates/mosschat-net/tests/harness/.run/spike-b.pid; exec ip netns exec house-b $SPIKE_BIN listen --identity $HOUSE_B_SEED --bind 10.2.0.2:7777" >/tmp/spike-b-id.log 2>&1 &
sleep 2
HOUSE_B_PUB=$(grep -m1 'spike: identity' /tmp/spike-b-id.log | awk '{print $3}')
SPIKE_B_PID=$(cat crates/mosschat-net/tests/harness/.run/spike-b.pid)
if tr '\0' ' ' </proc/$SPIKE_B_PID/cmdline 2>/dev/null | grep -q spike; then
  kill -TERM "$SPIKE_B_PID" 2>/dev/null
fi
wait

printf '%s\n%s\n' "$HOUSE_A_PUB" "$HOUSE_B_PUB" > crates/mosschat-net/tests/harness/.run/members.txt
echo "community: $COMMUNITY"
cat crates/mosschat-net/tests/harness/.run/members.txt
```

Each `kill -TERM` above stops that one `spike listen` by the pid its own
pidfile records, written from inside the process itself (same
`sh -c 'echo $$ ...; exec ...'` pattern as the gatehouse below, issue
#50's fix applied here too: `$!` right after `sudo ... &` can name
sudo's own pid instead), and only after confirming `/proc/<pid>/cmdline`
still says `spike` -- there is no `pkill` anywhere in this harness. Save
`$HOUSE_A_SEED` and
`$HOUSE_B_SEED` somewhere if you want either house's identity to be
reproducible across runs; they are not written to disk by this snippet
except as public keys inside `members.txt`, and `.run/` is gitignored.

Now start the gatehouse inside the `internet` namespace, in the
foreground so the terminal still blocks and shows its output
(`fault-matrix.sh`'s `gatehouse-killed` row reads the pidfile below to
know what to signal, never a name match). `$!` right after `sudo ... &`
is **not** used here (issue #50): `sudo` does not always exec its child
in place, so `$!` can name sudo's own pid rather than the gatehouse's, a
SIGKILL escalation then kills sudo while the gatehouse keeps running,
and `kill -0` on that stale pid reports success. Instead the pidfile is
written from *inside* the process that becomes the gatehouse, by its own
`$$`, right before `exec` replaces that shell with `ip netns exec`,
which itself execs into the gatehouse binary in place on Linux (same
reasoning as `netns-nat.sh`'s NAT-mode comment) -- so the pid written is
never anyone's monitor or wrapper, it is the pid the gatehouse actually
runs under, start to finish:

```
sudo sh -c "echo \$\$ > crates/mosschat-net/tests/harness/.run/gatehouse.pid; exec ip netns exec internet $MOSSCHAT_BIN gatehouse --bind 203.0.113.1:443 --secondary-bind 203.0.113.1:444 --community $COMMUNITY --members crates/mosschat-net/tests/harness/.run/members.txt"
```

Leave that terminal running. If you get either flag wrong, the
gatehouse's own error text tells you plainly
(`mosschat gatehouse: error: --community <64 hex chars> is required`).

In a second terminal, listen inside house-b for the connection
fault-matrix.sh (or a manual dial) will drive:

```
sudo ip netns exec house-b $SPIKE_BIN listen --bind 10.2.0.2:7777 --advertise 10.2.0.2:7777
```

It prints a ticket starting `moss1...`. Copy it. In a third terminal,
dial from house-a:

```
sudo ip netns exec house-a $SPIKE_BIN dial <the ticket from house-b>
```

This is a direct connection between the two houses' namespaces, not
through the gatehouse (WO-1.3b's doorbell is what would route this
through the gate and prove relay fallback; until `doctor` exists, proving
the relay path specifically means watching the gatehouse's own stdout
counts while a connection is attempted through it, per its design doc
section 1, rather than a single command that reports success or failure).

## The long-lived row command

Every row above dials, measures and exits inside a second or two, which is
enough for a netem loss or delay row and useless for the two rows that need
a connection to still be there a minute later: `blackout-60s` and
`gatehouse-killed`. WO-1.5a added the two halves those rows need, a callee
that stays running and a caller that holds a visit open, so from here the
row command is one `doctor` run rather than a `spike dial`.

**Seeds go in files here, not in variables.** `house` and `doctor` both
take `--identity-file`, a path holding 64 hex characters, rather than the
`--identity <hex>` the spike sections above use, because a seed on a
command line is readable by any local user through `ps`. Write one per
identity before starting anything: house-b's, and one per matrix row (see
"One identity cannot run every row" below). `.run/` is gitignored, and
these files are this run's private keys, so give them 0600 and delete them
with the rest of `.run/` at teardown.

Each identity is made once and used twice: the seed goes in a file for
`house`/`doctor`, and its public key goes in the gate's `members.txt` and,
for a row, in house-b's `friends.txt`. The public key comes from the
binaries rather than being typed: `spike listen` prints
`spike: identity <64 hex>` as soon as it has bound, before it waits for
anything, which is the same trick the spike section above uses. The helper
below runs it outside the namespaces (no root, no `ip netns`), reads that
one line and lets `timeout` end it.

```
RUN=crates/mosschat-net/tests/harness/.run
mkdir -p "$RUN"
umask 077

# $1 = a name. Writes $RUN/$1.seed (0600) and prints that identity's
# public key. The seed is on spike's command line, and so is briefly
# visible in `ps`, exactly as the spike section above already does it;
# these are throwaway harness identities, and the file is what `house`
# and `doctor` read precisely so their seeds are never in argv.
new_identity() {
  seed=$(openssl rand -hex 32)
  printf '%s\n' "$seed" > "$RUN/$1.seed"
  timeout 2 "$SPIKE_BIN" listen --identity "$seed" --bind 127.0.0.1:0 \
    | sed -n 's/^spike: identity //p' | head -1
}

HOUSE_B_PUB=$(new_identity house-b)

# One identity per row. Take the row ids from
# `fault-matrix.sh --help` and list them here; there is no parsing of
# that output, on purpose, so a change to it cannot silently produce
# fewer identities than rows.
ROWS="loss-1pct loss-5pct loss-20pct delay-50ms delay-200ms delay-1000ms reorder duplicate bandwidth-256kbit blackout-60s asymmetric-loss gatehouse-killed"

: > "$RUN/friends.txt"
for row in $ROWS; do
  new_identity "row-$row" >> "$RUN/friends.txt"
done

# The gate seats house-b and every row; house-b answers every row.
cp "$RUN/friends.txt" "$RUN/members.txt"
printf '%s\n' "$HOUSE_B_PUB" >> "$RUN/members.txt"

wc -l "$RUN/friends.txt" "$RUN/members.txt"
awk 'length != 64 { print FILENAME": bad line "NR": "$0; bad=1 } END { exit bad }' \
  "$RUN/friends.txt" "$RUN/members.txt" && echo "both files are 64 hex per line"
```

Check `$ROWS` against `fault-matrix.sh --help` before running it: a row
with no identity of its own falls back to sharing one, which is the thing
"One identity cannot run every row" below exists to stop.
`MemberList::load` reads both files and refuses any non-blank, non-`#`
line that is not exactly 64 hex characters
(`crates/mosschat-net/src/gate/mod.rs`), so a blank line or a stray
placeholder stops the gate or the house at start rather than halfway
through the matrix, which is what the `awk` check above catches first.

**house-b runs the callee**, after those two files exist and after the
gatehouse is up with this `members.txt` (the gate reads it once, at
start, and on `SIGHUP`, so every key goes in before it starts or the
reload does):

```
sudo sh -c "echo \$\$ > crates/mosschat-net/tests/harness/.run/house-b.pid; exec ip netns exec house-b $MOSSCHAT_BIN house --headless --gate 203.0.113.1:443 --community $COMMUNITY --identity-file crates/mosschat-net/tests/harness/.run/house-b.seed --friends crates/mosschat-net/tests/harness/.run/friends.txt" | tee /tmp/house-b.jsonl
```

It prints one line on stderr before anything else saying what its output
contains (addresses, its friends' fingerprints, its own public key), and
then one JSON object per line on stdout.

Same pidfile rule as the gatehouse and the same reason (issue #50): the pid
is written from inside the process that becomes the house, by its own `$$`,
right before `exec`, so it is never sudo's or a wrapper's. Leave that
terminal running; `tee` keeps its stdout, which is one JSON object per line
and the callee's own account of every visit, beside the caller's record.
Its first line names this house's public key, which is what `--friend`
below takes and what the `HOUSE_B_PUB` line above reads:

```
{"detail":"house <64 hex>, gate 203.0.113.1:443, observed 10.2.0.2:51820, secondary port 444","event":"registered","peer":null,"ts_ms":1757362800123}
```

**house-a runs the row**, one seed file per row:

```
sudo bash crates/mosschat-net/tests/harness/fault-matrix.sh -- \
  ip netns exec house-a $MOSSCHAT_BIN doctor \
    --gate 203.0.113.1:443 --community $COMMUNITY \
    --identity-file $RUN/row-blackout-60s.seed \
    --friend $HOUSE_B_PUB --hold 90 --json
```

**Case (e), hole punching forced off**, is the one row that changes both
commands: add `--no-punch` to the `doctor` line above. The flag rides the
candidate exchange, so house-b is told and neither side probes; adding it
to the house as well makes the row's intent obvious in both accounts and
is what the tests cover. Both records then say `punch_disabled`, which is
the result that row is looking for, and neither says a failure.

`--hold 90` is what makes the row a measurement rather than a connect:
after the visit goes live it stays open for 90 seconds, sending section 4's
keepalives, sampling the round trip once a second, and recording every path
event with its timestamp. 90 rather than 60 because the two rows this is
for apply a 60 second fault five seconds in, and a hold that ends with the
fault would measure the fault's start and nothing after it. It is also
above the gate's own 90 second registration expiry by design: nothing sent
frame 9 before WO-1.5a, and a hold that outlives a registration is exactly
how that was found.

Exit codes read differently for a held run, and `fault-matrix.sh` records
them. 0 means the visit went live and every step that *builds* it
succeeded: the gate dial, the registration, the introduction, the relay
session, the peer handshake and the candidate exchange. Non-zero means one
of those failed, or the visit never went live, or it was cut short, and
the message names the step. A row that stayed on the relay for its whole
hold, or upgraded and then lost the path, is a **green** row with a record
that says so: a relayed path is a result WO-1.5 asks for by name, and a
lost path is what `--hold` is for. `--json` puts the whole record on
stdout, which is the row's raw file.

`--hold` takes at most 86400 seconds. A measurement wanting longer wants a
house on both ends rather than a doctor.

**What each row reads out of that record.** All of it is in one JSON object
(`docs/dev/gatehouse-design.md` section 7, plus its amendment 4):

- `path` and `path_addr`: relay or direct, and where the traffic went.
- `rtt_median_us`, `rtt_p95_us`, `rtt_samples`, `rtt_source`: the round trip
  over the hold. `probe` samples are this design's own probe pongs on a
  direct path; `quic` samples are the end to end connection's estimate,
  which is what a relayed visit has; `mixed` means the path changed and the
  events say when.
- `events`: `visit_open`, `upgraded`, `path_stale`, `fell_back`,
  `path_dead`, `recovered`, `goodbye`, each with milliseconds since the
  attempt started. `path_stale` is the detection, `fell_back` is the move
  back to the relay, and the gap between them is what the Phase 1 criterion
  bounds at 1 s on the side that moved. The human report (drop `--json`)
  prints those two gaps on one `path change:` line.
- `steps` and `failed_step`: how the visit connected, unchanged.
- `gate_carried_traffic`, `gate_bytes` and the three shaper counters:
  whether the relay carried this visit and how much.

The house's own stdout carries the same events in the same words from the
other end, so a row that says the caller fell back can be checked against
whether the callee saw the same thing at the same moment.

**Two things this cannot measure yet, stated plainly.** A blackout longer
than 30 seconds kills the connections it is measuring: `max_idle_timeout`
is 30 s on the peer connection (section 4, deliberately) and quinn's
default on the gate connection, so a 60 second blackout ends both, and
nothing redials a gate whose connection is gone. The `blackout-60s` row
therefore measures what dying looks like and what the record says about it,
not a visit that survived; expect the record to end at the fault rather
than after it, and read `events` for when it noticed. And a visit whose
path flaps more than about three times in one hold runs out of the gate's
own budget of 4 `StartRequest`s per session, after which it stays relayed
and the record's `start_signal` step says so.

## Running the fault matrix

`fault-matrix.sh` needs a command to run per row, after `--`. The command
to use is the `doctor --hold` row above; what follows is the older
`spike dial` form, kept because it needs no house and no friend list and
so is the quickest way to check that a namespace pair passes traffic at
all under a row's condition:

```
sudo bash crates/mosschat-net/tests/harness/fault-matrix.sh -- \
  ip netns exec house-a $SPIKE_BIN dial <ticket>
```

A ticket is single-use per spike's own design (the listener answers one
dial and exits), so for a full matrix run you will restart `spike listen`
in house-b between rows, or write a small wrapper script that does that
and pass the wrapper as the command instead. `fault-matrix.sh --help`
lists every row id if you want to run a subset with `--rows`.

### `run-harness.sh matrix` drives a live visit, not a bare dial

**This depends on WO-1.5a (`house --headless`, `doctor --hold` and
`--no-punch`, PR 79 and PR 80), not merged yet, and has not been run.**
Once it lands, `sudo bash run-harness.sh matrix` wraps everything above
into one command, and `blackout-60s` and `gatehouse-killed` measure a
real visit instead of a dial that finished before either fault landed.

It mints 14 identities, not 12: seeds 01 to 13 are the doctor's, one per
doctor run (the unshaped smoke run plus the fault matrix's 12 rows,
exactly the identity-per-row rule below), and seed 14 is house-b's own,
the long-lived callee those two rows need something to still be
connected to. All 14 public keys go in the gate's `members.txt`, as
before; only 01 to 13 go in a `friends.txt` that house-b answers knocks
from.

After the gatehouse is up, `run-harness.sh` starts `house --headless`
inside the `house-b` namespace on its own identity, waits up to 10
seconds for its `registered` line, and reads house-b's public key off
that line by pattern (`house <64 hex>`) rather than typing it anywhere or
assuming which JSON field carries it or where that field falls in the
object, since field order is a `serde_json` implementation detail, not
something this script should depend on. Every row's
command is then `doctor --gate 203.0.113.1:443 --community $MOSS_COMMUNITY
--identity-file <next seed> --friend <house-b's key> --hold 90 --json`
from house-a; the unshaped smoke run is the same command with `--hold 5`.
`fault-matrix.sh` runs with `--row-timeout 240 --blackout-start-delay 10`,
so a 90 second hold with a 60 second blackout starting 10 seconds in
comfortably fits inside the row timeout.

`sudo bash run-harness.sh matrix --relay-only` adds `--no-punch` to both
house-b and every doctor row, the harness equivalent of WO-1.5 case (e):
every visit stays relayed on purpose, and the matrix-setup file says which
mode ran.

`down` stops house-b the same way it stops the gatehouse, by the pid its
own pidfile records, and copies `.run/house-b.jsonl`, the callee's own
account of every visit, to `docs/measurements/<date>-house-b.jsonl` before
teardown deletes `.run`. It also copies both roles' section 7 diagnostics
records out, to `<date>-house-a-records.jsonl` and
`<date>-house-b-records.jsonl`. Each role runs with its own
`XDG_STATE_HOME` under `.run` so the two sides land in two files rather
than interleaved in one, and so they survive teardown at all: run 3 came
down to whether the callee had ever probed, its stdout could not say, and
its records were inside `.run` when teardown ran.

**The unshaped smoke run must reach a direct path**, not merely exit 0.
Exit 0 says the visit went live, which is equally true of a visit that
relayed for its whole hold; run 3 relayed every row, said `probe_timeout`
in every record, and the matrix reported twelve passes. In normal mode a
smoke run that never leaves the relay now stops the matrix and prints the
record's `path`, `reason` and `failed_step`, because measuring how
fall-back degrades under twelve fault conditions is worth nothing until
something has punched once. `MOSS_ALLOW_RELAY_SMOKE=1` runs the matrix
anyway, for the case where the relay behaviour itself is what is being
measured; `--relay-only` skips the check outright, that mode being
relayed on purpose.

**What the copied files contain, before you commit them.** Everything
under `docs/measurements/` goes into a public repository. A run through
this harness is safe by construction: both roles live inside network
namespaces, so every address in a record is 10.1.0.x, 10.2.0.x or
203.0.113.x, a peer is a salted fingerprint and never a key, and no seed
or payload byte is written (section 7's redaction). A run of the same
binaries *outside* the namespaces is not: `local_observed` is then
whatever address your gate reflected, which is your machine's. Read a
record before committing one that did not come from this harness
(Yseult's Info 1 on PR 89).

### One identity cannot run every row

`mosschat doctor` is a real house session: it registers on the gate's
primary port and then reflects off the secondary one, on a second
connection. Section 1 of `docs/dev/gatehouse-design.md` limits `Register`
to **4 connection attempts per key per minute**, and the matrix runs
twelve rows back to back, so pointing every row at one `--identity-file`
runs out of attempts partway through: from the fifth run the registration
is refused, and that run exits 1 with reason `gate_rate_limited` and
`failed_step gate_register`. That is not the row's fault condition, and it
is not netem.

(The `Reflect` cap is 2 **per connection** since amendment 3, and every
run dials its own, so reflections themselves are not what runs out.
Before that amendment it was 2 per key per minute, which is why the
2026-09-08 run also failed at `reflect_secondary` from its third row. The
secondary port has its own 4 connection attempts per key per minute, a
separate bucket, so it runs out at the same fifth run the primary port
does rather than earlier.)

Give each row its own identity (one seed file per row, every one of those
public keys in the gate's members file), or pace the rows at least 60
seconds apart, and say which you did beside the results. The 2026-09-08
run did neither: its rows 3 to 10 ran inside four seconds on one identity
and measured the gate's per-key limits rather than netem, and rows 11 and
12 passed only because the `blackout-60s` row's own 60 second hold had let
the buckets refill.

Every row is bounded by `timeout --kill-after=5 <row-timeout>` (default
180 seconds, `--row-timeout` to change it), and `timeout` kills its
child by pid, not by name. **If a row hangs or you interrupt with
Ctrl-C:** a `trap` on `EXIT`/`INT`/`TERM` resets whatever netem the
current row had applied, and stops the row's command by its recorded
pid (SIGTERM, then SIGKILL after a 2 second grace period if it is still
alive), before the script exits. Nothing is left shaped or running from
a bad row. This applies to every row equally; there is nothing further
to configure per row for it.

The `blackout-60s` row applies loss on **both** `veth-ha` and `veth-hb`
(an earlier version of this script only shaped house-a's own egress,
which left the return direction working and meant the row measured a
dial started into an already-dead link rather than a live connection
surviving an outage). It starts the row's command first, waits 5 seconds
(`--blackout-start-delay` to change it) for a connection to establish
before applying the blackout, holds it for 60 seconds
(`--blackout-hold`), then lifts it and keeps waiting for the command so
it can observe recovery. State that 5 second assumption plainly if your
command's own connection setup is slower than that: increase
`--blackout-start-delay` and say so next to the row's output.

The `gatehouse-killed` row reads `crates/mosschat-net/tests/harness/.run/gatehouse.pid`
(written by the gatehouse-starting step above), sends `SIGTERM` to that
exact pid 5 seconds after the row's command starts, waits up to 2
seconds, escalates to `SIGKILL` if it is still alive, and writes which
one actually worked into the row's own output file. It fails fast with a
clear message if that pidfile does not exist yet.

Each row's output file starts with a header naming the row, its
condition, its pass criterion, the exact command, and (for netem rows) a
`tc qdisc show` captured right after the condition was applied, so the
file is citable evidence on its own rather than bare, unlabelled
command output. The row's own stdin is redirected from `/dev/null`, not
inherited from this script's row-selection loop, so a command that reads
stdin cannot hang waiting on it or silently consume the next row's
input (both were real bugs in an earlier version, PR 48 review).

Each row's raw stdout (and stderr, merged) lands in
`docs/measurements/<today's date>-faults/<row-id>.txt`. When it finishes
it prints a report card, one line per row: condition, verdict, the exit
code, and a plain-English note.

### The report card

Toby is not a network engineer, so the end-of-run table reads as a
report card rather than a bare exit-code list. Each row's own
`<row-id>.txt` (its header plus the doctor's `--json` record, if the row
command was the doctor) is read back into one of four verdicts. Where
more than one could apply to the same row, the precedence is FAIL beats
SUSPECT beats NOT TESTED: an incomplete or wrong-reason record means the
doctor itself misbehaved, and that must never be hidden behind "the
fault did not land".

- **PASS** -- the command exited 0 and the record shows a complete run
  (`failed_step` null, `reason` `ok`, all four gate steps present), and,
  for a row whose fault only lands after a start delay, the doctor was
  still running when it did (see NOT TESTED below). The note is the
  step timing: `dial N ms, register N ms, reflect N ms`.
- **FAIL** -- the command exited non-zero, or the record names a
  `failed_step`. The note names the failed step and the reason in
  words, for example "failed at registering with the gate: the gate
  rate limited this house".
- **SUSPECT** -- exit 0, no `failed_step`, but the record's `reason` is
  not `ok` or it has fewer than four steps (an unrecorded post-dial
  failure, see the 2026-09-08 hewn-mini run below). The note says so.
  Decided before NOT TESTED: a row can only be NOT TESTED once its
  record already looks complete and ok.
- **NOT TESTED** -- only possible for a row whose fault applies after a
  start delay (today: `blackout-60s`, at `--blackout-start-delay`, and
  `gatehouse-killed`, at its fixed 5 s kill delay), and only once the
  record has already cleared the SUSPECT check above. If the record's
  last step finished before that delay elapsed, the fault never landed
  on a live connection, so a PASS there would be exactly the misread
  this card exists to prevent -- caught in PR 78 review, both rows had
  looked like clean passes despite the doctor finishing in a few
  milliseconds, seconds before either fault applied. The note says how
  many ms it took and when the fault would have landed, for example
  "command finished in 4 ms, before the fault was applied at 5 s; needs
  a long-lived command". Both rows need a long-lived row command (a
  visit, not yet built) to mean anything; see each row's own note in
  `docs/measurements/2026-09-08-hewn-mini*/NOTES.md`.

A row whose command was not the doctor, or whose output has no JSON
record at all, gets PASS or FAIL from its exit code alone, noted "no
doctor record in output" -- the card does not assume the row command is
`mosschat doctor --json`.

Every card ends with a totals line, `totals: N PASS, N FAIL, N SUSPECT,
N NOT TESTED`, counting the rows above it. The same card, with the same
totals line, is written to `<output dir>/REPORT.md` as a markdown table
(date, host, the command run, a one-line legend for all four verdicts,
then the rows) every time `fault-matrix.sh` finishes a real run. Every
row's `<row-id>.txt` also gets a trailing `# fault-matrix.sh: exit N`
line so the real exit code survives being read back later.

**`--report-only <dir>`** regenerates and prints this same card from an
existing output directory's `<row-id>.txt` files, without running
anything and without root. It never writes into `<dir>` (no
`REPORT.md`, no edits to the row files), so it is safe to point at
`docs/measurements/2026-09-08-hewn-mini/faults` or
`docs/measurements/2026-09-08-hewn-mini-run2/faults` to see, without a
Linux box, what the report card says about those two runs:

- Run 1: 2 PASS, 9 SUSPECT, 1 NOT TESTED. `blackout-60s` stays SUSPECT
  (the doctor defect described in that run's own NOTES.md, only
  `gate_dial` recorded, fixed by PR 69, still SUSPECT under the FAIL
  beats SUSPECT beats NOT TESTED precedence above, since it never
  cleared the SUSPECT check to begin with); `gatehouse-killed` had a
  complete, ok record and moves out of PASS into NOT TESTED, the doctor
  having finished in a handful of milliseconds, well before its fault
  landed at 5 s.
- Run 2: 10 PASS, 2 NOT TESTED. `blackout-60s` and `gatehouse-killed`
  both had complete, ok records and move out of what was previously 12
  PASS.

Row files written before the `# fault-matrix.sh: exit N` line existed
(both of those) fall back to inferring 0 when the row printed anything
after its header and 1 when it printed nothing at all.

## What to paste back into the repo

Everything under `docs/measurements/<date>-faults/` that `fault-matrix.sh`
just wrote, plus a new file with both `conntrack -L` outputs from the
NAT-mode step above, for example `docs/measurements/<date>-nat-modes.txt`
with a clear heading over each mode's output. Commit these as raw text,
not paraphrased.

**Branch and owner:** commit to this same branch,
`phase-1/wo-1.6-harness`, and push, while PR 48 is still open; if it has
already merged by the time you run this, branch from `main` instead and
open a small follow-up PR that adds only the new files under
`docs/measurements/`. Toby is the owner and committer for this step: it
needs root on a real Linux box, which Wystan does not have, so the
measurements themselves are human-required evidence, not something an
agent produced or can vouch for.

## Tearing down

```
sudo bash crates/mosschat-net/tests/harness/teardown.sh
```

Safe to run even if setup only partly completed, or was already torn
down. It removes the five namespaces and everything inside them (veths,
the bridge, the nftables tables) and this harness's own `.run/`
directory (pidfiles, the members file). Verify it actually worked:

```
ip netns list | grep -E '^(house-a|nat-a|house-b|nat-b|internet)( |$)' && echo STILL PRESENT || echo clean
```

If `fault-matrix.sh` was interrupted mid-row before you ran teardown, its
own trap already reset the qdisc it had applied and stopped the row's
process by pid before it exited, so there is nothing left over from it
either; `teardown.sh` deleting the namespaces afterward covers the rest.

## Known gaps, stated plainly

- The doorbell is drivable from the command line now (`doctor --hold`
  against a `house --headless`), so `punch.rs`'s symmetric-NAT fallback
  and PLAN WO-1.6's "endpoint-dependent case forces the relay path inside
  WO-1.3's stated deadline" verification line can be proved by this
  harness. What it still cannot prove is a visit surviving a fault longer
  than 30 seconds: both connections carry a 30 s idle timeout and nothing
  redials a gate whose connection is gone, so the `blackout-60s` row
  measures what dying looks like rather than a survived outage. Stated in
  full under "The long-lived row command".
- The `edm` mode's nftables rule (`snat ... random`) does not pick a
  literal fresh random port on every new conntrack entry; corrected in
  netns-nat.sh's own comment after PR 48 review (Konrad): the kernel
  seeds its port search from a hash over source address, destination
  address and destination port when `random` is set, which is RFC
  4787's definition of endpoint-dependent mapping, not per-entry
  randomness. Two flows to the same destination tend to land on the same
  external port while it stays free; two flows to different destinations
  do not. That is the property the conntrack check above actually
  observes, and it is a real, if strict, endpoint-dependent NAT, not an
  artificially harsher one.
