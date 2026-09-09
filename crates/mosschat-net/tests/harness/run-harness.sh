#!/usr/bin/env bash
# MossChat Phase 1 harness runner, one command per phase. Run as root:
#   sudo bash run-harness.sh nat      # EIM + EDM conntrack proof, tears down after each
#   sudo bash run-harness.sh matrix [--relay-only]  # community, gatehouse,
#                                    # house-b, doctor smoke, fault matrix.
#                                    # --relay-only adds --no-punch to both
#                                    # the house and every doctor row.
#   sudo bash run-harness.sh capture  # community, gatehouse, house-b, one
#                                    # doctor row (--hold 20), tcpdump on
#                                    # both NATs' outward interfaces and both
#                                    # houses' interfaces, a mid-hold
#                                    # conntrack/nft/ip snapshot, then its own
#                                    # teardown. Self-contained: do not run
#                                    # `down` after it, and do not run it
#                                    # while `matrix` or `nat` is up (issue 88).
#   sudo bash run-harness.sh down     # teardown only (namespaces, veths, nft)
# Wraps netns-nat.sh, fault-matrix.sh and teardown.sh in this directory;
# adds nothing to them. Output goes under <repo root>/docs/measurements/.
# Binaries: $MOSSCHAT_BIN and $SPIKE_BIN if set, else <repo root>/mosschat
# and <repo root>/spike (the layout a prebuilt CI artifact is dropped into
# on a test box with no toolchain). A symlink to this script from the repo
# root works: the path is resolved through readlink.
set -u
H="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
ROOT="$(cd "$H/../../../.." && pwd)"
export MOSSCHAT_BIN="${MOSSCHAT_BIN:-$ROOT/mosschat}"
export SPIKE_BIN="${SPIKE_BIN:-$ROOT/spike}"
OUT="$ROOT/docs/measurements"
RUN="$H/.run"
DATE_TAG="$(date -u +%F)"
mkdir -p "$OUT" "$RUN"
# Everything this script prints also goes to run.log so it can be read
# back over ssh without anyone pasting terminal output. The per-row
# `row` invocation is exempt: fault-matrix.sh captures its output itself.
if [ "${1:-}" != row ]; then
  exec > >(tee -a "$OUT/run.log") 2>&1
  echo; echo "#### $(date -u +%FT%TZ) run-harness.sh ${1:-}"
fi

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 2; }
[ -x "$MOSSCHAT_BIN" ] && [ -x "$SPIKE_BIN" ] || { echo "binaries missing under $ROOT"; exit 2; }

say(){ echo; echo "== $*"; }

# One NAT-mode proof: bring the namespaces up, send two probes from the
# same house-a source port to two gate ports, read nat-a's conntrack table
# while the entries are still alive (30 s UDP timeout, issue 52), tear down.
nat_proof(){
  local mode="$1"
  local f="$OUT/${DATE_TAG}-nat-${mode}.txt"
  say "netns-nat.sh --mode $mode"
  bash "$H/netns-nat.sh" --mode "$mode" || { echo "netns-nat.sh failed"; return 1; }
  {
    echo "# hewn-mini $(uname -r) $(date -u +%FT%TZ) mode=$mode"
    echo "# probes: house-a 10.1.0.2:55555 -> 203.0.113.1:443 and :444"
    printf 'x' | ip netns exec house-a socat -T 2 - UDP-DATAGRAM:203.0.113.1:443,bind=10.1.0.2:55555
    printf 'x' | ip netns exec house-a socat -T 2 - UDP-DATAGRAM:203.0.113.1:444,bind=10.1.0.2:55555
    echo "# conntrack -L -n -s 10.1.0.2  (nat-a)"
    ip netns exec nat-a conntrack -L -n -s 10.1.0.2 2>&1
    echo "# nft ruleset (nat-a)"
    ip netns exec nat-a nft list ruleset
  } | tee "$f"
  say "wrote $f; tearing down"
  bash "$H/teardown.sh"
}

stop_gatehouse(){
  local pid
  pid="$(cat "$RUN/gatehouse.pid" 2>/dev/null)" || return 0
  if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q gatehouse; then
    echo "stopping gatehouse pid $pid"; kill -TERM "$pid" 2>/dev/null; sleep 1
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null
  fi
  rm -f "$RUN/gatehouse.pid"
}

# Same pidfile rule as stop_gatehouse and the same reason (issue #50):
# house-b's pid is written from inside the process itself, so this is
# never sudo's or a wrapper's pid.
stop_house(){
  local pid
  pid="$(cat "$RUN/house-b.pid" 2>/dev/null)" || return 0
  if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q 'house --headless'; then
    echo "stopping house-b pid $pid"; kill -TERM "$pid" 2>/dev/null; sleep 1
    kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null
  fi
  rm -f "$RUN/house-b.pid"
}

# capture()'s four tcpdumps. Same pidfile rule as the gatehouse and
# house-b above, and the same reason (issue #50): the pid is written from
# inside the process that becomes tcpdump, by its own `$$`, right before
# `exec`, so it is never a wrapper's. `-U` makes tcpdump flush each packet
# to the savefile as it is written (packet-buffered) rather than holding
# it in its own internal buffer -- without it, a TERM (or, worse, a KILL)
# before tcpdump's own buffer fills can leave a 24 byte file (pcap header,
# zero packets) even though traffic crossed the interface the whole time
# (found live, run 2).
start_tcpdump(){
  local ns="$1" iface="$2" out="$3" tag="$4"
  say "tcpdump on $iface in $ns -> $out"
  sh -c "echo \$\$ > $RUN/tcpdump-$tag.pid; exec ip netns exec $ns tcpdump -U -n -i $iface -w $out udp" \
    >"$RUN/tcpdump-$tag.log" 2>&1 &
}

# TERM, then actually wait for the pid to be gone (bounded at 5 s, half
# second steps) before ever escalating to KILL -- a KILL can cut tcpdump
# off before it finishes flushing `-U`'s per-packet writes, the same
# empty-pcap failure `-U` alone does not fully rule out under a dead-set
# SIGKILL (found live, run 2; the previous version here only slept a
# flat 1 s and did not confirm the process was actually gone before it
# moved on).
stop_tcpdump(){
  local tag="$1" pid waited
  pid="$(cat "$RUN/tcpdump-$tag.pid" 2>/dev/null)" || return 0
  if [ -n "$pid" ] && [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q tcpdump; then
    echo "stopping tcpdump $tag pid $pid"; kill -TERM "$pid" 2>/dev/null
    waited=0
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 10 ]; do
      sleep 0.5
      waited=$((waited + 1))
    done
    kill -0 "$pid" 2>/dev/null && { echo "tcpdump $tag did not exit in 5s, sending KILL"; kill -KILL "$pid" 2>/dev/null; }
  fi
  rm -f "$RUN/tcpdump-$tag.pid"
}

stop_tcpdumps(){
  local tag
  for tag in nat-a nat-b house-a house-b; do
    stop_tcpdump "$tag"
  done
}

# Copies house-b's own event log out of .run before `down` calls
# teardown.sh, which deletes .run, so the callee's account of the matrix
# survives (README, "The long-lived row command").
save_house_log(){
  [ -f "$RUN/house-b.jsonl" ] || return 0
  local dest="$OUT/${DATE_TAG}-house-b.jsonl"
  cp "$RUN/house-b.jsonl" "$dest"
  echo "wrote $dest"
}

# The same for both roles' section 7 diagnostics records, which are the
# only place a callee's own view of a visit exists.
#
# Run 3 needed exactly this and did not have it: house-b's stdout showed a
# visit open and then nothing, and the one thing that would have said
# whether it ever probed -- its own `start_signal` and `probe_burst` steps
# -- was inside .run, which teardown.sh deletes. Each role gets its own
# XDG_STATE_HOME (see matrix() and row()) so the two sides' records land in
# two files rather than interleaved in one.
save_records(){
  local role dir dest
  for role in house-a house-b; do
    dir="$RUN/state-$role/mosschat/diagnostics"
    [ -d "$dir" ] || continue
    # Globbed into a variable first, and the redirect only after there is
    # something to write: `cat "$dir"/*.jsonl > "$dest"` creates $dest
    # before cat runs, so a role with no records left a zero byte file and
    # no line saying so (Yseult's Info 2).
    set -- "$dir"/*.jsonl
    [ -f "$1" ] || { echo "no records under $dir"; continue; }
    dest="$OUT/${DATE_TAG}-$role-records.jsonl"
    cat "$@" > "$dest"
    echo "wrote $dest ($(wc -l < "$dest") records)"
  done
}

# Read a fixed identity's public key off a short-lived spike listen
# (nothing else derives a public key from a seed on the command line).
pub_of(){
  local ns="$1" seed="$2" bind="$3" tag="$4" pid i
  local log="$RUN/spike-id-$tag.log"
  sh -c "echo \$\$ > $RUN/spike-id-$tag.pid; exec ip netns exec $ns $SPIKE_BIN listen --identity $seed --bind $bind" >"$log" 2>&1 &
  for i in 1 2 3 4 5 6 7 8 9 10; do grep -q 'spike: identity' "$log" 2>/dev/null && break; sleep 0.2; done
  pid="$(cat "$RUN/spike-id-$tag.pid")"
  [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q spike && kill -TERM "$pid" 2>/dev/null
  wait
  grep -m1 'spike: identity' "$log" | awk '{print $3}'
}

# The gate rate limits Register (4 connection attempts per key per minute)
# and Reflect (2 per minute) per key, so twelve back-to-back rows on one
# identity measure those limits, not netem (README, "One identity cannot
# run every row"). Every doctor run therefore gets its own identity:
# SEEDS seeds are minted up front, every public key goes in the members
# file before the gatehouse starts, and `row` takes the next unused one.
#
# Identity SEEDS is not a doctor identity: it is house-b's own, the
# long-lived callee every row's doctor visits. Seeds 01 to DOCTOR_SEEDS
# are the doctor's, one per doctor run. matrix() and capture() each
# export both of these (to 14/13 and 3/2 respectively) right before
# calling setup_eim(), so the fresh `bash run-harness.sh row` process
# each row's DOCTOR command starts inherits them -- but only if the
# lines below respect an inherited value rather than overwrite it: an
# unconditional `SEEDS=14` here would run again in that fresh process
# too (every invocation of this script reaches this point, `row`
# included) and silently stomp the export right back to 14/13. That
# does not break anything a single row can observe on its own (1 or 2
# is always <= 13), so it went unnoticed until traced end to end; fixed
# by only defaulting when unset.
SEEDS="${SEEDS:-14}"
DOCTOR_SEEDS="${DOCTOR_SEEDS:-$((SEEDS - 1))}"
next_seed(){
  local n
  n="$(cat "$RUN/seed-next" 2>/dev/null || echo 1)"
  [ "$n" -le "$DOCTOR_SEEDS" ] || { echo "run-harness.sh: all $DOCTOR_SEEDS doctor identities used" >&2; return 1; }
  echo $((n+1)) > "$RUN/seed-next"
  printf '%02d' "$n"
}

# Shared by matrix() and capture(): brings up the eim topology, mints
# $1 identities (the last one is house-b's own; the rest are doctor
# seeds, taken in order by next_seed()), builds members.txt and
# friends.txt, starts the gatehouse and starts house-b headless.
# Transcript goes to $2. $3 is relay_only (0 or 1), same meaning as
# matrix's own flag. Callers set SEEDS and DOCTOR_SEEDS (next_seed()'s
# existing contract) before calling this. Exports MOSS_COMMUNITY,
# MOSS_RUN, MOSS_RELAY_ONLY and MOSS_HOUSE_B for row(), same as matrix()
# always has.
setup_eim(){
  local total="$1" f="$2" relay_only="${3:-0}"
  say "netns-nat.sh --mode eim (left up for this run)"
  bash "$H/netns-nat.sh" --mode eim || { echo "netns-nat.sh failed"; return 1; }

  say "community, $total identities ($((total - 1)) doctor, 1 house-b), members, friends"
  local COMMUNITY seed pub tag
  COMMUNITY="$(openssl rand -hex 32)"
  mkdir -p "$RUN/seeds"; : > "$RUN/members.txt"; echo 1 > "$RUN/seed-next"
  for tag in $(seq -f '%02g' 1 "$total"); do
    seed="$(openssl rand -hex 32)"
    ( umask 077; echo "$seed" > "$RUN/seeds/$tag.seed" )
    pub="$(pub_of house-a "$seed" 10.1.0.2:7777 "$tag")"
    [ ${#pub} -eq 64 ] || { echo "could not read public key $tag off spike; see $RUN/spike-id-$tag.log"; return 1; }
    echo "$pub" >> "$RUN/members.txt"
  done
  # house-b's own key (tag $total, the last line of members.txt) does not
  # go in its own friends file; friends.txt is who house-b answers a
  # knock from, seeds 01 to $((total - 1)), in the same order they were
  # just written.
  head -n "$((total - 1))" "$RUN/members.txt" > "$RUN/friends.txt"
  {
    echo "# hewn-mini $(uname -r) $(date -u +%FT%TZ)"
    echo "community: $COMMUNITY"
    if [ "$relay_only" -eq 1 ]; then
      echo "mode: relay-only (--no-punch on house-b and every doctor row)"
    else
      echo "mode: normal (punching allowed)"
    fi
    echo "identities: $total total; $((total - 1)) for doctor runs, one identity each, in" \
      "$RUN/seeds; identity $total is house-b's own; public keys:"
    cat "$RUN/members.txt"
  } | tee "$f"
  export MOSS_COMMUNITY="$COMMUNITY" MOSS_RUN="$RUN" MOSS_RELAY_ONLY="$relay_only"

  say "gatehouse in the internet namespace (log: $RUN/gatehouse.log)"
  sh -c "echo \$\$ > $RUN/gatehouse.pid; exec ip netns exec internet $MOSSCHAT_BIN gatehouse --bind 203.0.113.1:443 --secondary-bind 203.0.113.1:444 --community $COMMUNITY --members $RUN/members.txt" >"$RUN/gatehouse.log" 2>&1 &
  sleep 2
  grep -q 'mosschat gatehouse: community=' "$RUN/gatehouse.log" || { echo "gatehouse did not start:"; cat "$RUN/gatehouse.log"; return 1; }
  cat "$RUN/gatehouse.log"

  # house-b, headless, in its own namespace, bound to 10.2.0.2 by that
  # namespace's own routing (house takes no --bind flag of its own): the
  # long-lived callee `blackout-60s` and `gatehouse-killed` need a real
  # visit to still be open when their fault lands. Same pidfile-from-
  # inside-the-process shape as the gatehouse above, same reason (issue
  # #50). stdout (one JSON event per line) goes to house-b.jsonl; stderr
  # (the privacy notice) goes to its own log so the first stdout line is
  # always the "registered" event.
  local house_no_punch=""
  [ "$relay_only" -eq 1 ] && house_no_punch=" --no-punch"
  say "house-b in its own namespace, headless (log: $RUN/house-b.jsonl)"
  mkdir -p "$RUN/state-house-a" "$RUN/state-house-b"
  # Seed files are named by the same %02d padding next_seed() and the
  # minting loop above both use (01.seed, 02.seed, ...), so house-b's own
  # tag (the last one minted, plain $total here) has to be padded the
  # same way -- matrix() only worked by coincidence, because 14 prints
  # identically either way; capture()'s 3 does not (found live, run 1).
  local total_tag
  total_tag="$(printf '%02d' "$total")"
  sh -c "echo \$\$ > $RUN/house-b.pid; XDG_STATE_HOME=$RUN/state-house-b exec ip netns exec house-b $MOSSCHAT_BIN house --headless --gate 203.0.113.1:443 --community $COMMUNITY --identity-file $RUN/seeds/$total_tag.seed --friends $RUN/friends.txt$house_no_punch" >"$RUN/house-b.jsonl" 2>"$RUN/house-b.stderr.log" &

  local i
  # 50 x 0.2s = 10s, bounded.
  for i in $(seq 1 50); do
    grep -q '"event":"registered"' "$RUN/house-b.jsonl" 2>/dev/null && break
    sleep 0.2
  done
  grep -q '"event":"registered"' "$RUN/house-b.jsonl" 2>/dev/null || {
    echo "house-b did not register within 10s. stdout:"; cat "$RUN/house-b.jsonl" 2>/dev/null
    echo "stderr:"; cat "$RUN/house-b.stderr.log" 2>/dev/null
    return 1
  }
  # By pattern, not by field position: the "house <64 hex>" text is
  # inside the registered line's "detail" value today, but which key that
  # is and where it falls in the object is a serde_json implementation
  # detail (its default map happens to sort alphabetically; that changes
  # the moment a preserve_order feature or a struct field does), so this
  # greps the line as text rather than assuming a field order.
  local MOSS_HOUSE_B
  MOSS_HOUSE_B="$(grep -m1 '"event":"registered"' "$RUN/house-b.jsonl" | grep -o 'house [0-9a-f]\{64\}' | head -1 | cut -d' ' -f2)"
  [ -n "$MOSS_HOUSE_B" ] && [ "${#MOSS_HOUSE_B}" -eq 64 ] || { echo "could not read house-b's public key off its registered line:"; cat "$RUN/house-b.jsonl"; return 1; }
  echo "house-b public key: $MOSS_HOUSE_B" | tee -a "$f"
  export MOSS_HOUSE_B
}

matrix(){
  local relay_only=0
  [ "${1:-}" = "--relay-only" ] && relay_only=1
  local f="$OUT/${DATE_TAG}-matrix-setup.txt"
  trap 'stop_house; stop_gatehouse' EXIT INT TERM
  export SEEDS=14
  export DOCTOR_SEEDS=$((SEEDS - 1))
  setup_eim "$SEEDS" "$f" "$relay_only" || return 1

  # Per-row command: house-a's doctor visiting house-b and holding the
  # visit open (README, "The long-lived row command"). MOSS_HOLD sets how
  # long; row() defaults to 90 if it is unset, which is what a plain
  # `run-harness.sh row` outside the matrix gets.
  local DOCTOR=(bash "$H/run-harness.sh" row)

  say "doctor smoke run, unshaped, hold 5s"
  local smoke="$RUN/smoke.json"
  MOSS_HOLD=5 "${DOCTOR[@]}" | tee "$smoke" | tee -a "$f"; local rc="${PIPESTATUS[0]}"
  echo "doctor exit: $rc" | tee -a "$f"
  [ "$rc" -eq 0 ] || { echo "doctor failed unshaped; not running the matrix. gatehouse log:"; cat "$RUN/gatehouse.log"; return 1; }

  # **The smoke run has to prove a direct path, not just exit 0** (run 3,
  # issue 84). Exit 0 means the visit went live, which a visit that relayed
  # for its whole hold also did: run 3 relayed all twelve rows, reported
  # `probe_timeout` in every record, and the matrix called it a pass,
  # because nothing here ever looked at the path. In normal mode the smoke
  # run's whole job is to say the lab can punch before 25 minutes are spent
  # measuring how it degrades, so a relayed smoke run stops here and prints
  # the record that says so.
  if [ "$relay_only" -eq 0 ] && ! grep -q '"path":"direct"' "$smoke"; then
    echo
    echo "run-harness.sh: the unshaped smoke run never left the relay, so every matrix row"
    echo "run-harness.sh: would measure fall-back behaviour and none would measure a direct"
    echo "run-harness.sh: path. Its record:"
    grep -o '"path":"[^"]*"\|"reason":"[^"]*"\|"failed_step":[^,]*' "$smoke" | sed 's/^/run-harness.sh:   /'
    echo "run-harness.sh: to run the matrix anyway, set MOSS_ALLOW_RELAY_SMOKE=1."
    [ "${MOSS_ALLOW_RELAY_SMOKE:-0}" = "1" ] || return 1
    echo "run-harness.sh: MOSS_ALLOW_RELAY_SMOKE=1, continuing on the relay."
  fi

  say "fault matrix (12 rows, each on its own identity, hold 90s; blackout starts 10s in" \
    "and holds 60s, --row-timeout 240s)"
  MOSS_HOLD=90 bash "$H/fault-matrix.sh" --row-timeout 240 --blackout-start-delay 10 -- "${DOCTOR[@]}"
  echo "matrix exit: $?" | tee -a "$f"
  say "gatehouse log after the matrix"; cat "$RUN/gatehouse.log" | tee -a "$f"
  say "done. Results: $OUT/${DATE_TAG}-faults/  Now run:  sudo bash $ROOT/run-harness.sh down"
}

row(){
  local tag hold="${MOSS_HOLD:-90}"
  local -a flags=()
  tag="$(next_seed)" || exit 2
  echo "# identity $tag"
  [ "${MOSS_RELAY_ONLY:-0}" = "1" ] && flags=(--no-punch)
  XDG_STATE_HOME="$MOSS_RUN/state-house-a" exec ip netns exec house-a "$MOSSCHAT_BIN" doctor --gate 203.0.113.1:443 --community "$MOSS_COMMUNITY" --identity-file "$MOSS_RUN/seeds/$tag.seed" --friend "$MOSS_HOUSE_B" --hold "$hold" --json "${flags[@]}"
}

# Issue 88: both houses behind EIM masquerade NAT probe each other's
# gate-reflected address and neither probe is ever answered. This answers
# the two questions that decide it: does an 81 byte probe datagram leave
# each NAT for the peer's reflected address, and does the reply tuple's
# port in conntrack match the port the gate reflected. Self-contained:
# brings its own topology up and tears it down, so do not run `down`
# after it and do not run it while `matrix` or `nat` already has the
# namespaces up.
capture(){
  command -v tcpdump >/dev/null 2>&1 || {
    echo "capture needs tcpdump: sudo apt install tcpdump"
    return 2
  }
  local f="$OUT/${DATE_TAG}-capture-setup.txt"
  local capdir="$OUT/${DATE_TAG}-capture"
  mkdir -p "$capdir"
  # Tears down fully on every exit path, not just the happy one: a run
  # that fails partway through setup_eim (e.g. house-b never registers)
  # used to only stop the two processes here and leave the five
  # namespaces up, breaking the "self-contained" promise below and
  # needing a manual `down` (found live, run 1). teardown.sh is
  # idempotent, so running it from here as well as, previously, again
  # explicitly at the end was always safe; it is now the only place this
  # runs, so success and failure tear down exactly the same way.
  trap 'stop_tcpdumps; stop_house; stop_gatehouse; bash "$H/teardown.sh"' EXIT INT TERM

  # 2 doctor seeds (only one row runs, but next_seed() takes the contract
  # from matrix() as given -- see the SEEDS/DOCTOR_SEEDS comment above)
  # plus house-b's own, matching the work order's "2 doctor seeds plus
  # house-b".
  export SEEDS=3
  export DOCTOR_SEEDS=2
  setup_eim "$SEEDS" "$f" 0 || return 1

  say "four tcpdumps: both NATs' outward interfaces and both houses'"
  start_tcpdump nat-a veth-na-out "$capdir/nat-a.pcap" nat-a
  start_tcpdump nat-b veth-nb-out "$capdir/nat-b.pcap" nat-b
  start_tcpdump house-a veth-ha "$capdir/house-a.pcap" house-a
  start_tcpdump house-b veth-hb "$capdir/house-b.pcap" house-b
  sleep 1

  # Stdout and stderr to two separate files: `doctor --json` prints the
  # record's one JSON line on stdout and the privacy notice (or, if
  # something fails before that, the actual error) on stderr
  # (print_record and the `mosschat doctor: error: {err}` wrapper,
  # main.rs), and doctor.json has to stay exactly the JSON line for the
  # grep below and for whoever reads it back. The previous version left
  # stderr unredirected, so a row that failed before printing anything
  # left doctor.json holding only row()'s own "# identity NN" line with
  # the actual reason nowhere in the results directory (found live, run
  # 2) -- captured now, and printed in the summary below either way.
  say "doctor row from house-a, hold 20s (log: $capdir/doctor.json, stderr: $capdir/doctor.stderr.txt)"
  MOSS_HOLD=20 bash "$H/run-harness.sh" row >"$capdir/doctor.json" 2>"$capdir/doctor.stderr.txt" &
  local doctor_pid=$!

  sleep 10
  say "mid-hold snapshot at ~10s: conntrack, nft ruleset, ip state in all five namespaces"
  {
    echo "# conntrack -L -n (nat-a) $(date -u +%FT%TZ)"
    ip netns exec nat-a conntrack -L -n 2>&1
  } >"$capdir/conntrack-nat-a.txt"
  {
    echo "# conntrack -L -n (nat-b) $(date -u +%FT%TZ)"
    ip netns exec nat-b conntrack -L -n 2>&1
  } >"$capdir/conntrack-nat-b.txt"
  ip netns exec nat-a nft list ruleset >"$capdir/nft-nat-a.txt" 2>&1
  ip netns exec nat-b nft list ruleset >"$capdir/nft-nat-b.txt" 2>&1
  {
    local ns
    for ns in house-a nat-a house-b nat-b internet; do
      echo "# $ns: ip -j addr"
      ip netns exec "$ns" ip -j addr 2>&1
      echo "# $ns: ip route"
      ip netns exec "$ns" ip route 2>&1
      echo
    done
  } >"$capdir/netns-state.txt"

  say "waiting for the doctor's 20s hold to finish"
  wait "$doctor_pid"
  local doctor_rc=$?
  echo "doctor exit: $doctor_rc" | tee -a "$f"

  say "stopping the four tcpdumps"
  stop_tcpdumps

  # Before teardown removes .run: house-b's log and diagnostics records
  # (as before), plus the gatehouse's and house-b's own logs, which
  # otherwise only ever existed under .run (found live, run 2 needed
  # house-b's registration line and the gatehouse's own output to rule
  # out a gate-side cause).
  say "copying house-b's log, the gatehouse and house-b logs, and both roles' diagnostics records"
  cp "$RUN/house-b.jsonl" "$capdir/house-b.jsonl" 2>/dev/null || echo "no $RUN/house-b.jsonl"
  cp "$RUN/gatehouse.log" "$capdir/gatehouse.log" 2>/dev/null || echo "no $RUN/gatehouse.log"
  cp "$RUN/house-b.stderr.log" "$capdir/house-b.stderr.log" 2>/dev/null || echo "no $RUN/house-b.stderr.log"
  save_records
  local role
  for role in house-a house-b; do
    [ -f "$OUT/${DATE_TAG}-$role-records.jsonl" ] && cp "$OUT/${DATE_TAG}-$role-records.jsonl" "$capdir/"
  done

  say "summary: packet counts and probe traffic in each pcap (udp, excluding the gate's" \
    "ports 443 and 444) -- a pcap at 24 bytes is the header alone, zero packets captured"
  local pcap
  for pcap in nat-a nat-b house-a house-b; do
    echo "-- $capdir/$pcap.pcap ($(wc -c <"$capdir/$pcap.pcap" 2>/dev/null || echo 0) bytes," \
      "$(tcpdump -n -r "$capdir/$pcap.pcap" 2>/dev/null | wc -l) packets) --"
    tcpdump -n -r "$capdir/$pcap.pcap" 'udp and not port 443 and not port 444' 2>/dev/null | head -40
  done

  say "doctor record: candidate_exchange and probe_burst"
  grep -o '"step":"candidate_exchange"[^}]*}' "$capdir/doctor.json" 2>/dev/null
  grep -o '"step":"probe_burst"[^}]*}' "$capdir/doctor.json" 2>/dev/null

  say "doctor stderr"
  cat "$capdir/doctor.stderr.txt" 2>/dev/null

  say "capture is self-contained: the EXIT trap now stops house-b, the gatehouse and" \
    "tears down"
  say "done. Results: $capdir"
  return "$doctor_rc"
}

case "${1:-}" in
  row)     row ;;
  nat)     nat_proof eim && nat_proof edm ;;
  matrix)  matrix "${2:-}" ;;
  capture) capture ;;
  down)    stop_house; stop_gatehouse; save_house_log; save_records; bash "$H/teardown.sh" ;;
  *)       sed -n 2,16p "$(readlink -f "$0")"; exit 2 ;;
esac
