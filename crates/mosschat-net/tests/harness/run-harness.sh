#!/usr/bin/env bash
# MossChat Phase 1 harness runner, one command per phase. Run as root:
#   sudo bash run-harness.sh nat      # EIM + EDM conntrack proof, tears down after each
#   sudo bash run-harness.sh matrix [--relay-only]  # community, gatehouse,
#                                    # house-b, doctor smoke, fault matrix.
#                                    # --relay-only adds --no-punch to both
#                                    # the house and every doctor row.
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

# Copies house-b's own event log out of .run before `down` calls
# teardown.sh, which deletes .run, so the callee's account of the matrix
# survives (README, "The long-lived row command").
save_house_log(){
  [ -f "$RUN/house-b.jsonl" ] || return 0
  local dest="$OUT/${DATE_TAG}-house-b.jsonl"
  cp "$RUN/house-b.jsonl" "$dest"
  echo "wrote $dest"
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
# Identity SEEDS (14) is not a doctor identity: it is house-b's own, the
# long-lived callee every row's doctor visits. Seeds 01 to DOCTOR_SEEDS
# (13) are the doctor's, one per doctor run -- the smoke run plus the
# fault matrix's 12 rows.
SEEDS=14
DOCTOR_SEEDS=$((SEEDS - 1))
next_seed(){
  local n
  n="$(cat "$RUN/seed-next" 2>/dev/null || echo 1)"
  [ "$n" -le "$DOCTOR_SEEDS" ] || { echo "run-harness.sh: all $DOCTOR_SEEDS doctor identities used" >&2; return 1; }
  echo $((n+1)) > "$RUN/seed-next"
  printf '%02d' "$n"
}

matrix(){
  local relay_only=0
  [ "${1:-}" = "--relay-only" ] && relay_only=1
  local f="$OUT/${DATE_TAG}-matrix-setup.txt"
  trap 'stop_house; stop_gatehouse' EXIT INT TERM
  say "netns-nat.sh --mode eim (left up for the matrix)"
  bash "$H/netns-nat.sh" --mode eim || { echo "netns-nat.sh failed"; return 1; }

  say "community, $SEEDS identities ($DOCTOR_SEEDS doctor, 1 house-b), members, friends"
  local COMMUNITY seed pub tag
  COMMUNITY="$(openssl rand -hex 32)"
  mkdir -p "$RUN/seeds"; : > "$RUN/members.txt"; echo 1 > "$RUN/seed-next"
  for tag in $(seq -f '%02g' 1 "$SEEDS"); do
    seed="$(openssl rand -hex 32)"
    ( umask 077; echo "$seed" > "$RUN/seeds/$tag.seed" )
    pub="$(pub_of house-a "$seed" 10.1.0.2:7777 "$tag")"
    [ ${#pub} -eq 64 ] || { echo "could not read public key $tag off spike; see $RUN/spike-id-$tag.log"; return 1; }
    echo "$pub" >> "$RUN/members.txt"
  done
  # house-b's own key (tag $SEEDS, the last line of members.txt) does not
  # go in its own friends file; friends.txt is who house-b answers a
  # knock from, seeds 01 to $DOCTOR_SEEDS, in the same order they were
  # just written.
  head -n "$DOCTOR_SEEDS" "$RUN/members.txt" > "$RUN/friends.txt"
  {
    echo "# hewn-mini $(uname -r) $(date -u +%FT%TZ)"
    echo "community: $COMMUNITY"
    if [ "$relay_only" -eq 1 ]; then
      echo "mode: relay-only (--no-punch on house-b and every doctor row)"
    else
      echo "mode: normal (punching allowed)"
    fi
    echo "identities: $SEEDS total; $DOCTOR_SEEDS for doctor runs (smoke run plus the 12" \
      "matrix rows, one identity each, in $RUN/seeds), identity $SEEDS is house-b's own;" \
      "public keys:"
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
  sh -c "echo \$\$ > $RUN/house-b.pid; exec ip netns exec house-b $MOSSCHAT_BIN house --headless --gate 203.0.113.1:443 --community $COMMUNITY --identity-file $RUN/seeds/$SEEDS.seed --friends $RUN/friends.txt$house_no_punch" >"$RUN/house-b.jsonl" 2>"$RUN/house-b.stderr.log" &

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
  local MOSS_HOUSE_B
  MOSS_HOUSE_B="$(grep -m1 '"event":"registered"' "$RUN/house-b.jsonl" | grep -oE '"detail":"house [0-9a-f]{64}' | grep -oE '[0-9a-f]{64}')"
  [ ${#MOSS_HOUSE_B} -eq 64 ] || { echo "could not read house-b's public key off its registered line:"; cat "$RUN/house-b.jsonl"; return 1; }
  echo "house-b public key: $MOSS_HOUSE_B" | tee -a "$f"
  export MOSS_HOUSE_B

  # Per-row command: house-a's doctor visiting house-b and holding the
  # visit open (README, "The long-lived row command"). MOSS_HOLD sets how
  # long; row() defaults to 90 if it is unset, which is what a plain
  # `run-harness.sh row` outside the matrix gets.
  local DOCTOR=(bash "$H/run-harness.sh" row)

  say "doctor smoke run, unshaped, hold 5s"
  MOSS_HOLD=5 "${DOCTOR[@]}" | tee -a "$f"; local rc="${PIPESTATUS[0]}"
  echo "doctor exit: $rc" | tee -a "$f"
  [ "$rc" -eq 0 ] || { echo "doctor failed unshaped; not running the matrix. gatehouse log:"; cat "$RUN/gatehouse.log"; return 1; }

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
  exec ip netns exec house-a "$MOSSCHAT_BIN" doctor --gate 203.0.113.1:443 --community "$MOSS_COMMUNITY" --identity-file "$MOSS_RUN/seeds/$tag.seed" --friend "$MOSS_HOUSE_B" --hold "$hold" --json "${flags[@]}"
}

case "${1:-}" in
  row)    row ;;
  nat)    nat_proof eim && nat_proof edm ;;
  matrix) matrix "${2:-}" ;;
  down)   stop_house; stop_gatehouse; save_house_log; bash "$H/teardown.sh" ;;
  *)      sed -n 2,8p "$(readlink -f "$0")"; exit 2 ;;
esac
