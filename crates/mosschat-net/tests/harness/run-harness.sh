#!/usr/bin/env bash
# MossChat Phase 1 harness runner, one command per phase. Run as root:
#   sudo bash run-harness.sh nat      # EIM + EDM conntrack proof, tears down after each
#   sudo bash run-harness.sh matrix   # community, gatehouse, doctor smoke, fault matrix
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
# back over ssh without anyone pasting terminal output.
exec > >(tee -a "$OUT/run.log") 2>&1
echo; echo "#### $(date -u +%FT%TZ) run-harness.sh ${1:-}"

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

# Read a fixed identity's public key off a short-lived spike listen.
pub_of(){
  local ns="$1" seed="$2" bind="$3" pid
  local log="$RUN/spike-id-$ns.log"
  sh -c "echo \$\$ > $RUN/spike-id-$ns.pid; exec ip netns exec $ns $SPIKE_BIN listen --identity $seed --bind $bind" >"$log" 2>&1 &
  sleep 2
  pid="$(cat "$RUN/spike-id-$ns.pid")"
  [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q spike && kill -TERM "$pid" 2>/dev/null
  wait
  grep -m1 'spike: identity' "$log" | awk '{print $3}'
}

matrix(){
  local f="$OUT/${DATE_TAG}-matrix-setup.txt"
  trap 'stop_gatehouse' EXIT INT TERM
  say "netns-nat.sh --mode eim (left up for the matrix)"
  bash "$H/netns-nat.sh" --mode eim || { echo "netns-nat.sh failed"; return 1; }

  say "community, seeds, members"
  local A_SEED B_SEED COMMUNITY A_PUB B_PUB
  A_SEED="$(openssl rand -hex 32)"; B_SEED="$(openssl rand -hex 32)"; COMMUNITY="$(openssl rand -hex 32)"
  umask 077
  echo "$A_SEED" > "$RUN/house-a.seed"; echo "$B_SEED" > "$RUN/house-b.seed"
  umask 022
  A_PUB="$(pub_of house-a "$A_SEED" 10.1.0.2:7777)"
  B_PUB="$(pub_of house-b "$B_SEED" 10.2.0.2:7777)"
  [ ${#A_PUB} -eq 64 ] && [ ${#B_PUB} -eq 64 ] || { echo "could not read a public key off spike; see $RUN/spike-id-*.log"; return 1; }
  printf '%s\n%s\n' "$A_PUB" "$B_PUB" > "$RUN/members.txt"
  {
    echo "# hewn-mini $(uname -r) $(date -u +%FT%TZ)"
    echo "community: $COMMUNITY"; echo "house-a: $A_PUB"; echo "house-b: $B_PUB"
  } | tee "$f"

  say "gatehouse in the internet namespace (log: $RUN/gatehouse.log)"
  sh -c "echo \$\$ > $RUN/gatehouse.pid; exec ip netns exec internet $MOSSCHAT_BIN gatehouse --bind 203.0.113.1:443 --secondary-bind 203.0.113.1:444 --community $COMMUNITY --members $RUN/members.txt" >"$RUN/gatehouse.log" 2>&1 &
  sleep 2
  grep -q 'mosschat gatehouse: community=' "$RUN/gatehouse.log" || { echo "gatehouse did not start:"; cat "$RUN/gatehouse.log"; return 1; }
  cat "$RUN/gatehouse.log"

  # Per-row command: house-a's doctor reaching the gate (no friend is home
  # behind this gate yet, so --friend is not attempted; exit 0 means every
  # step it ran succeeded).
  local DOCTOR=(ip netns exec house-a "$MOSSCHAT_BIN" doctor --gate 203.0.113.1:443 --community "$COMMUNITY" --identity-file "$RUN/house-a.seed" --json)

  say "doctor smoke run, unshaped"
  "${DOCTOR[@]}" | tee -a "$f"; local rc="${PIPESTATUS[0]}"
  echo "doctor exit: $rc" | tee -a "$f"
  [ "$rc" -eq 0 ] || { echo "doctor failed unshaped; not running the matrix. gatehouse log:"; cat "$RUN/gatehouse.log"; return 1; }

  say "fault matrix (12 rows; blackout row alone takes ~70 s)"
  bash "$H/fault-matrix.sh" --row-timeout 120 -- "${DOCTOR[@]}"
  echo "matrix exit: $?" | tee -a "$f"
  say "gatehouse log after the matrix"; cat "$RUN/gatehouse.log" | tee -a "$f"
  say "done. Results: $OUT/${DATE_TAG}-faults/  Now run:  sudo bash $ROOT/run-harness.sh down"
}

case "${1:-}" in
  nat)    nat_proof eim && nat_proof edm ;;
  matrix) matrix ;;
  down)   stop_gatehouse; bash "$H/teardown.sh" ;;
  *)      sed -n 2,5p "$(readlink -f "$0")"; exit 2 ;;
esac
