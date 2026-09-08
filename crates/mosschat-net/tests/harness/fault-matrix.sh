#!/usr/bin/env bash
# WO-1.6: runs a command once per row of network-fault-testing.md section D,
# with the row's condition applied via `tc qdisc ... netem` (or, for the
# two rows that are not netem conditions, a process kill) on the named
# veth inside the named network namespace created by netns-nat.sh. Resets
# the condition between rows. Captures each row's raw stdout under
# docs/measurements/<date>-faults/<row-id>.txt and prints a table citing
# the files at the end.
#
# Usage:
#   fault-matrix.sh [--rows id1,id2,...] [--dry-run] -- <command...>
#
# <command...> is run once per selected row, unmodified, from the
# directory this script was invoked from. It is the caller's job to make
# that command exercise the right path (a spike dial, a gatehouse
# doctor-style probe once WO-1.4b lands, a note-delivery check, etc) --
# see README.md for worked examples against this repo's current CLI
# surface. This script only shapes the network and records what the
# command printed.
#
# Requires root (real runs only; --dry-run does not).

set -euo pipefail

# --- repo-relative output location; never a path outside the repo ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
DATE_TAG="$(date -u +%Y-%m-%d)"
OUT_DIR="$REPO_ROOT/docs/measurements/${DATE_TAG}-faults"

# --- row table: id|type|spec|description|pass_criterion|hold_seconds ---
# type=netem: spec is one or more "ns:iface:netem-args" separated by ";".
#   Multiple entries (asymmetric-loss) are applied together, one tc call
#   per entry, so each direction's egress interface gets its own netem.
# type=killgate: spec is "ns:pkill-pattern:delay-seconds". The command
#   runs in the background; after delay-seconds this script sends SIGINT
#   to whatever in that namespace matches the pattern (via `pkill -f`).
#   There is nothing to "reset" for this type: Toby restarts the
#   gatehouse himself before a later row that needs it.
# hold_seconds: 0 means the condition stays applied for the command's
#   whole run. Nonzero (blackout-60s) means: apply, start the command in
#   the background, sleep hold_seconds, lift the condition, then wait for
#   the command -- so the row can observe recovery partway through a
#   longer-running command, per D's "Recovers inside WO-1.6 case (e)".
ROWS_TABLE=(
"loss-1pct|netem|house-a:veth-ha:loss random 1%|Packet loss 1%|Connects; log shows no failed step|0"
"loss-5pct|netem|house-a:veth-ha:loss random 5%|Packet loss 5%|Connects, degraded RTT; log records timings, no false failure|0"
"loss-20pct|netem|house-a:veth-ha:loss random 20%|Packet loss 20%|Connects direct or relays inside the deadline; log names the fallback step|0"
"delay-50ms|netem|house-a:veth-ha:delay 50ms 10ms|Delay 50ms plus jitter|Median RTT under 500ms (acceptance criterion 1)|0"
"delay-200ms|netem|house-a:veth-ha:delay 200ms 40ms|Delay 200ms plus jitter|Criterion 1 boundary; a miss is explained in the log|0"
"delay-1000ms|netem|house-a:veth-ha:delay 1000ms 200ms|Delay 1000ms plus jitter|Visit still opens; doorbell and notes still succeed, only slower|0"
"reorder|netem|house-a:veth-ha:delay 10ms reorder 25% 50%|Reorder|No duplicate or out-of-order events; host ordering unaffected|0"
"duplicate|netem|house-a:veth-ha:duplicate 1%|Duplicate|QUIC dedups; no duplicate message in the recording|0"
"bandwidth-256kbit|netem|house-a:veth-ha:rate 256kbit|Bandwidth cap 256kbit|File transfer resumes by missing pieces, completes; no false timeout (full pass criterion is WO-4.3's; this row only applies the condition)|0"
"blackout-60s|netem|house-a:veth-ha:loss 100%|Total blackout 60 seconds|Recovers inside WO-1.6 case (e); a queued note delivers within 60s per WO-3.3; log records the drop and recovery|60"
"asymmetric-loss|netem|house-a:veth-ha:loss random 10%;house-b:veth-hb:loss random 2%|Asymmetric loss, 10 percent A to B and 2 percent B to A|Fallback does not assume symmetric loss; log shows each side's own view|0"
"gatehouse-killed|killgate|internet:mosschat.*gatehouse:5|Gatehouse killed mid-visit|Direct connections continue; gate-dependent ones fail closed with a log record, never a silent hang|0"
)

DRY_RUN=0
ROWS_FILTER=""
CMD=()

usage() {
    cat <<'EOF'
Usage: fault-matrix.sh [--rows id1,id2,...] [--dry-run] -- <command...>

  --rows id1,id2   Run only these row ids (default: all rows, in table order).
  --dry-run        Print every command this script would run, run nothing,
                    and do not actually execute <command...>.
  --               Everything after this is the command to run per row.

Row ids (see the table at the top of this script for conditions):
EOF
    for row in "${ROWS_TABLE[@]}"; do
        IFS='|' read -r id _ _ desc _ _ <<<"$row"
        printf '  %-20s %s\n' "$id" "$desc"
    done
}

while [ $# -gt 0 ]; do
    case "$1" in
        --rows)
            ROWS_FILTER="${2:-}"
            shift 2
            ;;
        --rows=*)
            ROWS_FILTER="${1#--rows=}"
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            CMD=("$@")
            break
            ;;
        *)
            echo "fault-matrix.sh: unknown argument: $1 (did you forget --?)" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ "${#CMD[@]}" -eq 0 ]; then
    echo "fault-matrix.sh: no command given; pass it after --" >&2
    usage >&2
    exit 2
fi

if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "fault-matrix.sh: requires root (tc, ip netns exec, pkill by namespace)." >&2
    echo "fault-matrix.sh: re-run under sudo, or pass --dry-run to preview." >&2
    exit 1
fi

run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '%q ' "$@"
        printf '\n'
    else
        "$@"
    fi
}

selected_rows() {
    if [ -z "$ROWS_FILTER" ]; then
        printf '%s\n' "${ROWS_TABLE[@]}"
        return
    fi
    local wanted=",${ROWS_FILTER},"
    for row in "${ROWS_TABLE[@]}"; do
        IFS='|' read -r id _ <<<"$row"
        case "$wanted" in
            *",${id},"*) printf '%s\n' "$row" ;;
        esac
    done
}

apply_netem_targets() {
    # $1 = "ns:iface:args;ns:iface:args"
    local spec="$1"
    local target ns iface args
    local IFS=';'
    for target in $spec; do
        IFS=':' read -r ns iface args <<<"$target"
        # shellcheck disable=SC2086 # $args is deliberately unquoted: it is
        # a space-separated netem option list ("delay 50ms 10ms") that tc
        # needs as several argv words, not one.
        run ip netns exec "$ns" tc qdisc replace dev "$iface" root netem $args
    done
}

reset_netem_targets() {
    local spec="$1"
    local target ns iface args
    local IFS=';'
    for target in $spec; do
        IFS=':' read -r ns iface args <<<"$target"
        if [ "$DRY_RUN" -eq 1 ]; then
            run ip netns exec "$ns" tc qdisc del dev "$iface" root
        else
            ip netns exec "$ns" tc qdisc del dev "$iface" root 2>/dev/null || true
        fi
    done
}

if [ "$DRY_RUN" -eq 1 ]; then
    echo "mkdir -p $OUT_DIR"
else
    mkdir -p "$OUT_DIR"
fi

echo "== fault-matrix.sh: dry_run=$DRY_RUN command: ${CMD[*]} =="
echo "== output directory: $OUT_DIR =="

declare -a RESULT_IDS=()
declare -a RESULT_FILES=()
declare -a RESULT_CODES=()

while IFS= read -r row; do
    [ -z "$row" ] && continue
    IFS='|' read -r id type spec desc pass_criterion hold <<<"$row"
    outfile="$OUT_DIR/${id}.txt"
    echo
    echo "-- row: $id --"
    echo "   condition: $desc"
    echo "   pass criterion: $pass_criterion"
    echo "   output: $outfile"

    rc=0
    if [ "$type" = "netem" ]; then
        apply_netem_targets "$spec"
        if [ "$DRY_RUN" -eq 1 ]; then
            echo "${CMD[*]} > $outfile"
            if [ "$hold" != "0" ]; then
                echo "sleep $hold"
            fi
            reset_netem_targets "$spec"
        else
            if [ "$hold" != "0" ]; then
                "${CMD[@]}" >"$outfile" 2>&1 &
                cmd_pid=$!
                sleep "$hold"
                reset_netem_targets "$spec"
                wait "$cmd_pid" || rc=$?
            else
                set +e
                "${CMD[@]}" >"$outfile" 2>&1
                rc=$?
                set -e
                reset_netem_targets "$spec"
            fi
        fi
    elif [ "$type" = "killgate" ]; then
        IFS=':' read -r kns kpattern kdelay <<<"$spec"
        if [ "$DRY_RUN" -eq 1 ]; then
            echo "${CMD[*]} > $outfile   # started in background"
            echo "sleep $kdelay"
            echo "ip netns exec $kns pkill -INT -f '$kpattern'"
        else
            "${CMD[@]}" >"$outfile" 2>&1 &
            cmd_pid=$!
            sleep "$kdelay"
            if ! ip netns exec "$kns" pkill -INT -f "$kpattern"; then
                echo "fault-matrix.sh: warning: nothing in $kns matched '$kpattern' to kill" >&2
            fi
            set +e
            wait "$cmd_pid"
            rc=$?
            set -e
        fi
    else
        echo "fault-matrix.sh: unknown row type '$type' for row '$id'" >&2
        exit 2
    fi

    RESULT_IDS+=("$id")
    RESULT_FILES+=("$outfile")
    RESULT_CODES+=("$rc")
done < <(selected_rows)

echo
echo "== fault-matrix.sh: summary =="
printf '%-20s %-10s %s\n' "row" "exit" "file"
for i in "${!RESULT_IDS[@]}"; do
    printf '%-20s %-10s %s\n' "${RESULT_IDS[$i]}" "${RESULT_CODES[$i]}" "${RESULT_FILES[$i]}"
done
