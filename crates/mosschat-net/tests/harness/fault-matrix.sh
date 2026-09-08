#!/usr/bin/env bash
# WO-1.6: runs a command once per row of network-fault-testing.md section D,
# with the row's condition applied via `tc qdisc ... netem` (or, for the
# gatehouse-kill row, a signal by pid) on the named veth inside the named
# network namespace created by netns-nat.sh. Resets the condition between
# rows. Captures each row's raw stdout, with a header proving what was
# actually applied, under docs/measurements/<date>-faults/<row-id>.txt,
# and prints a table citing the files at the end.
#
# No `pkill -f` anywhere in this script (PR 48 review, Ursula and Konrad
# both flagged it: `ip netns exec` only changes network namespace, not
# PID namespace, so a name/pattern match is host-wide, not namespace-
# scoped). Every process this script starts is tracked by pid: the row
# command via `$!` right after backgrounding it, and the gatehouse (which
# this script does not start; see README.md) via a pidfile it writes
# itself when it is started. `timeout` also kills by pid internally, not
# by name.
#
# Usage:
#   fault-matrix.sh [--rows id1,id2,...] [--row-timeout SECONDS] [--dry-run] -- <command...>
#
# <command...> is run once per selected row, unmodified, from the
# directory this script was invoked from. It is the caller's job to make
# that command exercise the right path (a spike dial, a gatehouse
# doctor-style probe once WO-1.4b lands, a note-delivery check, etc) --
# see README.md for worked examples against this repo's current CLI
# surface. This script only shapes the network, bounds and records the
# run, and captures what the command printed.
#
# Requires root (real runs only; --dry-run does not).

set -euo pipefail

# --- repo-relative output location; never a path outside the repo ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
DATE_TAG="$(date -u +%Y-%m-%d)"
OUT_DIR="$REPO_ROOT/docs/measurements/${DATE_TAG}-faults"
RUN_DIR="$SCRIPT_DIR/.run"

# --- row table: id|type|spec|description|pass_criterion|start_delay|hold_seconds ---
#
# type=netem: spec is one or more "ns:iface:netem-args" separated by ";".
#   Multiple entries (asymmetric-loss, blackout-60s) are applied together,
#   one tc call per entry, so more than one direction's egress interface
#   can get its own netem in the same row.
#
# type=killgate: spec is "pidfile-name:delay-seconds". The row command
#   runs in the background; after delay-seconds this script reads
#   $RUN_DIR/<pidfile-name>, sends SIGTERM to that exact pid (never a
#   name match), waits up to 2 seconds for it to exit, escalates to
#   SIGKILL if it has not, and reports which one worked. Both the signal
#   and the verification are by pid.
#
# start_delay: seconds to wait after the row command has started, before
#   applying the row's condition. 0 for every row except blackout-60s: a
#   loss/delay/reorder/duplicate/rate condition is meant to be present
#   from the first packet (that is what "connects under this condition"
#   in the pass criterion means), but a blackout's pass criterion is
#   about an already-open connection surviving and recovering, so the
#   connection must exist first. 5 seconds is this harness's stated
#   assumption for how long a direct dial takes to establish (comfortably
#   above gatehouse-design.md section 2's own under-1-second direct
#   target plus this repo's own build/startup jitter); override with
#   --blackout-start-delay if your command's own setup is slower.
#
# hold_seconds: 0 means the condition stays applied for the whole row,
# reset only after the command exits (or is killed by --row-timeout).
# Nonzero (blackout-60s) means: apply, sleep hold_seconds, lift the
# condition, then keep waiting for the command -- so the row can observe
# recovery partway through a longer-running command, per section D's
# "Recovers inside WO-1.6 case (e)". --blackout-hold overrides it.
BLACKOUT_START_DELAY=5
BLACKOUT_HOLD=60
ROW_TIMEOUT=180

build_rows_table() {
    ROWS_TABLE=(
"loss-1pct|netem|house-a:veth-ha:loss random 1%|Packet loss 1%|Connects; log shows no failed step|0|0"
"loss-5pct|netem|house-a:veth-ha:loss random 5%|Packet loss 5%|Connects, degraded RTT; log records timings, no false failure|0|0"
"loss-20pct|netem|house-a:veth-ha:loss random 20%|Packet loss 20%|Connects direct or relays inside the deadline; log names the fallback step|0|0"
"delay-50ms|netem|house-a:veth-ha:delay 50ms 10ms|Delay 50ms plus jitter|Median RTT under 500ms (acceptance criterion 1)|0|0"
"delay-200ms|netem|house-a:veth-ha:delay 200ms 40ms|Delay 200ms plus jitter|Criterion 1 boundary; a miss is explained in the log|0|0"
"delay-1000ms|netem|house-a:veth-ha:delay 1000ms 200ms|Delay 1000ms plus jitter|Visit still opens; doorbell and notes still succeed, only slower|0|0"
"reorder|netem|house-a:veth-ha:delay 10ms reorder 25% 50%|Reorder|No duplicate or out-of-order events; host ordering unaffected|0|0"
"duplicate|netem|house-a:veth-ha:duplicate 1%|Duplicate|QUIC dedups; no duplicate message in the recording|0|0"
"bandwidth-256kbit|netem|house-a:veth-ha:rate 256kbit|Bandwidth cap 256kbit|File transfer resumes by missing pieces, completes; no false timeout (full pass criterion is WO-4.3's; this row only applies the condition)|0|0"
"blackout-60s|netem|house-a:veth-ha:loss 100%;house-b:veth-hb:loss 100%|Total blackout, both directions, ${BLACKOUT_HOLD}s, applied ${BLACKOUT_START_DELAY}s after the command starts|Recovers inside WO-1.6 case (e); a queued note delivers within 60s per WO-3.3; log records the drop and recovery|${BLACKOUT_START_DELAY}|${BLACKOUT_HOLD}"
"asymmetric-loss|netem|house-a:veth-ha:loss random 10%;house-b:veth-hb:loss random 2%|Asymmetric loss, 10 percent A to B and 2 percent B to A|Fallback does not assume symmetric loss; log shows each side's own view|0|0"
"gatehouse-killed|killgate|gatehouse.pid:5|Gatehouse killed mid-visit, by its recorded pid, 5s after the command starts|Direct connections continue; gate-dependent ones fail closed with a log record, never a silent hang|0|0"
    )
}

DRY_RUN=0
ROWS_FILTER=""
CMD=()

usage() {
    cat <<'EOF'
Usage: fault-matrix.sh [--rows id1,id2,...] [--row-timeout SECONDS]
                        [--blackout-start-delay SECONDS] [--blackout-hold SECONDS]
                        [--dry-run] -- <command...>

  --rows id1,id2          Run only these row ids (default: all, table order).
  --row-timeout SECONDS   Max wall time per row's command (default: 180).
                           Enforced by timeout(1), which kills by pid, not
                           by name. Must comfortably exceed the blackout
                           row's start-delay plus hold.
  --blackout-start-delay  Seconds after the command starts before the
                           blackout row applies loss (default: 5).
  --blackout-hold         Seconds the blackout row stays applied (default: 60).
  --dry-run               Print every command this script would run, run
                           nothing, and do not execute <command...>.
  --                      Everything after this is the command to run per row.

If a row hangs or you interrupt with Ctrl-C, a trap on EXIT/INT/TERM
resets whatever netem this script applied for the current row and kills
the row's command by its recorded pid (SIGTERM, then SIGKILL if still
alive after 2 seconds) before this script exits, so nothing is left
running or shaped after a bad row.

Row ids (see the table at the top of this script for conditions):
EOF
    build_rows_table
    for row in "${ROWS_TABLE[@]}"; do
        IFS='|' read -r id _ _ desc _ _ _ <<<"$row"
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
        --row-timeout)
            ROW_TIMEOUT="${2:-}"
            shift 2
            ;;
        --blackout-start-delay)
            BLACKOUT_START_DELAY="${2:-}"
            shift 2
            ;;
        --blackout-hold)
            BLACKOUT_HOLD="${2:-}"
            shift 2
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

build_rows_table

if [ "${#CMD[@]}" -eq 0 ]; then
    echo "fault-matrix.sh: no command given; pass it after --" >&2
    usage >&2
    exit 2
fi

if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "fault-matrix.sh: requires root (tc, ip netns exec)." >&2
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

# --- netem target application, fixed IFS-scoping bug from PR 48 review ---
# The previous version set `local IFS=';'` for the whole function body,
# which was still in effect when $args (e.g. "delay 50ms 10ms") was
# later expanded unquoted -- so it word-split on ';' (none present) and
# tc got ONE argv word instead of several, and rejected it (Konrad's
# review on PR 48, reproduced there: argc 12 not 14). Splitting each
# target's args into an explicit array, with IFS scoped only to that one
# `read`, fixes it: every netem option is its own argv word to tc,
# provably so in --dry-run output because run()'s `%q` quoting shows them
# as separate tokens rather than one string with escaped spaces.
netem_targets_as_array() {
    # $1 = "ns:iface:args;ns:iface:args" -> fills global TARGETS array,
    # one "ns:iface:args" element per target (still ':'-joined; parsed
    # again per-target below so args keeps its internal spaces intact).
    local spec="$1"
    IFS=';' read -r -a TARGETS <<<"$spec"
}

apply_netem_targets() {
    local spec="$1"
    local target ns iface args
    local -a nargs
    netem_targets_as_array "$spec"
    for target in "${TARGETS[@]}"; do
        IFS=':' read -r ns iface args <<<"$target"
        IFS=' ' read -r -a nargs <<<"$args"
        run ip netns exec "$ns" tc qdisc replace dev "$iface" root netem "${nargs[@]}"
    done
}

reset_netem_targets() {
    local spec="$1"
    local target ns iface args
    netem_targets_as_array "$spec"
    for target in "${TARGETS[@]}"; do
        IFS=':' read -r ns iface args <<<"$target"
        if [ "$DRY_RUN" -eq 1 ]; then
            run ip netns exec "$ns" tc qdisc del dev "$iface" root
        else
            ip netns exec "$ns" tc qdisc del dev "$iface" root 2>/dev/null || true
        fi
    done
}

# tc qdisc show for every interface a spec touches, for the row's own
# output header (Konrad's review, should: rows need to be citable as
# evidence, not just carry the command's stdout).
show_netem_targets() {
    local spec="$1"
    local target ns iface args
    netem_targets_as_array "$spec"
    for target in "${TARGETS[@]}"; do
        IFS=':' read -r ns iface args <<<"$target"
        if [ "$DRY_RUN" -eq 1 ]; then
            run ip netns exec "$ns" tc qdisc show dev "$iface"
        else
            echo "tc qdisc show dev $iface (in $ns):"
            ip netns exec "$ns" tc qdisc show dev "$iface" | sed 's/^/  /'
        fi
    done
}

# --- pid tracking; no pkill -f anywhere in this file ---
CMD_PID=""
ACTIVE_SPEC=""

# Sends TERM then, after a grace period, KILL to $1 if it is still alive,
# and reports which one actually worked (or that the pid was already
# gone). Always by pid.
kill_and_verify() {
    local pid="$1" label="$2"
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "$label (pid $pid): already gone"
        return 0
    fi
    kill -TERM "$pid" 2>/dev/null || true
    local waited=0
    while [ "$waited" -lt 2 ] && kill -0 "$pid" 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
        sleep 1
    fi
    if kill -0 "$pid" 2>/dev/null; then
        echo "$label (pid $pid): WARNING still alive after SIGTERM and SIGKILL" >&2
        return 1
    fi
    echo "$label (pid $pid): confirmed terminated"
    return 0
}

cleanup() {
    local ec=$?
    if [ -n "$CMD_PID" ] && kill -0 "$CMD_PID" 2>/dev/null; then
        echo "fault-matrix.sh: cleanup: row command still running, stopping it" >&2
        kill_and_verify "$CMD_PID" "row command" >&2 || true
    fi
    if [ -n "$ACTIVE_SPEC" ]; then
        echo "fault-matrix.sh: cleanup: resetting netem left applied by an interrupted row" >&2
        reset_netem_targets "$ACTIVE_SPEC" || true
    fi
    exit "$ec"
}
trap cleanup EXIT INT TERM

if [ "$DRY_RUN" -eq 1 ]; then
    echo "mkdir -p $OUT_DIR"
else
    mkdir -p "$OUT_DIR"
fi

echo "== fault-matrix.sh: dry_run=$DRY_RUN row_timeout=${ROW_TIMEOUT}s command: ${CMD[*]} =="
echo "== output directory: $OUT_DIR =="

declare -a RESULT_IDS=()
declare -a RESULT_FILES=()
declare -a RESULT_CODES=()

row_header() {
    # $1 outfile $2 id $3 desc $4 pass_criterion $5 spec-or-empty
    {
        echo "# fault-matrix.sh row: $2"
        echo "# condition: $3"
        echo "# pass criterion: $4"
        echo "# started (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# command: ${CMD[*]}"
        if [ -n "$5" ]; then
            echo "# netem applied (tc qdisc show, captured right after applying):"
            show_netem_targets "$5" 2>&1 | sed 's/^/# /'
        fi
        echo "# --- command output follows ---"
    } >"$1"
}

while IFS= read -r row; do
    [ -z "$row" ] && continue
    IFS='|' read -r id type spec desc pass_criterion start_delay hold <<<"$row"
    outfile="$OUT_DIR/${id}.txt"
    echo
    echo "-- row: $id --"
    echo "   condition: $desc"
    echo "   pass criterion: $pass_criterion"
    echo "   output: $outfile"

    rc=0
    if [ "$type" = "netem" ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            if [ "$start_delay" = "0" ]; then
                apply_netem_targets "$spec"
                show_netem_targets "$spec"
            fi
            echo "timeout --kill-after=5 ${ROW_TIMEOUT} ${CMD[*]} > $outfile 2>&1 </dev/null   # backgrounded, pid recorded"
            if [ "$start_delay" != "0" ]; then
                echo "sleep $start_delay"
                apply_netem_targets "$spec"
                show_netem_targets "$spec"
            fi
            if [ "$hold" != "0" ]; then
                echo "sleep $hold"
            fi
            reset_netem_targets "$spec"
            echo "wait <row command pid>"
        else
            if [ "$start_delay" = "0" ]; then
                apply_netem_targets "$spec"
                row_header "$outfile" "$id" "$desc" "$pass_criterion" "$spec"
            else
                row_header "$outfile" "$id" "$desc" "$pass_criterion" ""
            fi
            timeout --kill-after=5 "$ROW_TIMEOUT" "${CMD[@]}" >>"$outfile" 2>&1 </dev/null &
            CMD_PID=$!
            ACTIVE_SPEC="$spec"
            if [ "$start_delay" != "0" ]; then
                sleep "$start_delay"
                apply_netem_targets "$spec"
                {
                    echo "# netem applied ${start_delay}s after start (tc qdisc show):"
                    show_netem_targets "$spec" 2>&1 | sed 's/^/# /'
                } >>"$outfile"
            fi
            if [ "$hold" != "0" ]; then
                sleep "$hold"
                reset_netem_targets "$spec"
                ACTIVE_SPEC=""
                echo "# netem lifted after ${hold}s hold" >>"$outfile"
            fi
            set +e
            wait "$CMD_PID"
            rc=$?
            set -e
            CMD_PID=""
            if [ -n "$ACTIVE_SPEC" ]; then
                reset_netem_targets "$spec"
                ACTIVE_SPEC=""
            fi
        fi
    elif [ "$type" = "killgate" ]; then
        IFS=':' read -r pidfile_name kdelay <<<"$spec"
        pidfile="$RUN_DIR/$pidfile_name"
        if [ "$DRY_RUN" -eq 1 ]; then
            echo "timeout --kill-after=5 ${ROW_TIMEOUT} ${CMD[*]} > $outfile 2>&1 </dev/null   # backgrounded, pid recorded"
            echo "sleep $kdelay"
            echo "pid=\$(cat $pidfile)   # gatehouse's own pidfile, written when Toby started it; see README.md"
            echo "kill -TERM \$pid; wait up to 2s; kill -KILL \$pid if still alive; verify by kill -0 \$pid"
            echo "wait <row command pid>"
        else
            row_header "$outfile" "$id" "$desc" "$pass_criterion" ""
            if [ ! -f "$pidfile" ]; then
                echo "fault-matrix.sh: $pidfile does not exist; start the gatehouse per README.md first (it writes this file itself)" >&2
                exit 2
            fi
            timeout --kill-after=5 "$ROW_TIMEOUT" "${CMD[@]}" >>"$outfile" 2>&1 </dev/null &
            CMD_PID=$!
            sleep "$kdelay"
            gate_pid="$(cat "$pidfile")"
            {
                echo "# killing gatehouse by its recorded pid ($gate_pid) from $pidfile"
                kill_and_verify "$gate_pid" "gatehouse"
            } >>"$outfile" 2>&1
            set +e
            wait "$CMD_PID"
            rc=$?
            set -e
            CMD_PID=""
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
