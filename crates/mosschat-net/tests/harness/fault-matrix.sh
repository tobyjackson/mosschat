#!/usr/bin/env bash
# WO-1.6: runs a command once per row of network-fault-testing.md section D,
# with the row's condition applied via `tc qdisc ... netem` (or, for the
# gatehouse-kill row, a signal by pid) on the named veth inside the named
# network namespace created by netns-nat.sh. Resets the condition between
# rows. Captures each row's raw stdout, with a header proving what was
# actually applied, under docs/measurements/<date>-faults/<row-id>.txt,
# and prints a plain-English report card at the end, also written to
# <output dir>/REPORT.md. `--report-only <dir>` regenerates and prints
# that same card from an existing output directory without running
# anything (no root needed); see README.md.
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
REPORT_ONLY_DIR=""

usage() {
    cat <<'EOF'
Usage: fault-matrix.sh [--rows id1,id2,...] [--row-timeout SECONDS]
                        [--blackout-start-delay SECONDS] [--blackout-hold SECONDS]
                        [--dry-run] -- <command...>
       fault-matrix.sh --report-only <dir>

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
  --report-only <dir>     Regenerate and print the report card from an
                           existing output directory's <row-id>.txt files
                           instead of running anything. No root needed,
                           does not require <command...>, and never
                           writes into <dir> (REPORT.md is only written
                           by a real run, not by --report-only).
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
        --report-only)
            REPORT_ONLY_DIR="${2:-}"
            shift 2
            ;;
        --report-only=*)
            REPORT_ONLY_DIR="${1#--report-only=}"
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

if [ -z "$REPORT_ONLY_DIR" ]; then
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

# --- report card: turns a row's raw output into a plain-English verdict ---
#
# Toby, who owns this harness, is not a network engineer; the exit-code
# table this used to print names files, not what happened. These
# functions read a row's own output file the same way whether it just
# ran (this script's own end-of-matrix card) or was written by an
# earlier run (`--report-only <dir>`), so both paths share one reading
# of what "passed" means.
#
# Every real run also appends "# fault-matrix.sh: exit N" to the row's
# outfile right after the row's exit code is known, so a later
# `--report-only` run of the same directory reads the real code back.
# Row files written before this existed (docs/measurements/2026-09-08-
# hewn-mini{,-run2}) have no such line; row_exit_code_of() falls back to
# inferring 0 when the row printed anything after its header sentinel
# and 1 (assumed failed) when it printed nothing, which is what both of
# those directories' real exit codes were (confirmed from their own
# NOTES.md and run.log, not guessed).

# Section 7 of gatehouse-design.md's reason enum, in plain English.
reason_words() {
    case "$1" in
        ok) echo "everything worked" ;;
        gate_unreachable) echo "no answer from the gate" ;;
        gate_refused_not_member) echo "the gate refused this house, it is not a member" ;;
        gate_at_capacity) echo "the gate was full" ;;
        gate_rate_limited) echo "the gate rate limited this house" ;;
        relay_stream_fallback) echo "fell back to the relay's stream path" ;;
        relay_datagram_too_large) echo "a relay datagram was too large to send" ;;
        introduce_timeout) echo "no introduction arrived in time" ;;
        peer_handshake_failed) echo "the handshake with the peer failed" ;;
        peer_key_mismatch) echo "the peer's key did not match" ;;
        no_candidates) echo "no connection candidates were found" ;;
        probe_timeout) echo "no probe answered in time" ;;
        endpoint_dependent_mapping) echo "the NAT changes its mapping per destination" ;;
        hairpin_failure) echo "the direct path could not hairpin through the router" ;;
        udp_blocked) echo "UDP looks blocked on this network" ;;
        path_idle_timeout) echo "the path went idle and timed out" ;;
        local_address_changed) echo "the local address changed mid-visit" ;;
        peer_goodbye) echo "the peer said goodbye" ;;
        cap_exceeded) echo "a connection cap was exceeded" ;;
        internal) echo "an internal error, not a network condition" ;;
        "") echo "no reason recorded" ;;
        *) echo "an unrecognized reason ($1)" ;;
    esac
}

# Section 7's step enum, in plain English.
step_words() {
    case "$1" in
        gate_dial) echo "dialing the gate" ;;
        gate_register) echo "registering with the gate" ;;
        reflect_primary) echo "the primary reflection" ;;
        reflect_secondary) echo "the secondary reflection" ;;
        introduce) echo "the introduction" ;;
        relay_open) echo "opening the relay" ;;
        peer_handshake) echo "the peer handshake" ;;
        candidate_exchange) echo "exchanging candidates" ;;
        start_signal) echo "the start signal" ;;
        probe_burst) echo "the probe burst" ;;
        upgrade) echo "upgrading the path" ;;
        live) echo "the live path" ;;
        path_lost) echo "losing the path" ;;
        relay_fallback) echo "falling back to the relay" ;;
        closed) echo "closing" ;;
        *) echo "step '$1'" ;;
    esac
}

# $1 json (one line) $2 step name -> that step's at_ms, empty if absent.
# Steps always serialize as {"at_ms":N,"detail":"...","outcome":"...",
# "step":"name"} (alphabetical field order), so at_ms is always the
# first field of the object whose "step" field names $2.
step_at_ms() {
    local json="$1" step="$2"
    printf '%s' "$json" \
        | grep -oE '"at_ms":[0-9]+,"detail":"[^"]*","outcome":"[a-z_]+","step":"'"$step"'"' \
        | grep -oE '^"at_ms":[0-9]+' | grep -oE '[0-9]+' | head -n1
}

# $1 file -> sets ROW_CONDITION, ROW_JSON, ROW_FAILED_STEP, ROW_REASON,
# ROW_STEPS_COUNT from that row's own output file.
parse_row_file() {
    local file="$1"
    ROW_CONDITION="$(grep -m1 '^# condition: ' "$file" 2>/dev/null | sed 's/^# condition: //')"
    [ -n "$ROW_CONDITION" ] || ROW_CONDITION="(condition unknown, no header line found)"
    ROW_JSON="$(grep '^{' "$file" 2>/dev/null | tail -n1 || true)"
    ROW_FAILED_STEP=""
    ROW_REASON=""
    ROW_STEPS_COUNT=0
    if [ -n "$ROW_JSON" ]; then
        ROW_FAILED_STEP="$(printf '%s' "$ROW_JSON" | grep -oE '"failed_step":(null|"[a-z_]+")' | sed -E 's/^"failed_step":"?//; s/"$//')"
        ROW_REASON="$(printf '%s' "$ROW_JSON" | grep -oE '"reason":"[a-z_]+"' | sed -E 's/^"reason":"//; s/"$//')"
        ROW_STEPS_COUNT="$(printf '%s' "$ROW_JSON" | grep -oE '"step":"[a-z_]+"' | wc -l | tr -d ' ')"
    fi
}

# $1 file -> that row's exit code, from its own "# fault-matrix.sh:
# exit N" line if present, else the fallback described above.
row_exit_code_of() {
    local file="$1" marker after
    marker="$(grep -m1 '^# fault-matrix.sh: exit ' "$file" 2>/dev/null | sed -E 's/^# fault-matrix.sh: exit //')"
    if [ -n "$marker" ]; then
        printf '%s' "$marker"
        return
    fi
    if grep -q '^# --- command output follows ---' "$file" 2>/dev/null; then
        after="$(sed -n '/^# --- command output follows ---/,$p' "$file" | tail -n +2 | grep -c '[^[:space:]]' || true)"
        if [ "${after:-0}" -gt 0 ]; then
            printf '0'
        else
            printf '1'
        fi
    else
        printf '1'
    fi
}

# $1 file $2 exit code -> sets CARD_CONDITION, CARD_VERDICT, CARD_NOTE.
compute_card() {
    local file="$1" ec="$2" dial reg reflect
    parse_row_file "$file"
    CARD_CONDITION="$ROW_CONDITION"
    if [ -z "$ROW_JSON" ]; then
        # No doctor record in this row's output at all: the command run
        # by this row was not the doctor (or produced nothing), so the
        # only evidence left is the exit code.
        if [ "$ec" -eq 0 ]; then
            CARD_VERDICT="PASS"
        else
            CARD_VERDICT="FAIL"
        fi
        CARD_NOTE="no doctor record in output"
        return
    fi
    if [ "$ec" -eq 0 ] && [ "$ROW_FAILED_STEP" = "null" ] && [ "$ROW_REASON" = "ok" ] && [ "$ROW_STEPS_COUNT" -ge 4 ]; then
        CARD_VERDICT="PASS"
        dial="$(step_at_ms "$ROW_JSON" gate_dial)"
        reg="$(step_at_ms "$ROW_JSON" gate_register)"
        reflect="$(step_at_ms "$ROW_JSON" reflect_secondary)"
        CARD_NOTE="dial ${dial:-?} ms, register ${reg:-?} ms, reflect ${reflect:-?} ms"
    elif [ "$ec" -ne 0 ] || { [ -n "$ROW_FAILED_STEP" ] && [ "$ROW_FAILED_STEP" != "null" ]; }; then
        CARD_VERDICT="FAIL"
        if [ -n "$ROW_FAILED_STEP" ] && [ "$ROW_FAILED_STEP" != "null" ]; then
            CARD_NOTE="failed at $(step_words "$ROW_FAILED_STEP"): $(reason_words "$ROW_REASON")"
        else
            CARD_NOTE="exited $ec: $(reason_words "$ROW_REASON")"
        fi
    else
        CARD_VERDICT="SUSPECT"
        CARD_NOTE="exit 0 but the record does not show a complete run"
    fi
}

print_card_header() {
    printf '%-20s %-58s %-8s %-5s %s\n' "row" "condition" "verdict" "exit" "note"
}

emit_row_text() {
    printf '%-20s %-58s %-8s %-5s %s\n' "$1" "$2" "$3" "$4" "$5"
}

# Escapes a literal "|" so a condition or note with one in it cannot
# break the markdown table.
emit_row_md() {
    local id="$1" cond="${2//|/\\|}" verdict="$3" ec="$4" note="${5//|/\\|}"
    printf '| %s | %s | %s | %s | %s |\n' "$id" "$cond" "$verdict" "$ec" "$note"
}

print_md_header() {
    local date="$1" host="$2" cmd="$3"
    echo "# fault-matrix.sh report card"
    echo
    echo "- date: $date"
    echo "- host: $host (\`uname -r\`)"
    echo "- command: \`$cmd\`"
    echo
    echo "PASS: the row's own record shows a complete run, reason ok, no failed step. FAIL: the command exited non-zero, or the record names a failed step. SUSPECT: exit 0 but the record is incomplete (fewer than four steps) or its reason is not ok."
    echo
    echo "| row | condition | verdict | exit | note |"
    echo "|---|---|---|---|---|"
}

# --report-only <dir>: reads <dir>/<row-id>.txt for every row in the
# table plus any other *.txt file found, in that order, and prints the
# card. Runs nothing, needs no root, and never writes into <dir>.
report_only() {
    local dir="$1" row rid file ec extra id
    local -a ordered=()
    [ -d "$dir" ] || { echo "fault-matrix.sh: --report-only: not a directory: $dir" >&2; exit 2; }
    for row in "${ROWS_TABLE[@]}"; do
        IFS='|' read -r rid _ <<<"$row"
        [ -f "$dir/$rid.txt" ] && ordered+=("$rid")
    done
    while IFS= read -r extra; do
        [ -z "$extra" ] && continue
        id="$(basename "$extra" .txt)"
        case " ${ordered[*]-} " in
            *" $id "*) ;;
            *) ordered+=("$id") ;;
        esac
    done < <(find "$dir" -maxdepth 1 -name '*.txt' 2>/dev/null | sort)

    echo "== fault-matrix.sh: report card (from $dir) =="
    print_card_header
    for id in "${ordered[@]}"; do
        file="$dir/$id.txt"
        ec="$(row_exit_code_of "$file")"
        compute_card "$file" "$ec"
        emit_row_text "$id" "$CARD_CONDITION" "$CARD_VERDICT" "$ec" "$CARD_NOTE"
    done
}

if [ -n "$REPORT_ONLY_DIR" ]; then
    report_only "$REPORT_ONLY_DIR"
    exit 0
fi

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

# Refuses to sign anything whose /proc cmdline does not actually mention
# "gatehouse" (issue #50 defense-in-depth): a stale or reused pid in the
# pidfile must never get signalled just because it happens to still be
# alive under that number.
pid_is_gatehouse() {
    local pid="$1"
    [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -q gatehouse
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
                # ACTIVE_SPEC set before apply, not after (issue #54): a
                # hang or interrupt during apply_netem_targets itself, or
                # in the gap before the old unconditional assignment
                # further down, would otherwise leave the trap's cleanup
                # with no spec recorded to reset.
                ACTIVE_SPEC="$spec"
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
            echo "pid=\$(cat $pidfile)   # gatehouse's own pidfile, written from inside itself; see README.md"
            echo "grep -q gatehouse /proc/\$pid/cmdline || refuse to signal   # pre-kill check, issue #50"
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
            if ! pid_is_gatehouse "$gate_pid"; then
                echo "fault-matrix.sh: pid $gate_pid from $pidfile is not a gatehouse process (checked /proc/$gate_pid/cmdline); refusing to signal it" >&2
                exit 2
            fi
            kg_rc=0
            {
                echo "# killing gatehouse by its recorded pid ($gate_pid) from $pidfile"
                kill_and_verify "$gate_pid" "gatehouse" || kg_rc=$?
                if pid_is_gatehouse "$gate_pid" 2>/dev/null; then
                    echo "gatehouse (pid $gate_pid): WARNING still present in /proc after kill_and_verify" >&2
                    kg_rc=1
                fi
            } >>"$outfile" 2>&1
            # kill_and_verify returning 1 is a per-row failure, not a
            # reason to abort the whole matrix under set -e (issue #55);
            # it is already logged above, so just fold it into rc below.
            set +e
            wait "$CMD_PID"
            rc=$?
            set -e
            [ "$kg_rc" -ne 0 ] && [ "$rc" -eq 0 ] && rc=$kg_rc
            CMD_PID=""
        fi
    else
        echo "fault-matrix.sh: unknown row type '$type' for row '$id'" >&2
        exit 2
    fi

    # Recorded on the row's own outfile so a later `--report-only` run
    # of this same directory reads the real exit code back, not a
    # fallback guess (DRY_RUN never reaches here with a real outfile).
    if [ "$DRY_RUN" -eq 0 ]; then
        echo "# fault-matrix.sh: exit $rc" >>"$outfile"
    fi

    RESULT_IDS+=("$id")
    RESULT_FILES+=("$outfile")
    RESULT_CODES+=("$rc")
done < <(selected_rows)

echo
echo "== fault-matrix.sh: report card =="
print_card_header
for i in "${!RESULT_IDS[@]}"; do
    compute_card "${RESULT_FILES[$i]}" "${RESULT_CODES[$i]}"
    emit_row_text "${RESULT_IDS[$i]}" "$CARD_CONDITION" "$CARD_VERDICT" "${RESULT_CODES[$i]}" "$CARD_NOTE"
done

if [ "$DRY_RUN" -eq 0 ]; then
    REPORT_MD="$OUT_DIR/REPORT.md"
    {
        print_md_header "$DATE_TAG" "$(uname -r)" "${CMD[*]}"
        for i in "${!RESULT_IDS[@]}"; do
            compute_card "${RESULT_FILES[$i]}" "${RESULT_CODES[$i]}"
            emit_row_md "${RESULT_IDS[$i]}" "$CARD_CONDITION" "$CARD_VERDICT" "${RESULT_CODES[$i]}" "$CARD_NOTE"
        done
    } >"$REPORT_MD"
    echo
    echo "== report card written to $REPORT_MD =="
fi
