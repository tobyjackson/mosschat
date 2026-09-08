#!/usr/bin/env bash
# WO-1.6: removes everything netns-nat.sh created. Idempotent: safe to
# run even if setup was only partly applied, or already torn down.
#
# Deleting a namespace deletes every interface and nftables table inside
# it, so this script does not need to walk veth pairs, bridges or nft
# rules individually -- it only needs to delete the five namespaces.
# The commands are still listed explicitly (rather than one loop) so
# --dry-run output shows exactly what runs.

set -euo pipefail

DRY_RUN=0

usage() {
    cat <<'EOF'
Usage: teardown.sh [--dry-run]

  --dry-run    Print every command this script would run, run nothing.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "teardown.sh: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "teardown.sh: requires root (network namespaces)." >&2
    echo "teardown.sh: re-run as: sudo $0" >&2
    echo "teardown.sh: or pass --dry-run to preview without root." >&2
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

ns_exists() {
    ip netns list | grep -qx "$1"
}

delete_netns() {
    local ns="$1"
    if [ "$DRY_RUN" -eq 1 ]; then
        run ip netns delete "$ns"
        return
    fi
    if ns_exists "$ns"; then
        ip netns delete "$ns"
        echo "teardown.sh: deleted namespace $ns"
    else
        echo "teardown.sh: namespace $ns already absent"
    fi
}

echo "== teardown.sh: dry_run=$DRY_RUN =="

for ns in house-a nat-a house-b nat-b internet; do
    delete_netns "$ns"
done

echo "== teardown.sh: done =="
echo "Note: this does not reset any tc qdisc left on a host interface by"
echo "fault-matrix.sh outside a namespace. fault-matrix.sh resets its own"
echo "qdisc between rows and at exit; if it was killed mid-row, clear the"
echo "qdisc it names by hand: tc qdisc del dev <iface> root"
