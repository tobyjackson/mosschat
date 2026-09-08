#!/usr/bin/env bash
# WO-1.6: build two "houses" behind two separately-configured NAT
# namespaces, joined by a shared "internet" namespace where the gatehouse
# runs. Confirms which NAT behaviour is live with `conntrack`, per
# research/network-fault-testing.md section B: "a wrong assumption tests
# the wrong path."
#
# Topology:
#
#   house-a --veth-- nat-a --veth-- [ br0 in "internet" ] --veth-- nat-b --veth-- house-b
#                                          ^ gatehouse binds here
#
# house-a  10.1.0.2/24   gw 10.1.0.1
# nat-a    10.1.0.1/24 (house side)   203.0.113.11/24 (internet side)
# house-b  10.2.0.2/24   gw 10.2.0.1
# nat-b    10.2.0.1/24 (house side)   203.0.113.12/24 (internet side)
# internet br0  203.0.113.1/24
#
# --mode eim  (default): nat-a and nat-b MASQUERADE. Linux's default
#   conntrack NAT reuses the same external port for a given internal
#   (address, port) regardless of destination, when that port is free --
#   endpoint-independent, full-cone-like mapping.
# --mode edm: nat-a and nat-b SNAT with the `random` port flag, which
#   allocates a fresh external port per new conntrack entry rather than
#   preserving the internal port. Because a new destination is a new
#   conntrack entry, this makes the external port vary by destination --
#   endpoint-dependent (symmetric) mapping. This is a stricter symmetric
#   NAT than some routers (it also re-picks a port for a second flow to
#   the SAME destination once the first entry expires), which is fine for
#   this harness: the property under test is "does a second destination
#   get a different mapped port", and this rule guarantees it.
#
# This script does not start the gatehouse process; see
# crates/mosschat-net/tests/harness/README.md for that step, run
# separately inside the "internet" namespace once this script has built
# the topology.
#
# Idempotent: safe to re-run. Requires root (real runs only; --dry-run
# does not).

set -euo pipefail

MODE="eim"
DRY_RUN=0

usage() {
    cat <<'EOF'
Usage: netns-nat.sh [--mode eim|edm] [--dry-run]

  --mode eim   Endpoint-independent mapping (MASQUERADE). Default.
  --mode edm   Endpoint-dependent (symmetric) mapping (random-port SNAT).
  --dry-run    Print every command this script would run, run nothing.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --mode)
            MODE="${2:-}"
            shift 2
            ;;
        --mode=*)
            MODE="${1#--mode=}"
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
        *)
            echo "netns-nat.sh: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ "$MODE" != "eim" ] && [ "$MODE" != "edm" ]; then
    echo "netns-nat.sh: --mode must be eim or edm, got: $MODE" >&2
    exit 2
fi

if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "netns-nat.sh: requires root (network namespaces, veth, nftables)." >&2
    echo "netns-nat.sh: re-run as: sudo $0 --mode $MODE" >&2
    echo "netns-nat.sh: or pass --dry-run to preview without root." >&2
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

# Runs `cmd` but treats a non-zero exit as success when stderr matches an
# "already exists" style message, so re-running the script is a no-op on
# the second pass. Only used for the handful of `ip` subcommands that have
# no idempotent form of their own (`addr replace`, `route replace`, and
# `link set ... up` are already idempotent and do not need this).
run_ok_if_exists() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '%q ' "$@"
        printf '  # (no-op if it already exists)\n'
        return 0
    fi
    local out
    if out=$("$@" 2>&1); then
        [ -n "$out" ] && echo "$out"
        return 0
    fi
    if printf '%s' "$out" | grep -qiE 'exist|already'; then
        return 0
    fi
    echo "$out" >&2
    return 1
}

ns_exists() {
    ip netns list | grep -qx "$1"
}

ensure_netns() {
    local ns="$1"
    if [ "$DRY_RUN" -eq 1 ]; then
        run ip netns add "$ns"
        return
    fi
    if ! ns_exists "$ns"; then
        ip netns add "$ns"
    fi
}

ensure_veth_pair() {
    # $1 ns_a $2 if_a $3 ns_b $4 if_b
    local ns_a="$1" if_a="$2" ns_b="$3" if_b="$4"
    if [ "$DRY_RUN" -eq 1 ]; then
        run ip link add "$if_a" netns "$ns_a" type veth peer name "$if_b" netns "$ns_b"
        return
    fi
    if ! ip netns exec "$ns_a" ip link show "$if_a" >/dev/null 2>&1; then
        ip link add "$if_a" netns "$ns_a" type veth peer name "$if_b" netns "$ns_b"
    fi
}

ensure_bridge() {
    local ns="$1" br="$2"
    if [ "$DRY_RUN" -eq 1 ]; then
        run ip netns exec "$ns" ip link add "$br" type bridge
        return
    fi
    if ! ip netns exec "$ns" ip link show "$br" >/dev/null 2>&1; then
        ip netns exec "$ns" ip link add "$br" type bridge
    fi
}

addr_replace() {
    local ns="$1" dev="$2" cidr="$3"
    run ip netns exec "$ns" ip addr replace "$cidr" dev "$dev"
}

link_up() {
    local ns="$1" dev="$2"
    run ip netns exec "$ns" ip link set dev "$dev" up
}

set_master() {
    local ns="$1" dev="$2" br="$3"
    run ip netns exec "$ns" ip link set dev "$dev" master "$br"
}

route_replace_default() {
    local ns="$1" via="$2"
    run ip netns exec "$ns" ip route replace default via "$via"
}

sysctl_forward() {
    local ns="$1"
    run ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
}

# Applies an nftables ruleset to a namespace by replacing the whole `ip
# nat` table each time, which is what makes this idempotent: re-running
# the script never appends a second copy of the same rule.
apply_nft_snat() {
    local ns="$1" subnet="$2" out_if="$3" out_ip="$4"
    local rule
    if [ "$MODE" = "eim" ]; then
        rule="ip saddr ${subnet} oifname \"${out_if}\" masquerade"
    else
        rule="ip saddr ${subnet} oifname \"${out_if}\" snat to ${out_ip}:1024-65535 random"
    fi
    local ruleset
    ruleset=$(cat <<EOF
flush ruleset
table ip nat {
    chain postrouting {
        type nat hook postrouting priority 100;
        ${rule}
    }
}
EOF
)
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "ip netns exec $ns nft -f - <<'NFT'"
        echo "$ruleset"
        echo "NFT"
    else
        echo "$ruleset" | ip netns exec "$ns" nft -f -
    fi
}

echo "== netns-nat.sh: mode=$MODE dry_run=$DRY_RUN =="

# --- namespaces ---
for ns in house-a nat-a house-b nat-b internet; do
    ensure_netns "$ns"
done

# --- veth pairs ---
ensure_veth_pair house-a veth-ha nat-a veth-na-in
ensure_veth_pair nat-a veth-na-out internet veth-in-a
ensure_veth_pair house-b veth-hb nat-b veth-nb-in
ensure_veth_pair nat-b veth-nb-out internet veth-in-b

# --- internet bridge ---
ensure_bridge internet br0
set_master internet veth-in-a br0
set_master internet veth-in-b br0
addr_replace internet br0 203.0.113.1/24
link_up internet br0
link_up internet veth-in-a
link_up internet veth-in-b
link_up internet lo

# --- house-a / nat-a ---
addr_replace house-a veth-ha 10.1.0.2/24
link_up house-a veth-ha
link_up house-a lo
route_replace_default house-a 10.1.0.1

addr_replace nat-a veth-na-in 10.1.0.1/24
addr_replace nat-a veth-na-out 203.0.113.11/24
link_up nat-a veth-na-in
link_up nat-a veth-na-out
link_up nat-a lo
route_replace_default nat-a 203.0.113.1
sysctl_forward nat-a

# --- house-b / nat-b ---
addr_replace house-b veth-hb 10.2.0.2/24
link_up house-b veth-hb
link_up house-b lo
route_replace_default house-b 10.2.0.1

addr_replace nat-b veth-nb-in 10.2.0.1/24
addr_replace nat-b veth-nb-out 203.0.113.12/24
link_up nat-b veth-nb-in
link_up nat-b veth-nb-out
link_up nat-b lo
route_replace_default nat-b 203.0.113.1
sysctl_forward nat-b

# --- NAT rules, mode-dependent ---
apply_nft_snat nat-a 10.1.0.0/24 veth-na-out 203.0.113.11
apply_nft_snat nat-b 10.2.0.0/24 veth-nb-out 203.0.113.12

echo "== topology ready (mode=$MODE) =="
echo "gatehouse binds inside the 'internet' namespace, e.g.:"
echo "  ip netns exec internet <path-to>/mosschat gatehouse --bind 203.0.113.1:443 --secondary-bind 203.0.113.1:444 --community <hex> --members <path>"
echo
echo "house-a and house-b reach it as 203.0.113.1:443 / :444 through their own NAT."
echo
echo "== confirm the NAT mode with conntrack, never assume it =="
echo "After each house has sent at least one packet through its NAT to two"
echo "different destinations (for example two spike 'dial' attempts, or two"
echo "gatehouse registrations), run:"
echo
echo "  ip netns exec nat-a conntrack -L -n -s 10.1.0.2"
echo
echo "Interpretation: if every entry for that source shows the SAME mapped"
echo "port (e.g. sport=... dport=... all sharing one 203.0.113.11:PORT), the"
echo "NAT is behaving endpoint-independently (EIM). If entries to two"
echo "different destination addresses show two DIFFERENT mapped ports on"
echo "203.0.113.11, the NAT is behaving endpoint-dependently, i.e."
echo "symmetric (EDM). Do this for nat-b with -s 10.2.0.2 too."
