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
# --mode edm: nat-a and nat-b SNAT with the `random` port flag. Corrected
#   rationale (Konrad's review on PR 48 caught the first version wrong):
#   `random` does not mean "a fresh literal-random port on every new
#   conntrack entry". The kernel seeds its port search with a hash over
#   (source address, destination address, destination port) when this
#   flag is set (RFC 4787's definition of endpoint-dependent mapping,
#   `net/netfilter/nf_nat_core.c`'s `random` path via
#   `secure_ipv4_port_ephemeral()`), so the mapped port is a function of
#   the destination rather than reused verbatim from the internal port.
#   Two flows from the same internal (address, port) to two different
#   destinations land on two different external ports; two flows to the
#   SAME destination tend to land on the same one, while it stays free.
#   That is what makes it endpoint-dependent (symmetric), and it is what
#   the conntrack check below in this script's own output, and the one in
#   README.md, must actually observe rather than assume.
#
# This script does not start the gatehouse process; see
# crates/mosschat-net/tests/harness/README.md for that step, run
# separately inside the "internet" namespace once this script has built
# the topology.
#
# Idempotent: safe to re-run. Requires root (real runs only; --dry-run
# does not).

set -euo pipefail

# CI (.github/workflows/ci.yml, job artifacts-linux) publishes prebuilt
# release binaries; this script never runs the gatehouse itself (see the
# comment above), but the topology-ready message below tells the operator
# what to run next, so it uses the same two variables README.md's
# "Getting the binaries" section sets, with the same local-build fallback
# path as its default.
MOSSCHAT_BIN="${MOSSCHAT_BIN:-./target/release/mosschat}"

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

# `ip netns list` prints a bare name only until the kernel has allocated
# that namespace an nsid (which happens the first time it is referenced
# from another namespace, e.g. by the veth pairs this script creates
# right after); from then on the line reads "house-a (id: 0)" and a
# plain `grep -qx "$1"` against it stops matching (Konrad's review on
# PR 48). `ip netns` namespaces are bind mounts under /run/netns, so
# testing for the mount is exact and unaffected by any nsid suffix.
ns_exists() {
    [ -e "/run/netns/$1" ]
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
        rule="ip saddr ${subnet} oifname \"${out_if}\" meta l4proto { tcp, udp } snat to ${out_ip}:1024-65535 random"
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
echo "  ip netns exec internet $MOSSCHAT_BIN gatehouse --bind 203.0.113.1:443 --secondary-bind 203.0.113.1:444 --community <hex> --members <path>"
echo
echo "house-a and house-b reach it as 203.0.113.1:443 / :444 through their own NAT."
echo
echo "== confirm the NAT mode with conntrack, never assume it =="
echo "Only one address exists past nat-a's outward side (203.0.113.1, the"
echo "internet bridge), so the probe below varies the DESTINATION PORT, not"
echo "the destination address, and it must be sent from one FIXED local"
echo "source port -- two different ephemeral source ports would get two"
echo "different mappings under EITHER mode and prove nothing. See"
echo "README.md 'Confirming which NAT mode is really in effect' for the"
echo "exact socat commands, then run:"
echo
echo "  ip netns exec nat-a conntrack -L -n -s 10.1.0.2"
echo
echo "Interpretation: each line shows two tuples, the original request and"
echo "the reply tuple as the NAT sees it. The mapped external port is the"
echo "reply tuple's dport= field (e.g. '... src=203.0.113.1 dst=203.0.113.11"
echo "sport=443 dport=41234 ...', src/dst/sport/dport in that order, same as"
echo "README.md's worked example), not the sport on the request side. If the"
echo "two probes (dest port 443, then 444) show the SAME reply dport=, the"
echo "NAT is endpoint-independent (EIM). If they show two DIFFERENT reply"
echo "dport= values, it is endpoint-dependent, i.e. symmetric (EDM)."
echo "Do this for nat-b with -s 10.2.0.2 too."
