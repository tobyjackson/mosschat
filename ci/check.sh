#!/usr/bin/env bash
# The one script CI and a developer both run (PLAN.md section "Team process" /
# Ursula's pipeline principle: CI runs the same commands developers run locally).
# Exits non-zero on the first failure and prints a one-line reason before it does.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail() {
    echo "check.sh: FAIL: $1" >&2
    exit 1
}

echo "check.sh: cargo fmt --all --check"
cargo fmt --all --check || fail "cargo fmt found unformatted code"

echo "check.sh: cargo clippy --all-targets -- -D warnings"
cargo clippy --all-targets -- -D warnings || fail "clippy reported a warning or lint violation"

echo "check.sh: cargo test --workspace"
cargo test --workspace || fail "a workspace test failed"

echo "check.sh: cargo deny check"
cargo deny check || fail "cargo deny found a licence, advisory, ban or source violation"

echo "check.sh: invariant 11, mosschat-core has no networking and no async dependency"
forbidden_deps="quinn rustls tokio iroh libp2p"
core_tree="$(cargo tree -p mosschat-core -e normal)"
for dep in $forbidden_deps; do
    if echo "$core_tree" | grep -qw "$dep"; then
        fail "invariant 11 violated: mosschat-core depends on $dep (cargo tree -p mosschat-core -e normal)"
    fi
done

echo "check.sh: invariant 2, every crate root has #![forbid(unsafe_code)]"
while IFS= read -r -d '' root; do
    if ! grep -q '^#!\[forbid(unsafe_code)\]' "$root"; then
        fail "invariant 2 violated: $root is missing #![forbid(unsafe_code)]"
    fi
done < <(find crates -type f \( -name lib.rs -o -name main.rs \) -path '*/src/*' -print0)

echo "check.sh: all checks passed"
