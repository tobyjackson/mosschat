# Lints

Invariant 1 denies `clippy::unwrap_used`, `clippy::expect_used`, `clippy::indexing_slicing`,
`clippy::panic` and `clippy::dbg_macro` for every crate through `[workspace.lints.clippy]` in
the root `Cargo.toml`, and every crate opts in with `[lints] workspace = true` in its own
`Cargo.toml`. `cargo clippy --all-targets -- -D warnings` runs against test code as well as
library code, so a test that calls `.unwrap()` on a value it just built fails the same gate a
library function would. The convention: a `#[cfg(test)] mod tests { ... }` block that needs any
of the five carries `#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing,
clippy::panic)]` directly above the `mod tests` line, scoped to that module and nowhere wider, so
the allow is visible next to the code it covers and library code outside `#[cfg(test)]` stays
denied. `clippy::dbg_macro` is not allowed even in tests; there is no legitimate reason to leave a
`dbg!` in committed test code either.
