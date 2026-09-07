//! Identity, devices, events, recordings, views and the encrypted store for one house.
//! This crate holds everything a house is while offline: the ed25519 identity and its
//! linked devices (D4), the signed-event recording format with its ingest checks (D5),
//! the computed contact and group views (D5), and the encrypted SQLite store (D6). It has
//! no networking and no async runtime (invariant 11): `mosschat-net` is the only crate
//! that speaks to another house, and everything here is reachable and testable with no
//! socket open.

#![forbid(unsafe_code)]

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    #[test]
    fn crate_loads_and_unwrap_is_usable_in_tests() {
        let parsed: i32 = "2".parse().unwrap();
        assert_eq!(parsed, 2);
    }
}
