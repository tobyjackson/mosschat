//! The terminal reference client: ratatui over the explicit `crossterm_0_29` backend,
//! seeing only plain `mosschat-core` types and the door (D11). It is the client that
//! proves the door protocol is complete, not the one a non-technical friend opens
//! daily; the graphical client in Phase 6 is that. It never calls the store or the
//! network directly.

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
