//! The door protocol: the documented and versioned CBOR request and event framing
//! spoken over the house's Unix socket or named pipe, and, key-authenticated, over a
//! network connection (D1). `mosschat-tui` and any third-party client reach the house
//! through this one interface and nothing else, so the door is never half finished.

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
