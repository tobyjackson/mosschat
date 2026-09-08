//! The network layer: quinn for QUIC, rustls for TLS 1.3, the gatehouse and the
//! doorbell hole punch, same-network discovery, presence, visits, notes, file transfer,
//! voice and the diagnostics log (D2, D3, D8 to D10). This is the only crate allowed to
//! depend on quinn, rustls, tokio or any other transport crate; `mosschat-core` stays
//! free of all of them so identity, events and storage are testable with nothing bound.

#![forbid(unsafe_code)]

pub mod authed;
pub mod diag;
pub mod discovery;
pub mod gate;
pub mod house;
pub mod live;
pub(crate) mod lockext;
pub mod path;
pub mod punch;
pub mod sock;

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
