//! Error types for `mosschat-core`.

use thiserror::Error;

/// Errors produced by `mosschat-core`.
///
/// This crate has no networking and no async runtime (invariant 11), so every
/// variant here describes a failure that can be detected from bytes already in
/// hand: a bad signature, a malformed key, or a non-deterministic re-encoding.
#[derive(Debug, Error)]
pub enum CoreError {
    /// The signature did not verify against the given public key and message.
    #[error("signature verification failed")]
    InvalidSignature,
    /// A public key or signature was not well-formed bytes for ed25519.
    #[error("malformed key or signature bytes")]
    MalformedKeyOrSignature,
}
