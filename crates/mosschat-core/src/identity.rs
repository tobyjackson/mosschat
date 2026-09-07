//! The ed25519 identity (D4) and the one-method `Signer` trait it implements.
//!
//! `mosschat-core` signs through `Signer` and never sees a network type (D4):
//! `mosschat-net` calls `sign` and `verify` on bytes it has already framed, and
//! nothing in this module knows what a QUIC connection or a TLS certificate is.

use ed25519_dalek::{Signature, Signer as EdSigner, SigningKey, VerifyingKey};

use crate::error::CoreError;

/// A one-method signing capability.
///
/// Implemented by [`AuthorKey`] and by anything else that can produce an
/// ed25519 signature over an arbitrary byte string, so callers outside this
/// crate can depend on the trait rather than on a concrete key type.
pub trait Signer {
    /// Signs `msg` and returns the 64 raw signature bytes.
    fn sign(&self, msg: &[u8]) -> [u8; 64];
}

/// An ed25519 signing key identifying one author (a device, per D4).
///
/// A newtype over [`ed25519_dalek::SigningKey`] so the rest of the crate
/// depends on this type rather than on the `ed25519-dalek` crate directly.
pub struct AuthorKey(SigningKey);

impl AuthorKey {
    /// Generates a new random signing key using the thread-local CSPRNG.
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut rand::rng()))
    }

    /// Builds an `AuthorKey` from 32 raw secret key bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(bytes))
    }

    /// Returns the 32 byte public key that verifies signatures from this key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

impl Signer for AuthorKey {
    fn sign(&self, msg: &[u8]) -> [u8; 64] {
        EdSigner::sign(&self.0, msg).to_bytes()
    }
}

/// Verifies an ed25519 signature over `msg` made by the key `public`.
///
/// # Errors
///
/// Returns [`CoreError::MalformedKeyOrSignature`] if `public` or `sig` are
/// not well-formed ed25519 bytes, and [`CoreError::InvalidSignature`] if the
/// signature does not verify.
pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), CoreError> {
    let verifying_key =
        VerifyingKey::from_bytes(public).map_err(|_| CoreError::MalformedKeyOrSignature)?;
    let signature = Signature::from_bytes(sig);
    // `verify_strict` rejects low-order (weak) public keys and signatures, on
    // top of the malleability checks plain `verify` already applies. Every
    // caller here accepts a peer-chosen key (WO-1.3 registration, WO-3.2
    // beacons, WO-3.4 device-add, WO-4.2 redemption), so non-strict `verify`
    // is never safe in this permanent path (CWE-347).
    verifying_key
        .verify_strict(msg, &signature)
        .map_err(|_| CoreError::InvalidSignature)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let key = AuthorKey::generate();
        let msg = b"a message from one house to another";
        let sig = key.sign(msg);
        let public = key.public_bytes();
        assert!(verify(&public, msg, &sig).is_ok());
    }

    #[test]
    fn a_flipped_byte_fails_verification() {
        let key = AuthorKey::generate();
        let msg = b"a message from one house to another";
        let mut sig = key.sign(msg);
        sig[0] ^= 0x01;
        let public = key.public_bytes();
        assert!(verify(&public, msg, &sig).is_err());
    }

    #[test]
    fn a_flipped_message_byte_fails_verification() {
        let key = AuthorKey::generate();
        let msg = b"a message from one house to another".to_vec();
        let sig = key.sign(&msg);
        let mut tampered = msg;
        tampered[0] ^= 0x01;
        let public = key.public_bytes();
        assert!(verify(&public, &tampered, &sig).is_err());
    }

    /// Reproduces Yseult's review finding: the low-order public key `01
    /// 00..00` paired with the signature `01 00..00` followed by 32 zero
    /// bytes "verifies" against every message under non-strict `verify`,
    /// with no private key involved. `verify_strict` must reject it.
    #[test]
    fn low_order_key_and_signature_are_rejected_for_an_arbitrary_message() {
        let mut public = [0u8; 32];
        public[0] = 0x01;
        let mut sig = [0u8; 64];
        sig[0] = 0x01;
        let msg = b"an arbitrary message held under no private key";
        assert!(verify(&public, msg, &sig).is_err());
    }
}
