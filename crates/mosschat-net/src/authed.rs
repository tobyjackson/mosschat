//! Identity binding (`docs/dev/gatehouse-design.md` section 5). Closes
//! issues #13 and #14 from the WO-1.2 spike's follow-up review.
//!
//! Two checks, both made twice. First, in the rustls verifier
//! ([`GateCertVerifier`]), which fails closed with a TLS alert mid-handshake
//! if the peer presents anything other than exactly one self-signed
//! id-Ed25519 certificate whose signature verifies under its own
//! SubjectPublicKeyInfo. Second, in [`AuthedConnection::new`], which wraps a
//! `quinn::Connection` once, right after the handshake and before any
//! application byte is read, and re-derives the same 32 byte key from
//! `Connection::peer_identity()` rather than trusting anything the peer
//! supplies in a frame. Nothing in the gate module outside this constructor
//! holds a bare `quinn::Connection`; every application signature this WO
//! verifies (the sealed introduction, in `gate::client`) is checked against
//! `AuthedConnection::peer_key`, never a peer-supplied key (issue #13).
//!
//! **Recorded as a decision, not an oversight** (section 5, Yseult finding
//! 6): validity dates and server name are deliberately not checked. There is
//! no certificate authority and no clock trusted for this; the certificate
//! carries a key pinned out of band (the member list, or the ticket in a
//! later work order), its lifetime is the process, and rotating it does not
//! rotate the identity.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};

use crate::gate::GateError;

/// The DER content bytes of OID 1.3.101.112 (RFC 8410, id-Ed25519).
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

/// The fixed 16-byte PKCS#8 v1 header for an RFC 8410 Ed25519 private key,
/// before the 32 raw seed bytes (the same construction the WO-1.2 spike
/// used).
const PKCS8_ED25519_HEADER: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Extracts the raw 32 byte ed25519 public key from a certificate's
/// SubjectPublicKeyInfo via a real DER parse, never a fixed-byte-prefix
/// search.
fn extract_ed25519_public_key(cert_der: &[u8]) -> Option<[u8; 32]> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    let spki = &cert.tbs_certificate.subject_pki;
    if spki.algorithm.algorithm.as_bytes() != OID_ED25519 {
        return None;
    }
    <[u8; 32]>::try_from(spki.subject_public_key.data.as_ref()).ok()
}

/// Checks that `cert_der` is exactly one self-signed certificate: issuer
/// equals subject, and the certificate's own signature verifies under its
/// own SPKI key (issue #14: today intermediates were ignored rather than
/// rejected; here there is no intermediate to ignore in the first place,
/// since only the single `end_entity` certificate this function is given is
/// ever considered trustworthy).
fn verify_self_signed(cert_der: &[u8]) -> Result<[u8; 32], TlsError> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    if cert.tbs_certificate.issuer != cert.tbs_certificate.subject {
        return Err(TlsError::InvalidCertificate(
            rustls::CertificateError::UnknownIssuer,
        ));
    }
    let public_bytes = extract_ed25519_public_key(cert_der).ok_or(TlsError::InvalidCertificate(
        rustls::CertificateError::BadEncoding,
    ))?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let sig_bytes: [u8; 64] = cert
        .signature_value
        .data
        .as_ref()
        .try_into()
        .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadSignature))?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(cert.tbs_certificate.as_ref(), &signature)
        .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadSignature))?;
    Ok(public_bytes)
}

fn verify_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, TlsError> {
    if dss.scheme != SignatureScheme::ED25519 {
        return Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::NoSignatureSchemesInCommon,
        ));
    }
    let public_bytes = extract_ed25519_public_key(cert).ok_or(TlsError::InvalidCertificate(
        rustls::CertificateError::BadEncoding,
    ))?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let sig_bytes: [u8; 64] = dss
        .signature()
        .try_into()
        .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let signature = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(message, &signature)
        .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadSignature))?;
    Ok(HandshakeSignatureValid::assertion())
}

/// A rustls verifier, usable on either side of the handshake, that accepts
/// exactly one self-signed id-Ed25519 certificate and rejects everything
/// else: any chain with intermediates (issue #14), any non-Ed25519 SPKI, any
/// certificate whose own signature does not verify under its own key, and
/// any certificate that is not self-signed (issuer != subject). It performs
/// no pinning of its own; the gate does not know a connecting house's key
/// ahead of the handshake completing, so membership is checked afterwards,
/// against [`crate::gate::MemberList`], via [`AuthedConnection::peer_key`].
pub struct GateCertVerifier;

impl fmt::Debug for GateCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GateCertVerifier").finish()
    }
}

impl ServerCertVerifier for GateCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if !intermediates.is_empty() {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        verify_self_signed(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

impl ClientCertVerifier for GateCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        if !intermediates.is_empty() {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        verify_self_signed(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// A `quinn::Connection` wrapped exactly once, right after the handshake and
/// before any application byte is read, carrying the peer's TLS-proven
/// ed25519 public key. Every application signature verified against a peer
/// in this crate is checked against [`Self::peer_key`], never a key the
/// peer supplies in a frame.
pub struct AuthedConnection {
    connection: quinn::Connection,
    peer_key: [u8; 32],
}

impl AuthedConnection {
    /// Wraps `connection`, deriving `peer_key` from
    /// [`quinn::Connection::peer_identity`].
    ///
    /// # Errors
    ///
    /// Returns [`GateError::InvalidIdentity`] if the peer's certificate
    /// chain does not carry exactly one certificate, or if that
    /// certificate's SubjectPublicKeyInfo is not a well-formed 32 byte
    /// id-Ed25519 key. Both cases should already be impossible past a
    /// handshake that used [`GateCertVerifier`], since it rejects the same
    /// shapes with a TLS alert; this is the second, redundant check section
    /// 5 calls for.
    pub fn new(connection: quinn::Connection) -> Result<Self, GateError> {
        let chain = connection
            .peer_identity()
            .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
            .ok_or_else(|| {
                GateError::InvalidIdentity("no certificate chain on this connection".into())
            })?;
        if chain.len() != 1 {
            return Err(GateError::InvalidIdentity(format!(
                "expected exactly one certificate, found {}",
                chain.len()
            )));
        }
        let cert = chain.first().ok_or_else(|| {
            GateError::InvalidIdentity("certificate chain unexpectedly empty".into())
        })?;
        let peer_key = extract_ed25519_public_key(cert).ok_or_else(|| {
            GateError::InvalidIdentity("certificate SPKI is not a 32 byte Ed25519 key".into())
        })?;
        Ok(Self {
            connection,
            peer_key,
        })
    }

    /// The peer's TLS-proven ed25519 public key.
    #[must_use]
    pub fn peer_key(&self) -> [u8; 32] {
        self.peer_key
    }

    /// The wrapped connection.
    #[must_use]
    pub fn connection(&self) -> &quinn::Connection {
        &self.connection
    }
}

/// Builds a self-signed certificate whose key is the given ed25519 seed,
/// returning the certificate DER and the matching PKCS#8 private key DER.
/// Used by both the gate and the house to present their identity over TLS
/// (section 5).
///
/// # Errors
///
/// Returns an error if certificate generation fails.
pub fn self_signed_cert(
    seed: &[u8; 32],
) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>), Box<dyn std::error::Error>> {
    let mut pkcs8 = Vec::with_capacity(48);
    pkcs8.extend_from_slice(&PKCS8_ED25519_HEADER);
    pkcs8.extend_from_slice(seed);
    let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8.clone()),
        &rcgen::PKCS_ED25519,
    )?;
    let params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    let cert = params.self_signed(&key_pair)?;
    Ok((cert.der().clone(), PrivatePkcs8KeyDer::from(pkcs8)))
}

/// Installs the `ring` rustls crypto provider as the process default, if not
/// already installed. Idempotent: the second and later calls in one process
/// (multiple gate/client instances in one test binary) are no-ops.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Builds a `rustls::ServerConfig` requiring a client certificate, verified
/// only structurally by [`GateCertVerifier`] (membership is an
/// application-level check, made after the handshake).
///
/// # Errors
///
/// Returns an error if the certificate or key is malformed, or if no ALPN
/// protocol negotiates.
pub fn server_tls_config(
    cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
    alpn: &[u8],
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    let verifier = Arc::new(GateCertVerifier);
    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], rustls::pki_types::PrivateKeyDer::Pkcs8(key))?;
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

/// Builds a `rustls::ClientConfig` presenting `cert`/`key` as a mandatory
/// client certificate and verifying the server structurally by
/// [`GateCertVerifier`], with no pinning of its own (a caller that already
/// knows the expected key, such as a house dialing a specific gate, checks
/// [`AuthedConnection::peer_key`] against it after connecting).
///
/// # Errors
///
/// Returns an error if the certificate or key is malformed.
pub fn client_tls_config(
    cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
    alpn: &[u8],
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error>> {
    let verifier = Arc::new(GateCertVerifier);
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert], rustls::pki_types::PrivateKeyDer::Pkcs8(key))?;
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

/// The read deadline for a control frame that should follow immediately
/// (section 5: "every read on the control and porch streams carries a
/// deadline").
#[must_use]
pub fn control_read_deadline() -> Duration {
    crate::gate::limits::CONTROL_READ_DEADLINE
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
    fn self_signed_cert_round_trips_its_key() {
        let seed = [3u8; 32];
        let (cert, _key) = self_signed_cert(&seed).unwrap();
        let extracted = extract_ed25519_public_key(&cert).unwrap();
        let key = mosschat_core::identity::AuthorKey::from_bytes(&seed);
        assert_eq!(extracted, key.public_bytes());
        verify_self_signed(&cert).unwrap();
    }
}
