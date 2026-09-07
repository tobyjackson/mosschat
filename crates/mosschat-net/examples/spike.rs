//! WO-1.2 spike: a key-authenticated QUIC connection, and the run that
//! answers two of Phase 1's open research questions (`research/nat-traversal-lessons.md`
//! section E). Throwaway quality, kept lint-clean; none of this is permanent
//! `mosschat-net` code. The gatehouse, the doorbell and real address
//! discovery are WO-1.3; this spike only proves the pieces WO-1.3 depends on:
//! an ed25519 identity presented through rustls, a pinned-key verifier, and
//! a signed nonce exchanged over `mosschat-core`'s `Signer`.
//!
//! # Run
//!
//! In one terminal:
//!
//! ```text
//! cargo run -p mosschat-net --example spike -- listen
//! ```
//!
//! It prints a ticket. In a second terminal:
//!
//! ```text
//! cargo run -p mosschat-net --example spike -- dial <ticket>
//! ```
//!
//! To reproduce the substituted-key failure case, mutate the 32 public-key
//! bytes encoded in the ticket (leaving the address alone) before dialing;
//! see [`ticket`] for the encoding. `docs/dev/spike-notes.md` cites the run
//! that answered each research question.
//!
//! # Ticket
//!
//! A ticket is `moss1` followed by unpadded RFC 4648 base32 of 32 pinned
//! public-key bytes plus a socket address (1 byte address family, 4 or 16
//! address bytes, 2 byte big-endian port). No other fields for now; the
//! gate address and other invite fields are WO-4.1's job.
//!
//! # TLS identity and the pinned verifier
//!
//! Each side presents a self-signed certificate whose key is its ed25519
//! identity (`identity::load_or_generate`, then [`cert::self_signed_cert`]).
//! The dialer's [`verify::PinnedKeyVerifier`] uses rustls's `dangerous()`
//! verifier API (`ClientConfig::dangerous().with_custom_certificate_verifier`)
//! to accept exactly the one 32-byte key from the ticket and reject every
//! other key; this is deliberate for a spike where the peer's identity is
//! already known out of band; real certificate-chain validation is not
//! wanted or meaningful here. The listener does not verify the dialer's TLS
//! certificate at all: authentication of the dialer happens at the
//! application layer instead, via the signed nonce exchange in [`handshake`].

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mosschat_core::identity::{AuthorKey, Signer, verify};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const ALPN: &[u8] = b"moss-spike";
const TICKET_PREFIX: &str = "moss1";
const PING_COUNT: usize = 100;

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("spike: error: {err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("listen") => listen().await,
        Some("dial") => {
            let ticket_str = args.next().ok_or("usage: spike dial <ticket>")?;
            dial(&ticket_str).await
        }
        _ => Err("usage: spike listen | spike dial <ticket>".into()),
    }
}

// ---------------------------------------------------------------------
// Identity and certificates
// ---------------------------------------------------------------------

mod identity {
    use mosschat_core::identity::AuthorKey;
    use rand::RngExt;

    /// Generates a fresh random ed25519 identity for this run of the spike.
    ///
    /// A real house persists its identity (D4); a spike process is
    /// throwaway, so a new key each run is correct here.
    pub fn generate() -> (AuthorKey, [u8; 32]) {
        let seed: [u8; 32] = rand::rng().random();
        let key = AuthorKey::from_bytes(&seed);
        (key, seed)
    }
}

mod cert {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    /// The fixed 16-byte PKCS#8 v1 header for an RFC 8410 Ed25519 private
    /// key, before the 32 raw seed bytes. This is a well-known, constant
    /// byte template (the same one `ring` and other libraries emit): a
    /// `PrivateKeyInfo` with algorithm OID 1.3.101.112 and an OCTET STRING
    /// wrapping the 32 byte seed. Hand-building it here avoids adding a
    /// pkcs8-encoding dependency for a spike that needs this once.
    const PKCS8_ED25519_HEADER: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];

    fn pkcs8_der(seed: &[u8; 32]) -> Vec<u8> {
        let mut der = Vec::with_capacity(48);
        der.extend_from_slice(&PKCS8_ED25519_HEADER);
        der.extend_from_slice(seed);
        der
    }

    /// Builds a self-signed certificate whose key is the given ed25519 seed,
    /// returning the certificate DER and the matching PKCS#8 private key DER.
    pub fn self_signed_cert(
        seed: &[u8; 32],
    ) -> Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>), Box<dyn std::error::Error>>
    {
        let pkcs8 = pkcs8_der(seed);
        let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(pkcs8.clone()),
            &PKCS_ED25519,
        )?;
        let params = CertificateParams::new(Vec::<String>::new())?;
        let cert = params.self_signed(&key_pair)?;
        Ok((cert.der().clone(), PrivatePkcs8KeyDer::from(pkcs8)))
    }
}

mod verify {
    use std::fmt;

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};

    /// The fixed 12-byte prefix of an RFC 8410 Ed25519 SubjectPublicKeyInfo:
    /// a `SEQUENCE` wrapping the algorithm identifier for OID 1.3.101.112
    /// and a `BIT STRING` header, immediately followed by the 32 raw public
    /// key bytes. Searching a small self-signed certificate's DER for this
    /// exact byte string is a deliberate spike shortcut in place of a real
    /// X.509 parser (not in this work order's dependency list); it works
    /// because rcgen's Ed25519 SPKI encoding is fixed and this prefix is
    /// long enough not to occur by chance elsewhere in a certificate this
    /// small.
    const SPKI_ED25519_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    fn extract_ed25519_public_key(cert_der: &[u8]) -> Option<[u8; 32]> {
        let windows = cert_der.windows(SPKI_ED25519_PREFIX.len());
        for (offset, window) in windows.enumerate() {
            if window == SPKI_ED25519_PREFIX {
                let start = offset + SPKI_ED25519_PREFIX.len();
                let end = start + 32;
                if let Some(key) = cert_der
                    .get(start..end)
                    .and_then(|slice| <[u8; 32]>::try_from(slice).ok())
                {
                    return Some(key);
                }
            }
        }
        None
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

    /// A rustls server certificate verifier that accepts exactly one pinned
    /// 32-byte ed25519 public key, taken from the ticket, and rejects every
    /// other key. Installed via `ClientConfig::dangerous()`, which is the
    /// documented escape hatch for a verifier that does not do chain-of-trust
    /// validation; that is the deliberate choice here, since the peer's key
    /// is already known from the ticket and there is no certificate
    /// authority in this system (D2, D4).
    pub struct PinnedKeyVerifier {
        pub pinned: [u8; 32],
    }

    impl fmt::Debug for PinnedKeyVerifier {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PinnedKeyVerifier").finish()
        }
    }

    impl ServerCertVerifier for PinnedKeyVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, TlsError> {
            let actual = extract_ed25519_public_key(end_entity).ok_or(
                TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding),
            )?;
            if actual != self.pinned {
                return Err(TlsError::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
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
}

// ---------------------------------------------------------------------
// The ticket
// ---------------------------------------------------------------------

mod ticket {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{TICKET_PREFIX, base32};

    /// Encodes a pinned public key and a socket address as a `moss1`-prefixed
    /// ticket string: no other fields for now.
    pub fn encode(pubkey: &[u8; 32], addr: SocketAddr) -> String {
        let mut bytes = Vec::with_capacity(32 + 1 + 16 + 2);
        bytes.extend_from_slice(pubkey);
        match addr.ip() {
            IpAddr::V4(v4) => {
                bytes.push(4);
                bytes.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                bytes.push(6);
                bytes.extend_from_slice(&v6.octets());
            }
        }
        bytes.extend_from_slice(&addr.port().to_be_bytes());
        format!("{TICKET_PREFIX}{}", base32::encode(&bytes))
    }

    /// Decodes a ticket string back into a pinned public key and address.
    pub fn decode(ticket: &str) -> Result<([u8; 32], SocketAddr), String> {
        let body = ticket
            .strip_prefix(TICKET_PREFIX)
            .ok_or_else(|| "ticket is missing the moss1 prefix".to_string())?;
        let bytes = base32::decode(body).map_err(|e| format!("ticket base32 is invalid: {e}"))?;
        if bytes.len() < 32 + 1 {
            return Err("ticket is too short".to_string());
        }
        let pubkey: [u8; 32] = bytes
            .get(..32)
            .ok_or_else(|| "ticket is too short".to_string())?
            .try_into()
            .map_err(|_| "ticket public key is malformed".to_string())?;
        let family = *bytes
            .get(32)
            .ok_or_else(|| "ticket is missing its address family byte".to_string())?;
        let (ip, rest_start): (IpAddr, usize) = match family {
            4 => {
                let octets: [u8; 4] = bytes
                    .get(33..37)
                    .ok_or_else(|| "ticket is too short for an IPv4 address".to_string())?
                    .try_into()
                    .map_err(|_| "ticket IPv4 address is malformed".to_string())?;
                (IpAddr::V4(Ipv4Addr::from(octets)), 37)
            }
            6 => {
                let octets: [u8; 16] = bytes
                    .get(33..49)
                    .ok_or_else(|| "ticket is too short for an IPv6 address".to_string())?
                    .try_into()
                    .map_err(|_| "ticket IPv6 address is malformed".to_string())?;
                (IpAddr::V6(Ipv6Addr::from(octets)), 49)
            }
            other => return Err(format!("unknown address family byte {other}")),
        };
        let port_bytes: [u8; 2] = bytes
            .get(rest_start..rest_start + 2)
            .ok_or_else(|| "ticket is missing its port".to_string())?
            .try_into()
            .map_err(|_| "ticket port is malformed".to_string())?;
        let port = u16::from_be_bytes(port_bytes);
        Ok((pubkey, SocketAddr::new(ip, port)))
    }
}

mod base32 {
    //! A minimal RFC 4648 base32 codec, unpadded. Not a dependency because
    //! none of WO-1.2's listed dependencies cover it and the ticket is a
    //! handful of bytes; WO-4.1 picks the real invite ticket encoding.
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    pub fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
        let mut buf: u32 = 0;
        let mut bits = 0u32;
        for &byte in data {
            buf = (buf << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                let idx = ((buf >> bits) & 0x1f) as usize;
                #[allow(clippy::indexing_slicing)]
                out.push(ALPHABET[idx] as char);
            }
        }
        if bits > 0 {
            let idx = ((buf << (5 - bits)) & 0x1f) as usize;
            #[allow(clippy::indexing_slicing)]
            out.push(ALPHABET[idx] as char);
        }
        out
    }

    pub fn decode(text: &str) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(text.len() * 5 / 8);
        let mut buf: u32 = 0;
        let mut bits = 0u32;
        for ch in text.chars() {
            let upper = ch.to_ascii_uppercase();
            let value = ALPHABET
                .iter()
                .position(|&c| c == upper as u8)
                .ok_or_else(|| format!("invalid base32 character {ch:?}"))?;
            buf = (buf << 5) | value as u32;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push(((buf >> bits) & 0xff) as u8);
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------
// The signed nonce exchange
// ---------------------------------------------------------------------

mod handshake {
    use super::*;
    use rand::RngExt;

    /// One side's outcome of the signed nonce exchange: the nonce it sent,
    /// signed and verified by the peer, and the nonce it received, signed
    /// and verified locally.
    pub struct Outcome {
        pub sent_nonce: [u8; 32],
        pub received_nonce: [u8; 32],
    }

    /// Runs the initiator half of the exchange: send a nonce, receive the
    /// peer's signature over it plus the peer's own nonce, verify against
    /// `peer_pinned`, then sign the peer's nonce and send it back with our
    /// own public key.
    pub async fn initiator(
        send: &mut SendStream,
        recv: &mut RecvStream,
        key: &AuthorKey,
        peer_pinned: &[u8; 32],
    ) -> Result<Outcome, Box<dyn Error>> {
        let sent_nonce: [u8; 32] = rand::rng().random();
        send.write_all(&sent_nonce).await?;

        let mut peer_reply = [0u8; 96];
        recv.read_exact(&mut peer_reply).await?;
        #[allow(clippy::indexing_slicing)]
        let sig_over_sent: [u8; 64] = peer_reply[0..64].try_into()?;
        #[allow(clippy::indexing_slicing)]
        let received_nonce: [u8; 32] = peer_reply[64..96].try_into()?;
        verify(peer_pinned, &sent_nonce, &sig_over_sent)?;

        let sig_over_received = key.sign(&received_nonce);
        let mut reply = Vec::with_capacity(96);
        reply.extend_from_slice(&sig_over_received);
        reply.extend_from_slice(&key.public_bytes());
        send.write_all(&reply).await?;

        Ok(Outcome {
            sent_nonce,
            received_nonce,
        })
    }

    /// Runs the responder half: receive a nonce, sign it and send it back
    /// with our own nonce, then receive the peer's signature and public key
    /// over our nonce and verify.
    pub async fn responder(
        send: &mut SendStream,
        recv: &mut RecvStream,
        key: &AuthorKey,
    ) -> Result<Outcome, Box<dyn Error>> {
        let mut received_nonce = [0u8; 32];
        recv.read_exact(&mut received_nonce).await?;

        let sig_over_received = key.sign(&received_nonce);
        let sent_nonce: [u8; 32] = rand::rng().random();
        let mut reply = Vec::with_capacity(96);
        reply.extend_from_slice(&sig_over_received);
        reply.extend_from_slice(&sent_nonce);
        send.write_all(&reply).await?;

        let mut peer_reply = [0u8; 96];
        recv.read_exact(&mut peer_reply).await?;
        #[allow(clippy::indexing_slicing)]
        let sig_over_sent: [u8; 64] = peer_reply[0..64].try_into()?;
        #[allow(clippy::indexing_slicing)]
        let peer_pubkey: [u8; 32] = peer_reply[64..96].try_into()?;
        verify(&peer_pubkey, &sent_nonce, &sig_over_sent)?;

        Ok(Outcome {
            sent_nonce,
            received_nonce,
        })
    }
}

// ---------------------------------------------------------------------
// RTT measurement
// ---------------------------------------------------------------------

struct Stats {
    median_ms: f64,
    p95_ms: f64,
}

fn summarize(mut samples: Vec<Duration>) -> Stats {
    samples.sort_unstable();
    let median = percentile(&samples, 0.50);
    let p95 = percentile(&samples, 0.95);
    Stats {
        median_ms: median.as_secs_f64() * 1000.0,
        p95_ms: p95.as_secs_f64() * 1000.0,
    }
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    let idx = rank.min(sorted.len() - 1);
    sorted.get(idx).copied().unwrap_or(Duration::ZERO)
}

async fn ping_client(
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<Stats, Box<dyn Error>> {
    let mut samples = Vec::with_capacity(PING_COUNT);
    for i in 0..PING_COUNT as u64 {
        let start = Instant::now();
        send.write_all(&i.to_le_bytes()).await?;
        let mut echo = [0u8; 8];
        recv.read_exact(&mut echo).await?;
        if u64::from_le_bytes(echo) != i {
            return Err("ping echo did not match".into());
        }
        samples.push(start.elapsed());
    }
    send.write_all(&u64::MAX.to_le_bytes()).await?;
    Ok(summarize(samples))
}

async fn pong_server(send: &mut SendStream, recv: &mut RecvStream) -> Result<(), Box<dyn Error>> {
    loop {
        let mut buf = [0u8; 8];
        recv.read_exact(&mut buf).await?;
        let value = u64::from_le_bytes(buf);
        if value == u64::MAX {
            return Ok(());
        }
        send.write_all(&buf).await?;
    }
}

// ---------------------------------------------------------------------
// TLS and QUIC endpoint setup
// ---------------------------------------------------------------------

fn install_crypto_provider() {
    // ring, to match rcgen's default "ring" feature: one TLS crypto
    // backend in this binary rather than two.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn server_endpoint(
    cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
) -> Result<Endpoint, Box<dyn Error>> {
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], PrivateKeyDer::Pkcs8(key))?;
    tls_config.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = QuicServerConfig::try_from(tls_config)?;
    let server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    let bind_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    Ok(Endpoint::server(server_config, bind_addr)?)
}

fn client_endpoint(pinned: [u8; 32]) -> Result<Endpoint, Box<dyn Error>> {
    let verifier = Arc::new(verify::PinnedKeyVerifier { pinned });
    let mut tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = QuicClientConfig::try_from(tls_config)?;
    let client_config = ClientConfig::new(Arc::new(quic_crypto));
    let bind_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

// ---------------------------------------------------------------------
// listen / dial
// ---------------------------------------------------------------------

async fn listen() -> Result<(), Box<dyn Error>> {
    install_crypto_provider();
    let (key, seed) = identity::generate();
    let (cert_der, key_der) = cert::self_signed_cert(&seed)?;
    let endpoint = server_endpoint(cert_der, key_der)?;
    let local_addr = endpoint.local_addr()?;
    let public = key.public_bytes();
    println!("spike: listening on {local_addr}");
    println!("spike: ticket: {}", ticket::encode(&public, local_addr));

    loop {
        let Some(incoming) = endpoint.accept().await else {
            return Ok(());
        };
        let key_bytes = seed;
        tokio::spawn(async move {
            let author_key = AuthorKey::from_bytes(&key_bytes);
            if let Err(err) = handle_connection(incoming, author_key).await {
                eprintln!("spike: connection error: {err}");
            }
        });
    }
}

async fn handle_connection(
    incoming: quinn::Incoming,
    key: AuthorKey,
) -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let connection = incoming.accept()?.await?;
    println!(
        "spike: accepted connection from {} in {:.2} ms",
        connection.remote_address(),
        start.elapsed().as_secs_f64() * 1000.0
    );
    let (mut send, mut recv) = connection.accept_bi().await?;
    let outcome = handshake::responder(&mut send, &mut recv, &key).await?;
    println!(
        "spike: nonce_from_peer={} nonce_to_peer={}",
        hex(&outcome.received_nonce),
        hex(&outcome.sent_nonce)
    );
    pong_server(&mut send, &mut recv).await?;
    send.finish()?;
    Ok(())
}

async fn dial(ticket_str: &str) -> Result<(), Box<dyn Error>> {
    install_crypto_provider();
    let (pinned, addr) = ticket::decode(ticket_str)?;
    let (key, _seed) = identity::generate();
    let endpoint = client_endpoint(pinned)?;

    let start = Instant::now();
    let connecting = endpoint.connect(addr, "spike")?;
    let connection = connecting.await?;
    let handshake_time = start.elapsed();
    println!(
        "spike: connected to {} handshake_time={:.2} ms",
        connection.remote_address(),
        handshake_time.as_secs_f64() * 1000.0
    );

    let (mut send, mut recv) = connection.open_bi().await?;
    let outcome = handshake::initiator(&mut send, &mut recv, &key, &pinned).await?;
    println!(
        "spike: nonce_to_peer={} nonce_from_peer={}",
        hex(&outcome.sent_nonce),
        hex(&outcome.received_nonce)
    );

    let stats = ping_client(&mut send, &mut recv).await?;
    send.finish()?;
    println!(
        "spike: {PING_COUNT} pings: rtt_median={:.2} ms rtt_p95={:.2} ms",
        stats.median_ms, stats.p95_ms
    );

    let session_id = blake3::hash(&[key.public_bytes(), pinned].concat());
    println!("spike: session {}", &session_id.to_hex()[..8]);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
