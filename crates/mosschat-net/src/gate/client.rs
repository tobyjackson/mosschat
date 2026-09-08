//! The house side of the gate protocol (`docs/dev/gatehouse-design.md`
//! section 1): registering, reflecting, sealing an `Introduce`, and
//! answering a `Knock` against the local friend list and outstanding
//! invites.
//!
//! Both lists are simple in-memory stores behind a small trait for this
//! work order ([`FriendStore`], [`InviteStore`]): the real encrypted store
//! arrives in Phase 2 (D6), and nothing here assumes more about it than
//! "does this key belong to a friend" and "does this proof redeem an
//! outstanding invite".

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use ed25519_dalek::SigningKey as RawSigningKey;
use mosschat_core::identity::{AuthorKey, verify};
use quinn::crypto::rustls::QuicServerConfig;
use rand::RngExt;
use tokio::sync::{Mutex as AsyncMutex, oneshot};

use crate::authed::{self, AuthedConnection};
use crate::gate::wire::{self, Addr, Frame};
use crate::gate::{GateError, SeenSet, now_ms, within_freshness_window};
use crate::lockext::LockExt;
use crate::sock::{self, PorchSocket};

const ALPN: &[u8] = b"moss-gate";

/// A friend list, in the shape [`GateClient`] needs: only "is this key a
/// friend". A real store also knows names and events; that is Phase 2's.
pub trait FriendStore: Send + Sync {
    /// Whether `key` belongs to a friend.
    fn is_friend(&self, key: &[u8; 32]) -> bool;
}

/// An in-memory [`FriendStore`], usable directly in tests and as the
/// concrete type until Phase 2's store lands.
#[derive(Debug, Default)]
pub struct InMemoryFriendStore(StdMutex<HashSet<[u8; 32]>>);

impl InMemoryFriendStore {
    /// Builds an empty friend store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `key` as a friend.
    pub fn add(&self, key: [u8; 32]) {
        self.0.lock_or_recover().insert(key);
    }
}

impl FriendStore for InMemoryFriendStore {
    fn is_friend(&self, key: &[u8; 32]) -> bool {
        self.0.lock_or_recover().contains(key)
    }
}

/// One outstanding invite this house issued: the hash of its secret, its
/// expiry, and whether it has already been redeemed (single use).
#[derive(Debug)]
struct InviteRecord {
    expires_ms: u64,
    redeemed: bool,
}

/// An outstanding-invite list, in the shape [`GateClient`] needs: redeem
/// against a secret and a bind, once.
pub trait InviteStore: Send + Sync {
    /// Checks `secret` and `bind` against an outstanding, unexpired,
    /// unredeemed invite, marking it redeemed on success. `gate_key` is the
    /// identity key of the gate this knock arrived through, which the bind
    /// must cover (section 1: "useless at another gate").
    fn try_redeem(
        &self,
        secret: &[u8; 32],
        bind: &[u8; 32],
        my_key: &[u8; 32],
        gate_key: &[u8; 32],
    ) -> bool;
}

/// An in-memory [`InviteStore`].
#[derive(Debug, Default)]
pub struct InMemoryInviteStore(StdMutex<HashMap<[u8; 32], InviteRecord>>);

impl InMemoryInviteStore {
    /// Builds an empty invite store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues an invite for `secret`, expiring at `expires_ms`.
    pub fn issue(&self, secret: &[u8; 32], expires_ms: u64) {
        let hash = *blake3::hash(secret).as_bytes();
        self.0.lock_or_recover().insert(
            hash,
            InviteRecord {
                expires_ms,
                redeemed: false,
            },
        );
    }
}

/// Computes `bind = BLAKE3("mosschat-invite-bind-v1" || secret || my_key || gate_key)`
/// (section 1).
#[must_use]
pub fn invite_bind(secret: &[u8; 32], my_key: &[u8; 32], gate_key: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(21 + 32 + 32 + 32);
    input.extend_from_slice(b"mosschat-invite-bind-v1");
    input.extend_from_slice(secret);
    input.extend_from_slice(my_key);
    input.extend_from_slice(gate_key);
    *blake3::hash(&input).as_bytes()
}

impl InviteStore for InMemoryInviteStore {
    fn try_redeem(
        &self,
        secret: &[u8; 32],
        bind: &[u8; 32],
        my_key: &[u8; 32],
        gate_key: &[u8; 32],
    ) -> bool {
        let expected_bind = invite_bind(secret, my_key, gate_key);
        if *bind != expected_bind {
            return false;
        }
        let hash = *blake3::hash(secret).as_bytes();
        let mut invites = self.0.lock_or_recover();
        let Some(record) = invites.get_mut(&hash) else {
            return false;
        };
        if record.redeemed || now_ms() > record.expires_ms {
            return false;
        }
        record.redeemed = true;
        true
    }
}

/// The proof carried in a first-contact `Introduce` sealed body.
#[derive(Debug, Clone)]
pub struct InviteProof {
    /// The invite's 16 byte id.
    pub id: [u8; 16],
    /// The invite's 32 byte secret.
    pub secret: [u8; 32],
    /// `invite_bind(secret, my_key, gate_key)`, precomputed by the asker
    /// against the specific gate it is knocking through.
    pub bind: [u8; 32],
}

/// The sealed introduction body of section 1: `v`, `from`, `sent_ms`, and an
/// optional [`InviteProof`] for first contact.
struct SealedBody {
    from: [u8; 32],
    sent_ms: u64,
    invite: Option<InviteProof>,
}

/// Sealing and opening the `Introduce.sealed` / `Knock.sealed` body: an
/// ephemeral X25519 public key, then ChaCha20-Poly1305 over a small CBOR
/// body under `BLAKE3::derive_key("mosschat-introduce-seal-v1", dh ||
/// eph_pub || kB)` (section 1). The nonce is fixed at all zero bytes: the
/// key is unique per seal (a fresh ephemeral key every time), so nonce
/// reuse under a repeated key never happens.
mod seal {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use minicbor::{Decoder, Encoder};
    use rand::RngExt;

    use super::SealedBody;
    use crate::gate::GateError;

    const DOMAIN: &str = "mosschat-introduce-seal-v1";
    const ZERO_NONCE: [u8; 12] = [0u8; 12];

    fn derive_key(dh: &[u8; 32], eph_pub: &[u8; 32], recipient: &[u8; 32]) -> [u8; 32] {
        let mut material = Vec::with_capacity(96);
        material.extend_from_slice(dh);
        material.extend_from_slice(eph_pub);
        material.extend_from_slice(recipient);
        blake3::derive_key(DOMAIN, &material)
    }

    fn encode_body(body: &SealedBody) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        #[allow(clippy::unwrap_used)]
        {
            match &body.invite {
                Some(invite) => {
                    enc.array(6).unwrap();
                    enc.u8(1).unwrap();
                    enc.bytes(&body.from).unwrap();
                    enc.u64(body.sent_ms).unwrap();
                    enc.bytes(&invite.id).unwrap();
                    enc.bytes(&invite.secret).unwrap();
                    enc.bytes(&invite.bind).unwrap();
                }
                None => {
                    enc.array(3).unwrap();
                    enc.u8(1).unwrap();
                    enc.bytes(&body.from).unwrap();
                    enc.u64(body.sent_ms).unwrap();
                }
            }
        }
        buf
    }

    fn decode_body(bytes: &[u8]) -> Result<SealedBody, GateError> {
        let mut dec = Decoder::new(bytes);
        let len = dec
            .array()
            .map_err(|e| GateError::Protocol(e.to_string()))?
            .ok_or_else(|| GateError::Protocol("sealed body must be a definite array".into()))?;
        let _v = dec.u8().map_err(|e| GateError::Protocol(e.to_string()))?;
        let from: [u8; 32] = dec
            .bytes()
            .map_err(|e| GateError::Protocol(e.to_string()))?
            .try_into()
            .map_err(|_| GateError::Protocol("bad from key length".into()))?;
        let sent_ms = dec.u64().map_err(|e| GateError::Protocol(e.to_string()))?;
        let invite = if len == 6 {
            let id: [u8; 16] = dec
                .bytes()
                .map_err(|e| GateError::Protocol(e.to_string()))?
                .try_into()
                .map_err(|_| GateError::Protocol("bad invite id length".into()))?;
            let secret: [u8; 32] = dec
                .bytes()
                .map_err(|e| GateError::Protocol(e.to_string()))?
                .try_into()
                .map_err(|_| GateError::Protocol("bad invite secret length".into()))?;
            let bind: [u8; 32] = dec
                .bytes()
                .map_err(|e| GateError::Protocol(e.to_string()))?
                .try_into()
                .map_err(|_| GateError::Protocol("bad invite bind length".into()))?;
            Some(super::InviteProof { id, secret, bind })
        } else {
            None
        };
        Ok(SealedBody {
            from,
            sent_ms,
            invite,
        })
    }

    /// Seals `body` to `recipient`'s ed25519 public key (converted to
    /// Montgomery form for the DH, per `VerifyingKey::to_montgomery`).
    ///
    /// # Errors
    ///
    /// Returns [`GateError::Protocol`] if `recipient` is not a well-formed
    /// ed25519 point, or if encryption fails.
    pub fn seal(body: &SealedBody, recipient: &[u8; 32]) -> Result<Vec<u8>, GateError> {
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(recipient).map_err(|_| {
            GateError::Protocol("recipient key is not a valid ed25519 point".into())
        })?;
        let recipient_montgomery = verifying.to_montgomery();

        let eph_secret: [u8; 32] = rand::rng().random();
        let eph_pub = MontgomeryPoint::mul_base_clamped(eph_secret).to_bytes();
        let dh = recipient_montgomery.mul_clamped(eph_secret).to_bytes();
        let key_bytes = derive_key(&dh, &eph_pub, recipient);

        let cipher = ChaCha20Poly1305::new((&key_bytes).into());
        let plaintext = encode_body(body);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&ZERO_NONCE), plaintext.as_ref())
            .map_err(|_| GateError::Protocol("seal encryption failed".into()))?;

        let mut out = Vec::with_capacity(32 + ciphertext.len());
        out.extend_from_slice(&eph_pub);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens `sealed` with the recipient's raw ed25519 signing key (whose
    /// `to_scalar_bytes()` is the X25519 scalar `mul_clamped` needs, per
    /// `VerifyingKey::to_montgomery`'s own doc).
    ///
    /// # Errors
    ///
    /// Returns [`GateError::Protocol`] if `sealed` is too short or does not
    /// decrypt or decode.
    pub fn open(
        sealed: &[u8],
        recipient_signing: &ed25519_dalek::SigningKey,
    ) -> Result<SealedBody, GateError> {
        if sealed.len() < 32 + 16 {
            return Err(GateError::Protocol("sealed body too short".into()));
        }
        #[allow(clippy::indexing_slicing)]
        let eph_pub: [u8; 32] = sealed[..32].try_into().unwrap_or([0; 32]);
        #[allow(clippy::indexing_slicing)]
        let ciphertext = &sealed[32..];

        let eph_point = MontgomeryPoint(eph_pub);
        let recipient_scalar = recipient_signing.to_scalar_bytes();
        let dh = eph_point.mul_clamped(recipient_scalar).to_bytes();
        let recipient_key = recipient_signing.verifying_key().to_bytes();
        let key_bytes = derive_key(&dh, &eph_pub, &recipient_key);

        let cipher = ChaCha20Poly1305::new((&key_bytes).into());
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&ZERO_NONCE), ciphertext)
            .map_err(|_| GateError::Protocol("seal did not open".into()))?;
        decode_body(&plaintext)
    }
}

/// The outcome of a successful [`GateClient::introduce`] call.
#[derive(Debug, Clone)]
pub struct IntroduceOutcome {
    /// The session id the gate assigned.
    pub session: u32,
    /// The peer's most recent observed address at the gate.
    pub peer_observed: Addr,
    /// `1` if this house is the initiator, `2` if the responder.
    pub role: u8,
}

struct Inner {
    endpoint: quinn::Endpoint,
    porch: Arc<PorchSocket>,
    gate: AuthedConnection,
    control_send: AsyncMutex<quinn::SendStream>,
    identity_key: AuthorKey,
    signing_key: RawSigningKey,
    community: [u8; 32],
    process_salt: [u8; 5],
    introductions: StdMutex<HashMap<[u8; 32], oneshot::Sender<IntroduceOutcome>>>,
    /// `tag -> peer key`, recorded when this house accepts a `Knock`
    /// (`answer_knock`), so that when the matching `Introduction` arrives
    /// this house (the responder) knows which peer's synthetic address to
    /// register the relay session against; the asker already knows this
    /// from its own `introduce` call and does not consult this map.
    pending_accepts: StdMutex<HashMap<[u8; 32], [u8; 32]>>,
    friends: Arc<dyn FriendStore>,
    invites: Arc<dyn InviteStore>,
    seen: StdMutex<SeenSet>,
    auto_answer_knocks: std::sync::atomic::AtomicBool,
}

/// A house's connection to one gate: registered, able to seal and send an
/// `Introduce`, and answering incoming `Knock`s from its own background
/// task against `friends` and `invites`.
pub struct GateClient {
    inner: Arc<Inner>,
}

impl GateClient {
    /// Connects to the gate at `primary_addr`, registers for `community`,
    /// and starts the background reader that answers incoming `Knock`s.
    ///
    /// `expected_gate_key`, if given, pins the gate: the TLS-proven key the
    /// handshake actually produces must equal it, or the connection is
    /// refused before `Register` is ever sent (Yseult finding 8: previously
    /// `connect` took no expected key at all and never checked
    /// `peer_key()`, though `authed.rs`'s own doc says the caller does).
    /// `None` is trust-on-first-connect, for a caller (a fresh gate join)
    /// that has no key to pin against yet.
    ///
    /// # Errors
    ///
    /// Returns a [`GateError`] if the socket cannot be bound, the TLS
    /// handshake fails, the connected gate's key does not match
    /// `expected_gate_key`, or the gate refuses the registration.
    pub async fn connect(
        primary_addr: std::net::SocketAddr,
        identity_seed: [u8; 32],
        community: [u8; 32],
        expected_gate_key: Option<[u8; 32]>,
        friends: Arc<dyn FriendStore>,
        invites: Arc<dyn InviteStore>,
    ) -> Result<Self, GateError> {
        authed::install_crypto_provider();
        let (cert, key) = authed::self_signed_cert(&identity_seed)
            .map_err(|e| GateError::Protocol(e.to_string()))?;
        let client_tls = authed::client_tls_config(cert.clone(), key, ALPN)
            .map_err(|e| GateError::Protocol(e.to_string()))?;
        let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)?;
        let client_config = quinn::ClientConfig::new(Arc::new(quic_client));

        // A second self-signed cert/key pair for the server half (peer
        // connections this house later accepts as a responder); same
        // identity, rebuilt because `rustls::ServerConfig` and
        // `ClientConfig` each need their own owned certificate value.
        let (server_cert, server_key) = authed::self_signed_cert(&identity_seed)
            .map_err(|e| GateError::Protocol(e.to_string()))?;
        let server_tls = authed::server_tls_config(server_cert, server_key, ALPN)
            .map_err(|e| GateError::Protocol(e.to_string()))?;
        let quic_server = QuicServerConfig::try_from(server_tls)?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server));

        // Bound as IPv6 unspecified, not IPv4: `PorchSocket` (via
        // `quinn::udp::UdpSocketState`) configures this dual-stack, so one
        // socket reaches both the gate's real address (v4 or v6) and this
        // house's IPv6 synthetic peer addresses (section 3).
        let std_socket = std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0))?;
        let porch = PorchSocket::new(std_socket)?;
        let runtime: Arc<dyn quinn::Runtime> =
            Arc::new(quinn::TokioRuntime).clone() as Arc<dyn quinn::Runtime>;
        let endpoint_config = quinn::EndpointConfig::default();
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            Arc::clone(&porch) as Arc<dyn quinn::AsyncUdpSocket>,
            runtime,
        )?;
        endpoint.set_default_client_config(client_config);

        let connecting = endpoint.connect(primary_addr, "gate")?;
        let connection = connecting.await?;
        let authed_conn = AuthedConnection::new(connection)?;
        if let Some(expected) = expected_gate_key
            && authed_conn.peer_key() != expected
        {
            authed_conn
                .connection()
                .close(0u32.into(), b"gate key does not match the pinned key");
            return Err(GateError::InvalidIdentity(
                "connected gate's TLS-proven key does not match the pinned expected key".into(),
            ));
        }
        porch.attach_gate(authed_conn.connection().clone());

        let (mut send, mut recv) = authed_conn.connection().open_bi().await?;
        wire::write_frame(&mut send, &Frame::Register { v: 1, community }).await?;
        let reply = wire::read_frame(&mut recv, authed::control_read_deadline()).await?;
        match reply {
            Frame::Registered { .. } => {}
            Frame::Error { code, detail, .. } => {
                return Err(GateError::Protocol(format!(
                    "gate refused registration: code={code} detail={detail}"
                )));
            }
            other => {
                return Err(GateError::Protocol(format!(
                    "expected Registered or Error, got {other:?}"
                )));
            }
        }

        let signing_key = RawSigningKey::from_bytes(&identity_seed);
        let identity_key = AuthorKey::from_bytes(&identity_seed);
        let mut process_salt = [0u8; 5];
        rand::rng().fill(&mut process_salt);

        let inner = Arc::new(Inner {
            endpoint,
            porch,
            gate: authed_conn,
            control_send: AsyncMutex::new(send),
            identity_key,
            signing_key,
            community,
            process_salt,
            introductions: StdMutex::new(HashMap::new()),
            pending_accepts: StdMutex::new(HashMap::new()),
            friends,
            invites,
            seen: StdMutex::new(SeenSet::new()),
            auto_answer_knocks: std::sync::atomic::AtomicBool::new(true),
        });

        let reader_inner = Arc::clone(&inner);
        tokio::spawn(async move {
            reader_loop(reader_inner, recv).await;
        });

        Ok(Self { inner })
    }

    /// This house's public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.inner.identity_key.public_bytes()
    }

    /// The gate's TLS-proven public key.
    #[must_use]
    pub fn gate_key(&self) -> [u8; 32] {
        self.inner.gate.peer_key()
    }

    /// The underlying gate control connection, for tests that need to read
    /// connection-level facts such as `max_datagram_size()`.
    #[must_use]
    pub fn gate_connection(&self) -> &quinn::Connection {
        self.inner.gate.connection()
    }

    /// The quinn endpoint backing this client, shared by the gate
    /// connection and every relayed peer connection.
    #[must_use]
    pub fn endpoint(&self) -> quinn::Endpoint {
        self.inner.endpoint.clone()
    }

    /// The porch socket backing [`Self::endpoint`].
    #[must_use]
    pub fn porch(&self) -> Arc<PorchSocket> {
        Arc::clone(&self.inner.porch)
    }

    /// The stable synthetic address this house's porch socket presents for
    /// `peer_key` (section 3).
    #[must_use]
    pub fn synthetic_addr_for(&self, peer_key: &[u8; 32]) -> std::net::SocketAddr {
        sock::synthetic_addr(self.inner.process_salt, peer_key)
    }

    /// Disables this client's automatic `Knock` answering, so a test can
    /// simulate a house that never answers a knock at all (distinct from
    /// one that answers and declines).
    pub fn stop_answering_knocks(&self) {
        self.inner
            .auto_answer_knocks
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Sends `Keepalive` on the control stream.
    ///
    /// # Errors
    ///
    /// Returns a [`GateError`] if the write fails.
    pub async fn keepalive(&self) -> Result<(), GateError> {
        let mut send = self.inner.control_send.lock().await;
        wire::write_frame(&mut send, &Frame::Keepalive { v: 1 }).await
    }

    /// Sends `Goodbye` and closes the gate connection.
    ///
    /// # Errors
    ///
    /// Returns a [`GateError`] if the write fails.
    pub async fn goodbye(&self, reason: u8) -> Result<(), GateError> {
        let mut send = self.inner.control_send.lock().await;
        wire::write_frame(&mut send, &Frame::Goodbye { v: 1, reason }).await?;
        self.inner.gate.connection().close(0u32.into(), b"goodbye");
        Ok(())
    }

    /// Reflects off the gate's secondary port, returning the address it
    /// observed.
    ///
    /// # Errors
    ///
    /// Returns a [`GateError`] if the connection or exchange fails.
    pub async fn reflect(&self, secondary_addr: std::net::SocketAddr) -> Result<Addr, GateError> {
        let connecting = self.inner.endpoint.connect(secondary_addr, "gate")?;
        let connection = connecting.await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        wire::write_frame(&mut send, &Frame::Reflect { v: 1 }).await?;
        let reply = wire::read_frame(&mut recv, authed::control_read_deadline()).await?;
        // Closes promptly so the gate's secondary-port handler (which waits
        // for this before dropping its own `Connection`, see `server.rs`)
        // does not sit on its bounded wait for no reason.
        connection.close(0u32.into(), b"reflect done");
        match reply {
            Frame::Reflected { observed, .. } => Ok(observed),
            other => Err(GateError::Protocol(format!(
                "expected Reflected, got {other:?}"
            ))),
        }
    }

    /// Seals and sends an `Introduce` naming `peer_key`, then waits up to
    /// `ttl_s` for a matching `Introduction`.
    ///
    /// # Errors
    ///
    /// Returns [`GateError::Protocol`] with `"introduce_timeout"` if no
    /// `Introduction` arrives before `ttl_s` elapses (section 7: a tag
    /// matching nobody, a decline and a never-answered knock are one
    /// silence, and this is the only reason the asker ever sees).
    pub async fn introduce(
        &self,
        peer_key: [u8; 32],
        ttl_s: u16,
        invite: Option<InviteProof>,
    ) -> Result<IntroduceOutcome, GateError> {
        let tag = pair_tag(&self.inner.community, &self.public_key(), &peer_key);
        let body = SealedBody {
            from: self.public_key(),
            sent_ms: now_ms(),
            invite,
        };
        let sealed = seal::seal(&body, &peer_key)?;

        let (tx, rx) = oneshot::channel();
        {
            self.inner.introductions.lock_or_recover().insert(tag, tx);
        }

        {
            let mut send = self.inner.control_send.lock().await;
            wire::write_frame(
                &mut send,
                &Frame::Introduce {
                    v: 1,
                    tag,
                    ttl_s,
                    sealed,
                },
            )
            .await?;
        }

        match tokio::time::timeout(Duration::from_secs(u64::from(ttl_s)), rx).await {
            Ok(Ok(outcome)) => {
                self.inner
                    .porch
                    .register_relay_session(outcome.session, self.synthetic_addr_for(&peer_key));
                Ok(outcome)
            }
            _ => {
                self.inner.introductions.lock_or_recover().remove(&tag);
                Err(GateError::Protocol("introduce_timeout".into()))
            }
        }
    }
}

/// `BLAKE3("mosschat-gate-pair-v1" || community || min(kA,kB) || max(kA,kB))`
/// (section 1).
#[must_use]
pub fn pair_tag(community: &[u8; 32], a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut input = Vec::with_capacity(22 + 32 + 32 + 32);
    input.extend_from_slice(b"mosschat-gate-pair-v1");
    input.extend_from_slice(community);
    input.extend_from_slice(lo);
    input.extend_from_slice(hi);
    *blake3::hash(&input).as_bytes()
}

async fn reader_loop(inner: Arc<Inner>, mut recv: quinn::RecvStream) {
    loop {
        let frame = match wire::read_frame(&mut recv, Duration::from_secs(3600)).await {
            Ok(f) => f,
            Err(_) => return,
        };
        match frame {
            Frame::Introduction {
                tag,
                session,
                peer_observed,
                role,
                ..
            } => {
                let sender = { inner.introductions.lock_or_recover().remove(&tag) };
                if let Some(sender) = sender {
                    // The asker: `introduce` itself registers the relay
                    // route once the outcome reaches it, since it already
                    // knows the peer key it asked for.
                    let _ = sender.send(IntroduceOutcome {
                        session,
                        peer_observed,
                        role,
                    });
                } else {
                    // The responder: recover the peer key this `tag`'s
                    // accepted `Knock` came from, and register the relay
                    // route ourselves, since `Introduction` carries no key.
                    let peer_key = { inner.pending_accepts.lock_or_recover().remove(&tag) };
                    if let Some(peer_key) = peer_key {
                        inner.porch.register_relay_session(
                            session,
                            sock::synthetic_addr(inner.process_salt, &peer_key),
                        );
                    }
                }
            }
            Frame::Knock { tag, sealed, .. } => {
                if inner
                    .auto_answer_knocks
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    answer_knock(&inner, tag, sealed).await;
                }
            }
            Frame::KeepaliveAck { .. } | Frame::Error { .. } => {}
            _ => {}
        }
    }
}

async fn answer_knock(inner: &Arc<Inner>, tag: [u8; 32], sealed: Vec<u8>) {
    // Corrected reading of issue #16 (`gate/mod.rs`'s module doc): the seen
    // set is charged only once a sealed body has opened *and* verified --
    // decrypted, within its freshness window, and its pair tag matches --
    // never before. Charging it on every `Knock` delivered (the previous
    // order here) let anyone able to deliver a knock, opening or not, fill
    // a target's seen set on its behalf; charging it only once the friend
    // or invite decision is also made would instead let a captured, still
    // fresh seal replay against the exact same acceptance decision inside
    // the window, which section 1 says the set must prevent.
    let Ok(body) = seal::open(&sealed, &inner.signing_key) else {
        return;
    };
    if !within_freshness_window(body.sent_ms, now_ms()) {
        return;
    }
    if pair_tag(
        &inner.community,
        &body.from,
        &inner.identity_key.public_bytes(),
    ) != tag
    {
        return;
    }

    let fresh = {
        let mut seen = inner.seen.lock_or_recover();
        seen.accept(&sealed)
    };
    if !fresh {
        return;
    }

    let accept = if inner.friends.is_friend(&body.from) {
        true
    } else if let Some(invite) = &body.invite {
        inner.invites.try_redeem(
            &invite.secret,
            &invite.bind,
            &inner.identity_key.public_bytes(),
            &inner.gate.peer_key(),
        )
    } else {
        false
    };

    if !accept {
        // A stranger with no proof, or a spent invite: silence, per section
        // 1, never an explicit decline.
        return;
    }

    {
        inner
            .pending_accepts
            .lock_or_recover()
            .insert(tag, body.from);
    }

    let mut send = inner.control_send.lock().await;
    let _ = wire::write_frame(
        &mut send,
        &Frame::KnockAnswer {
            v: 1,
            tag,
            accept: true,
        },
    )
    .await;
}

/// Verifies `msg` was signed by `signer_key` under `sig`, delegating to
/// `mosschat_core::identity::verify` so the one verification path in this
/// crate goes through the audited implementation (`verify_strict`, low
/// order key rejection) rather than a second copy.
///
/// # Errors
///
/// Returns [`GateError::Protocol`] if verification fails.
pub fn verify_signature(
    signer_key: &[u8; 32],
    msg: &[u8],
    sig: &[u8; 64],
) -> Result<(), GateError> {
    verify(signer_key, msg, sig).map_err(|e| GateError::Protocol(e.to_string()))
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
    fn seal_and_open_round_trip_a_friend_body() {
        let recipient_seed = [11u8; 32];
        let recipient_signing = RawSigningKey::from_bytes(&recipient_seed);
        let recipient_key = recipient_signing.verifying_key().to_bytes();

        let body = SealedBody {
            from: [3u8; 32],
            sent_ms: now_ms(),
            invite: None,
        };
        let sealed = seal::seal(&body, &recipient_key).unwrap();
        let opened = seal::open(&sealed, &recipient_signing).unwrap();
        assert_eq!(opened.from, body.from);
        assert_eq!(opened.sent_ms, body.sent_ms);
        assert!(opened.invite.is_none());
    }

    #[test]
    fn seal_and_open_round_trip_an_invite_body() {
        let recipient_seed = [12u8; 32];
        let recipient_signing = RawSigningKey::from_bytes(&recipient_seed);
        let recipient_key = recipient_signing.verifying_key().to_bytes();

        let invite = InviteProof {
            id: [1u8; 16],
            secret: [2u8; 32],
            bind: [3u8; 32],
        };
        let body = SealedBody {
            from: [4u8; 32],
            sent_ms: now_ms(),
            invite: Some(invite.clone()),
        };
        let sealed = seal::seal(&body, &recipient_key).unwrap();
        let opened = seal::open(&sealed, &recipient_signing).unwrap();
        let opened_invite = opened.invite.unwrap();
        assert_eq!(opened_invite.secret, invite.secret);
        assert_eq!(opened_invite.bind, invite.bind);
    }

    /// Yseult finding 10: `seal::decode_body` (reached only after a
    /// successful decrypt) had no malformed-input test either. A sealed
    /// body shorter than the fixed ephemeral-key-plus-tag minimum must be
    /// rejected before any decryption is attempted.
    #[test]
    fn seal_open_rejects_a_body_shorter_than_the_minimum() {
        let recipient_signing = RawSigningKey::from_bytes(&[15u8; 32]);
        for len in 0..(32 + 16) {
            assert!(seal::open(&vec![0u8; len], &recipient_signing).is_err());
        }
    }

    #[test]
    fn opening_with_the_wrong_key_fails() {
        let recipient_key = RawSigningKey::from_bytes(&[13u8; 32])
            .verifying_key()
            .to_bytes();
        let wrong_signing = RawSigningKey::from_bytes(&[14u8; 32]);
        let body = SealedBody {
            from: [5u8; 32],
            sent_ms: now_ms(),
            invite: None,
        };
        let sealed = seal::seal(&body, &recipient_key).unwrap();
        assert!(seal::open(&sealed, &wrong_signing).is_err());
    }

    #[test]
    fn invite_store_redeems_once_and_checks_bind() {
        let store = InMemoryInviteStore::new();
        let secret = [9u8; 32];
        let my_key = [1u8; 32];
        let gate_key = [2u8; 32];
        store.issue(&secret, now_ms() + 60_000);
        let bind = invite_bind(&secret, &my_key, &gate_key);

        assert!(store.try_redeem(&secret, &bind, &my_key, &gate_key));
        // Second redemption of the same invite is refused.
        assert!(!store.try_redeem(&secret, &bind, &my_key, &gate_key));
    }

    #[test]
    fn invite_bind_is_gate_specific() {
        let secret = [9u8; 32];
        let my_key = [1u8; 32];
        let store = InMemoryInviteStore::new();
        store.issue(&secret, now_ms() + 60_000);
        let bind_for_gate_a = invite_bind(&secret, &my_key, &[2u8; 32]);
        // The same proof, presented against a different gate's key, fails.
        assert!(!store.try_redeem(&secret, &bind_for_gate_a, &my_key, &[3u8; 32]));
    }
}
