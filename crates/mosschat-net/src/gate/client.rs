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
use crate::diag::{self, Reason, Recorder, Step, StepOutcome};
use crate::gate::wire::{self, Addr, Frame};
use crate::gate::{GateError, SeenSet, limits, now_ms, within_freshness_window};
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
    /// This house's own address as the gate observed it on the primary
    /// connection, and the gate's secondary (reflection) port, both taken
    /// from `Registered` at connect time (Konrad finding 6: previously
    /// discarded, so a house could learn either only out of band).
    registered_observed: std::net::SocketAddr,
    registered_secondary_port: u16,
    /// The diagnostics recorder for the attempt this client was opened
    /// for, if the caller gave one ([`GateClient::connect_with_recorder`]).
    /// A plain `Option` rather than something settable later: section 7's
    /// record is per connection attempt, and the gate steps of an attempt
    /// are the ones that opened this connection.
    recorder: Option<Recorder>,
    /// The client-side QUIC configuration this house dials with, kept so
    /// [`GateClient::dial_peer`] can clone it and attach a peer
    /// connection's own transport config (section 3's pinned MTU and
    /// epoch-resetting congestion factory) without rebuilding the identity
    /// certificate from a seed this struct would then have to hold.
    client_config: quinn::ClientConfig,
    /// The sessions this house actually holds, from its own `Introduce` or
    /// from an `Introduction` following a `Knock` it accepted.
    ///
    /// A `Start` naming anything else is ignored (Yseult's Medium): the
    /// gate supplies the session id, so `entry(session).or_default()` on
    /// every `Start` let a hostile gate walk session ids and grow this map
    /// without bound.
    ///
    /// **Bounded, and it lets go** (Konrad's new must). The cap is
    /// [`limits::MAX_SESSIONS_PER_REGISTRATION`], the gate's own cap on how
    /// many a registration may hold, and it is a *live* cap in section 1's
    /// words, not a lifetime one. Refusing the newest arrival at the cap,
    /// as this used to, made it a lifetime cap here: nothing removed an
    /// entry, so the ninth introduction in a process lifetime had its
    /// `Start` dropped and that peer stayed relayed forever with nothing
    /// said. Entries now end three ways: when the attempt for them ends
    /// ([`GateClient::attempt_finished`]), when they pass
    /// [`limits::REGISTRATION_TTL`], which is when the gate would have
    /// expired the registration they hang off, and by eviction when the cap
    /// is reached, oldest finished first and oldest outright if none has
    /// finished, so the newest is never the one refused.
    sessions: StdMutex<HashMap<u32, SessionEntry>>,
    starts: StdMutex<HashMap<u32, StartSlot>>,
}

/// A `Start` (frame 7) as this house received it: the gate's parameters
/// plus the local instant it arrived, which is what section 2 step 4
/// actually fires from. `gate_ms` is the gate's monotonic clock, written
/// into the diagnostics record so two logs can be aligned, and is never a
/// time to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartSignal {
    /// The session the start is for.
    pub session: u32,
    /// How long after `received_at` to fire the first probe burst.
    pub fire_in_ms: u16,
    /// The gate's monotonic clock at the moment it sent this.
    pub gate_ms: u64,
    /// This house's own reading of when the frame arrived.
    pub received_at: std::time::Instant,
}

/// One session's `Start` slot. A `Start` can arrive before the side that
/// did not ask for it gets round to waiting, so an arrival with no waiter
/// is kept rather than dropped; otherwise the responder would wait out its
/// whole timeout for a frame it had already been sent.
/// One session this house holds: the peer's gate-observed address, when it
/// was opened, and whether the doorbell attempt for it has finished.
#[derive(Debug, Clone, Copy)]
struct SessionEntry {
    peer_observed: std::net::SocketAddr,
    opened_at: std::time::Instant,
    finished: bool,
}

#[derive(Default)]
struct StartSlot {
    received: Option<StartSignal>,
    waiter: Option<oneshot::Sender<StartSignal>>,
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
        Self::connect_with_recorder(
            primary_addr,
            identity_seed,
            community,
            expected_gate_key,
            friends,
            invites,
            None,
        )
        .await
    }

    /// [`GateClient::connect`], recording section 7's `gate_dial`,
    /// `gate_register` and `reflect_primary` steps into `recorder` and
    /// holding it for the `introduce`, `relay_open` and `peer_handshake`
    /// steps that follow on this connection.
    ///
    /// A separate constructor rather than a seventh parameter on
    /// [`GateClient::connect`] so that every existing caller (a house with
    /// no diagnostics directory, and every test written before WO-1.4b)
    /// keeps working unchanged.
    ///
    /// # Errors
    ///
    /// The same as [`GateClient::connect`]; each failure is recorded
    /// against the step it happened in before it is returned.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_recorder(
        primary_addr: std::net::SocketAddr,
        identity_seed: [u8; 32],
        community: [u8; 32],
        expected_gate_key: Option<[u8; 32]>,
        friends: Arc<dyn FriendStore>,
        invites: Arc<dyn InviteStore>,
        recorder: Option<Recorder>,
    ) -> Result<Self, GateError> {
        let rec = recorder.as_ref();
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
        // Section 3, "telling probes from QUIC": every QUIC header must
        // carry the fixed bit 0x40, but quinn enforces it on receive only
        // when greasing is off (`quinn-proto/src/packet.rs:585-586` from
        // `quinn-proto/src/endpoint.rs:158-161`) and greasing defaults to
        // on (`quinn-proto/src/config/mod.rs:63`), letting a peer clear the
        // bit at random. With it on, an 81 byte short-header packet whose
        // greased first byte happened to be 0x2A would be eaten by the
        // porch socket's probe filter, which is exactly half (a) of section
        // 3's reversing condition. Off, our own peers never clear it and
        // quinn rejects any first byte with it clear, so 0x2A is
        // unambiguous in both directions.
        let mut endpoint_config = quinn::EndpointConfig::default();
        endpoint_config.grease_quic_bit(false);
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            Arc::clone(&porch) as Arc<dyn quinn::AsyncUdpSocket>,
            runtime,
        )?;
        endpoint.set_default_client_config(client_config.clone());

        // Section 3's drop rule (`PorchSocket::allow_source`): the gate's
        // primary address is in no peer's candidate table, so it must be
        // allowed explicitly, and before the dial rather than after, since
        // the handshake's own packets come back from it.
        let primary_lease = porch.allow_source(primary_addr);
        // Armed here, before the dial, so the rule covers the handshake
        // too and `arm`'s doc is true of the code (Konrad's item 2:
        // `attach_gate` alone left it off until the handshake completed).
        porch.arm();
        // Section 7's `gate_dial`: the QUIC handshake with the gate. A
        // dial that never completes is `gate_unreachable`; one that
        // completes and is then refused is a `gate_register` failure
        // below, since the refusal arrives as an `Error` frame.
        let connecting = match endpoint.connect(primary_addr, "gate") {
            Ok(connecting) => connecting,
            Err(e) => {
                diag::record(rec, Step::GateDial, StepOutcome::Fail, e.to_string());
                return Err(e.into());
            }
        };
        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(e) => {
                diag::record(rec, Step::GateDial, StepOutcome::Fail, e.to_string());
                return Err(e.into());
            }
        };
        let authed_conn = match AuthedConnection::new(connection) {
            Ok(authed_conn) => authed_conn,
            Err(e) => {
                diag::record(rec, Step::GateDial, StepOutcome::Fail, e.to_string());
                return Err(e);
            }
        };
        diag::record(
            rec,
            Step::GateDial,
            StepOutcome::Ok,
            format!("gate at {primary_addr}"),
        );
        if let Some(expected) = expected_gate_key
            && authed_conn.peer_key() != expected
        {
            diag::record(
                rec,
                Step::GateDial,
                StepOutcome::Fail,
                "the gate's TLS-proven key does not match the pinned key",
            );
            authed_conn
                .connection()
                .close(0u32.into(), b"gate key does not match the pinned key");
            return Err(GateError::InvalidIdentity(
                "connected gate's TLS-proven key does not match the pinned expected key".into(),
            ));
        }
        porch.attach_gate(authed_conn.connection().clone());
        // The handshake window is over: this connection now holds its own
        // entry in the live gate-address set (`attach_gate`), so the
        // pre-dial one is handed back. The union never dips, since the
        // connection's own lease was taken before this line.
        porch.forget_source(primary_lease);

        // Every one of the three below used to be a bare `?`: the dial had
        // been recorded `ok` and the next step recorded nothing at all, so a
        // gate that closed the connection during registration (it refuses
        // `gate_at_capacity` and `gate_rate_limited` by closing, not always
        // by frame 12) produced a record with no failed step, which reads as
        // a run that simply stopped. `register_step` records `gate_register`
        // against whichever of them failed, so the record names the step the
        // house was on when the gate went away, and says why where the gate
        // said.
        let register_step = |e: GateError| {
            record_gate_close(rec, Step::GateRegister, &e, authed_conn.connection());
            e
        };
        let (mut send, mut recv) = authed_conn
            .connection()
            .open_bi()
            .await
            .map_err(|e| register_step(e.into()))?;
        wire::write_frame(&mut send, &Frame::Register { v: 1, community })
            .await
            .map_err(register_step)?;
        let reply = wire::read_frame(&mut recv, authed::control_read_deadline())
            .await
            .map_err(register_step)?;
        let (registered_observed, registered_secondary_port) = match reply {
            Frame::Registered {
                observed,
                secondary_port,
                ..
            } => {
                let decoded = observed.to_socket_addr().ok_or_else(|| {
                    GateError::Protocol("Registered.observed did not decode".into())
                });
                let decoded = match decoded {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        diag::record(rec, Step::GateRegister, StepOutcome::Fail, e.to_string());
                        return Err(e);
                    }
                };
                diag::record(
                    rec,
                    Step::GateRegister,
                    StepOutcome::Ok,
                    format!("registered, secondary port {secondary_port}"),
                );
                // Frame 2's `observed` is section 7's first reflection:
                // the source address the gate saw on the primary port.
                if let Some(recorder) = rec {
                    recorder.set_local_observed_primary(observed);
                }
                diag::record(
                    rec,
                    Step::ReflectPrimary,
                    StepOutcome::Ok,
                    format!("gate saw {decoded}"),
                );
                (decoded, secondary_port)
            }
            Frame::Error { code, detail, .. } => {
                // `detail` is the gate's own text, capped at 64 bytes on
                // the wire (section 1) and capped again by the record's
                // free-text limit; the code is section 7's reason enum on
                // the wire, so it names the record's reason rather than
                // leaving the caller to guess `internal` from the failed
                // step (Konrad's should 3).
                if let Some(recorder) = rec {
                    recorder.set_reason_hint(reason_for_error_code(code));
                }
                diag::record(
                    rec,
                    Step::GateRegister,
                    StepOutcome::Fail,
                    format!(
                        "gate refused registration: code={code} detail={}",
                        gate_text(&detail)
                    ),
                );
                return Err(GateError::Protocol(format!(
                    "gate refused registration: code={code} detail={}",
                    gate_text(&detail)
                )));
            }
            other => {
                diag::record(
                    rec,
                    Step::GateRegister,
                    StepOutcome::Fail,
                    format!("expected Registered or Error, got {other:?}"),
                );
                return Err(GateError::Protocol(format!(
                    "expected Registered or Error, got {other:?}"
                )));
            }
        };

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
            registered_observed,
            registered_secondary_port,
            recorder,
            client_config,
            sessions: StdMutex::new(HashMap::new()),
            starts: StdMutex::new(HashMap::new()),
        });

        let reader_inner = Arc::clone(&inner);
        tokio::spawn(async move {
            reader_loop(reader_inner, recv).await;
        });

        Ok(Self { inner })
    }

    /// The peer's gate-observed address for `session`, if this house holds
    /// that session. It is frame 6's `peer_observed`, and the doorbell
    /// needs it because it is the one address outside the globally routable
    /// range a peer may name as a candidate.
    #[must_use]
    pub fn peer_observed_for(&self, session: u32) -> Option<std::net::SocketAddr> {
        self.inner
            .sessions
            .lock_or_recover()
            .get(&session)
            .map(|entry| entry.peer_observed)
    }

    /// Marks `session`'s doorbell attempt as over, so its entry is the
    /// first evicted when room is needed, and drops any `Start` slot still
    /// held for it. Called by [`crate::punch::run_doorbell`] on every exit.
    pub fn attempt_finished(&self, session: u32) {
        if let Some(entry) = self.inner.sessions.lock_or_recover().get_mut(&session) {
            entry.finished = true;
        }
        self.inner.starts.lock_or_recover().remove(&session);
    }

    /// How many sessions this house currently holds, for tests.
    #[must_use]
    pub fn held_sessions(&self) -> usize {
        self.inner.sessions.lock_or_recover().len()
    }

    /// How many `Start` slots are outstanding, for tests: a slot exists
    /// only between a wait being registered and the signal arriving, and a
    /// taken or timed-out one leaves nothing behind.
    #[must_use]
    pub fn pending_start_slots(&self) -> usize {
        self.inner.starts.lock_or_recover().len()
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

    /// This house's own address as the gate observed it (`Registered.observed`),
    /// learned from the protocol at registration time.
    #[must_use]
    pub fn registered_observed(&self) -> std::net::SocketAddr {
        self.inner.registered_observed
    }

    /// The gate's secondary (reflection) port (`Registered.secondary_port`),
    /// learned from the protocol at registration time rather than out of
    /// band.
    #[must_use]
    pub fn registered_secondary_port(&self) -> u16 {
        self.inner.registered_secondary_port
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

    /// The UDP port this house's porch socket is bound to locally, which
    /// is the port section 2 step 1's local candidates carry.
    ///
    /// `None` if the socket cannot report its address. Named here so a
    /// caller outside this crate (the `doctor` subcommand) can gather
    /// candidates without depending on quinn for the `AsyncUdpSocket`
    /// trait that carries `local_addr`.
    #[must_use]
    pub fn local_port(&self) -> Option<u16> {
        use quinn::AsyncUdpSocket as _;
        self.inner.porch.local_addr().ok().map(|addr| addr.port())
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

    /// This client's diagnostics recorder, if it was opened with one.
    /// The doorbell takes the same handle, so one attempt's gate steps and
    /// doorbell steps land in one record (section 7).
    #[must_use]
    pub fn recorder(&self) -> Option<Recorder> {
        self.inner.recorder.clone()
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

    /// Sends `Goodbye` and closes the gate connection, returning once the
    /// gate has let the registration go.
    ///
    /// Section 1 has `Goodbye` "deregistering at once", and the gate drops
    /// the connection as soon as it has: waiting for that close is the
    /// acknowledgement that the slot is free, and the only one the protocol
    /// offers. Closing straight after the write instead, which is what this
    /// did, is a race quinn is documented to lose (`close` abandons data
    /// not yet transmitted), and a caller that ends the process next
    /// (`mosschat doctor`, through `std::process::exit`) leaves the driver
    /// no chance to send either frame: the registration then sat at the
    /// gate until its 30 s idle timeout, and with section 1's sub-cap of
    /// two live connections per key the third run inside that window was
    /// refused before it could register.
    ///
    /// **The whole call is bounded**, on one budget of section 5's deadline
    /// for a frame that should follow immediately (Yseult's M1 on PR 69).
    /// Not just the wait: taking the control stream's lock and writing to
    /// it both block with no deadline of their own, `write_all` on stream
    /// flow control, so a peer that stops issuing `MAX_STREAM_DATA` could
    /// hang a caller that had already finished its work. Every other
    /// network step of a `doctor` run is bounded at its call site, and
    /// `main.rs` says in as many words that a doctor which does not return
    /// is not a doctor.
    ///
    /// The close runs whether the budget was spent or not: it frees the
    /// gate's slot as surely as the `Goodbye` does, and a gate that has
    /// already gone cannot be waited on.
    ///
    /// # Errors
    ///
    /// Returns [`GateError::Timeout`] if the frame could not be written
    /// inside the deadline, or a [`GateError`] if the write itself failed.
    /// Waiting for the gate to let go is best effort: running out of budget
    /// there is not an error, since the frame is already gone.
    pub async fn goodbye(&self, reason: u8) -> Result<(), GateError> {
        let deadline = tokio::time::Instant::now() + authed::control_read_deadline();
        let connection = self.inner.gate.connection().clone();
        let written = tokio::time::timeout_at(deadline, async {
            let mut send = self.inner.control_send.lock().await;
            wire::write_frame(&mut send, &Frame::Goodbye { v: 1, reason }).await
        })
        .await;
        // Whatever happened above, stop holding this connection.
        let outcome = match written {
            Ok(Ok(())) => {
                // The gate deregisters on `Goodbye` and then drops the
                // connection, so its close is the acknowledgement that the
                // slot is free, and the only one the protocol offers. What
                // is left of the same budget bounds it.
                let _ = tokio::time::timeout_at(deadline, connection.closed()).await;
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(GateError::Timeout),
        };
        connection.close(0u32.into(), b"goodbye");
        outcome
    }

    /// Reflects off the gate's secondary port, returning the address it
    /// observed.
    ///
    /// # Errors
    ///
    /// Returns a [`GateError`] if the connection or exchange fails.
    pub async fn reflect(&self, secondary_addr: std::net::SocketAddr) -> Result<Addr, GateError> {
        let rec = self.inner.recorder.as_ref();
        // The gate's secondary port is the other address this house dials
        // itself, and the only other one; allowed for the life of this
        // short connection and withdrawn when it closes.
        let lease = self.inner.porch.allow_source(secondary_addr);
        let connecting = match self.inner.endpoint.connect(secondary_addr, "gate") {
            Ok(connecting) => connecting,
            Err(e) => {
                self.inner.porch.forget_source(lease);
                diag::record(
                    rec,
                    Step::ReflectSecondary,
                    StepOutcome::Fail,
                    e.to_string(),
                );
                return Err(e.into());
            }
        };
        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(e) => {
                self.inner.porch.forget_source(lease);
                diag::record(
                    rec,
                    Step::ReflectSecondary,
                    StepOutcome::Fail,
                    e.to_string(),
                );
                return Err(e.into());
            }
        };
        // The same gap the registration window had, and the same fix: the
        // secondary port refuses an over-rate `Reflect` by closing the
        // connection with no frame at all, so a bare `?` here left the
        // record with no failed step and `doctor --gate` exited 0 on a
        // reflection that never happened.
        let reflect_step = |e: GateError| {
            // The lease goes back on every exit, not only the happy one.
            // These three paths used to return without it, leaving the
            // gate's secondary address in the porch socket's live source
            // set (section 3) for the life of the process, so packets from
            // that address stayed admissible long after the short
            // connection that justified them had gone.
            self.inner.porch.forget_source(lease);
            record_gate_close(rec, Step::ReflectSecondary, &e, &connection);
            e
        };
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| reflect_step(e.into()))?;
        wire::write_frame(&mut send, &Frame::Reflect { v: 1 })
            .await
            .map_err(reflect_step)?;
        let reply = wire::read_frame(&mut recv, authed::control_read_deadline())
            .await
            .map_err(reflect_step)?;
        // Closes promptly so the gate's secondary-port handler (which waits
        // for this before dropping its own `Connection`, see `server.rs`)
        // does not sit on its bounded wait for no reason.
        connection.close(0u32.into(), b"reflect done");
        self.inner.porch.forget_source(lease);
        match reply {
            Frame::Reflected { observed, .. } => {
                // Section 7's second reflection, off the other port: the
                // pair is what `Mapping` is inferred from.
                if let Some(recorder) = rec {
                    recorder.set_local_observed_secondary(observed);
                }
                diag::record(
                    rec,
                    Step::ReflectSecondary,
                    StepOutcome::Ok,
                    match observed.to_socket_addr() {
                        Some(addr) => format!("gate saw {addr}"),
                        None => "gate saw an address that did not decode".to_string(),
                    },
                );
                Ok(observed)
            }
            other => {
                diag::record(
                    rec,
                    Step::ReflectSecondary,
                    StepOutcome::Fail,
                    format!("expected Reflected, got {other:?}"),
                );
                Err(GateError::Protocol(format!(
                    "expected Reflected, got {other:?}"
                )))
            }
        }
    }

    /// Section 2 step 4: asks the gate to fire the simultaneous open for
    /// `session`. Either side may ask; the gate sends `Start` to both,
    /// back to back.
    ///
    /// # Errors
    ///
    /// Returns a [`GateError`] if the control stream write fails.
    pub async fn request_start(&self, session: u32) -> Result<(), GateError> {
        let mut send = self.inner.control_send.lock().await;
        wire::write_frame(&mut send, &Frame::StartRequest { v: 1, session }).await
    }

    /// Waits for this session's `Start`, which either side receives whether
    /// or not it was the one that asked.
    ///
    /// # Errors
    ///
    /// Returns [`GateError::Timeout`] if none arrives inside `deadline`.
    pub async fn await_start(
        &self,
        session: u32,
        deadline: Duration,
    ) -> Result<StartSignal, GateError> {
        let rx = {
            let mut starts = self.inner.starts.lock_or_recover();
            let slot = starts.entry(session).or_default();
            if let Some(signal) = slot.received.take() {
                // Taken, so the slot is gone: nothing is left behind on the
                // success path either (Konrad's should 6).
                starts.remove(&session);
                return Ok(signal);
            }
            let (tx, rx) = oneshot::channel();
            slot.waiter = Some(tx);
            rx
        };
        match tokio::time::timeout(deadline, rx).await {
            Ok(Ok(signal)) => Ok(signal),
            _ => {
                self.inner.starts.lock_or_recover().remove(&session);
                Err(GateError::Timeout)
            }
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
        let rec = self.inner.recorder.as_ref();
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
                let synthetic = self.synthetic_addr_for(&peer_key);
                self.inner
                    .remember_session(outcome.session, outcome.peer_observed.to_socket_addr());
                self.inner
                    .porch
                    .register_relay_session(outcome.session, synthetic);
                // Section 2 step 2: the peer starts relayed, so its path
                // table entry exists from the introduction, not from the
                // upgrade. The doorbell finds it with `porch.path_for`.
                self.inner.porch.insert_relay_path(peer_key, synthetic);
                // The record names no key: the session and the peer's
                // gate-observed address are what section 7 asks for, and
                // the peer itself is already the record's redacted
                // fingerprint.
                if let Some(recorder) = rec {
                    recorder.set_session(outcome.session);
                    recorder.set_peer_observed(outcome.peer_observed);
                }
                diag::record(
                    rec,
                    Step::Introduce,
                    StepOutcome::Ok,
                    format!(
                        "introduced as role {role}, session {session}",
                        role = outcome.role,
                        session = outcome.session
                    ),
                );
                // The relay session exists from here: the gate forwards
                // datagrams for it, and the path table entry above is the
                // house's end of it.
                diag::record(
                    rec,
                    Step::RelayOpen,
                    StepOutcome::Ok,
                    format!("relay session {session}", session = outcome.session),
                );
                Ok(outcome)
            }
            _ => {
                self.inner.introductions.lock_or_recover().remove(&tag);
                // Section 7: `introduce_timeout` is inferred locally from
                // `ttl_s` elapsing, and is all an unsuccessful `Introduce`
                // yields. A tag matching nobody, a house that declined and
                // one that never answered are deliberately one outcome.
                diag::record(
                    rec,
                    Step::Introduce,
                    StepOutcome::Fail,
                    format!("no Introduction inside {ttl_s} s"),
                );
                Err(GateError::Protocol("introduce_timeout".into()))
            }
        }
    }

    /// Section 2 step 2: dials the end to end QUIC connection to `peer_key`
    /// through the relay session [`GateClient::introduce`] already opened,
    /// and returns it once the peer's TLS-proven key matches.
    ///
    /// The connection addresses the peer's synthetic address throughout
    /// (section 3), so it never learns which path carries it; the porch
    /// socket decides that. `peer_handshake` is the step section 7 names,
    /// and `peer_key_mismatch` the reason a wrong key produces.
    ///
    /// # Errors
    ///
    /// Returns a [`GateError`] if the path table has no entry for this
    /// peer (nothing has introduced it), the handshake fails, or the key
    /// the handshake proves is not `peer_key`.
    pub async fn dial_peer(&self, peer_key: &[u8; 32]) -> Result<quinn::Connection, GateError> {
        let rec = self.inner.recorder.as_ref();
        let Some(path) = self.inner.porch.path_for(peer_key) else {
            let detail = "no relay path for this peer: nothing has introduced it";
            diag::record(rec, Step::PeerHandshake, StepOutcome::Fail, detail);
            return Err(GateError::Protocol(detail.into()));
        };
        let mut config = self.inner.client_config.clone();
        config.transport_config(crate::path::peer_transport_config(path.epoch()));
        let synthetic = self.synthetic_addr_for(peer_key);
        let connecting = match self.inner.endpoint.connect_with(config, synthetic, "peer") {
            Ok(connecting) => connecting,
            Err(e) => {
                diag::record(rec, Step::PeerHandshake, StepOutcome::Fail, e.to_string());
                return Err(e.into());
            }
        };
        let connection = match connecting.await {
            Ok(connection) => connection,
            Err(e) => {
                diag::record(rec, Step::PeerHandshake, StepOutcome::Fail, e.to_string());
                return Err(e.into());
            }
        };
        let authed_conn = match AuthedConnection::new(connection) {
            Ok(authed_conn) => authed_conn,
            Err(e) => {
                diag::record(rec, Step::PeerHandshake, StepOutcome::Fail, e.to_string());
                return Err(e);
            }
        };
        if authed_conn.peer_key() != *peer_key {
            // Section 7's `peer_key_mismatch`. The record names neither
            // key: the expected one is already the record's redacted peer
            // fingerprint, and the one that answered is not written at all.
            diag::record(
                rec,
                Step::PeerHandshake,
                StepOutcome::Fail,
                "the peer's TLS-proven key is not the key this attempt asked for",
            );
            authed_conn
                .connection()
                .close(0u32.into(), b"peer key mismatch");
            return Err(GateError::InvalidIdentity(
                "peer key does not match the key this attempt asked for".into(),
            ));
        }
        diag::record(
            rec,
            Step::PeerHandshake,
            StepOutcome::Ok,
            "end to end connection open over the relay",
        );
        Ok(authed_conn.connection().clone())
    }
}

/// Records `step` as failed, carrying whatever the gate said as it closed:
/// its wording in the detail, and, when the close named one of section 7's
/// codes, that as the record's reason.
fn record_gate_close(
    rec: Option<&Recorder>,
    step: Step,
    e: &GateError,
    connection: &quinn::Connection,
) {
    if let (Some(recorder), Some(reason)) = (rec, gate_close_reason(connection)) {
        recorder.set_reason_hint(reason);
    }
    diag::record(rec, step, StepOutcome::Fail, closed_detail(e, connection));
}

/// Section 7's reason from a connection the gate closed, when the close
/// carried one of [`crate::gate::ErrorCode`]'s values as its QUIC
/// application error code (`server.rs::close_refused`). Code 0 is an
/// ordinary close and names no reason.
fn gate_close_reason(connection: &quinn::Connection) -> Option<Reason> {
    let quinn::ConnectionError::ApplicationClosed(closed) = connection.close_reason()? else {
        return None;
    };
    let code = u8::try_from(u64::from(closed.error_code)).ok()?;
    (code != 0).then(|| reason_for_error_code(code))
}

/// The detail a failed control exchange is recorded with: the error, plus
/// the connection's own close reason where it has one.
///
/// quinn folds every stream error on a dead connection into "connection
/// lost", which says nothing about why it died. A gate refusal that cannot
/// be answered with frame 12, because no stream is open yet (the connection
/// attempt rate limit) or because the frame did not outrun the close, puts
/// its reason in the CONNECTION_CLOSE instead, and this is the only place
/// the house can read it. Without it the record's detail was "stream read
/// error: connection lost" for a refusal the gate had named.
fn closed_detail(e: &GateError, connection: &quinn::Connection) -> String {
    match connection.close_reason() {
        Some(reason) => format!("{e} ({})", gate_text(&reason.to_string())),
        None => e.to_string(),
    }
}

/// Text the gate authored, made safe to put in a record a person reads.
///
/// Control characters are dropped and the rest is cut to
/// [`wire::ERROR_DETAIL_CAP`], the cap section 1 already puts on the one
/// field the gate fills in (Yseult's L1 on PR 69). Two reasons, both about
/// the human report, which interpolates a step's detail raw where the JSON
/// form caps it: a QUIC close reason is whatever bytes the peer sent, up to
/// about a packet's worth, rendered by `String::from_utf8_lossy`, so
/// without this a hostile or impersonated gate can forge or hide lines in a
/// report section 7 expects to be pasted into an issue, and can put ANSI
/// escapes on the terminal it is printed to. `char::is_control` is exactly
/// Unicode's Cc: C0, DEL and C1.
fn gate_text(text: &str) -> String {
    /// Cutting is marked rather than silent, for the reason `diag.rs`'s own
    /// cap marks it: a record that quietly says something other than what
    /// it was given is worse than one that says it was cut.
    const CUT: &str = "...";
    let mut out = String::with_capacity(text.len().min(wire::ERROR_DETAIL_CAP));
    let mut cut = false;
    for c in text.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > wire::ERROR_DETAIL_CAP - CUT.len() {
            cut = true;
            break;
        }
        out.push(c);
    }
    if cut {
        out.push_str(CUT);
    }
    out
}

/// Section 7's reason for a gate refusal, from frame 12's `code`, which is
/// [`crate::gate::ErrorCode`] and so is that same enum on the wire.
fn reason_for_error_code(code: u8) -> Reason {
    match code {
        c if c == crate::gate::ErrorCode::RefusedNotMember as u8 => Reason::GateRefusedNotMember,
        c if c == crate::gate::ErrorCode::AtCapacity as u8 => Reason::GateAtCapacity,
        c if c == crate::gate::ErrorCode::RateLimited as u8 => Reason::GateRateLimited,
        c if c == crate::gate::ErrorCode::CapExceeded as u8 => Reason::CapExceeded,
        _ => Reason::Internal,
    }
}

/// `BLAKE3("mosschat-gate-pair-v1" || community || min(kA,kB) || max(kA,kB))`
/// (section 1), the pair tag.
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

impl Inner {
    /// Records a session this house holds, making room for it rather than
    /// refusing it. See [`Inner::sessions`].
    fn remember_session(&self, session: u32, peer_observed: Option<std::net::SocketAddr>) {
        let Some(peer_observed) = peer_observed else {
            return;
        };
        let now = std::time::Instant::now();
        let mut sessions = self.sessions.lock_or_recover();

        // A session dies with the registration it hangs off, and the gate
        // expires a registration `REGISTRATION_TTL` after its last
        // keepalive, so anything older than that is already gone at the
        // gate whatever this map still says. Swept on insert, which is the
        // only moment the size matters.
        sessions.retain(|_, entry| now.duration_since(entry.opened_at) < limits::REGISTRATION_TTL);

        if !sessions.contains_key(&session) {
            while sessions.len() >= limits::MAX_SESSIONS_PER_REGISTRATION {
                // Oldest finished first, since its attempt is over and
                // nothing is waiting on its `Start`; oldest outright if none
                // has finished, because refusing the newest is the bug this
                // replaces and the gate's own cap means a house never
                // legitimately holds more than this many live.
                let victim = sessions
                    .iter()
                    .filter(|(_, entry)| entry.finished)
                    .min_by_key(|(_, entry)| entry.opened_at)
                    .or_else(|| sessions.iter().min_by_key(|(_, entry)| entry.opened_at))
                    .map(|(id, _)| *id);
                match victim {
                    Some(id) => {
                        sessions.remove(&id);
                    }
                    None => break,
                }
            }
        }

        sessions.insert(
            session,
            SessionEntry {
                peer_observed,
                opened_at: now,
                finished: false,
            },
        );
    }
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
                        let synthetic = sock::synthetic_addr(inner.process_salt, &peer_key);
                        inner.remember_session(session, peer_observed.to_socket_addr());
                        inner.porch.register_relay_session(session, synthetic);
                        inner.porch.insert_relay_path(peer_key, synthetic);
                        // The responder's relay leg opens here, and its
                        // record must say so too (Konrad's should 5): only
                        // the asker's `introduce` recorded it before, so
                        // the accepting side's log showed no session at
                        // all.
                        if let Some(recorder) = inner.recorder.as_ref() {
                            recorder.set_session(session);
                            recorder.set_peer_observed(peer_observed);
                        }
                        diag::record(
                            inner.recorder.as_ref(),
                            Step::RelayOpen,
                            StepOutcome::Ok,
                            format!("relay session {session}, as the responder"),
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
            Frame::Start {
                session,
                fire_in_ms,
                gate_ms,
                ..
            } => {
                // Only for a session this house actually holds. The gate
                // chooses session ids, so accepting a `Start` for any id it
                // names is a map this house does not control the size of.
                if !inner.sessions.lock_or_recover().contains_key(&session) {
                    continue;
                }
                let signal = StartSignal {
                    session,
                    fire_in_ms,
                    gate_ms,
                    received_at: std::time::Instant::now(),
                };
                let mut starts = inner.starts.lock_or_recover();
                if starts.len() >= limits::MAX_SESSIONS_PER_REGISTRATION
                    && !starts.contains_key(&session)
                {
                    continue;
                }
                let slot = starts.entry(session).or_default();
                match slot.waiter.take() {
                    Some(waiter) => {
                        starts.remove(&session);
                        let _ = waiter.send(signal);
                    }
                    None => slot.received = Some(signal),
                }
            }
            Frame::KeepaliveAck { .. } | Frame::Error { .. } => {}
            _ => {}
        }
    }
}

async fn answer_knock(inner: &Arc<Inner>, tag: [u8; 32], sealed: Vec<u8>) {
    // Design amendment 1 (settling issue #16): the seen set is charged only
    // on the accept decision itself -- the seal has opened, its freshness
    // and pair tag both verify, *and* the body names a friend or a valid
    // invite proof -- never on receipt and never on an open alone. B's key
    // is public, so anyone holding it can mint a seal that opens; charging
    // the set on opening alone lets a stranger fill it at whatever rate the
    // gate forwards knocks. Inserting after the accept decision loses
    // nothing: a seal this house was always going to answer with silence
    // (wrong freshness, wrong tag, or no friend/invite match) costs nothing
    // to drop again on a repeat.
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
        // 1, never an explicit decline, and the seen set is left uncharged
        // (never occupying a slot for a knock this house was never going to
        // accept).
        return;
    }

    let fresh = {
        let mut seen = inner.seen.lock_or_recover();
        seen.accept(&sealed)
    };
    if !fresh {
        // A repeat of an already-accepted seal replayed inside the window:
        // silence, per section 1.
        return;
    }

    diag::record(
        inner.recorder.as_ref(),
        Step::Introduce,
        StepOutcome::Ok,
        "knock accepted",
    );

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

    /// Gate-authored text cannot forge lines in a report or move a
    /// terminal's cursor, and cannot outrun section 1's own cap on the one
    /// field the gate fills in (Yseult's L1 on PR 69).
    ///
    /// Deliberate break to fail this test: return `text.to_string()` from
    /// `gate_text`, which is what interpolating the close reason did.
    #[test]
    fn gate_authored_text_is_stripped_of_control_characters_and_capped() {
        let hostile = "ok\u{1b}[2K\rfailed step gate_dial\nreason ok";
        let safe = gate_text(hostile);
        assert!(
            !safe.chars().any(char::is_control),
            "no C0, DEL or C1 survives: {safe:?}"
        );
        assert!(!safe.contains('\n') && !safe.contains('\r'));
        assert_eq!(safe, "ok[2Kfailed step gate_dialreason ok");

        // Cut on a char boundary, never through one, never past the cap,
        // and visibly: a close reason is up to a packet's worth of peer
        // bytes.
        let long = "e\u{e9}".repeat(wire::ERROR_DETAIL_CAP);
        let capped = gate_text(&long);
        assert!(capped.len() <= wire::ERROR_DETAIL_CAP, "{}", capped.len());
        assert!(capped.ends_with("..."), "{capped:?}");
        assert!(long.starts_with(capped.trim_end_matches('.')));
    }

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
