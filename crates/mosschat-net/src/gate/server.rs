//! The `mosschat gatehouse` role (`docs/dev/gatehouse-design.md` section 1).
//!
//! One `quinn::Endpoint` per port: `primary` carries `Register` and every
//! other control frame plus `Relay` datagrams for the life of a
//! registration; `secondary` exists only to answer `Reflect` with a second
//! address observation, per connection, then that connection is done.
//! Neither endpoint ever parses relayed bytes: `Relay` payloads are copied
//! from one connection's datagram channel to the other's, unopened.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use rand::RngExt;
use tokio::sync::mpsc;

use crate::authed::{self, AuthedConnection};
use crate::gate::wire::{self, Addr, Frame, decode_relay, encode_relay};
use crate::gate::{ErrorCode, GateError, MemberList, RateLimiter, limits};

/// Counters a test (or an operator) can read back from a running gate.
#[derive(Debug, Default)]
pub struct ServerCounters {
    /// `Relay` datagrams dropped because the sender was neither key of the
    /// named session (section 1: "dropped and counted, never answered").
    pub relay_sender_mismatch: AtomicU64,
    /// Registration attempts refused because the slot table was already at
    /// capacity.
    pub registrations_refused_at_capacity: AtomicU64,
}

struct RegistrationInner {
    key: [u8; 32],
    connection: quinn::Connection,
    frame_tx: mpsc::UnboundedSender<Frame>,
    observed: std::net::SocketAddr,
    last_keepalive: StdMutex<Instant>,
    introduce_min: StdMutex<RateLimiter>,
    introduce_hour: StdMutex<RateLimiter>,
    sessions: StdMutex<HashSet<u32>>,
}

type Registration = Arc<RegistrationInner>;

struct KnockState {
    requester: [u8; 32],
    target: [u8; 32],
    deadline: Instant,
}

struct SessionState {
    key_a: [u8; 32],
    key_b: [u8; 32],
}

struct ServerState {
    community: [u8; 32],
    members: StdMutex<MemberList>,
    capacity: usize,
    registrations: StdMutex<HashMap<[u8; 32], Registration>>,
    knocks: StdMutex<HashMap<[u8; 32], KnockState>>,
    sessions: StdMutex<HashMap<u32, SessionState>>,
    counters: ServerCounters,
}

impl ServerState {
    fn pair_tag(&self, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        let mut input = Vec::with_capacity(22 + 32 + 32 + 32);
        input.extend_from_slice(b"mosschat-gate-pair-v1");
        input.extend_from_slice(&self.community);
        input.extend_from_slice(lo);
        input.extend_from_slice(hi);
        *blake3::hash(&input).as_bytes()
    }
}

/// The gatehouse role: two endpoints (primary and secondary/reflection),
/// serving the gate protocol of section 1.
pub struct GateServer {
    primary_addr: std::net::SocketAddr,
    secondary_addr: std::net::SocketAddr,
    state: Arc<ServerState>,
}

/// Configuration for [`GateServer::bind`].
pub struct GateServerConfig {
    /// The community identifier this gate serves.
    pub community: [u8; 32],
    /// The gate's own ed25519 identity seed.
    pub identity_seed: [u8; 32],
    /// The member list; a proven key not on it is refused before a slot is
    /// touched.
    pub members: MemberList,
    /// Address to bind the primary (registration and control) endpoint to.
    pub primary_bind: std::net::SocketAddr,
    /// Address to bind the secondary (reflection-only) endpoint to.
    pub secondary_bind: std::net::SocketAddr,
    /// Overrides [`limits::MAX_REGISTRATIONS`], for tests that need a small
    /// cap to exercise refusal without opening 256 real connections.
    pub max_registrations: usize,
}

const ALPN: &[u8] = b"moss-gate";

impl GateServer {
    /// Binds both endpoints and returns immediately; call [`Self::serve`] to
    /// run the accept loops.
    ///
    /// # Errors
    ///
    /// Returns an error if either endpoint fails to bind or its TLS
    /// configuration fails to build.
    pub fn bind(config: GateServerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        authed::install_crypto_provider();
        let (cert, key) = authed::self_signed_cert(&config.identity_seed)?;
        let tls = authed::server_tls_config(cert, key, ALPN)?;
        let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into()?));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
        server_config.transport_config(Arc::new(transport));

        let primary = quinn::Endpoint::server(server_config.clone(), config.primary_bind)?;
        let secondary = quinn::Endpoint::server(server_config, config.secondary_bind)?;
        let primary_addr = primary.local_addr()?;
        let secondary_addr = secondary.local_addr()?;

        let state = Arc::new(ServerState {
            community: config.community,
            members: StdMutex::new(config.members),
            capacity: config.max_registrations,
            registrations: StdMutex::new(HashMap::new()),
            knocks: StdMutex::new(HashMap::new()),
            sessions: StdMutex::new(HashMap::new()),
            counters: ServerCounters::default(),
        });

        tokio::spawn(accept_loop_primary(primary, Arc::clone(&state)));
        tokio::spawn(accept_loop_secondary(secondary, Arc::clone(&state)));

        Ok(Self {
            primary_addr,
            secondary_addr,
            state,
        })
    }

    /// The bound address of the primary (registration) endpoint.
    #[must_use]
    pub fn primary_addr(&self) -> std::net::SocketAddr {
        self.primary_addr
    }

    /// The bound address of the secondary (reflection) endpoint.
    #[must_use]
    pub fn secondary_addr(&self) -> std::net::SocketAddr {
        self.secondary_addr
    }

    /// This gate's live counters.
    #[must_use]
    pub fn counters(&self) -> &ServerCounters {
        &self.state.counters
    }

    /// The number of currently live registrations, for tests.
    #[must_use]
    pub fn registration_count(&self) -> usize {
        #[allow(clippy::unwrap_used)]
        self.state.registrations.lock().unwrap().len()
    }

    /// Reloads the member list from `path`, without dropping any live
    /// registration (section 1: "read at start and on `SIGHUP`").
    ///
    /// # Errors
    ///
    /// Returns a [`GateError`] if `path` cannot be read or parsed.
    pub fn reload_members(&self, path: &std::path::Path) -> Result<(), GateError> {
        let members = MemberList::load(path)?;
        #[allow(clippy::unwrap_used)]
        {
            *self.state.members.lock().unwrap() = members;
        }
        Ok(())
    }
}

async fn accept_loop_secondary(endpoint: quinn::Endpoint, state: Arc<ServerState>) {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            return;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = handle_secondary_connection(incoming, state).await;
        });
    }
}

async fn handle_secondary_connection(
    incoming: quinn::Incoming,
    _state: Arc<ServerState>,
) -> Result<(), GateError> {
    let connection = incoming.accept()?.await?;
    let observed = connection.remote_address();
    let (mut send, mut recv) = connection.accept_bi().await?;
    let frame = wire::read_frame(&mut recv, authed::control_read_deadline()).await?;
    if !matches!(frame, Frame::Reflect { .. }) {
        return Err(GateError::Protocol(
            "expected Reflect as the first frame".into(),
        ));
    }
    let reply = Frame::Reflected {
        v: 1,
        observed: Addr::from_socket_addr(observed),
    };
    wire::write_frame(&mut send, &reply).await?;
    send.finish().ok();
    // Dropping the last `Connection` handle closes it at once (quinn's
    // `ConnectionRef::drop`), which can race the reply actually reaching
    // the house if this task returns immediately. Wait for the house to
    // close its side first (it does, right after reading the reply),
    // bounded so a house that never closes cannot hang this task forever.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), connection.closed()).await;
    Ok(())
}

async fn accept_loop_primary(endpoint: quinn::Endpoint, state: Arc<ServerState>) {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            return;
        };
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = handle_primary_connection(incoming, state).await;
        });
    }
}

async fn handle_primary_connection(
    incoming: quinn::Incoming,
    state: Arc<ServerState>,
) -> Result<(), GateError> {
    let connection = incoming.accept()?.await?;
    let authed = AuthedConnection::new(connection)?;
    let observed = authed.connection().remote_address();
    let peer_key = authed.peer_key();

    let (mut send, mut recv) = authed.connection().accept_bi().await?;
    let frame = wire::read_frame(&mut recv, authed::control_read_deadline()).await?;
    let Frame::Register { v: _, community } = frame else {
        return Err(GateError::Protocol(
            "expected Register as the first frame".into(),
        ));
    };
    if community != state.community {
        send_error_and_close(
            &mut send,
            &authed,
            ErrorCode::RefusedNotMember,
            "wrong community",
        )
        .await;
        return Ok(());
    }
    let is_member = {
        #[allow(clippy::unwrap_used)]
        let members = state.members.lock().unwrap();
        members.contains(&peer_key)
    };
    if !is_member {
        send_error_and_close(
            &mut send,
            &authed,
            ErrorCode::RefusedNotMember,
            "not a member",
        )
        .await;
        return Ok(());
    }

    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<Frame>();
    let registration = Arc::new(RegistrationInner {
        key: peer_key,
        connection: authed.connection().clone(),
        frame_tx,
        observed,
        last_keepalive: StdMutex::new(Instant::now()),
        introduce_min: StdMutex::new(RateLimiter::per_minute(
            limits::INTRODUCE_PER_MINUTE,
            limits::INTRODUCE_PER_MINUTE,
        )),
        introduce_hour: StdMutex::new(RateLimiter::per_minute(
            limits::INTRODUCE_PER_HOUR,
            limits::INTRODUCE_PER_HOUR,
        )),
        sessions: StdMutex::new(HashSet::new()),
    });

    let at_capacity = {
        #[allow(clippy::unwrap_used)]
        let mut registrations = state.registrations.lock().unwrap();
        let full = !registrations.contains_key(&peer_key) && registrations.len() >= state.capacity;
        if !full {
            registrations.insert(peer_key, Arc::clone(&registration));
        }
        full
    };
    if at_capacity {
        state
            .counters
            .registrations_refused_at_capacity
            .fetch_add(1, Ordering::Relaxed);
        send_error_and_close(
            &mut send,
            &authed,
            ErrorCode::AtCapacity,
            "gate at capacity",
        )
        .await;
        return Ok(());
    }

    let registered = Frame::Registered {
        v: 1,
        observed: Addr::from_socket_addr(observed),
        keepalive_s: 15,
        secondary_port: 0,
    };
    wire::write_frame(&mut send, &registered).await?;

    // Writer task: serialises every frame the gate sends this house onto
    // the one control stream.
    let writer = tokio::spawn(async move {
        while let Some(frame) = frame_rx.recv().await {
            if wire::write_frame(&mut send, &frame).await.is_err() {
                return;
            }
        }
    });

    // Relay datagram task: forwards `Relay` datagrams by session, checking
    // the sender's TLS-proven key against both halves of that session.
    let relay_state = Arc::clone(&state);
    let relay_connection = authed.connection().clone();
    let relay_task = tokio::spawn(async move {
        loop {
            match relay_connection.read_datagram().await {
                Ok(datagram) => {
                    if let Ok((session, payload)) = decode_relay(&datagram) {
                        forward_relay(&relay_state, session, peer_key, payload);
                    }
                }
                Err(_) => return,
            }
        }
    });

    // Control frame loop: the rest of section 1's house-to-gate frames.
    let result = control_loop(&state, &registration, &mut recv).await;

    writer.abort();
    relay_task.abort();
    {
        #[allow(clippy::unwrap_used)]
        let mut registrations = state.registrations.lock().unwrap();
        if let Some(current) = registrations.get(&peer_key)
            && Arc::ptr_eq(current, &registration)
        {
            registrations.remove(&peer_key);
        }
    }
    result
}

async fn control_loop(
    state: &Arc<ServerState>,
    registration: &Registration,
    recv: &mut quinn::RecvStream,
) -> Result<(), GateError> {
    loop {
        let frame = match wire::read_frame(recv, std::time::Duration::from_secs(120)).await {
            Ok(f) => f,
            Err(GateError::Timeout) => continue,
            Err(e) => return Err(e),
        };
        match frame {
            Frame::Keepalive { .. } => {
                #[allow(clippy::unwrap_used)]
                {
                    *registration.last_keepalive.lock().unwrap() = Instant::now();
                }
                let _ = registration.frame_tx.send(Frame::KeepaliveAck {
                    v: 1,
                    observed: Addr::from_socket_addr(registration.observed),
                });
            }
            Frame::Introduce {
                tag, ttl_s, sealed, ..
            } => {
                handle_introduce(state, registration, tag, ttl_s, sealed);
            }
            Frame::KnockAnswer { tag, accept, .. } => {
                handle_knock_answer(state, tag, accept);
            }
            Frame::Goodbye { .. } => {
                return Ok(());
            }
            other => {
                return Err(GateError::Protocol(format!(
                    "unexpected frame on the control stream: {other:?}"
                )));
            }
        }
    }
}

fn handle_introduce(
    state: &Arc<ServerState>,
    registration: &Registration,
    tag: [u8; 32],
    ttl_s: u16,
    sealed: Vec<u8>,
) {
    let ttl_s = ttl_s.min(limits::INTRODUCE_TTL_CAP_S);
    {
        #[allow(clippy::unwrap_used)]
        let mut minute = registration.introduce_min.lock().unwrap();
        #[allow(clippy::unwrap_used)]
        let mut hour = registration.introduce_hour.lock().unwrap();
        if !minute.try_take() || !hour.try_take() {
            let _ = registration.frame_tx.send(Frame::Error {
                v: 1,
                code: ErrorCode::RateLimited as u8,
                detail: "introduce rate limit exceeded".into(),
            });
            return;
        }
    }

    let target_key = {
        #[allow(clippy::unwrap_used)]
        let registrations = state.registrations.lock().unwrap();
        registrations
            .keys()
            .find(|candidate| {
                **candidate != registration.key
                    && state.pair_tag(&registration.key, candidate) == tag
            })
            .copied()
    };
    let Some(target_key) = target_key else {
        // No match: silence, per section 1.
        return;
    };
    let target = {
        #[allow(clippy::unwrap_used)]
        let registrations = state.registrations.lock().unwrap();
        registrations.get(&target_key).cloned()
    };
    let Some(target) = target else {
        return;
    };

    {
        #[allow(clippy::unwrap_used)]
        let mut knocks = state.knocks.lock().unwrap();
        knocks.insert(
            tag,
            KnockState {
                requester: registration.key,
                target: target_key,
                deadline: Instant::now() + std::time::Duration::from_secs(u64::from(ttl_s)),
            },
        );
    }

    let _ = target.frame_tx.send(Frame::Knock {
        v: 1,
        tag,
        ttl_s,
        sealed,
    });
}

fn handle_knock_answer(state: &Arc<ServerState>, tag: [u8; 32], accept: bool) {
    let knock = {
        #[allow(clippy::unwrap_used)]
        let mut knocks = state.knocks.lock().unwrap();
        knocks.remove(&tag)
    };
    let Some(knock) = knock else {
        return;
    };
    if Instant::now() > knock.deadline {
        return;
    }
    if !accept {
        // Decline: silence, per section 1.
        return;
    }

    #[allow(clippy::unwrap_used)]
    let registrations = state.registrations.lock().unwrap();
    let Some(requester) = registrations.get(&knock.requester) else {
        return;
    };
    let Some(target) = registrations.get(&knock.target) else {
        return;
    };
    if requester
        .sessions
        .lock()
        .map(|s| s.len())
        .unwrap_or(usize::MAX)
        >= limits::MAX_SESSIONS_PER_REGISTRATION
        || target
            .sessions
            .lock()
            .map(|s| s.len())
            .unwrap_or(usize::MAX)
            >= limits::MAX_SESSIONS_PER_REGISTRATION
    {
        return;
    }

    let mut session_id: u32 = rand::rng().random();
    #[allow(clippy::unwrap_used)]
    let mut sessions = state.sessions.lock().unwrap();
    while sessions.contains_key(&session_id) {
        session_id = rand::rng().random();
    }
    sessions.insert(
        session_id,
        SessionState {
            key_a: knock.requester,
            key_b: knock.target,
        },
    );
    drop(sessions);

    #[allow(clippy::unwrap_used)]
    {
        requester.sessions.lock().unwrap().insert(session_id);
        target.sessions.lock().unwrap().insert(session_id);
    }

    let _ = requester.frame_tx.send(Frame::Introduction {
        v: 1,
        tag,
        session: session_id,
        peer_observed: Addr::from_socket_addr(target.observed),
        role: 1,
    });
    let _ = target.frame_tx.send(Frame::Introduction {
        v: 1,
        tag,
        session: session_id,
        peer_observed: Addr::from_socket_addr(requester.observed),
        role: 2,
    });
}

fn forward_relay(state: &Arc<ServerState>, session: u32, sender_key: [u8; 32], payload: &[u8]) {
    let other_key = {
        #[allow(clippy::unwrap_used)]
        let sessions = state.sessions.lock().unwrap();
        let Some(session_state) = sessions.get(&session) else {
            state
                .counters
                .relay_sender_mismatch
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        if session_state.key_a == sender_key {
            Some(session_state.key_b)
        } else if session_state.key_b == sender_key {
            Some(session_state.key_a)
        } else {
            None
        }
    };
    let Some(other_key) = other_key else {
        state
            .counters
            .relay_sender_mismatch
            .fetch_add(1, Ordering::Relaxed);
        return;
    };
    let other = {
        #[allow(clippy::unwrap_used)]
        let registrations = state.registrations.lock().unwrap();
        registrations.get(&other_key).cloned()
    };
    let Some(other) = other else {
        return;
    };
    if let Ok(encoded) = encode_relay(session, payload) {
        let _ = other.connection.send_datagram(encoded.into());
    }
}

async fn send_error_and_close(
    send: &mut quinn::SendStream,
    authed: &AuthedConnection,
    code: ErrorCode,
    detail: &str,
) {
    let frame = Frame::Error {
        v: 1,
        code: code as u8,
        detail: detail.chars().take(wire::ERROR_DETAIL_CAP).collect(),
    };
    let _ = wire::write_frame(send, &frame).await;
    let _ = send.finish();
    authed.connection().close(0u32.into(), detail.as_bytes());
}

/// Generates a fresh random ed25519 identity seed for a gate that was not
/// given one explicitly. A real gate persists its identity across restarts;
/// that lands with the rest of Phase 2's key handling (D4), so this is a
/// process-lifetime identity only, mirroring the WO-1.2 spike's own
/// default.
#[must_use]
pub fn generate_identity_seed() -> [u8; 32] {
    rand::rng().random()
}
