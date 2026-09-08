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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rand::RngExt;
use tokio::sync::mpsc;

use crate::authed::{self, AuthedConnection};
use crate::gate::wire::{self, Addr, Frame, decode_relay, encode_relay};
use crate::gate::{ErrorCode, GateError, MemberList, RateLimiter, limits};
use crate::lockext::LockExt;

/// Counters a test (or an operator) can read back from a running gate.
#[derive(Debug, Default)]
pub struct ServerCounters {
    /// `Relay` datagrams dropped because the sender was neither key of the
    /// named session (section 1: "dropped and counted, never answered").
    pub relay_sender_mismatch: AtomicU64,
    /// `Relay` datagrams dropped because the sending half of the session
    /// exceeded its per-direction datagram or byte rate (section 1: 2000
    /// datagrams/s and the 2 GiB/hour cap, each way).
    pub relay_rate_limited: AtomicU64,
    /// Registration attempts refused because the slot table was already at
    /// capacity.
    pub registrations_refused_at_capacity: AtomicU64,
    /// `KnockAnswer` frames dropped because the answering registration was
    /// not the knock's own target (Yseult finding 2: previously any
    /// registrant holding the tag could accept or cancel a knock addressed
    /// to someone else).
    pub knock_answered_by_wrong_target: AtomicU64,
    /// Connections refused before a slot was touched because
    /// [`limits::MAX_PENDING_CONNECTIONS`] handshaked-but-not-yet-registered
    /// connections were already outstanding.
    pub pending_connections_refused: AtomicU64,
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

/// A per-direction budget on one live relay session: section 1's 2000
/// datagrams/s and 2 GiB/hour caps, each way, tracked independently so one
/// direction filling up never throttles the other.
struct RelayLimiter {
    datagrams: RateLimiter,
    bytes: RateLimiter,
}

impl RelayLimiter {
    fn new() -> Self {
        Self {
            datagrams: RateLimiter::per_second(
                limits::RELAY_DATAGRAMS_PER_SECOND,
                limits::RELAY_DATAGRAMS_PER_SECOND,
            ),
            #[allow(clippy::cast_precision_loss)]
            bytes: RateLimiter::capacity_per_hour(limits::RELAY_BYTES_PER_HOUR as f64),
        }
    }
}

struct SessionState {
    key_a: [u8; 32],
    key_b: [u8; 32],
    /// Charged against a datagram sent by `key_a`, forwarded to `key_b`.
    a_to_b: StdMutex<RelayLimiter>,
    /// Charged against a datagram sent by `key_b`, forwarded to `key_a`.
    b_to_a: StdMutex<RelayLimiter>,
}

struct ServerState {
    community: [u8; 32],
    members: StdMutex<MemberList>,
    capacity: usize,
    secondary_port: u16,
    registrations: StdMutex<HashMap<[u8; 32], Vec<Registration>>>,
    knocks: StdMutex<HashMap<[u8; 32], KnockState>>,
    sessions: StdMutex<HashMap<u32, SessionState>>,
    pending_handshakes: AtomicUsize,
    /// Section 1: "4 connection attempts per key per minute", tracked
    /// separately from [`limits::MAX_CONNECTIONS_PER_KEY`], which bounds
    /// concurrent connections rather than the rate of new ones.
    register_attempts: StdMutex<HashMap<[u8; 32], RateLimiter>>,
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

/// Removes `registration` from its key's slot and from every live session it
/// still holds, notifying the other half of each such session so a session
/// never outlives the registration that owns one of its two keys (Konrad
/// finding 4: previously nothing ever removed a session, so a gone
/// registrant's old sessions stayed forwardable, and counted against the
/// other party's `MAX_SESSIONS_PER_REGISTRATION`, forever).
fn teardown_registration(
    state: &Arc<ServerState>,
    peer_key: [u8; 32],
    registration: &Registration,
) {
    {
        let mut registrations = state.registrations.lock_or_recover();
        if let Some(list) = registrations.get_mut(&peer_key) {
            list.retain(|r| !Arc::ptr_eq(r, registration));
            if list.is_empty() {
                registrations.remove(&peer_key);
            }
        }
    }
    let session_ids: Vec<u32> = registration
        .sessions
        .lock_or_recover()
        .iter()
        .copied()
        .collect();
    if session_ids.is_empty() {
        return;
    }
    let mut orphaned = Vec::new();
    {
        let mut sessions = state.sessions.lock_or_recover();
        for id in session_ids {
            if let Some(session_state) = sessions.remove(&id) {
                let other_key = if session_state.key_a == peer_key {
                    session_state.key_b
                } else {
                    session_state.key_a
                };
                orphaned.push((other_key, id));
            }
        }
    }
    if orphaned.is_empty() {
        return;
    }
    let registrations = state.registrations.lock_or_recover();
    for (other_key, id) in orphaned {
        if let Some(list) = registrations.get(&other_key) {
            for reg in list {
                reg.sessions.lock_or_recover().remove(&id);
            }
        }
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
/// How often the background sweep (expired knocks, silent-past-TTL
/// registrations) runs. Chosen, not measured: well under
/// [`limits::REGISTRATION_TTL`] and any reasonable `Introduce.ttl_s`, so
/// nothing waits more than one tick past its own deadline.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

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
            secondary_port: secondary_addr.port(),
            registrations: StdMutex::new(HashMap::new()),
            knocks: StdMutex::new(HashMap::new()),
            sessions: StdMutex::new(HashMap::new()),
            pending_handshakes: AtomicUsize::new(0),
            register_attempts: StdMutex::new(HashMap::new()),
            counters: ServerCounters::default(),
        });

        tokio::spawn(accept_loop_primary(primary, Arc::clone(&state)));
        tokio::spawn(accept_loop_secondary(secondary, Arc::clone(&state)));
        tokio::spawn(sweep_loop(Arc::clone(&state)));

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

    /// The number of currently live registrations (distinct keys), for
    /// tests.
    #[must_use]
    pub fn registration_count(&self) -> usize {
        self.state.registrations.lock_or_recover().len()
    }

    /// The number of connections held for one key, for tests exercising the
    /// per-key sub-cap.
    #[must_use]
    pub fn connections_for_key(&self, key: &[u8; 32]) -> usize {
        self.state
            .registrations
            .lock_or_recover()
            .get(key)
            .map_or(0, Vec::len)
    }

    /// The number of currently live relay sessions, for tests.
    #[must_use]
    pub fn session_count(&self) -> usize {
        self.state.sessions.lock_or_recover().len()
    }

    /// Reloads the member list from `path`, without dropping any live
    /// registration (section 1: "read at start and on `SIGHUP`").
    ///
    /// # Errors
    ///
    /// Returns a [`GateError`] if `path` cannot be read or parsed.
    pub fn reload_members(&self, path: &std::path::Path) -> Result<(), GateError> {
        let members = MemberList::load(path)?;
        *self.state.members.lock_or_recover() = members;
        Ok(())
    }
}

async fn sweep_loop(state: Arc<ServerState>) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        interval.tick().await;
        sweep_once(&state);
    }
}

/// One sweep pass (Konrad finding 4): drops knocks past their own `ttl_s`
/// deadline, and closes and tears down any registration silent past
/// [`limits::REGISTRATION_TTL`] since its last keepalive, both previously
/// unimplemented.
fn sweep_once(state: &Arc<ServerState>) {
    let now = Instant::now();
    {
        let mut knocks = state.knocks.lock_or_recover();
        knocks.retain(|_, k| k.deadline > now);
    }
    {
        let mut attempts = state.register_attempts.lock_or_recover();
        attempts.retain(|_, limiter| !limiter.is_full());
    }
    let expired: Vec<([u8; 32], Registration)> = {
        let registrations = state.registrations.lock_or_recover();
        registrations
            .iter()
            .flat_map(|(key, list)| {
                list.iter().filter_map(move |r| {
                    let last = *r.last_keepalive.lock_or_recover();
                    if now.duration_since(last) > limits::REGISTRATION_TTL {
                        Some((*key, Arc::clone(r)))
                    } else {
                        None
                    }
                })
            })
            .collect()
    };
    for (key, registration) in expired {
        registration
            .connection
            .close(0u32.into(), b"registration expired");
        teardown_registration(state, key, &registration);
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
    state: Arc<ServerState>,
) -> Result<(), GateError> {
    let connection = incoming.accept()?.await?;
    let authed = AuthedConnection::new(connection)?;
    // Yseult finding 4: the secondary (reflection) endpoint never checked
    // membership at all, so any key on the internet got a free address
    // reflection and a five second hold. It now runs the same TLS-proven
    // membership check the primary endpoint does before doing anything
    // else.
    let is_member = {
        let members = state.members.lock_or_recover();
        members.contains(&authed.peer_key())
    };
    if !is_member {
        authed.connection().close(0u32.into(), b"not a member");
        return Ok(());
    }
    let observed = authed.connection().remote_address();
    let (mut send, mut recv) = tokio::time::timeout(
        authed::control_read_deadline(),
        authed.connection().accept_bi(),
    )
    .await
    .map_err(|_| GateError::Timeout)??;
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
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        authed.connection().closed(),
    )
    .await;
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

/// Holds one slot of [`limits::MAX_PENDING_CONNECTIONS`] for a connection
/// that has completed the TLS handshake but not yet completed `Register`
/// (Yseult finding 4: previously nothing bounded this population, and
/// `accept_bi` carried no deadline, so a peer that connected and then sent
/// nothing held a slot forever).
struct PendingGuard<'a> {
    counter: &'a AtomicUsize,
}

impl<'a> PendingGuard<'a> {
    fn acquire(counter: &'a AtomicUsize, cap: usize) -> Option<Self> {
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            if current >= cap {
                return None;
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Self { counter }),
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
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

    let Some(pending) =
        PendingGuard::acquire(&state.pending_handshakes, limits::MAX_PENDING_CONNECTIONS)
    else {
        state
            .counters
            .pending_connections_refused
            .fetch_add(1, Ordering::Relaxed);
        authed.connection().close(0u32.into(), b"gate at capacity");
        return Ok(());
    };

    // Section 1: "4 connection attempts per key per minute".
    let attempt_allowed = {
        let mut attempts = state.register_attempts.lock_or_recover();
        let limiter = attempts.entry(peer_key).or_insert_with(|| {
            RateLimiter::per_minute(
                limits::REGISTER_ATTEMPTS_PER_MINUTE,
                limits::REGISTER_ATTEMPTS_PER_MINUTE,
            )
        });
        limiter.try_take()
    };
    if !attempt_allowed {
        authed.connection().close(0u32.into(), b"gate_rate_limited");
        return Ok(());
    }

    // Deadline the first stream too, not just the `Register` frame that
    // follows it: a connected peer that never opens a bi stream at all
    // previously held its slot (and quinn's `keep_alive_interval`) forever.
    let (mut send, mut recv) = tokio::time::timeout(
        authed::control_read_deadline(),
        authed.connection().accept_bi(),
    )
    .await
    .map_err(|_| GateError::Timeout)??;
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
        let members = state.members.lock_or_recover();
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
        introduce_hour: StdMutex::new(RateLimiter::per_hour(
            limits::INTRODUCE_PER_HOUR,
            limits::INTRODUCE_PER_HOUR,
        )),
        sessions: StdMutex::new(HashSet::new()),
    });

    // Within one key, section 1 allows 2 live connections, a third evicting
    // that key's oldest by last keepalive (Konrad finding 3 on the earlier
    // draft: a second connection for the same key silently replaced the
    // first in the map without closing it, leaving it orphaned rather than
    // torn down).
    let (evicted, at_capacity) = {
        let mut registrations = state.registrations.lock_or_recover();
        let is_new_key = !registrations.contains_key(&peer_key);
        if is_new_key && registrations.len() >= state.capacity {
            (None, true)
        } else {
            let list = registrations.entry(peer_key).or_default();
            let evicted = if list.len() >= limits::MAX_CONNECTIONS_PER_KEY {
                let oldest = list
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, r)| *r.last_keepalive.lock_or_recover())
                    .map(|(i, _)| i);
                oldest.map(|i| list.remove(i))
            } else {
                None
            };
            list.push(Arc::clone(&registration));
            (evicted, false)
        }
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
    if let Some(evicted) = evicted {
        evicted
            .connection
            .close(0u32.into(), b"displaced: connection cap per key reached");
        teardown_registration(&state, peer_key, &evicted);
    }

    let registered = Frame::Registered {
        v: 1,
        observed: Addr::from_socket_addr(observed),
        keepalive_s: 15,
        secondary_port: state.secondary_port,
    };
    wire::write_frame(&mut send, &registered).await?;

    // This connection is registered now, not merely handshaked: free its
    // pending-handshake slot for the next connection rather than holding it
    // for this connection's whole lifetime.
    drop(pending);

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
    teardown_registration(&state, peer_key, &registration);
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
                *registration.last_keepalive.lock_or_recover() = Instant::now();
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
                handle_knock_answer(state, registration, tag, accept);
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
        let mut minute = registration.introduce_min.lock_or_recover();
        let mut hour = registration.introduce_hour.lock_or_recover();
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
        let registrations = state.registrations.lock_or_recover();
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
        let registrations = state.registrations.lock_or_recover();
        registrations
            .get(&target_key)
            .and_then(|list| list.last().cloned())
    };
    let Some(target) = target else {
        return;
    };

    {
        let mut knocks = state.knocks.lock_or_recover();
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

fn handle_knock_answer(
    state: &Arc<ServerState>,
    registration: &Registration,
    tag: [u8; 32],
    accept: bool,
) {
    // Yseult finding 2 / Konrad finding 3: a `KnockAnswer` is accepted only
    // from the registration whose key is the knock's own target. Anything
    // else -- including a member who can compute `tag(A, B)` for a pair
    // it is not part of -- is dropped and counted, and critically the knock
    // itself is left outstanding rather than consumed, so the real target
    // can still answer it before its `ttl_s` elapses.
    let knock = {
        let mut knocks = state.knocks.lock_or_recover();
        let is_target = knocks
            .get(&tag)
            .is_some_and(|k| k.target == registration.key);
        if !is_target {
            if knocks.contains_key(&tag) {
                state
                    .counters
                    .knock_answered_by_wrong_target
                    .fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
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

    let registrations = state.registrations.lock_or_recover();
    let Some(requester) = registrations
        .get(&knock.requester)
        .and_then(|list| list.last())
    else {
        return;
    };
    let Some(target) = registrations
        .get(&knock.target)
        .and_then(|list| list.last())
    else {
        return;
    };
    if requester.sessions.lock_or_recover().len() >= limits::MAX_SESSIONS_PER_REGISTRATION
        || target.sessions.lock_or_recover().len() >= limits::MAX_SESSIONS_PER_REGISTRATION
    {
        return;
    }

    let mut session_id: u32 = rand::rng().random();
    let mut sessions = state.sessions.lock_or_recover();
    while sessions.contains_key(&session_id) {
        session_id = rand::rng().random();
    }
    sessions.insert(
        session_id,
        SessionState {
            key_a: knock.requester,
            key_b: knock.target,
            a_to_b: StdMutex::new(RelayLimiter::new()),
            b_to_a: StdMutex::new(RelayLimiter::new()),
        },
    );
    drop(sessions);

    requester.sessions.lock_or_recover().insert(session_id);
    target.sessions.lock_or_recover().insert(session_id);

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
    #[allow(clippy::cast_precision_loss)]
    let payload_len = payload.len() as f64;
    let other_key = {
        let sessions = state.sessions.lock_or_recover();
        let Some(session_state) = sessions.get(&session) else {
            state
                .counters
                .relay_sender_mismatch
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let (other_key, limiter) = if session_state.key_a == sender_key {
            (session_state.key_b, &session_state.a_to_b)
        } else if session_state.key_b == sender_key {
            (session_state.key_a, &session_state.b_to_a)
        } else {
            state
                .counters
                .relay_sender_mismatch
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let mut limiter = limiter.lock_or_recover();
        let allowed = limiter.datagrams.try_take() && limiter.bytes.try_take_n(payload_len);
        if allowed { Some(other_key) } else { None }
    };
    let Some(other_key) = other_key else {
        state
            .counters
            .relay_rate_limited
            .fetch_add(1, Ordering::Relaxed);
        return;
    };
    let other = {
        let registrations = state.registrations.lock_or_recover();
        registrations
            .get(&other_key)
            .and_then(|list| list.last().cloned())
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
