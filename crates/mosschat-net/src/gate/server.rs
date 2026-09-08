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
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rand::RngExt;
use tokio::sync::mpsc;

use crate::authed::{self, AuthedConnection};
use crate::gate::wire::{self, Addr, Frame, decode_relay, encode_relay};
use crate::gate::{ErrorCode, GateError, MemberList, RateLimiter, limits};
use crate::lockext::LockExt;
use crate::path::{RelayShaper, ShaperStats};

/// Counters a test (or an operator) can read back from a running gate.
#[derive(Debug, Default)]
pub struct ServerCounters {
    /// `Relay` datagrams dropped because the sender was neither key of the
    /// named session (section 1: "dropped and counted, never answered").
    pub relay_sender_mismatch: AtomicU64,
    /// `Relay` datagrams dropped because the sending half of the session
    /// exhausted its per-direction volume budget, section 1's 2 GiB per
    /// session per hour, which is the only byte ceiling the design still
    /// names.
    ///
    /// It no longer counts the per-second datagram rate: that was a
    /// policer, whose drops are invisible to the peer connection's
    /// congestion control, and amended section 1 replaces it with the
    /// shaper below (issue #19). Nothing else may be counted here, so the
    /// name keeps naming something the design still has.
    pub relay_rate_limited: AtomicU64,
    /// `Relay` datagrams dropped because the forwarding direction's shaper
    /// queue was already at [`crate::path::GATE_RELAY_QUEUE_DEPTH`]
    /// (section 1: the gate cannot push back on unreliable datagrams, so
    /// it drops the newest and counts it, but only when full: 0 for a
    /// shaping house, the abuse cap in the open otherwise).
    pub relay_dropped_at_full: AtomicU64,
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
    /// A third connection for one key refused with `gate_at_capacity`
    /// (amended section 1: the sub-cap refuses rather than evicting the
    /// oldest of the two already seated).
    pub connections_refused_at_key_capacity: AtomicU64,
    /// An inbound `Relay` datagram dropped because it failed to decode
    /// (chiefly an over-cap payload): previously silent (Konrad finding 5
    /// remainder).
    pub relay_oversized_dropped: AtomicU64,
    /// A control frame dropped because the connection's frame rate limit
    /// (section 1: 32/s, burst 64) was exceeded.
    pub frame_rate_limited: AtomicU64,
    /// A `Reflect` request refused because that key's `Reflect` rate limit
    /// (section 1: 2/minute) was exceeded.
    pub reflect_rate_limited: AtomicU64,
    /// A `Keepalive` dropped because the connection's keepalive rate limit
    /// (section 1: 3/s tolerated) was exceeded.
    pub keepalive_rate_limited: AtomicU64,
    /// A gate-to-house frame dropped because [`limits::FRAME_TX_QUEUE_CAP`]
    /// was already full (Yseult finding 5 remainder: `frame_tx` was
    /// previously unbounded).
    pub frame_tx_dropped: AtomicU64,
    /// A `StartRequest` naming a session this gate does not hold, dropped
    /// in silence.
    pub start_request_unknown_session: AtomicU64,
    /// A `StartRequest` from a connection that is neither key of the named
    /// session, dropped in silence: answering would be an oracle for live
    /// sessions, exactly as it would be for a `Relay` datagram.
    pub start_request_wrong_sender: AtomicU64,
    /// A `StartRequest` past section 1's 4 per session, ignored.
    pub start_requests_ignored: AtomicU64,
}

struct RegistrationInner {
    key: [u8; 32],
    connection: quinn::Connection,
    /// Bounded at [`limits::FRAME_TX_QUEUE_CAP`] (Yseult finding 5
    /// remainder); sent through [`send_frame`], which drops the newest
    /// frame and counts it rather than blocking or growing without limit.
    frame_tx: mpsc::Sender<Frame>,
    observed: std::net::SocketAddr,
    last_keepalive: StdMutex<Instant>,
    introduce_min: StdMutex<RateLimiter>,
    introduce_hour: StdMutex<RateLimiter>,
    sessions: StdMutex<HashSet<u32>>,
    /// Section 1: "any control frame ... 32 frames per second per
    /// connection with burst 64", checked on every frame the control loop
    /// reads for this registration.
    frame_rate: StdMutex<RateLimiter>,
    /// Section 1: "`Keepalive`: one per `keepalive_s`, 3 per second
    /// tolerated", tracked separately from the general frame rate so an
    /// ordinary keepalive burst is not charged against it.
    keepalive_rate: StdMutex<RateLimiter>,
}

type Registration = Arc<RegistrationInner>;

struct KnockState {
    requester: [u8; 32],
    target: [u8; 32],
    deadline: Instant,
}

/// A per-direction volume budget on one live relay session: section 1's 2
/// GiB per hour, each way, tracked independently so one direction filling
/// up never throttles the other.
///
/// The per-second datagram half of this used to live here as a second
/// token bucket, and it was a policer: it dropped, and the drops were
/// invisible to the congestion control of the connection whose packets
/// they were, which is issue #19's stall. Amended section 1 replaces it
/// with [`RelayShaper`], which delays instead. What is left here is the
/// volume ceiling, which is a real cap on a rented box's bill rather than
/// a rate applied to a data path.
struct RelayLimiter {
    bytes: RateLimiter,
}

impl RelayLimiter {
    fn new() -> Self {
        Self {
            #[allow(clippy::cast_precision_loss)]
            bytes: RateLimiter::capacity_per_hour(limits::RELAY_BYTES_PER_HOUR as f64),
        }
    }
}

struct SessionState {
    key_a: [u8; 32],
    key_b: [u8; 32],
    /// Section 1: "`StartRequest`: 4 per session, then ignored". Counted
    /// per session rather than per connection, because both houses of one
    /// session share the budget: `Start` goes to both of them, so a fifth
    /// request costs the peer a frame as much as the asker.
    start_requests: AtomicU32,
    /// The instant this session was introduced, which is what `Start`'s
    /// `gate_ms` is measured from: a monotonic gate clock both houses write
    /// into their diagnostics records so two logs can be aligned. It is
    /// never a time to act on, so it needs no relation to anyone's wall
    /// clock and must not be one.
    opened_at: Instant,
    /// Charged against a datagram sent by `key_a`, forwarded to `key_b`.
    a_to_b: StdMutex<RelayLimiter>,
    /// Charged against a datagram sent by `key_b`, forwarded to `key_a`.
    b_to_a: StdMutex<RelayLimiter>,
    /// Section 1's shaper, one queue per direction, drained by its own
    /// task at 10 percent over the house rate.
    a_to_b_shaper: RelayShaper,
    /// The `key_b` to `key_a` direction's queue.
    b_to_a_shaper: RelayShaper,
}

impl SessionState {
    /// Ends both directions, so each drain task's next `drain` returns
    /// `None` and the task exits.
    fn close_shapers(&self) {
        self.a_to_b_shaper.close();
        self.b_to_a_shaper.close();
    }

    /// This session's two directions folded into one summary (section 7).
    fn shaper_stats(&self) -> ShaperStats {
        self.a_to_b_shaper
            .stats()
            .merged(self.b_to_a_shaper.stats())
    }
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
    /// Section 1: "`Reflect`: ... 2 per minute", tracked per key since each
    /// `Reflect` rides its own short-lived secondary-port connection rather
    /// than a long-lived registration.
    reflect_attempts: StdMutex<HashMap<[u8; 32], RateLimiter>>,
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

/// Queues `frame` for `registration`'s writer task, dropping and counting it
/// rather than blocking or growing the channel without limit if
/// [`limits::FRAME_TX_QUEUE_CAP`] is already full (Yseult finding 5
/// remainder: `frame_tx` was previously unbounded).
fn send_frame(state: &Arc<ServerState>, registration: &Registration, frame: Frame) {
    if registration.frame_tx.try_send(frame).is_err() {
        state
            .counters
            .frame_tx_dropped
            .fetch_add(1, Ordering::Relaxed);
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
                session_state.close_shapers();
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

        // `grease_quic_bit(false)` for the same reason the house sets it
        // (see `client.rs`): the gate's own packets travel over the house's
        // porch socket, past a probe filter that reads the first byte, so
        // the gate must not clear the fixed bit either. `Endpoint::new`
        // rather than `Endpoint::server` only because the latter takes no
        // `EndpointConfig`.
        let mut endpoint_config = quinn::EndpointConfig::default();
        endpoint_config.grease_quic_bit(false);
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let primary = quinn::Endpoint::new(
            endpoint_config.clone(),
            Some(server_config.clone()),
            std::net::UdpSocket::bind(config.primary_bind)?,
            Arc::clone(&runtime),
        )?;
        let secondary = quinn::Endpoint::new(
            endpoint_config,
            Some(server_config),
            std::net::UdpSocket::bind(config.secondary_bind)?,
            runtime,
        )?;
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
            reflect_attempts: StdMutex::new(HashMap::new()),
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

    /// Every live session's shaper counters folded into one summary
    /// (section 7's `relay_queued`, `relay_shaped_delay_us` and
    /// `relay_dropped_at_full`, as this gate sees them).
    #[must_use]
    pub fn relay_shaper_stats(&self) -> ShaperStats {
        self.state
            .sessions
            .lock_or_recover()
            .values()
            .fold(ShaperStats::default(), |acc, session| {
                acc.merged(session.shaper_stats())
            })
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
    {
        let mut attempts = state.reflect_attempts.lock_or_recover();
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

    // Section 1: "`Reflect`: ... 2 per minute", tracked per key.
    let reflect_allowed = {
        let mut attempts = state.reflect_attempts.lock_or_recover();
        let limiter = attempts.entry(authed.peer_key()).or_insert_with(|| {
            RateLimiter::per_minute(limits::REFLECT_PER_MINUTE, limits::REFLECT_PER_MINUTE)
        });
        limiter.try_take()
    };
    if !reflect_allowed {
        state
            .counters
            .reflect_rate_limited
            .fetch_add(1, Ordering::Relaxed);
        authed.connection().close(0u32.into(), b"gate_rate_limited");
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

    // Yseult finding 4 / amended section 1: membership is proven by the TLS
    // handshake alone, so it is checked here, before the gate ever awaits a
    // stream, not after `accept_bi` plus a `Register` read. Previously an
    // off-list key held one of `MAX_PENDING_CONNECTIONS` slots for the full
    // 10s control-read deadline before being refused.
    let is_member = {
        let members = state.members.lock_or_recover();
        members.contains(&peer_key)
    };
    if !is_member {
        authed.connection().close(0u32.into(), b"not a member");
        return Ok(());
    }

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
    // Membership is already proven above, before any stream was opened; not
    // re-checked here.

    let (frame_tx, mut frame_rx) = mpsc::channel::<Frame>(limits::FRAME_TX_QUEUE_CAP);
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
        frame_rate: StdMutex::new(RateLimiter::per_second(
            limits::FRAME_RATE_BURST,
            limits::FRAME_RATE_PER_SECOND,
        )),
        keepalive_rate: StdMutex::new(RateLimiter::per_second(
            limits::KEEPALIVE_PER_SECOND,
            limits::KEEPALIVE_PER_SECOND,
        )),
    });

    // Amended section 1: within one key, the sub-cap is 2 live connections;
    // a third is refused with `gate_at_capacity` in the handshake, the two
    // already seated left untouched. Never a silent displacement (Konrad
    // finding 3 on an earlier draft, and amendment 1 rejecting this same
    // WO's own earlier eviction-by-oldest-keepalive reading): a house
    // evicted without being told would believe it is still registered
    // while its knocks went nowhere. One whose mapping died comes back
    // through expiry (`sweep_once`) instead.
    enum Refusal {
        GateAtCapacity,
        KeyAtCapacity,
    }
    let refused = {
        let mut registrations = state.registrations.lock_or_recover();
        let is_new_key = !registrations.contains_key(&peer_key);
        if is_new_key && registrations.len() >= state.capacity {
            Some(Refusal::GateAtCapacity)
        } else {
            let current = registrations.get(&peer_key).map_or(0, Vec::len);
            if current >= limits::MAX_CONNECTIONS_PER_KEY {
                Some(Refusal::KeyAtCapacity)
            } else {
                registrations
                    .entry(peer_key)
                    .or_default()
                    .push(Arc::clone(&registration));
                None
            }
        }
    };
    if let Some(refusal) = refused {
        match refusal {
            Refusal::GateAtCapacity => state
                .counters
                .registrations_refused_at_capacity
                .fetch_add(1, Ordering::Relaxed),
            Refusal::KeyAtCapacity => state
                .counters
                .connections_refused_at_key_capacity
                .fetch_add(1, Ordering::Relaxed),
        };
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
                Ok(datagram) => match decode_relay(&datagram) {
                    Ok((session, payload)) => {
                        forward_relay(&relay_state, session, peer_key, payload);
                    }
                    Err(_) => {
                        // An over-cap or otherwise malformed `Relay`
                        // datagram (Konrad finding 5 remainder): previously
                        // silently dropped, never counted.
                        relay_state
                            .counters
                            .relay_oversized_dropped
                            .fetch_add(1, Ordering::Relaxed);
                    }
                },
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

        // Section 1: "any control frame ... 32 frames per second per
        // connection with burst 64" (Konrad finding 5 remainder). Over the
        // limit, the generic policy applies: answer `gate_rate_limited` and
        // keep the registration, dropping only this frame.
        if !registration.frame_rate.lock_or_recover().try_take() {
            state
                .counters
                .frame_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            send_frame(
                state,
                registration,
                Frame::Error {
                    v: 1,
                    code: ErrorCode::RateLimited as u8,
                    detail: "frame rate limit exceeded".into(),
                },
            );
            continue;
        }

        match frame {
            Frame::Keepalive { .. } => {
                // Section 1: "`Keepalive`: one per `keepalive_s`, 3 per
                // second tolerated", tracked separately from the general
                // frame rate so an ordinary keepalive burst is not charged
                // against it.
                if !registration.keepalive_rate.lock_or_recover().try_take() {
                    state
                        .counters
                        .keepalive_rate_limited
                        .fetch_add(1, Ordering::Relaxed);
                    send_frame(
                        state,
                        registration,
                        Frame::Error {
                            v: 1,
                            code: ErrorCode::RateLimited as u8,
                            detail: "keepalive rate limit exceeded".into(),
                        },
                    );
                    continue;
                }
                *registration.last_keepalive.lock_or_recover() = Instant::now();
                send_frame(
                    state,
                    registration,
                    Frame::KeepaliveAck {
                        v: 1,
                        observed: Addr::from_socket_addr(registration.observed),
                    },
                );
            }
            Frame::Introduce {
                tag, ttl_s, sealed, ..
            } => {
                handle_introduce(state, registration, tag, ttl_s, sealed);
            }
            Frame::KnockAnswer { tag, accept, .. } => {
                handle_knock_answer(state, registration, tag, accept);
            }
            Frame::StartRequest { session, .. } => {
                handle_start_request(state, registration, session);
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
            send_frame(
                state,
                registration,
                Frame::Error {
                    v: 1,
                    code: ErrorCode::RateLimited as u8,
                    detail: "introduce rate limit exceeded".into(),
                },
            );
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

    send_frame(
        state,
        &target,
        Frame::Knock {
            v: 1,
            tag,
            ttl_s,
            sealed,
        },
    );
}

/// Section 2 step 4: either side may ask, and the gate answers by sending
/// `Start` **to both houses back to back**, so the two first probes cross
/// inside a firewall's state window without any clock being synchronised.
///
/// The asker is checked against the session the way `forward_relay` checks
/// a datagram's sender, and for the same reason: the session id is the
/// authorisation, so a member who guessed one must not be able to make the
/// gate fire two other houses' bursts. A request naming a session this
/// connection is not a party to is dropped and counted, never answered,
/// since an error frame would be an oracle for live sessions.
fn handle_start_request(state: &Arc<ServerState>, registration: &Registration, session: u32) {
    let (key_a, key_b, gate_ms, over_limit) = {
        let sessions = state.sessions.lock_or_recover();
        let Some(session_state) = sessions.get(&session) else {
            state
                .counters
                .start_request_unknown_session
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        if session_state.key_a != registration.key && session_state.key_b != registration.key {
            state
                .counters
                .start_request_wrong_sender
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let taken = session_state.start_requests.fetch_add(1, Ordering::Relaxed);
        (
            session_state.key_a,
            session_state.key_b,
            u64::try_from(session_state.opened_at.elapsed().as_millis()).unwrap_or(u64::MAX),
            taken >= limits::START_REQUESTS_PER_SESSION,
        )
    };
    if over_limit {
        // Section 1: "4 per session, then ignored". Ignored, not refused:
        // an error frame here is one more frame for a peer to make the gate
        // send, and the two houses have already been told to start.
        state
            .counters
            .start_requests_ignored
            .fetch_add(1, Ordering::Relaxed);
        return;
    }
    let start = Frame::Start {
        v: 1,
        session,
        fire_in_ms: limits::START_FIRE_IN_MS,
        gate_ms,
    };
    let registrations = state.registrations.lock_or_recover();
    for key in [key_a, key_b] {
        if let Some(target) = registrations.get(&key).and_then(|list| list.last()) {
            send_frame(state, target, start.clone());
        }
    }
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
    let a_to_b_shaper = RelayShaper::gate();
    let b_to_a_shaper = RelayShaper::gate();
    sessions.insert(
        session_id,
        SessionState {
            key_a: knock.requester,
            key_b: knock.target,
            start_requests: AtomicU32::new(0),
            opened_at: Instant::now(),
            a_to_b: StdMutex::new(RelayLimiter::new()),
            b_to_a: StdMutex::new(RelayLimiter::new()),
            a_to_b_shaper: a_to_b_shaper.clone(),
            b_to_a_shaper: b_to_a_shaper.clone(),
        },
    );
    drop(sessions);

    // One drain task per direction, started with the session and ended
    // with it (`SessionState::close_shapers` on teardown, and a lost
    // destination connection).
    spawn_relay_drain(state, session_id, knock.target, a_to_b_shaper);
    spawn_relay_drain(state, session_id, knock.requester, b_to_a_shaper);

    requester.sessions.lock_or_recover().insert(session_id);
    target.sessions.lock_or_recover().insert(session_id);

    send_frame(
        state,
        requester,
        Frame::Introduction {
            v: 1,
            tag,
            session: session_id,
            peer_observed: Addr::from_socket_addr(target.observed),
            role: 1,
        },
    );
    send_frame(
        state,
        target,
        Frame::Introduction {
            v: 1,
            tag,
            session: session_id,
            peer_observed: Addr::from_socket_addr(requester.observed),
            role: 2,
        },
    );
}

/// Forwards one `Relay` datagram to the other half of its session, through
/// that direction's shaper queue (section 1).
///
/// Three checks before anything is queued, in order: the session exists,
/// the sending connection's TLS-proven key is one of its two, and the
/// direction still has volume budget. A datagram failing any of them is
/// dropped and counted, never answered, since an error frame would be an
/// oracle for live sessions.
fn forward_relay(state: &Arc<ServerState>, session: u32, sender_key: [u8; 32], payload: &[u8]) {
    #[allow(clippy::cast_precision_loss)]
    let payload_len = payload.len() as f64;
    enum Verdict {
        Queue(RelayShaper),
        OverVolume,
        NotOurs,
    }
    let verdict = {
        let sessions = state.sessions.lock_or_recover();
        let direction = sessions.get(&session).and_then(|session_state| {
            if session_state.key_a == sender_key {
                Some((&session_state.a_to_b, &session_state.a_to_b_shaper))
            } else if session_state.key_b == sender_key {
                Some((&session_state.b_to_a, &session_state.b_to_a_shaper))
            } else {
                None
            }
        });
        match direction {
            None => Verdict::NotOurs,
            Some((limiter, shaper)) => {
                if limiter.lock_or_recover().bytes.try_take_n(payload_len) {
                    Verdict::Queue(shaper.clone())
                } else {
                    Verdict::OverVolume
                }
            }
        }
    };
    let shaper = match verdict {
        Verdict::NotOurs => {
            state
                .counters
                .relay_sender_mismatch
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        Verdict::OverVolume => {
            state
                .counters
                .relay_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        Verdict::Queue(shaper) => shaper,
    };
    let Ok(encoded) = encode_relay(session, payload) else {
        state
            .counters
            .relay_oversized_dropped
            .fetch_add(1, Ordering::Relaxed);
        return;
    };
    // Section 1: unable to push back on unreliable datagrams, the gate
    // drops the newest and counts it, but only when full. 0 for a shaping
    // house; the abuse cap in the open otherwise.
    if !shaper.enqueue_or_drop(encoded) {
        state
            .counters
            .relay_dropped_at_full
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// Runs one direction of one session's shaper queue: waits for the rate to
/// release a batch, then writes it onto `destination_key`'s registration.
///
/// `send_datagram_wait` rather than `send_datagram`, because the latter
/// silently discards the *oldest* queued datagram when the destination
/// connection's own datagram buffer is full
/// (`quinn/src/connection.rs:436`), which is an invisible loss of exactly
/// the kind issue #19 is about. Waiting instead makes this queue and its
/// `relay_dropped_at_full` the one place a relayed datagram can be delayed
/// or dropped.
///
/// Exit paths, since no task may run without one: the session ending
/// (`close_shapers`, so `drain` returns `None`), the session no longer
/// being in the table, and the destination having no live registration
/// left.
fn spawn_relay_drain(
    state: &Arc<ServerState>,
    session: u32,
    destination_key: [u8; 32],
    shaper: RelayShaper,
) {
    let state = Arc::clone(state);
    tokio::spawn(async move {
        loop {
            let Some(payloads) = shaper.drain().await else {
                return;
            };
            if !state.sessions.lock_or_recover().contains_key(&session) {
                return;
            }
            let destination = {
                let registrations = state.registrations.lock_or_recover();
                registrations
                    .get(&destination_key)
                    .and_then(|list| list.last().cloned())
            };
            let Some(destination) = destination else {
                return;
            };
            for payload in payloads {
                if destination
                    .connection
                    .send_datagram_wait(payload.into())
                    .await
                    .is_err()
                {
                    return;
                }
            }
            tokio::task::yield_now().await;
        }
    });
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
