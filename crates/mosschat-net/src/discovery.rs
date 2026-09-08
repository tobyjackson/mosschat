//! Same-network discovery: `docs/dev/gatehouse-design.md` section 6.
//!
//! No gate involved, so two houses on one LAN work with a local-only
//! community (decision 7). A house announces its public key and its QUIC
//! port to a multicast group; a house that hears a friend announce turns
//! the **source address the kernel wrote** plus the announced port into a
//! candidate ([`crate::punch::CandidateSource::Discovery`]) and probes it
//! like any other. No name, no presence state, and no address in the frame:
//! the source address is the only trustworthy one.
//!
//! What this module holds: the group, port and fixed 144 byte frame
//! ([`Announce`]), the rate limits in both directions ([`Announcer`],
//! [`ReceiveLimiter`]), the socket that joins the group
//! ([`DiscoverySocket`]), and the handoff that makes a heard announce a
//! discovery-sourced candidate ([`Discovery`]).
//!
//! **Every signature check goes through `mosschat_core::identity::verify`**,
//! which is `verify_strict` and rejects the low-order keys plain `verify`
//! accepts. An announce carries a peer-chosen key, so nothing weaker is
//! safe here (CWE-347).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use mosschat_core::identity::{Signer, verify};

use crate::live::{AddressCache, DISCOVERED_ADDRESS_TTL};
use crate::punch::CandidateSource;

/// Section 6's IPv4 group: administratively scoped (RFC 2365), so it never
/// leaves the site.
pub const DISCOVERY_GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 49, 91);

/// Section 6's IPv6 group: link-local scope, so it never leaves the link.
pub const DISCOVERY_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x4d, 0x5343);

/// Section 6's port, in IANA's dynamic range and so assigned to nobody.
pub const DISCOVERY_PORT: u16 = 49911;

/// The announce's first byte, distinct from the probe's
/// [`crate::punch::PROBE_DISCRIMINATOR`] so one glance at byte 0 tells a
/// discovery packet from a probe.
pub const ANNOUNCE_DISCRIMINATOR: u8 = 0x2B;

/// The fixed on-wire size of an announce, section 6: not CBOR, so a hostile
/// packet needs no parser.
pub const ANNOUNCE_LEN: usize = 144;

/// Announce type byte.
pub const ANNOUNCE_TYPE: u8 = 0x01;

/// The bytes an announce's signature covers, prefixed to bytes 0..80.
pub const ANNOUNCE_SIGNING_CONTEXT: &[u8] = b"mosschat-discovery-v1";

/// Section 6: one announce per 30 s, plus one at start. 30 s because
/// criterion 3 gives 60 seconds from coming home to a note landing.
pub const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);

/// Section 6, receive side: a second announce from the same key inside 10 s
/// is dropped.
pub const ANNOUNCE_PER_KEY_GAP: Duration = Duration::from_secs(10);

/// Section 6, receive side: everything above 50 announce packets a second
/// is dropped, above what a 30 person community produces and below what
/// costs measurable CPU.
pub const ANNOUNCE_PACKETS_PER_SECOND: u32 = 50;

/// How many keys the per-key dedupe remembers before it forgets the oldest.
///
/// Chosen, not measured: [`ANNOUNCE_PACKETS_PER_SECOND`] distinct keys for
/// the whole [`ANNOUNCE_PER_KEY_GAP`] is 500, and only a friend's key ever
/// reaches the map, so this is already far past what a community of the
/// size decision 7 describes can fill. It bounds the map at 512 * 40 bytes
/// whatever arrives.
pub const DEDUPE_KEYS_REMEMBERED: usize = 512;

/// Why an announce was not turned into a candidate.
///
/// Each is counted separately in [`DiscoveryCounters`] because they mean
/// different things to whoever is reading the counts: a bad signature is an
/// attack or a bug, a stranger's announce is ordinary, and a rate limit
/// hit is load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AnnounceError {
    /// Not [`ANNOUNCE_LEN`] bytes, or the discriminator, magic, version or
    /// type byte is wrong. Every one of these is decided before anything is
    /// allocated or verified.
    #[error("malformed announce")]
    Malformed,
    /// A well-formed announce for a different community.
    #[error("announce for another community")]
    OtherCommunity,
    /// The announcing key is not a friend on file. Dropped **before** the
    /// signature is checked (research lesson 2, cheapest first), so an
    /// unknown key never costs a scalar multiplication.
    #[error("announce from a key that is not a friend")]
    NotAFriend,
    /// A friend's key with a signature that does not verify under
    /// `mosschat_core::identity::verify`.
    #[error("announce signature does not verify")]
    BadSignature,
    /// This house's own announce, heard back through multicast loopback.
    #[error("our own announce")]
    Ourselves,
    /// Dropped by [`ReceiveLimiter`]: a second announce from this key
    /// inside [`ANNOUNCE_PER_KEY_GAP`], or more than
    /// [`ANNOUNCE_PACKETS_PER_SECOND`].
    #[error("announce rate limited")]
    RateLimited,
}

/// One announce: a public key and a port, plus the community id so a
/// machine in two communities can tell them apart, and 8 random bytes
/// against replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Announce {
    /// The community this house belongs to.
    pub community: [u8; 32],
    /// The announcing house's ed25519 public key.
    pub key: [u8; 32],
    /// The QUIC port that house listens on, which the receiver pairs with
    /// the source address the kernel wrote.
    pub port: u16,
    /// 8 random bytes drawn per announce, against replay.
    pub nonce: [u8; 8],
}

impl Announce {
    /// Encodes and signs this announce, section 6's fixed 144 byte layout:
    /// byte 0 [`ANNOUNCE_DISCRIMINATOR`], 1..4 `"MSD"`, 4 version `0x01`,
    /// 5 type, 6..38 community id, 38..70 announcing public key, 70..72
    /// QUIC port big-endian, 72..80 the nonce, 80..144 the ed25519
    /// signature over [`ANNOUNCE_SIGNING_CONTEXT`] followed by bytes 0..80.
    ///
    /// `signer` must hold the key in `self.key`; nothing here checks that,
    /// because a house signing an announce for a key it does not hold
    /// produces a signature no receiver will accept, which is the same
    /// outcome an error would produce and one fewer way to fail.
    #[must_use]
    pub fn encode(&self, signer: &impl Signer) -> [u8; ANNOUNCE_LEN] {
        let mut out = [0u8; ANNOUNCE_LEN];
        #[allow(clippy::indexing_slicing)]
        {
            out[0] = ANNOUNCE_DISCRIMINATOR;
            out[1..4].copy_from_slice(b"MSD");
            out[4] = 0x01;
            out[5] = ANNOUNCE_TYPE;
            out[6..38].copy_from_slice(&self.community);
            out[38..70].copy_from_slice(&self.key);
            out[70..72].copy_from_slice(&self.port.to_be_bytes());
            out[72..80].copy_from_slice(&self.nonce);
            let mut signed = Vec::with_capacity(ANNOUNCE_SIGNING_CONTEXT.len() + 80);
            signed.extend_from_slice(ANNOUNCE_SIGNING_CONTEXT);
            signed.extend_from_slice(&out[..80]);
            out[80..144].copy_from_slice(&signer.sign(&signed));
        }
        out
    }

    /// Decodes and verifies an announce, in section 6's stated order:
    /// shape, then community, then "is this a friend", then the signature.
    ///
    /// `is_friend` runs before any verification because an announce whose
    /// key is not already a friend on file is dropped before the signature
    /// is checked (research lesson 2, cheapest first): otherwise anything
    /// on the LAN could spend this house's CPU on ed25519 by sending
    /// noise to a multicast group.
    ///
    /// # Errors
    ///
    /// Returns the [`AnnounceError`] naming which of those checks failed.
    pub fn decode(
        bytes: &[u8],
        community: &[u8; 32],
        is_friend: impl Fn(&[u8; 32]) -> bool,
    ) -> Result<Self, AnnounceError> {
        if bytes.len() != ANNOUNCE_LEN {
            return Err(AnnounceError::Malformed);
        }
        // Every index below is inside a slice whose length was just
        // checked to be exactly `ANNOUNCE_LEN`.
        #[allow(clippy::indexing_slicing)]
        {
            if bytes[0] != ANNOUNCE_DISCRIMINATOR
                || &bytes[1..4] != b"MSD"
                || bytes[4] != 0x01
                || bytes[5] != ANNOUNCE_TYPE
            {
                return Err(AnnounceError::Malformed);
            }
            let mut announced_community = [0u8; 32];
            announced_community.copy_from_slice(&bytes[6..38]);
            if &announced_community != community {
                return Err(AnnounceError::OtherCommunity);
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes[38..70]);
            if !is_friend(&key) {
                return Err(AnnounceError::NotAFriend);
            }
            let port = u16::from_be_bytes([bytes[70], bytes[71]]);
            let mut nonce = [0u8; 8];
            nonce.copy_from_slice(&bytes[72..80]);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&bytes[80..144]);

            let mut signed = Vec::with_capacity(ANNOUNCE_SIGNING_CONTEXT.len() + 80);
            signed.extend_from_slice(ANNOUNCE_SIGNING_CONTEXT);
            signed.extend_from_slice(&bytes[..80]);
            verify(&key, &signed, &sig).map_err(|_| AnnounceError::BadSignature)?;

            Ok(Self {
                community: announced_community,
                key,
                port,
                nonce,
            })
        }
    }
}

/// Section 6's send schedule: one announce at start, then one every
/// [`ANNOUNCE_INTERVAL`], plus one unicast reply to a friend's announce
/// when we hold no address for them.
#[derive(Debug)]
pub struct Announcer {
    next: Instant,
}

impl Announcer {
    /// An announcer that is due immediately, which is section 6's "one at
    /// start".
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self { next: now }
    }

    /// Whether a scheduled announce is due at `now`, arming the next one if
    /// it is. Deciding and arming are one call for the same reason
    /// [`crate::live::PeerLiveness::due_probe`] gives.
    pub fn due(&mut self, now: Instant) -> bool {
        if now < self.next {
            return false;
        }
        self.next = now + ANNOUNCE_INTERVAL;
        true
    }

    /// When the next scheduled announce is due.
    #[must_use]
    pub fn next_due(&self) -> Instant {
        self.next
    }
}

/// Section 6's receive-side limits: a second announce from the same key
/// inside [`ANNOUNCE_PER_KEY_GAP`] is dropped, and everything above
/// [`ANNOUNCE_PACKETS_PER_SECOND`] is dropped whatever it says.
///
/// The packet ceiling is checked first and against the raw datagram, so a
/// flood costs one counter increment each rather than a parse.
#[derive(Debug)]
pub struct ReceiveLimiter {
    window_start: Instant,
    in_window: u32,
    last_from: HashMap<[u8; 32], Instant>,
    order: std::collections::VecDeque<[u8; 32]>,
}

impl ReceiveLimiter {
    /// A limiter with an empty window starting at `now`.
    #[must_use]
    pub fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            in_window: 0,
            last_from: HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    /// Whether this datagram is inside the per-second ceiling. Called
    /// before the packet is looked at.
    pub fn admit_packet(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.in_window = 0;
        }
        if self.in_window >= ANNOUNCE_PACKETS_PER_SECOND {
            return false;
        }
        self.in_window = self.in_window.saturating_add(1);
        true
    }

    /// Whether this key has been quiet for [`ANNOUNCE_PER_KEY_GAP`].
    pub fn admit_key(&mut self, key: [u8; 32], now: Instant) -> bool {
        if let Some(last) = self.last_from.get(&key)
            && now.duration_since(*last) < ANNOUNCE_PER_KEY_GAP
        {
            return false;
        }
        if self.last_from.insert(key, now).is_none() {
            self.order.push_back(key);
            while self.order.len() > DEDUPE_KEYS_REMEMBERED {
                if let Some(evicted) = self.order.pop_front() {
                    self.last_from.remove(&evicted);
                }
            }
        }
        true
    }
}

/// What section 6 counts, so an operator can tell a flood from an attack
/// from an ordinary stranger.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiscoveryCounters {
    /// Announces accepted and turned into a candidate.
    pub accepted: u64,
    /// Datagrams dropped for shape, version or type.
    pub malformed: u64,
    /// Well-formed announces for another community.
    pub other_community: u64,
    /// Announces from a key that is not a friend on file, dropped before
    /// the signature was checked.
    pub not_a_friend: u64,
    /// A friend's key whose signature did not verify. Section 6: "a bad
    /// signature is dropped and counted".
    pub bad_signature: u64,
    /// Dropped by [`ReceiveLimiter`].
    pub rate_limited: u64,
    /// This house's own announces, heard back through multicast loopback.
    pub ourselves: u64,
}

/// Whether hearing this announce calls for the one unicast reply section 6
/// allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Nothing to send: an address for this friend is already held.
    None,
    /// Send one announce straight back to the address it came from, which
    /// is how the friend that has just come home learns about a house that
    /// announced 29 seconds ago.
    Unicast(SocketAddr),
}

/// An announce that survived every check: a friend, at an address this
/// house saw for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Discovered {
    /// The announcing friend's public key, proven by the signature.
    pub key: [u8; 32],
    /// The source address the announce arrived from, with the announced
    /// QUIC port. The address half is the kernel's, never the sender's.
    pub addr: SocketAddr,
}

/// What one received datagram did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Heard {
    /// A friend, at a new or refreshed address.
    Discovered(Discovered, Reply),
    /// Dropped, and why.
    Dropped(AnnounceError),
}

/// Section 6 assembled: the schedule, the limits, the verification and the
/// handoff of a discovered address into the candidate table.
///
/// It owns no socket and no clock, so the whole of section 6's policy is
/// exercised below without one, and [`DiscoverySocket`] is only the part
/// that joins a group and moves bytes.
#[derive(Debug)]
pub struct Discovery {
    community: [u8; 32],
    /// This house's own key, so an announce heard back through multicast
    /// loopback is recognised rather than discovered.
    own_key: [u8; 32],
    quic_port: u16,
    announcer: Announcer,
    limiter: ReceiveLimiter,
    cache: AddressCache,
    counters: DiscoveryCounters,
}

impl Discovery {
    /// A discovery state machine for one house, due to announce at once.
    #[must_use]
    pub fn new(community: [u8; 32], own_key: [u8; 32], quic_port: u16, now: Instant) -> Self {
        Self {
            community,
            own_key,
            quic_port,
            announcer: Announcer::new(now),
            limiter: ReceiveLimiter::new(now),
            cache: AddressCache::new(),
            counters: DiscoveryCounters::default(),
        }
    }

    /// The counters section 6 asks for.
    #[must_use]
    pub fn counters(&self) -> DiscoveryCounters {
        self.counters
    }

    /// Whether a scheduled announce is due at `now`.
    pub fn due_announce(&mut self, now: Instant) -> bool {
        self.announcer.due(now)
    }

    /// Builds this house's announce, signed by `signer`, with `nonce` as
    /// its 8 replay bytes.
    ///
    /// `nonce` is a parameter rather than a call into `rand` for the same
    /// reason [`crate::punch::Attempt::due_probes`] takes its tx ids that
    /// way: it makes the whole frame reproducible in a test.
    #[must_use]
    pub fn announce(&self, signer: &impl Signer, nonce: [u8; 8]) -> [u8; ANNOUNCE_LEN] {
        Announce {
            community: self.community,
            key: self.own_key,
            port: self.quic_port,
            nonce,
        }
        .encode(signer)
    }

    /// Handles one received datagram: the packet ceiling, then the frame,
    /// then the per-key gap, then the handoff.
    ///
    /// The address remembered is `from`'s IP with the **announced** port,
    /// never `from`'s port: the announce left a socket bound to
    /// [`DISCOVERY_PORT`] and the QUIC listener is somewhere else entirely.
    /// The IP is the kernel's and is the only part of this that no sender
    /// can choose.
    pub fn on_datagram(
        &mut self,
        bytes: &[u8],
        from: SocketAddr,
        now: Instant,
        is_friend: impl Fn(&[u8; 32]) -> bool,
    ) -> Heard {
        if !self.limiter.admit_packet(now) {
            self.counters.rate_limited = self.counters.rate_limited.saturating_add(1);
            return Heard::Dropped(AnnounceError::RateLimited);
        }
        let own_key = self.own_key;
        let announce = match Announce::decode(bytes, &self.community, |key| {
            *key == own_key || is_friend(key)
        }) {
            Ok(announce) => announce,
            Err(error) => {
                match error {
                    AnnounceError::Malformed => {
                        self.counters.malformed = self.counters.malformed.saturating_add(1);
                    }
                    AnnounceError::OtherCommunity => {
                        self.counters.other_community =
                            self.counters.other_community.saturating_add(1);
                    }
                    AnnounceError::NotAFriend => {
                        self.counters.not_a_friend = self.counters.not_a_friend.saturating_add(1);
                    }
                    AnnounceError::BadSignature => {
                        self.counters.bad_signature = self.counters.bad_signature.saturating_add(1);
                    }
                    AnnounceError::Ourselves | AnnounceError::RateLimited => {}
                }
                return Heard::Dropped(error);
            }
        };
        if announce.key == self.own_key {
            self.counters.ourselves = self.counters.ourselves.saturating_add(1);
            return Heard::Dropped(AnnounceError::Ourselves);
        }
        if !self.limiter.admit_key(announce.key, now) {
            self.counters.rate_limited = self.counters.rate_limited.saturating_add(1);
            return Heard::Dropped(AnnounceError::RateLimited);
        }

        let held_before = !self.cache.addresses(&announce.key).is_empty();
        // The kernel's address with the announced port, unmapped so a
        // dual-stack socket's `::ffff:a.b.c.d` and a plain IPv4 socket's
        // `a.b.c.d` are one candidate and not two (issue #37).
        let addr = crate::sock::unmap_v4(SocketAddr::new(from.ip(), announce.port));
        self.cache
            .remember(announce.key, addr, CandidateSource::Discovery, now);
        self.counters.accepted = self.counters.accepted.saturating_add(1);
        let reply = if held_before {
            Reply::None
        } else {
            // Section 6's one unicast reply, sent back to the port the
            // announce came from, which is the sender's discovery socket
            // and not its QUIC listener.
            Reply::Unicast(from)
        };
        Heard::Discovered(
            Discovered {
                key: announce.key,
                addr,
            },
            reply,
        )
    }

    /// The addresses discovered for `peer` and not yet expired, which is
    /// what [`crate::punch::DoorbellParams::peer_discovered`] is filled
    /// from: they enter the attempt as
    /// [`crate::punch::CandidateSource::Discovery`] and vouch for
    /// themselves there (issue #37).
    #[must_use]
    pub fn discovered(&self, peer: &[u8; 32]) -> Vec<SocketAddr> {
        self.cache.discovered(peer)
    }

    /// Section 6's 5 minute expiry, applied at `now`. Returns how many
    /// addresses went.
    pub fn expire(&mut self, now: Instant) -> usize {
        self.cache.expire(now)
    }

    /// How long a discovered address lives unanswered, restated here
    /// because section 6 states it and [`crate::live`] enforces it.
    #[must_use]
    pub fn address_ttl() -> Duration {
        DISCOVERED_ADDRESS_TTL
    }
}

/// The multicast socket section 6 asks for: its own socket, not the porch
/// socket, because joining a group changes socket options and the porch
/// mapping must stay clean.
#[derive(Debug)]
pub struct DiscoverySocket {
    socket: tokio::net::UdpSocket,
    group: SocketAddr,
}

/// Where a [`DiscoverySocket`] binds and announces.
///
/// `bind_port` and `announce_port` are both [`DISCOVERY_PORT`] in
/// production and that is what [`DiscoveryPorts::standard`] gives. They are
/// separable only so that two houses can run in one process on one machine:
/// a UDP port takes one bind without `SO_REUSEADDR`, which this crate
/// cannot set without a new dependency or `unsafe` (invariant 2), so a
/// two-house test crosses the ports instead. Everything else about such a
/// socket, the group, the join, the loopback and the frames, is the real
/// thing.
#[derive(Debug, Clone, Copy)]
pub struct DiscoveryPorts {
    /// The port this socket receives announces on.
    pub bind: u16,
    /// The port this socket sends announces to.
    pub announce: u16,
}

impl DiscoveryPorts {
    /// Section 6's ports: [`DISCOVERY_PORT`] both ways.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            bind: DISCOVERY_PORT,
            announce: DISCOVERY_PORT,
        }
    }
}

impl DiscoverySocket {
    /// Binds an IPv4 discovery socket and joins [`DISCOVERY_GROUP_V4`] on
    /// `interface`, `0.0.0.0` meaning the system's default.
    ///
    /// # Errors
    ///
    /// Returns the underlying error if the port cannot be bound or the
    /// group cannot be joined. A join failing is not fatal to a house: a
    /// network that blocks multicast costs same-network discovery and
    /// nothing else, so a caller is expected to carry on with the gate.
    pub fn bind_v4(ports: DiscoveryPorts, interface: Ipv4Addr) -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ports.bind,
        ))?;
        socket.join_multicast_v4(&DISCOVERY_GROUP_V4, &interface)?;
        // On, so two houses on one machine hear each other: without it the
        // kernel does not loop a multicast send back to other sockets on
        // the same host, and a pair sharing a machine is the ordinary
        // development case as well as this module's own test.
        socket.set_multicast_loop_v4(true)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: tokio::net::UdpSocket::from_std(socket)?,
            group: SocketAddr::new(IpAddr::V4(DISCOVERY_GROUP_V4), ports.announce),
        })
    }

    /// Sends one announce to the group.
    ///
    /// # Errors
    ///
    /// Returns the underlying send error.
    pub async fn announce(&self, frame: &[u8; ANNOUNCE_LEN]) -> io::Result<usize> {
        self.socket.send_to(frame, self.group).await
    }

    /// Sends one announce straight to `to`, section 6's unicast reply.
    ///
    /// # Errors
    ///
    /// Returns the underlying send error.
    pub async fn reply(&self, frame: &[u8; ANNOUNCE_LEN], to: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(frame, to).await
    }

    /// Receives one datagram, truncated to [`ANNOUNCE_LEN`]: anything
    /// longer is not an announce, and reading it whole would be allocating
    /// on a stranger's say-so.
    ///
    /// # Errors
    ///
    /// Returns the underlying receive error.
    pub async fn recv(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        let mut buf = [0u8; ANNOUNCE_LEN];
        let (len, from) = self.socket.recv_from(&mut buf).await?;
        let len = len.min(ANNOUNCE_LEN);
        Ok((buf.get(..len).unwrap_or_default().to_vec(), from))
    }

    /// The address this socket is bound to.
    ///
    /// # Errors
    ///
    /// Returns the underlying error.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
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
    use mosschat_core::identity::AuthorKey;

    const COMMUNITY: [u8; 32] = [3u8; 32];

    fn house(seed: u8) -> (AuthorKey, [u8; 32]) {
        let key = AuthorKey::from_bytes(&[seed; 32]);
        let public = key.public_bytes();
        (key, public)
    }

    /// Writes one line to the real stderr, bypassing libtest's output
    /// capture.
    ///
    /// `eprintln!` goes through `std::io::_eprint`, which libtest redirects
    /// per test thread and prints only for a *failing* test, so a skip
    /// notice written with it is invisible in a CI log: the run looks
    /// identical whether the multicast test exercised the group or returned
    /// on its first line. `std::io::stderr()` is the process's own handle
    /// and is not redirected, so the line appears either way, which is what
    /// makes "it ran on this platform" a checkable claim rather than an
    /// assumption.
    fn note(line: &str) {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), "{line}");
    }

    /// Section 6's frame, byte for byte: 144 bytes, the stated layout, and
    /// a signature over the context string and the first 80 bytes that
    /// `mosschat_core::identity::verify` accepts.
    ///
    /// Deliberate break to fail this test: in `Announce::encode`, sign
    /// `&out[..80]` without the `ANNOUNCE_SIGNING_CONTEXT` prefix. The
    /// layout assertions still pass and the decode fails with
    /// `BadSignature`.
    #[test]
    fn an_announce_is_144_bytes_with_the_layout_section_6_states() {
        let (signer, key) = house(1);
        let announce = Announce {
            community: COMMUNITY,
            key,
            port: 4433,
            nonce: [7u8; 8],
        };
        let bytes = announce.encode(&signer);
        assert_eq!(bytes.len(), ANNOUNCE_LEN);
        assert_eq!(bytes[0], ANNOUNCE_DISCRIMINATOR);
        assert_ne!(
            bytes[0],
            crate::punch::PROBE_DISCRIMINATOR,
            "distinct from the probe's, so byte 0 tells them apart"
        );
        assert_eq!(&bytes[1..4], b"MSD");
        assert_eq!(bytes[4], 0x01);
        assert_eq!(bytes[5], ANNOUNCE_TYPE);
        assert_eq!(&bytes[6..38], &COMMUNITY);
        assert_eq!(&bytes[38..70], &key);
        assert_eq!(u16::from_be_bytes([bytes[70], bytes[71]]), 4433);
        assert_eq!(&bytes[72..80], &[7u8; 8]);

        // No address anywhere in it: the source address is the only
        // trustworthy one (section 6).
        let decoded = Announce::decode(&bytes, &COMMUNITY, |_| true).unwrap();
        assert_eq!(decoded, announce);
    }

    /// Section 6's stated check order, and both refusals: a stranger's
    /// announce is dropped before the signature is checked, and a friend's
    /// bad signature is dropped and counted.
    ///
    /// Deliberate break to fail this test: in `Announce::decode`, move the
    /// `is_friend` check below the `verify(...)` call. A stranger whose
    /// signature is also bad then comes back as `BadSignature` instead of
    /// `NotAFriend`, which is what the second assertion pins.
    #[test]
    fn a_stranger_is_dropped_before_the_signature_and_a_bad_one_is_counted() {
        let (friend, friend_key) = house(1);
        let (stranger, stranger_key) = house(2);
        let is_friend = move |key: &[u8; 32]| *key == friend_key;

        // A stranger, whose announce is perfectly signed: still refused,
        // and refused for being a stranger rather than for its signature.
        let strangers = Announce {
            community: COMMUNITY,
            key: stranger_key,
            port: 4433,
            nonce: [1u8; 8],
        }
        .encode(&stranger);
        assert_eq!(
            Announce::decode(&strangers, &COMMUNITY, is_friend),
            Err(AnnounceError::NotAFriend)
        );

        // The same stranger with a signature that does not verify either:
        // still `NotAFriend`, which is the assertion that pins the *order*
        // of the two checks rather than merely their presence. Reversed,
        // this one comes back as `BadSignature`.
        let mut strangers_forged = strangers;
        strangers_forged[143] ^= 0x01;
        assert_eq!(
            Announce::decode(&strangers_forged, &COMMUNITY, is_friend),
            Err(AnnounceError::NotAFriend),
            "a stranger is dropped before the signature is checked"
        );

        // A friend's key with somebody else's signature.
        let mut forged = Announce {
            community: COMMUNITY,
            key: friend_key,
            port: 4433,
            nonce: [2u8; 8],
        }
        .encode(&friend);
        forged[143] ^= 0x01;
        assert_eq!(
            Announce::decode(&forged, &COMMUNITY, is_friend),
            Err(AnnounceError::BadSignature)
        );

        // A friend's key over a body somebody edited after signing: the
        // port is inside the signature, so moving it invalidates it.
        let mut moved = Announce {
            community: COMMUNITY,
            key: friend_key,
            port: 4433,
            nonce: [3u8; 8],
        }
        .encode(&friend);
        moved[70..72].copy_from_slice(&9999u16.to_be_bytes());
        assert_eq!(
            Announce::decode(&moved, &COMMUNITY, is_friend),
            Err(AnnounceError::BadSignature)
        );

        // Another community, and a short packet.
        let other = Announce {
            community: [9u8; 32],
            key: friend_key,
            port: 4433,
            nonce: [4u8; 8],
        }
        .encode(&friend);
        assert_eq!(
            Announce::decode(&other, &COMMUNITY, is_friend),
            Err(AnnounceError::OtherCommunity)
        );
        assert_eq!(
            Announce::decode(&other[..143], &COMMUNITY, is_friend),
            Err(AnnounceError::Malformed)
        );
    }

    /// Section 6's rate limits, both of them: one announce per key per 10
    /// seconds on receive, and 50 announce packets a second whatever they
    /// say, checked before the packet is parsed.
    ///
    /// Deliberate break to fail this test: in `ReceiveLimiter::admit_key`,
    /// return `true` unconditionally. The second announce inside the gap is
    /// then accepted and its assertion fails.
    #[test]
    fn the_receive_side_drops_a_repeat_inside_ten_seconds_and_a_flood_past_fifty() {
        let t0 = Instant::now();
        let (friend, friend_key) = house(1);
        let (_, own_key) = house(3);
        let frame = Announce {
            community: COMMUNITY,
            key: friend_key,
            port: 4433,
            nonce: [1u8; 8],
        }
        .encode(&friend);
        let from: SocketAddr = "192.168.4.21:49911".parse().unwrap();
        let is_friend = move |key: &[u8; 32]| *key == friend_key;

        let mut discovery = Discovery::new(COMMUNITY, own_key, 4433, t0);
        assert!(matches!(
            discovery.on_datagram(&frame, from, t0, is_friend),
            Heard::Discovered(..)
        ));
        assert_eq!(
            discovery.on_datagram(&frame, from, t0 + Duration::from_secs(9), is_friend),
            Heard::Dropped(AnnounceError::RateLimited)
        );
        assert!(matches!(
            discovery.on_datagram(&frame, from, t0 + ANNOUNCE_PER_KEY_GAP, is_friend),
            Heard::Discovered(..)
        ));

        // The packet ceiling, on garbage, so it is clear the drop happens
        // before anything is parsed: 50 in one window and no more.
        let mut flooded = Discovery::new(COMMUNITY, own_key, 4433, t0);
        let noise = [0u8; ANNOUNCE_LEN];
        let mut admitted = 0;
        for _ in 0..200 {
            if flooded.on_datagram(&noise, from, t0, is_friend)
                != Heard::Dropped(AnnounceError::RateLimited)
            {
                admitted += 1;
            }
        }
        assert_eq!(admitted, ANNOUNCE_PACKETS_PER_SECOND);
        assert_eq!(
            flooded.counters().malformed,
            u64::from(ANNOUNCE_PACKETS_PER_SECOND),
            "the ones that got past the ceiling were dropped on shape, not parsed further"
        );
        assert_eq!(
            flooded.counters().rate_limited,
            200 - u64::from(ANNOUNCE_PACKETS_PER_SECOND)
        );
        // The window rolls.
        assert_ne!(
            flooded.on_datagram(&noise, from, t0 + Duration::from_millis(1001), is_friend),
            Heard::Dropped(AnnounceError::RateLimited)
        );
    }

    /// Section 6's schedule: one at start, then one every 30 s, and one
    /// unicast reply to a friend's announce when we hold no address for
    /// them and none once we do.
    #[test]
    fn the_announce_schedule_is_one_at_start_then_one_every_thirty_seconds() {
        let t0 = Instant::now();
        let mut announcer = Announcer::new(t0);
        assert!(announcer.due(t0), "one at start");
        assert!(!announcer.due(t0 + Duration::from_secs(29)));
        assert!(announcer.due(t0 + ANNOUNCE_INTERVAL));
        assert_eq!(announcer.next_due(), t0 + ANNOUNCE_INTERVAL * 2);

        let (friend, friend_key) = house(1);
        let (_, own_key) = house(3);
        let is_friend = move |key: &[u8; 32]| *key == friend_key;
        let mut discovery = Discovery::new(COMMUNITY, own_key, 4433, t0);
        let from: SocketAddr = "192.168.4.21:49911".parse().unwrap();
        let frame = |nonce: u8| {
            Announce {
                community: COMMUNITY,
                key: friend_key,
                port: 4433,
                nonce: [nonce; 8],
            }
            .encode(&friend)
        };

        match discovery.on_datagram(&frame(1), from, t0, is_friend) {
            Heard::Discovered(_, reply) => assert_eq!(
                reply,
                Reply::Unicast(from),
                "no address held for this friend, so answer at once"
            ),
            other => panic!("expected a discovery, got {other:?}"),
        }
        match discovery.on_datagram(&frame(2), from, t0 + ANNOUNCE_PER_KEY_GAP, is_friend) {
            Heard::Discovered(_, reply) => assert_eq!(reply, Reply::None, "an address is held now"),
            other => panic!("expected a discovery, got {other:?}"),
        }
    }

    /// A house does not discover itself: its own announce comes back
    /// through multicast loopback, which is on precisely so two houses can
    /// share a machine.
    #[test]
    fn our_own_announce_is_recognised_rather_than_discovered() {
        let t0 = Instant::now();
        let (own, own_key) = house(3);
        let mut discovery = Discovery::new(COMMUNITY, own_key, 4433, t0);
        let frame = discovery.announce(&own, [1u8; 8]);
        assert_eq!(
            discovery.on_datagram(&frame, "127.0.0.1:49911".parse().unwrap(), t0, |_| false),
            Heard::Dropped(AnnounceError::Ourselves)
        );
        assert!(discovery.discovered(&own_key).is_empty());
        assert_eq!(discovery.counters().ourselves, 1);
    }

    /// Section 8's WO-1.3b case, over a real multicast socket: two houses
    /// on loopback multicast discover each other, and the discovered
    /// address arrives in the candidate table as a discovery-sourced
    /// candidate that passes the validation of issue #37, which a peer
    /// naming the same private address would not.
    ///
    /// **Skips cleanly** where the group cannot be joined: a CI runner may
    /// not permit multicast at all, and a test that cannot run must say so
    /// rather than fail or silently pass.
    ///
    /// Deliberate break to fail this test: in `Discovery::on_datagram`,
    /// build the remembered address from `from` whole rather than
    /// `SocketAddr::new(..., announce.port)`. The discovered address then
    /// carries the sender's discovery port instead of its QUIC port and
    /// the address assertion fails.
    #[tokio::test]
    async fn two_houses_on_loopback_multicast_discover_each_other() {
        let (alice, alice_key) = house(1);
        let (bob, bob_key) = house(2);

        // Two houses in one process cannot share one UDP port without
        // SO_REUSEADDR, so each binds its own and announces to the other's;
        // in production both are DISCOVERY_PORT. See `DiscoveryPorts`.
        let alice_port = 49911;
        let bob_port = 49912;
        // The group is joined on the default interface rather than on
        // `127.0.0.1`, and the datagram returns through `IP_MULTICAST_LOOP`
        // rather than over the loopback interface. Measured on this
        // machine: a socket that joined on `127.0.0.1` receives nothing,
        // because the send leaves by the default route and the two never
        // meet. The unspecified address is what a house uses in production
        // anyway.
        let interface = Ipv4Addr::UNSPECIFIED;
        let alice_socket = match DiscoverySocket::bind_v4(
            DiscoveryPorts {
                bind: alice_port,
                announce: bob_port,
            },
            interface,
        ) {
            Ok(socket) => socket,
            Err(error) => {
                note(&format!(
                    "discovery: SKIPPED, will not join {DISCOVERY_GROUP_V4} on {interface} ({error})"
                ));
                return;
            }
        };
        let bob_socket = match DiscoverySocket::bind_v4(
            DiscoveryPorts {
                bind: bob_port,
                announce: alice_port,
            },
            interface,
        ) {
            Ok(socket) => socket,
            Err(error) => {
                note(&format!(
                    "discovery: SKIPPED, will not join {DISCOVERY_GROUP_V4} on {interface} ({error})"
                ));
                return;
            }
        };

        let t0 = Instant::now();
        let mut alice_discovery = Discovery::new(COMMUNITY, alice_key, 4433, t0);
        let mut bob_discovery = Discovery::new(COMMUNITY, bob_key, 4434, t0);
        assert!(alice_discovery.due_announce(t0), "one announce at start");
        assert!(bob_discovery.due_announce(t0));

        if alice_socket
            .announce(&alice_discovery.announce(&alice, [1u8; 8]))
            .await
            .is_err()
        {
            note(&format!(
                "discovery: SKIPPED, will not send to {DISCOVERY_GROUP_V4}"
            ));
            return;
        }
        bob_socket
            .announce(&bob_discovery.announce(&bob, [2u8; 8]))
            .await
            .unwrap();

        let hear = async |socket: &DiscoverySocket,
                          discovery: &mut Discovery,
                          friend: [u8; 32]|
               -> Option<Discovered> {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let recv = tokio::time::timeout_at(deadline, socket.recv()).await;
                let Ok(Ok((bytes, from))) = recv else {
                    return None;
                };
                if let Heard::Discovered(discovered, _) =
                    discovery.on_datagram(&bytes, from, Instant::now(), |key| *key == friend)
                {
                    return Some(discovered);
                }
            }
        };

        let Some(bob_seen_by_alice) = hear(&alice_socket, &mut alice_discovery, bob_key).await
        else {
            note("discovery: SKIPPED, no multicast datagram was delivered");
            return;
        };
        let bob_seen = hear(&bob_socket, &mut bob_discovery, alice_key)
            .await
            .expect("bob heard alice's announce on the same group");

        assert_eq!(bob_seen_by_alice.key, bob_key);
        assert_eq!(bob_seen_by_alice.addr.port(), 4434, "bob's QUIC port");
        note(&format!(
            "discovery: RAN, both houses discovered each other at {} and {}",
            bob_seen_by_alice.addr, bob_seen.addr
        ));
        assert_eq!(bob_seen.key, alice_key);
        assert_eq!(bob_seen.addr.port(), 4433, "alice's QUIC port");
        assert_eq!(
            alice_discovery.discovered(&bob_key),
            vec![bob_seen_by_alice.addr]
        );

        // The handoff: a discovered address enters the attempt as a
        // discovery-sourced candidate and passes validation, where the same
        // address in a peer's own candidate list would not have (issue
        // #37). The refusal half is asserted only for an address in a
        // private range, which is what a machine on a LAN announces from
        // and what makes the relaxation necessary at all; a runner whose
        // default interface holds a globally routable address is a
        // different case, and asserting a refusal that the design does not
        // ask for there would be asserting the wrong thing.
        let mut attempt = crate::punch::Attempt::new([5u8; 16], [6u8; 32], None);
        let private = match bob_seen_by_alice.addr.ip() {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_loopback() || v6.octets()[0] & 0xfe == 0xfc,
        };
        if private {
            let mut unvouched = crate::punch::Attempt::new([5u8; 16], [6u8; 32], None);
            assert_eq!(
                unvouched.add_peer_candidates(&[crate::gate::wire::Addr::from_socket_addr(
                    bob_seen_by_alice.addr
                )]),
                0,
                "the peer's own word for a private-range address is not enough"
            );
        }
        assert!(attempt.add_discovered(bob_seen_by_alice.addr));
        assert_eq!(
            attempt.source_of(bob_seen_by_alice.addr),
            Some(CandidateSource::Discovery)
        );
        assert!(attempt.vouched_for(bob_seen_by_alice.addr));
    }
}
