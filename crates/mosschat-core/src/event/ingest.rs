//! [`Recording`], an in-memory ingest state machine for one visit
//! (`docs/spec/recording.md`).
//!
//! This is the stateful half of the format: the host's sequence, the
//! participant set derived from `join`/`leave`, revoked device keys, and
//! tombstones left by an honoured `drop-request`. `mosschat-core` has no
//! store dependency (invariant 11) and does not read the system clock
//! (section 4, R-32): every ingest call takes `now_ms` from its caller.

use std::collections::{HashMap, HashSet};

use thiserror::Error;

use super::body::Body;
use super::id::EventId;
use super::signed::{SignedEvent, SignedEventError};

/// `body_len`'s cap in bytes (R-5, section 6).
pub const BODY_LEN_MAX: usize = 130_847;
/// One whole event's cap in bytes: `envelope_bytes` + 64 byte signature +
/// `body_len` (R-43, section 6).
pub const EVENT_TOTAL_MAX: usize = 131_072;

/// One event stored in a [`Recording`], keyed by its host-assigned `seq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    /// The fully parsed and verified event.
    pub event: SignedEvent,
}

/// A tombstone left in place of an event whose author asked for it to be
/// dropped, and whose house honoured that request (R-41, R-50).
///
/// Holds **only** `seq` and `event_id`, structurally: no envelope, no
/// signature, no body, no author, no timestamp are recoverable from a
/// `Tombstone` value, because the fields do not exist on the type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tombstone {
    /// The dropped event's host-assigned sequence number.
    pub seq: u64,
    /// The dropped event's `event_id`, preserved so R-13's `prev` chain
    /// still matches across the drop.
    pub event_id: EventId,
}

/// One slot in the host's sequence: either a live event or a tombstone left
/// by an honoured drop-request.
///
/// `Event` is boxed: [`StoredEvent`] carries a whole [`SignedEvent`]
/// (envelope, signature, both raw and decoded body), which is far larger
/// than [`Tombstone`]'s two fields; boxing it keeps the enum itself small
/// rather than sizing every `Slot`, including every tombstone, to the
/// largest variant.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Slot {
    Event(Box<StoredEvent>),
    Tombstone(Tombstone),
}

impl Slot {
    fn event_id(&self) -> EventId {
        match self {
            Slot::Event(stored) => stored.event.event_id,
            Slot::Tombstone(tombstone) => tombstone.event_id,
        }
    }
}

/// The state of one person's admission to this visit, derived from `join`
/// and `leave` events (section 5.4, 5.5).
#[derive(Debug, Clone)]
struct Participant {
    /// Every device key this person has ever been admitted under, across
    /// every `join` naming them (a later `join` can list a different
    /// device set; R-27 checks membership in *any* un-`leave`d `join`).
    joins: Vec<JoinRecord>,
}

#[derive(Debug, Clone)]
struct JoinRecord {
    seq: u64,
    devices: HashSet<[u8; 32]>,
    /// `seq` of the `leave` that closed this join, if any.
    left_at: Option<u64>,
}

/// An event was rejected during ingest, one variant per rejection reason,
/// each naming the rule it enforces.
#[derive(Debug, Error)]
pub enum IngestError {
    /// The event's `visit` is the all-zero id (R-12).
    #[error("R-12: the all-zero visit id is never valid")]
    ZeroVisit,
    /// Parsing or stateless verification of the event failed (R-1 to R-6,
    /// R-9, R-10, R-15, R-16, R-43, R-44), reported with the underlying
    /// [`SignedEventError`].
    #[error("event failed to parse or verify: {0}")]
    Malformed(#[from] SignedEventError),
    /// R-11: the event's `visit` does not match this recording's visit.
    #[error("R-11: event visit does not match this recording's visit")]
    WrongVisit,
    /// R-7 / R-27: `author` is not named by any un-`leave`d `join` in this
    /// visit.
    #[error("R-7: author is not a named, unrevoked participant device")]
    UnknownAuthor,
    /// R-7 / R-37: `author` is a device key this recording has seen
    /// permanently revoked.
    #[error("R-7: author device key is revoked (R-37)")]
    RevokedAuthor,
    /// R-7 / R-32: `author`'s device key was granted through an
    /// in-recording `device-add` whose validity window does not cover the
    /// ingest clock.
    #[error("R-7: author's device-add grant is not in force at the ingest clock (R-32)")]
    DeviceAddGrantNotInForce,
    /// R-30: the author's person left at an earlier `seq` with no later
    /// `join` re-admitting them before this event.
    #[error("R-30: author's person left this visit and has not rejoined")]
    AuthorHasLeft,
    /// R-13: two events offered at the same `seq`, or a `prev` that does not
    /// match the stored predecessor (or its tombstone). The recording is
    /// marked broken; see [`Recording::is_broken`].
    #[error("R-13: seq collision or prev mismatch; the visit is now broken")]
    Broken,
    /// The event at `seq - 1` is not held yet, so R-13's `prev` check cannot
    /// be decided. The visit is NOT broken: a caller ingesting in the
    /// host's order (section 4) never sees this, and an out-of-order
    /// arrival is retryable once the predecessor lands.
    #[error("R-13: predecessor at seq {0} not held; cannot decide prev yet")]
    PredecessorMissing(u64),
    /// R-15: a known body type is missing a required key. Also used for the
    /// per-type validity rules folded into decode (R-17, R-20, R-22, R-26,
    /// R-31, R-39) since `Body::from_cbor` reports them the same way.
    #[error("R-15: known body type missing a required key or field out of range")]
    InvalidBody,
    /// R-18: `message.reply_to` names an event this recording does not
    /// hold, or holds at a `seq` not lower than the reply's own.
    #[error("R-18: reply_to does not name a stored event or tombstone at a lower seq")]
    ReplyTargetNotFound,
    /// R-19: `reaction.target` names an event this recording does not hold,
    /// or holds at a `seq` not lower than the reaction's own.
    #[error("R-19: reaction target does not name a stored event or tombstone at a lower seq")]
    ReactionTargetNotFound,
    /// R-25: a `join` authored by a non-host device.
    #[error("R-25: join must be authored by the host")]
    JoinNotByHost,
    /// R-28: a `leave` authored by a non-host device.
    #[error("R-28: leave must be authored by the host")]
    LeaveNotByHost,
    /// R-29: a `leave` names a person with no un-`leave`d `join` earlier in
    /// this visit.
    #[error("R-29: leave names a person with no active join")]
    LeaveWithoutActiveJoin,
    /// R-34: a `device-add` names a device key already in force for a
    /// different person.
    #[error("R-34: device already in force for a different person")]
    DeviceInForceForDifferentPerson,
    /// R-36: a `device-revoke` targets its own author, or targets a device
    /// of a different person.
    #[error("R-36: device-revoke cannot target its own author or another person's device")]
    InvalidRevokeTarget,
    /// R-37: a `device-add` for a device key this recording has already
    /// seen revoked.
    #[error("R-37: device-add names a permanently revoked device key")]
    DeviceAddOfRevokedKey,
    /// R-40: a `drop-request` target was not authored by the requester's
    /// own person.
    #[error("R-40: drop-request target not authored by the requester's own person")]
    DropRequestTargetNotOwnPerson,
    /// The recording has already been marked broken by an earlier R-13
    /// violation; no further event is accepted.
    #[error("the visit is already marked broken")]
    AlreadyBroken,
    /// [`Recording::honour_drop_request`] was asked to honour a
    /// `drop-request` `event_id` this recording does not hold, or which
    /// does not name a `drop-request` body.
    #[error("drop-request event not found, or not a drop-request body")]
    DropRequestNotFound,
}

/// An in-memory ingest state machine for one visit: the host's sequence,
/// the participant set, revoked keys and tombstones.
///
/// ## Interfaces for the store and the view module
///
/// - [`EventId`] is the 32 byte primary key for an event: `BLAKE3(envelope_bytes)`.
/// - A store must persist, per event, the received `envelope_bytes` and
///   `body_bytes` verbatim (R-8 forbids re-serialising them), the 64
///   signature bytes, and may additionally index the derived `seq`,
///   `visit` and `author` fields if it wants them queryable; those three
///   are recoverable from `envelope_bytes` and need not be stored
///   separately.
/// - [`Tombstone`] is `(seq, event_id)` and nothing else (R-50): a store row
///   for a tombstone must not have columns for body, author or timestamp,
///   because a tombstone never has anything to put in them.
/// - The ingest clock (`now_ms`, used by R-32) is passed in by the caller
///   on every call to [`Recording::ingest`]; `mosschat-core` never reads the
///   system clock itself, which keeps ingest deterministic and testable.
/// - This module enforces every rule that a single visit's own recording
///   can decide alone: R-1 to R-40, R-43, R-44 and R-50. R-41's local
///   delete-for-real and R-45 to R-49 (views, private visits, the store's
///   own delete) are the store's and the view module's job (WO-2.4b,
///   WO-2.5); [`Recording::honour_drop_request`] only replaces the target
///   slots with tombstones in this in-memory model; deleting the
///   corresponding bytes from a real store file is that layer's
///   responsibility.
#[derive(Debug, Clone)]
pub struct Recording {
    visit: [u8; 32],
    host: [u8; 32],
    /// The host's sequence, dense from `seq = 0`. `None` marks a `seq` that
    /// this recording has not (yet, or ever) received; a genuinely dense
    /// recording never has an internal `None`, but ingest does not require
    /// events to arrive in order, so the map form is used rather than a
    /// `Vec`.
    slots: HashMap<u64, Slot>,
    /// Every person seen in a `join`, keyed by their identity key
    /// (`join.person`).
    participants: HashMap<[u8; 32], Participant>,
    /// Device keys this recording has seen permanently revoked (R-37),
    /// mapped to the person that revoked them.
    revoked: HashMap<[u8; 32], [u8; 32]>,
    /// Device keys currently in force, mapped to the person they belong to
    /// (R-34, R-33): populated by `join.devices` and by an accepted
    /// `device-add`.
    devices_in_force: HashMap<[u8; 32], [u8; 32]>,
    /// The `(not_before_ms, not_after_ms)` window of every accepted
    /// `device-add` in this recording, keyed by the device key added.
    /// R-32's window governs authorship checks only for a device present
    /// here (a `device-add` actually in this recording, section 5.4's
    /// unnumbered paragraph); a device admitted solely through
    /// `join.devices` has no entry and so is never gated by any window.
    device_add_windows: HashMap<[u8; 32], (u64, u64)>,
    /// `(author, target, symbol)` triples this visit has seen an add
    /// reaction for, used only to detect a no-op remove (R-21); ingest
    /// still stores every reaction regardless of this set.
    reactions_added: HashSet<([u8; 32], EventId, String)>,
    broken: bool,
}

impl Recording {
    /// Opens a new, empty in-memory recording for `visit`, hosted by
    /// `host`.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError::ZeroVisit`] if `visit` is the all-zero id
    /// (R-12).
    pub fn new(visit: [u8; 32], host: [u8; 32]) -> Result<Self, IngestError> {
        if visit == [0u8; 32] {
            return Err(IngestError::ZeroVisit);
        }
        Ok(Self {
            visit,
            host,
            slots: HashMap::new(),
            participants: HashMap::new(),
            revoked: HashMap::new(),
            devices_in_force: HashMap::new(),
            device_add_windows: HashMap::new(),
            reactions_added: HashSet::new(),
            broken: false,
        })
    }

    /// `true` once an R-13 equivocation or corruption has been observed;
    /// see [`IngestError::Broken`].
    #[must_use]
    pub fn is_broken(&self) -> bool {
        self.broken
    }

    /// Returns the event stored at `seq`, if any (not a tombstone).
    #[must_use]
    pub fn get(&self, seq: u64) -> Option<&StoredEvent> {
        match self.slots.get(&seq) {
            Some(Slot::Event(stored)) => Some(stored),
            _ => None,
        }
    }

    /// Returns the tombstone at `seq`, if any (not a live event).
    #[must_use]
    pub fn tombstone_at(&self, seq: u64) -> Option<&Tombstone> {
        match self.slots.get(&seq) {
            Some(Slot::Tombstone(tombstone)) => Some(tombstone),
            _ => None,
        }
    }

    /// Finds the `seq` at which `id` is stored, whether as a live event or
    /// a tombstone (R-13, R-18, R-19 all match against either).
    fn seq_of(&self, id: EventId) -> Option<u64> {
        self.slots
            .iter()
            .find(|(_, slot)| slot.event_id() == id)
            .map(|(seq, _)| *seq)
    }

    /// The full ingest path (`docs/spec/recording.md`): every applicable
    /// rule, in the order the spec gives them, checked before anything is
    /// recorded. `now_ms` is the caller's ingest clock, used only by R-32.
    ///
    /// # Errors
    ///
    /// See [`IngestError`] for the specific rejection reasons.
    pub fn ingest(&mut self, bytes: &[u8], now_ms: u64) -> Result<EventId, IngestError> {
        if self.broken {
            return Err(IngestError::AlreadyBroken);
        }

        // R-1 to R-6, R-9, R-10, R-15, R-16, R-43, R-44: everything decidable
        // from the event's own bytes.
        let event = SignedEvent::parse(bytes)?;

        // R-12 is also checked at Recording::new time for this recording's
        // own visit; checked again here because a caller could in principle
        // hold a Recording and still be offered an event whose own `visit`
        // field is zero even though this recording's `visit` field is not
        // (R-12 talks about the event's own visit field).
        if event.envelope.visit == [0u8; 32] {
            return Err(IngestError::ZeroVisit);
        }

        // R-11: cross-visit replay check.
        if event.envelope.visit != self.visit {
            return Err(IngestError::WrongVisit);
        }

        let seq = event.envelope.seq;
        let author = event.envelope.author;

        // R-13: seq collision or prev mismatch marks the visit broken.
        if let Some(existing) = self.slots.get(&seq)
            && existing.event_id() != event.event_id
        {
            self.broken = true;
            return Err(IngestError::Broken);
        }
        let expected_prev = if seq == 0 {
            [0u8; 32]
        } else {
            match self.slots.get(&(seq - 1)) {
                Some(slot) => *slot.event_id().as_bytes(),
                None => {
                    // The predecessor is not held yet; this recording cannot
                    // yet decide R-13 for this event. Not broken: a real
                    // caller ingests in seq order (section 4), so this is
                    // reachable only when an event arrives out of order, and
                    // is retryable once the predecessor lands.
                    return Err(IngestError::PredecessorMissing(seq - 1));
                }
            }
        };
        if event.envelope.prev != expected_prev {
            self.broken = true;
            return Err(IngestError::Broken);
        }

        // R-7 / R-27 / R-30 / R-37: author must be a currently-admitted,
        // unrevoked device, unless this event is itself the `join` that
        // admits it (join is authored by the host, checked separately) or a
        // `device-add`/`device-revoke` for a not-yet-admitted device
        // (checked in their own per-type rules below).
        let is_join = matches!(&event.body, Body::Join(_));
        let is_leave = matches!(&event.body, Body::Leave(_));

        if self.revoked.contains_key(&author) {
            return Err(IngestError::RevokedAuthor);
        }

        if !is_join && !is_leave {
            match self.author_status(&author, seq) {
                AuthorStatus::Unknown => return Err(IngestError::UnknownAuthor),
                AuthorStatus::Left => return Err(IngestError::AuthorHasLeft),
                AuthorStatus::Active => {}
            }
            // R-32: if this author's device key was granted via an
            // in-recording device-add, that grant must be in force at the
            // ingest clock (never at the event's own ts_ms, which is
            // attacker-controlled display data, section 4). A device
            // admitted solely via join.devices has no window to check.
            if let Some((not_before_ms, not_after_ms)) = self.device_add_windows.get(&author)
                && !Self::device_add_grant_in_force(*not_before_ms, *not_after_ms, now_ms)
            {
                return Err(IngestError::DeviceAddGrantNotInForce);
            }
        }

        // Per-type rules (section 5).
        match &event.body {
            Body::Message(message) => {
                if let Some(reply_to) = message.reply_to {
                    self.require_stored_at_lower_seq(EventId::from_bytes(reply_to), seq)
                        .map_err(|()| IngestError::ReplyTargetNotFound)?;
                }
            }
            Body::Reaction(reaction) => {
                self.require_stored_at_lower_seq(EventId::from_bytes(reaction.target), seq)
                    .map_err(|()| IngestError::ReactionTargetNotFound)?;
            }
            Body::Attachment(_) => {}
            Body::Join(join) => {
                if author != self.host {
                    return Err(IngestError::JoinNotByHost);
                }
                self.apply_join(join, seq);
            }
            Body::Leave(leave) => {
                if author != self.host {
                    return Err(IngestError::LeaveNotByHost);
                }
                self.apply_leave(leave, seq)?;
            }
            Body::DeviceAdd(device_add) => {
                self.check_device_add(&author, device_add, now_ms)?;
                let adder_person = self.person_of(&author).unwrap_or(author);
                self.devices_in_force
                    .entry(device_add.device)
                    .or_insert(adder_person);
                self.device_add_windows.insert(
                    device_add.device,
                    (device_add.not_before_ms, device_add.not_after_ms),
                );
            }
            Body::DeviceRevoke(device_revoke) => {
                self.check_device_revoke(&author, device_revoke)?;
                self.revoked.insert(device_revoke.device, author);
                self.devices_in_force.remove(&device_revoke.device);
            }
            Body::DropRequest(drop_request) => {
                self.check_drop_request(&author, drop_request)?;
            }
            Body::Unknown { .. } => {}
        }

        self.slots.insert(
            seq,
            Slot::Event(Box::new(StoredEvent {
                event: event.clone(),
            })),
        );

        if let Body::Reaction(reaction) = &event.body
            && !reaction.remove
        {
            self.reactions_added.insert((
                author,
                EventId::from_bytes(reaction.target),
                reaction.symbol.clone(),
            ));
        }

        Ok(event.event_id)
    }

    /// R-18 / R-19: `id` must already be stored (as an event or a
    /// tombstone) at a `seq` strictly lower than `at_seq`.
    fn require_stored_at_lower_seq(&self, id: EventId, at_seq: u64) -> Result<(), ()> {
        match self.seq_of(id) {
            Some(found_seq) if found_seq < at_seq => Ok(()),
            _ => Err(()),
        }
    }

    fn person_of(&self, device: &[u8; 32]) -> Option<[u8; 32]> {
        self.devices_in_force.get(device).copied()
    }

    /// Whether `author` is currently an active, admitted device: either
    /// named directly by some un-`leave`d `join` at a `seq` at or before
    /// `at_seq`, or a device granted to an already-admitted person by an
    /// in-recording `device-add` (section 5.6), whose person has an
    /// un-`leave`d `join` at or before `at_seq`. In both cases, "un-`leave`d"
    /// means no intervening `leave` for that person that hasn't been
    /// followed by a re-`join`.
    fn author_status(&self, author: &[u8; 32], at_seq: u64) -> AuthorStatus {
        // A device named directly in a join.devices list.
        if let Some(status) = self.join_device_status(author, at_seq) {
            return status;
        }
        // A device granted via an in-recording device-add to a person who
        // is themselves an admitted participant: check the *person's*
        // active-join status, since the device itself never appears in any
        // join.devices list.
        if let Some(person) = self.devices_in_force.get(author)
            && let Some(participant) = self.participants.get(person)
        {
            let mut found_ever = false;
            for join in &participant.joins {
                if join.seq > at_seq {
                    continue;
                }
                found_ever = true;
                let still_open = match join.left_at {
                    None => true,
                    Some(left_seq) => left_seq > at_seq,
                };
                if still_open {
                    return AuthorStatus::Active;
                }
            }
            if found_ever {
                return AuthorStatus::Left;
            }
        }
        AuthorStatus::Unknown
    }

    /// The join-membership component of [`Self::author_status`]: whether
    /// `author` is named directly in some `join.devices` list, returning
    /// `None` when `author` is never named directly by any join (leaving
    /// the device-add path to decide).
    fn join_device_status(&self, author: &[u8; 32], at_seq: u64) -> Option<AuthorStatus> {
        let mut found_ever = false;
        for participant in self.participants.values() {
            for join in &participant.joins {
                if join.seq > at_seq || !join.devices.contains(author) {
                    continue;
                }
                found_ever = true;
                let still_open = match join.left_at {
                    None => true,
                    Some(left_seq) => left_seq > at_seq,
                };
                if still_open {
                    return Some(AuthorStatus::Active);
                }
            }
        }
        if found_ever {
            Some(AuthorStatus::Left)
        } else {
            None
        }
    }

    fn apply_join(&mut self, join: &super::body::Join, seq: u64) {
        for device in &join.devices {
            self.devices_in_force.entry(*device).or_insert(join.person);
        }
        let record = JoinRecord {
            seq,
            devices: join.devices.iter().copied().collect(),
            left_at: None,
        };
        self.participants
            .entry(join.person)
            .or_insert_with(|| Participant { joins: Vec::new() })
            .joins
            .push(record);
    }

    fn apply_leave(&mut self, leave: &super::body::Leave, seq: u64) -> Result<(), IngestError> {
        let participant = self
            .participants
            .get_mut(&leave.person)
            .ok_or(IngestError::LeaveWithoutActiveJoin)?;
        let mut closed_any = false;
        for join in participant.joins.iter_mut() {
            if join.seq < seq && join.left_at.is_none() {
                join.left_at = Some(seq);
                closed_any = true;
            }
        }
        if closed_any {
            Ok(())
        } else {
            Err(IngestError::LeaveWithoutActiveJoin)
        }
    }

    fn check_device_add(
        &self,
        author: &[u8; 32],
        device_add: &super::body::DeviceAdd,
        now_ms: u64,
    ) -> Result<(), IngestError> {
        // R-37: permanent once seen, regardless of window.
        if self.revoked.contains_key(&device_add.device) {
            return Err(IngestError::DeviceAddOfRevokedKey);
        }
        // R-33: this body carries no separate "person" field (unlike
        // `join`/`leave`): the person a device is added to is always the
        // author's own person, so R-33's self-authorship clause is met by
        // construction here — `author` reaching this point has already
        // passed the R-7 admitted-participant check in `Recording::ingest`,
        // so it is either an admitted device (already in force for some
        // person) or, if never seen before, is treated as that person's own
        // identity key self-signing its first grant, exactly as R-33's
        // second clause describes.
        let author_person = self.person_of(author).unwrap_or(*author);
        // R-34: `device` must not already be in force for a DIFFERENT
        // person than `author_person`. This is also the only place a
        // "person A adds a device to person B" attempt is detectable in
        // this body format: B's device keys are already claimed for B, so
        // A supplying one of them as `device_add.device` is caught here.
        if let Some(existing_person) = self.devices_in_force.get(&device_add.device)
            && *existing_person != author_person
        {
            return Err(IngestError::DeviceInForceForDifferentPerson);
        }
        let _ = now_ms;
        Ok(())
    }

    fn check_device_revoke(
        &self,
        author: &[u8; 32],
        device_revoke: &super::body::DeviceRevoke,
    ) -> Result<(), IngestError> {
        if device_revoke.device == *author {
            return Err(IngestError::InvalidRevokeTarget);
        }
        let author_person = self.person_of(author).unwrap_or(*author);
        let target_person = self.person_of(&device_revoke.device);
        if target_person != Some(author_person) {
            return Err(IngestError::InvalidRevokeTarget);
        }
        Ok(())
    }

    fn check_drop_request(
        &self,
        author: &[u8; 32],
        drop_request: &super::body::DropRequest,
    ) -> Result<(), IngestError> {
        if let Some(targets) = &drop_request.targets {
            let requester_person = self.person_of(author).unwrap_or(*author);
            for target in targets {
                let target_id = EventId::from_bytes(*target);
                let target_seq = self
                    .seq_of(target_id)
                    .ok_or(IngestError::DropRequestTargetNotOwnPerson)?;
                let Some(Slot::Event(stored)) = self.slots.get(&target_seq) else {
                    return Err(IngestError::DropRequestTargetNotOwnPerson);
                };
                let target_author = stored.event.envelope.author;
                let target_person = self.person_of(&target_author).unwrap_or(target_author);
                if target_person != requester_person {
                    return Err(IngestError::DropRequestTargetNotOwnPerson);
                }
            }
        }
        Ok(())
    }

    /// R-32: whether a `device-add` grant for `device` is in force for an
    /// event evaluated at `evaluation_instant_ms` (the ingest clock, never
    /// the event's own `ts_ms`).
    #[must_use]
    pub fn device_add_grant_in_force(
        not_before_ms: u64,
        not_after_ms: u64,
        evaluation_instant_ms: u64,
    ) -> bool {
        not_before_ms <= evaluation_instant_ms && evaluation_instant_ms < not_after_ms
    }

    /// R-41 + R-50: honours a `drop-request` by replacing every targeted
    /// event's slot with a [`Tombstone`] holding only its `seq` and
    /// `event_id`. Returns the number of slots tombstoned.
    ///
    /// `request` must name a stored `drop-request` event. When its `scope`
    /// is 0 (the whole visit), every currently stored event slot (not
    /// already a tombstone) is tombstoned. When its `scope` is 1, only the
    /// slots named in `targets` are tombstoned. The `drop-request` event
    /// itself is never tombstoned by honouring it (R-41).
    ///
    /// This in-memory model performs only the tombstone replacement; the
    /// actual local delete-for-real of the underlying bytes (R-41's "kind
    /// one") is the store's responsibility (WO-2.5), since `mosschat-core`
    /// holds no store.
    ///
    /// # Errors
    ///
    /// Returns [`IngestError::DropRequestNotFound`] if `request` does not
    /// name a stored `drop-request` event in this recording.
    pub fn honour_drop_request(&mut self, request: EventId) -> Result<usize, IngestError> {
        let request_seq = self
            .seq_of(request)
            .ok_or(IngestError::DropRequestNotFound)?;
        let Some(Slot::Event(stored)) = self.slots.get(&request_seq) else {
            return Err(IngestError::DropRequestNotFound);
        };
        let Body::DropRequest(drop_request) = &stored.event.body else {
            return Err(IngestError::DropRequestNotFound);
        };

        let targets: Vec<u64> = match drop_request.scope {
            0 => self
                .slots
                .keys()
                .copied()
                .filter(|seq| *seq != request_seq)
                .filter(|seq| matches!(self.slots.get(seq), Some(Slot::Event(_))))
                .collect(),
            _ => {
                let ids: Vec<[u8; 32]> = drop_request.targets.clone().unwrap_or_default();
                ids.into_iter()
                    .filter_map(|id| self.seq_of(EventId::from_bytes(id)))
                    .collect()
            }
        };

        let mut count = 0;
        for seq in targets {
            if let Some(Slot::Event(stored)) = self.slots.get(&seq) {
                let tombstone = Tombstone {
                    seq,
                    event_id: stored.event.event_id,
                };
                self.slots.insert(seq, Slot::Tombstone(tombstone));
                count += 1;
            }
        }
        Ok(count)
    }
}

/// The result of checking whether a device key is a currently-admitted
/// participant device (R-7, R-27, R-30).
enum AuthorStatus {
    /// Never named by any `join.devices` in this visit.
    Unknown,
    /// Named by a `join`, but every such `join` has since been closed by a
    /// `leave` with no later re-`join`.
    Left,
    /// Named by an un-`leave`d `join`.
    Active,
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
    use crate::event::body::{Body, Join, Message};
    use crate::event::envelope::Envelope;
    use crate::identity::AuthorKey;

    fn signed_bytes(envelope: Envelope, body: &Body, key: &AuthorKey) -> Vec<u8> {
        SignedEvent::sign(envelope, body, key).to_bytes()
    }

    fn base_envelope(visit: [u8; 32], author: [u8; 32], seq: u64, prev: [u8; 32]) -> Envelope {
        Envelope {
            v: 1,
            visit,
            author,
            seq,
            prev,
            ts_ms: 1_757_000_000_000,
            body_hash: [0u8; 32],
            body_len: 0,
        }
    }

    #[test]
    fn zero_visit_is_rejected_at_open() {
        let host = AuthorKey::generate();
        assert!(matches!(
            Recording::new([0u8; 32], host.public_bytes()),
            Err(IngestError::ZeroVisit)
        ));
    }

    #[test]
    fn join_then_message_from_admitted_device_is_accepted() {
        let visit = [0x11u8; 32];
        let host = AuthorKey::generate();
        let guest = AuthorKey::generate();
        let mut recording = Recording::new(visit, host.public_bytes()).expect("open");

        let join_body = Body::Join(Join {
            person: guest.public_bytes(),
            devices: vec![guest.public_bytes()],
            name: None,
        });
        let join_bytes = signed_bytes(
            base_envelope(visit, host.public_bytes(), 0, [0u8; 32]),
            &join_body,
            &host,
        );
        let join_id = recording.ingest(&join_bytes, 0).expect("join accepted");

        let message_body = Body::Message(Message {
            text: "hello".to_owned(),
            reply_to: None,
        });
        let message_bytes = signed_bytes(
            base_envelope(visit, guest.public_bytes(), 1, *join_id.as_bytes()),
            &message_body,
            &guest,
        );
        recording
            .ingest(&message_bytes, 0)
            .expect("message from admitted device accepted");
    }

    #[test]
    fn message_from_unadmitted_device_is_rejected() {
        let visit = [0x11u8; 32];
        let host = AuthorKey::generate();
        let stranger = AuthorKey::generate();
        let mut recording = Recording::new(visit, host.public_bytes()).expect("open");

        let message_body = Body::Message(Message {
            text: "hello".to_owned(),
            reply_to: None,
        });
        let message_bytes = signed_bytes(
            base_envelope(visit, stranger.public_bytes(), 0, [0u8; 32]),
            &message_body,
            &stranger,
        );
        assert!(matches!(
            recording.ingest(&message_bytes, 0),
            Err(IngestError::UnknownAuthor)
        ));
    }
}
