//! Computed views over recordings (`docs/spec/recording.md` section 8).
//!
//! A view is a pure function of the [`Recording`](crate::event::ingest::Recording)s
//! this machine holds (R-48): the same recordings produce the same view
//! whatever order their events arrived in and whatever order rows are read
//! back. Views are **computed, never stored** (section 8, decision D5): this
//! module holds no table, no cache, and reads no persisted view of its own.
//!
//! `Recording` keeps its slots and participants in `HashMap`s, whose
//! iteration order is randomised per process. Every function in this module
//! that walks one of those maps to build output sorts into a deterministic
//! order before returning it, per the ordering rules this module documents
//! at each function. This is the one property this module exists to get
//! right; getting it wrong is a silent, intermittent test failure that
//! depends on hash-seed luck, so every sort point below is called out
//! explicitly rather than left to be "probably fine" from a `HashMap`'s
//! typical behaviour on one run.
//!
//! ## What this module does not do
//!
//! - It does not read a second participant's recording to fill a gap in
//!   this one (section 9): every function here takes the caller's own
//!   in-memory [`Recording`]s or a single [`Store`] this house owns, never
//!   a peer's.
//! - It does not filter out private visits (R-46): a private visit has no
//!   [`Recording`] loaded from a store in the first place, because it has
//!   no rows to load (R-46 is enforced by absence). A caller that hands
//!   this module an in-memory `Recording` for a visit it privately decided
//!   not to persist is the caller's own bug; this module has no way to
//!   know a `Recording` "should have" been private and does not attempt to
//!   filter one out after the fact.
//! - It does not filter out a deleted visit for the same reason in
//!   reverse: after [`delete_visit_for_real`], the store holds no rows for
//!   that visit, so [`recordings_from_store`] simply does not produce a
//!   `Recording` for it, and no section names it (R-45).

use std::collections::BTreeMap;

use thiserror::Error;

use crate::event::envelope::Envelope;
use crate::event::id::EventId;
use crate::event::ingest::{IngestError, Recording};
use crate::store::{Store, StoreError};

/// The exact wording R-41 requires the view to show at a dropped position.
pub const DROPPED_MARKER: &str = "dropped at their request";

/// One rendered position in a visit's recording, in ascending `seq` order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewEntry {
    /// A live event at this seq.
    Event {
        /// The host-assigned sequence number.
        seq: u64,
        /// The device key that authored this event.
        author: [u8; 32],
        /// Display-only wall clock, never an ordering input (section 4).
        ts_ms: u64,
        /// This event's content-addressed id.
        event_id: EventId,
        /// A body this build does not recognise (an unassigned type value,
        /// section 5's reserved-but-unassigned range, or `128` and above)
        /// is surfaced as `Unreadable` rather than a decoded body (R-14):
        /// the recording layer still carries and stores it whole, but a
        /// view has nothing meaningful to render for it beyond that it
        /// exists. A known body type is `Readable`.
        body: RenderedBody,
    },
    /// R-41/R-49: an honoured drop-request left a tombstone here. The view
    /// renders a marker, never a gap. Carries only what a
    /// [`crate::event::ingest::Tombstone`] carries — `seq` and `event_id` —
    /// no author, no timestamp, no body, because those fields do not exist
    /// on a tombstone (R-50) and this type does not invent them.
    Dropped {
        /// The dropped event's former sequence number.
        seq: u64,
        /// The dropped event's `event_id`, preserved for display/matching.
        event_id: EventId,
    },
}

impl ViewEntry {
    /// The `seq` this entry occupies, whichever variant it is.
    #[must_use]
    pub fn seq(&self) -> u64 {
        match self {
            ViewEntry::Event { seq, .. } | ViewEntry::Dropped { seq, .. } => *seq,
        }
    }

    /// Renders this entry's marker text if it is [`ViewEntry::Dropped`]
    /// (R-41's exact wording, [`DROPPED_MARKER`]), or `None` for a live
    /// event. Exists so a caller (and this crate's own abuse tests) asserts
    /// the marker text through one function rather than inferring it from
    /// the variant alone.
    #[must_use]
    pub fn dropped_marker(&self) -> Option<&'static str> {
        match self {
            ViewEntry::Dropped { .. } => Some(DROPPED_MARKER),
            ViewEntry::Event { .. } => None,
        }
    }
}

/// Whether a rendered [`ViewEntry::Event`]'s body is one this build knows how
/// to decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderedBody {
    /// A known body type (section 5's table), decoded.
    Readable(crate::event::body::Body),
    /// An unassigned or private-extension body type (R-14): carried whole by
    /// the recording layer, but this build has nothing to render for it
    /// beyond "a message this version cannot read". Holds the raw body
    /// bytes and the type value at map key `0`, matching
    /// [`crate::event::body::Body::Unknown`]'s own shape.
    Unreadable {
        /// The body type value this build does not recognise.
        type_value: u64,
        /// The complete, unmodified body bytes (R-8, R-14).
        raw: Vec<u8>,
    },
}

/// One visit as a section of a view: decision 12, each visit is its own
/// section, and section 8, ordered within a section by ascending `seq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisitSection {
    /// The visit id.
    pub visit: [u8; 32],
    /// The visit's host device key.
    pub host: [u8; 32],
    /// The `ts_ms` of the event at `seq == 0` (`visit-open`), used to order
    /// sections within a view (section 8: "ordered by the visit's own
    /// opening").
    pub opened_ms: u64,
    /// Every identity key that has appeared in any in-force `join` in this
    /// recording, sorted ascending (section 8's participant-set rule).
    pub participants: Vec<[u8; 32]>,
    /// Every occupied `seq` in this recording, in ascending order, dense
    /// over the range actually held: a `seq` never received is simply
    /// absent (a short recording), not rendered as anything.
    pub entries: Vec<ViewEntry>,
}

/// Section 8: every visit a person was in, one-on-one or group, each its own
/// section, ordered by the visit's own opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactView {
    /// The identity key this page is for.
    pub person: [u8; 32],
    /// This person's visits, ordered by opening (tie-broken by visit id
    /// ascending, so the order is total).
    pub sections: Vec<VisitSection>,
}

/// Section 8: visits grouped by participant set — the union, over the whole
/// recording, of every identity key that ever appeared in an in-force
/// `join`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupView {
    /// The participant set this page is for, sorted ascending (this is also
    /// the type's own ordering key: see [`group_views`]'s docs).
    pub participants: Vec<[u8; 32]>,
    /// This group's visits, ordered by opening (tie-broken by visit id
    /// ascending).
    pub sections: Vec<VisitSection>,
}

/// Errors from the view layer's store-replay and delete-composition paths.
#[derive(Debug, Error)]
pub enum ViewError {
    /// A store operation failed while replaying or deleting.
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    /// A stored event failed to re-ingest during replay. Replay re-verifies
    /// every signature and every rule (it does not trust the store's own
    /// bytes blindly), so a corrupted or tampered row surfaces here rather
    /// than silently producing a wrong `Recording`.
    #[error("replay ingest failed: {0}")]
    Ingest(#[from] IngestError),
    /// [`recording_from_store`] was asked to replay a visit that has no
    /// `visit` row (never opened, deleted for real, or private — R-46).
    #[error("no visit row for this visit id")]
    NoSuchVisit,
    /// [`Recording::new`] rejected the replayed visit's own id (R-12); this
    /// would mean a `visit` row exists holding the all-zero id, which
    /// `Store::open_visit` never writes.
    #[error("recording open failed: {0}")]
    RecordingOpen(IngestError),
}

/// Builds one visit's [`VisitSection`] from its in-memory [`Recording`].
///
/// Walks [`Recording::seq_range`] in ascending order (R-48: never the
/// `HashMap`'s own iteration order), rendering a [`ViewEntry::Event`] for a
/// live slot and a [`ViewEntry::Dropped`] for a tombstoned one (R-49: a
/// marker, never a gap). A `seq` this recording holds no slot for at all is
/// simply absent from `entries` — a short recording, not a drop.
///
/// `opened_ms` is read from the event at `seq == 0` (`visit-open`, by
/// construction of section 4: `seq` counts from 0 at `visit-open`), read as
/// this event's own `ts_ms` since that is the only wall-clock information a
/// `Recording` carries; when `seq == 0` is not held (a partial recording),
/// `opened_ms` is `0`, which only affects section ordering within a view for
/// a recording that has not even received its own opening event yet.
#[must_use]
pub fn visit_section(recording: &Recording) -> VisitSection {
    let opened_ms = recording
        .get(0)
        .map(|stored| stored.event.envelope.ts_ms)
        .unwrap_or(0);

    let mut entries = Vec::new();
    if let Some((min, max)) = recording.seq_range() {
        for seq in min..=max {
            if let Some(stored) = recording.get(seq) {
                let envelope: &Envelope = &stored.event.envelope;
                let body = match &stored.event.body {
                    crate::event::body::Body::Unknown { type_value, raw } => {
                        RenderedBody::Unreadable {
                            type_value: *type_value,
                            raw: raw.clone(),
                        }
                    }
                    known => RenderedBody::Readable(known.clone()),
                };
                entries.push(ViewEntry::Event {
                    seq,
                    author: envelope.author,
                    ts_ms: envelope.ts_ms,
                    event_id: stored.event.event_id,
                    body,
                });
            } else if let Some(tombstone) = recording.tombstone_at(seq) {
                entries.push(ViewEntry::Dropped {
                    seq,
                    event_id: tombstone.event_id,
                });
            }
            // Neither: `seq` was never received. Absent from `entries`
            // entirely, per this function's own docs.
        }
    }

    VisitSection {
        visit: *recording.visit(),
        host: *recording.host(),
        opened_ms,
        participants: recording.participant_keys(),
        entries,
    }
}

/// Total order for sections within any view (section 8: "ordered by the
/// visit's own opening"), tie-broken by visit id ascending so the order is
/// total and never depends on input order (R-48).
fn section_order_key(section: &VisitSection) -> (u64, [u8; 32]) {
    (section.opened_ms, section.visit)
}

/// Section 8: every visit in which `person` appears in any in-force `join`,
/// whether one-on-one or group, each visit its own section, ordered by the
/// visit's own opening (tie-broken by visit id).
///
/// A contact's identity is their identity key (`join.person`): a person who
/// added a device still has one page, because [`Recording::participant_keys`]
/// returns identity keys, never device keys.
#[must_use]
pub fn contact_view(recordings: &[Recording], person: &[u8; 32]) -> ContactView {
    let mut sections: Vec<VisitSection> = recordings
        .iter()
        .filter(|recording| recording.participant_keys().contains(person))
        .map(visit_section)
        .collect();
    sections.sort_by_key(section_order_key);
    ContactView {
        person: *person,
        sections,
    }
}

/// Section 8: visits grouped by participant set — the union, over the whole
/// recording, of every identity key that ever appeared in an in-force
/// `join`. Two visits with the same participant set are two sections of one
/// group page; a visit where somebody joined late has the participant set
/// that includes them, so it groups with visits of that larger set (which
/// is exactly what [`Recording::participant_keys`] returns: every person
/// ever seen in a `join`, not a point-in-time membership).
///
/// Groups are ordered by their participant set, comparing the sorted key
/// lists lexicographically (`Vec<[u8; 32]>`'s derived `Ord` on its element
/// type does exactly this), so the output order is total and independent of
/// recording arrival order (R-48).
#[must_use]
pub fn group_views(recordings: &[Recording]) -> Vec<GroupView> {
    let mut groups: BTreeMap<Vec<[u8; 32]>, Vec<VisitSection>> = BTreeMap::new();
    for recording in recordings {
        let key = recording.participant_keys();
        groups
            .entry(key)
            .or_default()
            .push(visit_section(recording));
    }
    groups
        .into_iter()
        .map(|(participants, mut sections)| {
            sections.sort_by_key(section_order_key);
            GroupView {
                participants,
                sections,
            }
        })
        .collect()
}

/// Rebuilds the in-memory [`Recording`] for one visit from its stored bytes,
/// by re-ingesting each event in `seq` order through the same
/// [`Recording::ingest`] path that accepted it originally.
///
/// Replay re-verifies every signature and every rule — the reloaded
/// recording is validated, not trusted (a store row is opaque bytes to
/// `mosschat-core`'s own storage seam; only re-parsing and re-ingesting
/// proves it is still a valid recording). A tombstoned row has no bytes to
/// re-ingest, since a tombstone is not a signed, verifiable event; its slot
/// is reconstructed directly via [`Recording::insert_tombstone`] from the
/// stored `(seq, event_id)` pair (R-50).
///
/// `now_ms` is the ingest clock for R-32's evaluation instant, exactly as it
/// is for a live [`Recording::ingest`] call: replay does not read the
/// system clock itself (invariant 11 extends to this module).
///
/// # Errors
///
/// [`ViewError::Ingest`] if a stored row fails to re-verify.
pub fn recording_from_store(
    store: &Store,
    visit: &[u8; 32],
    host: &[u8; 32],
    now_ms: u64,
) -> Result<Recording, ViewError> {
    let mut recording = Recording::new(*visit, *host).map_err(ViewError::RecordingOpen)?;
    for (seq, row) in store.events_for_visit(visit)? {
        match row.event_bytes {
            Some(bytes) => {
                recording.ingest(&bytes, now_ms)?;
            }
            None => {
                recording.insert_tombstone(seq, EventId::from_bytes(row.event_id));
            }
        }
    }
    Ok(recording)
}

/// Rebuilds every visit's [`Recording`] this store currently holds, for view
/// computation over the whole house.
///
/// Uses [`Store::visit_row`] (WO-2.4b's second additive store method) to
/// recover each visit's host, since [`Store::list_visits`] returns ids
/// alone. A visit absent from the store (private, R-46, or deleted for
/// real, R-45) is simply not in [`Store::list_visits`]'s result and so
/// produces no `Recording` here, which is what satisfies R-49 for both
/// cases at the view layer.
///
/// # Errors
///
/// [`ViewError::NoSuchVisit`] if a listed visit's row disappears between the
/// list and the read (a concurrent delete this house's own caller ran); any
/// store or ingest error from replaying an individual visit.
pub fn recordings_from_store(store: &Store, now_ms: u64) -> Result<Vec<Recording>, ViewError> {
    let mut out = Vec::new();
    for visit in store.list_visits()? {
        let row = store.visit_row(&visit)?.ok_or(ViewError::NoSuchVisit)?;
        out.push(recording_from_store(store, &visit, &row.host, now_ms)?);
    }
    Ok(out)
}

/// Composes [`Store::delete_visit`] (kind one, R-45's store half) with the
/// view half of R-45: after this returns, recomputing views from the store
/// (e.g. via [`recordings_from_store`] and [`group_views`]/[`contact_view`])
/// produces no section naming `visit`, because [`Store::list_visits`] no
/// longer lists it and no row remains to replay. This function does not
/// itself touch any view; it documents and makes testable the composition
/// that satisfies R-45's "no view names that visit" half.
///
/// # Errors
///
/// Whatever [`Store::delete_visit`] returns.
pub fn delete_visit_for_real(store: &mut Store, visit: &[u8; 32]) -> Result<(), ViewError> {
    store.delete_visit(visit)?;
    Ok(())
}

/// Honours a `drop-request` across both halves R-41 requires: the in-memory
/// tombstone replacement ([`Recording::honour_drop_request`]) and the
/// store's own bytes-gone-from-the-row half ([`Store::tombstone_event`]) for
/// every `seq` the recording actually tombstoned.
///
/// The `drop-request` event itself is never among the tombstoned `seq`s
/// (R-41: "The `drop-request` event itself is never deleted by being
/// honoured"), which holds here because [`Recording::honour_drop_request`]
/// never includes its own target `seq` in what it tombstones.
///
/// # Errors
///
/// [`ViewError::Ingest`] if `request` does not name a stored `drop-request`
/// event in `recording`; [`ViewError::Store`] if tombstoning a targeted
/// `seq` in the store fails.
///
/// Returns the `seq`s tombstoned, in ascending order (the order
/// [`Recording::honour_drop_request`]'s own `count` covers; ascending here
/// so a caller logging or displaying the result gets a deterministic list,
/// consistent with this module's general ordering discipline).
pub fn honour_drop_request(
    store: &Store,
    visit: &[u8; 32],
    recording: &mut Recording,
    request: EventId,
) -> Result<Vec<u64>, ViewError> {
    // Snapshot which seqs are live (not already tombstoned) before
    // honouring, so we know exactly which ones the in-memory step just
    // changed and need the matching store-side tombstone.
    let before: Vec<u64> = match recording.seq_range() {
        Some((min, max)) => (min..=max)
            .filter(|seq| recording.get(*seq).is_some())
            .collect(),
        None => Vec::new(),
    };

    recording.honour_drop_request(request)?;

    let mut tombstoned: Vec<u64> = before
        .into_iter()
        .filter(|seq| recording.tombstone_at(*seq).is_some())
        .collect();
    tombstoned.sort_unstable();

    for seq in &tombstoned {
        store.tombstone_event(visit, *seq)?;
    }

    Ok(tombstoned)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests;
