//! Tests for the view module (WO-2.4b). Selected by
//! `cargo test -p mosschat-core view::`.

use super::*;
use crate::event::body::{Body, DropRequest, Join, Message};
use crate::event::envelope::Envelope;
use crate::event::signed::SignedEvent;
use crate::identity::AuthorKey;
use crate::store::{DataKey, KeyFile, Store, StoredEvent as StoreStoredEvent};

fn base_envelope(visit: [u8; 32], author: [u8; 32], seq: u64, prev: [u8; 32]) -> Envelope {
    Envelope {
        v: 1,
        visit,
        author,
        seq,
        prev,
        ts_ms: 1_757_000_000_000 + seq,
        body_hash: [0u8; 32],
        body_len: 0,
    }
}

fn signed_bytes(envelope: Envelope, body: &Body, key: &AuthorKey) -> Vec<u8> {
    SignedEvent::sign(envelope, body, key).to_bytes()
}

fn join_body(person: [u8; 32], devices: Vec<[u8; 32]>) -> Body {
    Body::Join(Join {
        person,
        devices,
        name: None,
    })
}

fn message_body(text: &str) -> Body {
    Body::Message(Message {
        text: text.to_owned(),
        reply_to: None,
    })
}

/// Builds a small recording: host + one guest joined at seq 0, then
/// `n_messages` alternating messages from host/guest.
fn build_recording(
    visit: [u8; 32],
    host: &AuthorKey,
    guest: &AuthorKey,
    n_messages: u64,
) -> Recording {
    let mut recording = Recording::new(visit, host.public_bytes()).expect("open");
    let join = signed_bytes(
        base_envelope(visit, host.public_bytes(), 0, [0u8; 32]),
        &join_body(
            guest.public_bytes(),
            vec![host.public_bytes(), guest.public_bytes()],
        ),
        host,
    );
    // The join names both host and guest as devices of `guest.public_bytes()`
    // person — that is wrong for a real two-person visit. Build it properly:
    // two separate joins instead.
    let _ = join;

    let host_join = signed_bytes(
        base_envelope(visit, host.public_bytes(), 0, [0u8; 32]),
        &join_body(host.public_bytes(), vec![host.public_bytes()]),
        host,
    );
    let host_join_id = recording.ingest(&host_join, 0).expect("host join accepted");

    let guest_join = signed_bytes(
        base_envelope(visit, host.public_bytes(), 1, *host_join_id.as_bytes()),
        &join_body(guest.public_bytes(), vec![guest.public_bytes()]),
        host,
    );
    let mut prev = recording
        .ingest(&guest_join, 0)
        .expect("guest join accepted");

    for i in 0..n_messages {
        let (author, key) = if i % 2 == 0 {
            (host.public_bytes(), host)
        } else {
            (guest.public_bytes(), guest)
        };
        let seq = 2 + i;
        let bytes = signed_bytes(
            base_envelope(visit, author, seq, *prev.as_bytes()),
            &message_body(&format!("message {i}")),
            key,
        );
        prev = recording.ingest(&bytes, 0).expect("message accepted");
    }

    recording
}

fn visit_id(byte: u8) -> [u8; 32] {
    let mut v = [0u8; 32];
    v[0] = byte;
    v
}

// ---------------------------------------------------------------------
// R-48: purity / determinism
// ---------------------------------------------------------------------

/// Building the same events through two different arrival orders (still
/// respecting seq order, since ingest requires it) and reading rows back
/// in different orders must produce byte-identical (`==`) views: the whole
/// point of R-48 is that `HashMap` iteration order inside `Recording` never
/// leaks into a view.
#[test]
fn view_r48_purity_same_recordings_same_view_regardless_of_order() {
    let host = AuthorKey::generate();
    let guest_a = AuthorKey::generate();
    let guest_b = AuthorKey::generate();

    // Many participants and many visits, asserted on full structure.
    let visit1 = visit_id(1);
    let visit2 = visit_id(2);
    let visit3 = visit_id(3);

    let rec1a = build_recording(visit1, &host, &guest_a, 12);
    let rec2a = build_recording(visit2, &host, &guest_b, 8);
    let rec3a = build_recording(visit3, &host, &guest_a, 5);

    // "Different order" #1: recordings vector in one order.
    let recordings_a = vec![rec1a.clone(), rec2a.clone(), rec3a.clone()];
    // "Different order" #2: same recordings, different vector order (this
    // simulates a different `HashMap`/store row read order upstream, since
    // the view functions themselves sort deterministically over whatever
    // order they are handed).
    let recordings_b = vec![rec3a.clone(), rec1a.clone(), rec2a.clone()];

    let contact_a = contact_view(&recordings_a, &host.public_bytes());
    let contact_b = contact_view(&recordings_b, &host.public_bytes());
    assert_eq!(contact_a, contact_b);

    let groups_a = group_views(&recordings_a);
    let groups_b = group_views(&recordings_b);
    assert_eq!(groups_a, groups_b);

    // Also assert against independently-rebuilt recordings (a second,
    // independently-constructed set of `Recording`s for the same events),
    // to catch any HashMap-order leak that happens to be stable within one
    // process run.
    let rec1c = build_recording(visit1, &host, &guest_a, 12);
    let rec2c = build_recording(visit2, &host, &guest_b, 8);
    let rec3c = build_recording(visit3, &host, &guest_a, 5);
    let recordings_c = vec![rec2c, rec3c, rec1c];
    assert_eq!(contact_a, contact_view(&recordings_c, &host.public_bytes()));
    assert_eq!(groups_a, group_views(&recordings_c));
}

// ---------------------------------------------------------------------
// R-49 (in-memory half): dropped marker, not a gap
// ---------------------------------------------------------------------

#[test]
fn view_r49_dropped_entry_is_a_marker_not_a_gap() {
    let host = AuthorKey::generate();
    let guest = AuthorKey::generate();
    let visit = visit_id(10);
    let mut recording = build_recording(visit, &host, &guest, 3);

    // Drop the message at seq 3 (the second message, authored by guest,
    // since seq 0/1 are joins and seq 2 is host's first message).
    let target_id = *recording
        .get(3)
        .expect("seq 3 present")
        .event
        .event_id
        .as_bytes();
    let drop = signed_bytes(
        base_envelope(visit, guest.public_bytes(), 5, {
            let last = recording.get(4).expect("seq 4 present");
            *last.event.event_id.as_bytes()
        }),
        &Body::DropRequest(DropRequest {
            scope: 1,
            targets: Some(vec![target_id]),
            note: None,
        }),
        &guest,
    );
    let drop_id = recording.ingest(&drop, 0).expect("drop-request accepted");

    recording
        .honour_drop_request(drop_id)
        .expect("honour succeeds");

    let section = visit_section(&recording);
    let entry_at_3 = section
        .entries
        .iter()
        .find(|e| e.seq() == 3)
        .expect("seq 3 still present as an entry");
    match entry_at_3 {
        ViewEntry::Dropped { seq, event_id } => {
            assert_eq!(*seq, 3);
            assert_eq!(*event_id.as_bytes(), target_id);
            assert_eq!(entry_at_3.dropped_marker(), Some(DROPPED_MARKER));
        }
        other => panic!("expected Dropped at seq 3, got {other:?}"),
    }

    // Entries either side are unchanged (still live events).
    let entry_at_2 = section.entries.iter().find(|e| e.seq() == 2).unwrap();
    assert!(matches!(entry_at_2, ViewEntry::Event { .. }));
    let entry_at_4 = section.entries.iter().find(|e| e.seq() == 4).unwrap();
    assert!(matches!(entry_at_4, ViewEntry::Event { .. }));
}

// ---------------------------------------------------------------------
// R-45 end to end, and R-41 end to end
// ---------------------------------------------------------------------

fn fresh_store() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("house.sqlite3");
    let key_path = dir.path().join("house.key");
    let key: DataKey = KeyFile::create(&key_path).expect("create key");
    let store = Store::open(&db_path, &key).expect("open store");
    (dir, store)
}

fn store_needle_search(db_path: &std::path::Path, needle: &[u8]) -> bool {
    let bytes = std::fs::read(db_path).expect("read store file");
    bytes.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn view_r45_end_to_end_deleted_visit_absent_and_bytes_gone() {
    let (dir, mut store) = fresh_store();
    let db_path = dir.path().join("house.sqlite3");

    let host = AuthorKey::generate();
    let visit = visit_id(20);
    let needle = b"R45 NEEDLE the swift heron crossed the marsh at dawn 778812";

    store
        .open_visit(&visit, &host.public_bytes(), 1_000)
        .unwrap();
    let join = signed_bytes(
        base_envelope(visit, host.public_bytes(), 0, [0u8; 32]),
        &join_body(host.public_bytes(), vec![host.public_bytes()]),
        &host,
    );
    let signed = SignedEvent::parse(&join).unwrap();
    store
        .append_event(
            &visit,
            &StoreStoredEvent {
                seq: 0,
                event_id: *signed.event_id.as_bytes(),
                event_bytes: join.clone(),
            },
        )
        .unwrap();

    let msg_body = Body::Message(Message {
        text: String::from_utf8(needle.to_vec()).unwrap(),
        reply_to: None,
    });
    let msg = signed_bytes(
        base_envelope(visit, host.public_bytes(), 1, *signed.event_id.as_bytes()),
        &msg_body,
        &host,
    );
    let msg_signed = SignedEvent::parse(&msg).unwrap();
    store
        .append_event(
            &visit,
            &StoreStoredEvent {
                seq: 1,
                event_id: *msg_signed.event_id.as_bytes(),
                event_bytes: msg.clone(),
            },
        )
        .unwrap();

    // Section present before delete. The needle is never found in the raw
    // file even before delete: the store is encrypted (SQLCipher), which is
    // exactly `hexdump_proves_no_plaintext`'s own premise in store.rs; this
    // test's R-45 proof is the file-level absence *specifically after*
    // delete-for-real, matching `delete_visit_removes_rows_and_bytes_from_file`.
    let recordings_before = recordings_from_store(&store, 0).expect("replay");
    let groups_before = group_views(&recordings_before);
    assert!(
        groups_before
            .iter()
            .any(|g| g.sections.iter().any(|s| s.visit == visit)),
        "visit should be present before delete"
    );

    // Delete for real.
    delete_visit_for_real(&mut store, &visit).expect("delete");

    let recordings_after = recordings_from_store(&store, 0).expect("replay after delete");
    let groups_after = group_views(&recordings_after);
    assert!(
        !groups_after
            .iter()
            .any(|g| g.sections.iter().any(|s| s.visit == visit)),
        "no view may name the deleted visit (R-45)"
    );
    assert!(
        !store_needle_search(&db_path, needle),
        "deleted visit's plaintext must be gone from the store file (R-45)"
    );
}

#[test]
fn view_r41_end_to_end_honoured_drop_deletes_bytes_leaves_marker_keeps_request() {
    let (dir, store) = fresh_store();
    let db_path = dir.path().join("house.sqlite3");

    let host = AuthorKey::generate();
    let visit = visit_id(21);
    let needle = b"R41 NEEDLE a private word never meant to persist 991133";

    store
        .open_visit(&visit, &host.public_bytes(), 1_000)
        .unwrap();

    let join = signed_bytes(
        base_envelope(visit, host.public_bytes(), 0, [0u8; 32]),
        &join_body(host.public_bytes(), vec![host.public_bytes()]),
        &host,
    );
    let join_signed = SignedEvent::parse(&join).unwrap();
    store
        .append_event(
            &visit,
            &StoreStoredEvent {
                seq: 0,
                event_id: *join_signed.event_id.as_bytes(),
                event_bytes: join,
            },
        )
        .unwrap();

    let msg_body = Body::Message(Message {
        text: String::from_utf8(needle.to_vec()).unwrap(),
        reply_to: None,
    });
    let msg = signed_bytes(
        base_envelope(
            visit,
            host.public_bytes(),
            1,
            *join_signed.event_id.as_bytes(),
        ),
        &msg_body,
        &host,
    );
    let msg_signed = SignedEvent::parse(&msg).unwrap();
    let msg_id = *msg_signed.event_id.as_bytes();
    store
        .append_event(
            &visit,
            &StoreStoredEvent {
                seq: 1,
                event_id: msg_id,
                event_bytes: msg,
            },
        )
        .unwrap();

    let drop = signed_bytes(
        base_envelope(visit, host.public_bytes(), 2, msg_id),
        &Body::DropRequest(DropRequest {
            scope: 1,
            targets: Some(vec![msg_id]),
            note: None,
        }),
        &host,
    );
    let drop_signed = SignedEvent::parse(&drop).unwrap();
    let drop_id_bytes = *drop_signed.event_id.as_bytes();
    store
        .append_event(
            &visit,
            &StoreStoredEvent {
                seq: 2,
                event_id: drop_id_bytes,
                event_bytes: drop,
            },
        )
        .unwrap();

    // Replay, then honour the drop-request through the composed function.
    let mut recording = recording_from_store(&store, &visit, &host.public_bytes(), 0).unwrap();
    let tombstoned = honour_drop_request(
        &store,
        &visit,
        &mut recording,
        EventId::from_bytes(drop_id_bytes),
    )
    .expect("honour succeeds");
    assert_eq!(tombstoned, vec![1]);

    assert!(
        !store_needle_search(&db_path, needle),
        "honoured drop-request's target bytes must be gone from the store file (R-41)"
    );

    let section = visit_section(&recording);
    let entry1 = section.entries.iter().find(|e| e.seq() == 1).unwrap();
    assert_eq!(entry1.dropped_marker(), Some(DROPPED_MARKER));

    // The drop-request event itself (seq 2) is still stored and visible.
    let entry2 = section.entries.iter().find(|e| e.seq() == 2).unwrap();
    match entry2 {
        ViewEntry::Event { event_id, .. } => {
            assert_eq!(*event_id.as_bytes(), drop_id_bytes);
        }
        other => panic!("drop-request event itself must still be visible, got {other:?}"),
    }
    let row2 = store.get_event(&visit, 2).unwrap().expect("row remains");
    assert!(row2.event_bytes.is_some(), "drop-request bytes must remain");
}

// ---------------------------------------------------------------------
// Restart / identical view (Phase 2 exit shape)
// ---------------------------------------------------------------------

#[test]
fn view_restart_10k_messages_identical_view_after_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("house.sqlite3");
    let key_path = dir.path().join("house.key");
    let key: DataKey = KeyFile::create(&key_path).expect("create key");

    let host = AuthorKey::generate();
    let visit = visit_id(30);
    const N: u64 = 10_000;

    let view_before = {
        let store = Store::open(&db_path, &key).expect("open store");
        store
            .open_visit(&visit, &host.public_bytes(), 1_000)
            .unwrap();

        let join = signed_bytes(
            base_envelope(visit, host.public_bytes(), 0, [0u8; 32]),
            &join_body(host.public_bytes(), vec![host.public_bytes()]),
            &host,
        );
        let join_signed = SignedEvent::parse(&join).unwrap();
        store
            .append_event(
                &visit,
                &StoreStoredEvent {
                    seq: 0,
                    event_id: *join_signed.event_id.as_bytes(),
                    event_bytes: join,
                },
            )
            .unwrap();

        let mut prev = *join_signed.event_id.as_bytes();
        for i in 0..N {
            let seq = 1 + i;
            let bytes = signed_bytes(
                base_envelope(visit, host.public_bytes(), seq, prev),
                &message_body(&format!("message number {i}")),
                &host,
            );
            let signed = SignedEvent::parse(&bytes).unwrap();
            store
                .append_event(
                    &visit,
                    &StoreStoredEvent {
                        seq,
                        event_id: *signed.event_id.as_bytes(),
                        event_bytes: bytes,
                    },
                )
                .unwrap();
            prev = *signed.event_id.as_bytes();
        }

        let recording = recording_from_store(&store, &visit, &host.public_bytes(), 0).unwrap();
        visit_section(&recording)
        // `store` (and its lock) drops here.
    };

    // Reopen and replay.
    let key2 = KeyFile::open(&key_path).expect("reopen key");
    let store2 = Store::open(&db_path, &key2).expect("reopen store");
    let recording2 = recording_from_store(&store2, &visit, &host.public_bytes(), 0).unwrap();
    let view_after = visit_section(&recording2);

    assert_eq!(view_before, view_after);
    assert_eq!(view_after.entries.len(), (N + 1) as usize);
}

// ---------------------------------------------------------------------
// Contact / group view semantics
// ---------------------------------------------------------------------

#[test]
fn view_contact_page_spans_one_on_one_and_group_visits() {
    let host = AuthorKey::generate();
    let a = AuthorKey::generate();
    let b = AuthorKey::generate();

    // One-on-one visit: host + a.
    let visit_1on1 = visit_id(40);
    let rec_1on1 = build_recording(visit_1on1, &host, &a, 2);

    // Group visit: host, a, b all joined.
    let visit_group = visit_id(41);
    let mut rec_group = Recording::new(visit_group, host.public_bytes()).expect("open");
    let host_join = signed_bytes(
        base_envelope(visit_group, host.public_bytes(), 0, [0u8; 32]),
        &join_body(host.public_bytes(), vec![host.public_bytes()]),
        &host,
    );
    let mut prev = rec_group.ingest(&host_join, 0).unwrap();
    let a_join = signed_bytes(
        base_envelope(visit_group, host.public_bytes(), 1, *prev.as_bytes()),
        &join_body(a.public_bytes(), vec![a.public_bytes()]),
        &host,
    );
    prev = rec_group.ingest(&a_join, 0).unwrap();
    let b_join = signed_bytes(
        base_envelope(visit_group, host.public_bytes(), 2, *prev.as_bytes()),
        &join_body(b.public_bytes(), vec![b.public_bytes()]),
        &host,
    );
    rec_group.ingest(&b_join, 0).unwrap();

    let recordings = vec![rec_1on1, rec_group];

    let a_contact = contact_view(&recordings, &a.public_bytes());
    assert_eq!(a_contact.sections.len(), 2);
    let visits: Vec<[u8; 32]> = a_contact.sections.iter().map(|s| s.visit).collect();
    assert!(visits.contains(&visit_1on1));
    assert!(visits.contains(&visit_group));

    let b_contact = contact_view(&recordings, &b.public_bytes());
    assert_eq!(b_contact.sections.len(), 1);
    assert_eq!(b_contact.sections[0].visit, visit_group);
}

#[test]
fn view_group_page_groups_same_participant_set_and_late_joiner_widens_set() {
    let host = AuthorKey::generate();
    let a = AuthorKey::generate();
    let b = AuthorKey::generate();

    // Two visits with exactly {host, a}: should be two sections of one group.
    let visit1 = visit_id(50);
    let visit2 = visit_id(51);
    let rec1 = build_recording(visit1, &host, &a, 1);
    let rec2 = build_recording(visit2, &host, &a, 1);

    // A third visit where b joins late: participant set is {host, a, b},
    // strictly larger, so it must NOT group with the {host, a} pair.
    let visit3 = visit_id(52);
    let mut rec3 = Recording::new(visit3, host.public_bytes()).expect("open");
    let host_join = signed_bytes(
        base_envelope(visit3, host.public_bytes(), 0, [0u8; 32]),
        &join_body(host.public_bytes(), vec![host.public_bytes()]),
        &host,
    );
    let mut prev = rec3.ingest(&host_join, 0).unwrap();
    let a_join = signed_bytes(
        base_envelope(visit3, host.public_bytes(), 1, *prev.as_bytes()),
        &join_body(a.public_bytes(), vec![a.public_bytes()]),
        &host,
    );
    prev = rec3.ingest(&a_join, 0).unwrap();
    let msg = signed_bytes(
        base_envelope(visit3, host.public_bytes(), 2, *prev.as_bytes()),
        &message_body("before b joins"),
        &host,
    );
    prev = rec3.ingest(&msg, 0).unwrap();
    // b joins late.
    let b_join = signed_bytes(
        base_envelope(visit3, host.public_bytes(), 3, *prev.as_bytes()),
        &join_body(b.public_bytes(), vec![b.public_bytes()]),
        &host,
    );
    rec3.ingest(&b_join, 0).unwrap();

    let recordings = vec![rec1, rec2, rec3];
    let groups = group_views(&recordings);

    let pair_group = groups
        .iter()
        .find(|g| {
            g.participants
                == vec![host.public_bytes(), a.public_bytes()]
                    .into_iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
        })
        .expect("a {host, a} group exists");
    assert_eq!(
        pair_group.sections.len(),
        2,
        "visit1 and visit2 share a participant set and must be two sections of one group"
    );
    let pair_visits: Vec<[u8; 32]> = pair_group.sections.iter().map(|s| s.visit).collect();
    assert!(pair_visits.contains(&visit1));
    assert!(pair_visits.contains(&visit2));
    assert!(
        !pair_visits.contains(&visit3),
        "the late-joiner visit's larger set must not group with the smaller pair"
    );

    let triple_group = groups
        .iter()
        .find(|g| g.sections.iter().any(|s| s.visit == visit3))
        .expect("visit3's own group exists");
    assert_eq!(triple_group.participants.len(), 3);
    assert!(triple_group.participants.contains(&b.public_bytes()));
}
