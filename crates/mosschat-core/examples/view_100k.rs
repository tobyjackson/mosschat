//! WO-2.4b's committed 100k-message view benchmark.
//!
//! `cargo run --release --example view_100k`
//!
//! Measures, on a fresh on-disk store:
//!
//! 1. **write**: opening a store and appending 100,000 `message` events to
//!    one visit's recording, one `append_event` call per event (the
//!    ordinary live-ingest write path).
//! 2. **replay**: dropping and reopening the store, then rebuilding the
//!    in-memory [`Recording`](mosschat_core::event::ingest::Recording) from
//!    stored bytes via [`mosschat_core::view::recording_from_store`], which
//!    reads every row through the bulk [`events_for_visit`
//!    ](mosschat_core::store::Store::events_for_visit) statement and
//!    re-ingests each event (re-verifying every signature and every rule).
//! 3. **view compute**: building the visit's
//!    [`VisitSection`](mosschat_core::view::VisitSection) from the replayed
//!    `Recording` via [`visit_section`](mosschat_core::view::visit_section).
//!
//! "The view path" (the plan's 2-second gate) is **replay + view compute**
//! together: that is what a house actually does on a cold-start read of a
//! large visit, since a view is never stored (D5) and is always recomputed
//! from the recording. The write phase is reported separately for context
//! but is not part of the gated number, since it is a one-time ingest cost
//! spread out over the life of a visit, not something a view read repeats.
//!
//! This binary returns `Result` from `main` and uses `?` throughout (no
//! `.expect()`/`.unwrap()`, matching the library's own lint policy, which
//! applies to example binaries as well as `src/`): a setup failure here is
//! reported as a normal process exit with an error message, not a panic.

#![forbid(unsafe_code)]

use std::error::Error;
use std::time::Instant;

use mosschat_core::event::body::{Body, Join, Message};
use mosschat_core::event::envelope::Envelope;
use mosschat_core::event::signed::SignedEvent;
use mosschat_core::identity::AuthorKey;
use mosschat_core::store::{DataKey, KeyFile, Store, StoredEvent};
use mosschat_core::view::{recording_from_store, visit_section};

const N: u64 = 100_000;

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

fn main() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let db_path = dir.path().join("house.sqlite3");
    let key_path = dir.path().join("house.key");
    let key: DataKey = KeyFile::create(&key_path)?;

    let host = AuthorKey::generate();
    let visit = [0x64u8; 32];

    println!("=== view_100k: {N} messages ===");

    // --- write ---------------------------------------------------------
    let write_start = Instant::now();
    {
        let store = Store::open(&db_path, &key)?;
        store.open_visit(&visit, &host.public_bytes(), 1_000)?;

        let join_body = Body::Join(Join {
            person: host.public_bytes(),
            devices: vec![host.public_bytes()],
            name: None,
        });
        let join_bytes = SignedEvent::sign(
            base_envelope(visit, host.public_bytes(), 0, [0u8; 32]),
            &join_body,
            &host,
        )
        .to_bytes();
        let join_signed = SignedEvent::parse(&join_bytes)?;
        store.append_event(
            &visit,
            &StoredEvent {
                seq: 0,
                event_id: *join_signed.event_id.as_bytes(),
                event_bytes: join_bytes,
            },
        )?;

        let mut prev = *join_signed.event_id.as_bytes();
        for i in 0..N {
            let seq = 1 + i;
            let body = Body::Message(Message {
                text: format!("message number {i}, padded a bit for realism xxxxxxxxxx"),
                reply_to: None,
            });
            let bytes = SignedEvent::sign(
                base_envelope(visit, host.public_bytes(), seq, prev),
                &body,
                &host,
            )
            .to_bytes();
            let signed = SignedEvent::parse(&bytes)?;
            store.append_event(
                &visit,
                &StoredEvent {
                    seq,
                    event_id: *signed.event_id.as_bytes(),
                    event_bytes: bytes,
                },
            )?;
            prev = *signed.event_id.as_bytes();
        }
        // `store` drops here, releasing the lock, exactly as a real house
        // restart would close its connection.
    }
    let write_elapsed = write_start.elapsed();

    // --- replay + view compute (the gated path) -------------------------
    let key2 = KeyFile::open(&key_path)?;
    let store2 = Store::open(&db_path, &key2)?;

    let replay_start = Instant::now();
    let recording = recording_from_store(&store2, &visit, &host.public_bytes(), 0)?;
    let replay_elapsed = replay_start.elapsed();

    let view_start = Instant::now();
    let section = visit_section(&recording);
    let view_elapsed = view_start.elapsed();

    let total_view_path = replay_elapsed + view_elapsed;

    if section.entries.len() != (N + 1) as usize {
        return Err(format!("expected {} entries, got {}", N + 1, section.entries.len()).into());
    }

    println!("write (100k append_event calls):   {write_elapsed:?}");
    println!("replay (bulk read + re-ingest):     {replay_elapsed:?}");
    println!("view compute (visit_section):       {view_elapsed:?}");
    println!("TOTAL view path (replay + compute): {total_view_path:?}");
    println!(
        "view path under 2s gate: {}",
        if total_view_path.as_secs_f64() < 2.0 {
            "YES"
        } else {
            "NO"
        }
    );

    Ok(())
}
