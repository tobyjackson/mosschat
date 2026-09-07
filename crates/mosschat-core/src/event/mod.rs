//! Signed events with an opaque body (D5).
//!
//! This module currently holds only [`envelope`], the frozen-at-version-1
//! envelope struct. The rest of D5 (body types, `event_id`, ingest checks,
//! computed views) lands in WO-2.4.

pub mod envelope;
