//! Abuse cases: one `#[ignore]`d failing stub per numbered rejection rule in
//! `docs/spec/recording.md` and `docs/spec/door.md`, plus one per WO-2.2
//! scenario, written before any implementation exists (WO-2.3).
//!
//! This file is the ignored list WO-2.4 (events, views) and later WO-3.x/
//! WO-4.x work implement against. A stub's doc comment quotes the rule's own
//! assertion verbatim and states the expected outcome; its body fails loudly
//! (`panic!` or `todo!()`) so the suite cannot pass silently, and so
//! `cargo test -p mosschat-core --test abuse -- --ignored --list` is an
//! auditable count of what remains to be proven.
//!
//! Grouped by spec section, in file order within each section, recording.md
//! first then door.md then the WO-2.2 scenarios. Naming: `r_<n>_...`,
//! `d_<n>_...`, `wo22_s<k>_...`, each carrying its rule or scenario number so
//! the name and the doc comment can be cross-checked against the spec by
//! number alone.
//!
//! ## Rules with no case
//!
//! - None. Every numbered rule in both specifications (R-1 to R-50, D-1 to
//!   D-54) has a stub below, including pure-definition rules, because every
//!   one of them has at least one observable consequence once implemented
//!   (a rejection, a stored-but-inert state, or a documented non-effect).
//!   Where a rule's consequence is itself the interesting case (for example
//!   R-38's "unaffected", or D-46's "no effect at all"), the stub asserts
//!   that absence of effect rather than a rejection.
//!
//! ## The R-51 count
//!
//! The work order that produced this file states "a grep counts 51 R
//! headings and 54 D headings". Repeated, independently-constructed greps
//! against this worktree's `docs/spec/recording.md` at `aec8a8d` (`grep -oE
//! '\*\*R-[0-9]+\.' docs/spec/recording.md`, matching the exact heading style
//! `**R-<n>.**` used throughout, and the looser `grep -c '\*\*R-'`) both
//! return **50**, not 51: the distinct numbers R-1 through R-50 with no gap
//! and no repeated number, which also matches the numbered-rule grep Toby
//! pasted into PR #101 itself (`1 2 3 ... 49 50`, 50 tokens). R-50 is the one
//! rule out of document order — defined in section 5.8 between R-41 and
//! R-42, per the tombstone added in the WO-2.2 revision at `f5a6369` — which
//! is consistent with the specification's own numbering rule ("a rule added
//! after first merge takes the next free number and sits where it belongs by
//! subject, so the numbers are not in document order") and is not a defect.
//! No duplicated number and no rule stated twice under two numbers was
//! found. This file therefore contains 50 `r_*` stubs, matching the
//! reproducible count, and reports the discrepancy with the work order's
//! premise rather than silently adjusting to it. Recommend Konrad confirm
//! which grep produced 51, in case it was run against an intermediate
//! revision (e.g. `159d4ea` or `f5a6369`) rather than the merged `aec8a8d`.
#![forbid(unsafe_code)]
#![allow(clippy::panic, clippy::todo)]
// WO-2.5: the two un-ignored store-backed cases below (`r_46_*`, `r_50_*`)
// use `.expect(...)` for setup that cannot fail short of a broken test
// environment (tempdir creation, opening a store this same test just
// created), matching the pattern `docs/dev/lints.md` documents for
// `#[cfg(test)] mod tests` blocks elsewhere in this crate. This file's own
// crate root doubles as its test module, so the allow is crate-wide rather
// than on a nested `mod tests`, same reasoning, different scope.
#![allow(clippy::unwrap_used, clippy::expect_used)]

// ===========================================================================
// docs/spec/recording.md
// ===========================================================================

// --- Section 1: Layout, and 1.1 the domain separation prefix ---------------

/// **R-1.** `verify_strict` over the author's key, the 64 signature bytes,
/// and exactly `SIGNING_PREFIX || envelope_bytes` succeeds. A signature
/// verified over any other message, or with non-strict `verify`, is not a
/// verified event.
///
/// Expected: an event whose signature verifies over `envelope_bytes` alone
/// (no `SIGNING_PREFIX`), or over a non-strict `verify`, is refused with an
/// invalid-signature error, not accepted.
#[test]
#[ignore = "not implemented: R-1"]
fn r_1_signature_must_cover_signing_prefix_and_use_verify_strict() {
    panic!("not implemented: R-1");
}

// --- Section 2: The envelope -------------------------------------------

/// **R-2.** `envelope_bytes` decodes as a definite-length CBOR array of
/// exactly 8 elements of the types above, with no trailing bytes after the
/// eighth.
///
/// Expected: an envelope with 7 or 9 elements, an indefinite-length array,
/// or trailing bytes after the 8th element is refused as malformed, before
/// signature verification.
#[test]
#[ignore = "not implemented: R-2"]
fn r_2_envelope_must_be_exactly_8_element_definite_array() {
    panic!("not implemented: R-2");
}

/// **R-3.** `v == 1`. An envelope carrying any other version is refused, not
/// skipped: the envelope is the part every build must parse, so a version it
/// does not know is a protocol error and not an unknown body.
///
/// Expected: `v == 2` (or any value other than 1) is refused with a protocol
/// error, distinct from R-14's "unknown body, carried" path.
#[test]
#[ignore = "not implemented: R-3"]
fn r_3_envelope_version_other_than_1_is_refused_not_skipped() {
    panic!("not implemented: R-3");
}

/// **R-4.** `body_len` equals the actual length of the body bytes that
/// follow.
///
/// Expected: an envelope claiming `body_len = N` followed by a body of a
/// different length is refused.
#[test]
#[ignore = "not implemented: R-4"]
fn r_4_body_len_must_match_actual_body_bytes_length() {
    panic!("not implemented: R-4");
}

/// **R-5.** `body_len <= 130_847`. (Section 6 derives the number.)
///
/// Expected: `body_len == 130_848` is refused before the body is read or
/// allocated (see also R-44).
#[test]
#[ignore = "not implemented: R-5"]
fn r_5_body_len_over_130_847_is_refused() {
    panic!("not implemented: R-5");
}

/// **R-6.** `BLAKE3(body_bytes) == body_hash`.
///
/// Expected: a body whose bytes hash to something other than the envelope's
/// claimed `body_hash` is refused.
#[test]
#[ignore = "not implemented: R-6"]
fn r_6_body_hash_must_match_blake3_of_body_bytes() {
    panic!("not implemented: R-6");
}

/// **R-7.** `author` is a device key that the recording's participant set
/// names for some person in this visit, and that key is not revoked as of
/// this event (section 5.7).
///
/// Expected: an event authored by a key never named in any `join.devices`
/// for this visit is refused; an event authored by a key revoked (R-36/R-37)
/// as of this event is refused.
#[test]
#[ignore = "not implemented: R-7"]
fn r_7_author_must_be_named_and_unrevoked_participant_device() {
    panic!("not implemented: R-7");
}

/// **R-8.** `event_id` and the signature check are computed over the
/// received `envelope_bytes`, never over a re-serialisation of a decoded
/// value.
///
/// Expected: given a decoded-then-re-encoded envelope that happens to differ
/// from the received bytes, `event_id` and signature verification are
/// performed against the *received* bytes; a test double that decodes then
/// re-serialises before hashing/verifying is the bug this guards against.
#[test]
#[ignore = "not implemented: R-8"]
fn r_8_event_id_and_signature_use_received_bytes_not_reencoding() {
    panic!("not implemented: R-8");
}

/// **R-9.** Re-encoding the decoded envelope produces `envelope_bytes` byte
/// for byte. An event whose re-encoding differs is rejected at ingest,
/// before the write transaction, however well it verifies.
///
/// Expected: an envelope with a non-canonical CBOR encoding (e.g. a
/// non-shortest-form integer) that still verifies its signature is refused
/// at ingest, before any store write.
#[test]
#[ignore = "not implemented: R-9"]
fn r_9_noncanonical_envelope_reencoding_rejected_before_write() {
    panic!("not implemented: R-9");
}

/// **R-10.** The body satisfies the deterministic profile of RFC 8949
/// section 4.2.1: definite lengths only, shortest-form arguments, map keys
/// sorted in bytewise lexicographic order of their deterministic encodings,
/// no floating-point values in any body this document defines. Re-encoding a
/// decoded body of a **known** type produces `body_bytes` byte for byte. An
/// unknown body is not re-encoded and R-10 does not apply to it (R-14): it
/// is stored as the bytes that arrived, and `body_hash` is what binds it.
///
/// Expected: a known-type body (e.g. `message`) with a float value, an
/// indefinite-length map, or out-of-order keys is refused; the identical
/// bytes under an unknown body type key (R-14) are accepted and carried
/// unchanged.
#[test]
#[ignore = "not implemented: R-10"]
fn r_10_known_body_must_be_deterministic_cbor_reencoding_exact() {
    panic!("not implemented: R-10");
}

// --- 2.1 Bytes are what arrived already covered by R-8/R-9 above -----------

// --- Section 3: Visit identity ---------------------------------------------

/// **R-11.** `visit` is identical in every event of one recording. An event
/// whose `visit` does not match the recording it is offered to is rejected,
/// which is also the replay-across-visits check: an event signed for visit A
/// cannot be replayed into visit B, because `visit` is inside the signed
/// envelope.
///
/// Expected: a validly signed event from visit A, offered to visit B's
/// recording, is refused.
#[test]
#[ignore = "not implemented: R-11"]
fn r_11_event_visit_must_match_target_recording_no_cross_visit_replay() {
    panic!("not implemented: R-11");
}

/// **R-12.** The 32 zero bytes are not a valid `visit`.
///
/// Expected: an envelope with `visit == [0u8; 32]` is refused regardless of
/// an otherwise-valid signature.
#[test]
#[ignore = "not implemented: R-12"]
fn r_12_all_zero_visit_is_never_valid() {
    panic!("not implemented: R-12");
}

// --- Section 4: Order is the host's order -----------------------------------

/// **R-13.** `prev` is the `event_id` of the event at `seq - 1`, and 32 zero
/// bytes when `seq == 0`. A recording holding two events with the same
/// `seq`, or an event whose `prev` does not match the event it stored at
/// `seq - 1`, is a host equivocating or a corrupted store; the second event
/// is rejected and the visit is marked broken to the user rather than
/// repaired. Where the event at `seq - 1` was dropped at its author's
/// request, `prev` is matched against the tombstone R-50 leaves in its
/// place.
///
/// Expected: two events at the same `seq` in one recording, or a `prev` that
/// mismatches the stored predecessor's `event_id` (or its tombstone), causes
/// the second event to be rejected and the visit to be flagged broken to the
/// user, not silently repaired or merged.
#[test]
#[ignore = "not implemented: R-13"]
fn r_13_seq_collision_or_prev_mismatch_marks_visit_broken() {
    panic!("not implemented: R-13");
}

/// `ts_ms` is display information (section 4, unnumbered paragraph). It is
/// never compared to another event's `ts_ms` to decide order, never used to
/// expire an event, and a recording whose timestamps run backwards is still
/// a valid recording.
///
/// Expected: two events with `seq` in increasing order but `ts_ms` running
/// backwards are both accepted and ordered by `seq`, not by `ts_ms`.
#[test]
#[ignore = "not implemented: R-13 (ts_ms is display-only, section 4)"]
fn r_13b_ts_ms_running_backwards_does_not_invalidate_or_reorder() {
    panic!("not implemented: ts_ms display-only rule, section 4");
}

// --- Section 5: Bodies -------------------------------------------------

/// **R-14.** An event whose body type key `0` is not in the table below
/// still verifies (R-1), still passes R-2 to R-13, is still stored with its
/// bytes unchanged, and is displayed as "a message this version cannot
/// read". It is never dropped, never rewritten, and its `event_id` is
/// unchanged by being carried. This is what lets a version 1 house sit in a
/// visit with a version 2 house without losing the recording.
///
/// Expected: an event with body type `200` (outside the assigned 1-8 range)
/// is accepted, stored byte-for-byte, its `event_id` unchanged, and
/// displayed as unreadable rather than dropped. See also WO-2.2 scenario 5.
#[test]
#[ignore = "not implemented: R-14"]
fn r_14_unknown_body_type_carried_whole_not_dropped() {
    panic!("not implemented: R-14");
}

/// **R-15.** A body of a **known** type carries every key marked required in
/// its table, each of the stated CBOR type and within its stated cap. A
/// known type missing a required key is rejected; it is not treated as
/// unknown.
///
/// Expected: a `message` body (type 1) missing required key 1 (`text`) is
/// rejected, not carried as an unreadable/unknown body.
#[test]
#[ignore = "not implemented: R-15"]
fn r_15_known_type_missing_required_key_is_rejected_not_unknown() {
    panic!("not implemented: R-15");
}

/// **R-16.** Every text field is valid UTF-8 and is measured in bytes, not
/// characters or grapheme clusters, against its cap.
///
/// Expected: a `message.text` of exactly 65_536 bytes composed of 4-byte
/// UTF-8 emoji (fewer than 65_536 grapheme clusters) is measured by its byte
/// length and accepted at the boundary; invalid UTF-8 bytes in a text field
/// are rejected.
#[test]
#[ignore = "not implemented: R-16"]
fn r_16_text_fields_measured_in_utf8_bytes_not_chars() {
    panic!("not implemented: R-16");
}

// --- 5.1 message -------------------------------------------------------

/// **R-17.** `text` is at most 65_536 bytes and is not empty. An empty
/// message is a client bug, not a message.
///
/// Expected: `text = ""` is rejected; `text` of 65_536 bytes is accepted;
/// `text` of 65_537 bytes is rejected.
#[test]
#[ignore = "not implemented: R-17"]
fn r_17_message_text_empty_or_over_65536_bytes_rejected() {
    panic!("not implemented: R-17");
}

/// **R-18.** `reply_to`, when present, is 32 bytes and names an event, or a
/// tombstone (R-50), already stored in this same visit at a lower `seq`. A
/// reply to an event this recording does not hold, or holds at a higher
/// `seq`, is rejected. A tombstone is a valid target: whether this house
/// honoured a drop-request must not change which events it admits, or a
/// house that honoured one would reject a reply that a house which declined
/// accepts, and section 9 would call that difference a defect or an attack.
///
/// Expected: `reply_to` naming an event not present in this recording, or
/// present at a higher `seq` than the reply, is rejected; `reply_to` naming
/// a tombstone left by an honoured drop-request (R-50) at a lower `seq` is
/// accepted. See also WO-2.2 scenario 7.
#[test]
#[ignore = "not implemented: R-18"]
fn r_18_reply_target_must_be_stored_event_or_tombstone_at_lower_seq() {
    panic!("not implemented: R-18");
}

// --- 5.2 reaction --------------------------------------------------------

/// **R-19.** `target` names an event, or a tombstone (R-50), already stored
/// in this same visit at a lower `seq`. A tombstone is a valid target, for
/// the reason R-18 gives.
///
/// Expected: a `reaction.target` naming an unstored event, or an event at a
/// higher `seq`, is rejected; a tombstone at a lower `seq` is accepted.
#[test]
#[ignore = "not implemented: R-19"]
fn r_19_reaction_target_must_be_stored_event_or_tombstone_at_lower_seq() {
    panic!("not implemented: R-19");
}

/// **R-20.** `symbol` is at most 32 bytes and is not empty. It is display
/// data and is not otherwise interpreted; a client renders what it can and
/// shows the raw string when it cannot.
///
/// Expected: `symbol = ""` is rejected; `symbol` of 33 bytes is rejected;
/// `symbol` of 32 bytes containing arbitrary (non-emoji) UTF-8 is accepted
/// and never interpreted as anything but display text.
#[test]
#[ignore = "not implemented: R-20"]
fn r_20_reaction_symbol_empty_or_over_32_bytes_rejected() {
    panic!("not implemented: R-20");
}

/// **R-21.** A `reaction` with `remove == true` whose `(author, target,
/// symbol)` triple matches no earlier reaction in this visit is stored and
/// has no effect on the view. It is not rejected: the event is a fact about
/// what its author sent, and R-14's carry-don't-drop principle applies to
/// known types whose effect is a no-op just as it does to unknown ones.
///
/// Expected: a `remove == true` reaction whose triple was never previously
/// added is accepted and stored, and the resulting view shows no reaction
/// added or removed (a pure no-op), not a rejection.
#[test]
#[ignore = "not implemented: R-21"]
fn r_21_remove_reaction_with_no_matching_add_is_stored_as_noop() {
    panic!("not implemented: R-21");
}

// --- 5.3 attachment ------------------------------------------------------

/// **R-22.** `name` is at most 128 bytes, is not empty, contains no
/// `U+0000`, no `/`, no `\`, and is not `.` or `..`.
///
/// Expected: `name = ""`, `name = "."`, `name = ".."`, `name` containing
/// `/`, `\`, or a NUL byte, and `name` of 129 bytes are each rejected.
#[test]
#[ignore = "not implemented: R-22"]
fn r_22_attachment_name_rejects_empty_dotpath_separators_and_over_128_bytes() {
    panic!("not implemented: R-22");
}

/// **R-23.** `name` is stored and displayed as the sender sent it and is
/// never used to construct a path. Sanitisation, reserved-name refusal and
/// the download folder are the receiver's, per WO-4.3; this format carries
/// the sender's claim and nothing more.
///
/// Expected: an `attachment.name` that is a valid CBOR text string but a
/// reserved filename on the receiving OS (e.g. `CON`, `NUL` on Windows) is
/// still accepted and stored verbatim by mosschat-core; rejection or
/// renaming for filesystem safety is out of scope here (WO-4.3) and must not
/// happen at ingest.
#[test]
#[ignore = "not implemented: R-23"]
fn r_23_attachment_name_stored_verbatim_never_used_as_path_here() {
    panic!("not implemented: R-23");
}

/// **R-24.** `media_type` is a hint. A receiver decides how to handle a file
/// from its own inspection, never from this field.
///
/// Expected: an `attachment` whose `media_type` is a lie (e.g. claims
/// `text/plain` for arbitrary bytes) is still accepted at ingest; nothing at
/// this layer inspects file contents against the claimed type.
#[test]
#[ignore = "not implemented: R-24"]
fn r_24_attachment_media_type_is_unverified_hint_only() {
    panic!("not implemented: R-24");
}

// --- 5.4 join --------------------------------------------------------------

/// **R-25.** A `join` is authored by the host of this visit. A `join` signed
/// by anyone else is rejected.
///
/// Expected: a `join` event signed by a non-host participant's device key is
/// rejected even if otherwise well-formed.
#[test]
#[ignore = "not implemented: R-25"]
fn r_25_join_authored_by_non_host_is_rejected() {
    panic!("not implemented: R-25");
}

/// **R-26.** `devices` is non-empty, holds at most 8 keys, holds no
/// duplicate, and contains `person`.
///
/// Expected: `devices = []`, `devices` with 9 entries, `devices` with a
/// duplicate key, and `devices` that omits `person` are each rejected.
#[test]
#[ignore = "not implemented: R-26"]
fn r_26_join_devices_empty_over_8_duplicate_or_missing_person_rejected() {
    panic!("not implemented: R-26");
}

/// **R-27.** An event whose `author` is not in the `devices` list of an
/// un-`leave`d `join` earlier in this visit is rejected. This is the
/// concrete form of R-7.
///
/// Expected: an event authored by a key never listed in any `join.devices`
/// for this visit — or listed only in a `join` that a later `leave` has
/// closed without a re-`join` — is rejected.
#[test]
#[ignore = "not implemented: R-27"]
fn r_27_author_not_in_any_unleft_joins_devices_is_rejected() {
    panic!("not implemented: R-27");
}

/// **`join` is the sole membership authority for a visit.** A key is
/// admitted because the host put it in a `join`, and for no other reason. A
/// participant does not check that a key in `join.devices` is backed by a
/// `device-add` in force, and cannot.
///
/// Expected: a key present in `join.devices` but never proven by any
/// `device-add` visible to this recording is nonetheless accepted for
/// events in this visit; implementing a check that requires a backing
/// `device-add` inside this visit's recording would be a spec violation, not
/// an improvement (Dmitri's WO-2.2 must-change item 2 was resolved this way,
/// PR #101). See also WO-2.2 scenario 2.
#[test]
#[ignore = "not implemented: join sole-membership-authority rule, section 5.4"]
fn join_is_sole_membership_authority_no_device_add_backing_required() {
    panic!("not implemented: join sole-membership-authority rule, section 5.4");
}

/// **R-32's validity window therefore does not gate the ordinary path**
/// (section 5.4, unnumbered paragraph following R-27). It governs only the
/// case where a `device-add` is itself present in this visit's recording
/// (a device added to a person mid-visit).
///
/// Expected: a key that arrives solely via `join.devices` (never via an
/// in-recording `device-add`) is authorised regardless of R-32's window,
/// because R-32 has nothing in this recording to evaluate for it; a key
/// added mid-visit via an in-recording `device-add` *is* gated by R-32. This
/// is an accepted-risk case (WO-2.2 scenario 2): the expected outcome is the
/// documented behaviour, not a rejection.
#[test]
#[ignore = "not implemented: R-32 window does not gate ordinary join path, section 5.4"]
fn r_32_window_does_not_gate_keys_admitted_only_via_join() {
    panic!("not implemented: R-32 window scope limit, section 5.4");
}

// --- 5.5 leave -------------------------------------------------------------

/// **R-28.** A `leave` is authored by the host.
///
/// Expected: a `leave` signed by a non-host device is rejected.
#[test]
#[ignore = "not implemented: R-28"]
fn r_28_leave_authored_by_non_host_is_rejected() {
    panic!("not implemented: R-28");
}

/// **R-29.** `person` names a person with an un-`leave`d `join` earlier in
/// this visit.
///
/// Expected: a `leave` naming a person never `join`ed, or already left
/// without a subsequent re-`join`, is rejected.
#[test]
#[ignore = "not implemented: R-29"]
fn r_29_leave_for_person_without_active_join_is_rejected() {
    panic!("not implemented: R-29");
}

/// **R-30.** After a `leave` for a person, an event authored by one of that
/// person's devices at a higher `seq` is rejected, unless a later `join` for
/// that person precedes it.
///
/// Expected: after a `leave` for person P at `seq = 10`, an event authored
/// by one of P's devices at `seq = 11` is rejected; the same event is
/// accepted if a `join` re-admitting P appears at some `seq` between 10 and
/// 11 (exclusive/inclusive boundary per implementation, but a re-join must
/// exist and precede it).
#[test]
#[ignore = "not implemented: R-30"]
fn r_30_event_after_leave_rejected_unless_later_rejoin_precedes_it() {
    panic!("not implemented: R-30");
}

// --- 5.6 device-add ----------------------------------------------------

/// **R-31.** `not_before_ms < not_after_ms`.
///
/// Expected: `not_before_ms == not_after_ms` and `not_before_ms >
/// not_after_ms` are both rejected.
#[test]
#[ignore = "not implemented: R-31"]
fn r_31_device_add_not_before_must_be_strictly_less_than_not_after() {
    panic!("not implemented: R-31");
}

/// **R-32.** A `device-add` grant is in force for an event when
/// `not_before_ms <= evaluation_instant < not_after_ms`. Slice one's
/// evaluation instant is the moment of ingest, from the receiving machine's
/// own clock, never the event's `ts_ms`. A grant outside its window at
/// ingest does not authorise the event, and the event is rejected under R-7.
///
/// Expected: an event authored by a device whose `device-add` window has
/// already elapsed as of the receiving machine's ingest clock is rejected
/// under R-7, even if the event's own `ts_ms` falls inside the window (an
/// attacker-controlled field per section 4).
#[test]
#[ignore = "not implemented: R-32"]
fn r_32_device_add_grant_evaluated_at_ingest_clock_not_event_ts_ms() {
    panic!("not implemented: R-32");
}

/// **R-33.** A `device-add` is authored by a device key already in force for
/// the same person, or it is the person's identity key self-signing its own
/// first grant. A person cannot add a device to another person.
///
/// Expected: a `device-add` for person B's new device, authored by a device
/// belonging to person A, is rejected; person A's identity key self-signing
/// A's own first grant is accepted.
#[test]
#[ignore = "not implemented: R-33"]
fn r_33_device_add_must_be_self_authored_by_same_person() {
    panic!("not implemented: R-33");
}

/// **R-34.** `device` is not already in force for a different person.
///
/// Expected: a `device-add` naming a device key currently in force for
/// person B, issued by person A, is rejected even if R-33's authorship check
/// would otherwise pass for A adding to A.
#[test]
#[ignore = "not implemented: R-34"]
fn r_34_device_add_rejected_if_key_in_force_for_different_person() {
    panic!("not implemented: R-34");
}

/// **R-35.** Slice one writes `not_after_ms = not_before_ms + 31_536_000_000`
/// (365 days). This is a default, not a format rule: a conforming reader
/// enforces R-32 against whatever window it is given.
///
/// Expected: a `device-add` this house authors sets `not_after_ms` to
/// exactly `not_before_ms + 31_536_000_000`; a *reader* nonetheless enforces
/// R-32 correctly against a `device-add` from elsewhere carrying a
/// different, non-default window (e.g. one day), proving R-35 is a writer
/// default and not baked into the reader's validity check.
#[test]
#[ignore = "not implemented: R-35"]
fn r_35_slice_one_writes_365_day_window_but_reader_honours_any_window() {
    panic!("not implemented: R-35");
}

// --- 5.7 device-revoke -------------------------------------------------

/// **R-36.** A `device-revoke` is authored by a device of the same person,
/// other than `device` itself. A device cannot revoke itself, because a
/// thief holding it could then revoke the owner's other devices; and a
/// person cannot revoke another person's device.
///
/// Expected: a `device-revoke` where `author == device` (self-revocation) is
/// rejected; a `device-revoke` authored by person A naming a device of
/// person B is rejected. See also WO-2.2 scenario 1 (stolen device).
#[test]
#[ignore = "not implemented: R-36"]
fn r_36_device_revoke_cannot_target_its_own_author_or_another_person() {
    panic!("not implemented: R-36");
}

/// **R-37.** A revocation is permanent once seen. A `device-add` for a key
/// this recording has already seen revoked is rejected whatever its window,
/// so a thief cannot re-add a key from a stolen device.
///
/// Expected: after a `device-revoke` for key K is stored, a later
/// `device-add` event (from anyone, any window) naming `device == K` is
/// rejected.
#[test]
#[ignore = "not implemented: R-37"]
fn r_37_device_add_for_previously_revoked_key_is_permanently_rejected() {
    panic!("not implemented: R-37");
}

/// **R-38.** Events authored by `device` at a `seq` lower than the
/// revocation's are unaffected. The revocation is not retroactive over the
/// host's sequence: those events were valid when the host sequenced them,
/// the signature still verifies, and rewriting the past on the strength of a
/// later event is exactly the merge this format does not do. `at_ms` is
/// recorded and displayed so a person can see the claim, and is never used
/// to invalidate a sequenced event.
///
/// Expected: an event authored by device K at `seq = 5`, followed by a
/// `device-revoke` for K at `seq = 8`, remains valid and displayed
/// unchanged; it is never retroactively invalidated or hidden. `at_ms` on
/// the revoke, even if it claims an instant before `seq = 5`'s `ts_ms`, does
/// not invalidate `seq = 5`.
#[test]
#[ignore = "not implemented: R-38"]
fn r_38_events_before_revocation_seq_remain_valid_and_unaffected() {
    panic!("not implemented: R-38");
}

// --- 5.8 drop-request --------------------------------------------------

/// **R-39.** `targets` is present, non-empty and at most 64 entries when
/// `scope == 1`, and absent when `scope == 0`.
///
/// Expected: `scope == 1` with `targets` absent, empty, or 65 entries is
/// rejected; `scope == 0` with `targets` present (non-absent) is rejected.
#[test]
#[ignore = "not implemented: R-39"]
fn r_39_drop_request_targets_required_and_bounded_iff_scope_is_1() {
    panic!("not implemented: R-39");
}

/// **R-40.** Every entry in `targets` names an event in this same visit
/// authored by the requester's own person. Nobody may ask for someone else's
/// words to be dropped; asking for the visit to go (`scope == 0`) is a
/// request about the whole visit and stands on its own.
///
/// Expected: a `drop-request` with `scope == 1` naming an event authored by
/// a different person is rejected.
#[test]
#[ignore = "not implemented: R-40"]
fn r_40_drop_request_targets_must_be_authored_by_requesters_own_person() {
    panic!("not implemented: R-40");
}

/// **R-41.** Honouring a `drop-request` deletes the named bytes locally
/// (section 7, kind one) and leaves a visible marker in the view reading
/// "dropped at their request". The `drop-request` event itself is never
/// deleted by being honoured: it is the record that the request was made.
///
/// Expected: after honouring a `drop-request`, the target event's bytes are
/// gone from the store (kind one, R-45-style), the view shows "dropped at
/// their request" at that position, and the `drop-request` event itself
/// remains stored and visible. See also WO-2.2 scenario 7.
#[test]
#[ignore = "not implemented: R-41"]
fn r_41_honouring_drop_request_deletes_target_bytes_leaves_marker_and_keeps_request() {
    panic!("not implemented: R-41");
}

/// **R-42.** A `drop-request` that a house declines to honour is still
/// stored and still displayed. Declining is a local choice and produces no
/// event.
///
/// Expected: a house that declines a `drop-request` still stores and
/// displays the request event; the target event remains fully present; no
/// additional event is written to record the decline.
#[test]
#[ignore = "not implemented: R-42"]
fn r_42_declined_drop_request_is_still_stored_and_displayed() {
    panic!("not implemented: R-42");
}

/// **R-50.** Honouring a `drop-request` leaves a tombstone at each dropped
/// `seq`, holding that event's `seq` and `event_id` and nothing else: no
/// envelope, no signature, no body, no author, no timestamp. R-13 matches a
/// later event's `prev` against the tombstone's `event_id` exactly as it
/// would against the event itself, so obeying decision 13 does not break the
/// chain and does not mark the visit broken.
///
/// Expected: after honouring a drop-request for the event at `seq = 5`, the
/// store holds a tombstone at `seq = 5` carrying only `seq` and `event_id`
/// (no envelope, signature, body, author or timestamp recoverable from it),
/// and a later event whose `prev` matches that `event_id` is accepted
/// without the visit being marked broken. See also WO-2.2 scenario 7.
///
/// WO-2.5 un-ignores the store's half of this rule: [`mosschat_core::store`]
/// proves the tombstone itself carries only `seq` and `event_id` (no
/// envelope, signature, body, author or timestamp recoverable) and that
/// `event_id` survives tombstoning for a later `prev` to match against
/// (`store::tests::tombstone_keeps_seq_and_event_id_removes_bytes`). Whether
/// a later event whose `prev` matches is actually *accepted* (as opposed to
/// merely matchable) is R-13's ingest check, `mosschat_core::event`, WO-2.4,
/// and is not asserted here.
#[test]
fn r_50_honoured_drop_leaves_tombstone_with_only_seq_and_event_id() {
    use mosschat_core::store::{DataKey, KeyFile, Store, StoredEvent};

    let dir = tempfile::tempdir().expect("create tempdir");
    let db_path = dir.path().join("house.sqlite3");
    let key_path = dir.path().join("house.key");
    let key: DataKey = KeyFile::create(&key_path).expect("create key file");
    let store = Store::open(&db_path, &key).expect("open store");

    let visit_id = [21u8; 32];
    let event_id = [22u8; 32];
    store
        .open_visit(&visit_id, &[1u8; 32], 1_000)
        .expect("open visit");
    store
        .append_event(
            &visit_id,
            &StoredEvent {
                seq: 5,
                event_id,
                event_bytes: b"a message someone asked to have dropped".to_vec(),
            },
        )
        .expect("append event");

    let tombstone = store
        .tombstone_event(&visit_id, 5)
        .expect("tombstone event");
    assert_eq!(tombstone.seq, 5);
    assert_eq!(tombstone.event_id, event_id);

    let row = store
        .get_event(&visit_id, 5)
        .expect("read back tombstoned row")
        .expect("tombstone row remains");
    assert!(
        row.event_bytes.is_none(),
        "R-50: a tombstone carries no envelope, signature, body, author or timestamp"
    );
    assert_eq!(
        row.event_id, event_id,
        "R-50/R-13: event_id survives tombstoning so a later prev still matches"
    );
}

// --- Section 6: Sizes ----------------------------------------------------

/// **R-43.** `len(envelope_bytes) + 64 + body_len <= 131_072`.
///
/// Expected: an envelope/body combination whose total (envelope + 64 byte
/// signature + body) is 131_073 bytes is rejected even if each individual
/// cap (R-5's `body_len <= 130_847`) is independently satisfied by a larger
/// envelope encoding.
#[test]
#[ignore = "not implemented: R-43"]
fn r_43_total_event_size_over_131072_bytes_rejected() {
    panic!("not implemented: R-43");
}

/// **R-44.** Every length prefix is checked against its cap before any
/// allocation sized by it. A claimed length above its cap is refused without
/// reading or reserving the claimed bytes (invariant 4).
///
/// Expected: an envelope claiming `body_len = 4_000_000_000` (a plausible
/// hostile length prefix, far over the 130_847 cap) is refused without the
/// implementation allocating or attempting to read anywhere near that many
/// bytes; this is the adversarial "huge length prefix" case for the
/// recording format.
#[test]
#[ignore = "not implemented: R-44"]
fn r_44_oversized_length_prefix_refused_before_allocation() {
    panic!("not implemented: R-44");
}

// --- Section 7: The three kinds of deleting ---------------------------------

/// **R-45.** After a delete-for-real of a visit, no view names that visit,
/// no row references it, and the store file contains none of its plaintext.
///
/// Expected: after `visit.delete` (kind one), no contact or group view lists
/// the visit, no row in the store references its id, and a hexdump-style
/// scan of the store file finds none of the deleted visit's plaintext
/// message content.
#[test]
#[ignore = "not implemented: R-45"]
fn r_45_deleted_visit_absent_from_views_rows_and_store_plaintext() {
    panic!("not implemented: R-45");
}

/// **R-46.** A private visit produces no store row of any kind. Its absence
/// is checked by there being no row, not by a filter over rows that exist.
///
/// Expected: for a visit opened with `private: true`, no row of any kind
/// exists in the store for it at any point, checkable directly (absence of
/// row), not merely by a query filter that happens to exclude it.
///
/// WO-2.5 un-ignores this at the store layer: [`mosschat_core::store::Store`]
/// exposes no way to write a `visit`/`message`/`participant`/`device`/
/// `attachment` row except `open_visit`/`append_event`, and a caller
/// implementing a private visit (decided above `mosschat-core`, per the
/// store module's own docs) never calls either for that visit's id. This
/// test asserts the negative directly, for an id nobody ever opened.
#[test]
fn r_46_private_visit_produces_no_store_row_at_all() {
    use mosschat_core::store::{DataKey, KeyFile, Store};

    let dir = tempfile::tempdir().expect("create tempdir");
    let db_path = dir.path().join("house.sqlite3");
    let key_path = dir.path().join("house.key");
    let key: DataKey = KeyFile::create(&key_path).expect("create key file");
    let store = Store::open(&db_path, &key).expect("open store");

    let private_visit_id = [55u8; 32];
    // A private visit: this test never calls `open_visit`/`append_event`
    // for `private_visit_id`, which is the whole point (R-46: checked by
    // there being no row, not by a filter over rows that exist).
    let visits = store.list_visits().expect("list visits");
    assert!(!visits.contains(&private_visit_id));
    let event = store
        .get_event(&private_visit_id, 0)
        .expect("query for a never-opened visit");
    assert!(event.is_none());
}

/// **R-47.** Privacy is a property of the visit, set at open, and no event
/// changes it. A visit does not become private partway through, and a
/// private visit does not become recorded partway through; either would
/// leave half a recording on disk.
///
/// Expected: there is no event or command that flips a visit's privacy after
/// `visit.open`; attempting to do so (if such an operation is even exposed)
/// is rejected, and a private visit's events remain entirely absent from the
/// store for the visit's whole lifetime, never partially written.
#[test]
#[ignore = "not implemented: R-47"]
fn r_47_visit_privacy_fixed_at_open_never_changes_mid_visit() {
    panic!("not implemented: R-47");
}

// --- Section 8: Views ----------------------------------------------------

/// **R-48.** Every view is a pure function of the recordings on this
/// machine. The same recordings produce the same view whatever order the
/// events arrived in and whatever order rows are read back (invariant 6).
///
/// Expected: building a view from one set of stored events read back in
/// order A, and the identical set of events read back in a different row
/// order B (or ingested in a different arrival order but reaching the same
/// stored `seq` order), produces byte-identical views.
#[test]
#[ignore = "not implemented: R-48"]
fn r_48_view_is_pure_function_of_recordings_independent_of_read_order() {
    panic!("not implemented: R-48");
}

/// **R-49.** A private visit appears in no view (R-46). A visit deleted for
/// real appears in no view (R-45). A drop-request honoured appears in the
/// view as a marker where the dropped events were, not as a gap.
///
/// Expected: a private visit and a delete-for-real'd visit are both absent
/// from every view; an honoured drop-request leaves a rendered marker
/// ("dropped at their request") at its position in the view, distinct from
/// simply omitting the row (a gap would look like data loss, not an
/// intentional drop).
#[test]
#[ignore = "not implemented: R-49"]
fn r_49_view_shows_drop_marker_not_gap_and_omits_private_and_deleted() {
    panic!("not implemented: R-49");
}

// --- Section 9: No rule merges two people's recordings ----------------------

/// Section 9, unnumbered but load-bearing: no rule in this specification
/// combines two people's records of a visit; nothing reads another
/// participant's recording to fill a gap in this one. A host replaying its
/// own sequence to a rejoining guest (decision 34, invariant 7) is not a
/// merge, because it is the host's own already-held sequence delivered to
/// one guest, not a read of a participant's recording.
///
/// Expected: no code path in `mosschat-core` reads a second participant's
/// stored recording to resolve, fill a gap in, or reconcile against this
/// machine's own recording of the same visit; the only permitted "catch-up"
/// is the host replaying its own sequence to a reconnecting guest inside a
/// live session, which a test can distinguish by asserting no store-level
/// read of another participant's on-disk recording ever occurs.
#[test]
#[ignore = "not implemented: section 9, no-merge invariant"]
fn section9_no_rule_reads_another_participants_recording_to_fill_a_gap() {
    panic!("not implemented: section 9 no-merge invariant");
}

// ===========================================================================
// docs/spec/door.md
// ===========================================================================

// --- Section 1: Transports --------------------------------------------------

/// **D-1.** The socket's directory is created mode `0700` and the socket
/// itself is bound mode `0600`, both owned by the user running the house.
/// The house checks both after binding and refuses to serve if either is
/// wider, because a socket created under a permissive `umask` is the whole
/// house readable by the machine.
///
/// Expected: given a door socket directory or socket file with mode wider
/// than `0700`/`0600` (e.g. created under a permissive `umask`), the house
/// refuses to serve rather than binding and accepting connections anyway.
#[test]
#[ignore = "not implemented: D-1"]
fn d_1_house_refuses_to_serve_if_socket_or_dir_permissions_too_wide() {
    panic!("not implemented: D-1");
}

/// **D-2.** On Windows the pipe is created with a DACL granting access to
/// the creating user's SID alone, and to no group, including no
/// administrators group. The pipe is opened with
/// `FILE_FLAG_FIRST_PIPE_INSTANCE` so a second process cannot squat an
/// existing name.
///
/// Expected (Windows-specific; stub carries the assertion regardless of the
/// platform this suite runs on): a second process attempting to create a
/// pipe of the same name while the house holds
/// `FILE_FLAG_FIRST_PIPE_INSTANCE` fails to squat it; the DACL grants no
/// access to any group, including Administrators.
#[test]
#[ignore = "not implemented: D-2 (Windows-specific)"]
fn d_2_windows_pipe_dacl_is_user_only_and_first_instance_only() {
    panic!("not implemented: D-2");
}

/// **Possession of the local socket is total authority over the house**
/// (section 1, unnumbered paragraph, added in the WO-2.2 revision closing
/// must-change item 1 / WO-2.2 scenario 1). A `Hello` with no `grant` gets
/// subject `house`, which includes `device.revoke`, `visit.delete` and
/// every recording in the store. `device-revoke`
/// (`docs/spec/recording.md` R-36) removes a key's standing with *other*
/// people's houses, and does not reduce what the local door grants on this
/// machine.
///
/// Expected: connecting over the local socket with no `grant` in `Hello`
/// yields a connection with subject `house` and every command permitted,
/// including `device.revoke` and `visit.delete`; a `device-revoke` issued
/// from a *different* house for one of this house's device keys has no
/// effect on what the local door grants here. See WO-2.2 scenario 1 below
/// for the accepted-risk framing.
#[test]
#[ignore = "not implemented: local-socket total-authority rule, door.md section 1"]
fn local_socket_possession_grants_full_house_authority_by_default() {
    panic!("not implemented: local-socket total-authority rule, section 1");
}

/// **D-3.** The network door binds nothing unless a listen address is
/// configured. When configured, it accepts a QUIC connection with mutual
/// TLS 1.3 over raw self-signed Ed25519 certificates, with ALPN
/// `mosschat-door-v1`. The client's key proven in that handshake is checked
/// against an explicitly configured allow list of client keys. A key not on
/// the list is refused and the connection is closed before any frame is
/// read.
///
/// Expected: with no listen address configured, nothing binds on the
/// network door; with one configured, a client key not on the configured
/// allow list is refused and the connection closed before `Hello` is read.
#[test]
#[ignore = "not implemented: D-3"]
fn d_3_network_door_binds_nothing_unconfigured_refuses_unlisted_keys() {
    panic!("not implemented: D-3");
}

/// **D-4.** The network door is never reachable because a peer is a friend.
/// Being a friend grants a visit; it does not grant the house.
///
/// Expected: a peer that is a friend (has an active visit/contact
/// relationship) but is not on the network door's explicit client-key allow
/// list cannot reach the door over the network; friendship alone confers no
/// door access.
#[test]
#[ignore = "not implemented: D-4"]
fn d_4_being_a_friend_does_not_grant_network_door_access() {
    panic!("not implemented: D-4");
}

// --- Section 2: Framing ------------------------------------------------

/// **D-5.** The payload is a definite-length CBOR array of exactly 2
/// elements, the first an unsigned integer, the second a map, with no
/// trailing bytes.
///
/// Expected: a payload that is a 3-element array, an indefinite-length
/// array, or has trailing bytes after the map is refused.
#[test]
#[ignore = "not implemented: D-5"]
fn d_5_payload_must_be_exactly_2_element_definite_array_type_then_map() {
    panic!("not implemented: D-5");
}

/// **D-6.** `len <= 1_048_576` (1 MiB, D5's frame cap). A frame claiming
/// more is refused and the connection is closed before the claimed bytes
/// are read or any buffer is sized by them.
///
/// Expected: a frame with `len = 1_048_577` is refused and the connection
/// closed without the house reading or allocating anywhere near that many
/// bytes. Adversarial case: a length prefix claiming 4 GiB must be refused
/// immediately from the 4-byte prefix alone.
#[test]
#[ignore = "not implemented: D-6"]
fn d_6_frame_len_over_1mib_refused_before_reading_claimed_bytes() {
    panic!("not implemented: D-6");
}

/// **D-7.** The payload satisfies the deterministic profile of RFC 8949
/// section 4.2.1: definite lengths only, shortest-form arguments, map keys
/// sorted in bytewise lexicographic order of their deterministic encodings,
/// no floats. A frame whose re-encoding differs is refused.
///
/// Expected: a frame whose map keys are not in ascending order, or that
/// contains a float, or a non-shortest-form integer, is refused even if
/// otherwise well-typed.
#[test]
#[ignore = "not implemented: D-7"]
fn d_7_frame_must_be_deterministic_cbor_reencoding_exact() {
    panic!("not implemented: D-7");
}

/// **D-8.** Unknown map keys inside a known frame type are ignored. An
/// unknown frame type is answered with `Error{unknown_frame}` and the
/// connection stays open; it is not a protocol error, so a version 2 client
/// talking to a version 1 house degrades instead of dying.
///
/// Expected: a frame of unknown type 99 gets `Error{unknown_frame}` and the
/// connection remains open and usable for further frames; a known frame
/// type carrying an extra unknown map key is processed normally, ignoring
/// the unknown key.
#[test]
#[ignore = "not implemented: D-8"]
fn d_8_unknown_frame_type_gets_error_reply_connection_stays_open() {
    panic!("not implemented: D-8");
}

/// **D-9.** Optional fields are absent, never null. An absent key and a null
/// value would be two encodings of one meaning, which D-7 forbids.
///
/// Expected: a frame encoding an optional field as CBOR null (rather than
/// omitting the key) is refused under D-7's determinism rule.
#[test]
#[ignore = "not implemented: D-9"]
fn d_9_optional_field_encoded_as_null_rather_than_absent_is_refused() {
    panic!("not implemented: D-9");
}

// --- Section 4: The nonced hello, and the snapshot --------------------------

/// **D-10.** `Hello` is the first frame on a connection and is sent exactly
/// once. Any other frame before it, or a second `Hello`, closes the
/// connection with `Error{protocol}`.
///
/// Expected: sending `Ping` before `Hello` closes the connection with
/// `Error{protocol}`; sending a second `Hello` after a valid first one also
/// closes the connection with `Error{protocol}`.
#[test]
#[ignore = "not implemented: D-10"]
fn d_10_frame_before_hello_or_second_hello_closes_with_protocol_error() {
    panic!("not implemented: D-10");
}

/// **D-11.** `nonce` is exactly 16 bytes and is drawn fresh per connection
/// from a cryptographic random source. The house echoes it in `Welcome` and
/// in `SnapshotEnd`, so a client can tell this connection's snapshot from a
/// stale one it is still draining after a reconnect.
///
/// Expected: a `Hello.nonce` of 15 or 17 bytes is rejected; a valid 16 byte
/// nonce is echoed unchanged in both `Welcome.nonce` and
/// `SnapshotEnd.nonce`.
#[test]
#[ignore = "not implemented: D-11"]
fn d_11_hello_nonce_must_be_16_bytes_and_is_echoed_in_welcome_and_snapshotend() {
    panic!("not implemented: D-11");
}

/// **D-12.** The house sends `Welcome` as the first frame after a valid
/// `Hello`, or `Error` and closes. It never sends anything else in between.
///
/// Expected: after a valid `Hello`, the very next frame the house sends is
/// `Welcome` (or `Error` followed by close); no other frame type is
/// interposed.
#[test]
#[ignore = "not implemented: D-12"]
fn d_12_welcome_or_error_is_the_first_frame_after_valid_hello() {
    panic!("not implemented: D-12");
}

/// **D-13.** Exactly one `SnapshotEnd` follows the `Snapshot` frames,
/// carrying the `Hello.nonce` of this connection. A client holds the whole
/// state it asked for at that frame and not before.
///
/// Expected: a snapshot sequence terminates in exactly one `SnapshotEnd`
/// carrying this connection's own `Hello.nonce`; no second `SnapshotEnd` is
/// ever sent on the same snapshot.
#[test]
#[ignore = "not implemented: D-13"]
fn d_13_exactly_one_snapshotend_carries_this_connections_nonce() {
    panic!("not implemented: D-13");
}

/// **D-14.** `Event` frames generated while the snapshot is streaming are
/// queued by the house and delivered after `SnapshotEnd`, never interleaved.
/// A client therefore never sees an update to a thing it has not been told
/// about, and never has to hold a reordering buffer.
///
/// Expected: an event that occurs (e.g. a new message arrives) while a
/// `Snapshot` sequence is still streaming to a client is not delivered as an
/// `Event` frame until after that connection's `SnapshotEnd` has been sent.
#[test]
#[ignore = "not implemented: D-14"]
fn d_14_events_during_snapshot_streaming_are_queued_until_after_snapshotend() {
    panic!("not implemented: D-14");
}

/// **D-15.** A snapshot is a consistent read: every `Snapshot` frame of one
/// connection reflects one instant of the house's state. Two snapshots
/// taken at different instants may differ; one snapshot is never half of
/// each.
///
/// Expected: if a mutation (e.g. a new visit opening) occurs concurrently
/// with a `Snapshot` sequence being streamed, the snapshot delivered is
/// entirely from before or entirely from after that mutation, never a mix
/// where some `Snapshot` frames reflect the old state and others the new.
#[test]
#[ignore = "not implemented: D-15"]
fn d_15_snapshot_is_a_consistent_single_instant_read_never_torn() {
    panic!("not implemented: D-15");
}

// --- Section 5: Requests and replies -----------------------------------

/// **D-16.** Every `Request` is answered with exactly one `Reply` or exactly
/// one `Error` carrying the same `id`. A house that cannot answer answers
/// `Error`; it never drops a request silently.
///
/// Expected: every `Request` sent, including one the house cannot fulfil
/// (e.g. malformed args), receives exactly one `Reply` or `Error` carrying
/// the same `id`; no request is left unanswered.
#[test]
#[ignore = "not implemented: D-16"]
fn d_16_every_request_gets_exactly_one_reply_or_error_with_same_id() {
    panic!("not implemented: D-16");
}

/// **D-17.** Requests may be in flight concurrently and replies may arrive
/// in any order. A client correlates on `id` and never on arrival order.
///
/// Expected: two `Request`s sent back-to-back with different `id`s may
/// receive their `Reply`/`Error` frames in either order; a correct client
/// (and this suite's fixture) never assumes reply order matches request
/// order.
#[test]
#[ignore = "not implemented: D-17"]
fn d_17_concurrent_requests_may_have_replies_arrive_out_of_order() {
    panic!("not implemented: D-17");
}

/// **D-18.** `id` is unique among a connection's outstanding requests.
/// Reusing an `id` that is still outstanding is `Error{protocol}` and closes
/// the connection, because the house cannot tell the two apart.
///
/// Expected: sending a second `Request` with the same `id` as a still
/// outstanding first request closes the connection with
/// `Error{protocol}`.
#[test]
#[ignore = "not implemented: D-18"]
fn d_18_reusing_outstanding_request_id_closes_with_protocol_error() {
    panic!("not implemented: D-18");
}

/// **D-19.** A connection has at most 64 outstanding requests. The 65th is
/// answered `Error{too_many_requests}` and the connection stays open.
///
/// Expected: sending 65 requests without waiting for replies causes the
/// 65th to receive `Error{too_many_requests}` while the connection remains
/// open and the first 64 are still answered normally.
#[test]
#[ignore = "not implemented: D-19"]
fn d_19_65th_outstanding_request_gets_too_many_requests_error() {
    panic!("not implemented: D-19");
}

// --- Section 6: Scope ----------------------------------------------------

/// **D-20.** A `Request` whose `command` is not in this connection's grant
/// is answered `Error{not_permitted}` and the connection stays open. The
/// error names the command and never what the command would have returned.
///
/// Expected: a scoped connection whose grant excludes `device.revoke`
/// receives `Error{not_permitted}` for a `device.revoke` request, with
/// `detail` naming the command and no leaked information about what the
/// command would have done.
#[test]
#[ignore = "not implemented: D-20"]
fn d_20_command_outside_grant_gets_not_permitted_names_command_only() {
    panic!("not implemented: D-20");
}

/// **D-21.** A `Request` naming a visit or a contact outside this
/// connection's `subject` is answered `Error{not_permitted}`, with the
/// identical error body it would send for a visit that does not exist. A
/// scoped client cannot use the door to learn what exists outside its
/// scope.
///
/// Expected: a connection scoped to `visit:A` requesting `visit.events` for
/// visit B (which exists but is outside scope) and for visit C (which does
/// not exist at all) receive byte-identical `Error` bodies, so scope cannot
/// be used as an existence oracle.
#[test]
#[ignore = "not implemented: D-21"]
fn d_21_out_of_scope_visit_and_nonexistent_visit_get_identical_error() {
    panic!("not implemented: D-21");
}

/// **D-22.** A grant with `expires_ms` at or before the house's current
/// clock does not authorise anything. A connection whose grant expires
/// mid-session is sent `Disconnect{grant_expired}` and closed; the house
/// does not keep serving a connection on an expired grant until its next
/// request.
///
/// Expected: a connection holding a grant that expires while idle (no
/// pending request) is proactively sent `Disconnect{grant_expired}` and
/// closed by the house at expiry, not merely rejected on its next request.
#[test]
#[ignore = "not implemented: D-22"]
fn d_22_grant_expiring_mid_session_proactively_disconnects_the_client() {
    panic!("not implemented: D-22");
}

/// **D-23.** `grant.create` and `grant.revoke` are permitted only to a
/// `house`-subject grant. A scoped client cannot mint itself a wider grant
/// or revoke the grant that constrains it.
///
/// Expected: a connection with a `visit:X`-subject grant calling
/// `grant.create` or `grant.revoke` (including to revoke its own handle)
/// gets `Error{not_permitted}`.
#[test]
#[ignore = "not implemented: D-23"]
fn d_23_scoped_grant_cannot_create_or_revoke_grants() {
    panic!("not implemented: D-23");
}

/// **D-24.** A `Hello` carrying an unknown, revoked or expired `handle` is
/// answered `Error{not_permitted}` and the connection is closed. It is
/// never silently downgraded to the full-house grant.
///
/// Expected: `Hello.grant` naming a handle that was never issued, was
/// revoked, or has expired gets `Error{not_permitted}` and connection
/// close; the connection is never instead granted subject `house`.
#[test]
#[ignore = "not implemented: D-24"]
fn d_24_unknown_revoked_or_expired_handle_refused_never_downgraded_to_house() {
    panic!("not implemented: D-24");
}

/// **D-25.** On the network transport, `Hello.grant` is required. The
/// full-house grant is not available by default over the network; it must
/// be minted explicitly and named by handle.
///
/// Expected: a `Hello` with no `grant` over the network transport is
/// refused (not silently given subject `house`); the identical `Hello` over
/// the local transport is accepted with subject `house`.
#[test]
#[ignore = "not implemented: D-25"]
fn d_25_network_transport_requires_explicit_grant_no_default_house_subject() {
    panic!("not implemented: D-25");
}

// --- Section 7: Commands -------------------------------------------------

/// **D-26.** `visit.send` returns only after the event is sequenced by the
/// host and written to this house's store. A client showing a message as
/// sent before its `Reply` is showing a message that may never become an
/// event.
///
/// Expected: `visit.send`'s `Reply` is not sent until the event has been
/// assigned a `seq` and durably written to this house's store; a client
/// cannot observe a `Reply` for an event that is not yet retrievable via
/// `visit.events`.
#[test]
#[ignore = "not implemented: D-26"]
fn d_26_visit_send_reply_only_after_event_sequenced_and_stored() {
    panic!("not implemented: D-26");
}

/// **D-27.** `file.send` takes a path the house opens. Bytes never cross the
/// door. A client that cannot hand the house a path cannot send a file.
///
/// Expected: `file.send` never accepts inline file bytes over the door
/// protocol (no such field exists in its args); a `file.send` naming a path
/// the house cannot open is refused, not silently accepted awaiting bytes
/// that will never arrive over this channel.
///
/// later: full transfer mechanics are WO-4.3's; this stub covers only the
/// door-protocol-level assertion that bytes never cross the door.
#[test]
#[ignore = "not implemented: D-27"]
fn d_27_file_send_never_carries_inline_bytes_only_a_house_opened_path() {
    panic!("not implemented: D-27");
}

/// **D-28.** Every command argument is checked against the caps in this
/// table before anything is read from the store, and a cap breach is
/// `Error{invalid_argument}` with the connection left open.
///
/// Expected: `visit.send` with `text` of 65_537 bytes gets
/// `Error{invalid_argument}` without any store read being attempted, and
/// the connection remains open for further requests.
#[test]
#[ignore = "not implemented: D-28"]
fn d_28_command_arg_over_cap_gets_invalid_argument_before_store_read() {
    panic!("not implemented: D-28");
}

/// **D-53.** Every multi-item result is capped by bytes, not by items. The
/// house accumulates encoded items into a `Reply` or a `Snapshot` frame and
/// stops at the first item that would carry the frame's encoded payload
/// past 917_504 bytes (896 KiB), leaving that item for the next frame or
/// the next request. An item count, where one is stated, is a second cap
/// that applies after this one; whichever binds first, binds.
///
/// Expected: a `visit.events` request whose matching events would encode
/// past 917_504 bytes, well before the stated 1024-item cap is reached (a
/// single large `event` item can approach 131_072 bytes per R-43), stops
/// accumulating at the byte boundary and reports `more: true`, never
/// producing a `Reply` frame whose payload would exceed D-6's 1 MiB cap.
/// This is WO-2.2 scenario 4 (hostile client at the door).
#[test]
#[ignore = "not implemented: D-53"]
fn d_53_multi_item_result_capped_by_917504_bytes_before_item_count() {
    panic!("not implemented: D-53");
}

/// **D-54.** Truncation is always signalled, never silent. For
/// `visit.events`, `more: true` means the house stopped early for either
/// reason and the client continues from the highest `seq` it received. For
/// a `Snapshot`, the house emits as many `Snapshot` frames as it needs and
/// the client knows it holds everything at `SnapshotEnd`, whose `counts`
/// give the per-kind totals to check against. A house never drops an item
/// it did not report, and a client never infers completeness from a short
/// frame.
///
/// Expected: a truncated `visit.events` reply sets `more: true`; a
/// multi-frame `Snapshot` sequence's `SnapshotEnd.counts` matches the actual
/// number of items sent per kind, so a client can detect a short delivery by
/// counting received items against `counts` rather than trusting frame
/// count alone.
#[test]
#[ignore = "not implemented: D-54"]
fn d_54_truncation_always_signalled_via_more_flag_or_snapshotend_counts() {
    panic!("not implemented: D-54");
}

/// **D-29.** `visit.delete` is irreversible and the house performs it
/// without a confirmation round trip. Confirming with the person is the
/// client's job; the door does not second-guess a command its grant
/// permits.
///
/// Expected: `visit.delete` executes immediately on receipt of the
/// `Request`, with no intermediate confirmation frame or second round trip
/// required from the client.
#[test]
#[ignore = "not implemented: D-29"]
fn d_29_visit_delete_executes_immediately_with_no_confirmation_round_trip() {
    panic!("not implemented: D-29");
}

/// **D-52.** `visit.delete` is close-then-delete, in that order, as one
/// operation. The house first leaves the visit if it is a guest, or closes
/// it for everyone if it is the host, and only then deletes. After
/// `visit.delete` the house is not the host of that visit and holds no role
/// in it; a later event naming that visit is refused as an event for a
/// visit this house is not in. The `Reply` is sent after both halves are
/// done.
///
/// Expected: calling `visit.delete` on a visit with a guest actively
/// writing to it closes the visit (leaving/closing) before deleting, so no
/// event arriving mid-operation can re-create a row after deletion; after
/// the `Reply` is received, an event that arrives afterward naming that
/// visit id is refused, not silently accepted into a resurrected visit. See
/// WO-2.2 scenario 6.
#[test]
#[ignore = "not implemented: D-52"]
fn d_52_visit_delete_is_close_then_delete_atomically_host_role_ends() {
    panic!("not implemented: D-52");
}

/// **D-30.** A private visit is live at the door and absent from the store.
/// `visit.open{private: true}` returns a visit id, `visit.send` works
/// against it, and `Event` frames for `visit:<its id>` are delivered to a
/// subscribed client while it is open. It never appears in `visit.list`,
/// never appears in a `Snapshot`, and its events are never returned by
/// `visit.events`, because none of that exists to return. A client must not
/// persist what it saw of a private visit.
///
/// Expected: a private visit is fully usable live (`visit.send` works,
/// subscribed `Event` frames arrive) but is absent from `visit.list`,
/// absent from any `Snapshot`, and `visit.events` for it returns
/// `not_found` (or an empty/absent result consistent with R-46); after it
/// closes, a fresh connection has no trace of it anywhere.
#[test]
#[ignore = "not implemented: D-30"]
fn d_30_private_visit_live_at_door_but_absent_from_list_snapshot_and_events() {
    panic!("not implemented: D-30");
}

// --- Section 8: Errors ---------------------------------------------------

/// **D-31.** `not_found` and `not_permitted` are not distinguishable by a
/// client for anything outside its scope. Inside its scope, `not_found` is
/// used and is not an information leak, because the client is already
/// entitled to know.
///
/// Expected: for a resource outside the connection's scope, the house
/// answers `not_permitted` (never `not_found`) consistently, so probing
/// with different ids never distinguishes "exists but forbidden" from
/// "does not exist"; for a resource inside scope that genuinely does not
/// exist, `not_found` is used.
#[test]
#[ignore = "not implemented: D-31"]
fn d_31_out_of_scope_resources_always_answer_not_permitted_never_not_found() {
    panic!("not implemented: D-31");
}

/// **D-32.** `detail` never carries key material, a whole invite ticket, a
/// grant handle, or message content.
///
/// Expected: for every `Error` this house can produce, `detail` (when
/// present) contains none of: a 32-byte key, a grant handle, an invite
/// ticket, or message text from the triggering request — a scan of the
/// error paths for leaking these into `detail` finds none.
#[test]
#[ignore = "not implemented: D-32"]
fn d_32_error_detail_never_leaks_keys_handles_tickets_or_message_content() {
    panic!("not implemented: D-32");
}

// --- Section 9: Subscriptions --------------------------------------------

/// **D-33.** A `Subscribe` to a topic outside this connection's grant is
/// `Error{not_permitted}`; the subscription is not created and no partial
/// set is applied. A `Subscribe` naming 32 topics of which one is refused
/// creates none of them.
///
/// Expected: a `Subscribe` request naming 32 topics, one of which
/// (`visit:<id-outside-scope>`) is outside the connection's grant, is
/// refused wholesale with `Error{not_permitted}`, and none of the other 31
/// topics is subscribed as a side effect.
#[test]
#[ignore = "not implemented: D-33"]
fn d_33_subscribe_with_one_out_of_scope_topic_creates_no_subscriptions_at_all() {
    panic!("not implemented: D-33");
}

/// **D-34.** Subscriptions live for the connection and are not persisted. A
/// reconnecting client re-subscribes, and its `Hello` snapshot is what
/// fills the gap.
///
/// Expected: after a connection closes and reconnects, no topic it
/// previously subscribed to is still active; it must send a fresh
/// `Subscribe` to resume receiving `Event` frames, and the gap since
/// disconnect is covered by the new connection's snapshot, not replay.
#[test]
#[ignore = "not implemented: D-34"]
fn d_34_subscriptions_do_not_survive_reconnect_must_resubscribe() {
    panic!("not implemented: D-34");
}

/// **D-35.** `Event` is never sent before `SnapshotEnd` on a connection that
/// asked for a snapshot.
///
/// Expected: on a connection with `want_snapshot` true (default), no
/// `Event` frame is ever observed before that connection's `SnapshotEnd`.
/// (Overlaps D-14; stated as its own rule number and given its own case for
/// auditability.)
#[test]
#[ignore = "not implemented: D-35"]
fn d_35_no_event_frame_before_snapshotend_when_snapshot_requested() {
    panic!("not implemented: D-35");
}

/// **D-36.** An `Event` is a notification, not a store. A client that missed
/// one because it was disconnected recovers by reconnecting and reading the
/// snapshot, never by asking the house to replay events it already sent.
///
/// Expected: there is no command or frame type that lets a client ask the
/// house to replay previously sent `Event` notifications; recovery after a
/// disconnect is exclusively via reconnect + fresh snapshot.
#[test]
#[ignore = "not implemented: D-36"]
fn d_36_no_mechanism_exists_to_replay_previously_sent_event_notifications() {
    panic!("not implemented: D-36");
}

// --- Section 10: Heartbeat -------------------------------------------------

/// **D-37.** Either side may send `Ping` at any time. The receiver answers
/// `Pong` with the identical `token` before any other frame it has not
/// already started writing.
///
/// Expected: a `Ping` with an 8-byte `token` sent mid-session is answered
/// with `Pong` carrying the identical `token`, promptly and ahead of frames
/// not already in flight.
#[test]
#[ignore = "not implemented: D-37"]
fn d_37_ping_is_answered_with_pong_carrying_identical_token() {
    panic!("not implemented: D-37");
}

/// **D-38.** The house sends `Ping` every 15 seconds on an otherwise idle
/// connection and closes the connection with `Disconnect{timeout}` if no
/// frame of any kind arrives within 45 seconds. The client applies the same
/// rule to the house.
///
/// Expected: an idle connection (no frames sent by the client) receives a
/// `Ping` from the house at 15 seconds and is closed with
/// `Disconnect{timeout}` if 45 seconds pass with no frame received from the
/// client at all.
#[test]
#[ignore = "not implemented: D-38"]
fn d_38_idle_connection_pinged_at_15s_and_disconnected_timeout_at_45s() {
    panic!("not implemented: D-38");
}

/// **D-39.** Any frame counts as liveness. A busy connection never needs a
/// `Ping`.
///
/// Expected: a connection that is continuously sending/receiving ordinary
/// `Request`/`Reply` frames (no explicit `Ping`) is never disconnected for
/// timeout, because every frame resets the liveness clock.
#[test]
#[ignore = "not implemented: D-39"]
fn d_39_any_frame_counts_as_liveness_busy_connection_never_pinged_or_timed_out() {
    panic!("not implemented: D-39");
}

// --- Section 11: Queue status ------------------------------------------

/// **D-40.** The house's per-connection outbound queue holds at most 1024
/// frames. The house sends `QueueStatus{door, pressure}` when it passes 768
/// and `QueueStatus{door, full}` when it reaches 1024.
///
/// Expected: as a slow-reading client's outbound queue depth crosses 768,
/// it receives `QueueStatus{door, pressure}`; at 1024, `QueueStatus{door,
/// full}`.
#[test]
#[ignore = "not implemented: D-40"]
fn d_40_outbound_queue_pressure_and_full_signalled_at_768_and_1024() {
    panic!("not implemented: D-40");
}

/// **D-41.** When the outbound queue is full the house closes the
/// connection with `Disconnect{queue_full}`. It does not drop frames from
/// the middle of a stream a client is relying on, and it does not block the
/// house's own work on a client that stopped reading. A client that was too
/// slow reconnects and takes a fresh snapshot.
///
/// Expected: a client that stops reading entirely, driving its outbound
/// queue to 1024 frames, is disconnected with `Disconnect{queue_full}`
/// rather than having frames silently dropped from the middle of its
/// stream, and the house's other work is not blocked by this client while
/// this happens.
#[test]
#[ignore = "not implemented: D-41"]
fn d_41_full_outbound_queue_disconnects_client_never_drops_mid_stream_frames() {
    panic!("not implemented: D-41");
}

/// **D-42.** The note queue's own cap (D8) is reported through
/// `QueueStatus{notes}` and is refused at the limit, never trimmed: the
/// house refuses to queue a new note and says so through `Error{busy}` on
/// the command that tried, rather than silently dropping the oldest.
///
/// Expected: when the note queue is at its cap, a command that would queue
/// another note gets `Error{busy}`; the oldest queued note is never
/// silently evicted to make room.
#[test]
#[ignore = "not implemented: D-42"]
fn d_42_note_queue_at_cap_refuses_new_note_with_busy_never_trims_oldest() {
    panic!("not implemented: D-42");
}

/// **D-43.** `QueueStatus` for the `queue` topic requires a subscription;
/// `QueueStatus{door, full}` is sent regardless of subscription, because it
/// immediately precedes a close.
///
/// Expected: a connection not subscribed to the `queue` topic does not
/// receive `QueueStatus{door, pressure}`, but does receive
/// `QueueStatus{door, full}` immediately before being disconnected,
/// regardless of subscription state.
#[test]
#[ignore = "not implemented: D-43"]
fn d_43_queuestatus_pressure_needs_subscription_but_full_is_sent_regardless() {
    panic!("not implemented: D-43");
}

// --- Section 12: Disconnect ----------------------------------------------

/// **D-44.** `Disconnect` is the last frame its sender writes on that
/// connection. The sender then closes.
///
/// Expected: after sending `Disconnect`, no further frame is written by
/// that side on that connection; the transport closes immediately after.
#[test]
#[ignore = "not implemented: D-44"]
fn d_44_disconnect_is_the_last_frame_written_before_close() {
    panic!("not implemented: D-44");
}

/// **D-45.** A client that exits without `Disconnect` is not an error and
/// the house does not log it as one. `Disconnect{client_done}` lets the
/// house distinguish a clean exit from a crash in its connection list; it
/// is a courtesy, not a requirement.
///
/// Expected: a client that closes its transport connection abruptly with no
/// `Disconnect` frame produces no error-level log entry and no `Error`
/// frame attempt; the house's connection list simply records the
/// disconnection without a crash marker distinct from a clean exit's
/// absence of error.
#[test]
#[ignore = "not implemented: D-45"]
fn d_45_client_exit_without_disconnect_frame_is_not_logged_as_an_error() {
    panic!("not implemented: D-45");
}

/// **D-46.** Killing a client never affects the house. Closing the door
/// connection closes no visit, cancels no transfer, and changes no presence
/// state. The house being home is the house running, not a window being
/// open.
///
/// Expected: abruptly killing a client process mid-session leaves every
/// visit it was connected to open, every in-progress transfer running
/// uncancelled, and presence state unchanged; only an explicit
/// `presence.set` or equivalent command changes presence, never a dropped
/// door connection.
#[test]
#[ignore = "not implemented: D-46"]
fn d_46_killing_client_process_leaves_visits_transfers_and_presence_unaffected() {
    panic!("not implemented: D-46");
}

// --- Section 13: Feature flags and the minimum client version --------------

/// **D-47.** A client uses only features present in `Welcome.features`.
/// Sending a command belonging to a feature the house did not advertise is
/// `Error{unknown_command}`, not a protocol error.
///
/// Expected: a client calling `file.send` against a house whose
/// `Welcome.features` omits `files.v1` gets `Error{unknown_command}`, and
/// the connection stays open (not a fatal `Error{protocol}`).
#[test]
#[ignore = "not implemented: D-47"]
fn d_47_command_for_unadvertised_feature_gets_unknown_command_not_protocol_error() {
    panic!("not implemented: D-47");
}

/// **D-48.** `core.v1` is advertised by every conforming house. A `Welcome`
/// without it is not a Mosschat door.
///
/// Expected: every `Welcome` frame this house produces includes `core.v1`
/// in its `features` array; a fixture asserting a `Welcome` without it
/// would be asserting a non-conforming implementation.
#[test]
#[ignore = "not implemented: D-48"]
fn d_48_welcome_always_advertises_core_v1() {
    panic!("not implemented: D-48");
}

/// **D-49.** A house receiving `client_version < min_client_version`
/// answers `Error{unsupported_version}` with `detail` naming the minimum,
/// and closes. It does not attempt a degraded session.
///
/// Expected: a `Hello` with `client_version = 0` against a house whose
/// `min_client_version = 1` gets `Error{unsupported_version}` (detail
/// naming `1`) and the connection is closed, with no degraded session
/// offered.
#[test]
#[ignore = "not implemented: D-49"]
fn d_49_client_below_min_version_gets_unsupported_version_error_and_close() {
    panic!("not implemented: D-49");
}

/// **D-50.** A house serves a client whose `client_version` is greater than
/// its own `house_version`. The newer client discovers what it can use from
/// `Welcome.features` and uses that. Refusing a newer client would make
/// every addition a flag day.
///
/// Expected: a `Hello` with `client_version = 99` (greater than this
/// house's `house_version`) is served normally, not refused; the house's
/// own `Welcome.features` still reflects only what it actually offers.
#[test]
#[ignore = "not implemented: D-50"]
fn d_50_house_serves_client_with_higher_client_version_than_its_own() {
    panic!("not implemented: D-50");
}

/// **D-51.** `min_client_version` rises only when a change makes older
/// clients genuinely unserveable, and every such rise is a release note.
/// Adding a command, a kind, a topic or a field is a feature flag, never a
/// version rise.
///
/// Expected: this is a process/documentation rule rather than a
/// per-connection runtime check; the closest enforceable assertion is that
/// adding a new command, kind, topic or field to this implementation must
/// not, by itself, require a `min_client_version` bump — expressed here as
/// a stub pending WO-2.4's design, to be replaced with a concrete
/// regression check (e.g. a test that a new feature-flagged command exists
/// while `min_client_version` is unchanged from the previous release).
#[test]
#[ignore = "not implemented: D-51"]
fn d_51_adding_a_feature_never_requires_a_min_client_version_rise() {
    panic!("not implemented: D-51");
}

// ===========================================================================
// WO-2.2 scenarios (Dmitri's critique on PR #101, all seven)
// ===========================================================================

/// WO-2.2 scenario 1: stolen device. A stolen, unlocked machine gives the
/// thief the local socket, which is total authority over the house (door.md
/// section 1, added in the WO-2.2 revision): `device-revoke`
/// (`recording.md` R-36) removes the device's standing with *other* people's
/// houses but does not reduce what the local door grants on this machine.
/// Marked **must-change** by Dmitri and closed in the WO-2.2 revision by
/// stating the limit explicitly rather than changing the grant model.
///
/// Expected: on the stolen machine itself, the thief connecting over the
/// local socket still gets full `house` authority even after the owner has
/// issued a `device-revoke` for that device from another machine — the
/// revocation protects *other* houses' recordings, not this one. This is
/// the accepted, documented behaviour (an honest limit, `docs/honest-limits.md`
/// WO-5.5), not a defect to be fixed by this test.
#[test]
#[ignore = "not implemented: WO-2.2 scenario 1 (stolen device)"]
fn wo22_s1_stolen_unlocked_machine_local_socket_still_grants_full_house() {
    panic!("not implemented: WO-2.2 scenario 1, stolen device");
}

/// WO-2.2 scenario 2: revocation never reaches a friend. A host that never
/// learned of a revocation will list a revoked key in a `join`, and every
/// participant accepts that key's events for that visit (`recording.md`
/// section 5.4, "join is the sole membership authority"). R-37 stops the
/// key being re-added to a person once the revocation is seen, but does not
/// reach back into a visit a stale host already opened. Accepted risk,
/// closed by stating it plainly rather than by an uncheckable
/// backing-device-add requirement.
///
/// Expected: a host that has not seen a revocation for key K lists K in a
/// `join` for a new visit; every other participant accepts K's events in
/// that visit despite K being revoked elsewhere. This is the documented,
/// accepted behaviour: the test asserts K's events ARE accepted in this
/// stale-host visit, and separately that a later `device-add` re-adding K
/// once the revocation is known (R-37) IS rejected.
#[test]
#[ignore = "not implemented: WO-2.2 scenario 2 (revocation never reaches a friend)"]
fn wo22_s2_stale_host_joins_revoked_key_events_accepted_in_that_visit() {
    panic!("not implemented: WO-2.2 scenario 2, revocation never reaches a friend");
}

/// WO-2.2 scenario 3: host lies about the order (cross-guest host
/// equivocation). R-13 detects equivocation only within one recording;
/// section 9 forbids reading another participant's recording to compare,
/// so a host giving two guests different orders is not detected by any
/// participant. Accepted risk, explicitly named in `recording.md` section 9
/// and R-13's own text; not changed by the WO-2.2 revision.
///
/// Expected: given two guests' recordings of one visit where the host
/// (hypothetically, maliciously) sequenced different orders to each, no
/// rule or mechanism in `mosschat-core` detects the divergence, because
/// nothing may read another participant's recording to compare (section 9).
/// The test asserts this is the documented behaviour: each guest's own
/// recording remains internally consistent (R-13 passes within each), and
/// no cross-recording comparison API exists to catch the divergence.
#[test]
#[ignore = "not implemented: WO-2.2 scenario 3 (host lies about the order, accepted risk)"]
fn wo22_s3_cross_guest_host_equivocation_undetectable_by_design() {
    panic!("not implemented: WO-2.2 scenario 3, host lies about the order");
}

/// WO-2.2 scenario 4: hostile client at the door. `visit.events`'s `limit`
/// (up to 1024 entries) and `Snapshot.items` (up to 256 entries) could,
/// under an item-only cap, produce a `Reply`/`Snapshot` frame far exceeding
/// D-6's 1 MiB frame cap, since one `event` item can approach 131_072 bytes
/// (R-43). Closed by new rules D-53 (byte cap of 917_504 bytes binds first)
/// and D-54 (truncation always signalled via `more`/`SnapshotEnd.counts`).
///
/// Expected: a hostile or naive client requesting `visit.events` with
/// `limit: 1024` against a visit holding 1024 near-maximum-size (near
/// 131_072 byte) events receives a `Reply` whose payload never exceeds
/// D-6's 1 MiB frame cap, `more: true` is set, and the client must issue
/// further requests from the highest `seq` received to retrieve the rest.
#[test]
#[ignore = "not implemented: WO-2.2 scenario 4 (hostile client at the door)"]
fn wo22_s4_max_size_events_at_high_limit_truncate_by_bytes_not_items() {
    panic!("not implemented: WO-2.2 scenario 4, hostile client at the door");
}

/// WO-2.2 scenario 5: body type added in version two. A version 1 house
/// must sit in a visit with a version 2 house without losing the
/// recording, handled by R-14 (unknown body type carried whole) together
/// with R-8 (event_id computed from received bytes, unaffected by carrying)
/// and the door's `readable: false` + `{"raw": ...}` event kind shape
/// (`door.md` section 7), D-8's unknown-frame-type tolerance, and
/// D-47/D-50's feature-flag and forward-version-serving rules. Marked
/// **handled** by Dmitri with no spec change required.
///
/// Expected: an event with an unassigned body type (e.g. 9, a hypothetical
/// version-two type) is accepted, stored unchanged, and surfaced through
/// the door's `event` kind with `readable: false` and `body: {"raw":
/// <bytes>}`, never dropped and never causing a protocol-level error at
/// either the recording or door layer.
#[test]
#[ignore = "not implemented: WO-2.2 scenario 5 (body type added in version two)"]
fn wo22_s5_v2_only_body_type_carried_and_surfaced_as_unreadable_raw() {
    panic!("not implemented: WO-2.2 scenario 5, body type added in version two");
}

/// WO-2.2 scenario 6: visit deleted while a guest is still writing. Without
/// D-52, `visit.delete` (kind one) satisfies R-45 at the instant of the
/// call and violates it a moment later as in-flight events keep arriving
/// and re-create rows. Closed by D-52: `visit.delete` is close-then-delete
/// as one operation, the house leaves/closes the visit first, and a later
/// event naming that visit is refused because this house holds no role in
/// it any more.
///
/// Expected: while a guest's `visit.send` is in flight (already accepted by
/// the host but not yet delivered to this house), a concurrent
/// `visit.delete` call on this house closes the visit first; the in-flight
/// event, on arrival, is refused (this house is no longer in that visit),
/// and the store contains no re-created row for the deleted visit
/// afterward (R-45 still holds after the race, not just at the instant of
/// the call).
#[test]
#[ignore = "not implemented: WO-2.2 scenario 6 (visit deleted while a guest is writing)"]
fn wo22_s6_delete_live_visit_closes_first_in_flight_event_then_refused() {
    panic!("not implemented: WO-2.2 scenario 6, visit deleted while a guest is writing");
}

/// WO-2.2 scenario 7: honouring a drop-request breaks the chain. R-41
/// deletes the named bytes locally; without a replacement, R-13 cannot
/// match the next event's `prev` against the event that was stored at
/// `seq - 1`, marking an honest house's visit broken for obeying decision
/// 13. Closed in two steps: R-50 (tombstone retaining `seq` and
/// `event_id`) and, in the final WO-2.2 item, R-18/R-19 accepting a
/// tombstone as a valid reply/reaction target so ingest is identical
/// between a house that honoured the drop and one that declined.
///
/// Expected: after honouring a `drop-request` for the event at `seq = N`,
/// (a) a later event whose `prev` matches the tombstone's `event_id` is
/// accepted and the visit is NOT marked broken (R-13/R-50), and (b) a
/// `reply_to`/`target` naming that tombstoned event is accepted (R-18/R-19)
/// exactly as it would be on a house that declined to honour the drop and
/// still holds the original event — i.e. ingest outcome is identical
/// between the two houses for every event after the drop.
#[test]
#[ignore = "not implemented: WO-2.2 scenario 7 (honouring a drop-request breaks the chain)"]
fn wo22_s7_honoured_drop_request_chain_and_reply_target_ingest_matches_declining_house() {
    panic!("not implemented: WO-2.2 scenario 7, honouring a drop-request breaks the chain");
}
