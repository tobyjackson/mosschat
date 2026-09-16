# WO-2.1 open questions

Four choices the plan and `decisions.md` leave open, each of which changes a
frozen format. Each one is **provisionally picked** in the specifications so
they are complete; each recommendation is marked. If Toby chooses otherwise,
the change is a small edit to `docs/spec/recording.md` or
`docs/spec/door.md` and to the worked-example test, made before WO-2.4 and
WO-2.5 build against them.

---

## Q1. What does `prev` chain: the host's sequence, or the author's own events?

This one contradicts committed Phase 1 code, which is why it is here rather
than being settled silently.

`crates/mosschat-core/src/event/envelope.rs` documents `prev` as "`event_id`
of the previous event in this author's chain, or all zero bytes for the
first event". Nothing else in the repository, in PLAN.md, or in
`decisions.md` addresses it; the docstring was written in WO-1.1 when the
struct was stubbed, ahead of any specification.

**Option A (recommended, and what `docs/spec/recording.md` R-13 says).**
`prev` is the `event_id` of the event at `seq - 1` in the **host's**
sequence, and 32 zero bytes at `seq == 0`.

- The recording becomes a hash chain over the host's order, which is the
  order D5 says is the only order. Criterion 2's property ("every recording
  holds a prefix-consistent copy of the host's sequence") becomes checkable
  from the bytes rather than asserted by the code that wrote them.
- A host that equivocates, giving two guests different events at the same
  `seq`, produces two chains that diverge at a detectable point. Under
  option B a host can equivocate freely and nothing in the format notices.
  WO-2.2 is briefed to attack exactly this ("a host lies about the order").
- Cost: the host must hand the guest `prev` along with `seq`, so the
  sequencing exchange carries two fields instead of one. That exchange
  already exists in section 4 of the recording spec and is WO-3.1's to
  specify; the cost is 32 bytes on a message that already round trips.

**Option B (what the Phase 1 docstring says).** `prev` chains an author's
own events within the visit.

- Proves an author did not have an event of theirs dropped, and nothing
  about the visit's order.
- Cheaper: a guest computes `prev` with no help from the host.
- A host reordering or forging the sequence is undetectable from the
  recording.

**Option C.** 32 zero bytes always; drop the chain.

- Honest about what option B actually buys, and one less field to get wrong.
- Throws away the only equivocation check available, in a format that then
  cannot gain one without a version bump.

**Recommendation: A.** The whole point of freezing `prev` into a signed
envelope is to make the host's claimed order verifiable after the fact. B
puts a field in every event that answers a question nobody is asking.

**Consequence if A stands:** the docstring in `envelope.rs` is wrong and
WO-2.4 corrects it. That is a comment change, not a format change; the
struct and its encoding are untouched either way.

---

## Q2. Is the evaluation instant for a `device-add` window the ingest clock or the event's `ts_ms`?

`docs/spec/recording.md` R-32 picks the ingest clock.

**Option A (recommended, R-32 as written).** The receiving machine's own
clock at the moment of ingest.

- `ts_ms` is display data an author chooses (section 4 of the recording
  spec). Letting it decide whether a grant is in force would let a thief
  with a revoked device backdate `ts_ms` inside an old window and have every
  event accepted.
- Cost: two machines with badly skewed clocks can disagree on whether a
  grant is in force at the edge of its window. With R-35's 365 day default
  window, that edge is reached roughly never in slice one.

**Option B.** The event's `ts_ms`.

- Every recipient reaches the same verdict about the same event forever,
  which makes ingest a pure function of the bytes.
- Defeated by the attacker it exists to stop, because the attacker writes
  `ts_ms`.

**Option C.** The host's clock at sequencing, carried as a new signed
envelope field.

- Correct in the sense that the host is the one party the visit already
  trusts for order, and it survives clock skew.
- Costs a ninth envelope field, and the envelope is frozen and already
  implemented. Not worth reopening for a mechanism slice one never exercises.

**Recommendation: A**, and accept the determinism loss. Say plainly in
WO-5.5's honest-limits page that a device grant is judged by your machine's
clock.

---

## Q3. Does the door's scope grant need a signature, or is possession enough?

`docs/spec/door.md` section 6 specifies an **unsigned** grant issued and
stored by the house, with an opaque 32 byte handle the client presents.

**Option A (recommended, as written).** The house mints a grant, stores it,
and hands the client a random 32 byte handle. The handle is a bearer token
against that one house; the grant's subject, command list and expiry live in
the house's own store and are checked there.

- No new signing context, no new verification path, no chain walking, no
  clock agreement between two parties. The house is both issuer and verifier,
  so a signature would be the house proving something to itself.
- Revocation actually works: the house deletes the row. This is the one
  place in Mosschat where revocation can fail closed, and an unsigned grant
  is what makes that true.
- Cost: a grant cannot be delegated onward by a client without the house's
  involvement, and cannot be shown to a third party as proof. Neither is
  wanted in slice one.

**Option B.** A signed, attenuable grant in UCAN's shape (subject, command,
expiry, proof chain), our CBOR, our BLAKE3.

- A client could hand a narrower grant to a helper without the house.
- Costs a signing context, a verification path, a chain depth limit, a
  proof-size cap, and a revocation problem the house does not otherwise
  have. `research/zero-trust-and-ucan.md` C recommends borrowing UCAN's
  *shape*, which is the subject/command/expiry triple, and says explicitly
  not to take the format; the triple is present either way.

**Recommendation: A.** WO-2.1's scope sentence asks for "a subject, a
command and an expiry, which is UCAN's shape borrowed into our own CBOR
rather than UCAN itself". Option A has all three. The signature is the part
that buys delegation, and delegation is what makes revocation unsolvable.

---

## Q4. May a client at the door open a network door, or only a local one?

`docs/spec/door.md` D-3 and section 7 pick: the network door is off by
default and, when on, is bound to an explicitly configured list of client
keys.

**Option A (recommended, as written).** The network door listens only when
the house is configured to, and only accepts client keys on a configured
allow list. There is no discovery, no gate involvement, and no invite path
into the door.

- Decision 27 requires the door to *work* over the network; it does not
  require it to be reachable by default. A door that is open by default is
  the house's entire authority on the internet.
- Cost: linking a phone in version two needs a configuration step. That is
  correct: handing a device the house's authority should be a deliberate act.

**Option B.** The network door accepts any friend of this house.

- No configuration step, and the friend list already exists.
- Conflates two very different grants. A friend may visit; a friend may not
  read your keys, your other friends' visits, or your note queue.

**Recommendation: A.**
</content>
