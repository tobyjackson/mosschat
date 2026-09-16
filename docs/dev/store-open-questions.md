# Store open questions (WO-2.5)

Two decisions the plan leaves to Toby because they change what ends up on
disk. Both are implemented provisionally per the recommendation below, so
the store is not blocked on an answer; either can be changed without a
schema-version bump if decided before this merges, and with one (a small,
mechanical migration) after.

## Q1. Where does the passphrase's Argon2 salt live?

`crates/mosschat-core/src/store.rs`'s `PassphraseKey` derives the 32 byte
SQLCipher key from a passphrase via Argon2id. Argon2 needs a salt, and the
same salt must be used every time so the same passphrase re-derives the
same key.

- **Option A — a salt sidecar file** (`<store name>.salt`), 16 random bytes,
  written once alongside the key file at setup and read on every start.
  **Implemented here, provisionally.** Keeps the data key's derivation
  independent of the identity key, which matches how decision 10 already
  treats them elsewhere (the data key is never derived from, or stored
  with, identity material). Cost: one more small file to back up (already
  covered by decision 11's sealed bundle, which already carries "the data
  key" as one of its three contents) and one more file whose permissions
  matter (this module writes it `0o600`, same as the key file).
- **Option B — a fixed derivation context plus the identity key's public
  bytes as the salt.** No extra file. Couples the store's key derivation to
  the identity key, which complicates identity rotation later (device-add
  a new identity key and the store's derivation input changes with it,
  which is not what decision 10's "the data key is never put in a vendor
  keychain" reasoning is about, but is a new coupling nonetheless) and,
  more importantly, exposes the person's public identity key to anyone who
  can read the store's directory listing even before the passphrase is
  entered — a smaller leak than the recording itself, but a leak this
  format did not have before.

**Recommendation: A.** It is what is implemented. It keeps the two keys
independent, which is the simpler invariant to reason about later, and
the extra file is small, already covered by the backup bundle, and
permissioned the same way the key file already is.

## Q2. Windows key file / lock file permissions

`KeyFile::create` sets `0o600` on Unix via
`std::os::unix::fs::OpenOptionsExt`. There is no Windows equivalent in this
module today, and `docs/spec/door.md` D-2 shows the pattern this store
should eventually follow for the key file (and, by the same reasoning, the
lock file and the passphrase salt sidecar): a DACL granting access to the
creating user's SID alone, no group, including no administrators group.

- **Option A — land Unix now, Windows as an explicit follow-up work
  order**, tracked here rather than silently deferred. **Implemented here,
  provisionally**, because decision 2 already names Windows second and
  slice one does not build for it; adding a Windows ACL dependency
  (`windows-acl` or hand-written `SetFileSecurityW` calls via `windows-sys`,
  already in the tree transitively through `fd-lock` on Windows) to satisfy
  a platform nothing else in this crate targets yet would be built against
  no Windows machine to verify it on, which is exactly the kind of
  unverified claim this process exists to avoid.
- **Option B — block WO-2.5 on writing and testing the Windows path now.**
  Rejected here as disproportionate to slice one's stated platform order,
  but flagged rather than silently skipped, per this work order's own
  instruction to write down anything left out and why.

**Recommendation: A.** Windows permissions are real work with a real
verification cost (a Windows machine, per decision 18's own pattern for
network testing) and decision 2 already says Windows is second. Tracking
it here means it is not forgotten, not that it is deferred silently.
