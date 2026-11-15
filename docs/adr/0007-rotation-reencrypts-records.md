# ADR 0007: Rotation re-encrypts records; no per-item keys

Status: accepted. Date: 2026-11-15.

## Context
Principle 5 (`02-architecture.md` §1) is "rotate on every membership change": when a member is removed or leaves, the
vault gets a new key so that they see nothing new. Review finding D10 pointed out what that costs as designed: every
live record is re-encrypted under the new key and uploaded again, O(items) work and O(items) upload on each removal.
§16 carried the alternative as an open question, promoted to a milestone-4 decision: **per-item keys**, where each
item is sealed under a key of its own and only that small key is wrapped by the vault key, so that a rotation
re-wraps item keys instead of re-encrypting items.

What a rotation has to achieve, in order of importance:

1. **Nothing written after the removal is readable with a key the former member holds.** This needs a new key for new
   writes, and nothing else.
2. **One key reads the vault.** A member added after a rotation is granted the current key only
   (`MembershipLedger.grantSender` entitles nobody to grant them an earlier one). If old records stayed under old
   keys for ever, new members could not read them, and every device would keep every key the vault ever had.
3. **Old ciphertext under a key the former member holds stops being useful.** Only as far as the store cooperates:
   we cannot make anyone forget what they synced (PRD F4.3 says so in the UI), and a hostile store (A1) keeps old
   objects whatever we ask. What re-encryption does buy is against a former member who had *not* fetched everything
   and later gets at a store that did honour deletion.

Options considered:

1. **Eager re-encryption under the vault key** (decided below): the rotation's last step re-seals every record not
   under the current key, as new versions through the ordinary save path.
2. **Per-item keys wrapped by the vault key.** Rotation re-wraps one 32-byte key per item.
3. **Lazy only**: new writes use the new key, old records stay as they are until next edited.

## Decision
**Keep one key per vault and re-encrypt eagerly on rotation (option 1). Do not introduce per-item keys.**

- A rotation is a `RotationPlan` (`WatchwordSharing`): the new key ID, the key wrapped to every remaining member, and
  the signed membership record. Its last step is "re-seal": `MembershipLedger.recordsToReseal(in:)` lists every record
  not under the current key, and the integrator re-seals each as a new version. The list is asked for again until it
  is empty, because other devices may still write under the old key until they have seen the new record. Any member
  who may write and holds both keys may do it; the rotating administrator's device does it eagerly, and the first
  writer to touch a stale record does it anyway (§4, "Records").
- The state between "key rotated" and "nothing left under an old key" is visible: `PendingRotation.resealing`, which
  is F4.3's "pending rotation" on every device, not only the one that rotated.
- An old key is kept by a device until nothing it holds is sealed under it, then dropped.

Why not per-item keys:

- **They do not give requirement 1 by themselves.** Re-wrapping an item key under the new vault key leaves the item
  key unchanged, and the former member has it. The next edit of that item must therefore also replace the item key,
  which is lazy re-encryption with an extra level, plus the bookkeeping of which item keys predate which removal.
- **They are still O(items) per rotation.** One wrap per item has to be written and synced (about 150 bytes each
  as an envelope, instead of the whole record), unless a further table of wrapped keys is added, which is a new record kind with its
  own merge rules.
- **They put a new level in the most sensitive path.** Every item read and write would unwrap or wrap a second key;
  `VaultSession.commitItem`, `ItemCodec`, the envelope context, the `NonceLedger` (one per item key) and sync's merge
  (two devices editing one item concurrently would each bring an item key, and the merge must choose) all change, and
  every stored record needs migrating. That is a great deal of new attack surface in exchange for upload volume.
- **The cost they save is small at household size.** Measured on the Linux CI image (swift-crypto over BoringSSL,
  x86-64, one core), opening and re-sealing with `RecordCipher`:

  | Vault | Re-seal CPU, debug build | release build | Bytes re-uploaded |
  | --- | --- | --- | --- |
  | 2,000 records of 4 KiB | 78 ms | 18 ms | 8.4 MB |
  | 10,000 records of 4 KiB | 350 ms | 136 ms | 42 MB |
  | 2,000 records of 64 KiB (long histories) | 300 ms | 122 ms | 131 MB |

  Wrapping the new key to 200 members took 30 ms (release), so the O(members) part is nothing either. CPU is
  irrelevant; the cost is the upload, and every other device downloading the same versions. For the household this
  product is for (hundreds to a few thousand items of a few kilobytes) that is megabytes, a few times a year at most,
  on an operation the person already expects to take a moment. Per-item keys would turn 8.4 MB into about 0.3 MB.
  It does not justify the above.

Why not lazy only: it fails requirement 2. A member invited after a rotation would be unable to read any record not
edited since, or would have to be granted every old key, which gives the vault a key history that only grows and
makes "who is entitled to which key" a much larger rule than the one `grantSender` enforces today.

## Consequences
- A rotation's work is proportional to the vault. It is planned as data and resumable (`RotationPlan.encoded`,
  `RotationStatus`), so an interruption costs time, not correctness: the membership record and the new key go out
  first and are small; re-sealing can finish on a later unlock.
- Until re-sealing finishes, records under the old key are readable by remaining members (who keep that key until
  then) but not by a member added in the meantime. The UI shows the vault as pending rotation (F4.3).
- Re-sealed records are new versions in every device's sync log, written by the re-sealing device. They carry the
  item unchanged, so `ItemMerge.written` (a version, not an edit) is the right way to seal them: they must not look
  like an edit to the merge. That is integration work in `VaultSession`.
- Item history lives inside the item's payload (F1.4) and is re-sealed with it. If history moves into records of its
  own (milestone 3's open item), those records are part of the inventory and re-sealed the same way.
- **When to revisit.** If attachments or other large blobs arrive, each blob should have a content key of its own,
  wrapped inside the item record that references it: re-sealing the item then re-wraps the blob key and the blob
  itself is not uploaded again. That is a per-blob key for a reason this ADR does not argue against, and it is the
  first thing to add if rotation volume ever matters. A vault above roughly 10,000 items, or a use that rotates often
  (a rota of temporary members), would be the other reason to reopen this.
- Review finding D10 is closed by this decision; §16 no longer lists per-item keys as open.
