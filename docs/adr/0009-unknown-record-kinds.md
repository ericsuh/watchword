# ADR 0009: Record kinds a reader does not know are critical or ignorable by their raw value

Status: accepted. Date: 2026-11-16.

## Context
A sync segment or snapshot (`SyncPayload`, `02-architecture.md` §7.5) lists record versions, each with a kind byte
(`EnvelopeKind`). Until now a reader refused any payload carrying a kind it does not carry. Every stream is merged
strictly in sequence, so one refused segment stops its stream for good on that reader: nothing more from the writing
device is merged (items included), nothing is acknowledged, and garbage collection, which waits for every device's
acknowledgement, stops for the whole account. The first kind added after the format (`scanStatus = 10`, synced
breach-check results, §13.9) would have done exactly that to every device that had not yet been updated: review
finding N7 (`06-adversarial-review.md` §N). Nothing is released, so the format can still change; after a release it
cannot, so the rule has to exist before then.

Not every kind can be passed over. Skipping an item, a deletion, a membership change or a vault's description loses
data or changes what is secure; skipping a breach-check result only means this device checks the password itself,
as it would without synced results (ADR 0005, amendment). So the rule, in the spirit of X.509's critical extensions,
is that every kind is **critical** or **ignorable**, and a reader that does not know a kind needs to be able to tell
which — from the bytes, since it does not know the kind.

Where the criticality lives:

1. **An explicit flag bit** in each entry's flags byte. Flexible (any kind could be either, per entry), but a second
   field to authenticate, one more state to refuse (a known kind with the wrong flag), and a value that a snapshot
   carrying an entry forward must copy exactly. The record envelope's own context (`EnvelopeContext`: record, vault,
   schema, kind, key, version) would not bind it.
2. **A range of kind raw values that is ignorable by definition.** No new field: criticality is a function of the kind
   byte, which is already bound twice — inside the segment's sealed and signed payload, and inside each record
   envelope's own header and associated data. Nothing can disagree with it, and nothing can change it without
   changing the kind. The cost is a constraint on choosing future raw values, and that the existing ones cannot move.

## Decision
**Option 2.** `EnvelopeKind.criticality(ofRawValue:)`: raw values **10 through 127 are ignorable**; everything else
— the kinds 0 to 9 assigned before the rule, and 128 to 255, left for later critical kinds — is **critical**. No
existing value is renumbered; `scanStatus` (10) is the first ignorable kind. A test lists every case's intended
criticality in an exhaustive switch, so a new kind does not compile there until someone decides, and fails unless
its value lies in the matching range. A kind this version knows but does not sync (a key wrap, say) counts as
unknown in a payload: a later version might sync it.

**A critical kind a reader does not carry** refuses the object, as before, but explicitly: the stream stops at that
segment and skips nothing (a merged snapshot that already covers it is still passed, as for any refused segment),
`SyncReport.requiresNewerVersion` tells the UI to say "update the app" (like
`SharedVaultStatus.requiresNewerVersion` for a membership chain in a later format, §8.9), and the object, being
complete and authentic, stays staged so the updated version merges it without downloading it again. A staged
snapshot its author has since collected is dropped from staging, so what waits is never more than what is listed.

**An ignorable kind a reader does not carry** is parsed into `SyncPayload.unknownEntries`, checked as far as the
reader can (a segment's entries are its author's; the version is positive; the record envelope's own header names the
entry's kind and key, so an item cannot be filed under an ignorable label and passed over), and kept byte for byte in
the sync state (`SyncState.stashed`); the rest of the payload is merged and the stream goes on. A version of a record
from a segment replaces the same device's lower versions of it (its author's later write contains them; a deletion
only replaces a deletion); one from a snapshot replaces nothing, because a snapshot may attribute a version to any
device. When a version that carries the kind syncs, it processes what was kept, with every context check and the
kind's merger, as if it had just arrived, without downloading anything again; an entry that does not check or merge
is kept in the quarantine for the person (PRD F7.7). A shared vault's engine, whose judge must see each segment that
carried a version (§8.8), replays its whole log instead (its log is never collected).

**Snapshots and collection.** A device holding entries it cannot read **writes no snapshot**
(`SyncReport.snapshotWithheld`). The alternative, carrying the kept entries forward in its snapshot, is not sound: a
snapshot holds one entry per record, and a device that cannot read a kind cannot join two concurrent versions of one
record, so its snapshot would have to drop one of them while claiming to cover both segments; once those segments
were collected, a device of the later version joining afterwards would never see the dropped one. With the rule,
every snapshot comes from a device that read everything it merged, so whatever covers a segment carries what the
segment said, and a segment is still collected only once every device has acknowledged it and a listed snapshot
covers it. Acknowledging is safe: the device that acknowledges holds what it could not read. The cost is liveness,
not data: if the device that is elected to write a snapshot cannot, the others step in at four times the threshold
(§7.5); if every device that can still write holds such entries, nothing is collected until one is updated. A device
that owes a snapshot for a revoked device's work (§7.8) also waits, holding that work in its own store.

**Bounds.** At most `SyncConfiguration.maximumStashedEntries` (4,096) entries and `maximumStashedBytes` (4 MiB) per
vault. Past either, an entry is not kept, `SyncReport.unknownEntriesDropped` counts it and its kind is recorded in
`SyncState.stashOverflow`. The stream still merges (a cap that stopped the stream would let whoever fills it stall the
device), the device writes no snapshot (as above), and the first version that carries a dropped kind replays the log
(a reconciling sync), which still holds every dropped entry: in its segment, or in a snapshot by a device that read
it. So a flood costs this device storage up to the cap and, after an update, one replay; it loses nothing for anyone.

## Consequences
- A1, the storage provider, cannot make a device skip anything: changing a kind byte fails the signature and the AEAD,
  as any change does, and the stream waits at the object (tested in "sync log": `kindFlip`).
- An authenticated writer (an account's device, or A4 in a shared vault) can put any number of entries of an ignorable
  kind in its own segments. The cap bounds what that costs a device that cannot read them; and since such a writer
  can already stall collection by never acknowledging, its stopping snapshots by keeping devices' stashes non-empty
  is no new capability. It cannot get a critical record passed over: the record's header must name the kind its entry
  does (`itemUnderIgnorableLabel`).
- The kept entries live in the sync state, which A8 can edit like the rest of `SyncState`. Since only ignorable kinds
  are ever kept, the worst a planted or removed entry can do is add or remove advisory data on this device (a planted
  deletion of a scan result is no stronger than a planted erasure in `SyncState.erasures`); every live entry is still
  opened under its own context and the vault key when processed. Removing every kept entry would let the device write
  a snapshot again, the same exposure as a row deleted from the record store before a snapshot.
- A new kind's raw value is a decision: ignorable only if skipping it can neither lose data nor change what is
  secure, and its records must satisfy "a later version by one device contains that device's earlier ones", as every
  kind written from a device's current row does. A kind's criticality can never change once released.
- An entry kept aside from a segment the judge holds aside (a shared vault's write outside its author's cut) is not
  kept: it would not count on a device that could read it either.
