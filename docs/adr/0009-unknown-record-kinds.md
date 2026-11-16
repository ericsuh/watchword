# ADR 0009: Record kinds a reader does not know are critical or ignorable by their raw value

Status: accepted. Date: 2026-11-16. Amended the same day after an independent review (`06-adversarial-review.md` §N,
N8 to N13): authors, per-author caps, the stash's own row, revoked devices, the owed snapshot. Amended again after a
second review (N14 to N20): the row signed and generation-bound, the dedupe and crowding rules, a linear parse.

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
the **stash** (`SyncStash`), together with its **author**, the device whose signed segment or snapshot carried it; the
rest of the payload is merged and the stream goes on. An entry already contained in one held is not kept again: the
same entry, or a lower version by the same writer than one held on the writer's own word (from its own stream or
snapshot) or on this carrier's; a version another carrier attributed to the writer keeps out nothing, or an insider's
inflated version would suppress the genuine one and both would go when the insider is revoked (N15). A version from a segment replaces the same device's lower versions of the record (its author's later write
contains them; a deletion only replaces a deletion); one from a snapshot replaces nothing, because a snapshot may
attribute a version to any device. Every lookup goes through the entry's slot (record, kind, writer, deletion), so
keeping an entry costs a dictionary lookup, not a scan of the stash. When a version that carries the kind syncs, it
processes what was kept in ascending version order, with every context check and the kind's merger, as if it had just
arrived, without downloading anything again; an entry that does not check or merge is kept in the quarantine for the
person (PRD F7.7). A shared vault's engine, whose judge must see each segment that carried a version (§8.8), replays
its whole log instead (its log is never collected).

**Where the stash lives.** In a row of its own in the state store (`SyncStateStore.stash`/`saveStash`; a `stash` table,
schema version 2, in `SQLiteSyncStateStore`), written once at the end of a sync, not inside `SyncState`, which is saved
after every merged segment: a full stash is about 5 MB, and a flooder could otherwise force that write once per
segment of a catch-up. Crash safety comes from `SyncState.stashUnsaved`, set in memory as soon as the stash changes and
so saved with the state that counts the segment as merged, and cleared once the stash is saved. A sync that finds it
set, or a row that does not parse, cannot trust the stash to hold everything its merged segments said, and replays the
log to rebuild it.

**The row is signed and generation-bound** (N14, N19). Ignorable data is still data: a planted kept *deletion* of a
scan result, processed, erases it here, is remembered as an erasure, and goes out in this device's next snapshot as a
tombstone signed with the account key, wiping the result across the household; naming a revoked device as its carrier
would take it past a shared vault's judge. So the session signs every row it writes (`AuthenticatedSyncState`, the
account key, `SignatureDomain.syncStash`, a domain of its own — raw value 9 — over `"WWST" ‖ vault ID ‖ device ID ‖
stash`; a magic inside `pendingDeletion`'s domain would not do, as those messages start with a vault ID and have no
magic of their own), checked with the keyset or, locked, the Keychain's copy of the account key; a row that does not
verify reads as one that does not parse. Each row also carries a generation that the engine raises at each save and
records in `SyncState.stashGeneration`: a row of another generation (an older signed one put back, say), or none
while the state names one, is not taken as empty, and the log is replayed. Locked, the session cannot sign: a stash
changed only by forgetting what revoked devices carried is simply worked out again at the next sync, and any other
change leaves `stashUnsaved` set. The row is also parsed as hostile: only ignorable kinds, positive versions, a
deletion with no key, a live entry with a non-empty envelope within the payload's bound, the declared count checked
against the engine's caps before a single entry is read and the bytes as they are read, and each slot sorted once, so
a row costs `n log n` however its entries fall (a quadratic parse of one slot took minutes, N16). `processStashed`
also drops any entry of a critical kind unread.

**Revoked devices.** A revoked device's objects are not read (§7.8), so what it carried is forgotten — except its own
versions from its own stream, which nothing else carries: those are kept (across a replay too, which cannot bring
them back), processed once their kind is read, and hold nothing back — unless trusted devices' entries have been
crowded out, when room for those comes first and the revoked device's own versions go too. Entries it carried for
other devices are dropped as well (N18): those devices' own streams carry them, or, collected, the later snapshots of
devices that read the kind, which every device merges; this device may lack such a version until one of those
arrives. What it dropped past the caps is forgotten: no replay reads its objects.

**Shared vaults and the judge** (`02-architecture.md` §8.10, `10-sync-correctness.md` §9). A segment the judge holds
aside, or makes wait, keeps nothing aside: its unknown entries are passed over with it, as its known ones are held
aside, so a write that does not count never reaches the stash. A kept live version is judged by `admits` when it is
processed, like any version. Kept entries of a trusted device are not processed from the stash at all: the session
replays the log (`replayNeeded`, `needsReconcile`), whose segments the judge sees, so each is judged, a tombstone by
`admitsErasure` (S45), exactly as if it had been read on arrival, and the replay's reset of the stash means none is
processed twice. A revoked device's own kept versions survive that replay (no replay reads them) and a take-out
(which works on stored rows only), and are processed once, from the stash; a kept *tombstone* among them has no
segment left for `admitsErasure` to judge by, so it is held aside (quarantined, the record stays), as a refused
tombstone is. In a vault of one account there is no judge, and kept tombstones are applied like any other.

**Snapshots and collection.** A device holding entries carried by a **trusted** device, or that dropped some, **writes
no ordinary snapshot** (`SyncReport.snapshotWithheld`, and `snapshotWithheldBy` names those devices). The alternative,
carrying the kept entries forward in its snapshot, is not sound: a snapshot holds one entry per record, and a device
that cannot read a kind cannot join two concurrent versions of one record, so its snapshot would have to drop one of
them while claiming to cover both segments; once those segments were collected, a device of the later version joining
afterwards would never see the dropped one. With the rule, every ordinary snapshot comes from a device that read
everything a trusted device carried to it, so whatever covers a segment carries what the segment said, and a segment
is still collected only once every device has acknowledged it and a listed snapshot covers it. Acknowledging is safe:
the device that acknowledges holds what it could not read. The cost is liveness, not data: if the elected device
cannot write one, the others step in at four times the threshold (§7.5); if every device holds such entries, nothing
is collected until one is updated (or the device that carried them is revoked).

The snapshot a device **owes** for a revoked device's work (§7.8) is written all the same, because waiting would keep
that work from every device that joins later: its entries are the whole store as always, and its coverage names only
revoked devices' streams. Nobody reads or collects those, so it makes nothing collectable, and it covers no snapshot
but another such one; it only hands the work on.

**Bounds.** At most `SyncConfiguration.maximumStashedEntries` (4,096) entries and `maximumStashedBytes` (4 MiB) per
vault, and `maximumStashedEntriesPerAuthor` (2,048) and `maximumStashedBytesPerAuthor` (2 MiB) carried by any one
device, so one device cannot crowd out the rest. Past any of them, an entry is not kept and
`SyncReport.unknownEntriesDropped` counts it. Past its author's share, the kind is recorded against that author
(`SyncStash.overflow`); past the vault's cap, which others' entries filled, it is recorded against nobody
(`SyncStash.crowdedOut`, N17), so an honest device is not named in `snapshotWithheldBy` for what insiders crowded out,
and when room is freed (their revocation) the log is replayed to fill it again. The stream still merges (a cap that stopped the stream would let whoever fills it stall the device), the device writes no
ordinary snapshot (as above), and the first version that carries a dropped kind replays the log (a reconciling sync),
which still holds every dropped entry: in its segment, or in a snapshot by a device that read it. So a flood costs this
device storage up to the cap and one stash write per sync, and after an update one replay; it loses nothing for anyone.

**The U5 ceiling.** A kept entry's version does not raise the vault's high water while it is unread (it is not
checked against the ceiling either), so a device of an earlier version may judge a later jump in a kind it reads
differently from one that reads everything. Kept entries are processed in ascending version order after the update,
so the ceiling climbs through them as it would have on arrival. Counting them earlier would let any writer raise this
device's ceiling without bound through entries nothing checks.

## Consequences
- A1, the storage provider, cannot make a device skip anything: changing a kind byte fails the signature and the AEAD,
  as any change does, and the stream waits at the object (tested in "sync log": `kindFlip`).
- An authenticated writer (an account's device, or A4 in a shared vault) can put any number of entries of an ignorable
  kind in its own segments. The caps bound what that costs a device that cannot read them, and the per-author share
  keeps it from crowding out honest results. It **can** keep every device from writing ordinary snapshots, for as long
  as it is trusted, by publishing one entry of a kind no version defines: that is a new capability, and it stops
  collection and makes devices that join later replay the whole log. It loses no data (the segments stay, and the
  snapshot owed for a revoked device's work is still written), `snapshotWithheldBy` names the device, and revoking it
  ends it: what it carried is then forgotten. It cannot get a critical record passed over: the record's header must
  name the kind its entry does (`itemUnderIgnorableLabel`).
- The stash lives in the state file, which A8 can edit, and an earlier draft of this record argued that, holding only
  advisory data, it was not worth signing. A review showed otherwise (N14): a planted kept deletion spreads, as a
  signed tombstone in this device's next snapshot. Rows are now signed by the session and bound to the vault, the
  device and the state's generation (`plantedStashRow` with real keys; `plantedStash`, `staleOrMissingRowIsRebuilt`).
  What remains (N19): `SyncState` itself is not authenticated, so A8 who rewrites the state too (generation zero, no
  marker) and deletes the row makes the device forget what it kept, and it may then write an ordinary snapshot
  without those entries — the same exposure as rows deleted from the record store before a snapshot, and only for
  advisory kinds. It cannot make the device apply anything it did not receive.
- `SQLiteSyncStateStore` is at schema version 2 (the `stash` table). An older app finds version 2 and throws
  `unsupportedSchemaVersion` rather than misread the file; nothing is deleted, and that app syncs nothing until it is
  updated again. Downgrading is not supported: the file holds pending deletions and the quarantine, which no replay
  can rebuild, so it is never thrown away to let an older version start afresh.
- A new kind's raw value is a decision: ignorable only if skipping it can neither lose data nor change what is
  secure, and its records must satisfy "a later version by one device contains that device's earlier ones", as every
  kind written from a device's current row does. A kind's criticality can never change once released.
- An entry kept aside from a segment the judge holds aside (a shared vault's write outside its author's cut) is not
  kept: it would not count on a device that could read it either.
