# Watchword — Why sync converges

This document states what an item *is* to the sync layer, what merging two versions of it means, and why devices that
have received the same versions hold the same item. It is the argument behind `ItemMerge`, `ItemState` and `NoteText`
(`Sources/WatchwordSync`), and the specification their tests check. `02-architecture.md` §7.5 describes sync as
built; `06-adversarial-review.md` §H lists what this audit and its review found (Y18–Y37).

The claim, in the vocabulary of Shapiro, Preguiça, Baquero and Zawirski ("Conflict-free Replicated Data Types",
2011): an item is a **state-based CRDT**. Its states form a join-semilattice; `ItemMerge.merge` is the join; every
update a device makes gives a state that contains the one it was made on. From those three facts follows *strong
eventual consistency*: any two devices that have received the same updates hold equal items, with no coordination
and whatever order, grouping or repetition the versions arrived in.

Where the code is not a join, this document says so (§5: permanent deletion) and states what holds instead.

## 1. Setting

- A **device** edits its own copy of an item and publishes each version it writes (a *row*: the sealed item, its
  version number and the device that wrote it). Other devices receive rows and merge them into their own copy.
- A **revision** `(version, device)` names one edit. Versions are assigned by the vault above every version the device
  has seen (`VaultSession.nextRevision`), so an edit's version is above the version of the row it was made on.
  Revisions are totally ordered by version, then device ID.
- A **version vector** maps each device to the highest of its edits a copy contains. Vectors are ordered entry by
  entry and joined by taking the maximum of each entry.

Two properties of honest devices are used, and only where §3.2 says so:

- **C1 (a device's edits of an item are in sequence).** Each edit a device makes of an item is made on a copy that
  contains its earlier edits of that item. This fails only if a device's store is rolled back and it then reuses a
  version number (A8, a restored backup); §8 says what happens then.
- **C2 (fresh revisions).** The revision of a new edit is above the version of the row it is made on.

Everything else in §3 holds for *arbitrary* states, which is what makes §6 (hostile metadata) possible.

## 2. The state

`ItemState` is the replicated state. `Item` is its stored form; the table says where each component lives.

| Component | In `Item` | Meaning |
| --- | --- | --- |
| Registers | `revisions`, `conflicts`, and the attributes and `fields` themselves | Per group (each attribute, each field by ID): the set of stamped values no other value of the group supersedes. One is *shown* (it is the attribute or field), the rest are in `conflicts`. A field's removal is a value too (`.field(nil)`). |
| Field order | `fieldOrder`, `revisions[.fieldOrder]` | The latest arrangement of the fields and its stamp. |
| Clock | `clock` | The version vector of every edit the copy contains. |
| Note lines | `noteLines` (`notes` is derived) | The set of lines by ID, each with the line it follows, its text, and whether it was removed. |
| History | `history` | A set of earlier field values. |
| Retained values | `retainedValues` | Conflicting values an edit superseded without the person choosing to discard them. |
| Discards | `discards` | Per group, the version vector a person had before them when they resolved a conflict there. |
| Dates | `createdAt`, `modifiedAt` | Earliest creation, latest modification. |

A **stamp** (`GroupStamp`) is the revision that wrote a value and the version vector of the writer's copy at the write
(`seen`, which includes the write itself).

Not part of the state: `version` and the device that wrote the row. They say which row carries the state, and two
devices that merged the same edits store the same state under different rows (`ItemMerge.written` changes nothing
else). Equality in every test is equality of the whole `Item` as sealed, with only `version` set aside.

**Equality is of bytes.** Swift's `String ==` is Unicode canonical equivalence: "é" as one scalar and "e" followed by
a combining accent are equal. To a password manager they are two values — a site hashes the bytes it is sent — and a
merge that took them for one kept whichever spelling a device already held, so two devices could hold different bytes
for good while every comparison, `sameState` included, called them equal; and an edit that only respelt a password
was not saved (Y31). So the model's own `==` (`Field`, `ServiceScope`, `NoteLine`, `ItemGroupValue`, `Item`;
`WatchwordModel/ExactEquality.swift`) compares text byte for byte, and `NoteText` compares lines by their UTF-8. Every
set and register in this document is a set under that equality: two spellings are two elements, kept side by side,
shown as a conflict, and an edit that changes only the spelling is an edit. Hashing is unchanged and stays consistent
(values equal byte for byte are canonically equal, so hash alike). A `Set<String>` (tags, excluded hosts) still holds
one spelling of a member; comparing two of them compares the spelling each holds.

**Canonical form.** `ItemState.init(_:origin:)` reads an `Item` and `ItemState.item` writes one, and the round trip is
the identity on everything `ItemMerge` produces: the shown value of each group is a fixed function of its register (a
deletion first, then the latest revision, then a fixed total order), conflicts and retained values are sorted in that
total order, `fields` is the present fields in the stored order followed by any it does not list by ID, `notes` is the
visible lines in document order, the history is sorted. So equal states have equal stored forms, and
`merge(a, a) == a` for anything this code wrote. Orders that break ties use `CanonicalWriter`, a length-prefixed
encoding that is injective and does not depend on hashing order, a locale or a JSON encoder.

## 3. The join

`ItemState.joined` joins each component; the state is their product, so it is a join-semilattice if each component is.

### 3.1 Clock, dates, history

Version vectors under entry-wise maximum, dates under minimum or maximum, and sets under union are semilattices.

### 3.2 Registers: a multi-value register per group

For one group, a state is a finite set `R` of pairs (stamp, value) and the join is

    R₁ ⊔ R₂ = max(R₁ ∪ R₂),   max(S) = { x ∈ S : no y ∈ S supersedes x }

where `y` **supersedes** `x` when `x.seen` is strictly covered by `y.seen` (every entry at most `y`'s, and the vectors
differ).

*Lemma 1.* "Strictly covered" is a strict partial order on arbitrary vectors (irreflexive and transitive), so
"supersedes" is a strict partial order on arbitrary stamps.

*Lemma 2.* For finite sets under a strict partial order, `max(max(A) ∪ B) = max(A ∪ B)`. (Every element of `A` that is
not maximal lies below a maximal one, by finiteness and transitivity; so removing it first cannot change what the
union's maximal elements are.)

Hence `⊔` is idempotent on canonical sets (`max(R) = R`), commutative (union is), and associative (both sides equal
`max(R₁ ∪ R₂ ∪ R₃)` by Lemma 2). Nothing here assumed the stamps were honest.

*Lemma 3 (what it means between honest devices).* Under C1, for stamps `x ≠ y` written by honest devices: `y`
supersedes `x` exactly when `y`'s writer had `x`'s write in its copy, i.e. when `y.seen` contains `x.revision`.
Proof: a copy that contains an edit descends, through merges and edits, from the version that edit wrote, and merges
and edits only raise the clock, so its clock covers `x.seen`; `y.seen` is that clock plus `y`'s own revision, which
`x.seen` cannot contain. Conversely `x.seen` contains `x.revision`, so covering it implies containing it.

So the register is the multi-value register of the literature: **an edit made after seeing another replaces it; an
edit made concurrently does not, and both values are kept** until a person chooses (PRD F7.4, F7.6). Concurrent writes
of the *same* value are both kept as well — they are distinct elements of the set — and only the view
(`ItemMerge.conflicts(of:)`, `Item.hasConflicts`) treats them as one. Dropping one of them at merge time, as the code
once did, is not a join (Y18): a third write that had seen only the stamp kept would then supersede the value entirely
on devices that merged in one order and not on those that merged in another.

### 3.3 Field order: a last-writer-wins register

The state is one pair (stamp, list of field IDs); the join is the later of the two under a total order (revision,
then a fixed order on the rest). A maximum in a total order is a join. Between honest devices the revision order
extends causality (C2: an edit's version is above everything its writer had seen), so a reorder made after seeing
another replaces it; of two concurrent reorders the later revision stands and the other is not kept — an arrangement
holds no field's contents, so nothing a person typed is lost by that.

The list is stored, not read off `fields`, and may name fields that are no longer present. `fields` is then a pure
function of the register and the set of present fields: listed ones in order, the rest (added concurrently, or since)
by ID. That is what makes field order *exact*: a field removed in one merge and brought back in a later one returns to
its place whatever the order of merges (Y4, previously accepted as a corner that settled "one exchange later").
Adding or removing a field does not write the register unless the fields would otherwise be shown in a different order
from the one saved, so a deliberate reorder is not displaced by a concurrent addition or removal.

### 3.4 Notes: a sequence of lines (RGA)

The state is a map from line ID to (anchor, text, removed). An ID is the revision that inserted the line, its index
in that edit, and a nonce drawn at random for the edit (§6 says why). The join is the union of the maps, with lines present in
both joined by `NoteText.join`: the later anchor, removed if either is, and for the text the same text or — when the
two differ, which only a writer reusing an ID causes — every distinct line of either in byte order. Each part is a
join (a maximum in a total order, a boolean "or", a set union with "removed" as top), so the map is a semilattice.

The document is a function of the map alone (`NoteText.ordered`): depth first from the start, each line's children
newest first. This is a replicated growable array over lines: a line is never changed in place (an edit removes it and
inserts the new text), an insertion is placed by the line it follows and its ID, and a removal keeps the line's place.
The function is total — a line whose anchor is missing is treated as inserted at the start, lines in a cycle follow
everything else, each cycle laid out depth first from its least ID — so equal maps give equal documents, on any input.
Copies of one ID in a single record are gathered and joined in one pass, which is the same join (Y32).

### 3.5 Retained values and discards

For one group the state is a pair `(T, X)`: a set `T` of retained values and a version vector `X`, canonical when no
value in `T` was written by a revision `X` contains. The join is

    (T₁, X₁) ⊔ (T₂, X₂) = ((T₁ ∪ T₂) ∖ covered(X₁ ⊔ X₂),  X₁ ⊔ X₂)

`covered` grows with `X`, so for three states both groupings give `(T₁ ∪ T₂ ∪ T₃) ∖ covered(X₁ ⊔ X₂ ⊔ X₃)`; the join
is also commutative and idempotent on canonical pairs. This is what makes a discard *stay* discarded (Y19): before,
`resolve` removed retained values on the resolving device only, and the next merge with any other copy put them back.

### 3.6 The item

The join of two items is the join of each component (`ItemState.joined`), and `ItemMerge.merge(a, b)` is
`ItemState(a).joined(ItemState(b)).item`. With §2's canonical form: **`merge` is commutative, associative and
idempotent, and `merge(a, b)` contains both** (`merge(merge(a, b), a) == merge(a, b)`).

## 4. Updates are inflationary

An update is *inflationary* if its result contains the state it was made on: `merge(u(s), s) == u(s)`.

| Update | Code | Why it contains its predecessor |
| --- | --- | --- |
| An edit: fields, attributes, notes, trash, restore | `ItemMerge.stamped` | Each changed group's register becomes one value whose stamp is the copy's clock plus the new revision. The clock covers every stamp the copy holds (an invariant `ItemState.init` maintains) and the revision is new (C2), so the new stamp strictly covers, hence supersedes, every value it replaces. Superseded conflicting values move to the retained set (a union). Notes: lines are added or marked removed, never dropped. History is the union with the predecessor's; `createdAt` the earlier, `modifiedAt` the later. Unchanged components are unchanged. |
| Resolving a conflict | `ItemMerge.resolve` | As an edit of the one group, with the value chosen. The group's discard vector is joined with the clock the person had before them, which covers every retained value removed: the clock covers every stamp's `seen`, and every stamp is read with its own revision in `seen` (§6), so it contains the value's revision. |
| Storing a merge result | `ItemMerge.written` | The state is unchanged. |
| A deletion that did not cover the item | `ItemMerge.settle` | A join with a constant (§5). |

**Theorem (strong eventual consistency).** Every state a device holds is the join of the results of the updates it
has received, directly or inside merged versions. By §3 that join does not depend on order, grouping or repetition.
So two devices that have received the same updates hold equal items.

**What a person can rely on** (PRD F7.4, F7.6, F7.7), as consequences:

1. Edits of different groups, or of different lines of the notes, never conflict: the components are independent.
2. An edit made on a copy that held another edit of the same group replaces it (Lemma 3) — the replaced field value
   goes to the history, as `VaultSession` writes it on every save that changes a field.
3. Edits of one group made without seeing each other are both kept, one shown, the same one on every device.
4. A value a device wrote leaves the union of shown value, conflicts, retained values and history only by a person's
   action: an edit made where the value was shown, a resolution made where it was listed, or a permanent deletion that
   had seen it. Merging discards nothing (unions and maxima only, and `max` drops only what a present value
   supersedes).

## 5. Permanent deletion

A permanent deletion publishes a tombstone carrying an **erasure** (`ItemErasure`): the deleting device's version
vector for the item, the version of the row it erased, its device ID, and when that row was last modified. Every device
settles each version of the item against it (`ItemMerge.settle`):

- a version whose clock the erasure's vector covers is **erased**: the deleting person had seen all of it;
- any other version is **kept, in the trash**: the deletion is applied to it as *a write by the deleting device at the
  tombstone's revision* (one above the row erased), having seen what the erasure had seen, that sets `trashedAt` and
  `keptAfterDeletion`;
- a version that already holds the deletion's write, or values that supersede it, and a clock that covers it, has
  met the deletion and stands as it is. This is decided from what the version holds, not from its clock merely
  naming the tombstone's revision, so the rule is the same join on a record whose clock claims more than its values
  show (Y34).

**What is exact.** The write is a function of the erasure alone, so applying a deletion to a version it does not cover
is a join with a constant: it commutes with merging, applying it twice changes nothing, and every device that keeps the
same edits holds the same item (before this audit each device made its own edit, Y25). The write takes part in the
`trashedAt` register like any other: a trash or restore the deletion had not seen stays beside it as a conflict, the
deletion shown; a restore made on a copy that had met the deletion supersedes it and is not undone by meeting the
tombstone again (a reconciling sync, a device joining).

**What is not a join, and why.** Erasing is all-or-nothing by design: an item is never split. Take versions `v₁`, which
an erasure `E` covers, and `v₂`, which holds an edit `E` had not seen. A device that receives `v₁`, then the
tombstone, then `v₂` erases `v₁` and keeps `v₂`; one that receives `v₁`, `v₂`, then the tombstone keeps `v₁ ⊔ v₂`,
because the merged item is not covered. No function of (item, erasure) that erases covered items whole can be
associative with the item join, because coverage of a join is not the join of coverages.

**What holds instead.**

- *Safety.* An edit the erasure had not seen is never erased: any version containing it is uncovered, on every device,
  in every order. This is F7.6's promise.
- *The discard is the person's.* Everything erased was in a version the deleting person's device held.
- *Convergence.* A device that keeps a version writes it as a row of its own, which it publishes; a device that had
  erased the item receives that row, finds it settled, and stores it. So after every row has been delivered, all
  devices hold the join of the versions any of them kept — or none holds the item. Which of those two it is, and how
  much covered content rides along with a kept edit, can depend on the order of arrival; that two devices end up
  *different* cannot.

**Several deletions of one item.** An item can be permanently deleted on two devices, each having seen something the
other had not. The engine remembers the *join* of every erasure of a record it knows (`RecordMerger.joinErasureSummaries`,
stamped with the later stamp) and judges every version against that, the local one when a tombstone arrives and one
arriving after (review findings W13, W18). For items the join is the *set* of the deletions (`ItemErasures`): set
union, commutative, associative and idempotent, with one canonical encoding (a single erasure as a tombstone carries
it, several as a sorted array; an undecodable summary is a deletion that had seen nothing, `ItemErasure.void`).
`ItemMerge.settle` against a set erases a version whose clock the deletions' vectors cover *between them*, since each
of its edits was in a copy a person deleted; any other version receives each deletion's own write, exactly as above.
It does not join the deletions into one erasure with one revision: that would be a write no device made, crediting
one deletion with what another had seen, and two devices that learned of the deletions in different orders would hold
different items (one still holding the earlier deletion's write beside the joined one, the other not) until they
exchanged versions. As a set, the result is a join with each deletion's constant, so it is the same whichever
deletion a device learned of first.

What a device learns in between still matters in one way, the same way as above: a device that kept a version
against the first deletion holds that deletion's write, which the second deletion had not seen, so the version is no
longer covered by the pair and stays kept; a device that learned of both before judging erases it. By the convergence
argument the kept row reaches the second device too, so devices still do not end up different, and the error is
towards keeping.

The engine passes the merger the joined erasure's stamp (`resolveErasure(_:of:above:)`), a function of the erasures
alone: a deletion whose summary names a row above it is not believed and has seen nothing (Y28), and a version kept
is written above that stamp and the row, at a version of the keeping device's own. Only that version number differs
between devices; the item, sealed through `ItemMerge.written`, is the same.

The 30-day purge (F1.5) is a permanent deletion and follows the same rules. It removes only `Item.isTrashedByPerson`:
a trash written knowing every edit the item holds, with no other value of `trashedAt` beside it, and not a version kept
after a deletion.

## 6. Hostile metadata

Sync metadata is inside the sealed item, so it is authenticated — but only as *written by someone who holds the vault
key*: one of the account's devices, or from milestone 4 any member of a shared vault (A4). Every stamp, vector, line ID
and conflict is that writer's claim. The merge must be safe on any claim.

**The laws hold on any input.** §3 used no property of honest devices except in Lemma 3, which is about meaning, not
about the laws. So two honest devices that merge the same records, hostile or not, in any order, hold the same item,
and exchanging merge results settles. The suite "Adversarial: sync log, item metadata" checks the laws on randomly
corrupted metadata.

**How a record is read** (`ItemState.init`), the same way on every device:

- *No claim about the future.* A record written at version `V` cannot contain an edit above `V`, so every count in
  every vector, stamp and line ID is read as at most `V`. The version is bound into the record's authenticated data
  and checked by the engine against the vault (U5), so this bounds every count by something the engine has vetted.
  Without it a writer could stamp a value as having seen every edit any device will ever make — a conflict no later
  edit or resolution could clear — or plant note lines under the IDs of edits made after its record is merged (Y21,
  Y23; against edits made before that, see the nonce below).
  With it, C2 holds for every honest edit whatever the record held, which is what §4 needs.
- *Values belong to their group.* A value filed under a group it does not fit (a title among a field's conflicts, one
  field's contents under another's ID, any group this client does not know or a second spelling of one it does) is not
  read. Applying a value by its type used to overwrite the honest value of that type under the honest stamp (Y20).
- *Repeated identifiers are joined, not chosen from.* A field ID given twice is the first; a device given twice in a
  vector takes the higher count; two lines with one ID are joined by §3.4, which keeps both texts; two values with one
  stamp, or stamps that each claim the other's revision, are incomparable and both kept. Nothing depends on which
  duplicate a dictionary yields first (Y22).
- *The clock covers what the item holds.* The clock is joined with every stamp in the item, so the next honest edit
  supersedes all of it.
- *Erasure summaries* are read by `ItemErasure(summary:)`: one that does not decode, names a version above 2^62, or
  whose vector claims more than the row it says it erased could hold, has seen nothing — it erases nothing, and no
  arithmetic is done on its numbers (Y24). One this client *writes* is at most `SyncPayload.maximumErasureLength`
  bytes, which every reader enforces: an item's clock is a claim and can name thousands of devices, and a tombstone
  over the limit was refused by every other device, stopping the deleting device's stream for good. A summary that
  would not fit says the deleting device had seen nothing, so it erases nothing elsewhere and every other copy is kept
  in the trash (Y36). The engine should also refuse to publish an over-long erasure; that is its own check.
- *A stamp contains its own write.* `GroupStamp.init` records the revision in `seen`, but a stamp decodes as it was
  encoded, so a record can carry one whose vector omits it. Every stamp is read (`GroupStamp.clamped`) with its revision
  recorded: otherwise a resolution's discard vector, which tests a value's revision, did not cover a value it had
  removed, and the next merge brought it back (Y34).
- *Line IDs cannot be predicted.* A device's next revision is one above the highest version it has seen, so another
  writer can predict it, and the record's version bound does not help against an edit made before the device has
  merged the writer's record: the writer simply writes its record at or above that version. Removed lines planted
  under the IDs that edit will use then join with what the person types, and removal wins (Y21, which the version
  bound alone did not close; Y33). So every edit of an existing item draws a nonce from the injected generator
  (`ItemMerge.stamped(_:previous:previousOrigin:revision:using:)`) and puts it in the ID of every line it inserts:
  naming a line takes having seen it. Lines of a new item, and lines read from notes stored before lines were, have
  nonce zero; every device numbers those alike, and nobody can aim at an item before it exists.

**What a writer can still do, because any writer may:** replace a value (by a stamp that claims to have seen it — a
claim nobody can check), remove a field or a note line it has seen, discard retained values by claiming a resolution,
delete an item it claims to have seen, and fill an item up to the payload limit. What it cannot do is make an honest
group value disappear without a value in the same group claiming to supersede it, remove a note line it has not seen,
make two honest devices disagree, or stop an honest device's later edits from taking effect. Note text has no safety
net of its own: a removed line keeps its place but not its text, and lines are in neither the history nor the
conflicts, so a writer that has seen a line and removes it leaves no trace of the text. That is the same capability
every writer has by editing the notes; a recoverable trail for notes would need removed text kept until a person
discards it.

**Cost.** Reading and joining are linear in the size of the item except for one step: finding the values of a group
nothing supersedes compares distinct vectors pairwise (each against the heavier ones not yet covered). Honest items
hold at most one value per device per group. The payload limit (SEC9, 1 MiB) bounds a crafted item to a few thousand
values in one group. Measured on the cloud VM with an optimised build: a 1 MiB record holding 4,000 values of one
group, none superseding another and no two of equal weight (the worst case for the pruning), merges in about a tenth
of a second — less than encoding and decoding the same payload as JSON takes. Copies of one note-line ID are joined
in one pass, gathering every distinct text piece once and sorting once: folding them in one at a time re-split and
re-sorted the text so far at each step, so a record holding 8,000 copies of one ID cost about 13 s of CPU every time
it was read (Y32). The adversarial suite merges both kinds of record under a time limit. The laws forbid truncating instead: "keep the first *k*" is not associative.

## 7. How this is checked

| What | Where | How |
| --- | --- | --- |
| The specification of §3.2–3.3, at every step | `MergeModel` (`Tests/WatchwordSyncTests`) | A pure model of devices editing and exchanging one item. Beside each copy it tracks, independently of the item's metadata, which writes were delivered to it and what each writer had seen, computes the values a multi-value register must hold, and compares. |
| The laws, convergence, nothing lost | `LongRunningItemMergeLawTests` | Random histories of every kind of edit, resolution and deletion on 2–4 devices; the laws on random triples of stored versions, compared as whole items; the same versions delivered in random orders with repeats; every update checked inflationary; after full exchange all devices equal and every field value and note line typed still present unless a person discarded it. Widened nightly. |
| Every small history | `LongRunningItemMergeExhaustiveTests` | From six starting points, every sequence of up to three steps (four nightly, for two of them) over an alphabet that includes conflict, resolution, trash, restore, deletion and respelling a value in another normalisation form. Each step is one device performing one operation with each choice it offers — which field or line, which spelling, and for a resolution which value is kept, the shown one or another (Y35: taking the first choice each time never resolved in favour of a value that was not shown) — or receiving another device's version. The same checks at every node, the laws on every triple of versions a history stores. The numbers of histories, versions, pairs and triples are asserted. Standard run: 34,933 histories; nightly: 297,775 (about half an hour on the loaded cloud VM). |
| Each finding | `ItemMergeAuditTests`, `AdversarialItemMergeTests` | The smallest history that showed it. |
| Arbitrary metadata | `AdversarialItemMergeTests` | The laws on corrupted records, with canonically equivalent spellings and stamps that omit their own revision among the values, and with every update (edit, resolution, deletion) checked to contain the hostile version it was made on; absurd counts; cyclic, dangling and repeated lines, and removed lines planted under a device's next IDs; values under wrong groups; records at the payload limit, of incomparable values and of copies of one line ID; hostile erasure summaries; a clock naming thousands of devices, then deleted; two versions whose merge is over the payload limit, at the engine. |
| The engine around it | `LongRunningSyncSimulationTests`, `SyncMergeCaseTests` | N devices, partitions, an eventually consistent store, locks, rollbacks. |

While writing them, each defence was removed in turn (same-value writes collapsed, discards not recorded, the stored
order dropped, the old supersession rule, group checks off, clamping off, the line join made one-sided) and a test
failed each time.

## 8. Assumptions and what remains open

- **C1 and rollback.** A device restored from a backup can reuse a revision until a sync raises its version again.
  Two different writes under one revision are then both kept (they are distinct register elements; reused line IDs
  keep both texts), so nothing is lost; but a third device's write that had seen the first is taken to have seen the
  second too. The remedy is for the vault to persist the highest version it has assigned outside the rolled-back file.
- **The engine did not tell the merger the tombstone's version** (Y28, fixed when the sync-core work merged). The
  engine now passes the joined erasure's stamp, and `ItemRecordMerger` believes no summary naming a row above it.
  Within that bound an insider can still name a *lower* row, or another device, in its summary; the write that
  deletion makes is then at a lower revision than its tombstone, which raises nothing and is the same on every device.
- **Saving a draft made from an older version** (Y29, fixed). `ItemMerge.stamped` treats every difference between the
  draft and the stored version as the person's edit, so a draft opened before a sync merged another device's edit
  would silently undo that edit. `VaultSession.save` now refuses a draft whose version is not the stored one
  (`versionConflict`), and the editor reopens the item.
- **Items were shown as stored** (Y30, fixed). A record adopted when the device held no version of the item is stored
  as written; `VaultSession` now reads every item through `ItemMerge.canonical`, so what a person sees is what every
  merge and save makes of it.
- **A merge result over the payload limit is quarantined** (Y37). Two versions that each fit the 1 MiB limit can
  have a join that does not — two long concurrent note edits, or history that only grows — and any writer can arrange
  it. `ItemRecordMerger` then throws `ItemMergeError.resultNotSealable`, and the engine treats it like a U5
  quarantine: the local version stays, the remote entry is kept for the person (PRD F7.7), and the stream carries on,
  so unrelated items keep arriving (`mergeOverThePayloadLimit`). On that device the item no longer converges with
  the others until a person resolves it: the price of a bound on record size.
- **Kinds a device does not know** (ADR 0009, N7). The argument above is about items, on devices that read every kind
  in the log. A device of an earlier version keeps the entries of an ignorable kind it cannot read aside, unmerged,
  and merges everything else, so its items converge with everyone's; its state of that kind is simply behind, and
  catches up when it is updated and processes what it kept (or replays the log, if it had to drop some, or its stash
  was not saved after a crash). What makes that safe for the *other* devices is that it writes no ordinary snapshot
  while it holds entries a trusted device carried: every ordinary snapshot is then the state of a device that merged
  everything it covers, which is all §7.5's collection rule relies on. The one snapshot it still writes, for a revoked
  device's work, covers only revoked streams, which nobody collects, so it changes nothing that rule relies on; and
  what a revoked device carried is forgotten (except its own versions, which nothing else carries), so a device
  revoked after planting an unreadable entry cannot hold snapshots back for good. A critical
  kind it cannot read stops that stream at the object, as a gap does; nothing past it is applied, so nothing is merged
  out of order, and the stream converges once the device is updated.
- **Growth.** History, note-line tombstones, removed fields' stamps and retained values only grow. An item at the
  payload limit refuses further edits until history moves to records of its own (already tracked), and merges as
  above.
- **Dates** are the writers' clocks. `modifiedAt` is a maximum, so one device with a clock far ahead sets it for good.
