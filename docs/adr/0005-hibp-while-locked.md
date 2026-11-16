# ADR 0005: Breach scanning only while keys are resident

Status: accepted. Date: 2026-10-13.

## Context
Background Have-I-Been-Pwned scanning needs the plaintext password to compute SHA-1. Running the
scan while the vault is locked would require persisting something derived from each password
(the SHA-1, or its 5-character prefix plus suffix). An unsalted SHA-1 of a password on disk is an
offline-crackable artefact and would defeat the at-rest guarantees.

## Decision
- The scanner runs only while key material is resident (app unlocked, or within the background
  grace period before auto-lock). On macOS, where the app typically stays running and unlocked,
  this yields near-continuous coverage; on iOS, scans run on unlock for changed items and complete
  a weekly full pass opportunistically.
- Nothing derived from a password is persisted; the HIBP prefix cache stores only public range
  responses keyed by prefix.
- The "last scanned" timestamp per item is stored inside the encrypted item.

## Consequences
- On iOS, a person who rarely opens the app may have stale breach status; the Watchtower report
  shows the last scan time to make this visible.

## Amendment (milestone 6, 2026-11-15)

Building `WatchwordHygiene` (`02-architecture.md` §13) showed two places where the decision above was looser
than its own reasoning, and one where it was more expensive than it needed to be.

- **The prefix cache is not public data.** Each cached *response* is public, but the set of prefixes a device
  holds is twenty bits of the SHA-1 of each of the person's passwords: with the file, an attacker can reject
  all but about one in a million guesses per password offline. So "nothing derived from a password is
  persisted" covers the cache too. A persisted cache is sealed under a key that is gone when the vault locks,
  is neither read nor written while locked, and stays on the device. The default cache is in memory only, and
  memory counts: the set of prefixes must not outlive the keys there either, so locking empties it
  (`PwnedRangeCache.lock()`, called by `HygieneEngine.lock()`), and an entry on its way into the cache when
  the lock lands is removed.
- **Breach results are derived from passwords.** A count from the range API all but names the password. The
  results the scanner keeps between launches (`ScanLedger`) are therefore persisted only sealed, never in the
  clear, and `HygieneEngine` hands the ledger out only while unlocked.
- **The last-scanned time is not stored inside each item.** Writing it there would make the weekly scan a
  weekly edit of every item: a new version, a new log segment and a merge for each, on every device. The
  ledger is one sealed, per-device, unsynced record holding, per item, the version scanned, the time and the
  per-field result. The report still shows when each item was last checked, and the oldest check overall.
  The ledger also holds which items' checks *failed*, and when. That is not derived from a password, but it
  is kept there, and not in memory, on purpose: it must last across a lock and a restart (or one refused
  range is asked for first at every unlock and nothing else is ever checked), and in the sealed record it
  does so without an item ID staying in memory while the vault is locked.

What does survive a lock is the scanner's rate limit and backoff (`ScanPacing`): a count of requests and
three times, none derived from a password, naming no item. Dropping them at lock would let every unlock
forget the server's `Retry-After` and start a new burst. For the same reason a scan that a lock interrupts
still writes to it, and to nothing else: the requests it sent are charged, and a refusal that arrived after
the lock still backs the scanner off.

Unchanged: scanning needs the plaintext, so it runs only while keys are resident; a scan a lock interrupts
resumes at the next unlock; with keys absent nothing is hashed, and a response that arrives after a lock is
discarded without being cached.

## Amendment (owner decision 10, 2026-11-16): results are synced with the vault

The owner's decision, verbatim: "Store and sync them with the items, with scan times synced. That way every client is
not repeating the checks too much, except for races, which are fine." Confirmed follow-up rule: **a synced "clear" only
postpones this device's next check, and never hides a breach this device has seen.**

This replaces "per-device, unsynced" for breach results and scan times, and nothing else: scanning still needs the
plaintext and runs only while keys are resident, the prefix cache stays in memory (or sealed on the device) and is
never synced, and the ledger stays a sealed, per-device, unsynced record. Representation (`02-architecture.md` §13.9):

- **A record kind of its own, beside the item.** `EnvelopeKind.scanStatus` (10; no raw value renumbered), record ID
  the item's, in the item's own vault, sealed under that vault's key with the usual context (record, vault, kind,
  key, version), so a record moved to another item or vault, or replayed at another version, does not open. It is
  never an item version: a check adds no history entry (F1.4 keeps item history unpruned, so weekly results there
  would grow without end), makes no conflict, and never reaches `ItemMerge`. It is deleted with its item (permanent
  deletion, the trash purge, a move's original, a vault's deletion), explicitly, through the deletion-recording store.
- **A join, per device.** The record (`SyncedScanRecord`) maps each device to its latest observation: when it checked,
  and per password whether it was found and how often. Each device writes only its own; the merge keeps, per device,
  the higher revision, and at most 32 devices (the highest revisions). Commutative, associative, idempotent.
- **Bound to the password, under a vault-derived key.** Each result is under a `ScanBinding`,
  `HMAC-SHA-256(K, "WW-scan-binding-v1" ‖ 0x00 ‖ itemID ‖ password)`, where `K` is derived from the vault key the
  observation names (`HKDF(vault key, vaultID ‖ keyID, "WW-hygiene-scan-binding-v1")`). Never a bare hash: without
  that vault key a binding confirms no guess. A changed password has a new binding, so no old result covers it; an
  edit that leaves the password leaves its result standing. The observation names its key, so a rotation's re-seal
  keeps results valid.
- **What a synced result is worth.** A remote "not found" counts as a check and nothing more. Synced times further than
  the clock tolerance (five minutes) ahead are ignored and the rest count as no later than now, so one check postpones
  this device's own by at most an interval; and synced checks together stand in for this device's own check of an item
  for at most `maximumSyncDeferral` (28 days, then the pass that ends it), however often a member reports "not found".
  A remote "found" is shown, labelled as another device's (`BreachSource.anotherDevice`), and remembered in this
  device's ledger (`ScanLedger.reported`), where only this device's own later check of the password removes it. This
  device's own results are read only from its own sealed ledger, never back from the synced record, so no record
  anyone else writes can remove a breach this device saw.
- **The ledger gains keyed digests.** Entries keep the binding of each password checked (under a key derived from the
  reuse key, which no vault rotation changes), plus the reports taken in and the deferral marks. The ledger is sealed
  under the device-local key; whoever can open it holds the keyset and could decrypt the items, so this weakens
  nothing. It still holds no hash or prefix.
- **Shared vaults.** Results are records like any other: a read-only member writes none, the write judge attributes
  each observation to its device and revision (S28: a removed member's late observation counts nowhere), and a
  rotation re-seals them.

Consequences: a household's devices check each password about once per interval between them, not once each; races
(two devices checking at once) cost a duplicate request and nothing else. A vault member can make a breached password
look clear on another device that has not checked it for at most the deferral limit, which is no worse than what a
member who can read and change the password can already do, and cannot hide a breach that device saw. Results reach
every member of the vault, who can read the passwords anyway. A client that does not know the kind refuses segments
carrying it; the repository has no released clients, so no migration is provided.
