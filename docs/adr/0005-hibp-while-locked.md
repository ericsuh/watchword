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
