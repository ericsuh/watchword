# ADR 0010: Contacts are verified with one-time vault sharing codes, not a 60-digit safety number

Status: accepted (owner's request of 2026-11-17, design and analysis left to this document). Date: 2026-11-17.

## Context
Before a vault key is wrapped to someone, and before a membership chain is anchored on an owner, the two accounts'
key bundles must be authenticated out of band (PRD F4.2, SEC3; `02-architecture.md` §8.4). The key directory is
adversary A1's ground, so what it returns is a candidate and nothing more. Until now the screens offered a 60-digit
safety number (a fingerprint of the bundle) to type or to compare by eye, an account ID or 158-character fingerprint
code to paste, and an invitation as 74 hexadecimal characters to paste. The owner asked for something a person can
read, or hear read by VoiceOver, without room for manual error, under the name "vault sharing code", and for camera
scanning; and asked that the suggestions (a short alphanumeric code, or a short random number per request shown on
one screen and typed on the other) be weighed, not taken as given.

What a design here must hold:

- **G1.** After it succeeds, each device holds the other account's true bundle, except with a stated, small
  probability per attempt, against an adversary who controls every channel but the one between the two people.
- **G2.** A failed attempt is visible to both people, and nothing is pinned, wrapped or anchored by it.
- **G3.** No step is a person's unchecked claim ("they match"): what a person does is checked by a device.
- **G4.** Only primitives the project already ships (CryptoKit's; `CLAUDE.md`, "No third-party dependencies").
- **G5.** The channel between the people needs to be authentic (they hear each other, or one sees the other's
  screen), never confidential: a code overheard or photographed must be worth nothing.

## Options considered

1. **A shorter fingerprint.** Refused. A fingerprint is a fixed function of public keys, so A1 can generate key pairs
   offline until one matches: 40 bits (eight letters and digits) is 2^40 key generations, an afternoon on rented
   hardware. Stretching the fingerprint with a slow hash buys perhaps 20 bits at the cost of seconds on every honest
   device, and still leaves an offline target. Short is only safe for a value that is fresh per attempt and cannot be
   searched for, which rules out anything static. Fails G1.
2. **One random code, typed once, with a password-authenticated key exchange** (CPace or SPAKE2). The best
   experience: one code, one direction, both sides authenticated. Refused for now: CryptoKit has no PAKE, and the
   smallest sound construction (CPace over X25519) needs a hand-written map from a hash to a curve point, field
   arithmetic of our own in a password manager, on a specification that is still an Internet-Draft. Fails G4. It also
   needs the code kept secret (fails G5), though a single-use code makes that mild. The message formats below are
   versioned so that this can replace option 4 later by its own ADR.
3. **One random code, typed once, authenticating by a MAC under a slow hash of the code.** Refused. Everything that
   authenticates is then guessable offline from one transcript, limited only by the session's lifetime and the hash's
   cost: an eight-character code under PBKDF2 at the floor is within reach of a large attacker inside ten minutes.
   Fails G1 for the adversary that matters, and G5.
4. **A short authentication string over a commitment** (the construction of ZRTP, Bluetooth numeric comparison and
   Matrix's device verification): the devices exchange a commitment and two nonces over the untrusted channel, and
   each derives a short code from everything it saw. Hashes only. The code is not a secret. An adversary in the
   middle cannot choose its messages to steer the code, because each side fixes its nonce before it can see the
   other's, so it gets one blind try per attempt. **Chosen.**
5. **A QR code carrying a one-time secret**, so that one scan authenticates both ways. Refused: it rests on nobody
   else seeing the screen (fails G5), and the failure is the worst one, a bystander's account invited in place of
   the invitee's. A QR code carrying the *fingerprint* needs no such assumption and is kept (below).

Typing beats comparing. Every scheme of kind 4 can be finished by two people each saying "mine matches", which is
the unchecked claim G3 forbids and the step people skip. Here each person types the other's code and the device
compares, at the price of one more read-aloud.

## Decision

### The session
A **sharing session** runs between a *starter* S and a *joiner* J over a **sharing board**: a public, untrusted
store of small objects fetched by exact name and created once, never overwritten or listed (a port in
`WatchwordSharing`, beside `KeyBundleDirectory`; its production adapter belongs with the directory's and is as open
as that one). All values are fixed-length and every parser exact.

```
S: number  = 8 random decimal digits          (shown to the person: the vault sharing code)
   session = 16 random bytes     Ns = 32 random bytes
   C       = SHA-256("WWSC1-commit" ‖ session ‖ S.account ‖ Ns)
   create  board[number]/commit = session ‖ S.account ‖ C          (taken: choose another number)
J: (the person types the number, or scans it)
   fetch commit; bundleS' = directory(S.account)                   (a candidate)
   Nj = 32 random bytes
   create  board[number]/reply  = J.account ‖ Nj                   (first writer wins)
S: fetch reply; bundleJ' = directory(J.account)                    (a candidate)
   create  board[number]/reveal = Ns                               (once, and only after the reply is held)
J: fetch reveal; check C
both: T = SHA-256("WWSC1-code" ‖ session ‖ number ‖ S.account ‖ bundle(S) ‖ J.account ‖ bundle(J) ‖ C ‖ Ns ‖ Nj)
      each with its own true bundle and the other's candidate, in `KeyBundleCodec` bytes
      joiner's code  = 6 decimal digits from T[0..<8]      shown by J, typed by S
      starter's code = 6 decimal digits from T[8..<16]     shown by S only once J's code was accepted, typed by J
```

A code is `big-endian UInt64 mod 10^6`, zero-padded (the bias is below 2^-44). A device accepts the other's code by
comparing what was typed with its own `T`; three wrong entries end the session. A session lives in memory only: a
lock, a restart or ten minutes without progress (the injected clock) abandons it, and a new one draws everything
fresh. The same account on both ends is refused. When both codes are accepted each device pins the other's bundle
through `VerifiedContacts` with a method of its own (`sharingCode`), from evidence only a completed session can
produce (the typing discipline of `VerifiedContact` and `NormalizedHost`).

What the people do, typed: the inviter reads eight digits; the invitee types them and reads six back; the inviter
types those and reads six; the invitee types those. Fourteen digits typed on one side, six on the other, in place of
some three hundred pasted and compared characters.

### Scanning
On iPhone and iPad a device can scan; every device can show. The starter's QR code is
`"WWSC1-" ‖ number ‖ fingerprint code of S` (the existing `WWFP1` payload: account and full fingerprint digest), and
the joiner's is its `WWFP1` code. A scan replaces typing in one direction and is stronger than it:

- J scanning S's code learns the number (nothing is typed), and authenticates `bundleS'` by its whole fingerprint
  (`VerificationMethod.scannedCode`), so J does not type the starter's code.
- S may scan J's code in place of typing the joiner's code, authenticating `bundleJ'` the same way.

Each direction is therefore a scan or six typed digits, independently, which is what a Mac (which shows but does not
scan) and an iPhone need: the iPhone scans the Mac's screen, and the Mac's person types six digits from the
iPhone's. A scanned code comes from the live camera only, never from the photo library or the pasteboard: a pasted
code names an account and proves nothing (review of the account screens, finding 2, unchanged).

### After the session
With both pins made, the starter chooses the vault and role and invites as before (`VaultSession.invite`); the
`Invitation` is delivered as one more object of the session, signed by the starter's now-verified key, so nothing
is pasted. Acceptance runs every existing check. **No vouching:** if the starter is an administrator and not the
vault's owner, the invitee still needs the owner pinned by a session (or fingerprint) of its own before the chain is
anchored. An administrator's word for the owner's keys would be a weaker pin stored under the owner's account,
usable later to wrap another vault's key to the wrong person; the household case is the owner inviting.

### What stays, and what goes
- The 60-digit fingerprint stays as a fallback for two people who cannot be at their devices together, typed and
  checked by the device (`VerificationMethod.safetyNumber`), behind a secondary action.
- "I compared them myself" (`comparedByEye`) is no longer offered or accepted: it is the unchecked claim of G3. Its
  raw value stays reserved.
- Pasting an account ID or a fingerprint code to name an account stays only with that fallback.

## Security analysis
The adversary is A1 with the board and the directory (it can read, drop, delay, reorder, replace and invent every
object, and answer each device differently); A4 and A5 are covered where they differ. The people's channel is
authentic and public.

- **An adversary in the middle** must make `T` agree on two sessions it runs back to back. Toward S it must supply
  a reply before S reveals `Ns`, and `C` hides `Ns` (32 random bytes under SHA-256), so it cannot predict S's `T`.
  Toward J it must supply a commitment before J sends `Nj`, and the commitment binds its nonce, so it cannot adjust
  afterwards. Whichever order it interleaves the two, one `T` is fixed before the other is known, and they agree in
  the six digits a person will type with probability 10^-6 per direction per session. That is G1's bound; it is
  Bluetooth numeric comparison's, and the constant is one line to raise.
- **Substituted bundles.** `T` covers both bundles as each device holds them, the account IDs, the roles (by
  position) and the session, so a directory that lies to either device changes that device's `T`. A reply or
  commitment replayed from another session meets fresh nonces on the honest side.
- **The reveal is made once.** S never reveals before it holds the reply and never reveals for a second reply: a
  reply written after `Ns` is public could be searched for. One reply slot, created once, and a session abandoned on
  restart, make that structural.
- **Retries.** A typed code is compared with a value fixed for the session, so three tries for a slip of the finger
  give the adversary nothing; what would is a new session, and every failed one is seen by both people (G2). (As
  built, the value typed must not change either: a joiner never answers a number it already answered, or a board
  serving a fresh commit would make each retry a new joiner session against the same starter one; V23.) An
  operator attacking every session succeeds in one of a million and visibly breaks the rest.
- **Sniping and denial of service.** The number is for finding the session and carries no security: anyone who
  guesses it can take the reply slot, and the session then fails at the first code. The board is fetched by name
  only, so finding sessions means guessing among 10^8 names; A1 can refuse service in any case.
- **Privacy.** The board shows two account IDs to whoever knows the number, and to A1 that two accounts paired.
  Account IDs are random and already public in the directory, and A1 already sees a share's participants.
- **The people's channel.** A voice imitated on a call, or a person persuaded to type digits from a message, defeats
  this as it defeats every out-of-band comparison. The screens say whose screen the digits come from, and nothing
  else can be done in the protocol.
- **Scans.** A scan's strength is the fingerprint's (full digest), independent of the session; mixing a scan one way
  with typed digits the other way composes, because each direction's check stands alone. A code shown by the wrong
  person is that person's account: the device names what it is about to pin, and membership lists show it. (As built:
  the person taps the code to scan among those in view, a joiner's scan counts only once the starter's reveal opened
  its commitment, and it is pinned on the person's yes to the account named; V18.)
- **A4, A5.** A member or former member gains nothing here that A1 does not have; `MemberKeyCheck` still refuses a
  member whose listed keys differ from the pin, however the pin was made.
- **Lock.** A session holds nonces and public values, no key material; pinning signs with the account key, so a
  lock ends the session and `lock()` wins as everywhere (`requireKeys(since:)`).

## Consequences
- Verifying needs both people at their devices at the same time, and the board reachable. The fingerprint fallback
  is for when they cannot.
- A new port (`SharingBoard`) with an in-memory implementation; UI tests drive two parties in process. No production
  sharing transport exists yet for either the directory or the board (`03-implementation-plan.md`, milestone 4).
- New adversarial tests in "sharing and membership" and "shared vaults through the session": a board that swaps
  bundles, replays, answers twice, reveals early or races the reply; a directory that lies to one side; wrong and
  exhausted codes; a lock mid-session; a session's evidence refused for any other session or account.
- The camera is a new permission on iOS (`NSCameraUsageDescription`), used only on the scanning screen, and cannot
  be exercised by CI: `docs/manual-tests/` lists what a person checks on real devices.

## Implementation note (2026-11-18)
Built as decided (`docs/02-architecture.md` §8.4; review in `06-adversarial-review.md` §U), with these specifics:

- The transcript hashes each bundle as `accountID ‖ X25519 key ‖ Ed25519 key`, not in `KeyBundleCodec` bytes: those
  carry the self-signature, which CryptoKit randomises, so a device's own bundle and the directory's copy would hash
  apart (V12). The self-signature says nothing about whose keys they are. As built, the transcript writes each account
  ID twice, `S.account ‖ keys(S)` with `keys(S)` beginning with the same ID (and likewise for J); the layout is pinned
  by a hashlib known-answer vector (V30) and written out in §8.4.
- Board objects carry the session ID in every message (`"WWVS" ‖ version ‖ kind ‖ session ‖ …`), so a reply or reveal
  of another session is refused at once; the invitation object is `"WWVI"`, bound to the session, its number and the
  joiner. Each device's lookup in the directory happens once, before its own nonce is published.
- A lock is checked after the board and the directory answer and before anything is held or published (V9); one step
  of a session runs at a time.
- The full-code fallback's screens show this device's own sixty digits and none of the directory's for the other
  account: the person types the code the other device shows, so a directory that publishes its own keys under that
  account cannot be passed by copying the screen (V17, from the follow-up audit of the sharing surface).
- The invitation's board name carries the session (`…/invitation/<session>`), and sending it is resumable: once
  issued it is delivered again, never issued twice, and if its slot was taken the starter hands it over as text (V22).
  An issued invitation is kept outside the session until delivered, so a session that ends after `invite` returned
  loses nothing: a later session with the same invitee delivers it, and the fallback shows it as text (V35).
- A scan is the person's choice and is named before it is pinned (V18): the scanner hands over only the code tapped;
  a joiner's scan is evidence only after the starter's reveal opened its commitment, and the screen names the account
  and pins it on a yes (`confirmScannedSharingPartner`). Nothing unpinned outlives the session. What the person
  compares is the **account check**, the first four groups of the scanned keys' fingerprint, which every step of the
  other screen shows for its own keys (V34): an 8-hex prefix of an account ID, which its holder chooses, could be
  ground in 2^32 tries; twenty fingerprint digits cost about 2^66. Reveal and commit are unsigned, so the reveal shows
  a live session, not that the account's device took part (V37).
- A start or a join ends the running session first and re-checks the lock and the session after every wait (V20),
  and each screen drives only the session it started, by its `runID` (V25): one session object serves every window.
- A session never replaces a pin on its own. "Keys changed" is settled only by the person's explicit choice, and only
  to keys a vault's chain lists for that account (V13, an owner decision still open).
- No production board adapter exists yet, as none exists for the directory, and a release build configures no sharing
  at all; sessions run in tests and in a `--uitest` launch. A configuration with a directory and no board offers the
  full code only (`SharedVaultError.sharingBoardNotConfigured`).
