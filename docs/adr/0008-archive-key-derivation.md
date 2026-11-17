# ADR 0008: The encrypted Watchword archive is sealed under the passphrase and the Secret Key

Status: accepted. Date: 2026-11-16.

## Context
PRD F8.4 asks for "an encrypted Watchword archive": a whole-account backup in a format only Watchword reads
(`02-architecture.md` §14.1). Its items are sealed under a fresh archive key, and that key must be wrapped under
something the person can supply when they restore. Two candidates:

1. **PBKDF2 over a passphrase the person chooses for the archive**, with `KDFParameters`' two-sided bounds. The
   archive opens with the passphrase alone: someone who has lost everything else, Emergency Kit included, can still
   restore.
2. **Two-secret derivation**: the same passphrase combined with the account's Secret Key, as the account password is
   (ADR 0003). The archive opens only with the passphrase *and* the Emergency Kit of the account that made it.

What decides it is where archives end up. A backup file is most likely saved where files sync: iCloud Drive, or
whatever file provider the vault itself syncs through, which is adversary A1's ground (`02-architecture.md` §2). The
account's ciphertext there resists offline guessing because of the 128-bit Secret Key; that is the reason 2SKD
exists. An archive under the passphrase alone would sit beside it as the one object A1 could guess at, as strong as
the person's choice of passphrase and the iteration count, and it holds every item of the account.

## Decision
**Option 2.** The archive's wrapping key is

```
salt' = HKDF-SHA256(ikm: salt, salt: archiveID, info: "WW-archive-salt-v1")
Kp    = PBKDF2-HMAC-SHA256(NFKD(passphrase), salt', iterations)
Ks    = HKDF-SHA256(ikm: SK, salt: accountID, info: "WW-archive-2SKD-v1")
AWK   = HKDF-SHA256(ikm: Kp ‖ Ks, salt: archiveID ‖ accountID, info: "WW-archive-key-v1")
```

(`ArchiveKeyDerivation`). Every info string differs from the account's, and the archive ID salts both the PBKDF2
input and the combination, so no crafted header can make the wrapping key equal an Account Unlock Key, and no two
archives share one. The parameters are the session's (`KDFStrategy`), validated on both sides when an archive is
written and again when one is read. The passphrase is at least ten characters (`VaultConfiguration`'s minimum).

The archive names its account in the clear, so a restore knows which Secret Key it needs: this account's, from the
Keychain, or another account's, typed from that account's Emergency Kit (a restore into a new account after the old
one is gone).

## Consequences
- An archive is no weaker against A1 than the account it came from.
- Restoring needs the Emergency Kit. Restoring an account needs it anyway (a new device enrols with it, F5.2), and
  the archive screen says so; an archive whose account's Emergency Kit is lost cannot be opened, by anyone.
- The passphrase may be the account password; nothing stops it, and nothing depends on it being different.
- Known-answer vectors come from Python `cryptography` (`AccountArchiveTests`), including a whole archive written by
  an independent implementation of the format.
