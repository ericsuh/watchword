# Watchword — Anti-phishing design

Version 0.1 (draft). Requirements live in `01-prd.md` §5.10 (F11); the matching machinery is in
`02-architecture.md` §9; the tests are in `04-test-plan.md` §6.7 and
`Tests/WatchwordAdversarialTests/AdversarialPhishingTests.swift`.

## 1. The problem a password manager actually has

A password manager that fills credentials only on matching hosts is already a strong anti-phishing
control — stronger than a human, who cannot reliably tell `amazon.com` from `аmazon.com`. The
mitigation is real but incomplete, because of how it fails:

> The person opens a link, lands on `аmazon.com` (Cyrillic `а`), and Watchword offers nothing.
> Nothing is also what Watchword offers on a site the person has genuinely never visited. So the
> person concludes the app is being unhelpful, opens it directly, searches for "Amazon", copies
> the password, and pastes it into the attacker's form.

Silence is the vulnerability. The app was right and the person was harmed anyway. Everything below
follows from that: **refusing to fill is necessary but not sufficient; the app must also say why
it refused.**

A second, subtler failure is the over-broad scope. A scope of `com` or `co.uk` with subdomains
enabled matches any host under it. On an attacker's domain where the person has nothing saved,
such a scope becomes the *top-ranked* match and the app offers a real credential. This is
self-inflicted phishing, and it is prevented at scope-creation time rather than at fill time.

## 2. Layers

| Layer | Mechanism | Where |
| --- | --- | --- |
| L1 Prevention | Passkeys are bound to the relying party by the protocol; a phished passkey assertion is useless | `02-architecture.md` §9; PRD F6.2 |
| L2 Refusal | Fill only on a host an item is scoped to; one chokepoint, type-enforced | `AutoFillGate`, `ItemRanker`, `NormalizedHost` |
| L3 Scope hygiene | Refuse to create scopes that span unrelated owners | `ScopePolicy`, `PublicSuffix` |
| L4 Normalisation | Never let parsing invent a match that the person cannot see in the address | `HostNormalizer` |
| L5 Warning | Turn "no match" into "this resembles a site you saved, and is not it" | `PhishingDetector` |
| L6 Containment | Withhold one-time codes and clipboard on mismatch; expire the clipboard | PRD F11.4, F5.6 |

### L1 — Prefer passkeys

The only mitigation that removes the human from the loop. A passkey assertion carries the relying
party identifier and is signed over `clientDataHash`; an attacker on a look-alike domain cannot
obtain a usable assertion for the real one. The app therefore:

- offers conditional passkey upgrade wherever a site supports it (`performWithoutUserInteractionIfPossible(passkeyRegistration:)`);
- marks password-only items for sites known to support passkeys in the Watchtower report;
- refuses a passkey assertion whose relying party does not match the stored `rpID`, regardless of
  what the person selected.

### L2 — One chokepoint for refusal

`AutoFillGate` is the only path by which a secret reaches the operating system.

```
decide(for: identifier, among: items) -> .fill(match) | .chooseAmong([match]) | .refuse(reason)
authorize(item, for: identifier, among: items) -> Result<NormalizedHost, FillRefusal>
```

`authorize` is called even when the person explicitly picked the item, because the question is not
"did they choose it" but "is this item for this site". A UI bug, a tampered record, or a mis-ranked
list cannot become a wrong-site fill without going through a function whose refusal is tested.

Both refuse a page loaded over plain `http` first (`FillRefusal.insecurePage`, PRD F6.9, owner decision
2026-11-16): the host may be right, but on such a page an attacker on the network path can read what is
filled and rewrite the form. The person's explicit choice does not get past it, and no login is saved from
such a page.

`.chooseAmong` exists because two accounts can legitimately tie on one host (scenario S1 at
`amazon.com`). The extension must present both and fill neither automatically: auto-filling the
first of an ambiguous set is how the AWS root password ends up in a retail login form.

### L3 — Scope hygiene

`ScopePolicy.validate` refuses, at creation and edit time:

- single-label hosts (`com`, `localhost`);
- hosts that are themselves public suffixes (`co.uk`, `com.au`, `github.io`, `herokuapp.com`), with one
  exception: a shared-hosting suffix that is also its operator's own sign-in site (`wordpress.com`,
  `substack.com`, `tumblr.com`, `bandcamp.com`, and the others in `PublicSuffix.signInAtSuffix`) is accepted as
  an *exact-host* scope, subdomains off, since that spans no other owner; with subdomains, which would reach its
  tenants, it is refused like the rest. Refusing it outright left those sites with no saved login, no passkey
  and so no look-alike warning either: the silence §1 is written against (review finding Z63). A new scope for
  such a host gets that reach wherever nobody chose one (`ScopePolicy.newScope(forHost:)`: the editor, an
  imported URL, a passkey's relying party).

The embedded list in `PublicSuffix` is deliberately small and covers the country-code second-level
domains plus the "anyone can host a tenant here" platforms, where one tenant must never be treated
as a subdomain of another. Adopting the full Public Suffix List means importing a ~14,000-entry
third-party data file with a refresh process, which is a supply-chain decision in its own right —
see `07-supply-chain.md` §6.

Importers run every scope through the same policy, so a malicious or sloppy 1PUX/CSV file cannot
install a `com` scope.

The other direction is the list's known tail, not a defect of the policy: a tenant-hosting parent the
list does not name (the audit's examples were `pythonanywhere.com`, `neocities.org` and `altervista.org`)
gets an ordinary scope with subdomains from the editor, an import and the `www` apex, so a tenant's page
under it is filled with the parent account's login. That is tracked with the open full-PSL decision
(`07-supply-chain.md` §6; review entries D1 and K6); entries are added to the embedded list one at a time, with
the tradeoff noted, never wholesale.

### L4 — Normalisation that cannot invent a match

Two findings from probing `URLComponents` on the real toolchain (both now tested):

1. **`URLComponents.host` percent-decodes.** `https://x.amazon%2Ecom/` yields host `x.amazon.com`,
   which matches an `amazon.com` scope with subdomains. The encoded dot invents a label boundary
   that is invisible in the address the person sees. `HostNormalizer` therefore inspects
   `percentEncodedHost` and rejects any escape in the ASCII range, while still allowing the
   non-ASCII escapes that are how Foundation represents an IDN host (`%D0%B0mazon.com`).
2. **`trimmingCharacters(in: .whitespacesAndNewlines)` strips U+200B.** A trailing zero-width space
   was silently removed, turning `amazon.com\u{200B}` into a match for `amazon.com`. Trimming is
   now ASCII-only, so exotic characters survive to be rejected rather than normalised away.

3. **An IPv6 literal is parsed, not pattern-matched.** The branch for a host containing `:` used to
   accept any run of hex digits, colons and dots and skip every other check, so `a::b.cafe.de` was a
   "subdomain" of a saved `cafe.de`, and neither the length bound nor the IDNA mapping applied (fullwidth
   hex digits passed). It is now parsed on ASCII bytes as RFC 4291 writes an address, bounded at 45 bytes,
   and the matcher never treats a colon-bearing host as below a scope (review finding Z64).

Also rejected: user-info (`https://amazon.com@evil.example/`), non-HTTP(S) schemes, C0/C1 controls,
zero-width and bidi formatting characters, soft hyphen, empty labels, and labels or hosts beyond
the DNS limits (63/253 bytes — which also bounds the work a hostile host can make the matcher do).

What is *not* rejected, deliberately: Foundation's IDNA compatibility mapping. Fullwidth
`ＡMAZON.com` and Kelvin-sign `amazonK.com` arrive already folded to `amazon.com`, which is what a
browser resolves, so matching them is correct rather than a hole. Characters IDNA keeps distinct —
Cyrillic `а` — stay distinct and never match an ASCII scope. That is the safe outcome, and it is
exactly the silent one L5 exists to break.

### L5 — Warn instead of staying silent

`PhishingDetector.assess(host:against:)` returns one of three things:

- `.recognized` — the host matches a saved scope. Normal AutoFill. Never phishing, whatever it
  looks like.
- `.unrecognized` — nothing saved resembles it. Offer nothing and say nothing alarming; this is
  the ordinary case for a new site, and warning here would spend the warning's credibility.
- `.suspicious(signals, impersonating)` — it resembles something saved and is not it.

Signals, each independently testable:

| Signal | Catches | Example |
| --- | --- | --- |
| `confusableWithSavedScope` | Visual skeleton collapses onto a saved scope | `arnazon.com`, `amaz0n.com`, `аmazon.com` |
| `nearMiss` | Edit distance ≤ 2 on the distinctive label | `amazom.com`, `firstbamk.co.uk` |
| `savedNameOutOfPosition` | Saved site's name in a label carrying no authority | `amazon.com.evil.example`, `secure-amazon.example` |
| `mixedScript` | A single label mixing writing systems | `аmazon.com` (Cyrillic + Latin) |
| `punycode` | Renders differently than it resolves | `xn--mazon-1nf.com` |

The skeleton folds case, width, and diacritics, maps Cyrillic/Greek/leetspeak confusables to ASCII
representatives, then applies the `rn`→`m` and `vv`→`w` digraphs. Only those two digraphs: each
extra entry raises the chance that two unrelated hosts collapse together, and a false warning
spends credibility the real warning needs.

Two tuning decisions worth stating because they are what make the warning trustworthy:

- **Mixed script is tested per label, not per host.** Testing the whole host flags every real
  internationalised domain, because the top-level label is Latin even when the name is not
  (`амазон.com`). A label that mixes Cyrillic and Latin is the attack itself. This matches UTS #39,
  and the test that caught the original whole-host implementation is in the suite.
- **The same name under a different public suffix is not a signal.** `amazon.de` against a saved
  `amazon.com` is a plausible regional site, not an impersonation. Without this exception the
  `savedNameOutOfPosition` check fires on every legitimate regional sibling.

A suspicious host with an empty `impersonating` list (punycode or mixed script with no resemblance
to anything saved) earns a weaker message — "this address cannot be visually verified" — rather
than a claim about which site it imitates. `impersonatesSavedSite` distinguishes the two.

### L6 — Containment

- **One-time codes are held to the same rule as passwords.** A TOTP typed into a look-alike site is
  replayable by the attacker within its window, so `authorizeOneTimeCode` refuses on mismatch
  rather than warning. There is no "copy the code anyway" affordance in the extension.
- **Clipboard.** Secrets copied from the app expire (default 60 s) and are marked local-only.
- **Manual reveal inside the app** is the one place a determined person can still defeat all of
  this. The app cannot know what site a browser is showing, so the design does not pretend to: the
  item detail view shows the item's scopes prominently, each in its ASCII form (a Cyrillic look-alike
  shows as `xn--…`) with how far it reaches. *Not built:* an assessment banner when a secret is revealed
  on an item whose scopes the person is searching away from. Earlier text described it in the present
  tense; nothing in the app or `WatchwordPresentation` computes it, and it is tracked as open (review
  finding Z69).

## 3. User-visible flows

**Suspicious host, AutoFill invoked.** The extension shows, in place of a credential list: the
normalised host (punycode form shown explicitly when present), the saved site it resembles, and
the reason. The only actions are "Go back" and "Open the real site" (which hands the saved scope's
URL to the system). There is no "fill anyway" button — adding one converts a strong control into a
dialog people click through.

**Suspicious host, person wants to use it anyway.** The sole route is adding the host as a scope on
the item, inside the app, which requires: unlocking, opening the item, typing the host, and
confirming a warning that names the site being added and the item (PRD F11.7). That deliberate
friction is the feature. It is enforced in the session, not the view: `VaultSession.save` judges every
host a save adds (to a new item, or one the item did not have) against what the gate ranks among
(`SavedSites`, every vault) and refuses one that resembles a saved site, or cannot be verified by eye,
with `VaultError.hostsNeedConfirmation` unless the call names it in `confirmingHosts`. `ItemEditorModel`
turns that refusal into the question, one per host, naming the site as it resolves, its reach and the
item, and saves again naming exactly the hosts asked about ("Add Anyway"). Before review finding Z61 the
editor added any host the scope policy accepted, with subdomains and no question, and the detail view
then showed a Cyrillic look-alike as the real name; only the import's merge screen asked.

**A website an import would add to an existing item.** The duplicate screen (`ImportModel`, `MergeHost`) shows
each host a merge would add in its ASCII form, punycode for any label in another alphabet (`аmazon.com` is
`xn--mazon-3ve.com`), with the registrable domain in bold, how far the scope reaches ("and its subdomains", "this
address only", and its exclusions), and `PhishingDetector`'s assessment against what the gate ranks among
(`SavedSites`: trashed items and policy-refused scopes left out, and a shared vault's scope vouching only for its own
vault, so a member's item scoped to the look-alike does not make it recognised; review finding Z65). A host that
resembles a saved site, or uses another alphabet at all, carries a warning that names the site, and switching it on
asks a second time ("Accept Anyway"); so does a host that would make the item hide or stand beside another saved
account, named in the warning (review finding Z75). The session holds the rule, not the screen: `commitImport`
judges every host a merge adds against `SavedSites` and refuses one that needs it unless
`MergeChoices.confirmedHosts` names it (`mergeNeedsConfirmation`). The switch is off to begin with, as every
addition is (`MergeChoices`). Before
this, the screen showed the host as the file spelled it, so a file could offer the bank's item a look-alike that
rendered as the bank (review of the account screens, finding 3).

**A new item an import would add.** Every entry's hosts are shown the same way, and an entry that would hide a saved
account from AutoFill, stand beside one, or name a look-alike host needs a decision ("Import Anyway" or "Skip")
that names the accounts it would hide and their vaults (`ImportConcern`, review finding Z62; architecture §14).

**Checking each other before sharing** (ADR 0010). The invite screen runs a vault sharing code session: eight digits
one way, then six typed on each device from the other's screen, each compared by the device, never a "they match"
taken on the person's word (G3). The screens say whose screen the digits come from and warn against digits that
arrive in a message (`SharingCodeWording.channelWarning`): a voice imitated on a call, or a person persuaded to type
digits someone sent, defeats this as it defeats every out-of-band comparison, and nothing in the protocol can tell.
A scan reads the other person's screen with the live camera only, never the photo library or the pasteboard, so a QR
code passed on in a message is no scan. A fingerprint code (`WWFP1-…`) pasted on the fallback path only names the
account: anyone who can message the person can send a code for an account of their own, so the full code must still be
typed, and the pin records how it was made (`VerificationMethod`, S16). Whatever the evidence, the session checks it
against the bundle it pins, so a key directory that answers a later lookup with other keys gets `fingerprintMismatch`,
not a pin (review finding Z40; architecture §8.4). The role step names the account being invited and says how its keys
were checked (finding 2). Accepting an invitation from an owner verified before still asks before joining (finding
8), and an invitation whose owner is not the person just checked waits for the owner to be checked too: nobody
vouches for an owner.

**Ambiguous match.** Both accounts listed with their distinguishing field (username/email) and the
matched scope. Nothing pre-selected.

**New site.** Normal "no matching items — create one?" with no alarm.

## 4. Residual risk, stated plainly

- A person who manually copies a password out of the app and pastes it into a phishing page is not
  prevented. L5 reduces the odds; only L1 removes them.
- The confusable table and the small public-suffix list are heuristics with a tail. They will miss
  novel look-alikes and will occasionally warn on an innocent domain.
- A legitimate IDN site arriving in punycode form gets the weak warning. Acceptable noise; a
  tuning item once real-device behaviour of `ASCredentialServiceIdentifier` is known.
- An attacker who compromises the sync store can add a scope to an item, which would make a
  malicious host match. Membership and record signing (`02-architecture.md` §8) is what defends
  that, not this document.
- Scope matching depends on the OS reporting the true host. A compromised OS is out of scope.
- Text insertion (PRD F6.4) is requested by the system without naming a site, so there is no host to
  check and no mismatch to detect. `CredentialProviderModel` then lets the person pick an item by hand,
  as they would in the app, and inserts only fields that are not secrets (user names, emails, phone,
  account and card numbers, dates). Passwords, one-time codes, passkeys, recovery codes, API keys,
  security answers and PINs cannot leave that way (`02-architecture.md` §9.2): each is replayable by a
  look-alike page, which is F11.4's reason for withholding a code instead of warning about it. They are
  inserted as text where the system does name the host, through the gate, and otherwise copied from the
  app, where the item's scopes are in view. This narrows F6.4 as written and is the owner's to revisit.
- QuickType suggestions are offered by the operating system's own domain matching, and a tap does not
  tell the extension which page it came from. Watchword therefore publishes a password or code identity
  only for an item that is the right answer on every page of its site (`02-architecture.md` §9.1); the
  two Amazon accounts of S1, a login saved for one exact host, and a tenant of a shared host are reached
  through the extension's list instead. What the system really matches on is unverified until
  milestone 5's on-device QA; the rule assumes the widest case.
- Plain `http` (F6.9). The gate refuses a page loaded over `http`, but two cases cannot be refused in the
  extension. A form on an `https` page that *submits* to an `http` address is filled: the credential
  provider API names the page, not the form's action. And a QuickType suggestion the system offers on an
  `http` page is filled when tapped, because the tap hands back the published identity (a domain, with no
  scheme) and not the page; a scope records no scheme, so there is nothing to withhold the identity on. The
  hygiene report flags every saved `http://` address, and no login is saved from an `http` page.
