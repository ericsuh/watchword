import Foundation
import WatchwordMatching
import WatchwordModel

/// Why a request stopped before producing a value. Internal: each public method maps it to its own outcome type.
enum Blocked: Error {
    case locked
    case refused(ProviderRefusal)
}

/// A concrete wrapper, because the generators take `inout some RandomNumberGenerator` and an existential cannot be
/// passed there directly.
struct InjectedGenerator: RandomNumberGenerator, Sendable {
    var base: any RandomNumberGenerator & Sendable

    mutating func next() -> UInt64 {
        base.next()
    }
}

/// Every decision the credential provider extension makes, and every byte it returns (PRD F6, F11;
/// docs/02-architecture.md §9.1).
///
/// The extension is an adapter: it converts each AuthenticationServices request into a call here, shows what the
/// returned value describes, and hands back what it carries. It holds no matching, no cryptography and no policy of
/// its own, so the security-relevant behaviour of AutoFill is this actor, tested on every platform with fakes.
///
/// Invariants:
/// - **One gate.** A password, a one-time code, a passkey assertion or text for a named host is read only through
///   an `Authorization`, which only `ReleaseGate.authorize` creates and only after `AutoFillGate.authorize` (or
///   `authorizeOneTimeCode`) has accepted that item for that host. An explicit choice by the person is re-checked
///   like any other (SEC6, F11.1).
/// - **No override.** No request, parameter or configuration releases anything for a host the gate refused (F11.4,
///   F11.7). A look-alike host gets a `LookAlikeWarning` in place of a list (F11.3), not a list with a caveat.
/// - **The page, or nothing.** The gate is asked about a host only when the system named it for *this* request: the
///   identifiers of a list request, the relying party of a passkey request, the identifier of a save. A QuickType
///   tap names no page (the system hands back the identity Watchword published), so it is answered only for an
///   identity `CredentialIdentityPlanner` would publish now, which is one that is right on every page of its site.
/// - **Locked is a state.** With no keys the answer is `vaultLocked` (or `requiresInteraction(.vaultLocked)`); the
///   extension unlocks and asks again. The items of each request are read once, at its start, and every step of an
///   interactive flow reads them afresh. A request that hands back a secret confirms the vault is still unlocked
///   as its last suspension, so a lock that lands while it runs wins.
/// - **The page is not trusted.** Service identifiers, relying party IDs, user names, password rules and reports
///   all originate with a web page or an app (adversary A6). Each is bounded and validated here, whatever the
///   operating system has already checked.
/// - **A remote party never deletes.** Reports flag fields and rename passkey accounts, at a bounded rate; saving a
///   password adds a version. Nothing here removes a field, an item or a history entry (F6.7, F1.4).
public actor CredentialProviderModel {
    let vault: any CredentialVault
    let clock: any AutoFillClock
    let publisher: (any CredentialIdentityPublisher)?
    var random: InjectedGenerator

    /// - Parameter publisher: When set, the identities of an item this model writes are republished after the
    ///   write, best effort: a failure there never fails the request, and the app republishes everything at its next
    ///   unlock.
    public init(
        vault: any CredentialVault, clock: any AutoFillClock = SystemAutoFillClock(),
        publisher: (any CredentialIdentityPublisher)? = nil,
        random: any RandomNumberGenerator & Sendable = SystemRandomNumberGenerator()
    ) {
        self.vault = vault
        self.clock = clock
        self.publisher = publisher
        self.random = InjectedGenerator(base: random)
    }

    // MARK: - Credential list (PRD F6.1, F6.6)

    /// The list for `prepareCredentialList`: logins the gate would release for the named hosts and, when `passkey` is
    /// given, the passkeys of its relying party. Nothing else: an account the ranker shadows on the host (one that
    /// matches less specifically than another) is never released there, so it is not listed either; it stays
    /// reachable in the app (PRD F6.6, owner decision 2026-11-16).
    ///
    /// When nothing matches and a host resembles a saved site, the answer is the warning instead of an empty list
    /// (F11.3). A page loaded over plain `http` lists nothing, and when it is the only page named the answer is
    /// `refused(.gate(.insecurePage))` (F6.9). When the system names no site at all there is nothing to authorise a
    /// password for, and a request without passkey parameters is refused.
    public func credentialList(
        for identifiers: [ServiceIdentifier], passkey request: PasskeyAssertionRequest? = nil
    ) async -> CredentialListOutcome {
        let snapshot: VaultSnapshot
        switch await loadResult() {
        case .success(let loaded): snapshot = loaded
        case .failure(.locked): return .vaultLocked
        case .failure(.refused(let refusal)): return .refused(refusal)
        }
        guard !identifiers.isEmpty || request != nil else { return .refused(.noServiceIdentifier) }

        let matching = Matching(identifiers: identifiers, snapshot: snapshot)
        var passwords: [PasswordEntry] = []
        for match in matching.primary where match.item.field(.password) != nil {
            let names = match.item.loginNames.filter { !$0.isEmpty }
            for name in names.isEmpty ? [""] : names {
                passwords.append(Self.passwordEntry(match, userName: name, in: snapshot))
            }
        }
        var suggested: PasswordEntry?
        if let only = matching.onlyFill, let first = passwords.first, first.itemID == only {
            suggested = first
        }

        var passkeys: [PasskeyEntry] = []
        var passkeyRefusal: ProviderRefusal?
        var assessedHosts = matching.hosts
        if let request {
            do {
                let relyingParty = try Self.relyingParty(request.relyingPartyID)
                try Self.checkCredentialList(request.allowedCredentialIDs)
                passkeys = Self.passkeyEntries(
                    for: relyingParty, allowed: request.allowedCredentialIDs, in: snapshot)
                if let host = try? HostNormalizer.normalize(relyingParty.serviceIdentifier),
                    !assessedHosts.contains(host)
                {
                    assessedHosts.append(host)
                }
            } catch {
                if case .refused(let refusal) = Self.blocked(error) { passkeyRefusal = refusal }
            }
        }

        if passwords.isEmpty && passkeys.isEmpty {
            if let warning = Self.warning(for: assessedHosts, in: snapshot) {
                return .warning(warning)
            }
            if matching.hosts.isEmpty, let page = matching.insecurePages.first {
                return .refused(.gate(.insecurePage(page)))
            }
            if assessedHosts.isEmpty, let error = matching.firstError {
                return .refused(passkeyRefusal ?? .gate(.unusableIdentifier(error)))
            }
        }
        return .list(
            CredentialList(
                hosts: assessedHosts.map(\.value), passwords: passwords, passkeys: passkeys, suggested: suggested,
                passkeyRefusal: passkeyRefusal))
    }

    /// The password for a login the person chose in the extension's list. The choice is authorised again here: what
    /// the list showed is not evidence (SEC6).
    public func password(
        for choice: PasswordChoice, identifiers: [ServiceIdentifier]
    ) async -> Outcome<PasswordCredential> {
        func run() async throws -> PasswordCredential {
            let snapshot = try await self.load()
            let authorization = try Self.unwrap(
                ReleaseGate.authorize(itemID: choice.itemID, for: identifiers, in: snapshot))
            return try await self.releasing(try Self.unwrap(authorization.password(userName: choice.userName)))
        }
        do {
            return .success(try await run())
        } catch {
            return Self.failure(error)
        }
    }

    /// The password for a QuickType suggestion, with no UI (`provideCredentialWithoutUserInteraction(for:)`, and
    /// again from `prepareInterfaceToProvideCredential(for:)` once the extension has unlocked the vault).
    ///
    /// The system hands back the identity Watchword published and does not name the page, so the request's
    /// identifier is a lookup key and the gate cannot be asked about where the person is. The password is released
    /// only if the identity is one `CredentialIdentityPlanner` would publish for the vault as it is now: the item
    /// is for every page of that site, no other account is more specific anywhere on it, and none shares the user
    /// name tapped. The gate is then asked about the identity's own host, like any release. An identity that no
    /// longer qualifies needs the person, in the extension's list, which is told the page (PRD F6.6, F11.5, S1).
    ///
    /// Because the page is not named, a QuickType fill on a page loaded over plain `http` cannot be refused here:
    /// the identity is a domain, and nothing in the request says which scheme the page was loaded with (F6.9;
    /// docs/02-architecture.md §9.2). An identifier that is itself an `http` URL is refused like any other.
    public func passwordWithoutInteraction(
        for request: PasswordIdentityRequest
    ) async -> SilentOutcome<PasswordCredential> {
        func run() async throws -> SilentOutcome<PasswordCredential> {
            guard let record = RecordIdentifier(request.recordIdentifier), record.fieldID == nil else {
                throw Blocked.refused(.unknownRecord)
            }
            let snapshot = try await self.load()
            let item = try Self.unwrap(snapshot.itemInUse(record.itemID))
            let host = try Self.publishedHost(request.serviceIdentifier)
            let standing = Self.standing(of: item, in: snapshot) {
                guard case .password(let identity) = $0 else { return false }
                return identity.host == host.value && identity.user == request.user
            }
            if let reason = standing { return .requiresInteraction(reason) }
            let authorization = try Self.unwrap(
                ReleaseGate.authorize(
                    itemID: item.id, for: [ServiceIdentifier(host.value, kind: .domain)], in: snapshot)
            )
            return .success(try await self.releasing(try Self.unwrap(authorization.password(userName: request.user))))
        }
        do {
            return try await run()
        } catch {
            return Self.silentFailure(error)
        }
    }

    // MARK: - One-time codes (PRD F6.3, F11.4)

    /// The list for `prepareOneTimeCodeCredentialList`. On a host nothing is scoped to there are no entries, and on
    /// a look-alike the warning: a code is withheld on a mismatch, never offered with a caveat.
    public func oneTimeCodeList(for identifiers: [ServiceIdentifier]) async -> OneTimeCodeListOutcome {
        let snapshot: VaultSnapshot
        switch await loadResult() {
        case .success(let loaded): snapshot = loaded
        case .failure(.locked): return .vaultLocked
        case .failure(.refused(let refusal)): return .refused(refusal)
        }
        guard !identifiers.isEmpty else { return .refused(.noServiceIdentifier) }
        let matching = Matching(identifiers: identifiers, snapshot: snapshot)
        var entries: [OneTimeCodeEntry] = []
        for match in matching.primary {
            let item = match.item
            for field in item.fields where field.kind == .totp && (try? field.otpParameters()) != nil {
                entries.append(
                    OneTimeCodeEntry(
                        itemID: item.id, fieldID: field.id, vault: snapshot.vault(of: item), title: item.title,
                        userName: item.loginNames.first { !$0.isEmpty } ?? "", label: field.label))
            }
        }
        if entries.isEmpty && matching.primary.isEmpty {
            if let warning = Self.warning(for: matching.hosts, in: snapshot) { return .warning(warning) }
            if matching.hosts.isEmpty, let page = matching.insecurePages.first {
                return .refused(.gate(.insecurePage(page)))
            }
            if matching.hosts.isEmpty, let error = matching.firstError {
                return .refused(.gate(.unusableIdentifier(error)))
            }
        }
        return .list(entries)
    }

    /// The current code of a field the person chose.
    public func oneTimeCode(for choice: FieldChoice, identifiers: [ServiceIdentifier]) async -> Outcome<OneTimeCode> {
        func run() async throws -> OneTimeCode {
            let snapshot = try await self.load()
            let authorization = try Self.unwrap(
                ReleaseGate.authorize(
                    itemID: choice.itemID, for: identifiers, in: snapshot, purpose: .oneTimeCode))
            let now = await self.clock.now()
            return try await self.releasing(
                try Self.unwrap(authorization.oneTimeCode(fieldID: choice.fieldID, at: now)))
        }
        do {
            return .success(try await run())
        } catch {
            return Self.failure(error)
        }
    }

    /// The current code for a published one-time code identity, with no UI. The rule of
    /// `passwordWithoutInteraction(for:)`: the identity names no page, so it must be one the planner would publish
    /// now, and a code is withheld otherwise (F11.4).
    public func oneTimeCodeWithoutInteraction(
        for request: OneTimeCodeIdentityRequest
    ) async -> SilentOutcome<OneTimeCode> {
        func run() async throws -> SilentOutcome<OneTimeCode> {
            guard let record = RecordIdentifier(request.recordIdentifier), let fieldID = record.fieldID else {
                throw Blocked.refused(.unknownRecord)
            }
            let snapshot = try await self.load()
            let item = try Self.unwrap(snapshot.itemInUse(record.itemID))
            let host = try Self.publishedHost(request.serviceIdentifier)
            let standing = Self.standing(of: item, in: snapshot) {
                $0
                    == .oneTimeCode(
                        OneTimeCodeIdentity(host: host.value, label: request.label, recordIdentifier: record))
            }
            if let reason = standing { return .requiresInteraction(reason) }
            let authorization = try Self.unwrap(
                ReleaseGate.authorize(
                    itemID: item.id, for: [ServiceIdentifier(host.value, kind: .domain)], in: snapshot,
                    purpose: .oneTimeCode))
            let now = await self.clock.now()
            return .success(
                try await self.releasing(try Self.unwrap(authorization.oneTimeCode(fieldID: fieldID, at: now))))
        }
        do {
            return try await run()
        } catch {
            return Self.silentFailure(error)
        }
    }

    // MARK: - Text to insert (PRD F6.4)

    /// The items and fields the person may insert as text on a site or in an app the system named.
    ///
    /// Gated like any other request: only items the gate would release for the host are listed, with every field
    /// but the passkey, and a look-alike host gets the warning. With no identifier there is no host to authorise
    /// anything for and the request is refused; the request the system makes without naming a site is
    /// `textInsertionListWithoutHost()`, a different question with a much smaller answer.
    public func textInsertionList(for identifiers: [ServiceIdentifier]) async -> TextInsertionListOutcome {
        let snapshot: VaultSnapshot
        switch await loadResult() {
        case .success(let loaded): snapshot = loaded
        case .failure(.locked): return .vaultLocked
        case .failure(.refused(let refusal)): return .refused(refusal)
        }
        guard !identifiers.isEmpty else { return .refused(.noServiceIdentifier) }
        let matching = Matching(identifiers: identifiers, snapshot: snapshot)
        if matching.primary.isEmpty {
            if let warning = Self.warning(for: matching.hosts, in: snapshot) { return .warning(warning) }
            if matching.hosts.isEmpty, let page = matching.insecurePages.first {
                return .refused(.gate(.insecurePage(page)))
            }
            if matching.hosts.isEmpty, let error = matching.firstError {
                return .refused(.gate(.unusableIdentifier(error)))
            }
        }
        let items = matching.primary.compactMap {
            Self.insertableItem($0.item, in: snapshot, including: { $0 != .passkey })
        }
        return .list(TextInsertionList(items: items, hostVerified: true))
    }

    /// The text of the field the person chose, for a host the system named. Authorised by the gate; refused with no
    /// identifier.
    public func textToInsert(for choice: TextChoice, identifiers: [ServiceIdentifier]) async -> Outcome<TextToInsert> {
        func run() async throws -> TextToInsert {
            let snapshot = try await self.load()
            guard !identifiers.isEmpty else { throw Blocked.refused(.noServiceIdentifier) }
            // A one-time code is held to the one-time code rule whichever request asks for it.
            let isCode =
                (try? snapshot.item(choice.itemID).get())?.fields.first { $0.id == choice.fieldID }?.kind == .totp
            let authorization = try Self.unwrap(
                ReleaseGate.authorize(
                    itemID: choice.itemID, for: identifiers, in: snapshot, purpose: isCode ? .oneTimeCode : .credential)
            )
            let now = await self.clock.now()
            return try await self.releasing(
                try Self.unwrap(authorization.text(fieldID: choice.fieldID, part: choice.part, at: now)))
        }
        do {
            return .success(try await run())
        } catch {
            return Self.failure(error)
        }
    }

    /// The list for the system's own text-insertion request, which names no site or app
    /// (`prepareInterfaceForUserChoosingTextToInsert()` has no parameters).
    ///
    /// With no host there is nothing for the gate to check and no mismatch to detect, so nothing that is a secret
    /// can leave this way: the list is every item in use, picked by hand as it would be in the app, with only the
    /// fields that are not secrets (user names, emails, phone, account and card numbers, dates, addresses). It is a
    /// separate request, not the gated one with an empty list of identifiers, so that an adapter that lost the
    /// identifiers gets a refusal instead of this.
    public func textInsertionListWithoutHost() async -> TextInsertionListOutcome {
        switch await loadResult() {
        case .success(let snapshot):
            let items = snapshot.inUse.sorted { $0.title < $1.title }.compactMap {
                Self.insertableItem($0, in: snapshot, including: ManualChoice.isInsertable)
            }
            return .list(TextInsertionList(items: items, hostVerified: false))
        case .failure(.locked):
            return .vaultLocked
        case .failure(.refused(let refusal)):
            return .refused(refusal)
        }
    }

    /// The text of a field the person picked from `textInsertionListWithoutHost()`. Any secret is
    /// `refused(.fieldWithheld)`, whatever the list showed.
    public func textToInsertWithoutHost(for choice: TextChoice) async -> Outcome<TextToInsert> {
        func run() async throws -> TextToInsert {
            let snapshot = try await self.load()
            let manual = try Self.unwrap(ReleaseGate.manualChoice(itemID: choice.itemID, in: snapshot))
            return try await self.releasing(try Self.unwrap(manual.text(fieldID: choice.fieldID, part: choice.part)))
        }
        do {
            return .success(try await run())
        } catch {
            return Self.failure(error)
        }
    }

    /// Marks one recovery code spent (or unspent) after the person used it (scenario S2). Releases nothing.
    public func markRecoveryCode(_ choice: FieldChoice, index: Int, used: Bool = true) async -> Outcome<Bool> {
        func run() async throws -> Bool {
            let snapshot = try await self.load()
            let item = try Self.unwrap(snapshot.itemInUse(choice.itemID))
            guard
                let position = item.fields.firstIndex(where: { $0.id == choice.fieldID && $0.kind == .recoveryCodes }),
                item.fields[position].recoveryCodes.indices.contains(index)
            else { throw Blocked.refused(.unknownRecord) }
            var updated = item
            updated.fields[position].markRecoveryCode(at: index, used: used)
            guard updated != item else { return false }
            _ = try await self.save(updated, replacing: item)
            return true
        }
        do {
            return .success(try await run())
        } catch {
            return Self.failure(error)
        }
    }

    // MARK: - Identities (PRD F6.1, F6.8)

    /// Replaces the published identities with those of the unlocked items. The number published.
    public func publishAllIdentities() async -> Outcome<Int> {
        func run() async throws -> Int {
            guard let publisher = self.publisher else { return 0 }
            let snapshot = try await self.load()
            do {
                return try await CredentialIdentityPublishing.publish(snapshot, to: publisher).count
            } catch {
                throw Blocked.refused(.vault(.failed("identity store")))
            }
        }
        do {
            return .success(try await run())
        } catch {
            return Self.failure(error)
        }
    }

    // MARK: - Shared machinery

    /// Hands `value` back only if the vault is still unlocked: the last suspension of every request that releases
    /// a secret. The items were read at the start of the request, and a lock since then must win.
    func releasing<Value>(_ value: Value) async throws -> Value {
        do {
            try await vault.confirmUnlocked()
        } catch {
            throw Self.blocked(error)
        }
        return value
    }

    /// The items of this request. Every vault error but `locked` is a refusal.
    func load() async throws -> VaultSnapshot {
        do {
            return VaultSnapshot(try await vault.credentialSnapshot())
        } catch {
            throw Self.blocked(error)
        }
    }

    func loadResult() async -> Result<VaultSnapshot, Blocked> {
        do {
            return .success(try await load())
        } catch {
            return .failure(Self.blocked(error))
        }
    }

    /// Writes `item` over `old` (or creates it), as a compare-and-swap on the version read, then republishes its
    /// identities. A conflict is reported, not retried: whoever asked decides again on what is there now.
    /// `confirmingHosts`: the hosts of a new item whose look-alike warning the person was shown and confirmed past
    /// (`NewItemProposal.warning`); empty for everything done without the person.
    func save(_ item: Item, replacing old: Item?, confirmingHosts: Set<String> = []) async throws -> Item {
        let stored: Item
        do {
            stored = try await vault.saveCredentialItem(
                item, replacingVersion: old?.version, confirmingHosts: confirmingHosts)
        } catch {
            throw Self.blocked(error)
        }
        if let publisher {
            let vault = vault
            _ = try? await CredentialIdentityPublishing.publishChange(
                from: old, to: stored, all: { try await vault.credentialSnapshot() }, to: publisher)
        }
        return stored
    }

    static func blocked(_ error: any Error) -> Blocked {
        if let blocked = error as? Blocked { return blocked }
        guard let vaultError = error as? CredentialVaultError else {
            // The type's name only: an arbitrary error's description could carry anything.
            return .refused(.vault(.failed(String(describing: type(of: error)))))
        }
        switch vaultError {
        case .locked: return .locked
        case .scopeRejected(let reason): return .refused(.scopeRejected(reason))
        default: return .refused(.vault(vaultError))
        }
    }

    static func unwrap<Value>(_ result: Result<Value, ProviderRefusal>) throws -> Value {
        switch result {
        case .success(let value): return value
        case .failure(let refusal): throw Blocked.refused(refusal)
        }
    }

    /// The outcome for a request the person takes part in that stopped with `error`.
    static func failure<Value>(_ error: any Error) -> Outcome<Value> {
        switch blocked(error) {
        case .locked: return .vaultLocked
        case .refused(let refusal): return .refused(refusal)
        }
    }

    /// The outcome for a request made without the person that stopped with `error`.
    static func silentFailure<Value>(_ error: any Error) -> SilentOutcome<Value> {
        switch blocked(error) {
        case .locked: return .requiresInteraction(.vaultLocked)
        case .refused(let refusal): return .refused(refusal)
        }
    }

    /// The host of an identity the system handed back: the identifier Watchword published, read as the gate reads a
    /// page, so an `http` URL in its place is refused (F6.9).
    static func publishedHost(_ identifier: ServiceIdentifier) throws -> NormalizedHost {
        switch AutoFillGate.page(identifier) {
        case .success(let host): return host
        case .failure(let refusal): throw Blocked.refused(.gate(refusal))
        }
    }

    /// Whether an identity the system handed back is one Watchword would publish for `item` now: `nil` if it is,
    /// and otherwise why the person is needed. `matches` picks the identity out of the planner's list.
    static func standing(
        of item: Item, in snapshot: VaultSnapshot, _ matches: (CredentialIdentity) -> Bool
    ) -> InteractionReason? {
        if CredentialIdentityPlanner.identities(for: item, in: snapshot).contains(where: matches) { return nil }
        // Published for the item on its own, so it is the other items that stand in the way.
        if CredentialIdentityPlanner.identities(for: item, in: snapshot.only(item)).contains(where: matches) {
            return .ambiguousMatch
        }
        return .staleIdentity
    }

    /// What creating an item scoped `narrow` would do to the accounts already offered on `host`, and the scope that
    /// would put it beside them instead.
    ///
    /// `narrow` is the scope a request asks for on its own terms: the exact host of a saved login, the relying party
    /// of a passkey. Where the accounts already offered on the host match it less specifically (a login for
    /// `amazon.com` and its subdomains, on `www.amazon.com`), an item scoped `narrow` outranks them, and the gate
    /// refuses an outranked item even when the person chooses it: the first account would drop out of AutoFill on
    /// that host. That is right when the new login is a different service under the same domain (scenario S1) and
    /// wrong when it is a second account on the same one, and nothing in the request says which. So the model does
    /// neither on its own: the proposal says how many accounts would be hidden, and offers the scope of the person's
    /// own most specific matches as the alternative, which makes the accounts tie, and a tie is the person's to
    /// choose from (PRD F6.6, F11.5).
    ///
    /// The new item goes into the default vault, which is the person's own, so it outranks less specific items of
    /// every vault, shared ones included, and all of those are counted as hidden. The scope offered for copying is
    /// only ever one the person gave an item of their own and the scope policy accepts: an item of a shared vault
    /// carries whatever scope a member chose, and copying that into a new item would let the member widen it
    /// (review finding Z60). The person's own most specific matches share the scope's host by construction, and
    /// where they differ on subdomains or exclusions the narrower holds.
    static func newItemProposal(
        title: String, narrow: ServiceScope, on host: NormalizedHost, userName: String, warning: LookAlikeWarning?,
        in snapshot: VaultSnapshot
    ) throws -> (proposal: NewItemProposal, sharedScope: ServiceScope?) {
        let destination = try newItemVault(in: snapshot)
        func proposal(hidden: Int, beside: SharedScopeProposal?) -> NewItemProposal {
            NewItemProposal(
                vault: destination, title: title, scopeHost: narrow.host, includesSubdomains: narrow.includeSubdomains,
                userName: userName, warning: warning, hiddenAccounts: hidden, besideExisting: beside)
        }
        guard let own = ScopeMatcher.match(narrow, host: host) else { return (proposal(hidden: 0, beside: nil), nil) }
        // Only accounts in use can be hidden from the person, or stood beside: an archived or excluded item that
        // is outranked loses nothing, and its scope is not offered for copying.
        let outranked = snapshot.offered(on: host).filter {
            $0.match.specificity < own.specificity && snapshot.isInUse($0.item)
        }
        guard !outranked.isEmpty else { return (proposal(hidden: 0, beside: nil), nil) }

        // The person's own matches among them all sit at one specificity (their own items shadow each other).
        let mine = outranked.filter { !snapshot.isShared($0.item) }
        guard let first = mine.first else { return (proposal(hidden: outranked.count, beside: nil), nil) }
        let scopes = mine.map(\.match.scope)
        let shared = ServiceScope(
            host: first.match.scope.host, includeSubdomains: scopes.allSatisfy(\.includeSubdomains),
            excludedHosts: scopes.reduce(into: Set<String>()) { $0.formUnion($1.excludedHosts) })
        guard scopes.allSatisfy({ $0.host == shared.host }), ScopePolicy.isAcceptable(shared),
            ScopeMatcher.match(shared, host: host)?.specificity == first.match.specificity
        else { return (proposal(hidden: outranked.count, beside: nil), nil) }
        return (
            proposal(
                hidden: outranked.count,
                beside: SharedScopeProposal(
                    scopeHost: shared.host, includesSubdomains: shared.includeSubdomains, accounts: mine.count)),
            shared
        )
    }

    /// The vault a new item goes into, as the sheet names it: the default vault the snapshot carries.
    static func newItemVault(in snapshot: VaultSnapshot) throws -> EntryVault {
        guard let id = snapshot.defaultVaultID else { throw Blocked.refused(.vault(.noAccount)) }
        return snapshot.vault(id)
    }

    /// The warning to show in place of an empty result, if any of the hosts resembles a saved site (PRD F11.3).
    ///
    /// Judged per vault (`VaultSnapshot.assess`): a scope in a shared vault does not make a host recognised on
    /// behalf of the other vaults, so a member cannot silence the warning about a look-alike of a site the person
    /// saved themselves.
    static func warning(for hosts: [NormalizedHost], in snapshot: VaultSnapshot) -> LookAlikeWarning? {
        var fallback: LookAlikeWarning?
        for host in hosts {
            guard case .suspicious(let signals, let impersonating) = snapshot.assess(host) else { continue }
            let warning = LookAlikeWarning(host: host.value, signals: signals, impersonating: impersonating)
            if !impersonating.isEmpty { return warning }
            fallback = fallback ?? warning
        }
        return fallback
    }

    static func passwordEntry(_ match: RankedMatch, userName: String, in snapshot: VaultSnapshot) -> PasswordEntry {
        PasswordEntry(
            itemID: match.item.id, vault: snapshot.vault(of: match.item), title: match.item.title, userName: userName,
            matchedHost: match.match.scope.host,
            hasOneTimeCode: match.item.fields.contains { $0.kind == .totp },
            reportedUnused: match.item.field(.password)?.reportedUnusedAt != nil)
    }

    static func insertableItem(
        _ item: Item, in snapshot: VaultSnapshot, including isIncluded: (FieldKind) -> Bool
    ) -> InsertableItem? {
        let fields = item.fields.filter { isIncluded($0.kind) && !$0.value.isEmpty }.map { field in
            InsertableField(
                fieldID: field.id, kind: field.kind, label: field.label,
                question: field.kind == .securityQuestion ? field.meta["question"] : nil,
                preview: field.kind.isSecret ? nil : field.value,
                recoveryCodeCount: field.recoveryCodes.count, usedRecoveryCodes: field.usedRecoveryCodeIndices)
        }
        guard !fields.isEmpty else { return nil }
        return InsertableItem(
            itemID: item.id, vault: snapshot.vault(of: item), title: item.title,
            userName: item.loginNames.first { !$0.isEmpty } ?? "", fields: fields)
    }
}

/// What the named hosts match, for a list. Display only: nothing here releases anything, and every entry a list
/// shows is authorised again by `ReleaseGate` when it is chosen.
struct Matching {
    /// The identifiers that normalised, in order, each once, less pages loaded over plain `http`.
    var hosts: [NormalizedHost] = []
    var firstError: HostNormalizationError?
    /// The hosts of identifiers that named a page loaded over plain `http` (PRD F6.9). Nothing is listed for them:
    /// they are neither ranked nor assessed, and a list with nothing else to show is refused as `insecurePage`.
    var insecurePages: [NormalizedHost] = []
    /// Items in use that the gate offers on at least one host. Archived and excluded items, and items that share
    /// an ID, take part in the ranking and are not listed. Items the ranking shadows are not listed either: the
    /// gate never releases them on the host (PRD F6.6). Nor is anything listed for a host the gate refuses, among
    /// them one only a shared vault is scoped to that resembles a site saved in another vault.
    var primary: [RankedMatch] = []
    /// The item to suggest first: set when every usable identifier's decision is to fill this one item. Never set
    /// where an item of a shared vault stands beside one of the person's own: that is a choice (review finding Z60).
    var onlyFill: UUID?

    init(identifiers: [ServiceIdentifier], snapshot: VaultSnapshot) {
        var fills = Set<UUID>()
        var undecided = false
        for identifier in identifiers.prefix(ReleaseGate.maximumIdentifiers) {
            let host: NormalizedHost
            // The gate's own reading of the page, so a list cannot show what a release would refuse.
            switch AutoFillGate.page(identifier) {
            case .success(let found):
                host = found
            case .failure(.insecurePage(let page)):
                if !insecurePages.contains(page) { insecurePages.append(page) }
                continue
            case .failure(.unusableIdentifier(let error)):
                firstError = firstError ?? error
                continue
            case .failure:
                firstError = firstError ?? .invalidHost(identifier.identifier)
                continue
            }
            guard !hosts.contains(host) else { continue }
            hosts.append(host)
            // One decision, the gate's, for what is listed and for what is suggested.
            let offered: [RankedMatch]
            switch snapshot.decide(for: identifier) {
            case .fill(let match):
                offered = [match]
                if snapshot.isInUse(match.item) { fills.insert(match.item.id) } else { undecided = true }
            case .chooseAmong(let matches):
                offered = matches
                undecided = true
            case .refuse:
                offered = []
            }
            for match in offered
            where snapshot.isInUse(match.item) && !primary.contains(where: { $0.item.id == match.item.id }) {
                primary.append(match)
            }
        }
        if !undecided, fills.count == 1 { onlyFill = fills.first }
    }
}
