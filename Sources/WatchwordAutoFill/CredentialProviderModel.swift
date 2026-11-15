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
/// - **Locked is a state.** With no keys the answer is `vaultLocked` (or `requiresInteraction(.vaultLocked)`); the
///   extension unlocks and asks again. The items of each request are read once, at its start, and every step of an
///   interactive flow reads them afresh.
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

    /// The list for `prepareCredentialList`: logins the gate would release for the named hosts, the less specific
    /// accounts kept apart, and, when `passkey` is given, the passkeys of its relying party.
    ///
    /// When nothing matches and a host resembles a saved site, the answer is the warning instead of an empty list
    /// (F11.3). When the system names no site at all there is nothing to authorise a password for, and a request
    /// without passkey parameters is refused.
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
                passwords.append(Self.passwordEntry(match, userName: name))
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

        if passwords.isEmpty && passkeys.isEmpty && matching.shadowed.isEmpty {
            if let warning = Self.warning(for: assessedHosts, in: snapshot) {
                return .warning(warning)
            }
            if assessedHosts.isEmpty, let error = matching.firstError {
                return .refused(passkeyRefusal ?? .gate(.unusableIdentifier(error)))
            }
        }
        return .list(
            CredentialList(
                hosts: assessedHosts.map(\.value), passwords: passwords, passkeys: passkeys,
                otherAccounts: matching.shadowed.map {
                    OtherAccountEntry(
                        itemID: $0.item.id, title: $0.item.title,
                        userName: $0.item.loginNames.first { !$0.isEmpty } ?? "", matchedHost: $0.match.scope.host)
                },
                suggested: suggested, passkeyRefusal: passkeyRefusal))
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
            return try Self.unwrap(authorization.password(userName: choice.userName))
        }
        do {
            return .success(try await run())
        } catch {
            return Self.failure(error)
        }
    }

    /// The password for a QuickType suggestion, with no UI (`provideCredentialWithoutUserInteraction`).
    ///
    /// Released only when the gate both authorises the item for the identity's host and decides that it alone is
    /// the fill there. A tie between accounts, or an identity whose user the item no longer has, needs the person:
    /// two suggestions with the same email are indistinguishable in the keyboard (PRD F11.5, scenario S1).
    public func passwordWithoutInteraction(
        for request: PasswordIdentityRequest
    ) async -> SilentOutcome<PasswordCredential> {
        func run() async throws -> SilentOutcome<PasswordCredential> {
            guard let record = RecordIdentifier(request.recordIdentifier), record.fieldID == nil else {
                throw Blocked.refused(.unknownRecord)
            }
            let snapshot = try await self.load()
            let authorization = try Self.unwrap(
                ReleaseGate.authorize(itemID: record.itemID, for: [request.serviceIdentifier], in: snapshot))
            guard Self.isSoleFill(authorization.item, for: request.serviceIdentifier, in: snapshot) else {
                return .requiresInteraction(.ambiguousMatch)
            }
            switch authorization.password(userName: request.user) {
            case .success(let credential): return .success(credential)
            case .failure(.unknownRecord): return .requiresInteraction(.staleIdentity)
            case .failure(let refusal): return .refused(refusal)
            }
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
                        itemID: item.id, fieldID: field.id, title: item.title,
                        userName: item.loginNames.first { !$0.isEmpty } ?? "", label: field.label))
            }
        }
        if entries.isEmpty && matching.primary.isEmpty {
            if let warning = Self.warning(for: matching.hosts, in: snapshot) { return .warning(warning) }
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
            return try Self.unwrap(authorization.oneTimeCode(fieldID: choice.fieldID, at: await self.clock.now()))
        }
        do {
            return .success(try await run())
        } catch {
            return Self.failure(error)
        }
    }

    /// The current code for a published one-time code identity, with no UI. Same rule as a password.
    public func oneTimeCodeWithoutInteraction(
        for request: OneTimeCodeIdentityRequest
    ) async -> SilentOutcome<OneTimeCode> {
        func run() async throws -> SilentOutcome<OneTimeCode> {
            guard let record = RecordIdentifier(request.recordIdentifier), let fieldID = record.fieldID else {
                throw Blocked.refused(.unknownRecord)
            }
            let snapshot = try await self.load()
            let authorization = try Self.unwrap(
                ReleaseGate.authorize(
                    itemID: record.itemID, for: [request.serviceIdentifier], in: snapshot, purpose: .oneTimeCode))
            guard Self.isSoleFill(authorization.item, for: request.serviceIdentifier, in: snapshot) else {
                return .requiresInteraction(.ambiguousMatch)
            }
            switch authorization.oneTimeCode(fieldID: fieldID, at: await self.clock.now()) {
            case .success(let code): return .success(code)
            case .failure(.unknownRecord): return .requiresInteraction(.staleIdentity)
            case .failure(let refusal): return .refused(refusal)
            }
        }
        do {
            return try await run()
        } catch {
            return Self.silentFailure(error)
        }
    }

    // MARK: - Text to insert (PRD F6.4)

    /// The items and fields the person may insert as text.
    ///
    /// With identifiers, the request is gated like any other: only items the gate would release for the host are
    /// listed, with every field but the passkey, and a look-alike host gets the warning. The operating system's own
    /// text-insertion request names no site, though (`prepareInterfaceForUserChoosingTextToInsert()` has no
    /// parameters). Then there is no host to check and no mismatch to detect, and the list is every item in use,
    /// picked by hand as it would be in the app, minus the three kinds that have a host-checked request of their
    /// own: passwords, one-time codes and passkeys are never released without a host.
    public func textInsertionList(for identifiers: [ServiceIdentifier]) async -> TextInsertionListOutcome {
        let snapshot: VaultSnapshot
        switch await loadResult() {
        case .success(let loaded): snapshot = loaded
        case .failure(.locked): return .vaultLocked
        case .failure(.refused(let refusal)): return .refused(refusal)
        }
        guard !identifiers.isEmpty else {
            let items = snapshot.inUse.sorted { $0.title < $1.title }.compactMap {
                Self.insertableItem($0, withholding: ManualChoice.withheldKinds)
            }
            return .list(TextInsertionList(items: items, hostVerified: false))
        }
        let matching = Matching(identifiers: identifiers, snapshot: snapshot)
        if matching.primary.isEmpty {
            if let warning = Self.warning(for: matching.hosts, in: snapshot) { return .warning(warning) }
            if matching.hosts.isEmpty, let error = matching.firstError {
                return .refused(.gate(.unusableIdentifier(error)))
            }
        }
        let items = matching.primary.compactMap { Self.insertableItem($0.item, withholding: [.passkey]) }
        return .list(TextInsertionList(items: items, hostVerified: true))
    }

    /// The text of the field the person chose. Authorised by the gate when the system named a host; restricted to
    /// fields without a host-checked request when it did not.
    public func textToInsert(for choice: TextChoice, identifiers: [ServiceIdentifier]) async -> Outcome<TextToInsert> {
        func run() async throws -> TextToInsert {
            let snapshot = try await self.load()
            guard !identifiers.isEmpty else {
                let manual = try Self.unwrap(ReleaseGate.manualChoice(itemID: choice.itemID, in: snapshot))
                return try Self.unwrap(manual.text(fieldID: choice.fieldID, part: choice.part))
            }
            // A one-time code is held to the one-time code rule whichever request asks for it.
            let isCode =
                snapshot.all.first { $0.id == choice.itemID }?.fields
                .first { $0.id == choice.fieldID }?.kind == .totp
            let authorization = try Self.unwrap(
                ReleaseGate.authorize(
                    itemID: choice.itemID, for: identifiers, in: snapshot, purpose: isCode ? .oneTimeCode : .credential)
            )
            return try Self.unwrap(
                authorization.text(fieldID: choice.fieldID, part: choice.part, at: await self.clock.now()))
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
            guard let item = snapshot.all.first(where: { $0.id == choice.itemID }) else {
                throw Blocked.refused(.unknownRecord)
            }
            guard !item.isTrashed, !item.archived else { throw Blocked.refused(.itemNotInUse) }
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
                return try await CredentialIdentityPublishing.publishAll(snapshot.all, to: publisher).count
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

    /// The items of this request. Every vault error but `locked` is a refusal.
    func load() async throws -> VaultSnapshot {
        do {
            return VaultSnapshot(try await vault.credentialItems())
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
    func save(_ item: Item, replacing old: Item?) async throws -> Item {
        let stored: Item
        do {
            stored = try await vault.saveCredentialItem(item, replacingVersion: old?.version)
        } catch {
            throw Self.blocked(error)
        }
        if let publisher {
            let vault = vault
            _ = try? await CredentialIdentityPublishing.publishChange(
                from: old, to: stored, all: { try await vault.credentialItems() }, to: publisher)
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

    /// Whether the gate's decision for `identifier` is to fill `item` and nothing else.
    static func isSoleFill(_ item: Item, for identifier: ServiceIdentifier, in snapshot: VaultSnapshot) -> Bool {
        if case .fill(let match) = AutoFillGate.decide(for: identifier, among: snapshot.rankable) {
            return match.item.id == item.id
        }
        return false
    }

    /// The warning to show in place of an empty result, if any of the hosts resembles a saved site (PRD F11.3).
    static func warning(for hosts: [NormalizedHost], in snapshot: VaultSnapshot) -> LookAlikeWarning? {
        var fallback: LookAlikeWarning?
        for host in hosts {
            guard
                case .suspicious(let signals, let impersonating) = PhishingDetector.assess(
                    host: host, againstItemsIn: snapshot.rankable)
            else { continue }
            let warning = LookAlikeWarning(host: host.value, signals: signals, impersonating: impersonating)
            if !impersonating.isEmpty { return warning }
            fallback = fallback ?? warning
        }
        return fallback
    }

    static func passwordEntry(_ match: RankedMatch, userName: String) -> PasswordEntry {
        PasswordEntry(
            itemID: match.item.id, title: match.item.title, userName: userName, matchedHost: match.match.scope.host,
            hasOneTimeCode: match.item.fields.contains { $0.kind == .totp },
            reportedUnused: match.item.field(.password)?.reportedUnusedAt != nil)
    }

    static func insertableItem(_ item: Item, withholding withheld: Set<FieldKind>) -> InsertableItem? {
        let fields = item.fields.filter { !withheld.contains($0.kind) && !$0.value.isEmpty }.map { field in
            InsertableField(
                fieldID: field.id, kind: field.kind, label: field.label,
                question: field.kind == .securityQuestion ? field.meta["question"] : nil,
                preview: field.kind.isSecret ? nil : field.value,
                recoveryCodeCount: field.recoveryCodes.count, usedRecoveryCodes: field.usedRecoveryCodeIndices)
        }
        guard !fields.isEmpty else { return nil }
        return InsertableItem(
            itemID: item.id, title: item.title, userName: item.loginNames.first { !$0.isEmpty } ?? "", fields: fields)
    }
}

/// What the named hosts match, for a list. Display only: nothing here releases anything, and every entry a list
/// shows is authorised again by `ReleaseGate` when it is chosen.
struct Matching {
    /// The identifiers that normalised, in order, each once.
    var hosts: [NormalizedHost] = []
    var firstError: HostNormalizationError?
    /// Items in use that are a most specific match for at least one host.
    var primary: [RankedMatch] = []
    /// Items in use that match only less specifically: "other accounts on this site".
    var shadowed: [RankedMatch] = []
    /// The item to suggest first: set when every usable identifier's decision is to fill this one item.
    var onlyFill: UUID?

    init(identifiers: [ServiceIdentifier], snapshot: VaultSnapshot) {
        var fills = Set<UUID>()
        var undecided = false
        var shadowedCandidates: [RankedMatch] = []
        for identifier in identifiers.prefix(ReleaseGate.maximumIdentifiers) {
            let host: NormalizedHost
            do {
                host = try HostNormalizer.normalize(identifier)
            } catch {
                firstError = firstError ?? (error as? HostNormalizationError) ?? .invalidHost(identifier.identifier)
                continue
            }
            guard !hosts.contains(host) else { continue }
            hosts.append(host)
            let ranking = ItemRanker.rank(items: snapshot.rankable, host: host)
            for match in ranking.primary
            where !match.item.archived && !primary.contains(where: { $0.item.id == match.item.id }) {
                primary.append(match)
            }
            shadowedCandidates.append(contentsOf: ranking.shadowed.filter { !$0.item.archived })
            switch AutoFillGate.decide(for: identifier, among: snapshot.rankable) {
            case .fill(let match) where !match.item.archived: fills.insert(match.item.id)
            case .fill, .chooseAmong: undecided = true
            case .refuse: break
            }
        }
        for match in shadowedCandidates
        where !primary.contains(where: { $0.item.id == match.item.id })
            && !shadowed.contains(where: { $0.item.id == match.item.id })
        {
            shadowed.append(match)
        }
        if !undecided, fills.count == 1 { onlyFill = fills.first }
    }
}
