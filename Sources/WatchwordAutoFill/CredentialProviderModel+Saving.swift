import Foundation
import WatchwordGenerator
import WatchwordMatching
import WatchwordModel

/// Saving and generating passwords (PRD F6.5, F3.1).
extension CredentialProviderModel {
    static let maximumPasswordLength = 4096
    /// A generated password is checked against the site's rules; this bounds the redraws.
    static let maximumGenerationAttempts = 512

    // MARK: Saving

    /// What a save-password request would do, for the sheet to show before anything is written.
    ///
    /// A new item is scoped to the exact host the login was made on, without subdomains: the narrowest scope that
    /// fills there again. Widening it is the person's decision, in the app. Where that would outrank accounts
    /// already offered on the host, the proposal says how many it would hide and offers their scope as the
    /// alternative (`newItemProposal`); which of the two it is, a different service or a second account, is the
    /// person's call and is never made without them. An existing item is offered for update only if the gate would
    /// fill it on this host and it could be this account (same user name, or none recorded); a less specific "other
    /// account" is never a candidate, because updating it would not make it fill here.
    public func savePasswordPlan(for request: SavePasswordRequest) async -> Outcome<SavePasswordPlan> {
        func run() async throws -> SavePasswordPlan {
            try Self.plan(for: request, in: try await self.load()).plan
        }
        do {
            return .success(try await run())
        } catch {
            return Self.failure(error)
        }
    }

    /// Carries out the save the person confirmed.
    ///
    /// Updating changes the item's password, and adds the user name if the item had none. It never changes the
    /// item's scopes, title or anything else, and the previous password stays in the item's history (F1.4). The item
    /// must be one the gate authorises for the request's host, whatever the sheet showed.
    public func savePassword(
        _ request: SavePasswordRequest, to destination: SaveDestination
    ) async -> Outcome<SavedPassword> {
        func run() async throws -> SavedPassword {
            let snapshot = try await self.load()
            let planned = try Self.plan(for: request, in: snapshot)
            switch destination {
            case .newItem:
                return try await self.createLogin(request, scope: planned.scope, title: planned.host.value)
            case .newItemBesideExisting:
                return try await self.createLogin(
                    request, scope: planned.sharedScope ?? planned.scope, title: planned.host.value)
            case .existingItem(let itemID):
                let authorization = try Self.unwrap(
                    ReleaseGate.authorize(itemID: itemID, for: [request.serviceIdentifier], in: snapshot))
                return try await self.updateLogin(authorization.item, with: request)
            }
        }
        do {
            return .success(try await run())
        } catch {
            return Self.failure(error)
        }
    }

    /// A save the system asks for with no UI. Only what cannot disturb anything is done unasked: nothing at all when
    /// the login is already saved, or a new item for a host nothing is saved for and that resembles no saved site.
    /// Changing a saved password, adding a second account where one is already offered (the two then tie, and the
    /// person chooses between them from then on), and saving on a look-alike host all need the person.
    public func savePasswordWithoutInteraction(_ request: SavePasswordRequest) async -> SilentOutcome<SavedPassword> {
        func run() async throws -> SilentOutcome<SavedPassword> {
            let planned = try Self.plan(for: request, in: try await self.load())
            switch planned.plan {
            case .alreadySaved(let itemID):
                return .success(SavedPassword(itemID: itemID, createdItem: false))
            case .createItem(let proposal) where proposal.warning == nil && planned.isNewSite:
                return .success(try await self.createLogin(request, scope: planned.scope, title: planned.host.value))
            case .createItem, .offerUpdate:
                return .requiresInteraction(.confirmation)
            }
        }
        do {
            return try await run()
        } catch {
            return Self.silentFailure(error)
        }
    }

    private struct Planned {
        var plan: SavePasswordPlan
        var host: NormalizedHost
        /// The exact host, without subdomains.
        var scope: ServiceScope
        /// The scope of the accounts a new item scoped `scope` would outrank, if there are any.
        var sharedScope: ServiceScope?
        var isNewSite: Bool
    }

    private static func plan(
        for request: SavePasswordRequest, in snapshot: VaultSnapshot
    ) throws -> Planned {
        guard !request.password.isEmpty, request.password.utf8.count <= maximumPasswordLength,
            !request.password.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F })
        else { throw Blocked.refused(.invalidRequest("password")) }
        guard isDisplayable(request.userName) else { throw Blocked.refused(.invalidRequest("userName")) }

        let host: NormalizedHost
        do {
            host = try HostNormalizer.normalize(request.serviceIdentifier)
        } catch {
            throw Blocked.refused(
                .gate(
                    .unusableIdentifier(
                        (error as? HostNormalizationError) ?? .invalidHost(request.serviceIdentifier.identifier))))
        }
        // The new scope goes through the same policy as one typed in the app (PRD F11.2).
        let scope = ServiceScope(host: host.value, includeSubdomains: false)
        do {
            try ScopePolicy.validate(scope)
        } catch {
            throw Blocked.refused(.scopeRejected((error as? ScopeValidationError) ?? .notAHostname(host.value)))
        }

        let matches: [RankedMatch]
        switch AutoFillGate.decide(for: request.serviceIdentifier, among: snapshot.rankable) {
        case .fill(let match): matches = [match]
        case .chooseAmong(let tied): matches = tied
        case .refuse: matches = []
        }
        let candidates = matches.filter {
            snapshot.isInUse($0.item) && couldBeAccount($0.item, userName: request.userName)
        }
        let (proposal, sharedScope) = newItemProposal(
            title: host.value, narrow: scope, on: host, userName: request.userName,
            warning: matches.isEmpty ? warning(for: [host], in: snapshot) : nil, in: snapshot)

        if let saved = candidates.first(where: { match in
            guard let current = match.item.field(.password) else { return false }
            return sameBytes(current.value, request.password)
                && (request.userName.isEmpty || names(of: match.item).contains(request.userName))
        }) {
            return Planned(
                plan: .alreadySaved(itemID: saved.item.id), host: host, scope: scope, sharedScope: sharedScope,
                isNewSite: false)
        }
        guard !candidates.isEmpty else {
            return Planned(
                plan: .createItem(proposal), host: host, scope: scope, sharedScope: sharedScope,
                isNewSite: matches.isEmpty)
        }
        let offered = candidates.map { match in
            SaveCandidate(
                itemID: match.item.id, title: match.item.title, userName: names(of: match.item).first ?? "",
                matchedHost: match.match.scope.host,
                passwordDiffers: !sameBytes(match.item.field(.password)?.value ?? "", request.password))
        }
        return Planned(
            plan: .offerUpdate(candidates: offered, newItem: proposal), host: host, scope: scope,
            sharedScope: sharedScope, isNewSite: false)
    }

    private static func names(of item: Item) -> [String] {
        item.loginNames.filter { !$0.isEmpty }
    }

    /// Whether a login with `userName` could be the account `item` holds: the same name, or no name on either side.
    private static func couldBeAccount(_ item: Item, userName: String) -> Bool {
        let names = names(of: item)
        return userName.isEmpty || names.isEmpty || names.contains(userName)
    }

    /// Byte equality: `String ==` would call two differently composed passwords the same.
    private static func sameBytes(_ lhs: String, _ rhs: String) -> Bool {
        Array(lhs.utf8) == Array(rhs.utf8)
    }

    private func createLogin(
        _ request: SavePasswordRequest, scope: ServiceScope, title: String
    ) async throws -> SavedPassword {
        var fields: [Field] = []
        if !request.userName.isEmpty {
            fields.append(
                Field(id: UUID.random(using: &random), kind: .username, label: "Username", value: request.userName))
        }
        fields.append(
            Field(id: UUID.random(using: &random), kind: .password, label: "Password", value: request.password))
        let itemID = UUID.random(using: &random)
        let vaultID: UUID
        do {
            vaultID = try await vault.defaultVaultID()
        } catch {
            throw Self.blocked(error)
        }
        let stored = try await save(
            Item(id: itemID, vaultID: vaultID, title: title, scopes: [scope], fields: fields), replacing: nil)
        return SavedPassword(itemID: stored.id, createdItem: true)
    }

    private func updateLogin(_ item: Item, with request: SavePasswordRequest) async throws -> SavedPassword {
        guard Self.couldBeAccount(item, userName: request.userName) else { throw Blocked.refused(.unknownRecord) }
        var updated = item
        if let position = updated.fields.firstIndex(where: { $0.kind == .password }) {
            if !Self.sameBytes(updated.fields[position].value, request.password) {
                updated.fields[position].value = request.password
                // A password just used to sign in is in use, whatever a report said about the old one.
                updated.fields[position].setTimestamp(nil, for: Field.reportedUnusedKey)
            }
        } else {
            updated.fields.append(
                Field(id: UUID.random(using: &random), kind: .password, label: "Password", value: request.password))
        }
        if !request.userName.isEmpty, Self.names(of: item).isEmpty {
            updated.fields.insert(
                Field(id: UUID.random(using: &random), kind: .username, label: "Username", value: request.userName),
                at: 0)
        }
        if updated != item {
            _ = try await save(updated, replacing: item)
        }
        return SavedPassword(itemID: item.id, createdItem: false)
    }

    // MARK: Generating

    /// A password for a generate-password request, obeying the site's rules when it declared any (PRD F3.1, F6.5).
    ///
    /// Needs no vault and releases nothing from it, so it is never `vaultLocked`. The rules are the page's; they
    /// are parsed strictly, cannot take the password outside the generator's own bounds, and the result is checked
    /// against them before it is returned. Its entropy is reported so the sheet can warn when a site's rules force a
    /// weak password (F3.4).
    public func generatePassword(
        for request: GeneratePasswordRequest = GeneratePasswordRequest()
    ) -> Outcome<GeneratedPassword> {
        do {
            let rules = try request.passwordRules.map { try PasswordRules(parsing: $0) } ?? PasswordRules()
            let policy = try rules.policy()
            var generator = PasswordGenerator(rng: random)
            defer { random = generator.rng }
            for _ in 0..<Self.maximumGenerationAttempts {
                let password = try generator.generate(policy)
                if rules.isSatisfied(by: password) {
                    return .success(
                        GeneratedPassword(
                            password: password, entropyBits: try Entropy.bits(for: policy), policy: policy))
                }
            }
            return .refused(.passwordRules(.unsatisfiable))
        } catch let error as PasswordRulesError {
            return .refused(.passwordRules(error))
        } catch {
            return .refused(.passwordRules(.unsatisfiable))
        }
    }
}
