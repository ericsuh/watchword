import Foundation
import SecureMemory
import WatchwordMatching
import WatchwordModel

/// Passkeys (PRD F6.2, F11.8; docs/02-architecture.md §9.1).
///
/// A passkey is bound twice. The credential stores its relying party ID and `PasskeyAuthenticator` signs for no
/// other; and the item holding it must pass `AutoFillGate` for that relying party as a host, like any release
/// (F11.1). A passkey created here passes when it is created: it goes into an item the gate already authorises for
/// the relying party, or into a new item scoped to it. It can stop passing later, when the person gives another
/// item a more specific scope: in the app, or here by choosing a new item for a relying party that items with a
/// broader scope already serve, which the registration sheet says would hide them (`newItemProposal`) and offers
/// their scope as the alternative. A passkey whose item the gate does not authorise is not published.
extension CredentialProviderModel {
    /// Most relying parties list a handful of credentials; this bounds what a page can make the model walk.
    static let maximumCredentialListCount = 256
    /// How many passkeys one item may hold. A person keeps one or two per account; every registration is a version
    /// in a history that is never pruned (PRD F1.4), and an item past its payload limit refuses every later edit.
    public static let maximumPasskeysPerItem = 8
    static let maximumNameLength = PasskeyCredential.maximumNameLength

    // MARK: Assertion

    /// An assertion with the passkey the person chose in the extension's list.
    public func passkeyAssertion(
        for choice: FieldChoice, request: PasskeyAssertionRequest, presence: PersonPresence
    ) async -> Outcome<PasskeyAssertionResult> {
        func run() async throws -> PasskeyAssertionResult {
            try await self.makeAssertion(
                itemID: choice.itemID, fieldID: choice.fieldID, request: request, presence: presence)
        }
        do {
            return .success(try await run())
        } catch {
            return Self.failure(error)
        }
    }

    /// An assertion for a passkey the person chose in the system's own sheet, with no extension UI.
    ///
    /// The gate must authorise the item, but unlike a password it need not be the only match: the system sheet shows
    /// each passkey by account, the choice is of one credential, and an assertion is useless to any party but the
    /// one it names. `presence` is what actually happened in this request; a relying party that requires
    /// verification the person has not given gets `requiresInteraction`, not an assertion with the flag set anyway.
    public func passkeyAssertionWithoutInteraction(
        request: PasskeyAssertionRequest, identity: PasskeyIdentityRequest, presence: PersonPresence
    ) async -> SilentOutcome<PasskeyAssertionResult> {
        func run() async throws -> SilentOutcome<PasskeyAssertionResult> {
            guard let record = RecordIdentifier(identity.recordIdentifier), let fieldID = record.fieldID else {
                throw Blocked.refused(.unknownRecord)
            }
            do {
                return .success(
                    try await self.makeAssertion(
                        itemID: record.itemID, fieldID: fieldID, request: request, presence: presence,
                        expecting: identity.credentialID))
            } catch {
                switch Self.blocked(error) {
                case .refused(.passkey(.userVerificationRequired)): return .requiresInteraction(.userVerification)
                case .refused(.passkey(.userPresenceRequired)): return .requiresInteraction(.userPresence)
                case let blocked: throw blocked
                }
            }
        }
        do {
            return try await run()
        } catch {
            return Self.silentFailure(error)
        }
    }

    private func makeAssertion(
        itemID: UUID, fieldID: UUID, request: PasskeyAssertionRequest, presence: PersonPresence,
        expecting credentialID: Data? = nil
    ) async throws -> PasskeyAssertionResult {
        let relyingParty = try Self.relyingParty(request.relyingPartyID)
        try Self.checkClientDataHash(request.clientDataHash)
        try Self.checkCredentialList(request.allowedCredentialIDs)
        if case .write(let blob) = request.extensions.largeBlob,
            blob.count > PasskeyCredential.maximumLargeBlobLength
        {
            throw Blocked.refused(.passkey(.largeBlobTooLong))
        }

        let snapshot = try await load()
        let authorization = try Self.unwrap(
            ReleaseGate.authorize(itemID: itemID, for: [relyingParty.serviceIdentifier], in: snapshot))
        var credential = try Self.unwrap(authorization.passkey(fieldID: fieldID))
        // Before anything else is done with it: the stored relying party, exactly (the authenticator checks again).
        guard credential.relyingPartyID == relyingParty.value else {
            throw Blocked.refused(.passkey(.relyingPartyMismatch))
        }
        if let credentialID, credentialID != credential.credentialID { throw Blocked.refused(.unknownRecord) }
        guard
            request.allowedCredentialIDs.isEmpty || request.allowedCredentialIDs.contains(credential.credentialID)
        else { throw Blocked.refused(.unknownRecord) }
        guard presence != .absent else { throw Blocked.refused(.passkey(.userPresenceRequired)) }
        guard request.userVerification != .required || presence == .verified else {
            throw Blocked.refused(.passkey(.userVerificationRequired))
        }

        // CTAP's hmac-secret keeps a separate secret for requests without verification. A Watchword credential has
        // one, so `prf` is evaluated only for a verified person; otherwise there is no output, rather than the
        // verified one.
        var prf: PRFOutputValues?
        if presence == .verified, let input = request.extensions.prf,
            let values = input.perCredential[credential.credentialID] ?? input.inputValues,
            let secret = credential.prfSecret
        {
            prf = try Self.passkey { try PasskeyPRF.evaluate(secret: secret, inputs: values) }
        }

        // Signed with the credential as stored, before any write: a key that cannot sign changes nothing.
        let backedUp = try await backedUp()
        let assertion = try Self.passkey {
            try PasskeyAuthenticator.assertion(
                with: credential, for: relyingParty, clientDataHash: request.clientDataHash, presence: presence,
                backedUp: backedUp)
        }

        var largeBlob: LargeBlobAssertionOutput?
        switch request.extensions.largeBlob {
        case .read:
            largeBlob = .read(credential.largeBlob)
        case .write(let blob):
            // A write that loses a race is reported as not written and the assertion is still good. A vault that
            // locks during the write yields no assertion at all: `storeLargeBlob` rethrows the lock.
            if credential.largeBlob == blob {
                largeBlob = .write(didWrite: true)
            } else {
                credential.largeBlob = blob
                largeBlob = .write(
                    didWrite: try await storeLargeBlob(credential, fieldID: fieldID, in: authorization.item))
            }
        case nil:
            break
        }
        return try await releasing(PasskeyAssertionResult(assertion: assertion, prf: prf, largeBlob: largeBlob))
    }

    private func storeLargeBlob(_ credential: PasskeyCredential, fieldID: UUID, in item: Item) async throws -> Bool {
        guard let position = item.fields.firstIndex(where: { $0.id == fieldID }),
            let value = try? credential.fieldValue()
        else { return false }
        var updated = item
        updated.fields[position].value = value
        do {
            _ = try await save(updated, replacing: item)
            return true
        } catch {
            if case .locked = Self.blocked(error) { throw Blocked.locked }
            return false
        }
    }

    // MARK: Registration

    /// What the registration sheet shows: the relying party, the account, and where the passkey could go.
    public func passkeyRegistrationOptions(
        for request: PasskeyRegistrationRequest
    ) async -> Outcome<PasskeyRegistrationOptions> {
        func run() async throws -> PasskeyRegistrationOptions {
            let relyingParty = try Self.validate(request)
            let snapshot = try await self.load()
            try Self.checkNotExcluded(request, relyingParty: relyingParty, in: snapshot)
            let candidates = Self.registrationCandidates(for: relyingParty, userName: request.user.name, in: snapshot)
            let named = candidates.filter(\.matchesUserName)
            let newItem = try Self.newItem(for: relyingParty, userName: request.user.name, in: snapshot).proposal
            let suggested: PasskeyDestination
            if named.count == 1 {
                suggested = .existingItem(named[0].itemID)
            } else {
                suggested = newItem.besideExisting == nil ? .newItem : .newItemBesideExisting
            }
            return PasskeyRegistrationOptions(
                relyingPartyID: relyingParty.value, userName: request.user.name, existingItems: candidates,
                relatedLogins: Self.relatedLogins(
                    for: relyingParty, userName: request.user.name, excluding: candidates, in: snapshot),
                newItem: newItem, suggested: suggested)
        }
        do {
            return .success(try await run())
        } catch {
            return Self.failure(error)
        }
    }

    /// Creates a passkey and stores it where the person chose.
    ///
    /// An existing item must be one the gate authorises for the relying party and hold fewer than
    /// `maximumPasskeysPerItem`; its scopes are never changed, so a login that is not scoped to the relying party
    /// cannot take the passkey from here (PRD F11.7: a scope is added in the app). A new item is titled by the
    /// relying party ID and scoped to it, an ID that has already passed the scope policy; `newItemBesideExisting`
    /// scopes it as the items already offered for the relying party are, so that it ties with them instead of
    /// outranking them.
    public func registerPasskey(
        _ request: PasskeyRegistrationRequest, destination: PasskeyDestination, presence: PersonPresence
    ) async -> Outcome<PasskeyRegistrationResult> {
        func run() async throws -> PasskeyRegistrationResult {
            guard presence != .absent else { throw Blocked.refused(.passkey(.userPresenceRequired)) }
            return try await self.register(request, destination: destination, presence: presence)
        }
        do {
            return .success(try await run())
        } catch {
            return Self.failure(error)
        }
    }

    /// Conditional registration: a site that has just signed the person in with a saved password asks for a passkey
    /// to be added quietly (PRD F6.2, F11.8).
    ///
    /// Nobody is asked, so this only ever upgrades, and only once: there must be exactly one item the gate would
    /// fill for the relying party, it must hold a password and the user name the site gives, and it must hold no
    /// passkey at all yet. A page can therefore not use this request to plant items in the vault, nor to grow one
    /// (every field of the request, the user handle included, is the page's to vary, and each passkey added is a
    /// version in a history that is never pruned): it can turn the password login the person already keeps for
    /// that very site into a login with one passkey. Nor does it ever add a scope, so a login saved for
    /// `www.shop.example` is not upgraded by a relying party `shop.example`. Anything else is
    /// `refused(.noItemToUpgrade)`, and the site is free to ask again with UI.
    public func registerPasskeyWithoutInteraction(
        _ request: PasskeyRegistrationRequest, presence: PersonPresence = .absent
    ) async -> SilentOutcome<PasskeyRegistrationResult> {
        func run() async throws -> SilentOutcome<PasskeyRegistrationResult> {
            let relyingParty = try Self.validate(request)
            guard request.userVerification != .required || presence == .verified else {
                return .requiresInteraction(.userVerification)
            }
            let snapshot = try await self.load()
            guard !request.user.name.isEmpty,
                case .fill(let match) = AutoFillGate.decide(
                    for: relyingParty.serviceIdentifier, among: snapshot.rankable),
                snapshot.isInUse(match.item), match.item.field(.password) != nil,
                match.item.loginNames.contains(request.user.name),
                // Any passkey field counts, whatever it decodes to and whoever it is for.
                !match.item.fields.contains(where: { $0.kind == .passkey })
            else { throw Blocked.refused(.noItemToUpgrade) }
            return .success(
                try await self.register(request, destination: .existingItem(match.item.id), presence: presence))
        }
        do {
            return try await run()
        } catch {
            return Self.silentFailure(error)
        }
    }

    private func register(
        _ request: PasskeyRegistrationRequest, destination: PasskeyDestination, presence: PersonPresence
    ) async throws -> PasskeyRegistrationResult {
        let relyingParty = try Self.validate(request)
        guard request.userVerification != .required || presence == .verified else {
            throw Blocked.refused(.passkey(.userVerificationRequired))
        }
        let snapshot = try await load()
        try Self.checkNotExcluded(request, relyingParty: relyingParty, in: snapshot)

        // Authorise the destination before any key exists.
        var existing: Item?
        if case .existingItem(let itemID) = destination {
            let item = try Self.unwrap(
                ReleaseGate.authorize(itemID: itemID, for: [relyingParty.serviceIdentifier], in: snapshot)
            ).item
            guard item.fields.filter({ $0.kind == .passkey }).count < Self.maximumPasskeysPerItem else {
                throw Blocked.refused(.passkey(.tooManyCredentials))
            }
            existing = item
        }
        var newItemScope = relyingParty.scope
        if destination == .newItemBesideExisting,
            let shared = try Self.newItem(for: relyingParty, userName: request.user.name, in: snapshot).sharedScope
        {
            newItemScope = shared
        }
        let backedUp = try await backedUp()
        let now = await clock.now()
        var generator = random
        let registration: PasskeyRegistration
        do {
            registration = try Self.passkey {
                try PasskeyAuthenticator.register(
                    relyingParty: relyingParty, user: request.user, presence: presence, backedUp: backedUp, now: now,
                    using: &generator)
            }
        } catch {
            random = generator
            throw error
        }
        let fieldID = UUID.random(using: &generator)
        let itemID = UUID.random(using: &generator)
        random = generator

        let credential = registration.credential
        // A credential ID seen before means the random source repeats; the key would repeat with it.
        let held = snapshot.all.flatMap { Self.credentials(in: $0) }
        guard !held.contains(where: { $0.credential.credentialID == credential.credentialID }) else {
            throw Blocked.refused(.passkey(.credentialIDCollision))
        }

        var prf: PRFRegistrationOutput?
        switch request.extensions.prf {
        case .checkForSupport:
            prf = PRFRegistrationOutput(isSupported: true, values: nil)
        case .evaluate(let inputs):
            // As for an assertion: supported, but evaluated only for a verified person.
            var values: PRFOutputValues?
            if presence == .verified, let secret = credential.prfSecret {
                values = try Self.passkey { try PasskeyPRF.evaluate(secret: secret, inputs: inputs) }
            }
            prf = PRFRegistrationOutput(isSupported: true, values: values)
        case nil:
            break
        }

        let field: Field
        do {
            field = try Field.passkey(credential, id: fieldID)
        } catch {
            throw Blocked.refused(.passkey(.malformedCredential((error as? PasskeyCodingError) ?? .malformed)))
        }
        let stored: Item
        if let existing {
            var updated = existing
            updated.fields.append(field)
            stored = try await save(updated, replacing: existing)
        } else {
            var fields: [Field] = []
            if !request.user.name.isEmpty {
                fields.append(
                    Field(id: UUID.random(using: &random), kind: .username, label: "Username", value: request.user.name)
                )
            }
            fields.append(field)
            let vaultID: UUID
            do {
                vaultID = try await vault.defaultVaultID()
            } catch {
                throw Self.blocked(error)
            }
            stored = try await save(
                Item(
                    id: itemID, vaultID: vaultID, title: relyingParty.value, scopes: [newItemScope], fields: fields),
                replacing: nil)
        }
        return PasskeyRegistrationResult(
            relyingPartyID: relyingParty.value, credentialID: credential.credentialID,
            clientDataHash: request.clientDataHash, attestationObject: registration.attestationObject,
            itemID: stored.id, fieldID: fieldID, createdItem: existing == nil, prf: prf,
            largeBlobSupported: request.extensions.largeBlobRequested ? true : nil)
    }

    // MARK: Checks

    func backedUp() async throws -> Bool {
        do {
            return try await vault.isBackedUp()
        } catch {
            throw Self.blocked(error)
        }
    }

    static func relyingParty(_ raw: String) throws -> RelyingPartyID {
        do {
            return try RelyingPartyID(raw)
        } catch let error as RelyingPartyIDError {
            throw Blocked.refused(.passkey(.relyingPartyRejected(error)))
        }
    }

    /// Runs an authenticator call, turning its errors into refusals.
    static func passkey<Value>(_ body: () throws -> Value) throws -> Value {
        do {
            return try body()
        } catch let error as PasskeyError {
            throw Blocked.refused(.passkey(error))
        }
    }

    static func checkClientDataHash(_ hash: Data) throws {
        guard hash.count == PasskeyAuthenticator.clientDataHashLength else {
            throw Blocked.refused(.passkey(.clientDataHashLength(hash.count)))
        }
    }

    static func checkCredentialList(_ list: [Data]) throws {
        guard list.count <= maximumCredentialListCount,
            list.allSatisfy({ $0.count <= PasskeyCredential.credentialIDLengthRange.upperBound })
        else { throw Blocked.refused(.passkey(.listTooLong)) }
    }

    /// Everything about a registration request that can be checked without the vault.
    static func validate(_ request: PasskeyRegistrationRequest) throws -> RelyingPartyID {
        let relyingParty = try relyingParty(request.relyingPartyID)
        try checkClientDataHash(request.clientDataHash)
        try checkCredentialList(request.excludedCredentialIDs)
        guard request.supportedAlgorithms.count <= maximumCredentialListCount,
            request.supportedAlgorithms.contains(PasskeyAuthenticator.es256)
        else { throw Blocked.refused(.passkey(.noSupportedAlgorithm)) }
        guard PasskeyCredential.userHandleLengthRange.contains(request.user.handle.count) else {
            throw Blocked.refused(.passkey(.invalidUser("userHandle")))
        }
        guard isDisplayable(request.user.name) else { throw Blocked.refused(.passkey(.invalidUser("userName"))) }
        guard isDisplayable(request.user.displayName) else {
            throw Blocked.refused(.passkey(.invalidUser("userDisplayName")))
        }
        if case .evaluate(let inputs) = request.extensions.prf,
            inputs.first.count > PasskeyPRF.maximumInputLength
                || (inputs.second?.count ?? 0) > PasskeyPRF.maximumInputLength
        {
            throw Blocked.refused(.passkey(.prfInputTooLong))
        }
        return relyingParty
    }

    /// A name a page supplies and the person will later read in a list: bounded, and without the control and
    /// direction-override characters that make text display as something else.
    static func isDisplayable(_ text: String) -> Bool {
        guard text.utf8.count <= maximumNameLength else { return false }
        return !text.unicodeScalars.contains { scalar in
            switch scalar.value {
            case 0x00...0x1F, 0x7F...0x9F, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069, 0x2028, 0x2029:
                return true
            default:
                return false
            }
        }
    }

    /// WebAuthn's `excludeCredentials`: refuse to create a second credential where the vault holds a listed one.
    static func checkNotExcluded(
        _ request: PasskeyRegistrationRequest, relyingParty: RelyingPartyID, in snapshot: VaultSnapshot
    ) throws {
        guard !request.excludedCredentialIDs.isEmpty else { return }
        let excluded = Set(request.excludedCredentialIDs)
        for item in snapshot.rankable {
            for held in credentials(in: item)
            where held.credential.relyingPartyID == relyingParty.value
                && excluded.contains(held.credential.credentialID)
            {
                throw Blocked.refused(.passkey(.credentialExcluded))
            }
        }
    }

    /// The passkeys an item holds that decode. A field that does not is skipped: it can be neither offered nor used.
    static func credentials(in item: Item) -> [(field: Field, credential: PasskeyCredential)] {
        item.fields.compactMap { field in
            guard field.kind == .passkey, let credential = try? field.passkeyCredential() else { return nil }
            return (field, credential)
        }
    }

    /// The passkeys the gate will release for `relyingParty`, optionally limited to an allow-list.
    static func passkeyEntries(
        for relyingParty: RelyingPartyID, allowed: [Data], in snapshot: VaultSnapshot
    ) -> [PasskeyEntry] {
        var entries: [PasskeyEntry] = []
        for authorization in ReleaseGate.authorizedItems(for: relyingParty.serviceIdentifier, in: snapshot) {
            let item = authorization.item
            for (field, credential) in credentials(in: item)
            where credential.relyingPartyID == relyingParty.value
                && (allowed.isEmpty || allowed.contains(credential.credentialID))
            {
                entries.append(
                    PasskeyEntry(
                        itemID: item.id, fieldID: field.id, title: item.title, userName: credential.userName,
                        relyingPartyID: credential.relyingPartyID, credentialID: credential.credentialID,
                        reportedUnknown: field.reportedUnknownAt != nil))
            }
        }
        return entries
    }

    /// The new item a registration for `relyingParty` would create, and the scope that would put it beside the
    /// items already offered for the relying party, if it would otherwise outrank them.
    static func newItem(
        for relyingParty: RelyingPartyID, userName: String, in snapshot: VaultSnapshot
    ) throws -> (proposal: NewItemProposal, sharedScope: ServiceScope?) {
        guard let host = try? HostNormalizer.normalize(relyingParty.serviceIdentifier) else {
            throw Blocked.refused(.passkey(.relyingPartyRejected(.notCanonical(relyingParty.value))))
        }
        return newItemProposal(
            title: relyingParty.value, narrow: relyingParty.scope, on: host, userName: userName, warning: nil,
            in: snapshot)
    }

    /// Logins in use with `userName` that are scoped at or under the relying party and are not candidates: the
    /// gate does not authorise them for it, and a registration never adds a scope to make it so.
    static func relatedLogins(
        for relyingParty: RelyingPartyID, userName: String, excluding candidates: [PasskeyRegistrationCandidate],
        in snapshot: VaultSnapshot
    ) -> [PasskeyRegistrationCandidate] {
        guard !userName.isEmpty else { return [] }
        let below = "." + relyingParty.host.value
        return snapshot.inUse.filter { item in
            item.loginNames.contains(userName) && !candidates.contains { $0.itemID == item.id }
                && item.scopes.contains {
                    ScopePolicy.isAcceptable($0) && ($0.host == relyingParty.host.value || $0.host.hasSuffix(below))
                }
        }
        .prefix(maximumCredentialListCount)
        .map {
            PasskeyRegistrationCandidate(itemID: $0.id, title: $0.title, userName: userName, matchesUserName: true)
        }
    }

    /// Items in use the gate authorises for the relying party and that have room: where a new passkey may be added.
    static func registrationCandidates(
        for relyingParty: RelyingPartyID, userName: String, in snapshot: VaultSnapshot
    ) -> [PasskeyRegistrationCandidate] {
        let authorized = ReleaseGate.authorizedItems(for: relyingParty.serviceIdentifier, in: snapshot).filter {
            $0.item.fields.filter { $0.kind == .passkey }.count < maximumPasskeysPerItem
        }
        let candidates = authorized.map {
            PasskeyRegistrationCandidate(
                itemID: $0.item.id, title: $0.item.title, userName: $0.item.loginNames.first { !$0.isEmpty } ?? "",
                matchesUserName: !userName.isEmpty && $0.item.loginNames.contains(userName))
        }
        return candidates.filter(\.matchesUserName) + candidates.filter { !$0.matchesUserName }
    }
}

extension UUID {
    /// A version-4 UUID from `generator`, so IDs are reproducible under a seeded test generator.
    static func random(using generator: inout some RandomNumberGenerator) -> UUID {
        var bytes = SecureBytes(randomCount: 16, using: &generator).unprotectedCopy()
        bytes[6] = (bytes[6] & 0x0F) | 0x40
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return UUID(
            uuid: (
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
                bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
            ))
    }
}
