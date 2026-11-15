import Foundation
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordSharing

public enum SharingSimulationError: Error, Equatable, Sendable {
    /// A different object already has the name: objects are written once.
    case objectExists(String)
    /// The store honours share membership and the writer was removed from the share.
    case forbidden(UUID)
    case noLedger(UUID)
    case noKey(UUID)
}

/// The sync store every simulated member of a shared vault talks to, run by the adversary of the sharing tests (A1,
/// docs/02-architecture.md §2). Honest operations keep the transport's contract (objects are written once); the
/// seams below them are everything someone with write access to the store can do.
public actor HostileSharingStore {
    private var objects: [String: [UInt8]] = [:]
    private var hidden: [UUID: Set<String>] = [:]
    private var revoked: Set<UUID> = []

    /// Whether the store refuses writes from accounts removed from the share (CloudKit does; a hostile store, or a
    /// plain shared folder, does not).
    public var enforcesShareMembership = false

    public init() {}

    public func setEnforcesShareMembership(_ value: Bool) {
        enforcesShareMembership = value
    }

    /// Creates an object. An identical object already there counts as created, which is what a content-addressed
    /// name means; a different one is refused.
    public func create(_ name: String, contents: [UInt8], by writer: UUID) throws {
        if enforcesShareMembership, revoked.contains(writer) { throw SharingSimulationError.forbidden(writer) }
        if let existing = objects[name] {
            guard existing == contents else { throw SharingSimulationError.objectExists(name) }
            return
        }
        objects[name] = contents
    }

    /// Removes an account from the share (PRD F4.3a).
    public func revokeShare(_ account: UUID) {
        revoked.insert(account)
    }

    public func isRevoked(_ account: UUID) -> Bool {
        revoked.contains(account)
    }

    /// Every object under `prefix` that `viewer` is shown, in name order.
    public func list(prefix: String, viewer: UUID) -> [(name: String, contents: [UInt8])] {
        let concealed = hidden[viewer] ?? []
        return objects.filter { $0.key.hasPrefix(prefix) && !concealed.contains($0.key) }
            .sorted { $0.key < $1.key }
            .map { (name: $0.key, contents: $0.value) }
    }

    // MARK: - What the adversary can do

    public var allObjects: [String: [UInt8]] {
        objects
    }

    /// Writes, overwrites or deletes an object with no checks.
    public func tamper(_ name: String, contents: [UInt8]?) {
        objects[name] = contents
    }

    /// Withholds objects from one account's devices.
    public func hide(_ names: [String], from viewer: UUID) {
        hidden[viewer, default: []].formUnion(names)
    }

    public func reveal(to viewer: UUID) {
        hidden[viewer] = nil
    }
}

/// What a simulated member made of one item object on the store.
public enum SimulatedItemOutcome: Sendable, Hashable {
    case read(String)
    /// The author may not write: `MembershipLedger.writePermission` said no (PRD F4.5).
    case refused(WriteRefusal)
    /// Not signed by the author's key in the verified chain.
    case forged
    /// Sealed under a key this member does not hold, or it does not decrypt.
    case undecryptable(keyID: UUID)
    case malformed
}

public struct SimulatedItem: Sendable, Hashable {
    public let recordID: UUID
    public let version: UInt64
    public let author: UUID
    public let keyID: UUID?
    public let outcome: SimulatedItemOutcome
}

/// One account with real keys taking part in shared vaults: the code an integrator will write around
/// `WatchwordSharing`, kept as small as it can be while still exercising every step (create, invite, verify, accept,
/// write, read, change a role, remove with rotation, leave, re-seal) against a `HostileSharingStore`.
///
/// Item writes stand in for sync's log segments: an item envelope sealed with `RecordCipher` under the vault key and
/// signed by its author over `name ‖ 0x00 ‖ envelope`, as `SyncEngine`'s objects are. A reader applies the three checks
/// the integration must make, in this order: may the author write (the ledger, at its current epoch), is the
/// signature the author's (the key the chain lists), does it open under a key this member holds.
public struct SimulatedMember: Sendable {
    public let name: String
    public let keyset: Keyset
    public let bundle: PublicKeyBundle
    public let contactStore: InMemoryVerifiedContactStore
    public let contacts: VerifiedContacts
    public let store: HostileSharingStore
    public let directory: InMemoryKeyBundleDirectory
    public var ledgers: [UUID: MembershipLedger] = [:]
    /// Vault keys held, by vault and key ID.
    public var keys: [UUID: [UUID: VaultKey]] = [:]
    /// Unfinished rotation plans as they would be on disk, by vault.
    public var savedPlans: [UUID: [UInt8]] = [:]
    public var generator: SeededGenerator
    public var now = Date(timeIntervalSince1970: 1_800_000_000)

    public var accountID: UUID {
        keyset.accountID
    }

    public var safetyNumber: String {
        bundle.fingerprint.safetyNumber
    }

    /// Generates an account from `seed` and publishes its key bundle.
    public static func make(
        _ name: String, seed: UInt64, store: HostileSharingStore, directory: InMemoryKeyBundleDirectory
    ) async throws -> SimulatedMember {
        var generator = SeededGenerator(seed: seed)
        let accountID = SimulatedMember.uuid(using: &generator)
        let keyset = Keyset.generate(accountID: accountID, using: &generator)
        let bundle = try keyset.publicKeyBundle()
        await directory.publish(bundle)
        let contactStore = InMemoryVerifiedContactStore()
        return SimulatedMember(
            name: name, keyset: keyset, bundle: bundle, contactStore: contactStore,
            contacts: VerifiedContacts(store: contactStore, account: bundle), store: store, directory: directory,
            generator: generator)
    }

    public static func uuid<R: RandomNumberGenerator>(using generator: inout R) -> UUID {
        var bytes = (0..<16).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        bytes[6] = (bytes[6] & 0x0F) | 0x40
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return UUID(
            uuid: (
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
                bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
            ))
    }

    public func ledger(_ vault: UUID) throws -> MembershipLedger {
        guard let ledger = ledgers[vault] else { throw SharingSimulationError.noLedger(vault) }
        return ledger
    }

    public func currentKey(_ vault: UUID) throws -> VaultKey {
        let keyID = try ledger(vault).state.vaultKeyID
        guard let key = keys[vault]?[keyID] else { throw SharingSimulationError.noKey(keyID) }
        return key
    }

    func publish(_ object: SharingObject) async throws {
        try await store.create(object.name, contents: object.contents, by: accountID)
    }

    // MARK: - Creating, inviting, accepting

    public mutating func createVault() async throws -> UUID {
        let vault = SimulatedMember.uuid(using: &generator)
        let key = VaultKey.generate(vaultID: vault, using: &generator)
        let ledger = try MembershipLedger.create(vaultKey: key, owner: keyset)
        try await publish(SharingObject(ledger.chain[0].record))
        ledgers[vault] = ledger
        keys[vault] = [key.key.keyID: key]
        return vault
    }

    /// The inviting side, start to finish. `safetyNumber` is what the invitee read out: the out-of-band channel.
    @discardableResult
    public mutating func invite(_ invitee: UUID, to vault: UUID, as role: MemberRole, safetyNumber: String)
        async throws -> Invitation
    {
        var invitation = try await OutgoingInvitation.begin(
            vaultID: vault, inviting: invitee, as: role, directory: directory, contacts: contacts)
        if invitation.fingerprintToConfirm != nil {
            try await invitation.confirm(.safetyNumber(safetyNumber), contacts: contacts, signedBy: keyset, at: now)
        }
        let package = try invitation.issue(ledger: ledger(vault), vaultKey: currentKey(vault), signedBy: keyset)
        for object in package.objects {
            try await publish(object)
        }
        try await sync(vault)
        return package.invitation
    }

    /// The accepting side, start to finish. `ownerSafetyNumber` is what the owner read out.
    public mutating func accept(_ invitation: Invitation, ownerSafetyNumber: String) async throws {
        var incoming = try await IncomingInvitation.begin(
            invitation, knownOwner: ledgers[invitation.vaultID]?.owner.accountID, directory: directory,
            contacts: contacts)
        if incoming.fingerprintToConfirm != nil {
            try await incoming.confirm(
                .safetyNumber(ownerSafetyNumber), contacts: contacts, signedBy: keyset, at: now)
        }
        let vault = invitation.vaultID
        let records = await store.list(prefix: SharingObjectLocation.membershipPrefix(vault), viewer: accountID)
        let grants = await store.list(prefix: SharingObjectLocation.vaultPrefix(vault) + "grant/", viewer: accountID)
        let joined = try incoming.accept(membership: records.map(\.contents), grants: grants, as: keyset)
        ledgers[vault] = joined.ledger
        keys[vault, default: [:]][joined.vaultKey.key.keyID] = joined.vaultKey
    }

    // MARK: - Syncing

    /// Ingests the vault's membership objects and fetches the current key if this member is entitled to it and does
    /// not hold it yet.
    @discardableResult
    public mutating func sync(_ vault: UUID) async throws -> MembershipLedger.IngestReport {
        var ledger = try ledger(vault)
        let records = await store.list(prefix: SharingObjectLocation.membershipPrefix(vault), viewer: accountID)
        let report = try ledger.ingest(records.map(\.contents))
        ledgers[vault] = ledger
        let state = ledger.state
        if state.member(accountID) != nil, keys[vault]?[state.vaultKeyID] == nil {
            let grants = await store.list(
                prefix: SharingObjectLocation.grantPrefix(
                    vaultID: vault, keyID: state.vaultKeyID, recipient: accountID),
                viewer: accountID)
            if let key = try? ledger.openGrant(of: state.vaultKeyID, from: grants, as: keyset) {
                keys[vault, default: [:]][state.vaultKeyID] = key
            }
        }
        return report
    }

    // MARK: - Items

    static let itemSchemaVersion: UInt64 = 1

    static func itemPrefix(_ vault: UUID) -> String {
        "items/\(vault.uuidString)/"
    }

    public static func itemName(vault: UUID, recordID: UUID, version: UInt64, author: UUID) -> String {
        let digits = String(version)
        return itemPrefix(vault)
            + "\(recordID.uuidString)/\(String(repeating: "0", count: 20 - digits.count) + digits)-\(author.uuidString)"
    }

    static func itemContext(vault: UUID, recordID: UUID, keyID: UUID, version: UInt64) -> EnvelopeContext {
        EnvelopeContext(
            recordID: recordID, vaultID: vault, schemaVersion: itemSchemaVersion, kind: .item, keyID: keyID,
            recordVersion: version)
    }

    /// Seals and signs an item under `key` and puts it on the store, whatever this member's role: the store, not
    /// this method, is where a hostile member's write lands, and the readers are who must refuse it.
    public mutating func write(
        _ text: String, to vault: UUID, recordID: UUID, version: UInt64, under key: VaultKey
    ) async throws {
        let envelope = try RecordCipher.seal(
            Array(text.utf8),
            context: SimulatedMember.itemContext(
                vault: vault, recordID: recordID, keyID: key.key.keyID, version: version),
            key: key.key, using: &generator)
        let name = SimulatedMember.itemName(vault: vault, recordID: recordID, version: version, author: accountID)
        let signature = try keyset.sign(Array(name.utf8) + [0] + envelope, domain: .logSegment)
        try await store.create(name, contents: signature + envelope, by: accountID)
    }

    /// An honest write: refused locally unless the ledger allows it (the client's half of F4.5), under the current key.
    public mutating func write(_ text: String, to vault: UUID, recordID: UUID, version: UInt64) async throws {
        let ledger = try ledger(vault)
        if case .refused = ledger.writePermission(for: accountID, atEpoch: ledger.state.epoch) {
            throw SharingError.notPermitted
        }
        try await write(text, to: vault, recordID: recordID, version: version, under: currentKey(vault))
    }

    /// Every item object on the store as this member judges it, in name order.
    public func items(in vault: UUID) async throws -> [SimulatedItem] {
        let ledger = try ledger(vault)
        var result: [SimulatedItem] = []
        for object in await store.list(prefix: SimulatedMember.itemPrefix(vault), viewer: accountID) {
            let parts = object.name.split(separator: "/").map(String.init)
            let tail = parts.count == 4 ? parts[3].split(separator: "-", maxSplits: 1).map(String.init) : []
            guard tail.count == 2, let recordID = UUID(uuidString: parts[2]), let version = UInt64(tail[0]),
                let author = UUID(uuidString: tail[1]), object.contents.count > 64
            else { continue }
            let signature = Array(object.contents[..<64])
            let envelope = Array(object.contents[64...])
            let keyID = (try? EnvelopeHeader.parse(envelope, expecting: .item))?.header.keyID
            func item(_ outcome: SimulatedItemOutcome) -> SimulatedItem {
                SimulatedItem(recordID: recordID, version: version, author: author, keyID: keyID, outcome: outcome)
            }
            if case .refused(let refusal) = ledger.writePermission(for: author, atEpoch: ledger.state.epoch) {
                result.append(item(.refused(refusal)))
                continue
            }
            guard let member = ledger.state.member(author),
                (try? Signatures.verify(
                    signature, for: Array(object.name.utf8) + [0] + envelope, domain: .logSegment,
                    signingKey: member.bundle.signingKey)) != nil
            else {
                result.append(item(.forged))
                continue
            }
            guard let keyID else {
                result.append(item(.malformed))
                continue
            }
            guard let key = keys[vault]?[keyID],
                let plaintext = try? RecordCipher.open(
                    envelope,
                    context: SimulatedMember.itemContext(
                        vault: vault, recordID: recordID, keyID: keyID, version: version),
                    key: key.key)
            else {
                result.append(item(.undecryptable(keyID: keyID)))
                continue
            }
            result.append(item(.read(String(decoding: plaintext.unprotectedCopy(), as: UTF8.self))))
        }
        return result
    }

    /// The newest readable text of each record.
    public func readable(in vault: UUID) async throws -> [UUID: String] {
        var newest: [UUID: (version: UInt64, text: String)] = [:]
        for item in try await items(in: vault) {
            guard case .read(let text) = item.outcome, (newest[item.recordID]?.version ?? 0) <= item.version else {
                continue
            }
            newest[item.recordID] = (item.version, text)
        }
        return newest.mapValues(\.text)
    }

    /// The vault's live records as rotation sees them: the newest accepted version of each.
    public func inventory(of vault: UUID) async throws -> [SealedRecordReference] {
        var newest: [UUID: SealedRecordReference] = [:]
        for item in try await items(in: vault) {
            guard case .read = item.outcome, let keyID = item.keyID,
                (newest[item.recordID]?.version ?? 0) <= item.version
            else { continue }
            newest[item.recordID] = SealedRecordReference(
                recordID: item.recordID, kind: .item, keyID: keyID, version: item.version)
        }
        return Array(newest.values)
    }

    // MARK: - Role changes, removal, leaving, rotation

    public mutating func changeRole(of account: UUID, to role: MemberRole, in vault: UUID) async throws {
        let record = try ledger(vault).proposeRoleChange(of: account, to: role, signedBy: keyset)
        try await publish(SharingObject(record))
        try await sync(vault)
    }

    /// Plans a rotation and saves the plan, as an interrupted device would have it. Nothing is published.
    @discardableResult
    public mutating func planRotation(_ reason: RotationReason, in vault: UUID) throws -> RotationPlan {
        let plan = try RotationPlanner.plan(reason, ledger: ledger(vault), signedBy: keyset, using: &generator)
        savedPlans[vault] = plan.encoded()
        return plan
    }

    /// Carries the saved plan forward from wherever it stands, performing at most `limit` steps (to interrupt it).
    /// Returns the status afterwards.
    @discardableResult
    public mutating func resumeRotation(in vault: UUID, limit: Int = .max) async throws -> RotationStatus {
        guard let saved = savedPlans[vault] else { return .complete }
        let plan = try RotationPlan.parse(saved)
        var performed = 0
        for step in plan.steps where performed < limit {
            performed += 1
            switch step {
            case .revokeTransportAccess(let account):
                await store.revokeShare(account)
            case .publish(let object):
                // Publishing a record that has since lost a fork is harmless: it stays a valid, outranked candidate.
                try await publish(object)
            case .resealRecords:
                try await sync(vault)
                guard try plan.status(in: ledger(vault), inventory: []) != .superseded else { break }
                let live = try await inventory(of: vault)
                let texts = try await readable(in: vault)
                for reference in try ledger(vault).recordsToReseal(in: live) {
                    guard let text = texts[reference.recordID] else { continue }
                    try await write(text, to: vault, recordID: reference.recordID, version: reference.version + 1)
                }
            }
        }
        try await sync(vault)
        let live = try await inventory(of: vault)
        let status = try plan.status(in: ledger(vault), inventory: live)
        if status == .complete || status == .superseded { savedPlans[vault] = nil }
        return status
    }

    /// Removes a member: plan, then carry it out.
    @discardableResult
    public mutating func remove(_ account: UUID, from vault: UUID) async throws -> RotationStatus {
        try planRotation(.removal(account), in: vault)
        return try await resumeRotation(in: vault)
    }

    /// Publishes this member's leave request.
    public func requestToLeave(_ vault: UUID) async throws {
        let request = try LeaveRequest.make(leaving: ledger(vault).state, as: keyset)
        try await publish(SharingObject(request))
    }

    /// As an administrator: turns every valid pending leave request into a rotation.
    public mutating func processLeaveRequests(in vault: UUID) async throws {
        try await sync(vault)
        let objects = await store.list(prefix: SharingObjectLocation.leavePrefix(vault), viewer: accountID)
        for request in try ledger(vault).pendingLeaveRequests(among: objects.map(\.contents)) {
            try planRotation(.departure(request), in: vault)
            try await resumeRotation(in: vault)
        }
    }
}

/// An account with real keys and nothing else, for tests that drive `WatchwordSharing` directly.
public struct SharingParty: Sendable {
    public let keyset: Keyset
    public let bundle: PublicKeyBundle

    public init(seed: UInt64) throws {
        var generator = SeededGenerator(seed: seed)
        let accountID = SimulatedMember.uuid(using: &generator)
        keyset = Keyset.generate(accountID: accountID, using: &generator)
        bundle = try keyset.publicKeyBundle()
    }

    /// Other keys under an account ID that already exists: what a store substituting a key would publish.
    public init(accountID: UUID, seed: UInt64) throws {
        var generator = SeededGenerator(seed: seed)
        keyset = Keyset.generate(accountID: accountID, using: &generator)
        bundle = try keyset.publicKeyBundle()
    }

    public var accountID: UUID {
        keyset.accountID
    }
}

/// A store, a key directory and the members who use them.
public struct SharingWorld: Sendable {
    public let store = HostileSharingStore()
    public let directory = InMemoryKeyBundleDirectory()

    public init() {}

    public func member(_ name: String, seed: UInt64) async throws -> SimulatedMember {
        try await SimulatedMember.make(name, seed: seed, store: store, directory: directory)
    }

    /// An owner with a new vault and one member per role, each invited, verified both ways and joined.
    public func household(roles: [MemberRole], seed: UInt64 = 100) async throws
        -> (vault: UUID, owner: SimulatedMember, members: [SimulatedMember])
    {
        var owner = try await member("owner", seed: seed)
        let vault = try await owner.createVault()
        var members: [SimulatedMember] = []
        for (index, role) in roles.enumerated() {
            var member = try await member("member \(index + 1)", seed: seed + UInt64(index) + 1)
            let invitation = try await owner.invite(
                member.accountID, to: vault, as: role, safetyNumber: member.safetyNumber)
            try await member.accept(invitation, ownerSafetyNumber: owner.safetyNumber)
            members.append(member)
        }
        return (vault, owner, members)
    }
}
