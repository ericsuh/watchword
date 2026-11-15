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

/// A record as a simulated member's device holds it once merged: the newest version it accepted, and from whom.
public struct MergedItem: Sendable, Hashable {
    public let version: UInt64
    public let author: UUID
    public let keyID: UUID
    public let text: String
}

/// One account with real keys taking part in shared vaults: the code an integrator will write around
/// `WatchwordSharing`, kept as small as it can be while still exercising every step (create, invite, verify, accept,
/// write, read, change a role, remove with rotation, leave, re-seal) against a `HostileSharingStore`.
///
/// Item writes stand in for sync's log segments: an item envelope sealed with `RecordCipher` under the vault key and
/// signed by its author over `name ‖ 0x00 ‖ envelope`, as `SyncEngine`'s objects are. A reader applies the three checks
/// the integration must make, in this order: may the author write (the ledger, now), is the signature the author's
/// (the key the chain lists), does it open under a key this member holds. What passes is **merged** into the device's
/// own record store (`merged`) and stays there whatever happens to its author's standing afterwards; what the device
/// has merged and its author may no longer write, the device publishes again under its own name
/// (`MembershipLedger.recordsToReseal`), which is how a demoted or removed member's data reaches members who had not
/// merged it (docs/02-architecture.md §8.7).
///
/// The order of a sync pass is the one §8.8 prescribes: membership first, then keys, then this device's own
/// proposals, then items.
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
    /// Records this device proposed and has not yet seen adopted, as they would be on disk, by vault.
    public var proposals: [UUID: [[UInt8]]] = [:]
    /// The device's own record store: what it has merged, by vault and record.
    public var merged: [UUID: [UUID: MergedItem]] = [:]
    /// Membership objects found permanently unacceptable, so that a flood is paid for once.
    public var refusedNames: Set<String> = []
    /// What the last comparison of member keys with this device's pins found, by vault (for the UI).
    public var keyChecks: [UUID: MemberKeyCheck] = [:]
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
        // Propose on the newest head this device can see, and publish only what could still be adopted.
        try await sync(vault)
        let package = try invitation.issue(ledger: ledger(vault), vaultKey: currentKey(vault), signedBy: keyset)
        try await publish(package.grant)
        try await propose(package.proposal, in: vault)
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
        // The ledger of an earlier membership, if there was one, is continued, never replaced.
        let joined = try incoming.accept(
            membership: records.map(\.contents), grants: grants, as: keyset, continuing: ledgers[vault])
        ledgers[vault] = joined.ledger
        keys[vault, default: [:]][joined.vaultKey.key.keyID] = joined.vaultKey
        keyChecks[vault] = try await joined.ledger.checkMemberKeys(against: contacts)
        merged[vault] = try await view(of: vault)
    }

    // MARK: - Syncing

    /// One sync pass over a vault's sharing objects: ingests the membership objects this device does not hold,
    /// compares the members' keys with its pins, fetches the current key if it is entitled to it and does not hold
    /// it, settles its own pending proposals, and merges the items it now accepts. Returns what the first ingest
    /// did.
    @discardableResult
    public mutating func sync(_ vault: UUID) async throws -> MembershipLedger.IngestReport {
        let report = try await ingest(vault)
        // A record of this device's that was in the chain and has been displaced is a proposal again.
        proposals[vault, default: []] += report.superseded.filter { $0.signer == accountID }.map { $0.encoded() }
        if try await settleProposals(in: vault) { _ = try await ingest(vault) }
        let ledger = try ledger(vault)
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
        merged[vault] = try await view(of: vault)
        return report
    }

    /// Lists the membership prefix and offers the ledger every object it does not hold. Names are looked at first:
    /// one that is not a membership object's, that carries a hash the ledger holds, or whose contents were refused
    /// for good before, is not fetched again; and contents that are not what their name commits to are not offered.
    private mutating func ingest(_ vault: UUID) async throws -> MembershipLedger.IngestReport {
        var ledger = try ledger(vault)
        let listed = await store.list(prefix: SharingObjectLocation.membershipPrefix(vault), viewer: accountID)
        let offered = listed.filter { object in
            guard let location = SharingObjectLocation(name: object.name), !ledger.holds(location),
                !refusedNames.contains(object.name)
            else { return false }
            return location.isName(of: object.contents)
        }
        let report = ledger.ingest(offered.map(\.contents))
        for rejection in report.rejected {
            switch rejection.reason {
            case .malformed, .invalid: refusedNames.insert(offered[rejection.index].name)
            case .unconnected: break
            }
        }
        ledgers[vault] = ledger
        keyChecks[vault] = try await ledger.checkMemberKeys(against: contacts)
        return report
    }

    /// Publishes a record this device signed, if it can still be adopted, and remembers it until it is.
    private mutating func propose(_ record: MembershipRecord, in vault: UUID) async throws {
        guard try ledger(vault).status(of: record) == .awaitingPublication else { return }
        proposals[vault, default: []].append(record.encoded())
        try await publish(SharingObject(record))
        try await sync(vault)
    }

    /// Looks at every record this device proposed and has not seen adopted: one that was adopted is forgotten, one
    /// still waiting is published again, and one that lost its place is proposed again on the new head if what it
    /// did is still wanted and still possible. Returns whether anything was published.
    private mutating func settleProposals(in vault: UUID) async throws -> Bool {
        var published = false
        var remaining: [[UInt8]] = []
        for bytes in proposals[vault] ?? [] {
            let record = try MembershipRecord.parse(bytes)
            let ledger = try ledger(vault)
            switch ledger.status(of: record) {
            case .adopted:
                continue
            case .awaitingPublication:
                try await publish(SharingObject(record))
                remaining.append(bytes)
                published = true
            case .superseded:
                guard let again = try await proposeAgain(record.operation, in: vault) else { continue }
                try await publish(SharingObject(again))
                remaining.append(again.encoded())
                published = true
            }
        }
        proposals[vault] = remaining
        return published
    }

    /// The record that does on the current head what a superseded record of this device's did; `nil` if it has
    /// happened by other means, is no longer allowed, or is a rotation (which has a plan of its own).
    private mutating func proposeAgain(_ operation: MembershipRecord.Operation, in vault: UUID) async throws
        -> MembershipRecord?
    {
        let ledger = try ledger(vault)
        switch operation {
        case .changeRole(let account, let role):
            return try? ledger.proposeRoleChange(of: account, to: role, signedBy: keyset)
        case .addMember(let account, let role):
            // The invitation over again, from the pin: the key may have changed on the winning branch, so the grant
            // is made again too.
            guard
                var invitation = try? await OutgoingInvitation.begin(
                    vaultID: vault, inviting: account, as: role, directory: directory, contacts: contacts),
                let key = try? currentKey(vault),
                let package = try? invitation.issue(ledger: ledger, vaultKey: key, signedBy: keyset)
            else { return nil }
            try await publish(package.grant)
            return package.proposal
        case .deleteVault:
            return try? ledger.proposeDeletion(signedBy: keyset)
        case .createVault, .removeMember, .memberLeft, .rotateKey:
            return nil
        }
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
        if case .refused = ledger.writePermission(for: accountID) { throw SharingError.notPermitted }
        let key = try currentKey(vault)
        try await write(text, to: vault, recordID: recordID, version: version, under: key)
        merged[vault, default: [:]][recordID] = MergedItem(
            version: version, author: accountID, keyID: key.key.keyID, text: text)
    }

    /// Every item object on the store as this member judges it now, in name order.
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
            if case .refused(let refusal) = ledger.writePermission(for: author) {
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

    /// The device's record store as it would be after merging now: what it has merged already, overlaid with the
    /// newer versions it accepts at this moment. What was merged earlier is never taken out again.
    public func view(of vault: UUID) async throws -> [UUID: MergedItem] {
        var newest = merged[vault] ?? [:]
        for item in try await items(in: vault) {
            guard case .read(let text) = item.outcome, let keyID = item.keyID,
                (newest[item.recordID]?.version ?? 0) < item.version
            else { continue }
            newest[item.recordID] = MergedItem(version: item.version, author: item.author, keyID: keyID, text: text)
        }
        return newest
    }

    /// Merges what this device accepts now into its record store, without a membership pass: a rotation's
    /// `mergeOutstandingWrites` step.
    public mutating func mergeItems(in vault: UUID) async throws {
        merged[vault] = try await view(of: vault)
    }

    /// The newest text this device holds of each record.
    public func readable(in vault: UUID) async throws -> [UUID: String] {
        try await view(of: vault).mapValues(\.text)
    }

    /// The vault's live records as rotation sees them.
    public func inventory(of vault: UUID) async throws -> [SealedRecordReference] {
        try await view(of: vault).map { recordID, item in
            SealedRecordReference(
                recordID: recordID, kind: .item, keyID: item.keyID, version: item.version, author: item.author)
        }
    }

    /// The re-seal step: writes again, under the current key and this member's name, every record the ledger lists
    /// (sealed under an earlier key, or last written by an account that may no longer write). Skipped by a member
    /// who may not write or does not hold the current key. Returns how many were written.
    @discardableResult
    public mutating func reseal(_ vault: UUID) async throws -> Int {
        let ledger = try ledger(vault)
        guard ledger.writePermission(for: accountID).isAllowed, (try? currentKey(vault)) != nil else { return 0 }
        try await mergeItems(in: vault)
        let texts = merged[vault] ?? [:]
        let stale = ledger.recordsToReseal(in: try await inventory(of: vault))
        for reference in stale {
            guard let item = texts[reference.recordID] else { continue }
            try await write(item.text, to: vault, recordID: reference.recordID, version: reference.version + 1)
        }
        return stale.count
    }

    // MARK: - Role changes, removal, leaving, rotation

    /// Changes a member's role: a sync pass first (so the record is built on the newest head, and what the member
    /// wrote so far is merged while they may still write), then the record, then the re-seal step, which publishes
    /// again whatever a member who is now read-only had written.
    public mutating func changeRole(of account: UUID, to role: MemberRole, in vault: UUID) async throws {
        try await sync(vault)
        let record = try ledger(vault).proposeRoleChange(of: account, to: role, signedBy: keyset)
        try await propose(record, in: vault)
        try await reseal(vault)
    }

    /// Plans a rotation and saves the plan, as an interrupted device would have it. Nothing is published.
    @discardableResult
    public mutating func planRotation(_ reason: RotationReason, in vault: UUID) async throws -> RotationPlan {
        let ledger = try ledger(vault)
        let plan = try RotationPlanner.plan(
            reason, ledger: ledger, memberKeys: try await ledger.checkMemberKeys(against: contacts),
            signedBy: keyset, using: &generator)
        savedPlans[vault] = plan.encoded()
        return plan
    }

    /// Carries the saved plan forward from wherever it stands, performing at most `limit` steps (to interrupt it).
    /// Returns the status afterwards. A plan that was superseded is planned again, if its member is still to go.
    @discardableResult
    public mutating func resumeRotation(in vault: UUID, limit: Int = .max) async throws -> RotationStatus {
        var status = RotationStatus.complete
        for _ in 0..<3 {
            guard let saved = savedPlans[vault] else { return status }
            let plan = try RotationPlan.parse(saved, account: bundle)
            status = try await carryOut(plan, in: vault, limit: limit)
            switch status {
            case .complete:
                savedPlans[vault] = nil
            case .superseded:
                savedPlans[vault] = nil
                // The intent outlives the plan: a removal or departure that lost a fork is planned again.
                if plan.reason.departingAccount != nil, (try? await planRotation(plan.reason, in: vault)) != nil {
                    continue
                }
            case .awaitingPublication, .resealing:
                break
            }
            return status
        }
        return status
    }

    private mutating func carryOut(_ plan: RotationPlan, in vault: UUID, limit: Int) async throws -> RotationStatus {
        var performed = 0
        steps: for step in plan.steps(in: try ledger(vault)) where performed < limit {
            performed += 1
            switch step {
            case .revokeTransportAccess(let account):
                await store.revokeShare(account)
            case .mergeOutstandingWrites:
                try await mergeItems(in: vault)
            case .publish(let object):
                if object == plan.record {
                    // Never publish a record that can no longer be adopted: look at the store once more first.
                    try await sync(vault)
                    guard try ledger(vault).status(of: plan.proposal) == .awaitingPublication else { break steps }
                }
                try await publish(object)
            case .resealRecords:
                try await sync(vault)
                guard try ledger(vault).status(of: plan.proposal) == .adopted else { break steps }
                try await reseal(vault)
            }
        }
        try await sync(vault)
        return try plan.status(in: ledger(vault), inventory: await inventory(of: vault))
    }

    /// Removes a member: plan, then carry it out.
    @discardableResult
    public mutating func remove(_ account: UUID, from vault: UUID) async throws -> RotationStatus {
        try await sync(vault)
        try await planRotation(.removal(account), in: vault)
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
        for request in try ledger(vault).pendingLeaveRequests(among: objects) {
            guard (try? await planRotation(.departure(request), in: vault)) != nil else { continue }
            try await resumeRotation(in: vault)
        }
    }

    /// Plans again every removal that lost a fork and that this account may sign (`MembershipLedger.owedRemovals`).
    public mutating func settleOwedRemovals(in vault: UUID) async throws {
        try await sync(vault)
        for owed in try ledger(vault).owedRemovals {
            guard (try? await planRotation(owed.reason, in: vault)) != nil else { continue }
            try await resumeRotation(in: vault)
        }
    }

    /// Everything a device does for a shared vault when it syncs (docs/02-architecture.md §8.8): the sync pass, then
    /// any plan of its own, removals that are owed, departures that were asked for, and the re-seal step.
    public mutating func maintain(_ vault: UUID) async throws {
        try await sync(vault)
        try await resumeRotation(in: vault)
        try await settleOwedRemovals(in: vault)
        try await processLeaveRequests(in: vault)
        try await reseal(vault)
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
