import Foundation
import WatchwordCrypto
import WatchwordSharing

/// A member as a forged membership record spells it: any bytes at all.
public struct ForgedEntry: Sendable, Hashable {
    public var accountID: UUID
    public var role: UInt8
    public var since: UInt64
    public var agreementKey: [UInt8]
    public var signingKey: [UInt8]
    public var selfSignature: [UInt8]

    public init(_ member: Member) {
        self.init(bundle: member.bundle, role: member.role, since: member.since)
    }

    public init(bundle: PublicKeyBundle, role: MemberRole, since: UInt64) {
        accountID = bundle.accountID
        self.role = role.rawValue
        self.since = since
        agreementKey = bundle.agreementKey
        signingKey = bundle.signingKey
        selfSignature = bundle.selfSignature
    }
}

/// A membership record built field by field with an encoder of its own, so that tests can write what
/// `WatchwordSharing` would never sign (docs/04-test-plan.md §6.4): any signer, any epoch, any member list, any key.
/// It starts as the honest record for an operation and is then altered. Being a second implementation of the format,
/// it also checks the module's encoder: an unaltered forgery must be accepted.
public struct ForgedRecord: Sendable {
    public var magic: [UInt8] = Array("WWMR".utf8)
    public var formatVersion: UInt8 = 2
    public var vaultID: UUID
    public var epoch: UInt64
    public var previousHash: [UInt8]
    public var signer: UUID
    /// The operation code and its operands, as bytes.
    public var operation: [UInt8]
    public var vaultKeyID: UUID
    public var keyEpoch: UInt64
    /// The write cut, as bytes. Empty is what an honest record carries where no permission to write ends, and a
    /// legitimate cut ("nothing") where one does.
    public var writeCut: [UInt8] = []
    public var entries: [ForgedEntry]
    /// Whether to put the entries in canonical order when encoding.
    public var sortsEntries = true

    /// The honest genesis for `owner`.
    public init(genesisOf vaultID: UUID, owner: PublicKeyBundle, vaultKeyID: UUID) {
        self.vaultID = vaultID
        epoch = 0
        previousHash = [UInt8](repeating: 0, count: 32)
        signer = owner.accountID
        operation = [0]
        self.vaultKeyID = vaultKeyID
        keyEpoch = 0
        entries = [ForgedEntry(bundle: owner, role: .owner, since: 0)]
    }

    /// The record an honest `signer` would write for `operation` after `state`. `adding` is the new member's bundle
    /// for `.addMember`; `newKeyID` is the key a rotation introduces.
    public init(
        after state: MembershipState, signer: UUID, operation: MembershipRecord.Operation,
        adding: PublicKeyBundle? = nil, newKeyID: UUID? = nil
    ) {
        vaultID = state.vaultID
        epoch = state.epoch + 1
        previousHash = state.hash.bytes
        self.signer = signer
        self.operation = ForgedRecord.bytes(of: operation)
        vaultKeyID = newKeyID ?? state.vaultKeyID
        keyEpoch = newKeyID == nil ? state.keyEpoch : state.epoch + 1
        entries = state.members.map(ForgedEntry.init)
        switch operation {
        case .createVault, .rotateKey, .deleteVault:
            break
        case .addMember(_, let role):
            if let adding { entries.append(ForgedEntry(bundle: adding, role: role, since: state.epoch + 1)) }
        case .removeMember(let account), .memberLeft(let account, _):
            entries.removeAll { $0.accountID == account }
        case .changeRole(let account, let role):
            for index in entries.indices where entries[index].accountID == account {
                entries[index].role = role.rawValue
            }
        }
    }

    public static func bytes(of operation: MembershipRecord.Operation) -> [UInt8] {
        switch operation {
        case .createVault: return [0]
        case .addMember(let account, let role): return [1] + bytes(account) + [role.rawValue]
        case .removeMember(let account): return [2] + bytes(account)
        case .memberLeft(let account, let signature): return [3] + bytes(account) + signature
        case .changeRole(let account, let role): return [4] + bytes(account) + [role.rawValue]
        case .rotateKey: return [5]
        case .deleteVault: return [6]
        }
    }

    public static func bytes(_ id: UUID) -> [UInt8] {
        let u = id.uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }

    /// Sixteen bytes as a UUID.
    static func uuid(_ b: [UInt8]) -> UUID {
        precondition(b.count == 16)
        return UUID(
            uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
        )
    }

    static func littleEndian<T: FixedWidthInteger>(_ value: T) -> [UInt8] {
        (0..<(T.bitWidth / 8)).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
    }

    /// Everything before the signature.
    public var content: [UInt8] {
        var out = magic + [formatVersion]
        out += ForgedRecord.bytes(vaultID) + ForgedRecord.littleEndian(epoch) + previousHash
        out += ForgedRecord.bytes(signer) + operation
        out += ForgedRecord.bytes(vaultKeyID) + ForgedRecord.littleEndian(keyEpoch)
        out += ForgedRecord.littleEndian(UInt16(truncatingIfNeeded: writeCut.count)) + writeCut
        out += ForgedRecord.littleEndian(UInt16(truncatingIfNeeded: entries.count))
        let ordered =
            sortsEntries
            ? entries.sorted {
                ForgedRecord.bytes($0.accountID).lexicographicallyPrecedes(ForgedRecord.bytes($1.accountID))
            } : entries
        for entry in ordered {
            out += ForgedRecord.bytes(entry.accountID) + [entry.role] + ForgedRecord.littleEndian(entry.since)
            out += entry.agreementKey + entry.signingKey + entry.selfSignature
        }
        return out
    }

    /// The record signed by `keyset`'s key, whoever `signer` says signed it.
    public func signed(by keyset: Keyset) throws -> [UInt8] {
        content + (try keyset.sign(content, domain: .membership))
    }

    public func withSignature(_ signature: [UInt8]) -> [UInt8] {
        content + signature
    }
}

/// A shared vault with one member of each role and real keys, driven directly (no store, no simulation): the owner,
/// an administrator, a read-write member and a read-only member, with an outsider who was never invited.
public struct SharingHousehold: Sendable {
    public let owner: SharingParty
    public let administrator: SharingParty
    public let writer: SharingParty
    public let reader: SharingParty
    public let outsider: SharingParty
    /// The owner's verified contacts, in which everyone above is pinned.
    public let contacts: VerifiedContacts
    public let vaultID: UUID
    public var ledger: MembershipLedger
    public var vaultKey: VaultKey
    public var generator: SeededGenerator
    public let now = Date(timeIntervalSince1970: 1_800_000_000)

    /// Creates the vault and adds the three members: the head is epoch 3.
    public static func make(seed: UInt64 = 1) async throws -> SharingHousehold {
        var generator = SeededGenerator(seed: seed &* 1_000)
        let owner = try SharingParty(seed: seed &* 1_000 + 1)
        let vaultID = SimulatedMember.uuid(using: &generator)
        let vaultKey = VaultKey.generate(vaultID: vaultID, using: &generator)
        var household = SharingHousehold(
            owner: owner,
            administrator: try SharingParty(seed: seed &* 1_000 + 2),
            writer: try SharingParty(seed: seed &* 1_000 + 3),
            reader: try SharingParty(seed: seed &* 1_000 + 4),
            outsider: try SharingParty(seed: seed &* 1_000 + 5),
            contacts: VerifiedContacts(store: InMemoryVerifiedContactStore(), account: owner.bundle),
            vaultID: vaultID,
            ledger: try MembershipLedger.create(vaultKey: vaultKey, owner: owner.keyset),
            vaultKey: vaultKey,
            generator: generator)
        try await household.add(household.administrator, as: .administrator, by: owner)
        try await household.add(household.writer, as: .readWrite, by: owner)
        try await household.add(household.reader, as: .readOnly, by: owner)
        return household
    }

    /// `party` as a contact the owner has verified (by eye: these tests are not about the comparison).
    public func contact(_ party: SharingParty) async throws -> VerifiedContact {
        try await contacts.verify(
            party.bundle, evidence: .comparedByEye(shown: party.bundle.fingerprint), signedBy: owner.keyset, at: now)
    }

    public var state: MembershipState {
        ledger.state
    }

    /// Ingests one record and requires that it became the head.
    @discardableResult
    public mutating func adopt(_ record: [UInt8]) throws -> MembershipLedger.IngestReport {
        let report = ledger.ingest([record])
        if let rejection = report.rejected.first {
            switch rejection.reason {
            case .malformed(let error): throw error
            case .invalid(let error): throw error
            case .unconnected: throw MembershipError.previousHashMismatch
            }
        }
        return report
    }

    public mutating func add(_ party: SharingParty, as role: MemberRole, by signer: SharingParty) async throws {
        let record = try ledger.proposeAddition(of: await contact(party), as: role, signedBy: signer.keyset)
        try adopt(record.encoded())
    }

    /// Plans a rotation as `signer`, ingests its record and switches `vaultKey` to the new key.
    @discardableResult
    public mutating func rotate(_ reason: RotationReason, by signer: SharingParty) throws -> RotationPlan {
        let plan = try RotationPlanner.plan(reason, ledger: ledger, signedBy: signer.keyset, using: &generator)
        try adopt(plan.record.contents)
        vaultKey = try ledger.openGrant(
            of: plan.newKeyID, from: plan.grants.map { (name: $0.name, contents: $0.contents) }, as: signer.keyset)
        return plan
    }

    /// A forged record that starts as the honest one for `operation` on the current head.
    public func forgery(
        _ operation: MembershipRecord.Operation, signer: SharingParty, adding: PublicKeyBundle? = nil,
        newKeyID: UUID? = nil
    ) -> ForgedRecord {
        ForgedRecord(after: state, signer: signer.accountID, operation: operation, adding: adding, newKeyID: newKeyID)
    }

    public mutating func newKeyID() -> UUID {
        SimulatedMember.uuid(using: &generator)
    }
}

extension MemberKeyCheck {
    /// A comparison that found nothing, for tests that are not about pins: what a device with no pin that
    /// contradicts the chain would get from `MembershipLedger.checkMemberKeys`.
    public static func findingNothing(in ledger: MembershipLedger) -> MemberKeyCheck {
        .unchecked(in: ledger)
    }
}

extension RotationPlanner {
    /// Plans with a member-key comparison that found nothing (`MemberKeyCheck.findingNothing`) and, where the
    /// rotation needs a write cut, the cut that holds nothing: for tests that are not about pins or about writes.
    public static func plan<R: RandomNumberGenerator>(
        _ reason: RotationReason, ledger: MembershipLedger, signedBy keyset: Keyset, using generator: inout R
    ) throws -> RotationPlan {
        try plan(
            reason, ledger: ledger, memberKeys: .findingNothing(in: ledger),
            writeCut: ledger.cutOfNothing(for: reason), signedBy: keyset, using: &generator)
    }

    public static func plan(_ reason: RotationReason, ledger: MembershipLedger, signedBy keyset: Keyset) throws
        -> RotationPlan
    {
        try plan(
            reason, ledger: ledger, memberKeys: .findingNothing(in: ledger),
            writeCut: ledger.cutOfNothing(for: reason), signedBy: keyset)
    }

    /// Plans with a given member-key comparison and the cut that holds nothing where one is needed.
    public static func plan<R: RandomNumberGenerator>(
        _ reason: RotationReason, ledger: MembershipLedger, memberKeys: MemberKeyCheck, signedBy keyset: Keyset,
        using generator: inout R
    ) throws -> RotationPlan {
        try plan(
            reason, ledger: ledger, memberKeys: memberKeys, writeCut: ledger.cutOfNothing(for: reason),
            signedBy: keyset, using: &generator)
    }
}

extension MembershipLedger {
    /// `WriteCut.nothing` if a rotation for `reason` on this head needs a cut, `nil` if it must not carry one.
    public func cutOfNothing(for reason: RotationReason) -> WriteCut? {
        guard let account = reason.departingAccount, requiresWriteCut(removing: account) else { return nil }
        return .nothing
    }

    /// Changes a role with the cut that holds nothing where one is needed: for tests that are not about writes.
    public func proposeRoleChange(of accountID: UUID, to role: MemberRole, signedBy keyset: Keyset) throws
        -> MembershipRecord
    {
        try proposeRoleChange(
            of: accountID, to: role,
            writeCut: requiresWriteCut(changingRoleOf: accountID, to: role) ? .nothing : nil, signedBy: keyset)
    }

    /// Wraps a key to a member with a member-key comparison that found nothing.
    public func makeGrant(of vaultKey: VaultKey, to recipient: UUID, from keyset: Keyset) throws
        -> VaultKeyGrantRecord
    {
        try makeGrant(of: vaultKey, to: recipient, memberKeys: .findingNothing(in: self), from: keyset)
    }

    /// Leave requests as a store would list them, under their own names.
    public func pendingLeaveRequests(among requests: [LeaveRequest]) -> [LeaveRequest] {
        pendingLeaveRequests(among: requests.map { (name: SharingObject($0).name, contents: $0.encoded()) })
    }
}
