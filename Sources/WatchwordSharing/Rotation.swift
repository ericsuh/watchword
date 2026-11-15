import Foundation
import WatchwordCrypto
import WatchwordEnvelope

/// A stored record as rotation needs to know it: which record, and which key it is sealed under. The integrator
/// builds these from its record store's rows; this module never sees a ciphertext.
public struct SealedRecordReference: Sendable, Hashable {
    public let recordID: UUID
    public let kind: EnvelopeKind
    public let keyID: UUID
    public let version: UInt64

    public init(recordID: UUID, kind: EnvelopeKind, keyID: UUID, version: UInt64) {
        self.recordID = recordID
        self.kind = kind
        self.keyID = keyID
        self.version = version
    }
}

/// Why a vault key is being rotated (docs/02-architecture.md §8.6, principle 5).
public enum RotationReason: Sendable, Hashable {
    /// An administrator removes a member (PRD F4.3).
    case removal(UUID)
    /// A member asked to leave (PRD F4.4); an administrator's device carries it out.
    case departure(LeaveRequest)
    /// A new key with the same members.
    case routine

    /// The account that loses access, if any.
    public var departingAccount: UUID? {
        switch self {
        case .removal(let account): return account
        case .departure(let request): return request.accountID
        case .routine: return nil
        }
    }
}

/// One thing the integrator does to carry out a rotation. Every step is safe to repeat.
public enum RotationStep: Sendable, Hashable {
    /// Remove the account from the transport's share (the CloudKit share's participants, the shared folder). First,
    /// because it takes effect at once on the server, whenever the rest completes (PRD F4.3a).
    case revokeTransportAccess(UUID)
    /// Create the object on the transport. An object that already exists with these contents counts as created.
    case publish(SharingObject)
    /// Re-seal every record `MembershipLedger.recordsToReseal(in:)` lists, under the vault's current key, as new
    /// versions through the vault's ordinary save path. Repeat until the list is empty: other devices may still be
    /// writing under the old key until they have seen the new record.
    case resealRecords
}

/// Where a rotation stands, judged from what this device can see rather than from a counter it kept, so that an
/// interrupted rotation resumes correctly from whatever was actually done.
public enum RotationStatus: Sendable, Hashable {
    /// The plan's record is not in this device's accepted chain: publish the plan's objects (again) and ingest.
    case awaitingPublication
    /// The record is accepted; `remaining` records are still sealed under an earlier key.
    case resealing(remaining: Int)
    case complete
    /// Another record took the plan's place in the chain (a concurrent administrator's, by the ledger's fork rule), or
    /// the chain was reorganised beneath it. The plan is dead; plan again on the new head if the change is still
    /// wanted (`RotationPlanner.plan` throws `nothingToDo` if it has already happened).
    case superseded
}

/// A vault-key rotation as data (docs/02-architecture.md §8.6; PRD F4.3, F4.4): the new key ID, the key wrapped to
/// every remaining member, and the signed membership record that removes the departing member and names the new key.
/// Which records to re-seal is `MembershipLedger.recordsToReseal(in:)`, asked afresh each time because the set
/// changes while other devices catch up.
///
/// The plan holds no key material in the clear: the new key exists only inside the grants, including one to the
/// planner's own account, which is how the planning device (and the account's other devices) obtain it once the
/// record is accepted (`MembershipLedger.openGrant`). So a plan can be written to disk and resumed after any
/// interruption, and losing it loses nothing but the work.
///
/// ```
/// magic "WWRP"  formatVersion u8 = 1  vaultID 16  baseEpoch u64  baseHash 32  newKeyID 16
/// reason u8: 0 removal + account 16 | 1 departure + leave request 109 | 2 routine
/// recordLength u16, membership record
/// grantCount u16 (1...64), then that many grants of 245 bytes each
/// ```
public struct RotationPlan: Sendable, Hashable {
    static let magic: [UInt8] = Array("WWRP".utf8)
    static let formatVersion: UInt8 = 1
    /// The most a plan can encode to; anything longer is refused before it is parsed (SEC9).
    public static let maximumLength =
        4 + 1 + 16 + 8 + 32 + 16 + 1 + LeaveRequest.encodedLength + 2 + MembershipRecord.maximumLength + 2
        + MembershipLimits.maximumMembers * KeyGrantCodec.encodedLength

    public let vaultID: UUID
    public let reason: RotationReason
    /// The head the plan was made on.
    public let baseEpoch: UInt64
    public let baseHash: MembershipHash
    public let newKeyID: UUID
    /// The membership record, at `baseEpoch + 1`.
    public let record: SharingObject
    public let recordHash: MembershipHash
    /// One grant of the new key per remaining member, the planner's own account included.
    public let grants: [SharingObject]

    /// What to do, in order: revoke the transport share, publish the grants, publish the record, re-seal.
    public var steps: [RotationStep] {
        var steps: [RotationStep] = []
        if let account = reason.departingAccount { steps.append(.revokeTransportAccess(account)) }
        steps += grants.map(RotationStep.publish)
        steps.append(.publish(record))
        steps.append(.resealRecords)
        return steps
    }

    /// Where the rotation stands on this device. `inventory` is the vault's live records.
    public func status(in ledger: MembershipLedger, inventory: [SealedRecordReference]) -> RotationStatus {
        if ledger.contains(recordHash) {
            let remaining = ledger.recordsToReseal(in: inventory).count
            return remaining == 0 ? .complete : .resealing(remaining: remaining)
        }
        guard let base = ledger.state(atEpoch: baseEpoch), base.hash == baseHash,
            ledger.state(atEpoch: baseEpoch + 1) == nil
        else { return .superseded }
        return .awaitingPublication
    }

    public func encoded() -> [UInt8] {
        var out = RotationPlan.magic + [RotationPlan.formatVersion]
        out += vaultID.sharingBytes + SharingBytes.littleEndian(baseEpoch) + baseHash.bytes + newKeyID.sharingBytes
        switch reason {
        case .removal(let account): out += [0] + account.sharingBytes
        case .departure(let request): out += [1] + request.encoded()
        case .routine: out += [2]
        }
        out += SharingBytes.littleEndian(UInt16(record.contents.count)) + record.contents
        out += SharingBytes.littleEndian(UInt16(grants.count))
        for grant in grants {
            out += grant.contents
        }
        return out
    }

    /// Parses a plan read back from local storage. The objects' names are derived again from their contents, and the
    /// record and every grant must be for this plan's vault, epoch and key, so a plan altered on disk cannot make
    /// this device publish something under a name of the attacker's choosing.
    public static func parse(_ bytes: [UInt8]) throws -> RotationPlan {
        guard bytes.count <= maximumLength else { throw SharingFormatError.tooLarge(bytes.count) }
        var reader = SharingReader(bytes)
        try reader.header(magic: magic, version: formatVersion)
        let vaultID = try reader.uuid()
        let baseEpoch = try reader.uint64()
        guard baseEpoch < MembershipLimits.maximumEpoch else { throw SharingFormatError.epochOutOfRange(baseEpoch) }
        let baseHash = MembershipHash(unchecked: try reader.read(MembershipHash.byteCount))
        let newKeyID = try reader.uuid()
        let reason: RotationReason
        let code = try reader.byte()
        switch code {
        case 0: reason = .removal(try reader.uuid())
        case 1: reason = .departure(try LeaveRequest.parse(reader.read(LeaveRequest.encodedLength)))
        case 2: reason = .routine
        default: throw SharingFormatError.unknownOperation(code)
        }
        let recordLength = Int(try reader.uint16())
        guard recordLength <= MembershipRecord.maximumLength else { throw SharingFormatError.tooLarge(recordLength) }
        let record = try MembershipRecord.parse(reader.read(recordLength))
        let count = Int(try reader.uint16())
        guard (1...MembershipLimits.maximumMembers).contains(count) else {
            throw SharingFormatError.memberCountOutOfRange(count)
        }
        guard reader.remaining == count * KeyGrantCodec.encodedLength else {
            throw reader.remaining < count * KeyGrantCodec.encodedLength
                ? SharingFormatError.truncated : SharingFormatError.trailingBytes
        }
        var grants: [SharingObject] = []
        for _ in 0..<count {
            let grant = try VaultKeyGrantRecord(KeyGrantCodec.parse(reader.read(KeyGrantCodec.encodedLength)))
            guard grant.grant.vaultID == vaultID, grant.grant.keyID == newKeyID else {
                throw SharingFormatError.notCanonical
            }
            grants.append(SharingObject(grant))
        }
        try reader.finish()
        guard record.vaultID == vaultID, record.epoch == baseEpoch + 1, record.previousHash == baseHash,
            record.vaultKeyID == newKeyID
        else { throw SharingFormatError.notCanonical }
        return RotationPlan(
            vaultID: vaultID, reason: reason, baseEpoch: baseEpoch, baseHash: baseHash, newKeyID: newKeyID,
            record: SharingObject(record), recordHash: record.hash, grants: grants)
    }
}

/// Plans rotations (docs/02-architecture.md §8.6).
public enum RotationPlanner {
    /// Plans the removal of a member, a member's departure, or a routine rotation, on the ledger's current head.
    ///
    /// Generates the new vault key, wraps it to every member who remains, signs the membership record, and forgets
    /// the key. Needs an unlocked administrator: the owner for anything that removes an administrator.
    ///
    /// - Throws: `SharingError.nothingToDo` if the member is already gone (a concurrent administrator got there
    ///   first); `SharingError.notPermitted` or a `MembershipError` if this account may not do it.
    public static func plan<R: RandomNumberGenerator>(
        _ reason: RotationReason, ledger: MembershipLedger, signedBy keyset: Keyset, using generator: inout R
    ) throws -> RotationPlan {
        let state = ledger.state
        guard !state.isDeleted else { throw SharingError.vaultDeleted }
        let operation: MembershipRecord.Operation
        switch reason {
        case .removal(let account):
            guard state.member(account) != nil else { throw SharingError.nothingToDo }
            operation = .removeMember(account)
        case .departure(let request):
            guard request.vaultID == ledger.vaultID else { throw SharingError.leaveRequestInvalid }
            guard state.member(request.accountID) != nil else { throw SharingError.nothingToDo }
            try request.validate(against: state)
            operation = .memberLeft(request.accountID, requestSignature: request.signature)
        case .routine:
            operation = .rotateKey
        }

        let newKey = VaultKey.generate(vaultID: ledger.vaultID, using: &generator)
        defer { newKey.zeroise() }
        let (record, next) = try ledger.propose(
            operation, newKeyID: newKey.key.keyID, adding: nil, signedBy: keyset)
        let grants = try next.members.map { member in
            SharingObject(try VaultKeyGrantRecord(VaultKeyGrant.seal(newKey, to: member.bundle, from: keyset)))
        }
        return RotationPlan(
            vaultID: ledger.vaultID, reason: reason, baseEpoch: state.epoch, baseHash: state.hash,
            newKeyID: newKey.key.keyID, record: SharingObject(record), recordHash: record.hash, grants: grants)
    }

    public static func plan(_ reason: RotationReason, ledger: MembershipLedger, signedBy keyset: Keyset) throws
        -> RotationPlan
    {
        var generator = SystemRandomNumberGenerator()
        return try plan(reason, ledger: ledger, signedBy: keyset, using: &generator)
    }
}

/// One reason a vault's rotation is not finished, for the UI to show (PRD F4.3: "pending rotation").
public enum PendingRotation: Sendable, Hashable {
    /// A member asked to leave and no administrator's device has rotated the key yet. They are already off the
    /// transport share; until the rotation, new items are still sealed under a key they hold.
    case departureRequested(UUID)
    /// This device planned a rotation whose record is not yet in the chain it sees.
    case awaitingPublication(RotationReason)
    /// The key has been rotated; this many records are still sealed under an earlier key.
    case resealing(remaining: Int)
    /// This device does not hold the vault's current key yet (its grant has not arrived or does not open).
    case awaitingKey(UUID)
}

extension MembershipLedger {
    /// The valid leave requests among objects listed under `SharingObjectLocation.leavePrefix`, one per member, in
    /// account order. Requests that are malformed, for another vault, replayed from an earlier stint or not signed
    /// by the member are skipped (§8.6).
    public func pendingLeaveRequests(among candidates: [[UInt8]]) -> [LeaveRequest] {
        var found: [UUID: LeaveRequest] = [:]
        for bytes in candidates.prefix(MembershipLimits.maximumCandidates) {
            guard let request = try? LeaveRequest.parse(bytes), found[request.accountID] == nil,
                (try? request.validate(against: state)) != nil
            else { continue }
            found[request.accountID] = request
        }
        return found.values.sorted { $0.accountID.sharingPrecedes($1.accountID) }
    }

    /// The records that must be re-sealed: every one not under the vault's current key (principle 5; ADR 0007).
    /// In a stable order, so that an interrupted pass resumes where it stopped.
    public func recordsToReseal(in inventory: [SealedRecordReference]) -> [SealedRecordReference] {
        let current = state.vaultKeyID
        return inventory.filter { $0.keyID != current }.sorted {
            $0.recordID == $1.recordID
                ? $0.kind.rawValue < $1.kind.rawValue : $0.recordID.sharingPrecedes($1.recordID)
        }
    }

    /// Everything that keeps this vault's key rotation from being finished, as this device sees it; empty when
    /// nothing is pending (PRD F4.3).
    ///
    /// - Parameters:
    ///   - plan: this device's own unfinished plan, if it has one.
    ///   - leaveRequests: objects listed under `SharingObjectLocation.leavePrefix`.
    ///   - inventory: the vault's live records.
    ///   - heldKeyIDs: the IDs of the vault keys this device holds for the vault.
    public func pendingRotation(
        plan: RotationPlan?, leaveRequests: [[UInt8]], inventory: [SealedRecordReference], heldKeyIDs: Set<UUID>
    ) -> [PendingRotation] {
        var pending: [PendingRotation] = pendingLeaveRequests(among: leaveRequests).map {
            .departureRequested($0.accountID)
        }
        if let plan, plan.status(in: self, inventory: inventory) == .awaitingPublication {
            pending.append(.awaitingPublication(plan.reason))
        }
        if !state.isDeleted, !heldKeyIDs.contains(state.vaultKeyID) {
            pending.append(.awaitingKey(state.vaultKeyID))
        }
        let remaining = recordsToReseal(in: inventory).count
        if remaining > 0 { pending.append(.resealing(remaining: remaining)) }
        return pending
    }
}
