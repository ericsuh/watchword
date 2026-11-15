import Foundation
import WatchwordCrypto
import WatchwordEnvelope

/// A stored record as rotation needs to know it: which record, which key it is sealed under, and which account
/// wrote the stored version. The integrator builds these from its record store's rows; this module never sees a
/// ciphertext.
public struct SealedRecordReference: Sendable, Hashable {
    public let recordID: UUID
    public let kind: EnvelopeKind
    public let keyID: UUID
    public let version: UInt64
    /// The account whose write the stored version is: the signer of the sync object that carried it, or this
    /// device's own account for a local save.
    public let author: UUID

    public init(recordID: UUID, kind: EnvelopeKind, keyID: UUID, version: UInt64, author: UUID) {
        self.recordID = recordID
        self.kind = kind
        self.keyID = keyID
        self.version = version
        self.author = author
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
    /// Merge everything the account has published so far, now, while this device's ledger still lets it write.
    /// Once the record below is in the ledger the account's writes are refused, and what this device has not merged
    /// by then it never will (§8.7); what it has merged is re-sealed by the last step and so survives the removal.
    case mergeOutstandingWrites(UUID)
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
    /// The record is accepted; `remaining` records still have to be re-sealed.
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
/// magic "WWRP"  formatVersion u8 = 2  planner account 16  vaultID 16  baseEpoch u64  baseHash 32  newKeyID 16
/// reason u8: 0 removal | 1 departure + memberSince u64 | 2 routine
/// recordLength u16, membership record
/// grantCount u16 (1...64), then that many grants of 245 bytes each
/// signature 64
/// ```
///
/// The signature is the planner's own account key over everything before it, under `SignatureDomain.membership`. A
/// plan on disk is local state like a pin or the saved ledger, and like them it is believed only if this account
/// signed it: a plan's first step removes an account from the transport's share, and that must not be something a
/// file planted or altered on the device (A8) can aim at a member of its choosing (review finding S23). The account
/// that leaves is not stored at all; it is read from the signed record.
public struct RotationPlan: Sendable, Hashable {
    static let magic: [UInt8] = Array("WWRP".utf8)
    static let formatVersion: UInt8 = 2
    static let signatureLength = 64
    /// The most a plan can encode to; anything longer is refused before it is parsed (SEC9).
    public static let maximumLength =
        4 + 1 + 16 + 16 + 8 + 32 + 16 + 1 + 8 + 2 + MembershipRecord.maximumLength + 2
        + MembershipLimits.maximumMembers * KeyGrantCodec.encodedLength + signatureLength

    /// The account that planned it and signs both the record and the plan.
    public let planner: UUID
    public let vaultID: UUID
    public let reason: RotationReason
    /// The head the plan was made on.
    public let baseEpoch: UInt64
    public let baseHash: MembershipHash
    public let newKeyID: UUID
    /// The membership record, at `baseEpoch + 1`.
    public let proposal: MembershipRecord
    /// The record as an object to publish.
    public let record: SharingObject
    public let recordHash: MembershipHash
    /// One grant of the new key per remaining member, the planner's own account included.
    public let grants: [SharingObject]
    let signature: [UInt8]

    /// What is left to do on this device, in order: revoke the transport share, merge what the departing account
    /// has written, publish the grants, publish the record, re-seal. Empty for a plan that was superseded.
    ///
    /// Asked of the ledger rather than fixed, so that carrying out a plan found on disk does only what is still
    /// right: once the record is in the chain nothing is published again, and the share is revoked again only
    /// while the account is still not a member (it may have been invited back since).
    public func steps(in ledger: MembershipLedger) -> [RotationStep] {
        switch ledger.status(of: proposal) {
        case .superseded:
            return []
        case .awaitingPublication:
            var steps: [RotationStep] = []
            if let account = reason.departingAccount {
                steps += [.revokeTransportAccess(account), .mergeOutstandingWrites(account)]
            }
            steps += grants.map(RotationStep.publish)
            steps.append(.publish(record))
            steps.append(.resealRecords)
            return steps
        case .adopted:
            var steps: [RotationStep] = []
            if let account = reason.departingAccount, ledger.state.member(account) == nil {
                steps.append(.revokeTransportAccess(account))
            }
            steps.append(.resealRecords)
            return steps
        }
    }

    /// Where the rotation stands on this device. `inventory` is the vault's live records.
    public func status(in ledger: MembershipLedger, inventory: [SealedRecordReference]) -> RotationStatus {
        switch ledger.status(of: proposal) {
        case .awaitingPublication:
            return .awaitingPublication
        case .superseded:
            return .superseded
        case .adopted:
            let remaining = ledger.recordsToReseal(in: inventory).count
            return remaining == 0 ? .complete : .resealing(remaining: remaining)
        }
    }

    static func reason(of record: MembershipRecord, memberSince: UInt64?) -> RotationReason? {
        switch record.operation {
        case .removeMember(let account):
            return memberSince == nil ? .removal(account) : nil
        case .memberLeft(let account, let requestSignature):
            guard let memberSince else { return nil }
            return .departure(
                LeaveRequest(
                    vaultID: record.vaultID, accountID: account, memberSince: memberSince,
                    signature: requestSignature))
        case .rotateKey:
            return memberSince == nil ? .routine : nil
        case .createVault, .addMember, .changeRole, .deleteVault:
            return nil
        }
    }

    private var signedContent: [UInt8] {
        var out = RotationPlan.magic + [RotationPlan.formatVersion]
        out += planner.sharingBytes + vaultID.sharingBytes + SharingBytes.littleEndian(baseEpoch) + baseHash.bytes
        out += newKeyID.sharingBytes
        switch reason {
        case .removal: out += [0]
        case .departure(let request): out += [1] + SharingBytes.littleEndian(request.memberSince)
        case .routine: out += [2]
        }
        out += SharingBytes.littleEndian(UInt16(record.contents.count)) + record.contents
        out += SharingBytes.littleEndian(UInt16(grants.count))
        for grant in grants {
            out += grant.contents
        }
        return out
    }

    init(
        reason: RotationReason, base: MembershipState, newKeyID: UUID, proposal: MembershipRecord,
        grants: [SharingObject], signedBy keyset: Keyset
    ) throws {
        self.init(
            planner: keyset.accountID, vaultID: base.vaultID, reason: reason, baseEpoch: base.epoch,
            baseHash: base.hash, newKeyID: newKeyID, proposal: proposal, grants: grants, signature: [])
        self = RotationPlan(
            planner: planner, vaultID: vaultID, reason: reason, baseEpoch: baseEpoch, baseHash: baseHash,
            newKeyID: newKeyID, proposal: proposal, grants: grants,
            signature: try keyset.sign(signedContent, domain: .membership))
    }

    private init(
        planner: UUID, vaultID: UUID, reason: RotationReason, baseEpoch: UInt64, baseHash: MembershipHash,
        newKeyID: UUID, proposal: MembershipRecord, grants: [SharingObject], signature: [UInt8]
    ) {
        self.planner = planner
        self.vaultID = vaultID
        self.reason = reason
        self.baseEpoch = baseEpoch
        self.baseHash = baseHash
        self.newKeyID = newKeyID
        self.proposal = proposal
        record = SharingObject(proposal)
        recordHash = proposal.hash
        self.grants = grants
        self.signature = signature
    }

    public func encoded() -> [UInt8] {
        signedContent + signature
    }

    /// Parses a plan read back from local storage, as the account that made it.
    ///
    /// The plan must carry `account`'s signature, and its record and every grant must be `account`'s own, for this
    /// plan's vault, epoch and key; the reason is read from the record, and the objects' names are derived again
    /// from their contents. A plan that was altered or planted on disk is refused (`SharingError.savedPlanInvalid`),
    /// so it can neither make this device publish something under a name of the attacker's choosing nor take a
    /// member of the attacker's choosing off the transport's share.
    public static func parse(_ bytes: [UInt8], account: PublicKeyBundle) throws -> RotationPlan {
        guard bytes.count <= maximumLength else { throw SharingFormatError.tooLarge(bytes.count) }
        var reader = SharingReader(bytes)
        try reader.header(magic: magic, version: formatVersion)
        let planner = try reader.uuid()
        let vaultID = try reader.uuid()
        let baseEpoch = try reader.uint64()
        guard baseEpoch < MembershipLimits.maximumEpoch else { throw SharingFormatError.epochOutOfRange(baseEpoch) }
        let baseHash = MembershipHash(unchecked: try reader.read(MembershipHash.byteCount))
        let newKeyID = try reader.uuid()
        let memberSince: UInt64?
        let code = try reader.byte()
        switch code {
        case 0, 2:
            memberSince = nil
        case 1:
            let since = try reader.uint64()
            guard since <= baseEpoch else { throw SharingFormatError.epochOutOfRange(since) }
            memberSince = since
        default: throw SharingFormatError.unknownOperation(code)
        }
        let recordLength = Int(try reader.uint16())
        guard recordLength <= MembershipRecord.maximumLength else { throw SharingFormatError.tooLarge(recordLength) }
        let record = try MembershipRecord.parse(reader.read(recordLength))
        let count = Int(try reader.uint16())
        guard (1...MembershipLimits.maximumMembers).contains(count) else {
            throw SharingFormatError.memberCountOutOfRange(count)
        }
        let expected = count * KeyGrantCodec.encodedLength + signatureLength
        guard reader.remaining == expected else {
            throw reader.remaining < expected ? SharingFormatError.truncated : SharingFormatError.trailingBytes
        }
        var grants: [SharingObject] = []
        for _ in 0..<count {
            let grant = try VaultKeyGrantRecord(KeyGrantCodec.parse(reader.read(KeyGrantCodec.encodedLength)))
            guard grant.grant.vaultID == vaultID, grant.grant.keyID == newKeyID,
                grant.grant.senderAccountID == planner
            else { throw SharingFormatError.notCanonical }
            grants.append(SharingObject(grant))
        }
        let signature = try reader.read(signatureLength)
        try reader.finish()
        guard record.vaultID == vaultID, record.epoch == baseEpoch + 1, record.previousHash == baseHash,
            record.vaultKeyID == newKeyID, record.signer == planner,
            let reason = reason(of: record, memberSince: memberSince),
            code == (memberSince != nil ? 1 : record.operation == .rotateKey ? 2 : 0)
        else { throw SharingFormatError.notCanonical }

        let plan = RotationPlan(
            planner: planner, vaultID: vaultID, reason: reason, baseEpoch: baseEpoch, baseHash: baseHash,
            newKeyID: newKeyID, proposal: record, grants: grants, signature: signature)
        guard planner == account.accountID,
            (try? Signatures.verify(
                signature, for: plan.signedContent, domain: .membership, signingKey: account.signingKey)) != nil
        else { throw SharingError.savedPlanInvalid }
        return plan
    }
}

/// Plans rotations (docs/02-architecture.md §8.6).
public enum RotationPlanner {
    /// Plans the removal of a member, a member's departure, or a routine rotation, on the ledger's current head.
    ///
    /// Generates the new vault key, wraps it to every member who remains, signs the membership record, and forgets
    /// the key. Needs an unlocked administrator: the owner for anything that removes an administrator.
    ///
    /// - Parameter memberKeys: this device's comparison of the chain's member keys with its verified contacts, made
    ///   on the ledger's current head (`MembershipLedger.checkMemberKeys`). The new key is wrapped to the keys the
    ///   chain lists, so a member whose listed keys are not the ones this account's person verified must not be
    ///   among the recipients: planning then throws `keySubstituted`, unless that member is the one being removed.
    /// - Throws: `SharingError.nothingToDo` if the member is already gone (a concurrent administrator got there
    ///   first); `SharingError.notPermitted` or a `MembershipError` if this account may not do it;
    ///   `SharingError.memberKeysNotChecked` if `memberKeys` is for another vault or another head;
    ///   `SharingError.keySubstituted` as above.
    public static func plan<R: RandomNumberGenerator>(
        _ reason: RotationReason, ledger: MembershipLedger, memberKeys: MemberKeyCheck, signedBy keyset: Keyset,
        using generator: inout R
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
        try memberKeys.requireVerifiedKeys(of: next.members, in: ledger)
        let grants = try next.members.map { member in
            SharingObject(try VaultKeyGrantRecord(VaultKeyGrant.seal(newKey, to: member.bundle, from: keyset)))
        }
        return try RotationPlan(
            reason: reason, base: state, newKeyID: newKey.key.keyID, proposal: record, grants: grants,
            signedBy: keyset)
    }

    public static func plan(
        _ reason: RotationReason, ledger: MembershipLedger, memberKeys: MemberKeyCheck, signedBy keyset: Keyset
    ) throws -> RotationPlan {
        var generator = SystemRandomNumberGenerator()
        return try plan(reason, ledger: ledger, memberKeys: memberKeys, signedBy: keyset, using: &generator)
    }
}

/// One reason a vault's rotation is not finished, for the UI to show (PRD F4.3: "pending rotation").
public enum PendingRotation: Sendable, Hashable {
    /// A member asked to leave and no administrator's device has rotated the key yet. They are already off the
    /// transport share; until the rotation, new items are still sealed under a key they hold.
    case departureRequested(UUID)
    /// A record that removed this member lost a fork, and the removal has not been planned again yet
    /// (`MembershipLedger.owedRemovals`). Until it is, the member is listed again and holds the current key; their
    /// writes are refused and nothing is re-sealed.
    case removalOwed(UUID)
    /// This device planned a rotation whose record is not yet in the chain it sees.
    case awaitingPublication(RotationReason)
    /// This many records are still sealed under an earlier key, or were last written by an account that may no
    /// longer write, and wait to be sealed again by a member who may.
    case resealing(remaining: Int)
    /// This device does not hold the vault's current key yet (its grant has not arrived or does not open).
    case awaitingKey(UUID)
}

extension MembershipLedger {
    /// The valid leave requests among objects listed under `SharingObjectLocation.leavePrefix`, one per member, in
    /// account order. Requests that are malformed, misfiled, for another vault, replayed from an earlier stint or
    /// not signed by the member are skipped (§8.6).
    ///
    /// Every object is looked at, names first: anyone who can create objects can put any number under that prefix,
    /// and a bound on how many are examined would let them hide a real request behind junk, so that nobody is told
    /// the key was not rotated (review finding S24). What an object costs is its name, then a digest, then, only if
    /// it is filed under a current member, of the right length and for their current stint, one signature check.
    public func pendingLeaveRequests(among objects: [(name: String, contents: [UInt8])]) -> [LeaveRequest] {
        let state = self.state
        guard !state.isDeleted else { return [] }
        var found: [UUID: LeaveRequest] = [:]
        for object in objects {
            guard let location = SharingObjectLocation(name: object.name), location.vaultID == vaultID,
                case .leave(let account, let digest) = location.kind, found[account] == nil,
                state.member(account) != nil, object.contents.count == LeaveRequest.encodedLength,
                digest == SharingBytes.sha256(object.contents),
                let request = try? LeaveRequest.parse(object.contents), request.accountID == account,
                (try? request.validate(against: state)) != nil
            else { continue }
            found[account] = request
        }
        return found.values.sorted { $0.accountID.sharingPrecedes($1.accountID) }
    }

    /// The records a member who may write must seal again, as new versions through the ordinary save path
    /// (principle 5; ADR 0007; §8.7): every one that is not under the vault's current key, and every one whose stored
    /// version was written by an account that may not write now (removed, or made read-only). In a stable order, so
    /// that an interrupted pass resumes where it stopped.
    ///
    /// The second kind is what keeps a demotion or a removal from stranding data. Another member's write is merged
    /// only while its author may write (`writePermission(for:)`), so a device that meets a since-demoted member's
    /// record for the first time refuses it; a device that merged it in time publishes it again under its own name,
    /// and that version everyone accepts (review finding S25). A device whose own account may not write skips this.
    ///
    /// Empty while a removal is owed (`owedRemovals`): the current key is then one that the member to be removed
    /// holds, the removal is about to rotate it, and sealing anything again towards it would hand that member what
    /// was written under the newer key (review finding S19). Empty for a deleted vault.
    public func recordsToReseal(in inventory: [SealedRecordReference]) -> [SealedRecordReference] {
        let state = self.state
        guard !state.isDeleted, owedRemovals.isEmpty else { return [] }
        return inventory.filter {
            $0.keyID != state.vaultKeyID || !state.writePermission(for: $0.author).isAllowed
        }.sorted {
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
        plan: RotationPlan?, leaveRequests: [(name: String, contents: [UInt8])],
        inventory: [SealedRecordReference], heldKeyIDs: Set<UUID>
    ) -> [PendingRotation] {
        var departing = Set(pendingLeaveRequests(among: leaveRequests).map(\.accountID))
        var removing: Set<UUID> = []
        for owed in owedRemovals {
            if case .departure = owed.reason {
                departing.insert(owed.accountID)
            } else {
                removing.insert(owed.accountID)
            }
        }
        removing.subtract(departing)
        func inAccountOrder(_ accounts: Set<UUID>) -> [UUID] {
            accounts.sorted { $0.sharingPrecedes($1) }
        }
        var pending =
            inAccountOrder(departing).map(PendingRotation.departureRequested)
            + inAccountOrder(removing).map(PendingRotation.removalOwed)
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
