import Foundation
import WatchwordCrypto

/// The state machine of a membership chain (docs/02-architecture.md §8.3): which record may follow which state, and
/// the state that results. Pure; `MembershipLedger` decides which records to offer it.
///
/// Who may sign what:
///
/// | Operation | Signer |
/// | --- | --- |
/// | `createVault` (epoch 0 only) | the owner |
/// | `addMember` as read-write or read-only; `removeMember` and `memberLeft` of a member who is not an administrator; `changeRole` between read-write and read-only; `rotateKey` | the owner or an administrator |
/// | `addMember` as administrator; `removeMember` and `memberLeft` of an administrator; `changeRole` to or from administrator; `deleteVault` | the owner |
/// | anything that removes, re-roles or replaces the owner | nobody |
///
/// Two consequences the rest of the design leans on. The set of accounts that may sign changes only in records the
/// owner signed, so a former administrator's signature can never outrank the record that ended their authority
/// (`MembershipLedger`'s fork rule). And the owner can always sign the next record, so no sequence of records, honest
/// or hostile, locks everyone out.
enum MembershipRules {
    /// Verifies a genesis record against the owner whose fingerprint was verified out of band.
    static func genesisState(
        _ record: MembershipRecord, hash: MembershipHash, vaultID: UUID, owner: PublicKeyBundle,
        signatureChecks: inout Int
    ) throws -> MembershipState {
        guard record.vaultID == vaultID else {
            throw MembershipError.wrongVault(expected: vaultID, actual: record.vaultID)
        }
        guard record.epoch == 0, record.previousHash == .none, record.operation == .createVault,
            record.keyEpoch == 0, record.vaultKeyID != .sharingZero
        else { throw MembershipError.malformedGenesis }
        // The keys are compared, not the bundle's self-signature: Ed25519 signing may be randomised, so the bundle the
        // owner's device put in the record and the one this device pinned can be two signatures over the same keys.
        guard record.signer == owner.accountID, record.entries.count == 1, let entry = record.entries.first,
            entry.accountID == owner.accountID, entry.role == .owner, entry.since == 0,
            entry.agreementKey == owner.agreementKey, entry.signingKey == owner.signingKey
        else { throw MembershipError.ownerMismatch }
        signatureChecks += 1
        try verifySignature(of: record, signingKey: owner.signingKey)
        return MembershipState(
            vaultID: vaultID, epoch: 0, hash: hash, members: [try entry.member()],
            vaultKeyID: record.vaultKeyID, keyEpoch: 0, isDeleted: false)
    }

    static func genesisState(
        _ record: MembershipRecord, hash: MembershipHash, vaultID: UUID, owner: PublicKeyBundle
    ) throws -> MembershipState {
        var signatureChecks = 0
        return try genesisState(record, hash: hash, vaultID: vaultID, owner: owner, signatureChecks: &signatureChecks)
    }

    /// Verifies `record` as the successor of `previous` and returns the state it produces.
    ///
    /// Order: the checks that cost nothing (position in the chain, the signer's standing, what the operation is
    /// allowed to do, the shape of the key change), then the record's signature, and only then anything that costs
    /// work or validates material the record brought with it (whether its branch used the key before, a new member's
    /// key bundle, a leave request). Unsigned junk therefore costs exactly one signature check and nothing more
    /// (review finding S22); `signatureChecks` counts them.
    static func nextState(
        _ record: MembershipRecord, hash: MembershipHash, after previous: MembershipState,
        keyUsedBefore: (UUID) -> Bool, signatureChecks: inout Int
    ) throws -> MembershipState {
        guard !previous.isDeleted else { throw MembershipError.vaultDeleted }
        guard record.vaultID == previous.vaultID else {
            throw MembershipError.wrongVault(expected: previous.vaultID, actual: record.vaultID)
        }
        guard record.epoch == previous.epoch + 1 else {
            throw MembershipError.epochNotNext(expected: previous.epoch + 1, actual: record.epoch)
        }
        guard record.previousHash == previous.hash else { throw MembershipError.previousHashMismatch }

        guard let signer = previous.member(record.signer) else {
            throw MembershipError.signerNotAMember(record.signer)
        }
        guard signer.role.isAdministrator else { throw MembershipError.signerNotAdministrator(record.signer) }
        guard signer.role == .owner || record.epoch <= MembershipLimits.maximumAdministratorEpoch else {
            throw MembershipError.epochReservedForOwner
        }
        try authorise(record.operation, by: signer, in: previous)
        try checkKeyChange(of: record, after: previous)
        signatureChecks += 1
        try verifySignature(of: record, signingKey: signer.bundle.signingKey)

        if record.operation.rotatesKey, keyUsedBefore(record.vaultKeyID) {
            throw MembershipError.keyReused(record.vaultKeyID)
        }
        let members = try resultingMembers(of: record, after: previous)
        guard record.entries == members.map(MembershipRecord.Entry.init) else {
            throw MembershipError.resultingMembersMismatch
        }
        return MembershipState(
            vaultID: previous.vaultID, epoch: record.epoch, hash: hash, members: members,
            vaultKeyID: record.vaultKeyID, keyEpoch: record.keyEpoch, isDeleted: record.operation == .deleteVault)
    }

    static func nextState(
        _ record: MembershipRecord, hash: MembershipHash, after previous: MembershipState,
        keyUsedBefore: (UUID) -> Bool
    ) throws -> MembershipState {
        var signatureChecks = 0
        return try nextState(
            record, hash: hash, after: previous, keyUsedBefore: keyUsedBefore, signatureChecks: &signatureChecks)
    }

    /// Whether `signer` may perform `operation` on `state`. No cryptography.
    static func authorise(_ operation: MembershipRecord.Operation, by signer: Member, in state: MembershipState)
        throws
    {
        let isOwner = signer.role == .owner
        switch operation {
        case .createVault:
            throw MembershipError.malformedGenesis
        case .addMember(let account, let role):
            guard role != .owner else { throw MembershipError.ownerIsFixed }
            guard state.member(account) == nil else { throw MembershipError.memberAlreadyPresent(account) }
            guard state.members.count < MembershipLimits.maximumMembers else {
                throw MembershipError.tooManyMembers
            }
            guard role != .administrator || isOwner else { throw MembershipError.ownerOnly }
        case .removeMember(let account), .memberLeft(let account, _):
            guard let target = state.member(account) else { throw MembershipError.memberNotFound(account) }
            guard target.role != .owner else { throw MembershipError.ownerIsFixed }
            guard target.role != .administrator || isOwner else { throw MembershipError.ownerOnly }
        case .changeRole(let account, let role):
            guard let target = state.member(account) else { throw MembershipError.memberNotFound(account) }
            guard target.role != .owner, role != .owner else { throw MembershipError.ownerIsFixed }
            guard target.role != role else { throw MembershipError.roleUnchanged }
            guard (target.role != .administrator && role != .administrator) || isOwner else {
                throw MembershipError.ownerOnly
            }
        case .rotateKey:
            break
        case .deleteVault:
            guard isOwner else { throw MembershipError.ownerOnly }
        }
    }

    /// Principle 5: a removal or departure always introduces a key the departed member never held, and nothing else
    /// but an explicit rotation changes the key. The part of the rule that needs no history; that a key ID is never
    /// used twice on a branch, so "the record that introduced this key" is one record (§8.5), is checked after the
    /// signature.
    private static func checkKeyChange(of record: MembershipRecord, after previous: MembershipState) throws {
        if record.operation.rotatesKey {
            guard record.vaultKeyID != previous.vaultKeyID else { throw MembershipError.keyNotRotated }
            guard record.vaultKeyID != .sharingZero else { throw MembershipError.keyReused(record.vaultKeyID) }
            guard record.keyEpoch == record.epoch else { throw MembershipError.unexpectedKeyChange }
        } else {
            guard record.vaultKeyID == previous.vaultKeyID, record.keyEpoch == previous.keyEpoch else {
                throw MembershipError.unexpectedKeyChange
            }
        }
    }

    private static func verifySignature(of record: MembershipRecord, signingKey: [UInt8]) throws {
        do {
            try Signatures.verify(
                record.signature, for: record.signedContent, domain: .membership, signingKey: signingKey)
        } catch {
            throw MembershipError.signatureInvalid
        }
    }

    /// The member list after `record`'s operation, already authorised. A new member comes from the record, with
    /// their key bundle validated here; everyone else is carried over from the verified previous state.
    private static func resultingMembers(of record: MembershipRecord, after previous: MembershipState) throws
        -> [Member]
    {
        var members = previous.members
        switch record.operation {
        case .createVault, .rotateKey, .deleteVault:
            break
        case .addMember(let account, let role):
            guard let entry = record.entries.first(where: { $0.accountID == account }), entry.role == role,
                entry.since == record.epoch
            else { throw MembershipError.resultingMembersMismatch }
            members.append(try entry.member())
        case .removeMember(let account):
            members.removeAll { $0.accountID == account }
        case .memberLeft(let account, let requestSignature):
            // `authorise` established that the member exists.
            guard let target = previous.member(account),
                LeaveRequest.verify(requestSignature, vaultID: previous.vaultID, member: target)
            else { throw MembershipError.leaveRequestInvalid }
            members.removeAll { $0.accountID == account }
        case .changeRole(let account, let role):
            members = members.map { $0.accountID == account ? $0.with(role: role) : $0 }
        }
        return members.sorted { $0.accountID.sharingPrecedes($1.accountID) }
    }
}
