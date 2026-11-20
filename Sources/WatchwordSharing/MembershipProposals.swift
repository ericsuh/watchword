import Foundation
import WatchwordCrypto

/// Where a record this device proposed stands in its ledger (docs/02-architecture.md §8.3).
public enum ProposalStatus: Sendable, Hashable {
    /// Not in the accepted chain, and nothing else is at its epoch: publish it (again) and ingest.
    case awaitingPublication
    /// In the accepted chain. A later reorganisation can still displace it (`IngestReport.superseded`).
    case adopted
    /// Another record is at its epoch, or the chain beneath it changed. The record is dead: if the change is still
    /// wanted, propose it again on the new head (the proposing function throws if it has already happened).
    case superseded
}

extension MembershipLedger {
    /// Where `proposal` stands. Ask after every `ingest` about each record this device has proposed and not yet
    /// seen adopted, and keep those records (`MembershipRecord.encoded()`) across restarts until they are adopted or
    /// deliberately given up.
    ///
    /// A device's own record is not in its chain until it has ingested it, and if a competing record reached the
    /// store first the device's record is merely `outranked` in that first report; an integrator that watched only
    /// `IngestReport.superseded` would drop an invitation, a role change or a deletion without a word (review
    /// finding S27). And a record must never be published once it is `superseded`: `propose…` always builds on the
    /// current head, so ingest first, propose, check the status is `awaitingPublication`, then publish.
    public func status(of proposal: MembershipRecord) -> ProposalStatus {
        guard proposal.vaultID == vaultID else { return .superseded }
        if let accepted = state(atEpoch: proposal.epoch) {
            return accepted.hash == proposal.hash ? .adopted : .superseded
        }
        return proposal.epoch == state.epoch + 1 && proposal.previousHash == state.hash
            ? .awaitingPublication : .superseded
    }

    /// Whether `addition`, a record that added a member, was undone on its own branch: a record this ledger holds on
    /// a losing branch, built on it, removed that member or recorded their departure. Such an addition is not
    /// proposed again when it is superseded: what its branch last meant is that they are not a member, and replaying
    /// it alone would sign them back in and wrap the current key to them with nobody asking (review finding Z43).
    /// Records built on the removal are not looked at: an addition after it is another record, replayed by its own
    /// author.
    ///
    /// A removal undoes it only if its signer could remove such a member on the accepted head (Z53): anyone who
    /// could once sign on that branch, a former or demoted administrator, could otherwise build a removal on an
    /// honest administrator's displaced invitation and have it quietly dropped. A departure carries the member's own
    /// request and needs no standing.
    public func wasUndoneOnItsBranch(_ addition: MembershipRecord) -> Bool {
        guard case .addMember(let accountID, _) = addition.operation,
            let added = branches.first(where: { $0.state.hash == addition.hash })
        else { return false }
        let head = state
        // `branches` holds every record after its predecessor, so one pass follows every path from the addition.
        var descendants: [MembershipHash: MembershipState] = [addition.hash: added.state]
        for link in branches {
            guard let before = descendants[link.record.previousHash] else { continue }
            switch link.record.operation {
            case .removeMember(let removed) where removed == accountID:
                if let remover = head.member(link.record.signer), remover.role.isAdministrator,
                    let target = before.member(accountID), target.role != .owner,
                    target.role != .administrator || remover.role == .owner
                {
                    return true
                }
            case .memberLeft(let left, _) where left == accountID:
                return true
            default:
                descendants[link.state.hash] = link.state
            }
        }
        return false
    }

    /// Signs the record that adds a verified contact to the vault (PRD F4.1). `contact` is a `VerifiedContact`, so the
    /// fingerprint comparison of F4.2 cannot be skipped. Only the owner may add an administrator.
    ///
    /// The record is returned, not applied: publish it, then `ingest` it like anyone else's.
    public func proposeAddition(of contact: VerifiedContact, as role: MemberRole, signedBy keyset: Keyset) throws
        -> MembershipRecord
    {
        try propose(
            .addMember(contact.accountID, role: role), newKeyID: nil,
            adding: MembershipRecord.Entry(bundle: contact.bundle, role: role, since: state.epoch + 1),
            signedBy: keyset
        ).record
    }

    /// Signs the record that changes a member's role. Granting or revoking the administrator role is the owner's
    /// alone ("admin succession", §8.3).
    ///
    /// - Parameter writeCut: which of the member's writes count from now on, when the change makes a member who
    ///   could write read-only or ends an administrator's role (`requiresWriteCut(changingRoleOf:to:)`): what this
    ///   device has merged of theirs, taken after one more sync pass. `nil` for every other change of role.
    /// - Throws: `SharingError.writeCutRequired` or `writeCutNotExpected` if `writeCut` is not what the change needs.
    public func proposeRoleChange(
        of accountID: UUID, to role: MemberRole, writeCut: WriteCut?, signedBy keyset: Keyset
    ) throws -> MembershipRecord {
        try propose(.changeRole(accountID, to: role), newKeyID: nil, adding: nil, writeCut: writeCut, signedBy: keyset)
            .record
    }

    /// Whether the record that gives `accountID` the role `role` must carry a `WriteCut`: it makes a member who can
    /// write read-only, or it ends an administrator's role, a demotion to read-write included (§8.7). The second is
    /// what bounds a former administrator's renames of the vault: without a cut in that record, nothing would say
    /// which of their descriptions were written while they held the role.
    public func requiresWriteCut(changingRoleOf accountID: UUID, to role: MemberRole) -> Bool {
        MembershipRules.accountWhoseWorkIsCut(by: .changeRole(accountID, to: role), in: state) != nil
    }

    /// Whether the record that removes `accountID`, or carries out their departure, must carry a `WriteCut`: they
    /// can write now (§8.7). A read-only member's writes were settled when they became read-only, or never counted.
    public func requiresWriteCut(removing accountID: UUID) -> Bool {
        MembershipRules.accountWhoseWorkIsCut(by: .removeMember(accountID), in: state) != nil
    }

    /// Whether `signer` may remove `accountID`, or carry out their departure, on the current head: an administrator,
    /// and the owner if the member is one. For the UI, and for a device about to take the member off the transport's
    /// share before it plans the removal (§8.6): that step is not signed by anything, so it is not taken for a removal
    /// this account could not sign.
    public func mayRemove(_ accountID: UUID, signer: UUID) -> Bool {
        let state = self.state
        guard !state.isDeleted, let member = state.member(signer), member.role.isAdministrator else { return false }
        return (try? MembershipRules.authorise(.removeMember(accountID), by: member, in: state)) != nil
    }

    /// Signs the record that deletes the vault. Owner only; nothing can follow it.
    public func proposeDeletion(signedBy keyset: Keyset) throws -> MembershipRecord {
        try propose(.deleteVault, newKeyID: nil, adding: nil, signedBy: keyset).record
    }

    /// Builds, signs and checks the next record. The check is the verifier's own (`MembershipRules.nextState`), so
    /// this device never publishes a record that others would refuse.
    func propose(
        _ operation: MembershipRecord.Operation, newKeyID: UUID?, adding entry: MembershipRecord.Entry?,
        writeCut: WriteCut? = nil, signedBy keyset: Keyset
    ) throws -> (record: MembershipRecord, state: MembershipState) {
        let state = self.state
        guard !state.isDeleted else { throw SharingError.vaultDeleted }
        guard !continuesInLaterFormat else { throw SharingError.requiresNewerVersion }
        guard let signer = state.member(keyset.accountID), signer.role.isAdministrator else {
            throw SharingError.notPermitted
        }
        let epoch = state.epoch + 1
        guard epoch <= MembershipLimits.maximumEpoch else { throw SharingFormatError.epochOutOfRange(epoch) }
        // Before signing anything: nothing this account is not allowed to do gets its signature.
        try MembershipRules.authorise(operation, by: signer, in: state)
        // A cut exactly where a permission to write or an administrator role ends: an integrator that forgot one is
        // told, not given an empty one that would count nothing of the member's work.
        let endsPermission = MembershipRules.accountWhoseWorkIsCut(by: operation, in: state) != nil
        guard endsPermission || writeCut == nil else { throw SharingError.writeCutNotExpected }
        guard !endsPermission || writeCut != nil else { throw SharingError.writeCutRequired }

        var entries = state.members.map(MembershipRecord.Entry.init)
        switch operation {
        case .createVault, .rotateKey, .deleteVault:
            break
        case .addMember:
            if let entry { entries.append(entry) }
        case .removeMember(let account), .memberLeft(let account, _):
            entries.removeAll { $0.accountID == account }
        case .changeRole(let account, let role):
            entries = entries.map { entry in
                guard entry.accountID == account else { return entry }
                return MembershipRecord.Entry(
                    accountID: entry.accountID, role: role, since: entry.since, agreementKey: entry.agreementKey,
                    signingKey: entry.signingKey, selfSignature: entry.selfSignature)
            }
        }
        let record = try MembershipRecord.signed(
            vaultID: vaultID, epoch: epoch, previousHash: state.hash, operation: operation,
            vaultKeyID: newKeyID ?? state.vaultKeyID, keyEpoch: newKeyID == nil ? state.keyEpoch : epoch,
            writeCut: writeCut ?? .nothing, entries: entries, by: keyset)
        let next = try MembershipRules.nextState(
            record, hash: record.hash, after: state,
            keyUsedBefore: { keyID in chain.contains { $0.state.vaultKeyID == keyID } })
        return (record, next)
    }
}
