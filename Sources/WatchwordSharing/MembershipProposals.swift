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
    public func proposeRoleChange(of accountID: UUID, to role: MemberRole, signedBy keyset: Keyset) throws
        -> MembershipRecord
    {
        try propose(.changeRole(accountID, to: role), newKeyID: nil, adding: nil, signedBy: keyset).record
    }

    /// Signs the record that deletes the vault. Owner only; nothing can follow it.
    public func proposeDeletion(signedBy keyset: Keyset) throws -> MembershipRecord {
        try propose(.deleteVault, newKeyID: nil, adding: nil, signedBy: keyset).record
    }

    /// Builds, signs and checks the next record. The check is the verifier's own (`MembershipRules.nextState`), so
    /// this device never publishes a record that others would refuse.
    func propose(
        _ operation: MembershipRecord.Operation, newKeyID: UUID?, adding entry: MembershipRecord.Entry?,
        signedBy keyset: Keyset
    ) throws -> (record: MembershipRecord, state: MembershipState) {
        let state = self.state
        guard !state.isDeleted else { throw SharingError.vaultDeleted }
        guard let signer = state.member(keyset.accountID), signer.role.isAdministrator else {
            throw SharingError.notPermitted
        }
        let epoch = state.epoch + 1
        guard epoch <= MembershipLimits.maximumEpoch else { throw SharingFormatError.epochOutOfRange(epoch) }
        // Before signing anything: nothing this account is not allowed to do gets its signature.
        try MembershipRules.authorise(operation, by: signer, in: state)

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
            entries: entries, by: keyset)
        let next = try MembershipRules.nextState(
            record, hash: record.hash, after: state,
            keyUsedBefore: { keyID in chain.contains { $0.state.vaultKeyID == keyID } })
        return (record, next)
    }
}
