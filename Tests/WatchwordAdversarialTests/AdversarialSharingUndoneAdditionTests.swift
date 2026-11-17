import Foundation
import Testing
import WatchwordCrypto
import WatchwordSharing
import WatchwordTestSupport

// Review finding Z43 in the ledger itself: an addition and the removal that undid it lose a fork together.
extension AdversarialSharingTests {
    /// Threat: a former member (A5) helped by the store (A1), which hides one owner-signed record from an
    /// administrator's device. On the stale head the administrator adds an outsider, who is granted the current key,
    /// and removes them again with a rotation. The owner's record then wins the fork and all three records lose. The
    /// outsider is in no accepted state, so no removal is owed; but the key they were granted is the accepted head's.
    /// The ledger must say so, as a function of the records alone, must re-seal nothing towards that key, and must
    /// tell the administrator's device not to replay the addition; a routine rotation ends it. An addition that lost
    /// alone is still its author's to replay, and so is one its branch made again after the removal.
    @Test("an addition and its removal that lose a fork together leave the key reported as held outside the vault")
    func additionUndoneOnALosingBranch() async throws {
        let base = try await SharingHousehold.make()
        let outsider = base.outsider.accountID
        let firstKey = base.state.vaultKeyID

        // The administrator's branch, on the head it was shown.
        var branch = base
        try await branch.add(base.outsider, as: .readWrite, by: base.administrator)
        let addition = try #require(branch.ledger.chain.last).record
        let removal = try branch.rotate(.removal(outsider), by: base.administrator)
        // The owner's path: one record on the same head, which the administrator was not shown.
        var winning = base
        try winning.adopt(
            winning.ledger.proposeRoleChange(of: base.reader.accountID, to: .readWrite, signedBy: base.owner.keyset)
                .encoded())

        var device = winning.ledger
        let report = device.ingest([removal.record.contents, addition.encoded()])
        #expect(report.rejected.isEmpty && !report.changedHead, "the owner's record wins on owner-signed records")
        #expect(device.state.member(outsider) == nil && device.state.vaultKeyID == firstKey)
        #expect(device.owedRemovals.isEmpty, "they are not in the accepted state: no removal is owed")
        #expect(device.exposedKeyHolders == [outsider])
        #expect(device.wasUndoneOnItsBranch(addition), "the administrator's device must not replay it")
        let underBranchKey = SealedRecordReference(recordID: UUID(), kind: .item, keyID: removal.newKeyID, version: 2)
        #expect(device.recordsToReseal(in: [underBranchKey]).isEmpty, "nothing is sealed towards a key they hold")
        #expect(
            device.pendingRotation(plan: nil, leaveRequests: [], inventory: [underBranchKey], heldKeyIDs: [firstKey])
                == [.keyHeldOutsideTheVault(outsider)])

        // A function of the records: the same from a device that sees them in another order, and after a restart.
        let records = winning.ledger.chain.map(\.encoded) + [addition.encoded(), removal.record.contents]
        for order in [records, records.reversed()] {
            let fresh = try Self.freshDevice(base, Array(order))
            #expect(fresh.state == device.state && fresh.exposedKeyHolders == [outsider])
        }
        let restored = try MembershipLedger.restore(
            device.persisted(signedBy: base.owner.keyset), vaultID: base.vaultID, owner: Self.trusted(base.owner),
            account: base.owner.bundle)
        #expect(restored.exposedKeyHolders == [outsider])

        // A routine rotation, by anyone who may, ends it.
        var rotated = device
        rotated.ingest([
            try RotationPlanner.plan(.routine, ledger: device, signedBy: base.owner.keyset).record.contents
        ])
        #expect(rotated.state.vaultKeyID != firstKey && rotated.exposedKeyHolders.isEmpty)
        #expect(!rotated.recordsToReseal(in: [underBranchKey]).isEmpty)

        // The addition alone, superseded: nobody undid it, so its author replays it (S27) and nothing is reported.
        var alone = winning.ledger
        alone.ingest([addition.encoded()])
        #expect(alone.exposedKeyHolders.isEmpty && !alone.wasUndoneOnItsBranch(addition))
        #expect(alone.status(of: addition) == .superseded)

        // The branch went on to add them again: what it last meant is that they are a member.
        var again = branch
        try await again.add(base.outsider, as: .readOnly, by: base.administrator)
        let second = try #require(again.ledger.chain.last).record
        var takenBack = winning.ledger
        takenBack.ingest([addition.encoded(), removal.record.contents, second.encoded()])
        #expect(takenBack.state.member(outsider) == nil)
        #expect(takenBack.exposedKeyHolders.isEmpty, "that addition is its author's to replay")
        #expect(takenBack.wasUndoneOnItsBranch(addition) && !takenBack.wasUndoneOnItsBranch(second))
    }
}
