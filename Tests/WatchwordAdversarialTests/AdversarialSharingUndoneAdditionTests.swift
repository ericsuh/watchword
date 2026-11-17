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

// Review finding Z53: who is believed about a key handed out on a branch that lost.
extension AdversarialSharingTests {
    /// Threat: a former administrator (A5) who can still create objects in the store, or with the store's help. The
    /// owner removed them, rotating to a key they never held. On the dead branch from before their removal, where
    /// their signature is still valid, they sign a rotation that names the **ID** of the vault's current key (key IDs
    /// are public), add a throwaway account and remove it again. Believed, that says someone outside the vault holds
    /// its key: nothing is sealed again in the whole vault, every device shows the warning, and every
    /// administrator's device rotates, as often as the former administrator repeats it with the next key's ID. A
    /// key ID on a branch is the vault's key only if a record of the accepted chain introduced it there; and a branch
    /// is believed about an addition only if its signer could sign the same on the accepted head, as for an owed
    /// removal (S29).
    @Test("a former administrator's dead branch exposes nobody, whatever key ID and members it names")
    func deadBranchExposesNobody() async throws {
        let base = try await SharingHousehold.make()
        let former = base.administrator
        var winning = base
        let removal = try winning.rotate(.removal(former.accountID), by: base.owner)
        let headKey = removal.newKeyID
        #expect(winning.state.vaultKeyID == headKey && winning.state.member(former.accountID) == nil)

        // The dead branch: a rotation naming the head's key ID, a member added under it, and removed again.
        var branch = base
        try branch.adopt(
            ForgedRecord(after: base.state, signer: former.accountID, operation: .rotateKey, newKeyID: headKey)
                .signed(by: former.keyset))
        #expect(branch.state.vaultKeyID == headKey)
        try await branch.add(base.outsider, as: .readWrite, by: former)
        let addition = try #require(branch.ledger.chain.last).record
        let undone = try RotationPlanner.plan(
            .removal(base.outsider.accountID), ledger: branch.ledger, signedBy: former.keyset)
        try branch.adopt(undone.record.contents)

        var device = winning.ledger
        let report = device.ingest(branch.ledger.chain.dropFirst(base.ledger.chain.count).map(\.encoded))
        #expect(report.rejected.isEmpty && !report.changedHead)
        #expect(device.exposedKeyHolders.isEmpty, "a former administrator's branch was believed")
        let stale = SealedRecordReference(recordID: UUID(), kind: .item, keyID: base.state.vaultKeyID, version: 2)
        #expect(device.recordsToReseal(in: [stale]) == [stale], "re-sealing was stopped for the whole vault")
        #expect(
            device.pendingRotation(plan: nil, leaveRequests: [], inventory: [], heldKeyIDs: [headKey]).isEmpty)
        #expect(!device.wasUndoneOnItsBranch(addition))
    }

    /// Threat: the same, by someone who is still a member and no longer an administrator: the owner made them an
    /// ordinary member, which rotates nothing, so the key on their old branch really is the vault's. Their branch
    /// from before that adds an account and removes it. They can hand the key to anyone, being a member; what they
    /// can no longer do is have every device act on what their records say. And a removal signed by someone with no
    /// standing does not stop an honest administrator's own addition from being proposed again.
    @Test("a demoted administrator's branch is not believed, and cannot stop an honest addition being proposed again")
    func demotedAdministratorsBranch() async throws {
        var base = try await SharingHousehold.make()
        let second = try SharingParty(seed: 5301)
        try await base.add(second, as: .administrator, by: base.owner)
        let demoted = base.administrator
        var winning = base
        try winning.adopt(
            winning.ledger.proposeRoleChange(of: demoted.accountID, to: .readWrite, signedBy: base.owner.keyset)
                .encoded())
        let headKey = winning.state.vaultKeyID
        #expect(headKey == base.state.vaultKeyID)

        // Their own pair on the stale head.
        var theirs = base
        try await theirs.add(base.outsider, as: .readWrite, by: demoted)
        try theirs.rotate(.removal(base.outsider.accountID), by: demoted)
        var device = winning.ledger
        device.ingest(theirs.ledger.chain.dropFirst(base.ledger.chain.count).map(\.encoded))
        #expect(device.exposedKeyHolders.isEmpty)

        // An honest administrator's addition on the stale head, and the demoted one's removal built on it.
        var honest = base
        try await honest.add(base.outsider, as: .readWrite, by: second)
        let addition = try #require(honest.ledger.chain.last).record
        let spoiler = try RotationPlanner.plan(
            .removal(base.outsider.accountID), ledger: honest.ledger, signedBy: demoted.keyset)
        var other = winning.ledger
        other.ingest([addition.encoded(), spoiler.record.contents])
        #expect(other.status(of: addition) == .superseded)
        #expect(!other.wasUndoneOnItsBranch(addition), "someone with no standing stopped the invitation")
        #expect(other.exposedKeyHolders.isEmpty)
        // Undone by the administrator who made it, it is let go and the key reported, as before (Z43).
        let own = try RotationPlanner.plan(
            .removal(base.outsider.accountID), ledger: honest.ledger, signedBy: second.keyset)
        var third = winning.ledger
        third.ingest([addition.encoded(), own.record.contents])
        #expect(third.wasUndoneOnItsBranch(addition))
        #expect(third.exposedKeyHolders == [base.outsider.accountID])
    }
}

extension AdversarialSharingTests {
    /// Threat: the store (A1) flooding a device with valid records on dead branches (an administrator's, kept from
    /// an owner's record), hoping the two that show someone outside the vault holds its key are the ones dropped
    /// when the limit on kept branch records is reached; and the member's own departure in place of a removal. The
    /// records that show an exposure are the last let go, as an owed removal's are, and a departure counts as a
    /// removal does, with the member's request for standing.
    @Test("the records that show a key held outside the vault are kept past the branch limit, and a departure counts")
    func exposureIsKeptAndDeparturesCount() async throws {
        let base = try await SharingHousehold.make()
        let outsider = base.outsider.accountID
        var branch = base
        try await branch.add(base.outsider, as: .readWrite, by: base.administrator)
        let addition = try #require(branch.ledger.chain.last).record
        let request = try LeaveRequest.make(leaving: branch.state, as: base.outsider.keyset)
        let departure = try RotationPlanner.plan(
            .departure(request), ledger: branch.ledger, signedBy: base.administrator.keyset)
        var winning = base
        try winning.adopt(
            winning.ledger.proposeRoleChange(of: base.reader.accountID, to: .readWrite, signedBy: base.owner.keyset)
                .encoded())

        var device = winning.ledger
        device.ingest([addition.encoded(), departure.record.contents])
        #expect(device.exposedKeyHolders == [outsider] && device.wasUndoneOnItsBranch(addition))

        let limit = MembershipLimits.maximumRetainedBranchRecords
        let flood = try (0..<(limit + 40)).map { _ in
            try base.forgery(.rotateKey, signer: base.administrator, newKeyID: UUID()).signed(
                by: base.administrator.keyset)
        }
        let report = device.ingest(flood)
        #expect(report.forgotten == 42 && device.branches.count == limit)
        #expect(device.holds(addition.hash) && device.holds(departure.recordHash), "dropped to make room for junk")
        #expect(device.exposedKeyHolders == [outsider])
        // The same from a device that is shown the flood first.
        var late = winning.ledger
        late.ingest(flood)
        late.ingest([departure.record.contents, addition.encoded()])
        #expect(late.exposedKeyHolders == [outsider] && late.branches == device.branches)
    }

    /// Threat: a member, current or former (A4, A5), in a vault whose integration judges nothing while the chain is
    /// its owner's alone (review finding Z56). That must be true only of a chain that has never listed anyone else:
    /// one whose members have all been removed still holds their work, their cuts and their late writes, and is
    /// judged like any other.
    @Test("a chain is its owner's alone only while it has never listed anyone else")
    func ownersAloneOnlyBeforeAnyoneIsListed() async throws {
        let base = try await SharingHousehold.make()
        var device = try Self.freshDevice(base, [base.ledger.chain[0].encoded])
        #expect(device.isOwnersAlone)
        device.ingest(base.ledger.chain.dropFirst().map(\.encoded))
        #expect(device.state == base.state && !device.isOwnersAlone)
        for member in base.state.members where member.accountID != base.owner.accountID {
            device.ingest([
                try RotationPlanner.plan(.removal(member.accountID), ledger: device, signedBy: base.owner.keyset)
                    .record.contents
            ])
        }
        #expect(device.state.members.map(\.accountID) == [base.owner.accountID])
        #expect(!device.isOwnersAlone, "a vault everyone was removed from was taken for one nobody had joined")
    }

    /// Threat: the key directory (A1) between a safety number being shown and the confirmation (review finding Z40),
    /// at the two places an invitation takes evidence itself rather than through a screen. The directory serves the
    /// bundle the person compared when the fingerprint was displayed, and another when the invitation begins: the
    /// evidence names the fingerprint that was shown, and each invitation must refuse to pin the other bundle on it,
    /// leaving nobody pinned.
    @Test(
        "evidence of a comparison by eye is refused by both sides of an invitation for a bundle other than the one shown"
    )
    func invitationRefusesEvidenceForAnotherBundle() async throws {
        let household = try await SharingHousehold.make()
        let guest = try SharingParty(seed: 51)
        let impostor = try SharingParty(accountID: guest.accountID, seed: 52)
        let ownerImpostor = try SharingParty(accountID: household.owner.accountID, seed: 53)

        // The inviter was shown the guest's fingerprint; the directory now serves the impostor's bundle.
        let inviterStore = InMemoryVerifiedContactStore()
        let inviterContacts = VerifiedContacts(store: inviterStore, account: household.owner.bundle)
        let directory = InMemoryKeyBundleDirectory()
        await directory.publish(impostor.bundle)
        var outgoing = try await OutgoingInvitation.begin(
            vaultID: household.vaultID, inviting: guest.accountID, as: .readWrite, directory: directory,
            contacts: inviterContacts)
        await #expect(throws: SharingError.fingerprintMismatch) {
            try await outgoing.confirm(
                .comparedByEye(shown: guest.bundle.fingerprint), contacts: inviterContacts,
                signedBy: household.owner.keyset, at: Self.now)
        }
        #expect(try await inviterContacts.pinned(guest.accountID) == nil)

        // The invitee was shown the owner's fingerprint; the directory serves another bundle under the owner's ID.
        let guestContacts = VerifiedContacts(store: InMemoryVerifiedContactStore(), account: guest.bundle)
        await directory.publish(ownerImpostor.bundle)
        var incoming = try await IncomingInvitation.begin(
            Invitation(vaultID: household.vaultID, ownerAccountID: household.owner.accountID), knownOwner: nil,
            directory: directory, contacts: guestContacts)
        await #expect(throws: SharingError.fingerprintMismatch) {
            try await incoming.confirm(
                .comparedByEye(shown: household.owner.bundle.fingerprint), contacts: guestContacts,
                signedBy: guest.keyset, at: Self.now)
        }
        #expect(try await guestContacts.pinned(household.owner.accountID) == nil)
    }
}
