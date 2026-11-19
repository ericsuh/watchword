import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit
@testable import WatchwordSync

// The review of the merge of round 17 into the branch that keeps conflict copies (docs/06-adversarial-review.md Z221,
// V56): what a restore's carry counts as published of an earlier device ID's stream that forked. In the suite "shared
// vaults through the session".
extension AdversarialSharedVaultTests {
    /// Plants a second segment under `location`'s name in the household's store, genuinely `account`'s: the same
    /// payload sealed again (a new nonce) and signed again, as old hardware still running under the ID, or a backup
    /// restored under it, would write at a number already used. Both copies verify.
    static func forkSegment(
        at location: SyncObjectLocation, of account: SharingAccount, in household: SharedVaultHousehold
    ) async throws {
        let bytes = try #require(await household.transport.allObjects[location.name])
        let object = try SignedObject.parse(bytes)
        let header = try EnvelopeHeader.parse(object.envelope, expecting: location.envelopeKind).header
        let payload = try await account.session.syncOpen(
            object.envelope, context: location.envelopeContext(keyID: header.keyID))
        let envelope = try await account.session.syncSeal(payload, at: location)
        let signature = try await account.session.syncSign(envelope, at: location)
        let copy = SignedObject(signature: signature, envelope: envelope).serialized()
        #expect(copy != bytes, "the copy is the same object: nothing is tested")
        await household.transport.plantCopy(location.name, contents: copy)
    }

    /// Threat: the earlier device ID's own genuine signatures on two segments under one number (old hardware still
    /// running under the ID a restore left, Z198), both kept by the provider (A1), and a backup whose sync state does
    /// not verify (damaged, or edited by A8), so that what the earlier ID published is read from its stream alone
    /// (review of round 13, M2). Every member whose judge sees both copies refuses the name (`conflictingVersions`)
    /// and never merges that stream past it; a member that had merged the name before the second copy appeared keeps
    /// what it merged. The restored device's stream index holds the name from before the backup, and the carry's
    /// bound counted every segment the index held (review of the merge of round 17, finding 1; V56): it renamed none
    /// of the work that segment carried, so a member who saw the fork first held every later version of the item
    /// aside for good, waiting for a stream that never passes the name. The index counts only as far as a merge here
    /// can take the stream now (`mergeReach`): the work is written again as the new ID's and reaches that member. The
    /// member that merged the name first holds the earlier ID's values and the renamed ones side by side (duplicates,
    /// as the bound may give; never a loss), and what it publishes of the earlier ID's values is held aside by the
    /// member who saw the fork first, as any version holding them is: only the refused name carried them (V56).
    @Test("a restore's work that only a forked name of its earlier ID carried reaches a member who saw the fork first")
    func forkedNameOfTheEarlierIDCountsForNothing() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readWrite], seed: 31_400)
        let member = members[0]
        let late = members[1]
        let saved = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner])
        let oldID = try #require(await member.session.deviceIDForTest())
        let ownStream = await household.transport.allObjects.keys.compactMap(SyncObjectLocation.init(name:)).filter {
            $0.kind == .segment && $0.vaultID == vaultID && $0.author == oldID
        }
        let forked = try #require(ownStream.max { $0.number < $1.number })
        try await Self.forkSegment(at: forked, of: member, in: household)

        var first = try await member.session.item(id: saved.id)
        first.title = "Bank, first"
        _ = try await member.session.save(first)
        var backup = try await Backup.take(of: member, item: saved.id, vaultID: vaultID)
        var state = try #require(backup.state)
        state.authenticator = Array(repeating: 0, count: state.authenticator.count)
        backup = Backup(row: backup.row, state: state, index: backup.index)

        try await late.session.sync()
        #expect((try? await late.session.item(id: saved.id)) == nil, "the late member merged the forked name")

        let restored = try await backup.restore(member, household: household, seed: 31_401)
        _ = try await restored.session.syncAll()
        _ = try await restored.session.syncAll()
        try await Self.syncAll([late, owner])

        let atLate = try await late.session.item(id: saved.id)
        #expect(Self.titles(atLate).contains("Bank, first"), "the restored edit never reached the late member")
        let newID = try #require(await restored.session.deviceIDForTest())
        let heldAtLate = try await late.session.quarantine().filter { $0.entry.recordID == saved.id }
        #expect(!heldAtLate.contains { $0.entry.device == newID }, "the late member held the restore's work aside")
        let atOwner = try await owner.session.item(id: saved.id)
        #expect(Self.titles(atOwner).contains("Bank, first"), "the restored edit never reached the owner")
        #expect(try await owner.session.quarantine().isEmpty, "the owner held the restore's work aside")
        #expect(Self.titles(try await restored.session.item(id: saved.id)).contains("Bank, first"))
    }
}
