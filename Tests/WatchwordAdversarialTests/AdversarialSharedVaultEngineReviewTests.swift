import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The review of the engine's third round (rows Z135 to Z143) in shared vaults (docs/06-adversarial-review.md §Z,
// rows from Z144).
extension AdversarialSharedVaultTests {
    /// Threat: the ordinary loss of a member's laptop, revoked by the member (no adversary is needed), and the same
    /// state reached by someone with the owner's files (A8), who edits the signed stream index so that it is refused
    /// and rebuilt from the log. A revoked device's stream is not read, and a shared vault writes no snapshots, so a
    /// device that builds its index after the revocation (a new device of the member, a member who joins later, any
    /// device whose index was rebuilt) never records the laptop's segments. Every version whose values or clock name
    /// the laptop was then held aside: a value carried by none of its segments waited for its stream, and a claim
    /// about its edits waited for its first segment (Z136), for good, since that stream is never read again; the first
    /// take-out removed those rows into the quarantine. A revoked device's work and edits are believed in a version
    /// that otherwise counts, as its own versions already were: it can publish nothing that any device reads, so a
    /// claim about it supersedes nothing yet to come.
    @Test("the items a revoked device edited stay visible to devices that never read its stream")
    func revokedDeviceWorkStaysVisible() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 3300)
        let member = members[0]
        let invitation = Invitation(vaultID: vaultID, ownerAccountID: owner.accountID)
        let laptop = try await household.secondDevice(of: member)
        try await laptop.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await laptop.session.sync()

        // The laptop writes one item, whose password stays its own, and changes the other's password, which the owner
        // then changes again; the owner renames the first. The last version of each is the owner's, holding the
        // laptop's values or history and naming it in its clock.
        var kept = Self.bank(in: vaultID)
        kept.title = "Written on the laptop"
        kept = try await laptop.session.save(Self.setting(.password, to: "laptop-password", in: kept))
        let overwritten = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, laptop, member])
        _ = try await laptop.session.save(
            Self.setting(.password, to: "laptop-change", in: try await laptop.session.item(id: overwritten.id)))
        try await Self.syncAll([laptop, owner, member])
        var renamed = try await owner.session.item(id: kept.id)
        renamed.title = "Renamed by the owner"
        _ = try await owner.session.save(renamed)
        _ = try await owner.session.save(
            Self.setting(.password, to: "owner-change", in: try await owner.session.item(id: overwritten.id)))
        try await Self.syncAll([owner, member, laptop])

        let laptopID = try await Self.deviceID(of: laptop)
        try await member.session.revokeDevice(laptopID, password: .keepPassword(current: TestVault.password))
        try await Self.syncAll([member, owner])

        // A new device of the member, a member who joins after the revocation (which changes the head, so every device
        // takes out and replays), and the owner's index rebuilt from the log.
        let phone = try await household.secondDevice(of: member)
        try await phone.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(owner.safetyNumber))
        let joiner = try await household.account(seed: 3391)
        try await owner.invite(joiner, to: vaultID, as: .readWrite, owner: owner)
        await owner.state.tamper(.streamIndex, vaultID: vaultID, value: nil)
        let relaunched = owner.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: owner.state, contacts: owner.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        try await Self.syncAll([member, phone, joiner])
        for _ in 0..<3 {
            try await relaunched.session.sync()
            try await Self.syncAll([member, phone, joiner], rounds: 1)
        }

        for (name, session) in [
            ("owner", relaunched.session), ("member", member.session), ("phone", phone.session),
            ("joiner", joiner.session),
        ] {
            let first = try? await session.item(id: kept.id)
            #expect(first?.title == "Renamed by the owner", "the item the laptop wrote is gone on the \(name)'s device")
            #expect(first?.field(.password)?.value == "laptop-password", "on the \(name)'s device")
            #expect(
                (try? await session.item(id: overwritten.id))?.field(.password)?.value == "owner-change",
                "the item the laptop changed is gone on the \(name)'s device")
        }
        // And they go on converging: an edit made now reaches every device.
        var later = try await joiner.session.item(id: kept.id)
        later.title = "Edited by the member who joined"
        _ = try await joiner.session.save(later)
        try await Self.syncAll([joiner, phone, member])
        try await relaunched.session.sync()
        for session in [relaunched.session, member.session, phone.session] {
            #expect(try await session.item(id: kept.id).title == "Edited by the member who joined")
        }
    }
}

// Review finding Z146: a read-only member's segment at the first number of another member's stream decided whose the
// stream was.
extension AdversarialSharedVaultTests {
    /// Threat: a member the vault never let write (read-only from the start, A4), with a device registered under a
    /// writer's device ID (S33), who signs segment 1 of that device's stream before the writer has published in the
    /// vault. Since Z137 every device took such a segment in and recorded it, and a stream belonged to the account that
    /// signed its lowest segment: every other device took the writer's stream for the read-only member's and held aside
    /// everything the writer published there, while the writer's device stepped over the planted segment and published
    /// from 2, told nothing. The writer's device ID commits to the writer's account (Z157): the plant verifies nowhere,
    /// names nothing and erases nothing. It sits at the number the writer would publish at, as anything anyone can
    /// create there would (A1): the writer is told, and goes on once it is gone.
    @Test("a read-only member's segment at the start of a writer's stream does not take the stream")
    func readOnlyMemberPlantAtSegmentOne() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 3400)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let victim = try await household.account(seed: 3401)
        let reader = try await household.account(seed: 3402)
        try await owner.invite(victim, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(reader, to: vaultID, as: .readOnly, owner: owner)
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, victim, reader])
        let victimDevice = try await Self.deviceID(of: victim)
        let victimStream = "vault/\(vaultID.uuidString)/log/\(victimDevice.uuidString)/"
        #expect(await household.transport.list(prefix: victimStream).isEmpty, "the victim has published already")
        let rogue = try await household.secondDevice(of: reader, deviceID: victimDevice)
        try await rogue.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await rogue.session.sync()

        let summary = try ItemErasure(
            seen: VersionVector([victimDevice: 1000]), row: 1000, device: victimDevice, date: nil
        ).summary()
        let deletion = SyncEntry.tombstone(
            RecordKey(recordID: bank.id, kind: .item),
            stamp: RecordStamp(version: 1001, device: victimDevice, deleted: true), erasure: summary)
        let location = SyncObjectLocation.segment(vaultID: vaultID, author: victimDevice, sequence: 1)
        let payload = SyncPayload(
            kind: .segment, vaultID: vaultID, author: victimDevice, number: 1, vector: [:], entries: [deletion])
        let adapter = VaultSyncAdapter(session: rogue.session)
        let envelope = try await adapter.seal(payload.encoded(), at: location)
        let signature = try await adapter.sign(envelope, at: location)
        try await household.transport.create(
            location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())

        var item = Self.bank(in: vaultID)
        item.title = "The victim's own"
        let own = try await victim.session.save(item)
        let report = try #require(try await victim.session.syncAll().vaults[vaultID])
        #expect(report.ownStreamConflict == 1, "the victim is not told someone wrote in its place")
        try await Self.syncAll([owner, reader])
        for account in [owner, reader] {
            #expect(Self.refused(location.name, in: try await account.session.syncAll().vaults[vaultID]))
            #expect(try await account.session.item(id: bank.id).title == bank.title, "the planted deletion counted")
            #expect(await account.session.streamOwner(victimDevice, in: vaultID) == nil)
        }
        await Self.remove(location.name, from: household.transport)
        try await Self.syncAll([victim, owner, reader])
        for account in [owner, reader] {
            #expect(
                (try? await account.session.item(id: own.id))?.title == own.title,
                "the victim's work did not arrive")
            #expect(await account.session.streamOwner(victimDevice, in: vaultID) == victim.accountID)
        }
    }
}
