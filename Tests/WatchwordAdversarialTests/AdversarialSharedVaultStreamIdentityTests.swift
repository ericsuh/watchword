import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

// Review finding Z157 (docs/06-adversarial-review.md): which account a device's stream in a shared vault belongs to
// was inferred, because any member could list another account's device ID in their own registry (S33). A device's ID
// now commits to its account under its key, and a shared vault counts a registry's device only if its ID commits to
// that registry's account: the account of a stream, a value's stamp and a revocation are a matter of identity.
extension AdversarialSharedVaultTests {
    /// Puts `name` back as nothing: the planted object removed (by the provider, or by the person).
    static func remove(_ name: String, from transport: InMemorySyncTransport) async {
        await transport.tamper(name, contents: nil)
    }

    /// Whether `report` refused the object `name` (`SyncReport.rejected`).
    static func refused(_ name: String, in report: SyncReport?) -> Bool {
        report?.rejected.contains { $0.name == name } == true
    }

    /// Threat: a member who may write (A4), round 5's M1. A read-only member is promoted while the vault key stays the
    /// same, and that member's device publishes segments 1 to 5 under it. The writer registers a device of their own
    /// account under the promoted member's device ID (S33) and signs segment 6 of its stream, carrying a deletion that
    /// claims to have seen that device's edits far beyond what it published. Under Z152 the writer could name streams
    /// under that key and the promoted member could not, so the plant named the stream for the writer everywhere, the
    /// victim's own device included; segments 1 to 5 and everything after were held aside, the victim's device refused
    /// every other member's version that had seen its edits, and a rotation cured nothing. Now the writer's registry
    /// does not count the device (its ID commits to the victim's account), so the plant verifies nowhere: refused at
    /// download like any object no key it commits to signed, it takes nothing, before a rotation or after, on the
    /// victim's device or anyone's. It occupies the number, as any object anyone can create there does (A1): the
    /// victim's stream says so and waits, losing nothing, until the object is gone.
    @Test("a writer's segment in a promoted member's stream takes nothing, before a rotation or after")
    func plantInAPromotedMembersStream() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 5700)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let promoted = try await household.account(seed: 5701)
        let writer = try await household.account(seed: 5702)
        let bystander = try await household.account(seed: 5703)
        try await owner.invite(promoted, to: vaultID, as: .readOnly, owner: owner)
        try await owner.invite(writer, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(bystander, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([owner, promoted, writer, bystander])
        try await owner.session.changeRole(of: promoted.accountID, in: vaultID, to: .readWrite)
        try await Self.syncAll([owner, promoted, writer, bystander])

        // Segments 1 to 5 of the promoted member's stream, under the key current before the promotion.
        var written: [Item] = []
        for index in 0..<5 {
            var item = Self.bank(in: vaultID)
            item.title = "The promoted member's, number \(index)"
            written.append(try await promoted.session.save(item))
            try await promoted.session.sync()
        }
        let victimDevice = try await Self.deviceID(of: promoted)
        let head = try await Self.head(of: promoted, in: vaultID)
        #expect(head == 5)
        try await Self.syncAll([owner, writer, bystander])

        // The writer's device under the victim's device ID signs segment 6, erasing the first item "having seen" the
        // victim's edits up to 1000.
        let rogue = try await household.secondDevice(of: writer, deviceID: victimDevice)
        try await rogue.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await rogue.session.sync()
        let summary = try ItemErasure(
            seen: VersionVector([victimDevice: 1000]), row: 1000, device: victimDevice, date: nil
        ).summary()
        let deletion = SyncEntry.tombstone(
            RecordKey(recordID: written[0].id, kind: .item),
            stamp: RecordStamp(version: 1001, device: victimDevice, deleted: true), erasure: summary)
        try await Self.plantSegment(
            by: rogue, as: victimDevice, sequence: head + 1, in: vaultID, entries: [deletion],
            on: household.transport)
        let planted = SyncObjectLocation.segment(vaultID: vaultID, author: victimDevice, sequence: head + 1).name

        // The owner edits one of the victim's items, having seen the victim's edits.
        var edited = try await owner.session.item(id: written[1].id)
        edited.title = "Renamed by the owner"
        edited = try await owner.session.save(edited)
        for rotated in [false, true] {
            if rotated { _ = try await owner.session.rotateVaultKey(vaultID) }
            for account in [owner, bystander, promoted, writer] {
                let report = try await account.session.syncAll().vaults[vaultID]
                #expect(Self.refused(planted, in: report), "the planted segment verified (rotated: \(rotated))")
            }
            try await Self.syncAll([owner, bystander, promoted, writer])
            for (name, account) in [("victim", promoted), ("owner", owner), ("bystander", bystander)] {
                #expect(
                    await account.session.streamOwner(victimDevice, in: vaultID) == promoted.accountID,
                    "the stream is not the victim's on the \(name)'s device (rotated: \(rotated))")
                let titles = Set(try await account.session.items(in: vaultID).items.map(\.title))
                #expect(
                    Set(written.dropFirst(2).map(\.title)).isSubset(of: titles) && titles.contains(written[0].title),
                    "the victim's work is held aside or erased on the \(name)'s device (rotated: \(rotated))")
                #expect(
                    (try? await account.session.item(id: edited.id))?.title == edited.title,
                    "a version that saw the victim's edits is refused on the \(name)'s device (rotated: \(rotated))")
                #expect(try await account.session.sharedVaultStatus(vaultID).heldAside == 0)
            }
        }

        // The victim's next segment meets the object at its number, says so, and marks nothing sent; once the
        // object is gone it goes on, and its work arrives everywhere, after the writer is removed too.
        var later = Self.bank(in: vaultID)
        later.title = "Written by the victim afterwards"
        later = try await promoted.session.save(later)
        #expect(try await promoted.session.syncAll().vaults[vaultID]?.ownStreamConflict == head + 1)
        await Self.remove(planted, from: household.transport)
        #expect(try await owner.session.removeMember(writer.accountID, from: vaultID) == .complete)
        try await Self.syncAll([promoted, owner, bystander], rounds: 3)
        for account in [owner, bystander, promoted] {
            let titles = Set(try await account.session.items(in: vaultID).items.map(\.title))
            #expect(titles.contains(later.title) && titles.contains(edited.title))
            #expect(Set(written.dropFirst(2).map(\.title) + [written[0].title]).isSubset(of: titles))
            #expect(try await account.session.sharedVaultStatus(vaultID).heldAside == 0)
        }
    }

    /// Threat: a former member (A5) who may still create objects in the store, round 5's M2. A member enrols a new
    /// device, which joins the vault and publishes nothing yet. The removed member, who could write once and so kept
    /// standing for what their cut holds, registers a device under the new device's ID in their own registry, signs
    /// its segment 1 under a key from when they were a member, and revokes the device in their own registry. Under
    /// Z150 a stream nothing else named was the plant's signer's, so the revocation counted: the new device was
    /// retired on every device but itself, never read, and nothing it wrote reached anyone, silently, once per
    /// re-enrolment. Now no registry but the member's own account's counts the device, so the revocation is nobody's
    /// and the plant verifies nowhere; the new device's work reaches everyone once the object is gone.
    @Test("a removed member's plant and revocation of a new device's ID stop nothing")
    func removedMemberRevokesANewDevice() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 5710)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let member = try await household.account(seed: 5711)
        let former = try await household.account(seed: 5712)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(former, to: vaultID, as: .readWrite, owner: owner)
        _ = try await former.session.save(Self.bank(in: vaultID))
        let invitation = Invitation(vaultID: vaultID, ownerAccountID: owner.accountID)
        let fresh = try await household.secondDevice(of: member)
        try await fresh.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await Self.syncAll([owner, member, fresh, former])
        let freshID = try await Self.deviceID(of: fresh)

        let rogue = try await household.secondDevice(of: former, deviceID: freshID)
        try await rogue.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await rogue.session.sync()
        try await Self.plantSegment(by: rogue, as: freshID, sequence: 1, in: vaultID, on: household.transport)
        let planted = SyncObjectLocation.segment(vaultID: vaultID, author: freshID, sequence: 1).name
        #expect(try await owner.session.removeMember(former.accountID, from: vaultID) == .complete)
        try await Self.syncAll([owner, member, fresh, former])
        try await former.session.revokeDevice(freshID, password: .keepPassword(current: TestVault.password))
        try await Self.syncAll([former, owner, member, fresh])

        for (name, account) in [("owner", owner), ("member", member), ("new device", fresh)] {
            #expect(
                await !account.session.retiredInVault(vaultID).contains(freshID),
                "the new device is retired on the \(name)'s device")
            let report = try await account.session.syncAll().vaults[vaultID]
            #expect(report?.deviceRevoked == false)
            if name != "new device" {
                #expect(Self.refused(planted, in: report), "the plant verified on the \(name)'s device")
            }
        }
        var item = Self.bank(in: vaultID)
        item.title = "Written on the new device"
        item = try await fresh.session.save(item)
        #expect(try await fresh.session.syncAll().vaults[vaultID]?.ownStreamConflict == 1, "the plant was taken in")
        await Self.remove(planted, from: household.transport)
        try await Self.syncAll([fresh, owner, member])
        for account in [owner, member] {
            #expect(
                (try? await account.session.item(id: item.id))?.title == item.title, "the new device reached nobody")
        }
    }
}
