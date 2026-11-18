import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

// Review finding Z42 (docs/06-adversarial-review.md): sharing a vault that already holds work judged every row against
// a stream index that had recorded nothing.
extension AdversarialSharedVaultTests {
    /// Threat: none needed; an owner with two devices. One device shares a vault the other wrote to. The judge
    /// attributes a value through the segment of its writer's stream that carried it, and at the moment of sharing the
    /// index holds no segment at all: judged then, every item holding a value the other device wrote is taken out of
    /// the vault and held aside. The index must be built from the log first, and then nothing is taken out, on the
    /// owner's device or an invitee's.
    @Test("sharing a vault two devices wrote to takes nothing out of it, for the owner or for someone invited")
    func sharingAVaultTwoDevicesWroteTo() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 910)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.sync()
        let second = try await household.secondDevice(of: owner)
        for number in 0..<3 {
            var item = Self.bank(in: vaultID)
            item.title = "Written on the other device \(number)"
            _ = try await second.session.save(item)
        }
        try await second.session.sync()
        try await owner.session.sync()
        // Edited again here, so one row holds values of both devices.
        let mixed = try #require(try await owner.session.items(in: vaultID).items.first)
        try await owner.session.setArchived(true, id: mixed.id)
        #expect(try await owner.session.items(in: vaultID).items.count == 3)

        try await owner.session.shareVault(vaultID)
        try await owner.session.sync()
        #expect(try await owner.session.items(in: vaultID).items.count == 3)
        #expect(try await owner.session.quarantinedVersions().isEmpty, "the owner's own work was held aside")
        #expect(try await owner.session.sharedVaultStatus(vaultID).heldAside == 0)

        let member = try await household.account(seed: 911)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([owner, member])
        #expect(try await member.session.items(in: vaultID).items.count == 3)
        #expect(try await member.session.sharedVaultStatus(vaultID).heldAside == 0)
    }

    /// Threat: none needed. A vault used long enough that its log was compacted: segments were collected and their
    /// values survive only in a snapshot, which no stream's segment carries. Nothing can attribute those values once
    /// the vault is shared, so every device, an invitee's included, would hold the items aside for good. Until there
    /// is a rule that attributes them, such a vault is not shared at all, and says why.
    @Test("a vault whose log was compacted is not shared, rather than shared with its older items held aside")
    func sharingACompactedVault() async throws {
        let household = SharedVaultHousehold()
        var configuration = SyncSettings(state: InMemorySyncStateStore(), transport: household.transport).configuration
        configuration.snapshotThreshold = 2
        let owner = try await household.account(seed: 920, configuration: configuration)
        let vaultID = try await owner.session.createVault(name: "Household").id
        for number in 0..<6 {
            var item = Self.bank(in: vaultID)
            item.title = "Item \(number)"
            _ = try await owner.session.save(item)
            try await owner.session.sync()
        }
        let prefix = SyncObjectLocation.vaultPrefix(vaultID)
        #expect(
            await household.transport.list(prefix: prefix).contains { SyncObjectLocation(name: $0)?.kind == .snapshot },
            "the vault's log was not compacted: the test proves nothing")

        await #expect(throws: SharedVaultError.historyCompacted(vaultID)) {
            try await owner.session.shareVault(vaultID)
        }
        #expect(try await owner.session.sharedVaultIDs().isEmpty)
        #expect(try await owner.session.vaults().first { $0.id == vaultID }?.isSharedUnavailable == false)
        #expect(try await owner.session.items(in: vaultID).items.count == 6)
        // Still the account's own: writable, and nothing of a chain on the transport.
        _ = try await owner.session.save(Self.bank(in: vaultID))
        #expect(await household.transport.list(prefix: SharingObjectLocation.vaultPrefix(vaultID)).isEmpty)
    }
}
