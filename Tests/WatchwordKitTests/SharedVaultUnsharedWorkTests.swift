import Foundation
import Testing
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

// Review finding Z123 (docs/06-adversarial-review.md): what `unsharedWork(inSharedVault:)` counts.
extension SharedVaultScenarioTests {
    /// No adversary. A read-only member's device merges two concurrent edits by others and seals the result itself:
    /// the row carries this device's ID and was never published (the member may not publish there). It holds
    /// nothing anybody lacks, so it is not a change of this device's, and the confirmation before removing a left
    /// vault's items must not count it as one to be discarded for good. An edit the device made and did not publish
    /// is counted.
    @Test("changes nobody else has are this device's unpublished edits, not the merges it sealed")
    func unsharedWorkCountsEditsNotMerges() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 12300)
        let reader = try await household.account(seed: 12301)
        let (writer, writerView) = try await household.withheldAccount(seed: 12302)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(reader, to: vaultID, as: .readOnly, owner: owner)
        try await owner.invite(writer, to: vaultID, as: .readWrite, owner: owner)
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, writer, reader])

        // Two edits made apart: the writer is not shown the owner's.
        let ownerDevice = try #require(try await owner.vault.store.loadAccount()).deviceID
        await writerView.withholdNew(under: "vault/\(vaultID.uuidString)/log/\(ownerDevice.uuidString)/")
        var renamed = try await owner.session.item(id: bank.id)
        renamed.title = "First Bank (joint)"
        try await owner.session.save(renamed)
        try await owner.session.sync()
        var changed = try await writer.session.item(id: bank.id)
        changed.fields = changed.fields.map { field in
            var field = field
            if field.kind == .password { field.value = "changed-by-the-writer" }
            return field
        }
        try await writer.session.save(changed)
        try await writer.session.sync()

        try await reader.session.sync()
        let readerDevice = try #require(try await reader.vault.store.loadAccount()).deviceID
        let row = try #require(try await reader.vault.store.record(RecordKey(recordID: bank.id, kind: .item)))
        try #require(row.deviceID == readerDevice, "the reader did not seal a merge: the test proves nothing")
        #expect(try await reader.session.item(id: bank.id).title == "First Bank (joint)")
        #expect(try await reader.session.unsharedWork(inSharedVault: vaultID) == 0, "a merge was counted")

        // An edit of the writer's own, not yet published, is one.
        var again = try await writer.session.item(id: bank.id)
        again.title = "Bank, edited and not synced"
        try await writer.session.save(again)
        #expect(try await writer.session.unsharedWork(inSharedVault: vaultID) == 1)
    }
}
