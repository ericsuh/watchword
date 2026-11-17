import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// Y30 (docs/06-adversarial-review.md §H): an item's sync metadata is whatever its writer sealed. A writer holding the
/// vault key (another device of the account, or a member of a shared vault) can seal an item whose stamps count above
/// the row's version, or file a value under a group it does not belong to. The merge reads every item through
/// `ItemMerge.canonical`; the UI must get the same reading, or it shows (and the conflict screen offers) values no
/// device would merge.
@Suite("Vault session: items are read in canonical form")
struct CanonicalReadTests {
    @Test("an item sealed with forged sync metadata is presented as the merge reads it, in every read the UI gets")
    func forgedMetadata() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        let vaultID = try #require(await vault.session.personalVaultID)
        let saved = try await vault.session.save(login(vaultID, title: "Library"))
        let row = try #require(try await vault.store.record(RecordKey(recordID: saved.id, kind: .item)))

        // The forgery: a value under the wrong group, and a "conflict" stamped far above any version written.
        var forged = saved
        forged.version = row.version + 1
        let stranger = UUID()
        let future = GroupStamp(revision: Revision(version: 1_000_000, device: stranger), seen: VersionVector())
        forged.conflicts[.title] = [
            ConflictingValue(stamp: future, value: .tags(["planted"])),
            ConflictingValue(stamp: future, value: .title("Pay here")),
        ]
        let sealed = try await vault.session.syncSealItem(forged)
        try await vault.store.commit(StoreChange(upserts: [sealed]))

        let read = try await vault.session.item(id: saved.id)
        let canonical = ItemMerge.canonical(forged, origin: VaultSession.origin(sealed))
        #expect(read == canonical)
        #expect(read != forged, "the forgery is not what the UI is shown")
        #expect(ItemMerge.canonical(read, origin: VaultSession.origin(sealed)) == read)
        #expect(read.version == sealed.version && read.id == saved.id && read.vaultID == vaultID)
        let offered = (ItemMerge.conflicts(of: read)[.title] ?? []).map(\.value)
        #expect(!offered.contains(.tags(["planted"])), "no value under a group it does not belong to")
        #expect(
            read.conflicts.values.joined().allSatisfy { $0.stamp.revision.version <= sealed.version },
            "no stamp above the row's version")
        #expect(try await vault.session.items().items.first { $0.id == saved.id } == read)
        #expect(try await vault.session.search("someone@example.com").first { $0.id == saved.id } == read)
        #expect(try await vault.session.credentialItems().first { $0.id == saved.id } == read)
    }
}
