import Foundation
import Testing
import WatchwordModel
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// Found by the audit of the item merge (docs/10-sync-correctness.md §8, docs/06-adversarial-review.md §H, Y29). Not
/// a fault of the merge: `ItemMerge.stamped` stamps every group whose value differs between the draft and the stored
/// version, with everything the stored version has seen. That is right when the draft was made from the stored
/// version. A draft made from an *earlier* version, when a sync merged another device's edit in between, would make
/// the groups the other device changed "differ" too, stamp them as this device's writes made after seeing that edit,
/// and replace it, with no conflict and (for anything but a field) no history.
///
/// So `VaultSession.save` refuses a draft whose `version` is not the stored item's, with `versionConflict`, inside
/// the same compare-and-swap that refuses a write racing a merge, and the editor reopens the item.
@Suite("Vault session: saving a draft opened before a sync")
struct StaleDraftTests {
    @Test("a draft opened before another device's edit arrived is refused, and the edit survives")
    func staleDraft() async throws {
        let pair = try await SyncPair.make()
        let item = try await pair.a.session.save(login(pair.vaultID, title: "Library"))
        try await pair.exchange()

        // The person opens the item on B to change its password.
        var draft = try await pair.b.session.item(id: item.id)
        // Meanwhile A renames it, and B's next sync merges the rename while the editor is still open.
        var onA = try await pair.a.session.item(id: item.id)
        onA.title = "City Library"
        try await pair.a.session.save(onA)
        try await pair.exchange()
        let merged = try await pair.b.session.item(id: item.id)
        #expect(merged.title == "City Library")

        draft.fields[1].value = "a new password"
        await #expect(throws: VaultError.versionConflict(item.id)) {
            try await pair.b.session.save(draft)
        }
        let stored = try await pair.b.session.item(id: item.id)
        #expect(stored == merged, "nothing was written")

        // Reopened, the same change saves, and the rename is kept.
        var reopened = stored
        reopened.fields[1].value = "a new password"
        let saved = try await pair.b.session.save(reopened)
        #expect(saved.title == "City Library")
        #expect(saved.field(.password)?.value == "a new password")
    }

    @Test("a draft of a new item cannot replace an item already stored under its ID")
    func newDraftOverExisting() async throws {
        let pair = try await SyncPair.make()
        let item = try await pair.a.session.save(login(pair.vaultID, title: "Library"))
        var impostor = login(pair.vaultID, title: "Not the library")
        impostor.id = item.id
        await #expect(throws: VaultError.versionConflict(item.id)) {
            try await pair.a.session.save(impostor)
        }
        #expect(try await pair.a.session.item(id: item.id).title == "Library")
    }
}
