import Foundation
import Testing
import WatchwordModel
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// Found by the audit of the item merge (docs/10-sync-correctness.md §8, docs/06-adversarial-review.md §H, Y29). Not
/// a fault of the merge: `ItemMerge.stamped` stamps every group whose value differs between the draft and the stored
/// version, with everything the stored version has seen. That is right when the draft was made from the stored
/// version. `VaultSession.save` also passes it a draft made from an *earlier* version, when a sync merged another
/// device's edit in between — and then the groups the other device changed "differ" too, are stamped as this device's
/// writes made after seeing that edit, and replace it, with no conflict and (for anything but a field) no history.
///
/// The session knows which version a draft was opened from (`Item.version`), so it can refuse the save
/// (`RecordStoreError.versionConflict`, as it already does for a write that raced a merge) and let the editor reload.
/// Recorded as a known issue until it does.
@Suite("Vault session: saving a draft opened before a sync")
struct StaleDraftTests {
    @Test("a draft opened before another device's edit arrived does not silently undo that edit when saved")
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
        #expect(try await pair.b.session.item(id: item.id).title == "City Library")

        draft.fields[1].value = "a new password"
        let saved = try? await pair.b.session.save(draft)
        let stored = try await pair.b.session.item(id: item.id)
        #expect(saved == nil || stored.field(.password)?.value == "a new password")
        withKnownIssue("VaultSession.save does not check that the draft was made from the version it replaces") {
            // Either the save is refused, or the rename survives it: shown, or kept as a conflict.
            let titles = [stored.title] + (ItemMerge.conflicts(of: stored)[.title] ?? []).map { "\($0.value)" }
            #expect(titles.contains { $0.contains("City Library") })
        }
    }
}
