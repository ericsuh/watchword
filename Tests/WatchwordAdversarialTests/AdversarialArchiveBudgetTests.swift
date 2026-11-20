import Foundation
import SecureMemory
import Testing
import WatchwordInterchange
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordCrypto
@testable import WatchwordKit

// Review finding Z128 (docs/06-adversarial-review.md): the budgets an archive of another account gets.
extension AdversarialSessionInterchangeTests {
    /// Threat: A7 seals an archive under an account of its own and hands over its Kit. "Restore into a new account"
    /// takes the Secret Key as typed text, so the code cannot tell it from a genuine restore, and the restore gave it
    /// the limits sized for this app's own archives: 1 GiB of stored drafts where a CSV or 1PUX gets 512 MiB, and four
    /// times the scope derivations. Here 700 small entries whose notes are line feeds, each stored at just under the
    /// 1 MiB item bound, would commit some 570 MiB of sealed rows to every device of the account. Now an archive
    /// opened with a typed Secret Key keeps the format's item count and the per-item bound, and has `.standard`'s
    /// totals: it fails on the stored-size budget, as such a CSV does.
    @Test("an archive of another account gets the import-wide budgets a CSV gets")
    func anotherAccountsArchiveHasTheStandardBudgets() async throws {
        let (vault, personal) = try await Self.vault()
        let otherKey = SecretKey.generate()
        let notes = String(repeating: "\n", count: 3_000)
        let count = 700
        var generator = SeededGenerator(seed: 128)
        let archive = try AccountArchive.seal(
            entryCount: count,
            payload: { index in
                let item = Item(vaultID: UUID(), title: "Entry \(index)", scopes: [], fields: [], notes: notes)
                let encoded = try ItemCodec.encode(item)
                defer { encoded.zeroise() }
                return SecureBytes.concatenating([SecureBytes(copying: [2]), encoded])
            }, archiveID: UUID(), accountID: UUID(), createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            passphrase: Self.passphrase, secretKey: otherKey, parameters: .baseline, using: &generator)
        let one = Item(vaultID: UUID(), title: "Entry 0", scopes: [], fields: [], notes: notes)
        #expect(StoredItemSize.estimate(one) < InterchangeLimits.archive.maximumStoredItemBytes)
        #expect(StoredItemSize.estimate(one) * count > InterchangeLimits.standard.maximumTotalStoredBytes)

        await #expect(throws: InterchangeError.limitExceeded(.totalStoredBytes, limit: 512 << 20)) {
            _ = try await vault.session.previewArchiveImport(
                archive, passphrase: Self.passphrase, secretKey: otherKey.formatted, into: personal)
        }
        // This account's own archive of the same shape still restores into it, and its export says it would not
        // restore into a new account.
        var checkGenerator = SeededGenerator(seed: 129)
        let own = (0..<count).map { Item(vaultID: UUID(), title: "Entry \($0)", scopes: [], fields: [], notes: notes) }
        let check = ArchivedItems.restoreCheck(own, using: &checkGenerator)
        #expect(check.limitReached == nil && check.skipped.isEmpty)
        #expect(check.limitReachedInAnotherAccount == .totalStoredBytes && !check.restoresEverything)
        #expect(InterchangeLimits.archiveOfAnotherAccount.maximumItems == InterchangeLimits.archive.maximumItems)
        #expect(
            InterchangeLimits.archiveOfAnotherAccount.maximumStoredItemBytes
                == InterchangeLimits.archive.maximumStoredItemBytes)
        #expect(
            InterchangeLimits.archiveOfAnotherAccount.maximumScopeDerivations
                == InterchangeLimits.standard.maximumScopeDerivations)
    }
}
