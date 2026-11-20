import Foundation
import SecureMemory
import Testing
import WatchwordInterchange
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordCrypto
@testable import WatchwordKit

// Review finding Z132 (docs/06-adversarial-review.md): the dates an import keeps, all of them, and where they are
// bounded.
extension AdversarialSessionInterchangeTests {
    /// Threat: A7's archive (with its Kit) carries a passkey whose creation date, inside the field's value, is in the
    /// future. Z85 bounded the item's dates and its history's, and called that every date; the passkey's was kept
    /// verbatim (the year 2500, say). Nothing security-relevant reads it today, but the claim was wrong, and it is the date the item editor
    /// shows. Now it is bounded by the clock like the rest, in the field and in the history.
    @Test("a file cannot date a passkey in the future either")
    func futurePasskeyDate() async throws {
        let (vault, personal) = try await Self.vault()
        // The year 2500: within what a passkey field may hold.
        let future = Date(timeIntervalSince1970: 16_725_225_600)
        var field = AutoFillFixtures.passkey(relyingParty: "shop.example", seed: 132)
        var credential = try field.passkeyCredential()
        credential.createdAt = future
        field.value = try credential.fieldValue()
        let forged = Item(
            vaultID: personal, title: "Shop", scopes: [ServiceScope(host: "shop.example")], fields: [field],
            history: [ItemHistoryEntry(replacedAt: Date(timeIntervalSince1970: 1_000), version: 1, fields: [field])])
        let attackerKey = SecretKey.generate()
        var generator = SeededGenerator(seed: 132)
        let archive = try AccountArchive.seal(
            [SecureBytes.concatenating([SecureBytes(copying: [2]), try ItemCodec.encode(forged)])], archiveID: UUID(),
            accountID: UUID(), createdAt: Date(timeIntervalSince1970: 0), passphrase: Self.passphrase,
            secretKey: attackerKey, parameters: .baseline, using: &generator)
        let restored = try await vault.session.createVault(name: "Restored")
        let preview = try await vault.session.previewArchiveImport(
            archive, passphrase: Self.passphrase, secretKey: attackerKey.formatted, into: restored.id)
        #expect(preview.report.warnings.map(\.warning).contains(.futureDateBounded))
        let outcome = try await vault.session.commitImport(preview.id, decisions: [:])
        let created = try await vault.session.item(id: try #require(outcome.created.first))
        let now = await vault.clock.now()
        let passkeys = created.fields.filter { $0.kind == .passkey } + created.history.flatMap(\.fields)
        #expect(!passkeys.isEmpty)
        for passkey in passkeys {
            #expect(try passkey.passkeyCredential().createdAt <= now, "a passkey dated in the future")
        }
    }

    /// Threat: A7 chooses the file's size, and the bounding of its dates walked every draft on the session's actor,
    /// between the preview's epoch checks: up to 200,000 drafts with `lock()` waiting behind them. It is off the actor
    /// now, like the parse and the review, and a lock during it wins.
    @Test("a lock while an import's dates are bounded takes effect at once")
    func lockWinsDuringDateBounding() async throws {
        let (vault, personal) = try await Self.vault()
        try await Self.lockWins(at: .importDates, in: vault) {
            try await vault.session.previewImport(Self.file, format: .passwordCSV, into: personal)
        }
    }
}
