import Foundation
import SecureMemory
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordInterchange
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit

/// A store that holds the next read of item rows until the test releases it, to land a call inside a preview's
/// awaits.
actor ItemReadHoldingStore: RecordStore {
    private let inner = InMemoryRecordStore()
    private var armed = false
    private var held: CheckedContinuation<Void, Never>?
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var holding = false

    func holdNextItemRead() { armed = true }

    func waitUntilHeld() async {
        if holding { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        held?.resume()
        held = nil
    }

    func loadAccount() async throws -> AccountRecord? { await inner.loadAccount() }
    func record(_ key: RecordKey) async throws -> StoredRecord? { await inner.record(key) }

    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        if kind == .item, armed {
            armed = false
            holding = true
            for waiter in waiters { waiter.resume() }
            waiters = []
            await withCheckedContinuation { held = $0 }
            holding = false
        }
        return await inner.records(in: vaultID, kind: kind)
    }

    func commit(_ change: StoreChange) async throws { try await inner.commit(change) }
    func eraseAll() async throws { await inner.eraseAll() }
}

/// Regressions for the review of the interchange stream's session wiring (docs/06-adversarial-review.md §M).
@Suite("Vault session: import and archive review regressions")
struct InterchangeSessionReviewTests {
    static let passphrase = "a long archive passphrase"
    static let csv = InterchangeSessionTests.csv

    /// Review finding X2: the archive's creation time and identifier are authenticated (the manifest covers the
    /// header) and reach the preview, so the restore screen can show which archive it is restoring.
    @Test("an archive's preview carries its authenticated creation time and identifier")
    func archiveDate() async throws {
        let (vault, personal) = try await InterchangeSessionTests.unlockedVault()
        try await vault.session.save(InterchangeSessionTests.bankItem(personal))
        await vault.clock.set(Date(timeIntervalSince1970: 1_800_123_456))
        let archive = try await vault.session.exportArchive(
            vaults: [personal], passphrase: Self.passphrase, password: TestVault.password)
        let sealed = try AccountArchive.parse(archive.bytes)
        await vault.clock.advance(by: 86_400 * 365)
        let preview = try await vault.session.previewArchiveImport(
            archive.bytes, passphrase: Self.passphrase, into: personal)
        #expect(preview.archiveCreatedAt == Date(timeIntervalSince1970: 1_800_123_456))
        #expect(preview.archiveID == sealed.archiveID)
        let plain = try await vault.session.previewImport(Self.csv, format: .passwordCSV, into: personal)
        #expect(plain.archiveID == nil && plain.archiveCreatedAt == nil)
    }

    /// Review finding X4: an item sync kept in the trash after a permanent deletion that had not seen it is restored
    /// live, with or without `includesTrashed`, and the 30-day purge does not remove it.
    @Test("an item kept after a deletion survives a restore and the trash purge")
    func keptAfterDeletionSurvivesPurge() async throws {
        let (vault, personal) = try await InterchangeSessionTests.unlockedVault()
        var kept = InterchangeSessionTests.bankItem(UUID())
        kept.trashedAt = Date(timeIntervalSince1970: 1_700_000_000)
        kept.keptAfterDeletion = true
        #expect(!kept.isTrashedByPerson)
        let otherKey = SecretKey.generate()
        var generator = SeededGenerator(seed: 11)
        let archive = try AccountArchive.seal(
            entryCount: 1,
            payload: { _ in
                let encoded = try ItemCodec.encode(kept)
                defer { encoded.zeroise() }
                return SecureBytes.concatenating([SecureBytes(copying: [2]), encoded])
            }, archiveID: UUID(), accountID: UUID(), createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            passphrase: Self.passphrase, secretKey: otherKey, parameters: .baseline, using: &generator)

        for options in [ImportOptions(), ImportOptions(includesTrashed: true)] {
            let preview = try await vault.session.previewArchiveImport(
                archive, passphrase: Self.passphrase, secretKey: otherKey.formatted, into: personal, options: options)
            #expect(preview.report.skipped.isEmpty)
            #expect(preview.entries.map(\.state) == [.active])
            #expect(preview.report.warnings.map(\.warning).contains(.restoredFromSyncTrash))
            // The second pass matches the first restore; keeping both changes nothing about either.
            let decisions = Dictionary(
                uniqueKeysWithValues: preview.matches.map { ($0.importedID, ImportDecision.keepBoth) })
            let outcome = try await vault.session.commitImport(preview.id, decisions: decisions)
            let restored = try #require(outcome.created.first)
            await vault.clock.advance(by: 31 * 86_400)
            try await vault.session.purgeExpiredTrash()
            let item = try await vault.session.item(id: restored)
            #expect(!item.isTrashed && item.field(.password)?.value == "the-real-bank-pw")
        }
    }

    /// Review finding X7: a `discardImport()` that lands while a preview awaits the vault's items wins: the preview
    /// throws, and no drafts are left in the session to commit.
    @Test("discardImport() during a preview drops its drafts")
    func discardDuringPreview() async throws {
        let store = ItemReadHoldingStore()
        let vault = TestVault(store: store)
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)
        await store.holdNextItemRead()
        let preview = Task { try await vault.session.previewImport(Self.csv, format: .passwordCSV, into: personal) }
        await store.waitUntilHeld()
        await vault.session.discardImport()
        await store.release()
        await #expect(throws: InterchangeSessionError.noPendingImport) { try await preview.value }
        #expect(await vault.session.pendingImport == nil)
    }

    /// Review finding X7: of two previews, the one asked for last is the one kept, even when the earlier one finishes
    /// reading later.
    @Test("a newer preview overtakes one still being read")
    func newerPreviewWins() async throws {
        let store = ItemReadHoldingStore()
        let vault = TestVault(store: store)
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)
        await store.holdNextItemRead()
        let first = Task { try await vault.session.previewImport(Self.csv, format: .passwordCSV, into: personal) }
        await store.waitUntilHeld()
        let second = try await vault.session.previewImport(
            Array("Title,URL,Username,Password,Notes,OTPAuth\nOther,https://other.example/,me,pw,,\n".utf8),
            format: .passwordCSV, into: personal)
        await store.release()
        await #expect(throws: InterchangeSessionError.noPendingImport) { try await first.value }
        #expect(await vault.session.pendingImport?.id == second.id)
        let outcome = try await vault.session.commitImport(second.id, decisions: [:])
        #expect(outcome.created.count == 1)
    }

    /// A vault name longer than an archive's vault entry holds is cut at a scalar boundary: cut through a scalar, the
    /// entry's bytes would not decode and the restore would lose the name (every item's `container`).
    @Test("a long vault name is cut at a scalar boundary and survives a restore")
    func longVaultName() async throws {
        let (vault, _) = try await InterchangeSessionTests.unlockedVault()
        // 1 + 255 × 8 bytes: the 1,024-byte cut falls inside the skin-tone modifier of the 128th thumb.
        let name = "a" + String(repeating: "\u{1F44D}\u{1F3FD}", count: 255)
        #expect(name.count == 256 && name.utf8.count > ArchivePayload.maximumVaultNameBytes)
        let long = try await vault.session.createVault(name: name)
        try await vault.session.save(InterchangeSessionTests.bankItem(long.id))
        let archive = try await vault.session.exportArchive(
            vaults: [long.id], passphrase: Self.passphrase, password: TestVault.password)
        let preview = try await vault.session.previewArchiveImport(
            archive.bytes, passphrase: Self.passphrase, into: long.id)
        let container = try #require(preview.entries.first?.reference.container)
        #expect(name.unicodeScalars.starts(with: container.unicodeScalars))
        // Everything up to the scalar the cut would have split: "a", 127 whole thumbs, and one without its modifier.
        let kept = 1_021
        #expect(container.utf8.count == kept)
        #expect(ArchivePayload.vaultName("short") == Array("short".utf8))
        await vault.session.discardImport()
    }

    /// An archive's vault entry that does not parse (too short, or a name that is not UTF-8) is listed in the report
    /// as skipped (docs/02-architecture.md §14.1), never dropped in silence; the items beside it are imported.
    @Test("a malformed vault entry in an archive is listed as skipped")
    func malformedVaultEntry() async throws {
        let (vault, personal) = try await InterchangeSessionTests.unlockedVault()
        let key = SecretKey.generate()
        var generator = SeededGenerator(seed: 31)
        let item = try ItemCodec.encode(InterchangeSessionTests.bankItem(UUID()))
        defer { item.zeroise() }
        let payloads: [[UInt8]] = [
            [ArchivePayload.vault, 1, 2, 3],
            [ArchivePayload.vault] + [UInt8](repeating: 7, count: 16) + [0xFF, 0xFE],
        ]
        let archive = try AccountArchive.seal(
            entryCount: 3,
            payload: { index in
                index < 2
                    ? SecureBytes(copying: payloads[index])
                    : SecureBytes.concatenating([SecureBytes(copying: [ArchivePayload.item]), item])
            }, archiveID: UUID(), accountID: UUID(), createdAt: Date(timeIntervalSince1970: 1_800_000_000),
            passphrase: Self.passphrase, secretKey: key, parameters: .baseline, using: &generator)
        let preview = try await vault.session.previewArchiveImport(
            archive, passphrase: Self.passphrase, secretKey: key.formatted, into: personal)
        #expect(preview.report.skipped.count == 2)
        #expect(preview.report.skipped.allSatisfy { if case .malformed = $0.reason { true } else { false } })
        #expect(preview.entries.map(\.title) == ["Bank"])
        await vault.session.discardImport()
    }
}
