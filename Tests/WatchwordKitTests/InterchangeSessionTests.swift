import Foundation
import Testing
import WatchwordCrypto
import WatchwordInterchange
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordKit

/// Import, export and the encrypted archive through `VaultSession` (docs/02-architecture.md §14.1, PRD F8.1–F8.4).
@Suite("Vault session: import, export and the encrypted archive")
struct InterchangeSessionTests {
    static let passphrase = "a long archive passphrase"

    static let csv = Array(
        """
        Title,URL,Username,Password,Notes,OTPAuth
        Bank,https://bank.example/,wendy,bank-pw,,
        Mail,https://mail.example/,wendy@mail.example,mail-pw,first line,
        """.utf8)

    static func bankItem(_ vaultID: UUID) -> Item {
        Item(
            vaultID: vaultID, title: "Bank", scopes: [ServiceScope(host: "bank.example")],
            fields: [
                Field(kind: .username, label: "Username", value: "wendy"),
                Field(kind: .password, label: "Password", value: "the-real-bank-pw"),
            ])
    }

    static func unlockedVault() async throws -> (TestVault, UUID) {
        let vault = TestVault()
        try await vault.createAccount()
        return (vault, try #require(await vault.session.personalVaultID))
    }

    @Test("a preview reads the file and writes nothing")
    func previewWritesNothing() async throws {
        let (vault, personal) = try await Self.unlockedVault()
        let preview = try await vault.session.previewImport(Self.csv, format: .passwordCSV, into: personal)
        #expect(preview.report.format == .applePasswordsCSV)
        #expect(preview.entries.map(\.title) == ["Bank", "Mail"])
        #expect(preview.entries[0].hosts == ["bank.example"])
        #expect(preview.matches.isEmpty)
        #expect(try await vault.session.items().items.isEmpty)
    }

    @Test("a commit saves each entry as this device's write, scoped as the file's URLs allow")
    func commit() async throws {
        let (vault, personal) = try await Self.unlockedVault()
        let preview = try await vault.session.previewImport(Self.csv, format: .passwordCSV, into: personal)
        let outcome = try await vault.session.commitImport(preview.id, decisions: [:])
        #expect(outcome.created.count == 2 && outcome.failed.isEmpty)
        let items = try await vault.session.items().items
        #expect(items.map(\.title) == ["Bank", "Mail"])
        #expect(items.allSatisfy { $0.version > 0 && !$0.revisions.isEmpty && $0.vaultID == personal })
        #expect(items[0].field(.password)?.value == "bank-pw")
        // Consumed: a second commit of the same preview writes nothing more.
        await #expect(throws: InterchangeSessionError.noPendingImport) {
            try await vault.session.commitImport(preview.id, decisions: [:])
        }
    }

    @Test("a duplicate needs the person's decision, and a merge adds only what they accepted")
    func duplicates() async throws {
        let (vault, personal) = try await Self.unlockedVault()
        let existing = try await vault.session.save(Self.bankItem(personal))
        let file = Array(
            """
            Title,URL,Username,Password,Notes,OTPAuth
            Bank,https://bank.example/,wendy,a-different-pw,from the old manager,
            """.utf8)
        let preview = try await vault.session.previewImport(file, format: .passwordCSV, into: personal)
        let match = try #require(preview.matches.first)
        #expect(match.existingID == existing.id && match.hasNewSignInFields)
        await #expect(throws: InterchangeSessionError.decisionRequired(importedID: match.importedID)) {
            try await vault.session.commitImport(preview.id, decisions: [:])
        }
        let additions = try await vault.session.importAdditions(
            preview: preview.id, importedID: match.importedID, existingID: existing.id)
        #expect(additions.signInFields.map(\.value) == ["a-different-pw"])

        let outcome = try await vault.session.commitImport(
            preview.id, decisions: [match.importedID: .merge(into: existing.id)])
        #expect(outcome.merged == [existing.id] && outcome.created.isEmpty)
        let merged = try await vault.session.item(id: existing.id)
        #expect(merged.field(.password)?.value == "the-real-bank-pw")
        #expect(merged.fields.filter { $0.kind == .password }.count == 1)
        #expect(merged.notes == "from the old manager")
        #expect(merged.scopes == existing.scopes)
    }

    @Test("a decision naming an item the entry was not matched with is refused before anything is written")
    func unknownMatch() async throws {
        let (vault, personal) = try await Self.unlockedVault()
        let other = try await vault.session.save(login(personal, host: "other.example"))
        let preview = try await vault.session.previewImport(Self.csv, format: .passwordCSV, into: personal)
        let first = preview.entries[0].id
        await #expect(throws: InterchangeSessionError.unknownMatch(importedID: first)) {
            try await vault.session.commitImport(preview.id, decisions: [first: .merge(into: other.id)])
        }
        #expect(try await vault.session.items().items.count == 1)
    }

    @Test("lock() drops the preview: nothing of the file outlives the keys")
    func lockDropsPreview() async throws {
        let (vault, personal) = try await Self.unlockedVault()
        let preview = try await vault.session.previewImport(Self.csv, format: .passwordCSV, into: personal)
        await vault.session.lock()
        #expect(await vault.session.pendingImport == nil)
        try await vault.session.unlock(password: TestVault.password)
        await #expect(throws: InterchangeSessionError.noPendingImport) {
            try await vault.session.commitImport(preview.id, decisions: [:])
        }
        #expect(try await vault.session.items().items.isEmpty)
    }

    @Test("a plaintext export needs the account password, checked as an unlock checks it")
    func plaintextExport() async throws {
        let (vault, personal) = try await Self.unlockedVault()
        try await vault.session.save(Self.bankItem(personal))
        await #expect(throws: CryptoError.authenticationFailed) {
            try await vault.session.exportPlaintext(
                .applePasswordsCSV(formulaPolicy: .neutralise), vaults: [personal], password: "not the password")
        }
        let export = try await vault.session.exportPlaintext(
            .applePasswordsCSV(formulaPolicy: .neutralise), vaults: [personal], password: TestVault.password)
        #expect(String(decoding: export.bytes, as: UTF8.self).contains("the-real-bank-pw"))
        #expect(export.report.exportedCount == 1 && export.unreadable.isEmpty)
        let pux = try await vault.session.exportPlaintext(.onePUX, vaults: [personal], password: TestVault.password)
        #expect(!pux.bytes.isEmpty)
        let cxf = try await vault.session.exportPlaintext(
            .credentialExchange(exporterRelyingPartyID: "watchword.example"), vaults: [personal],
            password: TestVault.password)
        #expect(String(decoding: cxf.bytes, as: UTF8.self).contains("the-real-bank-pw"))
        #expect(VaultSession.plaintextExportWarning == InterchangeGuide.plaintextExportWarning.text)
    }

    @Test("an export is refused while locked and for no vault")
    func exportRefusals() async throws {
        let (vault, personal) = try await Self.unlockedVault()
        await #expect(throws: InterchangeSessionError.noVaultChosen) {
            try await vault.session.exportPlaintext(.onePUX, vaults: [], password: TestVault.password)
        }
        await vault.session.lock()
        await #expect(throws: VaultError.locked) {
            try await vault.session.exportPlaintext(.onePUX, vaults: [personal], password: TestVault.password)
        }
        await #expect(throws: VaultError.locked) {
            try await vault.session.exportArchive(
                vaults: [personal], passphrase: Self.passphrase, password: TestVault.password)
        }
    }

    @Test("an archive keeps history, times, archived marks and the vault's name through a restore")
    func archiveRoundTrip() async throws {
        let (vault, personal) = try await Self.unlockedVault()
        let saved = try await vault.session.save(Self.bankItem(personal))
        await vault.clock.advance(by: 3600)
        var edited = saved
        edited.fields[1].value = "a newer bank pw"
        edited.archived = true
        try await vault.session.save(edited)
        let original = try await vault.session.item(id: saved.id)
        #expect(original.history.count == 1)

        await #expect(throws: InterchangeSessionError.passphraseTooShort(minimum: 10)) {
            try await vault.session.exportArchive(vaults: [personal], passphrase: "short", password: TestVault.password)
        }
        let archive = try await vault.session.exportArchive(
            vaults: [personal], passphrase: Self.passphrase, password: TestVault.password)
        #expect(archive.itemCount == 1 && archive.vaultCount == 1)

        let restored = try await vault.session.createVault(name: "Restored")
        await vault.clock.advance(by: 3600)
        let preview = try await vault.session.previewArchiveImport(
            archive.bytes, passphrase: Self.passphrase, into: restored.id)
        #expect(preview.report.format == .watchwordArchive)
        #expect(preview.entries.first?.reference.container == VaultInfo.defaultPersonalName)
        #expect(preview.entries.first?.state == .archived)
        let outcome = try await vault.session.commitImport(preview.id, decisions: [:])
        let copy = try await vault.session.item(id: try #require(outcome.created.first))
        #expect(copy.id != original.id && copy.vaultID == restored.id)
        #expect(copy.createdAt == original.createdAt && copy.modifiedAt == original.modifiedAt)
        #expect(copy.archived)
        #expect(copy.history.count == 1)
        #expect(copy.history[0].fields.first { $0.kind == .password }?.value == "the-real-bank-pw")
        #expect(copy.field(.password)?.value == "a newer bank pw")
    }

    @Test("a wrong passphrase is an authentication failure, like a tampered archive")
    func wrongPassphrase() async throws {
        let (vault, personal) = try await Self.unlockedVault()
        try await vault.session.save(Self.bankItem(personal))
        let archive = try await vault.session.exportArchive(
            vaults: [personal], passphrase: Self.passphrase, password: TestVault.password)
        await #expect(throws: CryptoError.authenticationFailed) {
            try await vault.session.previewArchiveImport(
                archive.bytes, passphrase: "a long archive passphrasf", into: personal)
        }
        #expect(await vault.session.pendingImport == nil)
    }

    @Test("an archive from another account needs that account's Secret Key, and then restores into this one")
    func anotherAccount() async throws {
        let old = TestVault(seed: 41)
        let kit = try await old.createAccount()
        let oldPersonal = try #require(await old.session.personalVaultID)
        try await old.session.save(Self.bankItem(oldPersonal))
        let archive = try await old.session.exportArchive(
            vaults: [oldPersonal], passphrase: Self.passphrase, password: TestVault.password)

        let (vault, personal) = try await Self.unlockedVault()
        await #expect(throws: InterchangeSessionError.archiveFromAnotherAccount(kit.accountID)) {
            try await vault.session.previewArchiveImport(archive.bytes, passphrase: Self.passphrase, into: personal)
        }
        let ownKit = try await vault.session.emergencyKit()
        await #expect(throws: CryptoError.authenticationFailed) {
            try await vault.session.previewArchiveImport(
                archive.bytes, passphrase: Self.passphrase, secretKey: ownKit.secretKey, into: personal)
        }
        let preview = try await vault.session.previewArchiveImport(
            archive.bytes, passphrase: Self.passphrase, secretKey: kit.secretKey, into: personal)
        let outcome = try await vault.session.commitImport(preview.id, decisions: [:])
        #expect(outcome.created.count == 1)
        #expect(try await vault.session.items().items.first?.field(.password)?.value == "the-real-bank-pw")
    }
}
