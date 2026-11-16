import Foundation
import Testing
import WatchwordHygiene
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit

/// The session's hygiene wiring (docs/02-architecture.md §13.8; PRD F9.1 to F9.3).
@Suite("Vault session: hygiene")
struct SessionHygieneTests {
    typealias Fixture = HygieneSessionFixture

    static func unlocked() async throws -> (Fixture, UUID) {
        let fixture = await Fixture()
        _ = try await fixture.session.createAccount(password: TestVault.password)
        return (fixture, try #require(await fixture.session.personalVaultID))
    }

    @Test("scheduled steps check every password, and the report says which are breached and which are reused")
    func reportAfterScans() async throws {
        let (fixture, vaultID) = try await Self.unlocked()
        let breached = try await fixture.session.save(
            Fixture.login(vaultID, title: "Forum", host: "forum.example", password: "password"))
        let unique = try await fixture.session.save(
            Fixture.login(vaultID, title: "Bank", host: "bank.example", password: "V3ry-Un1que+Phrase"))
        let reused = try await fixture.session.save(
            Fixture.login(vaultID, title: "Shop", host: "shop.example", password: "password"))

        let before = try await fixture.session.hygieneReport()
        #expect(before.totals.itemsAwaitingBreachCheck == 3)
        let outcomes = try await fixture.scanUntilIdle()
        #expect(outcomes.count == 3)
        let report = try await fixture.session.hygieneReport()
        #expect(report.totals.itemsAwaitingBreachCheck == 0)
        #expect(report.item(breached.id)?.findings.contains { $0.kind == .breachedPassword } == true)
        #expect(report.item(reused.id)?.findings.contains { $0.kind == .reusedPassword } == true)
        #expect(report.item(unique.id)?.findings.contains { $0.kind == .breachedPassword } == false)
        #expect(Set(try await fixture.session.itemsUsingPassword("password")) == [breached.id, reused.id])

        // Only range requests left, each with five hexadecimal characters.
        for request in await fixture.http.requests {
            #expect(request.url.absoluteString.hasPrefix("https://api.pwnedpasswords.com/range/"))
            #expect(request.url.path.count == "/range/".count + 5)
        }
    }

    @Test("a save is due for a check at once, and an edit's new password replaces the old one's result")
    func saveUpdatesEngine() async throws {
        let (fixture, vaultID) = try await Self.unlocked()
        var item = try await fixture.session.save(
            Fixture.login(vaultID, title: "Forum", host: "forum.example", password: "V3ry-Un1que+Phrase"))
        try await fixture.scanUntilIdle()
        guard case .clear = try await fixture.session.hygieneReport().item(item.id)?.breachStatus else {
            Issue.record("a password not in the corpus is clear once checked")
            return
        }

        item.fields[1].value = "123456"
        item = try await fixture.session.save(item)
        let pending = try await fixture.session.hygieneReport()
        #expect(pending.totals.itemsAwaitingBreachCheck == 1)
        guard case .scanned(item.id, .scanned(breachedPasswords: 1, _)) = try await fixture.session.runHygieneStep()
        else {
            Issue.record("the edited item was not the one checked next")
            return
        }
        let after = try await fixture.session.hygieneReport()
        #expect(after.item(item.id)?.findings.contains { $0.kind == .breachedPassword } == true)
    }

    @Test("rows written behind the session's back (as the sync engine writes them) are in the next report")
    func reconcileWithStore() async throws {
        let (fixture, vaultID) = try await Self.unlocked()
        let kept = try await fixture.session.save(
            Fixture.login(vaultID, title: "Forum", host: "forum.example", password: "hunter2"))
        let deleted = try await fixture.session.save(
            Fixture.login(vaultID, title: "Old", host: "old.example", password: "qwerty"))
        #expect(try await fixture.session.hygieneReport().items.count == 2)

        // A merge stores a new version, and a deletion arrives, without going through `save`.
        var merged = Fixture.login(vaultID, title: "Merged", host: "merged.example", password: "letmein")
        merged.version = 1
        let row = try await fixture.session.syncSealItem(merged)
        try await fixture.store.commit(
            StoreChange(upserts: [row], deletions: [RecordKey(recordID: deleted.id, kind: .item)]))

        let report = try await fixture.session.hygieneReport()
        #expect(Set(report.items.map(\.id)) == [kept.id, merged.id])
    }

    @Test("the ledger and the prefix cache are kept sealed across a relaunch: nothing is asked for twice")
    func persistedAcrossRelaunch() async throws {
        let (fixture, vaultID) = try await Self.unlocked()
        let item = try await fixture.session.save(
            Fixture.login(vaultID, title: "Forum", host: "forum.example", password: "password"))
        try await fixture.scanUntilIdle()
        let sent = await fixture.http.requests.count
        #expect(sent == 1)
        #expect(!(await fixture.local.contents).isEmpty)

        let relaunched = await fixture.relaunched()
        try await relaunched.session.unlock(password: TestVault.password)
        let report = try await relaunched.session.hygieneReport()
        #expect(report.item(item.id)?.findings.contains { $0.kind == .breachedPassword } == true)
        #expect(report.totals.itemsAwaitingBreachCheck == 0)
        #expect(try await relaunched.scanUntilIdle().isEmpty)
        #expect(await fixture.http.requests.count == sent)

        // The cached range is found under its sealed record, by prefix.
        let prefix = try #require(PwnedRangePrefix("5BAA6"))
        #expect(await relaunched.session.hygieneCachedRange(prefix)?.range.prefix == prefix)
        await relaunched.session.lock()
        #expect(await relaunched.session.hygieneCachedRange(prefix) == nil)
    }

    @Test("an evicted or removed range is gone from the device-local store, and an account deletion erases it all")
    func cacheBoundsAndErasure() async throws {
        let (fixture, vaultID) = try await Self.unlocked()
        for (index, password) in ["password", "123456", "hunter2", "qwerty", "letmein"].enumerated() {
            try await fixture.session.save(
                Fixture.login(vaultID, title: "Item \(index)", host: "site\(index).example", password: password))
        }
        try await fixture.scanUntilIdle()
        // Five ranges, an index and a ledger.
        #expect(await fixture.local.contents.count == 7)
        await fixture.session.hygieneCacheRemove(nil)
        #expect(await fixture.local.contents.count == 2)
        let accountID = try #require(await fixture.session.account?.accountID)
        #expect(await fixture.keychain.contains(.deviceLocalSecret(accountID: accountID)))
        try await fixture.session.deleteAccount(password: TestVault.password)
        #expect(await fixture.local.contents.isEmpty)
        #expect(await !fixture.keychain.contains(.deviceLocalSecret(accountID: accountID)))
    }

    /// The device secret (`KeychainItem.deviceLocalSecret`) is made at the first unlock and kept only in this device's
    /// Keychain. A store restored onto other hardware arrives without it, as here: its sealed records open as nothing,
    /// so everything is due again, and a new secret is made.
    @Test("without this device's Keychain secret, the sealed ledger and cache open as nothing")
    func deviceSecretIsInTheKeychain() async throws {
        let (fixture, vaultID) = try await Self.unlocked()
        let item = try await fixture.session.save(
            Fixture.login(vaultID, title: "Forum", host: "forum.example", password: "password"))
        try await fixture.scanUntilIdle()
        let accountID = try #require(await fixture.session.account?.accountID)
        let secretItem = KeychainItem.deviceLocalSecret(accountID: accountID)
        let secret = try #require(await fixture.keychain.raw(secretItem))
        #expect(secret.count == 32)

        // A relaunch with the same Keychain reads the same secret: nothing is due.
        await fixture.session.lock()
        try await fixture.session.unlock(password: TestVault.password)
        #expect(try await fixture.session.hygieneReport().totals.itemsAwaitingBreachCheck == 0)
        #expect(await fixture.keychain.raw(secretItem) == secret)

        await fixture.session.lock()
        await fixture.keychain.delete(secretItem)
        try await fixture.session.unlock(password: TestVault.password)
        let report = try await fixture.session.hygieneReport()
        #expect(report.totals.itemsAwaitingBreachCheck == 1)
        #expect(await fixture.session.hygieneCachedRange(try #require(PwnedRangePrefix("5BAA6"))) == nil)
        let renewed = try #require(await fixture.keychain.raw(secretItem))
        #expect(renewed.count == 32 && renewed != secret)
        try await fixture.scanUntilIdle()
        #expect(
            try await fixture.session.hygieneReport().item(item.id)?.findings.contains {
                $0.kind == .breachedPassword
            } == true)
    }

    @Test("hygiene calls on a session without hygiene settings say so; while locked they say locked")
    func notConfiguredAndLocked() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        await #expect(throws: VaultError.hygieneNotConfigured) { try await vault.session.hygieneReport() }
        let (fixture, _) = try await Self.unlocked()
        await fixture.session.lock()
        await #expect(throws: VaultError.locked) { try await fixture.session.hygieneReport() }
        await #expect(throws: VaultError.locked) { try await fixture.session.runHygieneStep() }
        await #expect(throws: VaultError.locked) { try await fixture.session.itemsUsingPassword("password") }
    }
}
