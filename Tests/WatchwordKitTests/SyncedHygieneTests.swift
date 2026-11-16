import Foundation
import Testing
import WatchwordEnvelope
import WatchwordHygiene
import WatchwordModel
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// Breach-check results synced with the vault (owner decision 10; ADR 0005, amendment of 2026-11-16;
/// docs/02-architecture.md §13.9), through two real sessions of one account over one transport.
@Suite("Vault session: synced hygiene")
struct SyncedHygieneTests {
    static let deviceB = UUID(uuidString: "B0000000-0000-0000-0000-00000000000B")!

    struct Pair {
        let a: TestVault
        let b: TestVault
        let httpA: FakeHTTPClient
        let httpB: FakeHTTPClient
        let vaultID: UUID

        static func make(breached: [String: UInt32] = ["hunter2": 17_043]) async throws -> Pair {
            let transport = InMemorySyncTransport()
            let (settingsA, httpA) = await HygieneSessionFixture.settings(breached: breached)
            let (settingsB, httpB) = await HygieneSessionFixture.settings(breached: breached)
            let a = TestVault.syncing(over: transport, hygiene: settingsA)
            try await a.createAccount()
            let b = try await a.enrolledDevice(deviceID: deviceB, over: transport, hygiene: settingsB)
            try await b.session.unlock(password: TestVault.password)
            let vaultID = try #require(await a.session.personalVaultID)
            return Pair(a: a, b: b, httpA: httpA, httpB: httpB, vaultID: vaultID)
        }

        func exchange() async throws {
            try await a.session.sync()
            try await b.session.sync()
            try await a.session.sync()
        }

        func scan(_ vault: TestVault) async throws -> [ScanOutcome] {
            try await HygieneSessionFixture.scanUntilIdle(vault.session, clock: vault.clock)
        }
    }

    @Test("device B does not repeat a check device A made and synced, and shows A's result as A's")
    func bSkipsWhatASynced() async throws {
        let pair = try await Pair.make()
        let item = try await pair.a.session.save(
            HygieneSessionFixture.login(pair.vaultID, title: "Bank", host: "bank.example", password: "Zr8@Wn4&x7#Vq9!"))
        #expect(try await pair.scan(pair.a) == [.scanned(breachedPasswords: 0, networkRequests: 1)])
        try await pair.exchange()

        #expect(try await pair.scan(pair.b).isEmpty)
        #expect(await pair.httpB.requests.isEmpty)
        let entry = try #require(try await pair.b.session.hygieneReport().item(item.id))
        guard case .clear = entry.breachStatus else {
            Issue.record("expected clear, got \(entry.breachStatus)")
            return
        }
        #expect(entry.breachSource == .anotherDevice)
    }

    @Test("a breach A found is shown on B, attributed to sync, without B asking")
    func aBreachReachesB() async throws {
        let pair = try await Pair.make()
        let item = try await pair.a.session.save(
            HygieneSessionFixture.login(pair.vaultID, title: "Forum", host: "forum.example", password: "hunter2"))
        #expect(try await pair.scan(pair.a) == [.scanned(breachedPasswords: 1, networkRequests: 1)])
        try await pair.exchange()
        #expect(try await pair.scan(pair.b).isEmpty)
        let entry = try #require(try await pair.b.session.hygieneReport().item(item.id))
        guard case .breached = entry.breachStatus else {
            Issue.record("expected breached, got \(entry.breachStatus)")
            return
        }
        #expect(entry.breachSource == .anotherDevice)
        #expect(entry.findings.first?.detail == .breached(occurrences: 17_043))
    }

    @Test("a password changed after A's check is checked again on B: no earlier result covers it")
    func changedPasswordIsRechecked() async throws {
        let pair = try await Pair.make()
        var item = try await pair.a.session.save(
            HygieneSessionFixture.login(pair.vaultID, title: "Mail", host: "mail.example", password: "Zr8@Wn4&x7#Vq9!"))
        _ = try await pair.scan(pair.a)
        try await pair.exchange()
        #expect(try await pair.scan(pair.b).isEmpty)

        item = try await pair.b.session.item(id: item.id)
        item.fields[1].value = "hunter2"
        item = try await pair.b.session.save(item)
        #expect(try await pair.scan(pair.b) == [.scanned(breachedPasswords: 1, networkRequests: 1)])
        // And A, which checked the old password, takes B's result for the new one.
        try await pair.exchange()
        #expect(try await pair.scan(pair.a).isEmpty)
        let entry = try #require(try await pair.a.session.hygieneReport().item(item.id))
        guard case .breached = entry.breachStatus else {
            Issue.record("expected breached, got \(entry.breachStatus)")
            return
        }
    }

    @Test("checks and their sync never add an item version or a history entry, on either device")
    func noItemHistory() async throws {
        let pair = try await Pair.make()
        let saved = try await pair.a.session.save(
            HygieneSessionFixture.login(pair.vaultID, title: "Shop", host: "shop.example", password: "Zr8@Wn4&x7#Vq9!"))
        _ = try await pair.scan(pair.a)
        try await pair.exchange()
        _ = try await pair.scan(pair.b)
        try await pair.exchange()
        // A week on, both run the weekly pass; whoever goes first, nothing touches the item.
        await pair.a.clock.advance(by: 8 * 24 * 60 * 60)
        _ = try await pair.scan(pair.a)
        try await pair.exchange()
        _ = try await pair.scan(pair.b)
        try await pair.exchange()
        for vault in [pair.a, pair.b] {
            let item = try await vault.session.item(id: saved.id)
            #expect(item.version == saved.version)
            #expect(item.history.isEmpty)
            #expect(!item.hasConflicts)
        }
        // The results themselves are their own record, beside the item.
        let row = try #require(try await pair.b.store.record(RecordKey(recordID: saved.id, kind: .scanStatus)))
        #expect(row.vaultID == pair.vaultID)
    }

    @Test("deleting an item deletes its synced results too, on every device")
    func deletionTakesResults() async throws {
        let pair = try await Pair.make()
        let item = try await pair.a.session.save(
            HygieneSessionFixture.login(pair.vaultID, title: "Old", host: "old.example", password: "Zr8@Wn4&x7#Vq9!"))
        _ = try await pair.scan(pair.a)
        try await pair.exchange()
        let key = RecordKey(recordID: item.id, kind: .scanStatus)
        #expect(try await pair.b.store.record(key) != nil)
        try await pair.a.session.trash(id: item.id)
        try await pair.a.session.deletePermanently(id: item.id)
        #expect(try await pair.a.store.record(key) == nil)
        try await pair.exchange()
        #expect(try await pair.b.store.record(key) == nil)
    }
}
