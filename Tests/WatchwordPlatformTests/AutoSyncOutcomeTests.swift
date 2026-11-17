import Foundation
import Testing
import WatchwordKit
import WatchwordPlatform
import WatchwordSync
import WatchwordTestSupport

/// A transport that, once `throttling` is set, refuses every listing of a vault's log with `rateLimited`, as CloudKit
/// does per request, and counts those listings. The account's own objects still pass.
actor ThrottlingTransport: SyncTransport {
    let base = InMemorySyncTransport()
    var throttling: TimeInterval?
    private(set) var vaultListings = 0

    func throttle(retryAfter: TimeInterval?) {
        throttling = retryAfter
    }

    func list(prefix: String) async throws -> [String] {
        if prefix.hasPrefix("vault/"), let throttling {
            vaultListings += 1
            throw SyncTransportError.rateLimited(retryAfter: throttling)
        }
        return await base.list(prefix: prefix)
    }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws {
        try await base.create(name, contents: contents)
    }

    func delete(_ name: String) async throws {
        await base.delete(name)
    }
}

/// How a sync ended, as the driver tells the policy (docs/02-architecture.md §7.9): from every part of the account's
/// report, not only from the account's own objects (review of the adapters, finding 1).
@Suite("Automatic sync outcome")
struct AutoSyncOutcomeTests {
    @Test("a vault's log throttled is a throttled sync, and the other vaults do not ask the transport again")
    func throttledVault() async throws {
        let transport = ThrottlingTransport()
        let vault = TestVault.syncing(over: transport)
        try await vault.createAccount()
        _ = try await vault.session.createVault(name: "Second")
        _ = try await vault.session.createVault(name: "Third")
        try await vault.session.syncAll()
        await transport.throttle(retryAfter: 90)

        let report = try await vault.session.syncAll()
        #expect(AutoSyncOutcome(report) == .throttled(retryAfter: 90))
        #expect(await transport.vaultListings == 1)
        #expect(report.vaults.count == 3)
        #expect(report.vaults.values.allSatisfy { $0.transportFailure == .rateLimited(retryAfter: 90) })
    }

    @Test("throttling in a shared vault's pass counts, and the longest wait asked wins")
    func sharingAndLongestWait() {
        var report = AccountSyncReport()
        var shared = SharedVaultSyncReport()
        shared.transportFailure = .rateLimited(retryAfter: 30)
        report.sharing[UUID()] = shared
        #expect(AutoSyncOutcome(report) == .throttled(retryAfter: 30))
        var vaultReport = SyncReport()
        vaultReport.noteTransportFailure(.rateLimited(retryAfter: 120))
        report.vaults[UUID()] = vaultReport
        #expect(AutoSyncOutcome(report) == .throttled(retryAfter: 120))
    }

    @Test("a vault offline is a failure; nothing failing is a success")
    func failedVault() {
        var report = AccountSyncReport()
        report.vaults[UUID()] = SyncReport()
        #expect(AutoSyncOutcome(report) == .succeeded)
        var offline = SyncReport()
        offline.noteTransportFailure(.unavailable)
        report.vaults[UUID()] = offline
        #expect(AutoSyncOutcome(report) == .failed)
    }

    /// Automatic syncing reaches `syncAll` and nothing else (docs/02-architecture.md §7.9, §7.10). After a reset,
    /// whether the transport says so or the store merely lists nothing, every automatic sync is a failure the policy
    /// backs off from; however many it starts, nothing is uploaded and the store is not started again.
    @Test(
        "a reset store is a failed sync that backs off; no number of automatic syncs uploads again",
        arguments: [true, false])
    func resetStore(_ transportSaysSo: Bool) async throws {
        let store = ResettableSyncTransport()
        let vault = TestVault.syncing(over: store)
        try await vault.createAccount()
        _ = try await vault.session.createVault(name: "Second")
        try await vault.session.syncAll()
        if transportSaysSo { await store.reset() } else { await store.base.removeEverything() }
        await store.forgetCreates()

        var state = AutoSyncState()
        var now = Date(timeIntervalSince1970: 1_800_000_000)
        AutoSyncPolicy.record(.unlocked, at: now, in: &state)
        var started = 0
        for _ in 0..<200 {
            guard case .sync(let mode, _) = AutoSyncPolicy.decide(now: now, state: state) else {
                now.addTimeInterval(60)
                continue
            }
            AutoSyncPolicy.record(.syncStarted, at: now, in: &state)
            started += 1
            // What the driver's closure does for either mode: one `syncAll`.
            #expect(mode == .full)
            let report = try await vault.session.syncAll()
            #expect(AutoSyncOutcome(report) == .failed && report.storeNeedsReupload)
            AutoSyncPolicy.record(.syncFailed, at: now, in: &state)
        }
        #expect(started >= 3 && state.consecutiveFailures == started)
        #expect(await store.created.isEmpty)
        #expect(await store.startsAgain == 0)
    }
}
