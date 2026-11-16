import Foundation
import Testing
import WatchwordTestSupport

@testable import WatchwordSync

/// A transport that fails every call with one error once `failing` is set, as CloudKit does when throttled or signed
/// out. Otherwise it is the store underneath.
actor FailingTransport: SyncTransport {
    let base: InMemorySyncTransport
    var failure: SyncTransportError?
    var failsCreatesOnly = false

    init(base: InMemorySyncTransport) {
        self.base = base
    }

    func fail(with error: SyncTransportError?, createsOnly: Bool = false) {
        failure = error
        failsCreatesOnly = createsOnly
    }

    func list(prefix: String) async throws -> [String] {
        if let failure, !failsCreatesOnly { throw failure }
        return await base.list(prefix: prefix)
    }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        if let failure, !failsCreatesOnly { throw failure }
        return try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws {
        if let failure { throw failure }
        try await base.create(name, contents: contents)
    }

    func delete(_ name: String) async throws {
        if let failure, !failsCreatesOnly { throw failure }
        await base.delete(name)
    }
}

/// The transport's typed failures (docs/02-architecture.md §7.2): each one that says the store cannot be used now stops
/// the sync where it stands, as being offline always has, and the report says which.
@Suite("Sync transport failures")
struct SyncTransportFailureTests {
    @Test(
        "throttling, a full store, a signed-out account and a reset store stop the sync like being offline",
        arguments: [
            SyncTransportError.unavailable, .rateLimited(retryAfter: 30), .rateLimited(retryAfter: nil),
            .notAuthenticated,
            .storeReset,
        ])
    func stopping(_ error: SyncTransportError) async throws {
        #expect(error.stopsSync)
        let shared = InMemorySyncTransport()
        let failing = FailingTransport(base: shared)
        let home = await Household.make(2, transport: shared)
        let keys = home.keys
        let a = home.devices[0]
        let b = SyncTestClient(deviceID: SyncFixtures.deviceB, vaultID: Household.vault, keys: keys, transport: failing)
        let item = try await a.save(Household.login())
        try await a.sync()

        // Downloaded while locked, then the store fails: what was downloaded is still merged, nothing is published.
        await b.keyring.lock()
        #expect(try await b.sync().fetched == 1)
        await b.keyring.unlock()
        await failing.fail(with: error)
        _ = try await b.save(Household.login(title: "Mine"))
        let report = try await b.sync()
        #expect(report.transportUnavailable)
        #expect(report.transportFailure == error)
        #expect(report.applied == 1)
        #expect(report.segmentsWritten == 0)
        #expect(try await b.item(item.id) == item)
        #expect(try await b.engine.download().transportFailure == error)
    }

    @Test("a full store stops the sync at the write; the earlier merge stands and the write waits")
    func quota() async throws {
        let shared = InMemorySyncTransport()
        let failing = FailingTransport(base: shared)
        let keys = await Household.make(1, transport: shared).keys
        let b = SyncTestClient(deviceID: SyncFixtures.deviceA, vaultID: Household.vault, keys: keys, transport: failing)
        _ = try await b.save(Household.login())
        await failing.fail(with: .quotaExceeded, createsOnly: true)
        let full = try await b.sync()
        #expect(full.transportFailure == .quotaExceeded)
        #expect(full.segmentsWritten == 0)
        #expect(await shared.allObjects.isEmpty)
        await failing.fail(with: nil)
        #expect(try await b.sync().segmentsWritten == 1)
    }

    @Test(
        "errors about one object refuse that object and do not stop the sync",
        arguments: [
            SyncTransportError.objectExists("n"), .forbidden("n"), .objectTooLarge("n"), .invalidName("n"),
            .conflictingVersions("n"),
        ])
    func perObject(_ error: SyncTransportError) {
        #expect(!error.stopsSync)
        #expect(error.retryAfter == nil)
        #expect(SyncEngine.isFatal(error) == false)
    }

    @Test("only throttling carries a wait")
    func retryAfter() {
        #expect(SyncTransportError.rateLimited(retryAfter: 12).retryAfter == 12)
        #expect(SyncTransportError.rateLimited(retryAfter: nil).retryAfter == nil)
        #expect(SyncTransportError.notAuthenticated.retryAfter == nil)
    }
}
