import Foundation
import WatchwordSync

/// A store that can be reset the way a CloudKit zone is (docs/02-architecture.md §7.2, §7.10): after `reset()` it
/// holds nothing and every operation is `SyncTransportError.storeReset`, until some device calls `startStoreAgain`,
/// the one call that recreates it. It also records every create and every start, so a test can say that nothing
/// was uploaded unasked. (`InMemorySyncTransport.removeEverything` alone is the other kind of reset: a folder that
/// was emptied, which no transport reports.)
public actor ResettableSyncTransport: SyncTransport {
    public let base: InMemorySyncTransport
    public private(set) var isReset = false
    /// Calls to `startStoreAgain`, whether or not the store was reset at the time.
    public private(set) var startsAgain = 0
    /// Names created since the last `forgetCreates()`, in order.
    public private(set) var created: [String] = []
    private var startingAgain: (@Sendable () async -> Void)?
    private var refusedPrefix: String?

    public init(base: InMemorySyncTransport = InMemorySyncTransport()) {
        self.base = base
    }

    /// The person's "delete data", or the service discarding the store: everything goes, and the store says so.
    public func reset() async {
        await base.removeEverything()
        isReset = true
    }

    /// The store says it was reset and still holds everything: what A1 can claim at will.
    public func pretendReset() {
        isReset = true
    }

    public func forgetCreates() {
        created = []
    }

    /// Runs `hook` inside the next `startStoreAgain`, before it returns: a lock, say, that lands while the store
    /// is being started.
    public func whenStartingAgain(_ hook: @escaping @Sendable () async -> Void) {
        startingAgain = hook
    }

    /// From now on every create under `prefix` fails as `unavailable`, as a connection lost part-way through an
    /// upload; `nil` lets them through again.
    public func refuseCreates(under prefix: String?) {
        refusedPrefix = prefix
    }

    /// Every object the store holds.
    public func objects() async -> [String: [UInt8]] {
        await base.allObjects
    }

    private func check() throws {
        if isReset { throw SyncTransportError.storeReset }
    }

    public func list(prefix: String) async throws -> [String] {
        try check()
        return await base.list(prefix: prefix)
    }

    public func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        try check()
        return try await base.fetch(name, maximumLength: maximumLength)
    }

    public func create(_ name: String, contents: [UInt8]) async throws {
        try check()
        if let refusedPrefix, name.hasPrefix(refusedPrefix) { throw SyncTransportError.unavailable }
        try await base.create(name, contents: contents)
        created.append(name)
    }

    public func delete(_ name: String) async throws {
        try check()
        await base.delete(name)
    }

    public func listWithCopies(prefix: String) async throws -> SyncListing {
        try check()
        return try await base.listWithCopies(prefix: prefix)
    }

    public func fetchCopies(_ name: String, maximumLength: Int, maximumCopies: Int) async throws -> SyncObjectCopies {
        try check()
        return try await base.fetchCopies(name, maximumLength: maximumLength, maximumCopies: maximumCopies)
    }

    public func startStoreAgain() async throws {
        startsAgain += 1
        isReset = false
        if let hook = startingAgain {
            startingAgain = nil
            await hook()
        }
    }
}
