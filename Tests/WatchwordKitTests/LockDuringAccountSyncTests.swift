import Foundation
import Testing
import WatchwordEnvelope
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// A transport that locks a session from inside the fetch of the first object whose name contains `fragment`: an
/// auto-lock, or the person's lock button, landing while a sync is waiting on the network.
actor LockingTransport: SyncTransport {
    let base: any SyncTransport
    private var target: (session: VaultSession, fragment: String)?
    private(set) var locks = 0

    init(base: any SyncTransport) {
        self.base = base
    }

    func lock(_ session: VaultSession, whileFetching fragment: String) {
        target = (session, fragment)
    }

    func list(prefix: String) async throws -> [String] {
        try await base.list(prefix: prefix)
    }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        if let target, name.contains(target.fragment) {
            self.target = nil
            locks += 1
            await target.session.lock()
        }
        return try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws {
        try await base.create(name, contents: contents)
    }

    func delete(_ name: String) async throws {
        try await base.delete(name)
    }
}

/// A store that locks a session from inside its first read of a record of `kind` made while that session is
/// unlocked: the vault locking again while an unlock is still finishing.
actor LockingRecordStore: RecordStore {
    let base = InMemoryRecordStore()
    private var target: (session: VaultSession, kind: EnvelopeKind)?
    private(set) var locks = 0

    func lock(_ session: VaultSession, onNextUnlockedRead kind: EnvelopeKind) {
        target = (session, kind)
    }

    private func gate(_ kind: EnvelopeKind) async {
        guard let target, target.kind == kind, (try? await target.session.state()) == .unlocked else { return }
        self.target = nil
        locks += 1
        await target.session.lock()
    }

    func loadAccount() async throws -> AccountRecord? { try await base.loadAccount() }

    func record(_ key: RecordKey) async throws -> StoredRecord? {
        await gate(key.kind)
        return try await base.record(key)
    }

    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        await gate(kind)
        return try await base.records(in: vaultID, kind: kind)
    }

    func commit(_ change: StoreChange) async throws { try await base.commit(change) }
    func eraseAll() async throws { await base.eraseAll() }
}

/// `lock()` always wins (docs/02-architecture.md §7.6, the `VaultSession` invariants): the account's own half of a
/// sync and the reconciliation after an unlock re-check the lock epoch after every suspension, so a lock landing in
/// one of them never has key material read after it was zeroised (which traps, on purpose).
@Suite("Vault session: a lock during the account's objects")
struct LockDuringAccountSyncTests {
    @Test("a lock while a vault key is being fetched stops the sync, and the next unlocked sync takes the key")
    func lockWhileFetchingVaultKey() async throws {
        let transport = InMemorySyncTransport()
        let a = TestVault.syncing(over: transport)
        try await a.createAccount()
        let hook = LockingTransport(base: transport)
        let b = try await a.enrolledDevice(deviceID: Fleet.deviceID(1), over: hook)
        try await b.session.unlock(password: TestVault.password)
        let work = try await a.session.createVault(name: "Work")
        try await a.session.sync()

        await hook.lock(b.session, whileFetching: "/key/")
        let report = try await b.session.syncAll()
        #expect(await hook.locks == 1)
        #expect(try await b.session.state() == .locked)
        #expect(report.vaults.values.allSatisfy { $0.deferredUntilUnlock }, "the rest of the sync was a download")

        try await b.session.unlock(password: TestVault.password)
        try await b.session.sync()
        #expect(try await b.session.vaults().map(\.id).contains(work.id))
    }

    @Test("a lock while an unlock reconciles the account's objects leaves the session locked, not crashed")
    func lockWhileReconciling() async throws {
        let store = LockingRecordStore()
        let vault = TestVault(store: store)
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)
        await vault.session.lock()

        await store.lock(vault.session, onNextUnlockedRead: .accountHeader)
        try await vault.session.unlock(password: TestVault.password)
        #expect(await store.locks == 1)
        #expect(try await vault.session.state() == .locked)

        try await vault.session.unlock(password: TestVault.password)
        try await vault.session.save(login(personal, title: "After the race"))
        #expect(try await vault.session.deviceStanding() == .active)
    }
}
