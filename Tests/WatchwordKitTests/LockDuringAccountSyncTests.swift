import Foundation
import SecureMemory
import Testing
import WatchwordCrypto
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
    private var skipping = 0
    private(set) var locks = 0

    /// `skipping` such reads go by first: the lock lands in the one after them.
    func lock(_ session: VaultSession, onNextUnlockedRead kind: EnvelopeKind, skipping: Int = 0) {
        target = (session, kind)
        self.skipping = skipping
    }

    private func gate(_ kind: EnvelopeKind) async {
        guard let target, target.kind == kind, (try? await target.session.state()) == .unlocked else { return }
        guard skipping == 0 else {
            skipping -= 1
            return
        }
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

    /// A session's lock, callable from a Keychain hook: once, and only while the session is unlocked.
    actor LockOnce {
        private(set) var locks = 0

        func lock(_ session: VaultSession) async {
            guard locks == 0, (try? await session.state()) == .unlocked else { return }
            locks += 1
            await session.lock()
        }

        /// For a lock that lands before the unlock has installed anything.
        func lockWhateverTheState(_ session: VaultSession) async {
            guard locks == 0 else { return }
            locks += 1
            await session.lock()
        }
    }

    /// Review finding Z4. A password unlock installs its keys and then waits on the Keychain (the quick-unlock
    /// state) before it copies the account's signing key there: an auto-lock in that wait zeroised the keyset the
    /// copy then read.
    @Test("a lock while a password unlock waits on the Keychain leaves the session locked, not crashed")
    func lockWhileUnlockWaitsOnTheKeychain() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)
        await vault.session.lock()

        let once = LockOnce()
        let session = vault.session
        await vault.keychain.onRead { item in
            if case .quickUnlockState = item { await once.lock(session) }
        }
        try await vault.session.unlock(password: TestVault.password)
        #expect(await once.locks == 1)
        #expect(try await vault.session.state() == .locked)

        await vault.keychain.onRead(nil)
        try await vault.session.unlock(password: TestVault.password)
        try await vault.session.save(login(personal, title: "After the race"))
        let accountID = try #require(await session.account).accountID
        #expect(await vault.keychain.contains(.accountSigningKey(accountID: accountID)))
    }

    /// Review finding Z4, the quick-unlock side: a lock while the quick-unlock state is being written. The lock wins
    /// (`lockedDuringUnlock`), and no key is read after it.
    @Test("a lock while a quick unlock writes its state leaves the session locked, not crashed")
    func lockWhileQuickUnlockWritesItsState() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        try await vault.session.enableQuickUnlock(password: TestVault.password)
        await vault.session.lock()

        // The prompt has been answered and the key released; the lock lands in a write of the state after that.
        let session = vault.session
        let keychain = vault.keychain
        let landed = LockOnce()
        await keychain.onStore { item in
            guard case .quickUnlockState = item, await keychain.biometricPrompts == 1 else { return }
            await landed.lockWhateverTheState(session)
        }
        await #expect(throws: VaultError.lockedDuringUnlock) { try await vault.session.quickUnlock() }
        #expect(await landed.locks == 1)
        #expect(try await vault.session.state() == .locked)
        await keychain.onStore(nil)
        try await vault.session.quickUnlock()
        #expect(try await vault.session.state() == .unlocked)
    }

    /// Review finding Z4. A vault key that arrives by grant is wrapped under the keyset after two reads of the store:
    /// a lock during the second left the wrap reading a zeroised keyset.
    @Test("a lock while a granted vault key is being stored fails that cleanly, and the key is stored the next time")
    func lockWhileAdoptingAVaultKey() async throws {
        let store = LockingRecordStore()
        let vault = TestVault(store: store)
        try await vault.createAccount()
        let account = try #require(await vault.session.account)
        var generator = SeededGenerator(seed: 31)
        let vaultID = UUID(uuidString: "5A000000-0000-4000-8000-0000000000AA")!
        let granted = VaultKey(
            vaultID: vaultID, key: EncryptionKey.generate(using: &generator), arrivedByGrant: true)
        let again = VaultKey(
            vaultID: vaultID,
            key: try EncryptionKey(
                keyID: granted.key.keyID, material: SecureBytes(copying: granted.key.material.unprotectedCopy())),
            arrivedByGrant: true)

        // The first read of a wrap row is the check that the key's ID is free; the lock lands in the second.
        await store.lock(vault.session, onNextUnlockedRead: .vaultKeyWrap, skipping: 1)
        let epoch = await vault.session.lockEpoch
        await #expect(throws: VaultError.locked) {
            try await vault.session.adoptVaultKey(granted, owner: account.accountID, account: account, epoch: epoch)
        }
        #expect(await store.locks == 1)
        #expect(try await vault.session.state() == .locked)
        #expect(try await store.record(RecordKey(recordID: granted.key.keyID, kind: .vaultKeyWrap)) == nil)

        try await vault.session.unlock(password: TestVault.password)
        try await vault.session.adoptVaultKey(
            again, owner: account.accountID, account: account, epoch: await vault.session.lockEpoch)
        #expect(try await store.record(RecordKey(recordID: granted.key.keyID, kind: .vaultKeyWrap))?.vaultID == vaultID)
    }
}
