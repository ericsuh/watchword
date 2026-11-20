import Foundation
import Testing
import WatchwordAutoFill
import WatchwordEnvelope
import WatchwordMatching
import WatchwordModel
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// A record store that, once armed, runs `hook` after reading the row it is armed for and before returning it: a
/// write that lands between another write's read and its commit, without sleeping.
actor InterleavingRecordStore: RecordStore {
    let base = InMemoryRecordStore()
    private var armed: (key: RecordKey, hook: @Sendable () async -> Void)?

    func arm(_ key: RecordKey, _ hook: @escaping @Sendable () async -> Void) {
        armed = (key, hook)
    }

    func loadAccount() async throws -> AccountRecord? { await base.loadAccount() }

    func record(_ key: RecordKey) async throws -> StoredRecord? {
        let row = await base.record(key)
        if let armed, armed.key == key {
            self.armed = nil
            await armed.hook()
        }
        return row
    }

    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        await base.records(in: vaultID, kind: kind)
    }

    func commit(_ change: StoreChange) async throws { try await base.commit(change) }
    func eraseAll() async throws { await base.eraseAll() }
}

/// A `CredentialVault` that locks the session right after the items are read: the lock lands between the model's
/// read and its release.
struct LockingAfterRead: CredentialVault {
    let session: VaultSession

    func credentialSnapshot() async throws -> CredentialSnapshot {
        let snapshot = try await session.credentialSnapshot()
        await session.lock()
        return snapshot
    }

    func confirmUnlocked() async throws { try await session.confirmUnlocked() }
    func isBackedUp() async throws -> Bool { try await session.isBackedUp() }
    func saveCredentialItem(
        _ item: Item, replacingVersion: UInt64?, confirmingHosts: Set<String>
    ) async throws -> Item {
        try await session.saveCredentialItem(
            item, replacingVersion: replacingVersion, confirmingHosts: confirmingHosts)
    }
}

func libraryLogin(_ vaultID: UUID, password: String = "library-password") -> Item {
    Item(
        vaultID: vaultID, title: "Library", scopes: [ServiceScope(host: "library.example.org")],
        fields: [
            Field(kind: .username, label: "Username", value: "pat"),
            Field(kind: .password, label: "Password", value: password),
        ])
}

/// `VaultSession`'s conformance to `CredentialVault` (docs/02-architecture.md §9.2, docs/03 milestone 5).
@Suite("Vault session as the AutoFill vault")
struct CredentialVaultTests {
    static let page = ServiceIdentifier("https://library.example.org/login", kind: .url)

    static func model(_ vault: any CredentialVault, clock: FakeClock) -> CredentialProviderModel {
        CredentialProviderModel(vault: vault, clock: clock, random: SeededGenerator(seed: 5))
    }

    @Test("a save is a compare-and-swap on the version read: absent for a new item, the stored version otherwise")
    func compareAndSwap() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        let vaultID = try await vault.session.defaultVaultID()
        let created = try await vault.session.saveCredentialItem(libraryLogin(vaultID), replacingVersion: nil)
        await #expect(throws: CredentialVaultError.versionConflict(created.id)) {
            try await vault.session.saveCredentialItem(created, replacingVersion: nil)
        }
        var edited = created
        edited.fields[1].value = "new-password"
        let saved = try await vault.session.saveCredentialItem(edited, replacingVersion: created.version)
        #expect(saved.version > created.version)
        #expect(saved.history.first?.fields == created.fields)
        // A second write prepared against the first version: the store has moved on.
        var stale = created
        stale.fields[1].value = "stale-password"
        await #expect(throws: CredentialVaultError.versionConflict(created.id)) {
            try await vault.session.saveCredentialItem(stale, replacingVersion: created.version)
        }
        // Replacing an item that is not there is a conflict too, not a creation.
        await #expect(throws: CredentialVaultError.versionConflict(UUID(0))) {
            var missing = libraryLogin(vaultID)
            missing.id = UUID(0)
            try await vault.session.saveCredentialItem(missing, replacingVersion: 1)
        }
        #expect(try await vault.session.item(id: created.id) == saved)
    }

    @Test("a save that lands between the session's read and its commit wins, and the AutoFill write is refused")
    func concurrentSaveBetweenReadAndWrite() async throws {
        let store = InterleavingRecordStore()
        let vault = TestVault(store: store)
        try await vault.createAccount()
        let vaultID = try await vault.session.defaultVaultID()
        let created = try await vault.session.saveCredentialItem(libraryLogin(vaultID), replacingVersion: nil)
        let session = vault.session
        // The app saves an edit while the extension's write is between its read of the row and its commit.
        await store.arm(RecordKey(recordID: created.id, kind: .item)) {
            var inApp = created
            inApp.title = "City Library"
            _ = try? await session.save(inApp)
        }
        var fromExtension = created
        fromExtension.fields[1].value = "extension-password"
        await #expect(throws: CredentialVaultError.versionConflict(created.id)) {
            try await session.saveCredentialItem(fromExtension, replacingVersion: created.version)
        }
        let stored = try await session.item(id: created.id)
        #expect(stored.title == "City Library")
        #expect(stored.field(.password)?.value == "library-password")
    }

    @Test("a lock between the model's read and its release wins: nothing is handed back")
    func lockBetweenReadAndRelease() async throws {
        let clock = FakeClock()
        let vault = TestVault(clock: clock)
        try await vault.createAccount()
        let saved = try await vault.session.save(libraryLogin(try await vault.session.defaultVaultID()))
        let choice = PasswordChoice(itemID: saved.id, userName: "pat")
        #expect(
            try await Self.model(vault.session, clock: clock).password(for: choice, identifiers: [Self.page]).value
                .password == "library-password")

        let model = Self.model(LockingAfterRead(session: vault.session), clock: clock)
        #expect(await model.password(for: choice, identifiers: [Self.page]) == .vaultLocked)
        // And directly: the actor's own check, after a lock, is `locked`.
        try await vault.session.unlock(password: TestVault.password)
        _ = try await vault.session.credentialItems()
        await vault.session.lock()
        await #expect(throws: CredentialVaultError.locked) { try await vault.session.confirmUnlocked() }
        await #expect(throws: CredentialVaultError.locked) { try await vault.session.credentialItems() }
        await #expect(throws: CredentialVaultError.locked) { try await vault.session.isBackedUp() }
        await #expect(throws: CredentialVaultError.locked) { try await vault.session.defaultVaultID() }
    }

    @Test("every vault's items are listed, each ID once; a move leaves the copy fillable and the original not")
    func itemIDsAcrossVaults() async throws {
        let clock = FakeClock()
        let vault = TestVault(clock: clock)
        try await vault.createAccount()
        let personal = try await vault.session.defaultVaultID()
        let family = try await vault.session.createVault(name: "Family").id
        let saved = try await vault.session.save(libraryLogin(personal))
        try await vault.session.save(
            Item(vaultID: family, title: "Shop", scopes: [ServiceScope(host: "shop.example")], fields: []),
            // The reserved `.example` suffix is also the Library item's name, which a real suffix never is.
            confirmingHosts: ["shop.example"])

        let moved = try await vault.session.move(itemID: saved.id, to: family)
        #expect(moved.id != saved.id)
        let items = try await vault.session.credentialItems()
        #expect(Set(items.map(\.id)).count == items.count, "an item ID occurs once across every vault")
        #expect(items.contains { $0.vaultID == family && $0.id == moved.id })
        #expect(!items.contains { $0.id == saved.id && !$0.isTrashed }, "the original is gone or in the trash")

        let model = Self.model(vault.session, clock: clock)
        guard case .list(let list) = await model.credentialList(for: [Self.page]) else {
            Issue.record("no list")
            return
        }
        #expect(list.passwords.map(\.itemID) == [moved.id])
        #expect(
            try await model.password(
                for: PasswordChoice(itemID: moved.id, userName: "pat"), identifiers: [Self.page]
            ).value.password == "library-password")
        let original = await model.password(
            for: PasswordChoice(itemID: saved.id, userName: "pat"), identifiers: [Self.page])
        #expect((try? original.value) == nil, "the original's ID releases nothing")
    }

    @Test("BS is true to the facts: backed up only when the session syncs")
    func backedUp() async throws {
        let local = TestVault()
        try await local.createAccount()
        #expect(try await local.session.isBackedUp() == false)
        let syncing = TestVault.syncing(over: InMemorySyncTransport())
        try await syncing.createAccount()
        #expect(try await syncing.session.isBackedUp() == true)
    }

    /// The extension's unlock: a session over the same store and Keychain, unlocked by the Local Unlock Key the
    /// Keychain releases, never by a flag. A refused quick unlock leaves the model locked and deletes the key.
    @Test("the extension process unlocks through quick unlock only, and a refusal releases nothing")
    func extensionUnlock() async throws {
        let clock = FakeClock()
        let app = TestVault(clock: clock)
        try await app.createAccount()
        let saved = try await app.session.save(libraryLogin(try await app.session.defaultVaultID()))
        try await app.session.enableQuickUnlock(password: TestVault.password)

        let extensionProcess = app.relaunched()
        let model = Self.model(extensionProcess.session, clock: clock)
        let choice = PasswordChoice(itemID: saved.id, userName: "pat")
        #expect(await model.password(for: choice, identifiers: [Self.page]) == .vaultLocked)
        try await extensionProcess.session.quickUnlock(prompt: "Fill your library password")
        #expect(
            try await model.password(for: choice, identifiers: [Self.page]).value.password == "library-password")

        // Biometric enrolment changed: the key is destroyed, and the model stays locked.
        await extensionProcess.session.lock()
        await app.biometrics.set(.enrolled(domainState: [0x09]))
        await #expect(throws: VaultError.quickUnlockRefused(.enrolmentChanged)) {
            try await extensionProcess.session.quickUnlock()
        }
        let accountID = try #require(try await app.session.status().accountID)
        #expect(await app.keychain.contains(.quickUnlockKey(accountID: accountID)) == false)
        #expect(await model.password(for: choice, identifiers: [Self.page]) == .vaultLocked)
    }
}

extension UUID {
    fileprivate init(_ small: UInt8) {
        self.init(uuid: (0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, small))
    }
}
