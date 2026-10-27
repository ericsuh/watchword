import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// Two devices of one account, each a real `VaultSession` (AES-GCM records and segments, Ed25519 signatures) over
/// a shared in-memory transport: milestone 3's Mac half, end to end (docs/04-test-plan.md §2, §3.3).
struct SyncPair {
    static let deviceB = UUID(uuidString: "D0000000-0000-4000-8000-0000000000B0")!

    let transport: InMemorySyncTransport
    let a: TestVault
    let b: TestVault
    let vaultID: UUID

    /// A with an account, unlocked; B enrolled from it, unlocked. Nothing synced yet.
    static func make() async throws -> SyncPair {
        let transport = InMemorySyncTransport()
        let a = TestVault.syncing(over: transport)
        try await a.createAccount()
        let b = try await a.enrolledDevice(deviceID: deviceB, over: transport)
        try await b.session.unlock(password: TestVault.password)
        let vaultID = try #require(await a.session.personalVaultID)
        return SyncPair(transport: transport, a: a, b: b, vaultID: vaultID)
    }

    /// A, then B, then A again: enough for each to see everything the other published.
    func exchange() async throws {
        try await a.session.sync()
        try await b.session.sync()
        try await a.session.sync()
    }
}

@Suite("Vault session: sync between devices")
struct VaultSyncTests {
    @Test("items saved on one device reach the other, and edits come back")
    func roundTrip() async throws {
        let pair = try await SyncPair.make()
        let item = try await pair.a.session.save(login(pair.vaultID, title: "Library"))
        try await pair.exchange()
        #expect(try await pair.b.session.item(id: item.id).title == "Library")

        var edited = try await pair.b.session.item(id: item.id)
        edited.title = "City Library"
        try await pair.b.session.save(edited)
        try await pair.b.session.sync()
        try await pair.a.session.sync()
        let seen = try await pair.a.session.item(id: item.id)
        #expect(seen.title == "City Library")
        #expect(!seen.hasConflicts)
    }

    @Test("nothing a person typed reaches the transport (PRD F7.3)")
    func ciphertextOnly() async throws {
        let pair = try await SyncPair.make()
        try await pair.a.session.save(
            login(pair.vaultID, title: "Quarterly taxes", host: "irs.example", password: "hunter2-but-longer"))
        try await pair.exchange()
        let objects = await pair.transport.allObjects
        #expect(!objects.isEmpty)
        for needle in ["Quarterly taxes", "irs.example", "hunter2-but-longer", "someone@example.com"] {
            let bytes = Array(needle.utf8)
            for (name, contents) in objects {
                #expect(!name.contains(needle))
                #expect(!contents.contains(subsequence: bytes), "\(needle) in \(name)")
            }
        }
    }

    @Test("concurrent edits of one field keep both values on both devices, and the person's choice settles it")
    func conflictAndResolve() async throws {
        let pair = try await SyncPair.make()
        let item = try await pair.a.session.save(login(pair.vaultID, title: "Library"))
        try await pair.exchange()

        var onA = try await pair.a.session.item(id: item.id)
        onA.title = "Public Library"
        try await pair.a.session.save(onA)
        var onB = try await pair.b.session.item(id: item.id)
        onB.title = "City Library"
        try await pair.b.session.save(onB)
        try await pair.exchange()
        try await pair.b.session.sync()

        let a = try await pair.a.session.item(id: item.id)
        let b = try await pair.b.session.item(id: item.id)
        #expect(a.hasConflicts && b.hasConflicts)
        #expect(a.title == b.title, "both devices show the same value")
        let held = Set(
            [a.title]
                + (a.conflicts[.title] ?? []).compactMap { conflict -> String? in
                    if case .title(let title) = conflict.value { return title }
                    return nil
                })
        #expect(held == ["Public Library", "City Library"])

        let other = try #require(a.conflicts[.title]?.first?.value)
        let resolved = try await pair.a.session.resolveConflict(itemID: item.id, group: .title, choosing: other)
        #expect(!resolved.hasConflicts)
        try await pair.exchange()
        let settled = try await pair.b.session.item(id: item.id)
        #expect(!settled.hasConflicts)
        #expect(.title(settled.title) == other)
    }

    @Test("a conflict can only be resolved to a value the item holds")
    func resolveOnlyHeldValues() async throws {
        let pair = try await SyncPair.make()
        let item = try await pair.a.session.save(login(pair.vaultID, title: "Library"))
        await #expect(throws: VaultError.conflictValueNotHeld) {
            try await pair.a.session.resolveConflict(itemID: item.id, group: .title, choosing: .title("Elsewhere"))
        }
    }

    @Test("the vault owns sync metadata: a draft's stamps, clock and conflicts are replaced on save")
    func saveIgnoresCallerMetadata() async throws {
        let pair = try await SyncPair.make()
        let stranger = UUID()
        var draft = login(pair.vaultID, title: "Library")
        draft.clock = VersionVector([stranger: 1 << 40])
        draft.revisions = [
            .title: GroupStamp(revision: Revision(version: 1 << 40, device: stranger), seen: draft.clock)
        ]
        draft.conflicts = [.title: [ConflictingValue(stamp: draft.revisions[.title]!, value: .title("Planted"))]]
        let saved = try await pair.a.session.save(draft)
        #expect(saved.conflicts.isEmpty)
        #expect(saved.clock.entries.keys.allSatisfy { $0 != stranger })
        #expect(saved.revisions.values.allSatisfy { $0.revision.device != stranger })
    }

    @Test("while locked, sync downloads and checks signatures but merges nothing until unlock (§7.4)")
    func lockedDownload() async throws {
        let pair = try await SyncPair.make()
        let item = try await pair.b.session.save(login(pair.vaultID, title: "Library"))
        try await pair.b.session.sync()

        await pair.a.session.lock()
        let locked = try await pair.a.session.sync()
        #expect(locked.deferredUntilUnlock)
        #expect(locked.fetched > 0)
        #expect(locked.rejected.isEmpty, "signatures verify against the Keychain copy of the account key")

        try await pair.a.session.unlock(password: TestVault.password)
        let unlocked = try await pair.a.session.sync()
        #expect(unlocked.applied > 0)
        #expect(try await pair.a.session.item(id: item.id).title == "Library")
    }

    @Test("a permanent deletion reaches the other device; an edit it had not seen is kept in the trash (F7.6)")
    func deletionKeepsUnseenEdit() async throws {
        let pair = try await SyncPair.make()
        let gone = try await pair.a.session.save(login(pair.vaultID, title: "Gone"))
        let kept = try await pair.a.session.save(login(pair.vaultID, title: "Kept"))
        try await pair.exchange()

        for id in [gone.id, kept.id] {
            try await pair.a.session.trash(id: id)
            try await pair.a.session.deletePermanently(id: id)
        }
        var edit = try await pair.b.session.item(id: kept.id)
        edit.title = "Kept, edited elsewhere"
        try await pair.b.session.save(edit)
        try await pair.exchange()
        try await pair.b.session.sync()

        for vault in [pair.a, pair.b] {
            let items = try await vault.session.items().items
            #expect(!items.contains { $0.id == gone.id })
            let survivor = try #require(items.first { $0.id == kept.id })
            #expect(survivor.title == "Kept, edited elsewhere")
            #expect(survivor.isTrashed && survivor.keptAfterDeletion)
        }
    }

    @Test("the purge keeps trash that sync left there: a trash that had not seen a concurrent edit (F7.7)")
    func purgeKeepsTrashSyncLeft() async throws {
        let pair = try await SyncPair.make()
        let disputed = try await pair.a.session.save(login(pair.vaultID, title: "Disputed"))
        let plain = try await pair.a.session.save(login(pair.vaultID, title: "Plain"))
        try await pair.exchange()

        try await pair.a.session.trash(id: disputed.id)
        try await pair.a.session.trash(id: plain.id)
        var edit = try await pair.b.session.item(id: disputed.id)
        edit.title = "Disputed, edited elsewhere"
        try await pair.b.session.save(edit)
        try await pair.exchange()

        let merged = try await pair.a.session.item(id: disputed.id)
        #expect(merged.isTrashed && !merged.isTrashedByPerson)
        await pair.a.clock.advance(by: 31 * 86_400)
        try await pair.a.session.purgeExpiredTrash()
        #expect(try await pair.a.session.items().items.map(\.id) == [disputed.id])
    }

    @Test("deleting the account erases sync state and the Keychain copy of the signing key")
    func deleteAccountErasesSyncState() async throws {
        let pair = try await SyncPair.make()
        let accountID = try #require(try await pair.a.session.status().accountID)
        try await pair.a.session.save(login(pair.vaultID))
        try await pair.a.session.trash(id: try await pair.a.session.items().items[0].id)
        try await pair.a.session.sync()
        #expect(await pair.a.keychain.contains(.accountSigningKey(accountID: accountID)))
        try await pair.a.session.deleteAccount(password: TestVault.password)
        #expect(await pair.a.keychain.isEmpty)
        let state = try #require(pair.a.sync?.state)
        #expect(try await state.loadState(vaultID: pair.vaultID) == nil)
    }

    #if canImport(SQLite3)
        @Test("the app's own stores: SQLite records and sync state carry a conversation across a relaunch")
        func sqliteAcrossRelaunch() async throws {
            let directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("watchword-vault-sync-\(UUID().uuidString)", isDirectory: true)
            let transport = InMemorySyncTransport()
            func launch(keychain: FakeKeychain) throws -> TestVault {
                TestVault(
                    store: try SQLiteRecordStore(url: directory.appendingPathComponent("Watchword.sqlite")),
                    keychain: keychain,
                    sync: SyncSettings(
                        state: try SQLiteSyncStateStore(url: directory.appendingPathComponent("sync.sqlite")),
                        transport: transport))
            }
            let a = try launch(keychain: FakeKeychain())
            try await a.createAccount()
            let vaultID = try #require(await a.session.personalVaultID)
            let b = try await a.enrolledDevice(deviceID: SyncPair.deviceB, over: transport)
            try await b.session.unlock(password: TestVault.password)
            let item = try await a.session.save(login(vaultID, title: "Library"))
            try await a.session.trash(id: item.id)
            try await a.session.deletePermanently(id: item.id)
            let other = try await a.session.save(login(vaultID, title: "Other"))
            try await b.session.sync()

            // Relaunch A before it publishes: the pending deletion and the saves are on disk.
            let relaunched = try launch(keychain: a.keychain)
            try await relaunched.session.unlock(password: TestVault.password)
            let first = try await relaunched.session.sync()
            #expect(first.pushedEntries >= 2)
            try await b.session.sync()
            #expect(try await b.session.items().items.map(\.id) == [other.id])
            let second = try await launch(keychain: a.keychain).session.sync()
            #expect(second.pushedEntries == 0, "nothing is published twice after a relaunch")
        }
    #endif

    @Test("a session without sync settings refuses to sync")
    func notConfigured() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        #expect(!vault.session.isSyncConfigured)
        await #expect(throws: VaultError.syncNotConfigured) { try await vault.session.sync() }
    }
}

extension Array where Element == UInt8 {
    func contains(subsequence needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, needle.count <= count else { return false }
        return (0...(count - needle.count)).contains { Array(self[$0..<($0 + needle.count)]) == needle }
    }
}
