import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// Devices of one account, each a real `VaultSession`, sharing an in-memory transport. The first creates the
/// account; the others enrol from the transport (docs/04-test-plan.md §2).
struct Fleet {
    static func deviceID(_ index: Int) -> UUID {
        UUID(uuid: (0xD0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, UInt8(0xA0 + index)))
    }

    let transport: InMemorySyncTransport
    var devices: [TestVault]
    let personal: UUID

    static func make(_ count: Int = 2) async throws -> Fleet {
        let transport = InMemorySyncTransport()
        let first = TestVault.syncing(over: transport, name: "Device 0")
        try await first.createAccount()
        var fleet = Fleet(
            transport: transport, devices: [first], personal: try #require(await first.session.personalVaultID))
        for index in 1..<max(count, 1) {
            try await fleet.enrol(index)
        }
        return fleet
    }

    /// Enrols one more device, unlocked.
    @discardableResult
    mutating func enrol(_ index: Int, password: String = TestVault.password) async throws -> TestVault {
        let device = try await devices[0].enrolledDevice(
            deviceID: Self.deviceID(index), over: transport, password: password, name: "Device \(index)")
        try await device.session.unlock(password: password)
        devices.append(device)
        return device
    }

    /// Syncs every device, round after round, until a full round changes nothing anywhere.
    func settle(_ devices: [TestVault]? = nil, maximumRounds: Int = 12) async throws {
        for _ in 0..<maximumRounds {
            var changed = false
            for device in devices ?? self.devices {
                let report = try await device.session.syncAll()
                let account = report.account
                let total = report.combined
                if total.applied > 0 || total.segmentsWritten > 0 || total.snapshotsWritten > 0
                    || account.registryEntriesFetched + account.registryEntriesPublished > 0
                    || account.vaultKeysFetched + account.vaultKeysPublished > 0
                    || account.vaultDeletionsFetched + account.vaultDeletionsPublished > 0
                    || account.candidateHeadersFetched > 0 || account.headerPublished
                {
                    changed = true
                }
            }
            if !changed { return }
        }
        Issue.record("devices did not settle")
    }

    /// What must agree across devices about an item.
    struct Seen: Hashable {
        var vaultID: UUID
        var title: String
        var fields: [String]
        var notes: String
        var trashed: Bool
        var keptAfterDeletion: Bool
        var conflicts: Int
    }

    static func seen(_ device: TestVault) async throws -> [UUID: Seen] {
        var result: [UUID: Seen] = [:]
        for item in try await device.session.items().items {
            result[item.id] = Seen(
                vaultID: item.vaultID, title: item.title,
                fields: item.fields.sorted { $0.id.uuidString < $1.id.uuidString }.map(\.value), notes: item.notes,
                trashed: item.isTrashed, keptAfterDeletion: item.keptAfterDeletion,
                conflicts: item.conflicts.values.map(\.count).reduce(0, +))
        }
        return result
    }

    func expectConverged(_ devices: [TestVault]? = nil, sourceLocation: SourceLocation = #_sourceLocation)
        async throws
    {
        let devices = devices ?? self.devices
        let reference = try await Self.seen(devices[0])
        let vaults = try await devices[0].session.vaults(includingDeleted: true)
        for device in devices.dropFirst() {
            #expect(try await Self.seen(device) == reference, sourceLocation: sourceLocation)
            #expect(
                try await device.session.vaults(includingDeleted: true) == vaults, sourceLocation: sourceLocation)
        }
    }
}

/// A store that fails chosen commits, to stand in for an interruption between two of them.
actor InterruptibleStore: RecordStore {
    struct Interrupted: Error {}

    let base = InMemoryRecordStore()
    private var commits = 0
    private var failing: Set<Int> = []

    /// Fails the `n`th commit from now (1 is the next).
    func failCommit(_ n: Int) {
        failing.insert(commits + n)
    }

    func loadAccount() async throws -> AccountRecord? { await base.loadAccount() }
    func record(_ key: RecordKey) async throws -> StoredRecord? { await base.record(key) }
    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        await base.records(in: vaultID, kind: kind)
    }
    func commit(_ change: StoreChange) async throws {
        commits += 1
        if failing.contains(commits) { throw Interrupted() }
        try await base.commit(change)
    }
    func eraseAll() async throws { await base.eraseAll() }
}

@Suite("Vault session: vaults")
struct VaultsTests {
    static func session() async throws -> (TestVault, personal: UUID) {
        let vault = TestVault()
        try await vault.createAccount()
        return (vault, try #require(await vault.session.personalVaultID))
    }

    @Test("an account starts with the Personal vault; vaults are created, listed and renamed")
    func createListRename() async throws {
        let (vault, personal) = try await Self.session()
        #expect(
            try await vault.session.vaults().map(\.name) == [VaultInfo.defaultPersonalName],
            "the Personal vault needs no record to exist")
        let work = try await vault.session.createVault(name: "  Work  ")
        let family = try await vault.session.createVault(name: "Family")
        #expect(work.name == "Work" && !work.isPersonal && !work.isDeleted)
        let listed = try await vault.session.vaults()
        #expect(listed.map(\.name) == ["Personal", "Family", "Work"], "Personal first, then by name")
        #expect(listed.map(\.isPersonal) == [true, false, false])
        #expect(listed[0].id == personal)

        try await vault.session.renameVault(id: work.id, to: "Allotment")
        try await vault.session.renameVault(id: personal, to: "Mine")
        #expect(try await vault.session.vaults().map(\.name) == ["Mine", "Allotment", "Family"])
        #expect(try await vault.session.vaults().first { $0.id == family.id }?.createdAt != nil)

        for name in ["", "   ", String(repeating: "x", count: VaultMetadataCodec.maximumNameLength + 1)] {
            await #expect(throws: VaultError.invalidVaultName) { try await vault.session.createVault(name: name) }
            await #expect(throws: VaultError.invalidVaultName) {
                try await vault.session.renameVault(id: work.id, to: name)
            }
        }
        let nowhere = UUID()
        await #expect(throws: VaultError.unknownVault(nowhere)) {
            try await vault.session.renameVault(id: nowhere, to: "Nowhere")
        }
    }

    @Test("each vault has its own key, wrapped under the keyset, and its name is sealed under that key")
    func keysAndNamesAreSealed() async throws {
        let (vault, personal) = try await Self.session()
        let work = try await vault.session.createVault(name: "Quarterly taxes vault")
        let item = try await vault.session.save(login(work.id, title: "Revenue office"))
        let store = try #require(vault.store as? InMemoryRecordStore)
        let rows = await store.allRecords

        let wraps = rows.filter { $0.kind == .vaultKeyWrap }
        #expect(Set(wraps.map(\.vaultID)) == [personal, work.id])
        #expect(Set(wraps.map(\.recordID)).count == 2, "two vaults, two keys")
        let itemRow = try #require(rows.first { $0.recordID == item.id })
        #expect(itemRow.keyID == wraps.first { $0.vaultID == work.id }?.recordID)
        // Nothing the person typed is in the store in the clear: not the vault's name, not the item's title.
        for needle in ["Quarterly taxes vault", "Revenue office"] {
            for row in rows {
                #expect(!row.envelope.contains(subsequence: Array(needle.utf8)), "\(needle) in a \(row.kind) row")
            }
        }
    }

    @Test("items are listed per vault and across vaults; locking and unlocking reopens every vault")
    func itemsPerVault() async throws {
        let (vault, personal) = try await Self.session()
        let work = try await vault.session.createVault(name: "Work")
        let mine = try await vault.session.save(login(personal, title: "Mine"))
        let theirs = try await vault.session.save(login(work.id, title: "Theirs"))
        #expect(try await vault.session.items(in: personal).items.map(\.id) == [mine.id])
        #expect(try await vault.session.items(in: work.id).items.map(\.id) == [theirs.id])
        #expect(try await vault.session.items().items.map(\.title) == ["Mine", "Theirs"])
        #expect(try await vault.session.itemCount(in: work.id) == 1)

        await vault.session.lock()
        await #expect(throws: VaultError.locked) { try await vault.session.vaults() }
        try await vault.session.unlock(password: TestVault.password)
        #expect(try await vault.session.items().items.map(\.title) == ["Mine", "Theirs"])
        #expect(try await vault.session.items().unreadable.isEmpty)
        // And a relaunch.
        let relaunched = vault.relaunched()
        try await relaunched.session.unlock(password: TestVault.password)
        #expect(try await relaunched.session.vaults().map(\.name) == ["Personal", "Work"])
        #expect(try await relaunched.session.item(id: theirs.id).title == "Theirs")
    }

    @Test("save cannot change an item's vault, nor write to a vault the account does not have")
    func saveStaysInItsVault() async throws {
        let (vault, personal) = try await Self.session()
        let work = try await vault.session.createVault(name: "Work")
        var item = try await vault.session.save(login(personal))
        item.vaultID = work.id
        await #expect(throws: VaultError.vaultChangeNotSupported) { try await vault.session.save(item) }
        let nowhere = UUID()
        await #expect(throws: VaultError.unknownVault(nowhere)) { try await vault.session.save(login(nowhere)) }
    }

    @Test("a copy is a new item in the other vault; the original is untouched")
    func copy() async throws {
        let (vault, personal) = try await Self.session()
        let work = try await vault.session.createVault(name: "Work")
        var original = try await vault.session.save(login(personal, title: "Printer", password: "first"))
        original.fields[1].value = "second"
        original = try await vault.session.save(original)
        let copy = try await vault.session.copy(itemID: original.id, to: work.id)
        #expect(copy.id != original.id && copy.vaultID == work.id)
        #expect(copy.title == "Printer" && copy.fields.map(\.value) == original.fields.map(\.value))
        #expect(copy.history.isEmpty, "a copy starts its own history")
        #expect(try await vault.session.item(id: original.id) == original)
        #expect(try await vault.session.items().items.count == 2)
        // Within one vault it is a duplicate.
        let duplicate = try await vault.session.copy(itemID: original.id, to: personal)
        #expect(duplicate.id != original.id && duplicate.vaultID == personal)
    }

    @Test("a move takes the item, its fields and its history to the other vault and leaves nothing behind")
    func move() async throws {
        let (vault, personal) = try await Self.session()
        let work = try await vault.session.createVault(name: "Work")
        var original = try await vault.session.save(login(personal, title: "Printer", password: "first"))
        original.fields[1].value = "second"
        original = try await vault.session.save(original)

        let moved = try await vault.session.move(itemID: original.id, to: work.id)
        #expect(moved.id != original.id && moved.vaultID == work.id)
        #expect(moved.fields.map(\.value) == original.fields.map(\.value))
        #expect(moved.history.map(\.fields) == original.history.map(\.fields), "the history moves too")
        #expect(moved.createdAt == original.createdAt)
        #expect(try await vault.session.items(in: personal).items.isEmpty)
        #expect(try await vault.session.items(in: work.id).items.map(\.id) == [moved.id])
        await #expect(throws: VaultError.itemNotFound(original.id)) { try await vault.session.item(id: original.id) }

        // To the vault it is already in: nothing happens.
        #expect(try await vault.session.move(itemID: moved.id, to: work.id) == moved)
        // To a vault that does not exist, and of an item in the trash: refused, nothing changes.
        let nowhere = UUID()
        await #expect(throws: VaultError.unknownVault(nowhere)) {
            try await vault.session.move(itemID: moved.id, to: nowhere)
        }
        try await vault.session.trash(id: moved.id)
        await #expect(throws: VaultError.itemIsTrashed(moved.id)) {
            try await vault.session.move(itemID: moved.id, to: personal)
        }
        #expect(try await vault.session.items().items.map(\.id) == [moved.id])
    }

    @Test("an interrupted move leaves the item where it was, or moved with the original in the trash: never neither")
    func moveInterrupted() async throws {
        let store = InterruptibleStore()
        let vault = TestVault(store: store)
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)
        let work = try await vault.session.createVault(name: "Work")
        let original = try await vault.session.save(login(personal, title: "Printer"))

        // Interrupted before the move commits: nothing moved, and the caller is told.
        await store.failCommit(1)
        await #expect(throws: InterruptibleStore.Interrupted.self) {
            try await vault.session.move(itemID: original.id, to: work.id)
        }
        #expect(try await vault.session.items().items == [original])

        // Interrupted after it commits, before the original is deleted for good: the move happened, and says so;
        // the original is in the trash of the vault it came from, where the purge will find it.
        await store.failCommit(2)
        let moved = try await vault.session.move(itemID: original.id, to: work.id)
        let after = try await vault.session.items().items
        #expect(Set(after.map(\.id)) == [original.id, moved.id])
        let left = try #require(after.first { $0.id == original.id })
        #expect(left.isTrashed && left.isTrashedByPerson && left.vaultID == personal)
        #expect(try await vault.session.item(id: moved.id).vaultID == work.id)
        await vault.clock.advance(by: VaultConfiguration.trashRetention + 1)
        try await vault.session.purgeExpiredTrash()
        #expect(try await vault.session.items().items.map(\.id) == [moved.id])
    }

    @Test("deleting a vault takes the caller's confirmation of what is in it; the Personal vault cannot be deleted")
    func deleteVault() async throws {
        let (vault, personal) = try await Self.session()
        let work = try await vault.session.createVault(name: "Work")
        let kept = try await vault.session.save(login(personal, title: "Kept"))
        try await vault.session.save(login(work.id, title: "One"))
        let two = try await vault.session.save(login(work.id, title: "Two"))
        try await vault.session.trash(id: two.id)

        await #expect(throws: VaultError.cannotDeletePersonalVault) {
            try await vault.session.deleteVault(id: personal, confirmingItemCount: 1)
        }
        // The person was shown one item; there are two (one of them in the trash).
        await #expect(throws: VaultError.vaultDeletionNotConfirmed(itemCount: 2)) {
            try await vault.session.deleteVault(id: work.id, confirmingItemCount: 1)
        }
        #expect(try await vault.session.items().items.count == 3)

        try await vault.session.deleteVault(id: work.id, confirmingItemCount: 2)
        #expect(try await vault.session.vaults().map(\.id) == [personal])
        #expect(try await vault.session.vaults(includingDeleted: true).map(\.isDeleted) == [false, true])
        #expect(try await vault.session.items().items == [kept])
        await #expect(throws: VaultError.vaultDeleted(work.id)) {
            try await vault.session.save(login(work.id, title: "Too late"))
        }
        await #expect(throws: VaultError.vaultDeleted(work.id)) {
            try await vault.session.renameVault(id: work.id, to: "Back")
        }
        await #expect(throws: VaultError.vaultDeleted(work.id)) {
            try await vault.session.move(itemID: kept.id, to: work.id)
        }
        // Again: already done.
        try await vault.session.deleteVault(id: work.id, confirmingItemCount: 0)
        // It stays deleted across a lock and a relaunch.
        let relaunched = vault.relaunched()
        try await relaunched.session.unlock(password: TestVault.password)
        #expect(try await relaunched.session.vaults().map(\.id) == [personal])
    }

    @Test("search finds titles, hosts, usernames, tags and notes of decrypted items, and never a secret")
    func search() async throws {
        let (vault, personal) = try await Self.session()
        let work = try await vault.session.createVault(name: "Work")
        var cafe = login(personal, title: "Café Müller", host: "cafe-muller.example", password: "espresso-secret")
        cafe.tags = ["Food"]
        cafe.notes = "Loyalty card in the blue wallet"
        cafe = try await vault.session.save(cafe)
        var bank = login(work.id, title: "First Bank", host: "firstbank.co.uk", password: "wallet-pin")
        bank.fields[0].value = "pat@household.example"
        bank = try await vault.session.save(bank)
        let trashed = try await vault.session.save(login(personal, title: "Old café"))
        try await vault.session.trash(id: trashed.id)

        func found(_ query: String, in vaultID: UUID? = nil) async throws -> [UUID] {
            try await vault.session.search(query, in: vaultID).map(\.id)
        }
        #expect(try await found("cafe") == [cafe.id], "diacritics and case are folded; the trash is left out")
        #expect(try await found("MULLER caf") == [cafe.id], "every word must be found")
        #expect(try await found("firstbank") == [bank.id])
        #expect(try await found("household") == [bank.id], "usernames and emails")
        #expect(try await found("food") == [cafe.id], "tags")
        #expect(try await found("blue wallet") == [cafe.id], "notes")
        #expect(try await found("espresso").isEmpty, "never a secret")
        #expect(try await found("wallet-pin").isEmpty)
        #expect(try await found("example").count == 2, "both, by host and username")
        #expect(try await found("example", in: work.id) == [bank.id])
        #expect(try await found("").isEmpty)
        #expect(try await found("   ").isEmpty)
        #expect(try await found("cafe nowhere").isEmpty)
        #expect(try await vault.session.search("cafe", includingTrashed: true).count == 2)
        // A title match ranks above a match in the notes.
        var note = login(personal, title: "Garage")
        note.notes = "next to the cafe"
        note = try await vault.session.save(note)
        #expect(try await found("cafe") == [cafe.id, note.id])

        #expect(ItemSearch.tokens("  Ｃafé\tMÜLLER ") == ["cafe", "muller"])
        #expect(ItemSearch.score(cafe, tokens: []) == nil)
    }

    /// The local file is not trusted (A8): a directory row is only an index, and a deletion in it counts only if the
    /// account key and a registered device signed it for that vault.
    @Test("a directory row edited in the file deletes nothing")
    func plantedDirectoryRows() async throws {
        let (vault, personal) = try await Self.session()
        let work = try await vault.session.createVault(name: "Work")
        let gone = try await vault.session.createVault(name: "Gone")
        try await vault.session.deleteVault(id: gone.id, confirmingItemCount: 0)
        let store = try #require(vault.store as? InMemoryRecordStore)
        let accountID = try #require(try await vault.session.status().accountID)
        let genuine = try #require(await store.record(RecordKey(recordID: gone.id, kind: .vaultDirectory)))

        // The genuine deletion of one vault, copied onto another vault's row and onto the Personal vault's.
        for target in [work.id, personal] {
            var moved = genuine
            moved.recordID = target
            moved.version = 9
            await store.tamper(moved)
        }
        // And a deletion nobody signed.
        var unsigned = genuine
        unsigned.recordID = UUID()
        unsigned.envelope =
            [0x02] + SignedObject(signature: [UInt8](repeating: 1, count: 129), envelope: []).serialized()
        await store.tamper(unsigned)
        #expect(accountID == genuine.vaultID)

        let listed = try await vault.session.vaults(includingDeleted: true)
        #expect(Set(listed.filter(\.isDeleted).map(\.id)) == [gone.id])
        #expect(Set(try await vault.session.vaults().map(\.id)) == [personal, work.id])
        try await vault.session.save(login(work.id, title: "Still writable"))
    }
}

@Suite("Vault session: vaults across devices")
struct VaultsSyncTests {
    @Test("a vault created on one device, its name and its items reach the other; a rename comes back")
    func vaultReachesOtherDevices() async throws {
        let fleet = try await Fleet.make()
        let (a, b) = (fleet.devices[0].session, fleet.devices[1].session)
        let work = try await a.createVault(name: "Work")
        let item = try await a.save(login(work.id, title: "Payroll"))
        try await fleet.settle()
        #expect(try await b.vaults().map(\.name) == ["Personal", "Work"])
        #expect(try await b.item(id: item.id).vaultID == work.id)

        try await b.renameVault(id: work.id, to: "Office")
        try await b.save(login(work.id, title: "Door code"))
        try await fleet.settle()
        #expect(try await a.vaults().map(\.name) == ["Personal", "Office"])
        #expect(try await a.items(in: work.id).items.map(\.title) == ["Door code", "Payroll"])
        try await fleet.expectConverged()
    }

    @Test("two renames at once settle on one name everywhere")
    func concurrentRename() async throws {
        let fleet = try await Fleet.make(3)
        let sessions = fleet.devices.map(\.session)
        let work = try await sessions[0].createVault(name: "Work")
        try await fleet.settle()
        try await sessions[0].renameVault(id: work.id, to: "Office")
        try await sessions[1].renameVault(id: work.id, to: "Studio")
        try await sessions[2].renameVault(id: fleet.personal, to: "Mine")
        try await fleet.settle()
        try await fleet.expectConverged()
        let names = try await sessions[2].vaults().map(\.name)
        #expect(names[0] == "Mine" && ["Office", "Studio"].contains(names[1]))
    }

    @Test("no vault name, title or secret reaches the transport, in any account object or log")
    func ciphertextOnly() async throws {
        let fleet = try await Fleet.make()
        let a = fleet.devices[0].session
        let work = try await a.createVault(name: "Quarterly taxes vault")
        let item = try await a.save(login(work.id, title: "Revenue office", password: "hunter2-but-longer"))
        try await a.move(itemID: item.id, to: fleet.personal)
        try await fleet.settle()
        let objects = await fleet.transport.allObjects
        #expect(objects.keys.contains { $0.hasPrefix("account/") } && objects.keys.contains { $0.hasPrefix("vault/") })
        for needle in ["Quarterly taxes vault", "Revenue office", "hunter2-but-longer", "Device 0", "Device 1"] {
            for (name, contents) in objects {
                #expect(!name.contains(needle))
                #expect(!contents.contains(subsequence: Array(needle.utf8)), "\(needle) in \(name)")
            }
        }
    }

    @Test("a move made on one device is the same move on the others")
    func moveSyncs() async throws {
        let fleet = try await Fleet.make()
        let (a, b) = (fleet.devices[0].session, fleet.devices[1].session)
        let work = try await a.createVault(name: "Work")
        let item = try await a.save(login(fleet.personal, title: "Printer"))
        try await fleet.settle()
        let moved = try await b.move(itemID: item.id, to: work.id)
        try await fleet.settle()
        for session in [a, b] {
            #expect(try await session.items().items.map(\.id) == [moved.id])
            #expect(try await session.item(id: moved.id).vaultID == work.id)
        }
        try await fleet.expectConverged()
    }

    /// PRD F7.6, F7.7: the move deletes only what its author had seen.
    @Test("an edit made elsewhere that the move had not seen is kept, in the trash of the vault it was made in")
    func moveAgainstConcurrentEdit() async throws {
        let fleet = try await Fleet.make()
        let (a, b) = (fleet.devices[0].session, fleet.devices[1].session)
        let work = try await a.createVault(name: "Work")
        let item = try await a.save(login(fleet.personal, title: "Printer", password: "old"))
        try await fleet.settle()

        let moved = try await a.move(itemID: item.id, to: work.id)
        var edit = try await b.item(id: item.id)
        edit.fields[1].value = "changed-on-b"
        try await b.save(edit)
        try await fleet.settle()

        for session in [a, b] {
            let items = try await session.items().items
            #expect(Set(items.map(\.id)) == [item.id, moved.id])
            let left = try #require(items.first { $0.id == item.id })
            #expect(left.vaultID == fleet.personal && left.isTrashed && !left.isTrashedByPerson)
            #expect(left.fields[1].value == "changed-on-b", "the edit the move had not seen is still there")
            #expect(try #require(items.first { $0.id == moved.id }).fields[1].value == "old")
        }
        try await fleet.expectConverged()
        // And it is never purged behind the person's back.
        await fleet.devices[0].clock.advance(by: VaultConfiguration.trashRetention + 1)
        try await a.purgeExpiredTrash()
        #expect(try await a.items().items.count == 2)
    }

    @Test("two devices moving the same version to the same vault make one item, not two")
    func sameMoveOnTwoDevices() async throws {
        let fleet = try await Fleet.make()
        let (a, b) = (fleet.devices[0].session, fleet.devices[1].session)
        let work = try await a.createVault(name: "Work")
        let item = try await a.save(login(fleet.personal, title: "Printer"))
        try await fleet.settle()
        let onA = try await a.move(itemID: item.id, to: work.id)
        let onB = try await b.move(itemID: item.id, to: work.id)
        #expect(onA.id == onB.id)
        try await fleet.settle()
        for session in [a, b] {
            let items = try await session.items().items
            #expect(items.map(\.id) == [onA.id])
            #expect(!items[0].hasConflicts && !items[0].isTrashed)
        }
        try await fleet.expectConverged()
    }

    @Test("an item holding values kept for the person to choose between is not moved until they have chosen")
    func moveRefusesUnresolvedValues() async throws {
        let fleet = try await Fleet.make()
        let (a, b) = (fleet.devices[0].session, fleet.devices[1].session)
        let work = try await a.createVault(name: "Work")
        let item = try await a.save(login(fleet.personal, title: "Library"))
        try await fleet.settle()
        for (session, title) in [(a, "Public Library"), (b, "City Library")] {
            var edit = try await session.item(id: item.id)
            edit.title = title
            try await session.save(edit)
        }
        try await fleet.settle()
        let conflicted = try await a.item(id: item.id)
        #expect(conflicted.hasConflicts)
        await #expect(throws: VaultError.itemHasUnresolvedValues(item.id)) {
            try await a.move(itemID: item.id, to: work.id)
        }
        // A copy takes what is shown and leaves the original, and its kept values, where they are.
        let copy = try await a.copy(itemID: item.id, to: work.id)
        #expect(copy.title == conflicted.title && !copy.hasConflicts)
        #expect(try await a.item(id: item.id).hasConflicts)
        // Once the person has chosen, it moves.
        let other = try #require(conflicted.conflicts[.title]?.first?.value)
        try await a.resolveConflict(itemID: item.id, group: .title, choosing: other)
        let moved = try await a.move(itemID: item.id, to: work.id)
        #expect(.title(moved.title) == other)
    }

    /// PRD F7.6, F7.7 for a whole vault: the deletion is explicit, signed, and removes only what its author had seen.
    @Test(
        "a vault deleted on one device is deleted on the others; what the deletion had not seen is kept, in the trash")
    func deleteVaultAgainstConcurrentWork() async throws {
        let fleet = try await Fleet.make(3)
        let (a, b, c) = (fleet.devices[0].session, fleet.devices[1].session, fleet.devices[2].session)
        let work = try await a.createVault(name: "Work")
        let seen = try await a.save(login(work.id, title: "Seen and deleted"))
        let edited = try await a.save(login(work.id, title: "Edited elsewhere", password: "old"))
        try await fleet.settle()

        try await a.deleteVault(id: work.id, confirmingItemCount: 2)
        // Meanwhile, on B: a new item in the vault, and an edit of one A is deleting.
        let created = try await b.save(login(work.id, title: "Created elsewhere"))
        var edit = try await b.item(id: edited.id)
        edit.fields[1].value = "changed-on-b"
        try await b.save(edit)
        try await fleet.settle()
        try await fleet.settle()

        for session in [a, b, c] {
            #expect(try await session.vaults().map(\.id) == [fleet.personal], "deleted everywhere")
            let items = try await session.items().items
            #expect(Set(items.map(\.id)) == [created.id, edited.id], "the item A had seen all of is gone")
            for item in items {
                #expect(item.vaultID == work.id && item.isTrashed && item.keptAfterDeletion)
                #expect(!item.isTrashedByPerson, "never purged: nobody chose to discard it")
            }
            #expect(items.first { $0.id == edited.id }?.fields[1].value == "changed-on-b")
            #expect(!items.contains { $0.id == seen.id })
        }
        try await fleet.expectConverged()

        // Nothing new goes into the deleted vault, and what is left in it is not restored there but moved out.
        await #expect(throws: VaultError.vaultDeleted(work.id)) { try await c.restore(id: created.id) }
        let rescued = try await c.move(itemID: created.id, to: fleet.personal)
        #expect(!rescued.isTrashed && !rescued.keptAfterDeletion && rescued.vaultID == fleet.personal)
        try await b.deletePermanently(id: edited.id)
        try await fleet.settle()
        for session in [a, b, c] {
            #expect(try await session.items().items.map(\.id) == [rescued.id])
        }
        try await fleet.expectConverged()
    }

    @Test("a locked device learns of a new vault, and opens it at the next unlock")
    func lockedDeviceLearnsOfVault() async throws {
        let fleet = try await Fleet.make()
        let (a, b) = (fleet.devices[0].session, fleet.devices[1].session)
        await b.lock()
        let work = try await a.createVault(name: "Work")
        let item = try await a.save(login(work.id, title: "Payroll"))
        try await a.sync()
        let locked = try await b.syncAll()
        #expect(locked.account.vaultKeysFetched == 1 && locked.combined.deferredUntilUnlock)
        try await b.unlock(password: TestVault.password)
        try await b.sync()
        #expect(try await b.item(id: item.id).title == "Payroll")
        #expect(try await b.vaults().map(\.name) == ["Personal", "Work"])
    }

    @Test("quarantined versions are listed and discarded across vaults")
    func quarantineAcrossVaults() async throws {
        let fleet = try await Fleet.make(1)
        let a = fleet.devices[0]
        let work = try await a.session.createVault(name: "Work")
        let state = try #require(a.sync?.state)
        let entry = SyncEntry(
            recordID: UUID(), kind: .item, keyID: UUID(), version: 1 << 61, device: UUID(), envelope: [1, 2, 3])
        try await state.quarantine(entry, vaultID: work.id)
        #expect(try await a.session.quarantinedVersions() == [entry])
        try await a.session.discardQuarantined([entry])
        #expect(try await a.session.quarantinedVersions().isEmpty)
    }
}
