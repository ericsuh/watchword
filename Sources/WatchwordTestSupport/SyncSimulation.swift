import Foundation
import WatchwordEnvelope
import WatchwordKit
import WatchwordModel
import WatchwordStore
import WatchwordSync

/// One simulated device of an account: its own store and sync state, a fake keyring, the fake merger, and the engine
/// (docs/04-test-plan.md §2). `save`, `edit` and `delete` do what `VaultSession` does to the store — version above
/// everything seen, revisions stamped, sealed, committed through the deletion-recording store — so the simulation
/// exercises the engine with the same record traffic the app will produce. `opaqueKinds` (kind to schema version) are
/// further kinds it carries without reading them, merged by `OpaqueRecordMerger` and written with `saveRecord`; give
/// them to `configuration` as well.
public actor SyncTestClient {
    public static let configuration = SyncConfiguration(schemaVersions: [.item: ItemCodec.schemaVersion])

    public let deviceID: UUID
    public let vaultID: UUID
    public let store: InMemoryRecordStore
    public let sessionStore: DeletionRecordingStore
    public let syncState: InMemorySyncStateStore
    public let keyring: FakeSyncKeyring
    public let engine: SyncEngine
    private var tick: TimeInterval = 0
    /// For the note-line nonces `ItemMerge.stamped` draws, seeded from the device so that a simulation replays.
    private var generator: SeededGenerator

    public init(
        deviceID: UUID, vaultID: UUID, keys: FakeAccountKeys, transport: any SyncTransport,
        configuration: SyncConfiguration = SyncTestClient.configuration,
        store: InMemoryRecordStore = InMemoryRecordStore(),
        syncState: InMemorySyncStateStore = InMemorySyncStateStore(),
        opaqueKinds: [EnvelopeKind: UInt64] = [:]
    ) {
        self.deviceID = deviceID
        self.vaultID = vaultID
        generator = SeededGenerator(seed: deviceID.byteArray.reduce(0x17E3) { $0 &* 31 &+ UInt64($1) })
        self.store = store
        self.syncState = syncState
        sessionStore = DeletionRecordingStore(base: store, syncState: syncState, deviceID: deviceID)
        keyring = FakeSyncKeyring(deviceID: deviceID, keys: keys)
        var merger: any RecordMerger = FakeItemMerger(keyring: keyring)
        if !opaqueKinds.isEmpty {
            var mergers: [EnvelopeKind: any RecordMerger] = [.item: merger]
            for (kind, schema) in opaqueKinds {
                mergers[kind] = OpaqueRecordMerger(keyring: keyring, schemaVersion: schema)
            }
            merger = KindRoutingMerger(mergers)
        }
        engine = SyncEngine(
            vaultID: vaultID, deviceID: deviceID, store: store, syncState: syncState, transport: transport,
            keyring: keyring, merger: merger, configuration: configuration)
    }

    @discardableResult
    public func sync(reconcile: Bool = false) async throws -> SyncReport {
        try await engine.sync(reconcile: reconcile)
    }

    /// Creates or replaces an item, as `VaultSession.save` does.
    @discardableResult
    public func save(_ draft: Item) async throws -> Item {
        let existingRow = try await sessionStore.record(RecordKey(recordID: draft.id, kind: .item))
        var existing: Item?
        if let existingRow { existing = try await keyring.openItem(existingRow) }
        let highest = try await sessionStore.records(in: vaultID, kind: .item).map(\.version).max() ?? 0
        var item = draft
        item.vaultID = vaultID
        item.version = max(highest, existing?.version ?? 0) + 1
        tick += 1
        item.modifiedAt = Date(timeIntervalSince1970: 1_800_000_000 + tick)
        if let existing {
            item.createdAt = existing.createdAt
            item.history = existing.history
            if existing.fields != item.fields {
                item.history.insert(
                    ItemHistoryEntry(replacedAt: item.modifiedAt, version: existing.version, fields: existing.fields),
                    at: 0)
            }
        } else {
            item.createdAt = item.modifiedAt
            item.history = []
        }
        item = ItemMerge.stamped(
            item, previous: existing,
            previousOrigin: existingRow.map { Revision(version: $0.version, device: $0.deviceID) },
            revision: Revision(version: item.version, device: deviceID), using: &generator)
        let row = try await keyring.sealItem(item)
        var change = StoreChange(upserts: [row])
        change.expectations[row.key] = existingRow.map { .version($0.version) } ?? .absent
        try await sessionStore.commit(change)
        return item
    }

    /// Writes a new version of a record of a kind carried opaquely (`opaqueKinds`), above every version of that kind
    /// this device holds, as the session writes scan results beside an item.
    @discardableResult
    public func saveRecord(
        _ plaintext: [UInt8], recordID: UUID, kind: EnvelopeKind, schemaVersion: UInt64
    ) async throws -> StoredRecord {
        let key = RecordKey(recordID: recordID, kind: kind)
        let existing = try await sessionStore.record(key)
        let highest = try await sessionStore.records(in: vaultID, kind: kind).map(\.version).max() ?? 0
        let row = try await keyring.sealRecord(
            plaintext, recordID: recordID, kind: kind, schemaVersion: schemaVersion, vaultID: vaultID,
            version: max(highest, existing?.version ?? 0) + 1)
        var change = StoreChange(upserts: [row])
        change.expectations[key] = existing.map { .version($0.version) } ?? .absent
        try await sessionStore.commit(change)
        return row
    }

    /// Stores an item the caller built as a new version (a conflict resolution from `ItemMerge.resolve`), as the
    /// vault will.
    public func commitResolved(_ item: Item) async throws {
        let row = try await keyring.sealItem(item)
        let existing = try await sessionStore.record(row.key)
        var change = StoreChange(upserts: [row])
        change.expectations[row.key] = existing.map { .version($0.version) } ?? .absent
        try await sessionStore.commit(change)
    }

    @discardableResult
    public func edit(_ id: UUID, _ mutate: @Sendable (inout Item) -> Void) async throws -> Item {
        var item = try await item(id)
        mutate(&item)
        return try await save(item)
    }

    /// Permanently deletes an item, as `VaultSession.deletePermanently` does (conditional on the version read).
    public func delete(_ id: UUID) async throws {
        guard let row = try await sessionStore.record(RecordKey(recordID: id, kind: .item)) else { return }
        try await sessionStore.commit(StoreChange(conditionalDeletions: [row.key: row.version]))
    }

    public func item(_ id: UUID) async throws -> Item {
        guard let row = try await sessionStore.record(RecordKey(recordID: id, kind: .item)) else {
            throw RecordStoreError.versionConflict(recordID: id)
        }
        return try await keyring.openItem(row)
    }

    /// Every readable item, by ID.
    public func items() async throws -> [UUID: Item] {
        var items: [UUID: Item] = [:]
        for row in try await sessionStore.records(in: vaultID, kind: .item) {
            items[row.recordID] = try await keyring.openItem(row)
        }
        return items
    }

    public func state() async -> SyncState? {
        await syncState.loadState(vaultID: vaultID)
    }

    /// A validly sealed and signed segment of this device's stream at `sequence`, carrying `rows` (versions it
    /// wrote): the bytes another installation of this device would create under that name. Planted beside the
    /// segment the device really wrote, it is the second copy of a forked stream (docs/02-architecture.md §7.5,
    /// "Conflict copies").
    public func signedSegment(
        _ sequence: UInt64, carrying rows: [StoredRecord], acknowledging vector: [UUID: UInt64] = [:]
    ) async throws -> [UInt8] {
        let location = SyncObjectLocation.segment(vaultID: vaultID, author: deviceID, sequence: sequence)
        let payload = SyncPayload(
            kind: .segment, vaultID: vaultID, author: deviceID, number: sequence, vector: vector,
            entries: rows.map(SyncEntry.init))
        let envelope = try await keyring.seal(payload.encoded(), at: location)
        let signature = try await keyring.sign(envelope, at: location)
        return SignedObject(signature: signature, envelope: envelope).serialized()
    }

    /// The entries this device keeps aside for a later version (ADR 0009), as stored.
    public func stash() async -> SyncStash {
        guard let bytes = await syncState.stash(vaultID: vaultID) else { return SyncStash() }
        return (try? SyncStash.parse(bytes)) ?? SyncStash()
    }
}

/// A shared object store with the faults a real one has (docs/04-test-plan.md §2, `InMemorySyncTransport` with
/// partitions, reordering, duplication and delays): devices go offline, a new object becomes visible to other devices
/// only after a random number of ticks (iCloud Drive and CloudKit are eventually consistent), listings come back
/// shuffled with duplicates, and fetches of not-yet-visible objects miss. Each device talks to it through its own
/// `SimulatedTransport`.
public actor SimulatedServer {
    struct Stored {
        var bytes: [UInt8]
        var creator: UUID
        var visibleAt: Int
    }

    private var objects: [String: Stored] = [:]
    /// Copies beside an object, as iCloud Drive keeps a conflict version or a renamed second create (§7.5).
    private var otherCopies: [String: [Stored]] = [:]
    private var offline: Set<UUID> = []
    private var now = 0
    private var generator: SeededGenerator
    public var maximumVisibilityDelay: Int
    public var duplicateListings: Bool
    /// Whether a create of a name whose object the creating device cannot see yet succeeds and leaves two copies,
    /// as iCloud Drive does; off, every second create fails, as on CloudKit.
    public var keepsConflictCopies: Bool

    public init(
        seed: UInt64, maximumVisibilityDelay: Int = 3, duplicateListings: Bool = true,
        keepsConflictCopies: Bool = false
    ) {
        generator = SeededGenerator(seed: seed)
        self.maximumVisibilityDelay = maximumVisibilityDelay
        self.duplicateListings = duplicateListings
        self.keepsConflictCopies = keepsConflictCopies
    }

    public func transport(for device: UUID) -> SimulatedTransport {
        SimulatedTransport(device: device, server: self)
    }

    public func advance(by ticks: Int = 1) {
        now += ticks
    }

    public func setOffline(_ device: UUID, _ isOffline: Bool) {
        if isOffline { offline.insert(device) } else { offline.remove(device) }
    }

    /// Everything becomes visible and every device comes back: the end of a partition.
    public func heal() {
        offline = []
        for name in objects.keys { objects[name]!.visibleAt = min(objects[name]!.visibleAt, now) }
        for name in otherCopies.keys {
            for index in otherCopies[name]!.indices {
                otherCopies[name]![index].visibleAt = min(otherCopies[name]![index].visibleAt, now)
            }
        }
    }

    public var allObjects: [String: [UInt8]] {
        objects.mapValues(\.bytes)
    }

    /// How many copies are kept beside objects, in all.
    public var copyCount: Int {
        otherCopies.values.reduce(0) { $0 + $1.count }
    }

    /// Writes an object as no device: what a provider glitch, a half-uploaded file or a stray file looks like.
    public func plant(_ name: String, contents: [UInt8]) {
        objects[name] = Stored(bytes: contents, creator: UUID(), visibleAt: now)
    }

    /// Adds a copy beside the object under `name`, visible to everyone at once: junk someone planted, or the other
    /// copy of a name that was created twice.
    public func plantCopy(_ name: String, contents: [UInt8]) {
        otherCopies[name, default: []].append(Stored(bytes: contents, creator: UUID(), visibleAt: now))
    }

    /// Whether `device` could create `name` now although an object is under it: the object is not visible to it yet,
    /// which is when a file provider ends up with two copies of one name.
    public func createsCopy(device: UUID, name: String) -> Bool {
        guard let stored = objects[name] else { return false }
        return !visible(stored, to: device)
    }

    func check(_ device: UUID) throws {
        if offline.contains(device) { throw SyncTransportError.unavailable }
    }

    func visible(_ stored: Stored, to device: UUID) -> Bool {
        stored.creator == device || stored.visibleAt <= now
    }

    func list(device: UUID, prefix: String) throws -> [String] {
        try check(device)
        var names = objects.filter { $0.key.hasPrefix(prefix) && visible($0.value, to: device) }.map(\.key)
        if duplicateListings, !names.isEmpty, Bool.random(using: &generator) {
            names.append(names[Int.random(in: 0..<names.count, using: &generator)])
        }
        names.shuffle(using: &generator)
        return names
    }

    func listWithCopies(device: UUID, prefix: String) throws -> SyncListing {
        var listing = SyncListing(names: try list(device: device, prefix: prefix))
        for (name, copies) in otherCopies where name.hasPrefix(prefix) {
            let seen = copies.filter { visible($0, to: device) }.count
            guard seen > 0 else { continue }
            let current = objects[name].map { visible($0, to: device) } ?? false
            listing.copied[name] = seen + (current ? 1 : 0)
            if !current { listing.names.append(name) }
        }
        return listing
    }

    func fetchCopies(device: UUID, name: String, maximumLength: Int, maximumCopies: Int) throws -> SyncObjectCopies {
        try check(device)
        var found = SyncObjectCopies()
        for stored in (objects[name].map { [$0] } ?? []) + (otherCopies[name] ?? []) where visible(stored, to: device) {
            if found.copies.count < maximumCopies, stored.bytes.count <= maximumLength {
                found.copies.append(stored.bytes)
            } else {
                found.omitted += 1
            }
        }
        return found
    }

    func fetch(device: UUID, name: String, maximumLength: Int) throws -> [UInt8]? {
        try check(device)
        guard let stored = objects[name], visible(stored, to: device) else { return nil }
        guard stored.bytes.count <= maximumLength else { throw SyncTransportError.objectTooLarge(name) }
        return stored.bytes
    }

    func create(device: UUID, name: String, contents: [UInt8]) throws {
        try check(device)
        let delay = maximumVisibilityDelay > 0 ? Int.random(in: 0...maximumVisibilityDelay, using: &generator) : 0
        let stored = Stored(bytes: contents, creator: device, visibleAt: now + delay)
        if let existing = objects[name] {
            // A provider that has not shown this device the object yet takes the second create and keeps both
            // (`keepsConflictCopies`); otherwise, and always once the object is visible, objects are written once.
            guard keepsConflictCopies, !visible(existing, to: device) else {
                throw SyncTransportError.objectExists(name)
            }
            otherCopies[name, default: []].append(stored)
            return
        }
        objects[name] = stored
    }

    func delete(device: UUID, name: String) throws {
        try check(device)
        objects[name] = nil
        otherCopies[name] = nil
    }
}

public struct SimulatedTransport: SyncTransport {
    public let device: UUID
    public let server: SimulatedServer

    public func list(prefix: String) async throws -> [String] {
        try await server.list(device: device, prefix: prefix)
    }

    public func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        try await server.fetch(device: device, name: name, maximumLength: maximumLength)
    }

    public func create(_ name: String, contents: [UInt8]) async throws {
        try await server.create(device: device, name: name, contents: contents)
    }

    public func delete(_ name: String) async throws {
        try await server.delete(device: device, name: name)
    }

    public func listWithCopies(prefix: String) async throws -> SyncListing {
        try await server.listWithCopies(device: device, prefix: prefix)
    }

    public func fetchCopies(_ name: String, maximumLength: Int, maximumCopies: Int) async throws -> SyncObjectCopies {
        try await server.fetchCopies(
            device: device, name: name, maximumLength: maximumLength, maximumCopies: maximumCopies)
    }
}
