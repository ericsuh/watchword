import Foundation
import WatchwordEnvelope
import WatchwordKit
import WatchwordModel
import WatchwordStore
import WatchwordSync

/// One simulated device of an account: its own store and sync state, a fake keyring, the fake merger, and the engine
/// (docs/04-test-plan.md §2). `save`, `edit` and `delete` do what `VaultSession` does to the store — version above
/// everything seen, revisions stamped, sealed, committed through the deletion-recording store — so the simulation
/// exercises the engine with the same record traffic the app will produce.
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

    public init(
        deviceID: UUID, vaultID: UUID, keys: FakeAccountKeys, transport: any SyncTransport,
        configuration: SyncConfiguration = SyncTestClient.configuration,
        store: InMemoryRecordStore = InMemoryRecordStore(), syncState: InMemorySyncStateStore = InMemorySyncStateStore()
    ) {
        self.deviceID = deviceID
        self.vaultID = vaultID
        self.store = store
        self.syncState = syncState
        sessionStore = DeletionRecordingStore(base: store, syncState: syncState, deviceID: deviceID)
        keyring = FakeSyncKeyring(deviceID: deviceID, keys: keys)
        engine = SyncEngine(
            vaultID: vaultID, deviceID: deviceID, store: store, syncState: syncState, transport: transport,
            keyring: keyring, merger: FakeItemMerger(keyring: keyring), configuration: configuration)
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
            revision: Revision(version: item.version, device: deviceID))
        let row = try await keyring.sealItem(item)
        var change = StoreChange(upserts: [row])
        change.expectations[row.key] = existingRow.map { .version($0.version) } ?? .absent
        try await sessionStore.commit(change)
        return item
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
    private var offline: Set<UUID> = []
    private var now = 0
    private var generator: SeededGenerator
    public var maximumVisibilityDelay: Int
    public var duplicateListings: Bool

    public init(seed: UInt64, maximumVisibilityDelay: Int = 3, duplicateListings: Bool = true) {
        generator = SeededGenerator(seed: seed)
        self.maximumVisibilityDelay = maximumVisibilityDelay
        self.duplicateListings = duplicateListings
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
    }

    public var allObjects: [String: [UInt8]] {
        objects.mapValues(\.bytes)
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

    func fetch(device: UUID, name: String, maximumLength: Int) throws -> [UInt8]? {
        try check(device)
        guard let stored = objects[name], visible(stored, to: device) else { return nil }
        guard stored.bytes.count <= maximumLength else { throw SyncTransportError.objectTooLarge(name) }
        return stored.bytes
    }

    func create(device: UUID, name: String, contents: [UInt8]) throws {
        try check(device)
        guard objects[name] == nil else { throw SyncTransportError.objectExists(name) }
        let delay = maximumVisibilityDelay > 0 ? Int.random(in: 0...maximumVisibilityDelay, using: &generator) : 0
        objects[name] = Stored(bytes: contents, creator: device, visibleAt: now + delay)
    }

    func delete(device: UUID, name: String) throws {
        try check(device)
        objects[name] = nil
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
}
