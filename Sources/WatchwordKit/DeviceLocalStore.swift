import Foundation

/// Records one device keeps for itself: never synced, never on a transport, never in the record store the sync engine
/// reads (docs/02-architecture.md §13.8, ADR 0005 and its amendment). Today the hygiene engine's scan ledger and the
/// Pwned Passwords prefix cache.
///
/// The session writes only envelopes sealed under the device-local key (`DeviceLocalKeys.deviceLocalKey`), named by
/// keyed digests (`DeviceLocalKeys.recordName`), so an adapter stores opaque bytes under opaque names and needs no
/// knowledge of what they are. Everything read back is treated as hostile: it is opened under the key and context
/// the session derives for that name, or ignored. An adapter should keep the bytes on this device only (in the App
/// Group container, excluded from backup), and `deleteAll` must remove everything it holds.
public protocol DeviceLocalStore: Sendable {
    func read(_ name: UUID) async throws -> [UInt8]?
    /// Replaces whatever is stored under `name`.
    func write(_ bytes: [UInt8], as name: UUID) async throws
    func delete(_ names: [UUID]) async throws
    func deleteAll() async throws
}

/// A `DeviceLocalStore` in memory: what tests and UI-test launches use, and the default until the file adapter
/// exists (docs/03-implementation-plan.md, milestone 6).
public actor InMemoryDeviceLocalStore: DeviceLocalStore {
    private var records: [UUID: [UInt8]] = [:]

    public init() {}

    public func read(_ name: UUID) -> [UInt8]? {
        records[name]
    }

    public func write(_ bytes: [UInt8], as name: UUID) {
        records[name] = bytes
    }

    public func delete(_ names: [UUID]) {
        for name in names { records[name] = nil }
    }

    public func deleteAll() {
        records.removeAll()
    }

    /// Everything stored, by name: what someone reading the device at rest would find.
    public var contents: [UUID: [UInt8]] {
        records
    }
}
