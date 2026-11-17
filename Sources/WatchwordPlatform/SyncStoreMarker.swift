import Foundation

/// What this device remembers about the remote stores it syncs with: which it has seen exist
/// (docs/02-architecture.md §7.2). A CloudKit zone that this device created, or saw holding objects, and that is then
/// missing was deleted — by the person, in their iCloud settings ("delete data"), or by a reset — not "never created":
/// so it is `SyncTransportError.storeReset`, and the transport never recreates it or reports it as merely empty.
/// Without this memory, the next sync would silently put back what the person had deleted.
///
/// The memory is local and unsynced. The person's explicit choice to start the store again
/// (`VaultSession.reuploadAfterStoreReset`, §7.10) recreates the store and keeps the marker: the store has been seen,
/// and a later deletion is a reset like the first. `forget` is for a device that leaves the account. Someone who can
/// write this device's files (A8) can delete a marker; the store then reads as never created to the transport, which
/// needs that and the person's deletion together. Even then nothing a reset removed is uploaded again unasked: the
/// session stops at a store that holds none of the account's objects once this device has synced, and the engine
/// writes no snapshot while its own objects are missing (§7.10).
public protocol SyncStoreMarker: Sendable {
    func hasSeen(_ store: String) async throws -> Bool
    func markSeen(_ store: String) async throws
    func forget(_ store: String) async throws
}

/// A `SyncStoreMarker` in memory, for tests and previews.
public actor InMemorySyncStoreMarker: SyncStoreMarker {
    private var seen: Set<String> = []

    public init() {}

    public func hasSeen(_ store: String) -> Bool { seen.contains(store) }

    public func markSeen(_ store: String) { seen.insert(store) }

    public func forget(_ store: String) { seen.remove(store) }
}

/// A `SyncStoreMarker` as files: one empty file per store, `<store>.seen`, in a directory of its own beside the
/// device-local records (`AppContainer`), under the same checks as `FileDeviceLocalStore` (the whole path below the
/// container, never through a link). A store name is letters, digits and `-` only. Anything but a regular file under a
/// marker's name counts as seen: when in doubt, never recreate.
public struct FileSyncStoreMarker: SyncStoreMarker {
    public let store: FileDeviceLocalStore

    public init(ancestor: URL, components: [String]) {
        store = FileDeviceLocalStore(ancestor: ancestor, components: components, maximumRecordLength: 0)
    }

    public init(directory: URL) {
        store = FileDeviceLocalStore(directory: directory, maximumRecordLength: 0)
    }

    /// The record name of a store: a fixed UUID derived from its name, so the marker reuses the device-local store's
    /// checked file handling without a naming scheme of its own.
    static func recordName(_ store: String) throws -> UUID {
        let bytes = Array(store.utf8)
        guard (1...64).contains(bytes.count),
            bytes.allSatisfy({
                ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x2D
            })
        else { throw MarkerNameError.invalid(store) }
        // FNV-1a over the name, twice with different offsets: a name, not a secret, so no keyed digest is needed.
        func fnv(_ offset: UInt64) -> UInt64 {
            bytes.reduce(offset) { ($0 ^ UInt64($1)) &* 0x0000_0100_0000_01B3 }
        }
        let high = fnv(0xCBF2_9CE4_8422_2325)
        let low = fnv(0x9E37_79B9_7F4A_7C15 ^ UInt64(bytes.count))
        var raw = (0..<8).map { UInt8(truncatingIfNeeded: high >> (56 - 8 * $0)) }
        raw += (0..<8).map { UInt8(truncatingIfNeeded: low >> (56 - 8 * $0)) }
        return UUID(
            uuid: (
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7], raw[8], raw[9], raw[10], raw[11],
                raw[12], raw[13], raw[14], raw[15]
            ))
    }

    public enum MarkerNameError: Error, Equatable, Sendable {
        case invalid(String)
    }

    public func hasSeen(_ name: String) async throws -> Bool {
        do {
            return try await store.read(Self.recordName(name)) != nil
        } catch is MarkerNameError {
            throw MarkerNameError.invalid(name)
        } catch {
            return true  // A link or a directory under the name, or a path replaced: never recreate.
        }
    }

    public func markSeen(_ name: String) async throws {
        try await store.write([], as: Self.recordName(name))
    }

    public func forget(_ name: String) async throws {
        try await store.delete([Self.recordName(name)])
    }
}
