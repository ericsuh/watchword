import Foundation
import WatchwordModel
import WatchwordStore

/// What `ItemRecordMerger` needs from whoever holds the vault key: open an item row, checking the decrypted item's
/// identity against the row, and seal an item as a row written by this device.
///
/// Production: `VaultSession`'s sync adapter, over `RecordCipher` and the vault key (milestone 3's Mac half). Tests:
/// `WatchwordTestSupport.FakeSyncKeyring`. Both throw `SyncKeyringError.locked` when no key is resident.
public protocol ItemSealer: Sendable {
    func openItem(_ row: StoredRecord) async throws -> Item
    func sealItem(_ item: Item) async throws -> StoredRecord
}

/// The `RecordMerger` for item records: open both versions, `ItemMerge.merge`, seal the result through
/// `ItemMerge.written` (docs/02-architecture.md §7.5, PRD F7.4, F7.6).
///
/// One implementation for production and tests, so the merger the app runs is the one the N-client simulation and the
/// nightly long runs exercise; only the sealing behind `ItemSealer` differs.
public struct ItemRecordMerger: RecordMerger {
    public let sealer: any ItemSealer
    /// The device the merger writes as: merge results and kept-after-deletion versions are new versions by it.
    public let deviceID: UUID

    public init(sealer: any ItemSealer, deviceID: UUID) {
        self.sealer = sealer
        self.deviceID = deviceID
    }

    public func merge(local: StoredRecord, remote: StoredRecord) async throws -> MergeDecision {
        let remoteItem = try await sealer.openItem(remote)
        let localItem: Item
        do {
            localItem = try await sealer.openItem(local)
        } catch SyncKeyringError.locked {
            throw SyncKeyringError.locked
        } catch {
            // A local row that does not open is damage, not a version: the remote one replaces it.
            if remote.version > local.version { return .adoptRemote }
            let item = ItemMerge.written(remoteItem, as: Revision(version: local.version + 1, device: deviceID))
            return .replace(try await sealer.sealItem(item))
        }
        let merged = ItemMerge.merge(
            localItem, origin: Self.origin(local), remoteItem, origin: Self.origin(remote))
        if ItemMerge.sameState(merged, remoteItem), remote.version > local.version { return .adoptRemote }
        if ItemMerge.sameState(merged, localItem) { return .keepLocal }
        let item = ItemMerge.written(
            merged, as: Revision(version: max(local.version, remote.version) + 1, device: deviceID))
        return .replace(try await sealer.sealItem(item))
    }

    /// The item's version vector, as JSON with sorted keys.
    public func erasureSummary(of record: StoredRecord) async throws -> [UInt8] {
        let item = try await sealer.openItem(record)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return Array(try encoder.encode(ItemMerge.effectiveClock(item, origin: Self.origin(record))))
    }

    public func resolveErasure(_ summary: [UInt8], of record: StoredRecord) async throws -> ErasureDecision {
        let item = try await sealer.openItem(record)
        // A summary that does not decode claims to have seen nothing, so nothing is erased because of it.
        let erased = (try? JSONDecoder().decode(VersionVector.self, from: Data(summary))) ?? VersionVector()
        if ItemMerge.isCovered(item, origin: Self.origin(record), byErasure: erased) { return .erase }
        if item.isTrashed { return .keep }
        // Above the record and above any erasure of what the erased vector names (an erasure is one past the row).
        let version = max(record.version, erased.entries.values.max() ?? 0) + 2
        var trashed = item
        trashed.trashedAt = item.modifiedAt
        trashed.keptAfterDeletion = true
        trashed = ItemMerge.stamped(
            trashed, previous: item, previousOrigin: Self.origin(record),
            revision: Revision(version: version, device: deviceID))
        trashed.version = version
        return .replace(try await sealer.sealItem(trashed))
    }

    static func origin(_ record: StoredRecord) -> Revision {
        Revision(version: record.version, device: record.deviceID)
    }
}
