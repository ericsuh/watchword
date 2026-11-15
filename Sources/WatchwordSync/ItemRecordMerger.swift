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

/// Why `ItemRecordMerger` refused to merge. The engine reports any of them as a rejected object and keeps the local
/// version.
public enum ItemMergeError: Error, Equatable, Sendable {
    /// The two rows did not open to versions of one item in one vault. A sealer checks each item against its row;
    /// this is the merger's own check, so that a sealer which does not cannot make the merge trap.
    case identityMismatch(UUID)
    /// No version above the ones given exists.
    case versionOverflow
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
        guard remoteItem.id == remote.recordID, remoteItem.vaultID == remote.vaultID,
            remote.recordID == local.recordID, remote.vaultID == local.vaultID
        else { throw ItemMergeError.identityMismatch(remote.recordID) }
        let localItem: Item
        do {
            localItem = try await sealer.openItem(local)
        } catch SyncKeyringError.locked {
            throw SyncKeyringError.locked
        } catch {
            // A local row that does not open is damage, not a version: the remote one replaces it.
            if remote.version > local.version { return .adoptRemote }
            let item = ItemMerge.written(remoteItem, as: try Self.revision(above: local.version, by: deviceID))
            return .replace(try await sealer.sealItem(item))
        }
        guard localItem.id == local.recordID, localItem.vaultID == local.vaultID else {
            throw ItemMergeError.identityMismatch(local.recordID)
        }
        let merged = ItemMerge.merge(
            localItem, origin: Self.origin(local), remoteItem, origin: Self.origin(remote))
        // Compared with the items as stored, not as the merge reads them: a version that is not in the form the merge
        // writes (older metadata, or crafted) is replaced by one that is, so every device ends up storing the same.
        if ItemMerge.sameState(merged, remoteItem), remote.version > local.version { return .adoptRemote }
        if ItemMerge.sameState(merged, localItem) { return .keepLocal }
        let item = ItemMerge.written(
            merged, as: try Self.revision(above: max(local.version, remote.version), by: deviceID))
        return .replace(try await sealer.sealItem(item))
    }

    /// What this device had seen of the item when it erased it, and the row it erased (`ItemErasure`).
    public func erasureSummary(of record: StoredRecord) async throws -> [UInt8] {
        let item = try await sealer.openItem(record)
        return try ItemErasure(
            seen: ItemMerge.effectiveClock(item, origin: Self.origin(record)), row: record.version, device: deviceID,
            date: item.modifiedAt
        ).summary()
    }

    public func resolveErasure(_ summary: [UInt8], of record: StoredRecord) async throws -> ErasureDecision {
        try await resolveErasure(summary, of: record, tombstone: nil)
    }

    /// `resolveErasure`, for a caller that knows the version of the tombstone carrying `summary`: a summary that
    /// does not name the row just below it is then read as having seen nothing, and the version kept is written above
    /// the tombstone whatever the summary says. Without it the tombstone's version is taken from the summary.
    public func resolveErasure(_ summary: [UInt8], of record: StoredRecord, tombstone: UInt64?) async throws
        -> ErasureDecision
    {
        let item = try await sealer.openItem(record)
        guard item.id == record.recordID, item.vaultID == record.vaultID else {
            throw ItemMergeError.identityMismatch(record.recordID)
        }
        let erasure = ItemErasure(summary: summary, tombstone: tombstone)
        switch ItemMerge.settle(item, origin: Self.origin(record), against: erasure) {
        case .erase:
            return .erase
        case .keep:
            return .keep
        case .kept(let kept):
            // Above the record and above the tombstone, as every device that keeps a version writes it.
            let floor = max(record.version, tombstone ?? erasure.revision.version)
            let revision = try Self.revision(above: floor, by: deviceID)
            return .replace(try await sealer.sealItem(ItemMerge.written(kept, as: revision)))
        }
    }

    static func revision(above version: UInt64, by device: UUID) throws -> Revision {
        let (next, overflow) = version.addingReportingOverflow(1)
        guard !overflow else { throw ItemMergeError.versionOverflow }
        return Revision(version: next, device: device)
    }

    static func origin(_ record: StoredRecord) -> Revision {
        Revision(version: record.version, device: record.deviceID)
    }
}
