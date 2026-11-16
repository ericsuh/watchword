#if canImport(CloudKit)
    import CloudKit
    import Foundation
    import WatchwordPlatform

    /// An in-memory private database with CloudKit's semantics where the transport depends on them: zones must exist
    /// before records are saved in them (a per-record `zoneNotFound` inside a partial failure), a new record saved with
    /// `.ifServerRecordUnchanged` over an existing one fails with `serverRecordChanged` while any other policy
    /// overwrites (so a transport that chose the wrong one would fail the contract), queries evaluate their predicate
    /// and page by an integer cursor, `desiredKeys` limits the fields returned, and assets are copied at save. Every
    /// save's policy is recorded, and an error can be injected for the next call. (A copy lives in each test target
    /// that needs one; test code only.)
    final class FakeCloudKitDatabase: CloudKitDatabase, @unchecked Sendable {
        typealias Cursor = Int

        private let lock = NSLock()
        private var zones: Set<String> = []
        private var stored: [CKRecord.ID: CKRecord] = [:]
        private var injected: [any Error] = []
        private(set) var savePolicies: [CKModifyRecordsOperation.RecordSavePolicy] = []
        private(set) var savedChangeTags: [String?] = []
        private(set) var queriedKeys: [[CKRecord.FieldKey]] = []
        let pageLimit: Int

        init(pageLimit: Int = 3) {
            self.pageLimit = pageLimit
        }

        /// The next call throws `error` instead of doing anything.
        func injectFailure(_ error: any Error) {
            lock.withLock { injected.append(error) }
        }

        /// What the server holds under `id`, for inspection and for planting records as A1 could.
        func storedRecord(_ id: CKRecord.ID) -> CKRecord? {
            lock.withLock { stored[id] }
        }

        func plant(_ record: CKRecord) {
            lock.withLock {
                zones.insert(record.recordID.zoneID.zoneName)
                stored[record.recordID] = record
            }
        }

        var zoneNames: Set<String> { lock.withLock { zones } }

        private func takeInjected() throws {
            let error: (any Error)? = lock.withLock { injected.isEmpty ? nil : injected.removeFirst() }
            if let error { throw error }
        }

        func records(
            matching query: CKQuery, inZoneWith zoneID: CKRecordZone.ID, desiredKeys: [CKRecord.FieldKey],
            resultsLimit: Int, continuing cursor: Int?
        ) async throws -> (matchResults: [(CKRecord.ID, Result<CKRecord, any Error>)], cursor: Int?) {
            try takeInjected()
            return try lock.withLock {
                queriedKeys.append(desiredKeys)
                guard zones.contains(zoneID.zoneName) else { throw CKError(.zoneNotFound) }
                let matching = stored.values.filter {
                    $0.recordID.zoneID == zoneID && $0.recordType == query.recordType
                        && query.predicate.evaluate(with: ["name": $0["name"] as? String ?? ""])
                }.sorted { $0.recordID.recordName < $1.recordID.recordName }
                let start = cursor ?? 0
                let limit = min(resultsLimit, pageLimit)
                let page = matching.dropFirst(start).prefix(limit).map { record in
                    (record.recordID, Result<CKRecord, any Error>.success(Self.copy(record, keys: desiredKeys)))
                }
                let next = start + limit < matching.count ? start + limit : nil
                return (Array(page), next)
            }
        }

        func record(for recordID: CKRecord.ID) async throws -> CKRecord {
            try takeInjected()
            return try lock.withLock {
                guard zones.contains(recordID.zoneID.zoneName) else { throw CKError(.zoneNotFound) }
                guard let record = stored[recordID] else { throw CKError(.unknownItem) }
                return Self.copy(record, keys: nil)
            }
        }

        func modifyRecords(
            saving recordsToSave: [CKRecord], deleting recordIDsToDelete: [CKRecord.ID],
            savePolicy: CKModifyRecordsOperation.RecordSavePolicy, atomically: Bool
        ) async throws -> (
            saveResults: [CKRecord.ID: Result<CKRecord, any Error>],
            deleteResults: [CKRecord.ID: Result<Void, any Error>]
        ) {
            try takeInjected()
            return try lock.withLock {
                var saves: [CKRecord.ID: Result<CKRecord, any Error>] = [:]
                var deletes: [CKRecord.ID: Result<Void, any Error>] = [:]
                var partial: [AnyHashable: any Error] = [:]
                for record in recordsToSave {
                    savePolicies.append(savePolicy)
                    savedChangeTags.append(record.recordChangeTag)
                    guard zones.contains(record.recordID.zoneID.zoneName) else {
                        partial[record.recordID] = CKError(.zoneNotFound)
                        continue
                    }
                    if stored[record.recordID] != nil, savePolicy == .ifServerRecordUnchanged {
                        saves[record.recordID] = .failure(CKError(.serverRecordChanged))
                        continue
                    }
                    let copy = try Self.copyAssets(record)
                    stored[record.recordID] = copy
                    saves[record.recordID] = .success(copy)
                }
                for id in recordIDsToDelete {
                    guard zones.contains(id.zoneID.zoneName) else {
                        partial[id] = CKError(.zoneNotFound)
                        continue
                    }
                    deletes[id] = stored.removeValue(forKey: id) == nil ? .failure(CKError(.unknownItem)) : .success(())
                }
                if !partial.isEmpty {
                    throw CKError(.partialFailure, userInfo: [CKPartialErrorsByItemIDKey: partial])
                }
                return (saves, deletes)
            }
        }

        func saveZone(_ zone: CKRecordZone) async throws {
            try takeInjected()
            lock.withLock { _ = zones.insert(zone.zoneID.zoneName) }
        }

        /// A copy as the server would return it, with only `keys` (plain or encrypted) when given.
        static func copy(_ record: CKRecord, keys: [CKRecord.FieldKey]?) -> CKRecord {
            let copy = CKRecord(recordType: record.recordType, recordID: record.recordID)
            let encrypted = Set(record.encryptedValues.allKeys())
            for key in record.allKeys() where !encrypted.contains(key) && (keys?.contains(key) ?? true) {
                copy[key] = record[key]
            }
            for key in encrypted where keys?.contains(key) ?? true {
                copy.encryptedValues[key] = record.encryptedValues[key]
            }
            return copy
        }

        /// A record whose assets point at files of the fake's own, as CloudKit uploads the file at save.
        static func copyAssets(_ record: CKRecord) throws -> CKRecord {
            let copy = Self.copy(record, keys: nil)
            let encrypted = Set(record.encryptedValues.allKeys())
            for key in record.allKeys() where !encrypted.contains(key) {
                guard let asset = record[key] as? CKAsset, let url = asset.fileURL else { continue }
                let file = FileManager.default.temporaryDirectory.appendingPathComponent(
                    "fake-ck-\(UUID().uuidString)")
                try FileManager.default.copyItem(at: url, to: file)
                copy[key] = CKAsset(fileURL: file)
            }
            return copy
        }
    }
#endif
