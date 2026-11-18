#if canImport(CloudKit)
    import CloudKit
    import Foundation
    import Testing
    import WatchwordPlatform

    /// An in-memory private database with CloudKit's semantics where the transport depends on them: zones must exist
    /// before records are saved in them (a per-record `zoneNotFound` inside a partial failure), a new record saved with
    /// `.ifServerRecordUnchanged` over an existing one fails with `serverRecordChanged` while any other policy
    /// overwrites (so a transport that chose the wrong one would fail the contract), queries are read (a CKQuery's
    /// predicate cannot be evaluated on Apple platforms: only `TRUEPREDICATE` and `name BEGINSWITH <string>` are
    /// understood, and any other shape records an issue and throws, so a transport that changes its query cannot pass
    /// unnoticed) and page by an integer cursor, `desiredKeys` limits the fields returned, and assets are copied at save. Every
    /// save's policy is recorded, and an error can be injected for the next call. A zone whose encryption key was reset
    /// (`resetEncryptionKey`) behaves as Apple documents for `CKErrorUserDidResetEncryptedDataKey`, as read here: its
    /// metadata still fetches, and every read or write of its records answers `zoneNotFound` with that key set, until
    /// the zone is deleted (review finding SR26). (A copy lives in each test target that needs one; test code only.)
    final class FakeCloudKitDatabase: CloudKitDatabase, @unchecked Sendable {
        typealias Cursor = Int

        private let lock = NSLock()
        private var zones: Set<String> = []
        private var stored: [CKRecord.ID: CKRecord] = [:]
        private var injected: [any Error] = []
        private(set) var savePolicies: [CKModifyRecordsOperation.RecordSavePolicy] = []
        private(set) var savedChangeTags: [String?] = []
        private(set) var queriedKeys: [[CKRecord.FieldKey]] = []
        /// The predicate format and results limit of every query, in order.
        private(set) var queries: [(predicate: String, limit: Int)] = []
        /// Zones whose encryption key CloudKit reset: present, with records nobody can read.
        private var keyReset: Set<String> = []
        /// Every zone save and zone deletion asked for, in order.
        private(set) var savedZones: [String] = []
        private(set) var deletedZones: [String] = []
        let pageLimit: Int
        /// A1 answering without end: every page repeats the same records and offers another.
        var endless = false

        struct UnsupportedQuery: Error {}

        init(pageLimit: Int = 3) {
            self.pageLimit = pageLimit
        }

        /// Deletes a zone and everything in it, as the person's "delete data" in iCloud settings does.
        func purgeZone(_ zoneName: String) {
            lock.withLock {
                zones.remove(zoneName)
                keyReset.remove(zoneName)
                stored = stored.filter { $0.key.zoneID.zoneName != zoneName }
            }
        }

        /// CloudKit resets the key that protects `zoneName`'s encrypted fields (the person reset their iCloud
        /// Keychain, or recovered the account): the zone and its records stay on the server, unreadable.
        func resetEncryptionKey(of zoneName: String) {
            lock.withLock { _ = keyReset.insert(zoneName) }
        }

        static var resetError: CKError {
            CKError(.zoneNotFound, userInfo: [CKErrorUserDidResetEncryptedDataKey: true])
        }

        /// The prefix a query asks for: `""` for `TRUEPREDICATE`, the constant of `name BEGINSWITH <string>`, or `nil`
        /// for anything else.
        static func prefix(of predicate: NSPredicate) -> String? {
            if predicate.predicateFormat == "TRUEPREDICATE" { return "" }
            guard let comparison = predicate as? NSComparisonPredicate,
                comparison.predicateOperatorType == .beginsWith, comparison.comparisonPredicateModifier == .direct,
                comparison.leftExpression.expressionType == .keyPath, comparison.leftExpression.keyPath == "name",
                comparison.rightExpression.expressionType == .constantValue
            else { return nil }
            return comparison.rightExpression.constantValue as? String
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
            guard let prefix = Self.prefix(of: query.predicate) else {
                Issue.record("the fake database does not understand the query \(query.predicate.predicateFormat)")
                throw UnsupportedQuery()
            }
            return try lock.withLock {
                queriedKeys.append(desiredKeys)
                queries.append((query.predicate.predicateFormat, resultsLimit))
                guard zones.contains(zoneID.zoneName) else { throw CKError(.zoneNotFound) }
                guard !keyReset.contains(zoneID.zoneName) else { throw Self.resetError }
                let matching = stored.values.filter {
                    $0.recordID.zoneID == zoneID && $0.recordType == query.recordType
                        && ($0["name"] as? String ?? "").hasPrefix(prefix)
                }.sorted { $0.recordID.recordName < $1.recordID.recordName }
                let limit = min(resultsLimit, pageLimit)
                if endless {
                    let page = matching.prefix(limit).map { record in
                        (record.recordID, Result<CKRecord, any Error>.success(Self.copy(record, keys: desiredKeys)))
                    }
                    return (Array(page), (cursor ?? 0) + 1)
                }
                let start = cursor ?? 0
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
                guard !keyReset.contains(recordID.zoneID.zoneName) else { throw Self.resetError }
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
                    guard !keyReset.contains(record.recordID.zoneID.zoneName) else {
                        partial[record.recordID] = Self.resetError
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
                    guard !keyReset.contains(id.zoneID.zoneName) else {
                        partial[id] = Self.resetError
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
            lock.withLock {
                _ = zones.insert(zone.zoneID.zoneName)
                savedZones.append(zone.zoneID.zoneName)
            }
        }

        func fetchZone(_ zoneID: CKRecordZone.ID) async throws {
            try takeInjected()
            try lock.withLock {
                guard zones.contains(zoneID.zoneName) else { throw CKError(.zoneNotFound) }
            }
        }

        func deleteZone(_ zoneID: CKRecordZone.ID) async throws {
            try takeInjected()
            lock.withLock {
                zones.remove(zoneID.zoneName)
                keyReset.remove(zoneID.zoneName)
                stored = stored.filter { $0.key.zoneID.zoneName != zoneID.zoneName }
                deletedZones.append(zoneID.zoneName)
            }
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
