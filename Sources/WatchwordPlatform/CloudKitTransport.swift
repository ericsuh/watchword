#if canImport(CloudKit)
    import CloudKit
    import Foundation
    import WatchwordSync

    /// The part of `CKDatabase` the CloudKit transport uses, and nothing more: the seam its tests replace with a fake,
    /// since a real database needs a signed app with the iCloud entitlement (docs/04-test-plan.md). The production
    /// conformance, `SystemCloudKitDatabase`, only forwards each call, so every decision the transport makes — names,
    /// fields, the save policy, what an error means — is in `CloudKitTransport` and exercised against the fake.
    public protocol CloudKitDatabase: Sendable {
        /// A query page's continuation (`CKQueryOperation.Cursor` for the real database).
        associatedtype Cursor

        /// One page of `query` in `zoneID`, or the page after `cursor`.
        func records(
            matching query: CKQuery, inZoneWith zoneID: CKRecordZone.ID, desiredKeys: [CKRecord.FieldKey],
            resultsLimit: Int, continuing cursor: Cursor?
        ) async throws -> (matchResults: [(CKRecord.ID, Result<CKRecord, any Error>)], cursor: Cursor?)

        func record(for recordID: CKRecord.ID) async throws -> CKRecord

        func modifyRecords(
            saving recordsToSave: [CKRecord], deleting recordIDsToDelete: [CKRecord.ID],
            savePolicy: CKModifyRecordsOperation.RecordSavePolicy, atomically: Bool
        ) async throws -> (
            saveResults: [CKRecord.ID: Result<CKRecord, any Error>],
            deleteResults: [CKRecord.ID: Result<Void, any Error>]
        )

        /// Creates the zone, or does nothing if it exists.
        func saveZone(_ zone: CKRecordZone) async throws
    }

    /// `CKDatabase` as a `CloudKitDatabase`: each call forwarded, nothing decided.
    public struct SystemCloudKitDatabase: CloudKitDatabase {
        public let database: CKDatabase

        public init(_ database: CKDatabase) {
            self.database = database
        }

        /// The private database of the container (§7.2: the account's own zones live there). Creating a `CKContainer`
        /// traps in a process without the iCloud entitlement, so nothing calls this but the app and an explicitly
        /// enabled integration test.
        public static func privateDatabase(containerIdentifier: String) -> SystemCloudKitDatabase {
            SystemCloudKitDatabase(CKContainer(identifier: containerIdentifier).privateCloudDatabase)
        }

        public func records(
            matching query: CKQuery, inZoneWith zoneID: CKRecordZone.ID, desiredKeys: [CKRecord.FieldKey],
            resultsLimit: Int, continuing cursor: CKQueryOperation.Cursor?
        ) async throws -> (matchResults: [(CKRecord.ID, Result<CKRecord, any Error>)], cursor: CKQueryOperation.Cursor?)
        {
            if let cursor {
                let page = try await database.records(
                    continuingMatchFrom: cursor, desiredKeys: desiredKeys, resultsLimit: resultsLimit)
                return (page.matchResults, page.queryCursor)
            }
            let page = try await database.records(
                matching: query, inZoneWith: zoneID, desiredKeys: desiredKeys, resultsLimit: resultsLimit)
            return (page.matchResults, page.queryCursor)
        }

        public func record(for recordID: CKRecord.ID) async throws -> CKRecord {
            try await database.record(for: recordID)
        }

        public func modifyRecords(
            saving recordsToSave: [CKRecord], deleting recordIDsToDelete: [CKRecord.ID],
            savePolicy: CKModifyRecordsOperation.RecordSavePolicy, atomically: Bool
        ) async throws -> (
            saveResults: [CKRecord.ID: Result<CKRecord, any Error>],
            deleteResults: [CKRecord.ID: Result<Void, any Error>]
        ) {
            try await database.modifyRecords(
                saving: recordsToSave, deleting: recordIDsToDelete, savePolicy: savePolicy, atomically: atomically)
        }

        public func saveZone(_ zone: CKRecordZone) async throws {
            let results = try await database.modifyRecordZones(saving: [zone], deleting: [])
            if let result = results.saveResults[zone.zoneID] { _ = try result.get() }
        }
    }

    /// The CloudKit transport (docs/02-architecture.md §7.2): each sync object one record in a custom zone of the
    /// private database, created once and never modified.
    ///
    /// - **Records.** Type `WWObject`, record name the object's name with `/` written `.` (both alphabets are the
    ///   layout's letters, digits and `-`, so the mapping is exact both ways). Two fields: `name`, plain and queryable
    ///   (it says no more than the record name, which §7.5 already gives the store), and the object's bytes in
    ///   `encryptedValues["payload"]`, so CloudKit adds its own Keychain-based layer over the envelope; an object over
    ///   `inlineLimit` goes in a `CKAsset` instead (`payloadAsset`), as a record's own fields are capped near 1 MB.
    ///   The architecture's `kind`, `lamport` and `deviceID` fields are not written: the name already carries them,
    ///   and nothing queries them.
    /// - **Create only.** A save is of a new `CKRecord` (no change tag) with `.ifServerRecordUnchanged`, which CloudKit
    ///   refuses with `serverRecordChanged` if the record exists, mapped to `objectExists`. Nothing fetched is ever saved
    ///   back. Deletion is by record ID.
    /// - **Listing** is a query on `name BEGINSWITH prefix`, asking for the `name` field only and following the
    ///   cursor, at most `maximumListedObjects` names. A record is listed only if its record name is in the layout, its
    ///   `name` field agrees with it, and it has the prefix.
    /// - **Reading** checks the record's type and `name` against the ID asked for, takes exactly one payload (inline or
    ///   asset; a record with both, or with bytes over the limit, is refused), and never reads a plain field as a
    ///   payload.
    /// - **The zone** is created when a create finds it missing, never on a read: a listing or fetch in a zone that does
    ///   not exist is empty. A zone the person deleted (`userDeletedZone`) or whose encryption key CloudKit reset is
    ///   `storeReset` and is never recreated silently (§7.2 says the person is asked; that flow is not built).
    /// - **Errors** map to `SyncTransportError` (`CloudKitErrors`): throttling with its `retryAfterSeconds`, a full
    ///   store, a missing account, the network.
    ///
    /// Every security decision is the engine's: this type only maps names and errors. Not built: `CKSyncEngine`
    /// scheduling and push (the app's `AutoSyncPolicy` driver takes a push as a remote-change hint), shared-database
    /// zones for shared vaults (milestone 4), and re-uploading after a reset.
    public struct CloudKitTransport<Database: CloudKitDatabase>: SyncTransport {
        public static var recordType: CKRecord.RecordType { "WWObject" }
        public static var nameField: CKRecord.FieldKey { "name" }
        public static var payloadField: CKRecord.FieldKey { "payload" }
        public static var assetField: CKRecord.FieldKey { "payloadAsset" }
        /// Objects up to this size are stored inline, encrypted; larger ones as an asset.
        public static var inlineLimit: Int { 512 << 10 }
        public static var defaultZoneName: String { "Watchword" }

        public let database: Database
        public let zoneName: String
        public let maximumListedObjects: Int
        /// The page size asked of each query.
        public let pageSize: Int

        public init(
            database: Database, zoneName: String = CloudKitTransport.defaultZoneName,
            maximumListedObjects: Int = 200_000, pageSize: Int = 400
        ) {
            self.database = database
            self.zoneName = zoneName
            self.maximumListedObjects = maximumListedObjects
            self.pageSize = pageSize
        }

        public var zoneID: CKRecordZone.ID {
            CKRecordZone.ID(zoneName: zoneName, ownerName: CKCurrentUserDefaultName)
        }

        // MARK: - Names

        /// The record name for an object name: `/` becomes `.`. Throws `invalidName` for anything outside the layout.
        public static func recordName(for name: String) throws -> String {
            let components = name.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            guard !components.isEmpty, components.allSatisfy(FileSyncTransport.isValidComponent), name.utf8.count <= 255
            else { throw SyncTransportError.invalidName(name) }
            return components.joined(separator: ".")
        }

        /// The object name a record name stands for, or `nil` if it is not one this transport writes.
        public static func objectName(forRecordName recordName: String) -> String? {
            let components = recordName.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            guard !components.isEmpty, components.allSatisfy(FileSyncTransport.isValidComponent) else { return nil }
            return components.joined(separator: "/")
        }

        func recordID(for name: String) throws -> CKRecord.ID {
            CKRecord.ID(recordName: try Self.recordName(for: name), zoneID: zoneID)
        }

        // MARK: - SyncTransport

        public func list(prefix: String) async throws -> [String] {
            guard prefix.utf8.count <= 255,
                prefix.split(separator: "/", omittingEmptySubsequences: false).allSatisfy({
                    $0.isEmpty || FileSyncTransport.isValidComponent(String($0))
                })
            else { throw SyncTransportError.invalidName(prefix) }
            let predicate =
                prefix.isEmpty
                ? NSPredicate(value: true) : NSPredicate(format: "%K BEGINSWITH %@", Self.nameField, prefix)
            let query = CKQuery(recordType: Self.recordType, predicate: predicate)
            var names: Set<String> = []
            var cursor: Database.Cursor?
            repeat {
                let page: (matchResults: [(CKRecord.ID, Result<CKRecord, any Error>)], cursor: Database.Cursor?)
                do {
                    page = try await database.records(
                        matching: query, inZoneWith: zoneID, desiredKeys: [Self.nameField], resultsLimit: pageSize,
                        continuing: cursor)
                } catch let error as CKError where error.code == .zoneNotFound && !CloudKitErrors.isReset(error) {
                    return []  // Nothing was ever created here.
                } catch {
                    throw CloudKitErrors.transportError(for: error, name: prefix)
                }
                for (id, result) in page.matchResults {
                    guard case .success(let record) = result, let name = Self.objectName(forRecordName: id.recordName),
                        id.zoneID == zoneID, name.hasPrefix(prefix), record.recordType == Self.recordType,
                        record[Self.nameField] as? String == name
                    else { continue }
                    names.insert(name)
                }
                guard names.count <= maximumListedObjects else { throw SyncTransportError.objectTooLarge(prefix) }
                cursor = page.cursor
            } while cursor != nil
            return names.sorted()
        }

        public func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
            let id = try recordID(for: name)
            let record: CKRecord
            do {
                record = try await database.record(for: id)
            } catch let error as CKError
                where error.code == .unknownItem || (error.code == .zoneNotFound && !CloudKitErrors.isReset(error))
            {
                return nil
            } catch {
                throw CloudKitErrors.transportError(for: error, name: name)
            }
            guard record.recordID == id, record.recordType == Self.recordType,
                record[Self.nameField] as? String == name
            else { throw SyncTransportError.invalidName(name) }
            let inline = record.encryptedValues[Self.payloadField] as? Data
            let asset = record[Self.assetField] as? CKAsset
            switch (inline, asset) {
            case (let data?, nil):
                guard data.count <= maximumLength else { throw SyncTransportError.objectTooLarge(name) }
                return Array(data)
            case (nil, let asset?):
                guard let url = asset.fileURL else { throw SyncTransportError.unavailable }
                return try Self.readAsset(at: url, name: name, maximumLength: maximumLength)
            case (nil, nil):
                return []  // No payload: the engine refuses it as malformed.
            case (.some, .some):
                throw SyncTransportError.invalidName(name)  // Two readings of one object.
            }
        }

        public func create(_ name: String, contents: [UInt8]) async throws {
            let id = try recordID(for: name)
            let record = CKRecord(recordType: Self.recordType, recordID: id)
            record[Self.nameField] = name
            var assetFile: URL?
            defer { if let assetFile { try? FileManager.default.removeItem(at: assetFile) } }
            if contents.count <= Self.inlineLimit {
                record.encryptedValues[Self.payloadField] = Data(contents)
            } else {
                let file = FileManager.default.temporaryDirectory.appendingPathComponent(
                    "watchword-asset-\(UUID().uuidString)", isDirectory: false)
                try Data(contents).write(to: file, options: [.atomic])
                assetFile = file
                record[Self.assetField] = CKAsset(fileURL: file)
            }
            do {
                try await save(record, name: name)
            } catch let error as CKError where error.code == .zoneNotFound && !CloudKitErrors.isReset(error) {
                do {
                    try await database.saveZone(CKRecordZone(zoneID: zoneID))
                } catch {
                    throw CloudKitErrors.transportError(for: error, name: name)
                }
                do {
                    try await save(record, name: name)
                } catch {
                    throw CloudKitErrors.transportError(for: error, name: name)
                }
            } catch {
                throw CloudKitErrors.transportError(for: error, name: name)
            }
        }

        /// Saves a new record so that it fails if one is there already. Throws the record's own `CKError`.
        private func save(_ record: CKRecord, name: String) async throws {
            let results:
                (
                    saveResults: [CKRecord.ID: Result<CKRecord, any Error>],
                    deleteResults: [CKRecord.ID: Result<Void, any Error>]
                )
            do {
                results = try await database.modifyRecords(
                    saving: [record], deleting: [], savePolicy: .ifServerRecordUnchanged, atomically: true)
            } catch let error as CKError where error.code == .partialFailure {
                // The one record's own error, so a missing zone is seen as such.
                throw error.partialErrorsByItemID?[record.recordID] ?? error
            }
            guard let result = results.saveResults[record.recordID] else { throw SyncTransportError.unavailable }
            _ = try result.get()
        }

        public func delete(_ name: String) async throws {
            let id = try recordID(for: name)
            do {
                let results = try await database.modifyRecords(
                    saving: [], deleting: [id], savePolicy: .ifServerRecordUnchanged, atomically: true)
                if let result = results.deleteResults[id] { try result.get() }
            } catch {
                // Gone already, or never there: deleted.
                if CloudKitErrors.isAbsence(error) { return }
                throw CloudKitErrors.transportError(for: error, name: name)
            }
        }

        static func readAsset(at url: URL, name: String, maximumLength: Int) throws -> [UInt8] {
            let size = (try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.intValue ?? 0
            guard size <= maximumLength else { throw SyncTransportError.objectTooLarge(name) }
            let handle = try FileHandle(forReadingFrom: url)
            defer { try? handle.close() }
            let data = try handle.read(upToCount: maximumLength + 1) ?? Data()
            guard data.count <= maximumLength else { throw SyncTransportError.objectTooLarge(name) }
            return Array(data)
        }
    }

    /// What a CloudKit error means to the sync engine (docs/02-architecture.md §7.2).
    public enum CloudKitErrors {
        /// `zoneNotFound` that CloudKit marks as a reset of its own encryption key: the data is gone, not absent.
        public static func isReset(_ error: CKError) -> Bool {
            error.userInfo[CKErrorUserDidResetEncryptedDataKeyKey] as? Bool == true
        }

        /// Whether a (possibly partial) failure says only that the record or its zone is not there.
        static func isAbsence(_ error: any Error) -> Bool {
            guard let error = error as? CKError else { return false }
            if error.code == .partialFailure, let inner = error.partialErrorsByItemID?.values.first {
                return isAbsence(inner)
            }
            return error.code == .unknownItem || (error.code == .zoneNotFound && !isReset(error))
        }

        /// The `SyncTransportError` for `error`, met while working on the object (or prefix) `name`.
        public static func transportError(for error: any Error, name: String) -> SyncTransportError {
            if let error = error as? SyncTransportError { return error }
            guard let error = error as? CKError else { return .unavailable }
            switch error.code {
            case .partialFailure:
                // One record per operation: its own error is the answer.
                guard let inner = error.partialErrorsByItemID?.values.first else { return .unavailable }
                return transportError(for: inner, name: name)
            case .serverRecordChanged:
                return .objectExists(name)
            case .requestRateLimited, .zoneBusy, .serviceUnavailable:
                return .rateLimited(retryAfter: error.retryAfterSeconds)
            case .quotaExceeded:
                return .quotaExceeded
            case .notAuthenticated, .accountTemporarilyUnavailable, .managedAccountRestricted:
                return .notAuthenticated
            case .userDeletedZone:
                return .storeReset
            case .zoneNotFound:
                return isReset(error) ? .storeReset : .unavailable
            case .networkUnavailable, .networkFailure, .serverResponseLost, .operationCancelled, .assetNotAvailable,
                .assetFileNotFound, .assetFileModified:
                return .unavailable
            case .permissionFailure:
                return .forbidden(name)
            case .limitExceeded:
                return .objectTooLarge(name)
            default:
                // A configuration or programming error (badContainer, missingEntitlement, invalidArguments,
                // serverRejectedRequest, internalError, ...): retrying will not help, and nothing is overwritten.
                return .forbidden(name)
            }
        }
    }
#endif
