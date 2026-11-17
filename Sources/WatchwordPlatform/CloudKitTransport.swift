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

        /// Deletes the zone and every record in it. Called only by `CloudKitTransport.startStoreAgain`, for a zone
        /// whose encryption key CloudKit reset: nothing in it can be read any more.
        func deleteZone(_ zoneID: CKRecordZone.ID) async throws
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

        public func deleteZone(_ zoneID: CKRecordZone.ID) async throws {
            let results = try await database.modifyRecordZones(saving: [], deleting: [zoneID])
            if let result = results.deleteResults[zoneID] { try result.get() }
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
    ///   cursor. A store answering without end (A1: endless cursors, duplicate or invalid records) cannot keep a sync
    ///   running: at most `maximumPages` pages, `2 × maximumListedObjects` raw results and `maximumListedObjects` names,
    ///   past which the listing is `listingTooLarge`, which stops the sync. A record is listed only if its record name
    ///   is in the layout, its `name` field agrees with it, and it has the prefix.
    /// - **Reading** checks the record's type and `name` against the ID asked for, takes exactly one payload (inline or
    ///   asset; a record with both, or with bytes over the limit, is refused), and never reads a plain field as a
    ///   payload. An asset that is missing or not available is `objectUnreadable`: that object is refused alone and its
    ///   stream waits at it; it never stops the sync, so one record A1 breaks cannot keep this device from publishing.
    /// - **The zone.** A zone that does not exist is empty only while this device has never seen it: the first create
    ///   makes it, and creating it or listing it marks it seen in `marker` (`SyncStoreMarker`, on this device). From
    ///   then on a missing zone was deleted — by the person ("delete data" in iCloud settings), or by a reset — and
    ///   every operation is `storeReset`; the transport never recreates it, and never lists it as empty. So is
    ///   `userDeletedZone`, and a zone whose encryption key CloudKit reset. Starting again is the person's decision
    ///   (§7.10): `startStoreAgain`, which no sync calls, is the one place such a zone is created again. The marker is
    ///   kept, not forgotten: the zone has been seen, and a second deletion is a reset like the first.
    /// - **Errors** map to `SyncTransportError` (`CloudKitErrors`): throttling with its `retryAfterSeconds`, a full
    ///   store, a missing account, the network.
    ///
    /// Every security decision is the engine's: this type only maps names and errors. Not built: `CKSyncEngine`
    /// scheduling and push (the app's `AutoSyncDriver` takes a push as a remote-change hint) and shared-database zones
    /// for shared vaults (milestone 4). What is uploaded again after a reset is the session's and the engine's
    /// (`VaultSession.reuploadAfterStoreReset`); this type only recreates the zone when told to.
    public struct CloudKitTransport<Database: CloudKitDatabase>: SyncTransport {
        public static var recordType: CKRecord.RecordType { "WWObject" }
        public static var nameField: CKRecord.FieldKey { "name" }
        public static var payloadField: CKRecord.FieldKey { "payload" }
        public static var assetField: CKRecord.FieldKey { "payloadAsset" }
        /// Objects up to this size are stored inline, encrypted; larger ones as an asset.
        public static var inlineLimit: Int { 512 << 10 }
        public static var defaultZoneName: String { "Watchword" }

        public let database: Database
        public let marker: any SyncStoreMarker
        public let zoneName: String
        public let maximumListedObjects: Int
        /// The page size asked of each query.
        public let pageSize: Int
        /// The most pages one listing follows.
        public let maximumPages: Int

        public init(
            database: Database, marker: any SyncStoreMarker, zoneName: String = CloudKitTransport.defaultZoneName,
            maximumListedObjects: Int = 200_000, pageSize: Int = 400, maximumPages: Int? = nil
        ) {
            self.database = database
            self.marker = marker
            self.zoneName = zoneName
            self.maximumListedObjects = max(0, maximumListedObjects)
            self.pageSize = max(1, pageSize)
            self.maximumPages = maximumPages ?? (max(0, maximumListedObjects) / max(1, pageSize) * 2 + 16)
        }

        public var zoneID: CKRecordZone.ID {
            CKRecordZone.ID(zoneName: zoneName, ownerName: CKCurrentUserDefaultName)
        }

        /// The name under which `marker` remembers this zone.
        public var markerName: String { "cloudkit-" + zoneName }

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

        // MARK: - The zone

        /// Whether this device has seen the zone exist. A marker that cannot be read counts as seen: when in doubt,
        /// never recreate.
        func zoneWasSeen() async -> Bool {
            (try? await marker.hasSeen(markerName)) ?? true
        }

        func markZoneSeen() async {
            if await zoneWasSeen() { return }
            try? await marker.markSeen(markerName)
        }

        /// What a missing zone means: nothing yet (`nil`), or a store that was deleted or reset.
        func missingZone(_ error: any Error) async -> SyncTransportError? {
            guard let zone = CloudKitErrors.zoneNotFound(in: error) else { return nil }
            if CloudKitErrors.isReset(zone) { return .storeReset }
            return await zoneWasSeen() ? .storeReset : nil
        }

        /// Starts the zone again after a reset, on the person's confirmed decision to upload again
        /// (`VaultSession.reuploadAfterStoreReset`, docs/02-architecture.md §7.10): the one place a zone this device
        /// has seen and then found missing is created. It uploads nothing. A zone that exists is left exactly as it
        /// is, whatever it holds (another device may have started it again already). A zone that is missing, or that
        /// CloudKit says the person deleted, is saved again. A zone whose encryption key CloudKit reset still exists
        /// on the server with records nobody can read, so it is deleted first and then saved, which is what Apple
        /// prescribes for `CKErrorUserDidResetEncryptedDataKey` (unverified against CloudKit: this file has not been
        /// run there). The marker is set, never forgotten. Any other failure is the transport's typed error, and the
        /// zone stays as it was.
        public func startStoreAgain() async throws {
            let query = CKQuery(recordType: Self.recordType, predicate: NSPredicate(value: true))
            var keyWasReset = false
            do {
                _ = try await database.records(
                    matching: query, inZoneWith: zoneID, desiredKeys: [Self.nameField], resultsLimit: 1,
                    continuing: nil)
                // The zone is there: nothing to recreate, and nothing in it is touched.
                try? await marker.markSeen(markerName)
                return
            } catch let error where CloudKitErrors.zoneNotFound(in: error) != nil {
                keyWasReset = CloudKitErrors.zoneNotFound(in: error).map(CloudKitErrors.isReset) ?? false
            } catch let error as CKError where error.code == .userDeletedZone {
                keyWasReset = false
            } catch {
                throw CloudKitErrors.transportError(for: error, name: zoneName)
            }
            do {
                if keyWasReset { try await database.deleteZone(zoneID) }
                try await database.saveZone(CKRecordZone(zoneID: zoneID))
            } catch {
                throw CloudKitErrors.transportError(for: error, name: zoneName)
            }
            try? await marker.markSeen(markerName)
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
            var pages = 0
            var results = 0
            repeat {
                guard pages < maximumPages else { throw SyncTransportError.listingTooLarge(prefix) }
                pages += 1
                let page: (matchResults: [(CKRecord.ID, Result<CKRecord, any Error>)], cursor: Database.Cursor?)
                do {
                    page = try await database.records(
                        matching: query, inZoneWith: zoneID, desiredKeys: [Self.nameField], resultsLimit: pageSize,
                        continuing: cursor)
                } catch let error where CloudKitErrors.zoneNotFound(in: error) != nil {
                    if let reset = await missingZone(error) { throw reset }
                    return []  // Never created, and never seen here.
                } catch {
                    throw CloudKitErrors.transportError(for: error, name: prefix)
                }
                results += page.matchResults.count
                guard results <= maximumListedObjects * 2 else { throw SyncTransportError.listingTooLarge(prefix) }
                for (id, result) in page.matchResults {
                    guard case .success(let record) = result, let name = Self.objectName(forRecordName: id.recordName),
                        id.zoneID == zoneID, name.hasPrefix(prefix), record.recordType == Self.recordType,
                        record[Self.nameField] as? String == name
                    else { continue }
                    names.insert(name)
                }
                guard names.count <= maximumListedObjects else { throw SyncTransportError.listingTooLarge(prefix) }
                cursor = page.cursor
            } while cursor != nil
            await markZoneSeen()
            return names.sorted()
        }

        public func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
            let id = try recordID(for: name)
            let record: CKRecord
            do {
                record = try await database.record(for: id)
            } catch let error as CKError where error.code == .unknownItem {
                return nil
            } catch let error where CloudKitErrors.zoneNotFound(in: error) != nil {
                if let reset = await missingZone(error) { throw reset }
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
                guard let url = asset.fileURL else { throw SyncTransportError.objectUnreadable(name) }
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
            } catch let error where CloudKitErrors.zoneNotFound(in: error) != nil {
                // Recreated only if this device has never seen it: otherwise the person deleted it.
                if let reset = await missingZone(error) { throw reset }
                do {
                    try await database.saveZone(CKRecordZone(zoneID: zoneID))
                    try? await marker.markSeen(markerName)
                    try await save(record, name: name)
                } catch {
                    throw CloudKitErrors.transportError(for: error, name: name)
                }
            } catch {
                throw CloudKitErrors.transportError(for: error, name: name)
            }
            await markZoneSeen()
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
            } catch let error where CloudKitErrors.zoneNotFound(in: error) != nil {
                if let reset = await missingZone(error) { throw reset }
            } catch {
                // Gone already: deleted.
                if CloudKitErrors.isUnknownItem(error) { return }
                throw CloudKitErrors.transportError(for: error, name: name)
            }
        }

        /// The asset's bytes within the limit. A file that cannot be read is that object's failure alone.
        static func readAsset(at url: URL, name: String, maximumLength: Int) throws -> [UInt8] {
            do {
                let size =
                    (try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.intValue ?? 0
                guard size <= maximumLength else { throw SyncTransportError.objectTooLarge(name) }
                let handle = try FileHandle(forReadingFrom: url)
                defer { try? handle.close() }
                let data = try handle.read(upToCount: maximumLength + 1) ?? Data()
                guard data.count <= maximumLength else { throw SyncTransportError.objectTooLarge(name) }
                return Array(data)
            } catch let error as SyncTransportError {
                throw error
            } catch {
                throw SyncTransportError.objectUnreadable(name)
            }
        }
    }

    /// What a CloudKit error means to the sync engine (docs/02-architecture.md §7.2).
    public enum CloudKitErrors {
        /// `zoneNotFound` that CloudKit marks as a reset of its own encryption key: the data is gone, not absent.
        public static func isReset(_ error: CKError) -> Bool {
            error.userInfo[CKErrorUserDidResetEncryptedDataKey] as? Bool == true
        }

        /// The `zoneNotFound` error in `error`, directly or as the one record's error of a partial failure.
        static func zoneNotFound(in error: any Error) -> CKError? {
            guard let error = error as? CKError else { return nil }
            if error.code == .partialFailure, let inner = error.partialErrorsByItemID?.values.first {
                return zoneNotFound(in: inner)
            }
            return error.code == .zoneNotFound ? error : nil
        }

        /// Whether a (possibly partial) failure says only that the record is not there.
        static func isUnknownItem(_ error: any Error) -> Bool {
            guard let error = error as? CKError else { return false }
            if error.code == .partialFailure, let inner = error.partialErrorsByItemID?.values.first {
                return isUnknownItem(inner)
            }
            return error.code == .unknownItem
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
            case .networkUnavailable, .networkFailure, .serverResponseLost, .operationCancelled:
                return .unavailable
            case .assetNotAvailable, .assetFileNotFound, .assetFileModified:
                // One object's asset, not the store: refused alone, so it cannot stop this device publishing.
                return .objectUnreadable(name)
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
