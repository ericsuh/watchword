#if canImport(CloudKit)
    import CloudKit
    import Foundation
    import Testing
    import WatchwordModel
    import WatchwordPlatform
    import WatchwordSync
    import WatchwordTestSupport

    /// `CloudKitTransport` against a hostile store (docs/02-architecture.md §7.2), through the fake database.
    ///
    /// Threat model: **A1, the CloudKit service or anyone with the iCloud account**, able to put any record in the
    /// zone and answer any request: records under names outside the layout, a `name` field that disagrees with the
    /// record, payloads too large, in a plain field, or two at once, and arbitrary errors (a `retryAfterSeconds` of
    /// years). The transport must hand the engine at most what a record under that exact name holds, within the
    /// reader's limit, in one reading, and turn the rest into a typed refusal; how long a stated wait lasts is bounded
    /// by `AutoSyncPolicy`. Runs on a Mac only; required there through its `darwin:` line in `adversarial-suites.txt`.
    @Suite("Adversarial: Apple adapters: CloudKit transport", .tags(.adversarial))
    struct AdversarialCloudKitTransportTests {
        typealias Transport = CloudKitTransport<FakeCloudKitDatabase>

        static let name = SyncObjectLocation.segment(vaultID: UUID(), author: UUID(), sequence: 1).name
        static var prefix: String { String(name.split(separator: "/").prefix(2).joined(separator: "/")) + "/" }

        static func record(_ recordName: String, in transport: Transport, fields: (CKRecord) -> Void) -> CKRecord {
            let record = CKRecord(
                recordType: "WWObject", recordID: CKRecord.ID(recordName: recordName, zoneID: transport.zoneID))
            fields(record)
            return record
        }

        /// A1 plants a record whose `name` field claims another object, and records whose names are not the layout's:
        /// none is listed, and the mislabelled one is refused when fetched.
        @Test("records that are not what their name says are neither listed nor read")
        func mislabelled() async throws {
            let database = FakeCloudKitDatabase()
            let transport = Transport(database: database, marker: InMemorySyncStoreMarker())
            let recordName = try Transport.recordName(for: Self.name)
            let other = Self.prefix + "log/" + UUID().uuidString + "/2"
            database.plant(Self.record(recordName, in: transport) { $0["name"] = other })
            database.plant(Self.record("_planted", in: transport) { $0["name"] = Self.prefix + "x" })
            database.plant(Self.record("vault.a b", in: transport) { $0["name"] = Self.prefix + "y" })
            #expect(try await transport.list(prefix: "").isEmpty)
            await #expect(throws: SyncTransportError.invalidName(Self.name)) {
                try await transport.fetch(Self.name, maximumLength: 100)
            }
        }

        /// A1 stores bytes in a plain field, or both an inline payload and an asset, or more than the reader allows:
        /// the plain field is never read as the object, two readings are refused, and the size is enforced.
        @Test("payloads in a plain field, two payloads, or oversized ones are refused")
        func payloads() async throws {
            let database = FakeCloudKitDatabase()
            let transport = Transport(database: database, marker: InMemorySyncStoreMarker())
            let recordName = try Transport.recordName(for: Self.name)
            database.plant(
                Self.record(recordName, in: transport) {
                    $0["name"] = Self.name
                    $0["payload"] = Data([1, 2, 3])
                })
            #expect(try await transport.fetch(Self.name, maximumLength: 100) == [])

            let file = FileManager.default.temporaryDirectory.appendingPathComponent("ww-adv-\(UUID().uuidString)")
            try Data([4]).write(to: file)
            database.plant(
                Self.record(recordName, in: transport) {
                    $0["name"] = Self.name
                    $0.encryptedValues["payload"] = Data([5])
                    $0["payloadAsset"] = CKAsset(fileURL: file)
                })
            await #expect(throws: SyncTransportError.invalidName(Self.name)) {
                try await transport.fetch(Self.name, maximumLength: 100)
            }

            database.plant(
                Self.record(recordName, in: transport) {
                    $0["name"] = Self.name
                    $0.encryptedValues["payload"] = Data(repeating: 6, count: 101)
                })
            await #expect(throws: SyncTransportError.objectTooLarge(Self.name)) {
                try await transport.fetch(Self.name, maximumLength: 100)
            }
        }

        /// A1 answers a listing with more records than any vault could hold: refused at the cap, not accumulated.
        @Test("a listing larger than the cap is refused")
        func listingCap() async throws {
            let database = FakeCloudKitDatabase(pageLimit: 5)
            let transport = Transport(database: database, marker: InMemorySyncStoreMarker(), maximumListedObjects: 8)
            for sequence in 1...12 {
                let name = Self.prefix + "log/" + UUID().uuidString + "/\(sequence)"
                database.plant(Self.record(try Transport.recordName(for: name), in: transport) { $0["name"] = name })
            }
            await #expect(throws: SyncTransportError.listingTooLarge(Self.prefix)) {
                try await transport.list(prefix: Self.prefix)
            }
        }

        /// A1 answers every page with the same records, or with records that are not the layout's, and always offers
        /// another page: the listing ends at its page and result caps, so the sync stops and the driver's sync ends
        /// (review of the adapters, finding 3).
        @Test("endless cursors of duplicate or invalid records end at the caps")
        func endlessCursor() async throws {
            for invalid in [false, true] {
                let database = FakeCloudKitDatabase(pageLimit: 4)
                database.endless = true
                let transport = Transport(
                    database: database, marker: InMemorySyncStoreMarker(), maximumListedObjects: 50, pageSize: 4)
                for sequence in 1...4 {
                    let name = Self.prefix + "log/" + UUID().uuidString + "/\(sequence)"
                    let recordName = invalid ? "_junk\(sequence)" : try Transport.recordName(for: name)
                    database.plant(Self.record(recordName, in: transport) { $0["name"] = name })
                }
                await #expect(throws: SyncTransportError.listingTooLarge(Self.prefix)) {
                    try await transport.list(prefix: Self.prefix)
                }
                #expect(database.queriedKeys.count <= transport.maximumPages)
            }
        }

        /// A1 plants one record in another device's stream whose asset is gone, hoping the error stops this device's
        /// sync and so keeps it from ever publishing (review of the adapters, finding 4): refused alone, the stream
        /// waits, and this device publishes.
        @Test("one record with a missing asset is refused alone; the device still publishes")
        func brokenRecord() async throws {
            let database = FakeCloudKitDatabase()
            let transport = Transport(database: database, marker: InMemorySyncStoreMarker())
            let keys = FakeAccountKeys(seed: 21)
            let vault = UUID()
            let (writer, other) = (UUID(), UUID())
            await keys.addVaultKey(vaultID: vault)
            await keys.trust(device: writer)
            await keys.trust(device: other)
            let planted = SyncObjectLocation.segment(vaultID: vault, author: other, sequence: 1).name
            let file = FileManager.default.temporaryDirectory.appendingPathComponent("ww-gone-\(UUID().uuidString)")
            try Data([1]).write(to: file)
            let record = Self.record(try Transport.recordName(for: planted), in: transport) {
                $0["name"] = planted
                $0["payloadAsset"] = CKAsset(fileURL: file)
            }
            try FileManager.default.removeItem(at: file)
            database.plant(record)

            let client = SyncTestClient(deviceID: writer, vaultID: vault, keys: keys, transport: transport)
            _ = try await client.save(
                Item(
                    id: UUID(), vaultID: vault, title: "Bank", scopes: [ServiceScope(host: "firstbank.co.uk")],
                    fields: [Field(kind: .password, label: "Password", value: "hunter22")]))
            let report = try await client.sync()
            #expect(!report.transportUnavailable)
            #expect(report.rejected.map(\.reason) == [.transport(.objectUnreadable(planted))])
            #expect(report.segmentsWritten == 1)
        }

        /// A1 asks the client to wait for years: the transport passes the claim on, and the policy holds it to its
        /// maximum backoff, so sync is never switched off by the store.
        @Test("a wait of years asked by the store is held to the policy's maximum")
        func hostileRetryAfter() {
            let error = CloudKitErrors.transportError(
                for: CKError(.requestRateLimited, userInfo: [CKErrorRetryAfterKey: 1e12]), name: "n")
            var state = AutoSyncState()
            let now = Date(timeIntervalSince1970: 1_800_000_000)
            AutoSyncPolicy.record(.unlocked, at: now, in: &state)
            AutoSyncPolicy.record(.syncStarted, at: now, in: &state)
            AutoSyncPolicy.record(.syncThrottled(retryAfter: error.retryAfter), at: now, in: &state)
            #expect(AutoSyncPolicy.backoff(after: state, .standard) == AutoSyncSettings.standard.backoffMaximum)
        }

        /// A1 answers a create with `serverRecordChanged` for a name nobody wrote: the engine is told the object
        /// exists and never retries with an overwriting policy.
        @Test("a refused create is objectExists, and no save ever overwrites")
        func refusedCreate() async throws {
            let database = FakeCloudKitDatabase()
            let transport = Transport(database: database, marker: InMemorySyncStoreMarker())
            try await transport.create(Self.name, contents: [1])
            database.injectFailure(
                CKError(
                    .partialFailure,
                    userInfo: [
                        CKPartialErrorsByItemIDKey: [
                            try transport.recordIDForAdversary(Self.prefix + "log/x/1"): CKError(.serverRecordChanged)
                        ] as [AnyHashable: any Error]
                    ]))
            await #expect(throws: SyncTransportError.objectExists(Self.prefix + "log/x/1")) {
                try await transport.create(Self.prefix + "log/x/1", contents: [2])
            }
            #expect(database.savePolicies.allSatisfy { $0 == .ifServerRecordUnchanged })
        }

        /// A1 (the service, or anyone with the iCloud account) can answer that the zone is gone at will, truthfully or
        /// not: delete it, or say `zoneNotFound` or `userDeletedZone`. No read, create or delete may recreate the
        /// zone on that answer (the person may have deleted the data on purpose), however often it is repeated; only
        /// `startStoreAgain`, which nothing but the person's confirmed decision calls, does, and it uploads nothing
        /// (docs/02-architecture.md §7.10).
        @Test("a faked reset recreates nothing however often it is answered; only startStoreAgain does")
        func fakedReset() async throws {
            let database = FakeCloudKitDatabase()
            let transport = Transport(database: database, marker: InMemorySyncStoreMarker())
            try await transport.create(Self.name, contents: [1])
            database.purgeZone("Watchword")
            let saves = database.savedZones
            for _ in 0..<5 {
                await #expect(throws: SyncTransportError.storeReset) { try await transport.list(prefix: "") }
                await #expect(throws: SyncTransportError.storeReset) {
                    try await transport.create(Self.name, contents: [1])
                }
                await #expect(throws: SyncTransportError.storeReset) { try await transport.delete(Self.name) }
            }
            for error in [CKError(.userDeletedZone), CKError(.zoneNotFound)] {
                database.injectFailure(error)
                await #expect(throws: SyncTransportError.storeReset) { try await transport.list(prefix: "") }
            }
            #expect(database.savedZones == saves && database.zoneNames.isEmpty)

            try await transport.startStoreAgain()
            #expect(database.zoneNames == ["Watchword"])
            #expect(try await transport.list(prefix: "").isEmpty)
        }

        /// A1 answers "the zone is gone" to a device whose zone is in fact there and full, hoping the person's yes
        /// wipes it: `startStoreAgain` deletes a zone only on CloudKit's own word that its key was reset, and a zone
        /// it finds present it leaves alone.
        @Test("startStoreAgain never deletes a zone that answers, whatever was said before")
        func startingAgainDeletesNothingThatAnswers() async throws {
            let database = FakeCloudKitDatabase()
            let transport = Transport(database: database, marker: InMemorySyncStoreMarker())
            try await transport.create(Self.name, contents: [7])
            database.injectFailure(CKError(.zoneNotFound))
            await #expect(throws: SyncTransportError.storeReset) { try await transport.list(prefix: "") }
            try await transport.startStoreAgain()
            #expect(database.deletedZones.isEmpty)
            #expect(try await transport.fetch(Self.name, maximumLength: 10) == [7])
        }

        /// Threat: review finding SR30, two of the person's devices (or the person twice) answering "Upload Again" at
        /// once after a real key reset, or CloudKit setting the reset flag while iCloud Keychain is still syncing.
        /// Device A deletes the zone, saves it and uploads; device B, which saw the reset a moment before, deletes the
        /// zone again and with it A's fresh upload. `startStoreAgain` looks again just before deleting and leaves a
        /// zone that reads by then. Here A acts between B's two looks.
        @Test("a zone another device started again between the two looks is not deleted")
        func concurrentStartAgain() async throws {
            let database = FakeCloudKitDatabase()
            let transport = Transport(database: database, marker: InMemorySyncStoreMarker())
            try await transport.create(Self.name, contents: [1])
            database.resetEncryptionKey(of: "Watchword")
            let other = Transport(database: database, marker: InMemorySyncStoreMarker())
            let upload = CKRecord(recordType: "WWObject", recordID: try other.recordIDForAdversary(Self.name))
            upload["name"] = Self.name
            upload.encryptedValues["payload"] = Data([2])
            database.onCall(.fetchZone, number: 2) {
                // Device A: deleted the reset zone, saved it again, uploaded.
                database.purgeZone("Watchword")
                database.plant(upload)
            }
            try await transport.startStoreAgain()
            #expect(database.deletedZones.isEmpty, "B deleted nothing")
            #expect(try await transport.fetch(Self.name, maximumLength: 10) == [2], "A's upload stands")
        }

        /// Threat: review finding SR30's second route. CloudKit (or A1 speaking for it) answers the reset once and then
        /// reads normally: a flag that cleared. The zone is not deleted on one answer the second look contradicts.
        @Test("a reset answered once and contradicted by the second look deletes nothing")
        func spuriousResetFlag() async throws {
            let database = FakeCloudKitDatabase()
            let transport = Transport(database: database, marker: InMemorySyncStoreMarker())
            try await transport.create(Self.name, contents: [7])
            database.injectFailure(FakeCloudKitDatabase.resetError, on: .query)
            try await transport.startStoreAgain()
            #expect(database.deletedZones.isEmpty)
            #expect(try await transport.fetch(Self.name, maximumLength: 10) == [7])
        }

        /// Threat: review finding SR29, a store reporting a key reset record by record in a listing's results. Taken
        /// as junk records, the listing came back empty and the zone was marked seen; the reset is a reset however it
        /// is reported.
        @Test("a reset reported record by record stops the listing as a reset")
        func resetPerRecord() async throws {
            let database = FakeCloudKitDatabase()
            database.resetReporting = .perRecord
            let transport = Transport(database: database, marker: InMemorySyncStoreMarker())
            try await transport.create(Self.name, contents: [1])
            database.resetEncryptionKey(of: "Watchword")
            await #expect(throws: SyncTransportError.storeReset) { try await transport.list(prefix: "") }
            try await transport.startStoreAgain()
            #expect(database.deletedZones == ["Watchword"])
            #expect(try await transport.list(prefix: "").isEmpty)
        }
    }

    extension CloudKitTransport {
        func recordIDForAdversary(_ name: String) throws -> CKRecord.ID {
            CKRecord.ID(recordName: try Self.recordName(for: name), zoneID: zoneID)
        }
    }
#endif
