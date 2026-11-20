#if canImport(CloudKit)
    import CloudKit
    import Foundation
    import Testing
    import WatchwordPlatform
    import WatchwordSync
    import WatchwordTestSupport

    typealias FakeCloudKitTransport = CloudKitTransport<FakeCloudKitDatabase>

    /// `CloudKitTransport` over the fake database (docs/02-architecture.md §7.2): the transport contract, the record
    /// layout, create-only saves, paging, assets, the zone, and what each CloudKit error means. The real database is
    /// the integration test below, which needs the iCloud entitlement and runs only when asked.
    @Suite("CloudKit transport")
    struct CloudKitTransportTests {
        @Test("keeps the sync transport contract over the fake database")
        func contract() async throws {
            let violations = try await SyncTransportContract.violations {
                FakeCloudKitTransport(database: FakeCloudKitDatabase(), marker: InMemorySyncStoreMarker())
            }
            #expect(violations == [])
        }

        @Test("every save is of a new record with ifServerRecordUnchanged: created once, never modified")
        func createOnly() async throws {
            let database = FakeCloudKitDatabase()
            let transport = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            let name = SyncTransportContract.name
            try await transport.create(name, contents: [1])
            await #expect(throws: SyncTransportError.objectExists(name)) {
                try await transport.create(name, contents: [2])
            }
            _ = try await transport.fetch(name, maximumLength: 10)
            try await transport.create(SyncTransportContract.name + "0", contents: [3])
            #expect(!database.savePolicies.isEmpty)
            #expect(database.savePolicies.allSatisfy { $0 == .ifServerRecordUnchanged })
            #expect(database.savedChangeTags.allSatisfy { $0 == nil })
            #expect(try await transport.fetch(name, maximumLength: 10) == [1])
        }

        @Test("a record holds the name in plain and the bytes encrypted; the record name is the name with dots")
        func layout() async throws {
            let database = FakeCloudKitDatabase()
            let transport = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            let name = SyncTransportContract.name
            try await transport.create(name, contents: [9, 8, 7])
            let id = CKRecord.ID(
                recordName: name.replacingOccurrences(of: "/", with: "."), zoneID: transport.zoneID)
            let record = try #require(database.storedRecord(id))
            #expect(record.recordType == "WWObject")
            #expect(record["name"] as? String == name)
            #expect(record.encryptedValues["payload"] as? Data == Data([9, 8, 7]))
            #expect(record["payloadAsset"] == nil)
            #expect(record.recordID.zoneID.zoneName == "Watchword")
            #expect(record.recordID.zoneID.ownerName == CKCurrentUserDefaultName)
        }

        @Test("names map to record names and back exactly; anything outside the layout is refused")
        func names() throws {
            let name = SyncTransportContract.name
            let recordName = try FakeCloudKitTransport.recordName(for: name)
            #expect(!recordName.contains("/"))
            #expect(FakeCloudKitTransport.objectName(forRecordName: recordName) == name)
            for bad in ["", "vault/../x", "vault/a.b", "vault//x", "_system", "vault/x y"] {
                #expect(throws: SyncTransportError.invalidName(bad)) { try FakeCloudKitTransport.recordName(for: bad) }
            }
            #expect(FakeCloudKitTransport.objectName(forRecordName: "_defaultZone") == nil)
            #expect(FakeCloudKitTransport.objectName(forRecordName: "a..b") == nil)
        }

        @Test("a listing follows every page and asks for the name field only")
        func paging() async throws {
            let database = FakeCloudKitDatabase(pageLimit: 2)
            let transport = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            let names = (1...7).map {
                SyncObjectLocation.segment(
                    vaultID: SyncTransportContract.vault, author: SyncTransportContract.deviceA, sequence: UInt64($0)
                ).name
            }
            for name in names { try await transport.create(name, contents: [1]) }
            #expect(try await transport.list(prefix: SyncTransportContract.prefix) == names.sorted())
            #expect(database.queriedKeys.count >= 4)
            #expect(database.queriedKeys.allSatisfy { $0 == ["name"] })
        }

        @Test("an object over the inline limit is an asset, and round-trips within the reader's limit")
        func asset() async throws {
            let database = FakeCloudKitDatabase()
            let transport = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            let name = SyncTransportContract.name
            let contents = (0..<(FakeCloudKitTransport.inlineLimit + 1)).map { UInt8(truncatingIfNeeded: $0) }
            try await transport.create(name, contents: contents)
            let record = try #require(database.storedRecord(try transport.recordIDForTests(name)))
            #expect(record["payloadAsset"] is CKAsset)
            #expect(record.encryptedValues["payload"] == nil)
            #expect(try await transport.fetch(name, maximumLength: contents.count) == contents)
            await #expect(throws: SyncTransportError.objectTooLarge(name)) {
                try await transport.fetch(name, maximumLength: contents.count - 1)
            }
        }

        @Test("reads in a zone never created are empty and create nothing; the first create makes the zone")
        func zone() async throws {
            let database = FakeCloudKitDatabase()
            let transport = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            #expect(try await transport.list(prefix: "vault/").isEmpty)
            #expect(try await transport.fetch(SyncTransportContract.name, maximumLength: 10) == nil)
            try await transport.delete(SyncTransportContract.name)
            #expect(database.zoneNames.isEmpty)
            try await transport.create(SyncTransportContract.name, contents: [1])
            #expect(database.zoneNames == ["Watchword"])
        }

        /// A marker that cannot be read, as on a damaged or locked file system.
        actor BrokenMarker: SyncStoreMarker {
            struct Broken: Error {}
            func hasSeen(_ store: String) throws -> Bool { throw Broken() }
            func markSeen(_ store: String) throws { throw Broken() }
            func forget(_ store: String) throws { throw Broken() }
        }

        /// The person deletes the app's iCloud data in Settings, which purges the zone; CloudKit then answers
        /// `zoneNotFound` without the reset flag (review of the adapters, finding 2). A device that created the zone, or
        /// saw it while listing, must read that as a reset: never recreate it and never list it as empty.
        @Test("a zone this device has seen and then finds missing is a reset; it is never recreated")
        func deletedByThePerson() async throws {
            let database = FakeCloudKitDatabase()
            let creator = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            let reader = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            let name = SyncTransportContract.name
            try await creator.create(name, contents: [1])
            #expect(try await reader.list(prefix: "vault/") == [name])
            database.purgeZone("Watchword")

            for transport in [creator, reader] {
                await #expect(throws: SyncTransportError.storeReset) { try await transport.list(prefix: "vault/") }
                await #expect(throws: SyncTransportError.storeReset) {
                    try await transport.fetch(name, maximumLength: 10)
                }
                await #expect(throws: SyncTransportError.storeReset) { try await transport.delete(name) }
                await #expect(throws: SyncTransportError.storeReset) {
                    try await transport.create(name + "0", contents: [2])
                }
            }
            #expect(database.zoneNames.isEmpty)

            // A device that never saw the zone (a marker of its own) creates it with its first write, as ever.
            let fresh = InMemorySyncStoreMarker()
            let restarted = FakeCloudKitTransport(database: database, marker: fresh)
            try await restarted.create(name, contents: [3])
            #expect(database.zoneNames == ["Watchword"])
            #expect(await fresh.hasSeen(restarted.markerName))
        }

        /// The person's confirmed decision to upload again (docs/02-architecture.md §7.10): `startStoreAgain`
        /// creates the zone this device had seen and found missing, uploads nothing, and keeps the marker, so a
        /// second deletion is a reset again.
        @Test("startStoreAgain recreates a zone that was deleted, uploads nothing, and keeps the marker")
        func startingAgain() async throws {
            let database = FakeCloudKitDatabase()
            let marker = InMemorySyncStoreMarker()
            let transport = FakeCloudKitTransport(database: database, marker: marker)
            let name = SyncTransportContract.name
            try await transport.create(name, contents: [1])
            database.purgeZone("Watchword")
            await #expect(throws: SyncTransportError.storeReset) { try await transport.list(prefix: "vault/") }

            try await transport.startStoreAgain()
            #expect(database.zoneNames == ["Watchword"] && database.deletedZones.isEmpty)
            #expect(try await transport.list(prefix: "").isEmpty)
            #expect(await marker.hasSeen(transport.markerName))
            try await transport.create(name, contents: [2])
            #expect(try await transport.fetch(name, maximumLength: 10) == [2])

            database.purgeZone("Watchword")
            await #expect(throws: SyncTransportError.storeReset) { try await transport.list(prefix: "vault/") }
        }

        /// Another device started the store again first, or the zone was never gone: nothing in it is touched.
        @Test("startStoreAgain leaves a zone that exists, and every record in it, as it is")
        func startingAgainOverAnExistingZone() async throws {
            let database = FakeCloudKitDatabase()
            let transport = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            let name = SyncTransportContract.name
            try await transport.create(name, contents: [1])
            let zoneSaves = database.savedZones
            let queries = database.queries.count
            try await transport.startStoreAgain()
            #expect(database.savedZones == zoneSaves && database.deletedZones.isEmpty)
            // One record per prefix, in a listing's shape: never a TRUEPREDICATE query, which needs an index nothing
            // else needs (SR20). The records are read, payload and all, since only they show a key reset (SR26, SR29):
            // the query asks for the encrypted field, and the record it lists is fetched whole.
            let probes = database.queries.dropFirst(queries)
            #expect(!probes.isEmpty && probes.count <= 3)
            #expect(probes.allSatisfy { $0.limit == 1 && $0.predicate.contains("BEGINSWITH") })
            #expect(database.queriedKeys.suffix(probes.count).allSatisfy { $0.contains("payload") })
            #expect(database.callCount(.fetchRecord) == 1)
            #expect(try await transport.fetch(name, maximumLength: 10) == [1])
        }

        /// CloudKit reset the key that protected the zone: the zone is still there, its metadata fetches, its records
        /// answer `zoneNotFound` with the reset key, and Apple prescribes deleting it before saving it again. Only
        /// then, and only on this call. Review finding SR26: a probe that only fetched the zone found it present and
        /// left it, so the listings kept answering the reset and the person was asked again at every sync. Review
        /// finding SR29: the probe that replaced it asked for the plain `name` field only, so if CloudKit reports the
        /// reset only when encrypted fields are read, it found a readable page and left the zone just the same. The
        /// documentation does not settle which, so the fake answers each way, and the transport must start again under
        /// each. (Unverified against CloudKit itself until a Mac run.)
        @Test(
            "a zone whose encryption key was reset is deleted and saved again by startStoreAgain alone",
            arguments: FakeCloudKitDatabase.ResetReporting.allCases)
        func startingAgainAfterAKeyReset(_ reporting: FakeCloudKitDatabase.ResetReporting) async throws {
            let database = FakeCloudKitDatabase()
            database.resetReporting = reporting
            let transport = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            try await transport.create(SyncTransportContract.name, contents: [1])
            database.resetEncryptionKey(of: "Watchword")
            if reporting == .encryptedFieldsOnly {
                // The listing asks for names only, and lists; the fetch reads the payload, and answers the reset.
                #expect(try await transport.list(prefix: "vault/") == [SyncTransportContract.name])
            } else {
                await #expect(throws: SyncTransportError.storeReset) { try await transport.list(prefix: "vault/") }
            }
            await #expect(throws: SyncTransportError.storeReset) {
                try await transport.fetch(SyncTransportContract.name, maximumLength: 10)
            }
            #expect(database.deletedZones.isEmpty && database.zoneNames == ["Watchword"])

            try await transport.startStoreAgain()
            #expect(database.deletedZones == ["Watchword"] && database.zoneNames == ["Watchword"])
            #expect(try await transport.list(prefix: "").isEmpty)
            try await transport.create(SyncTransportContract.name, contents: [2])
            #expect(try await transport.fetch(SyncTransportContract.name, maximumLength: 10) == [2])
        }

        /// Review finding SR20: after a key reset the zone may already be gone by the time it is deleted, and CloudKit
        /// then answers the deletion with `zoneNotFound` (or `userDeletedZone`, `unknownItem`). Taken as a failure,
        /// every retry would repeat it and the store could never be started again. Taken as done, the zone is saved.
        @Test(
            "a key reset whose zone is already gone when deleted is still started again",
            arguments: [CKError.Code.zoneNotFound, .userDeletedZone, .unknownItem])
        func startingAgainAfterAKeyResetWithTheZoneGone(_ answer: CKError.Code) async throws {
            let database = FakeCloudKitDatabase()
            let transport = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            try await transport.create(SyncTransportContract.name, contents: [1])
            database.purgeZone("Watchword")
            // Both looks at the zone answer the reset (SR30: the second, just before deleting, must agree).
            for _ in 0..<2 { database.injectFailure(FakeCloudKitDatabase.resetError, on: .fetchZone) }
            database.injectFailure(CKError(answer), on: .deleteZone)
            try await transport.startStoreAgain()
            #expect(database.zoneNames == ["Watchword"])
            #expect(try await transport.list(prefix: "").isEmpty)
        }

        /// Review finding SR29: the zone fetches, and then the probe's query fails for a reason that says nothing about
        /// the key (the network, throttling). Nothing is decided on it: the typed error, no deletion, no save, and the
        /// zone is as it was, whether its key was reset or not.
        @Test(
            "a probe query that fails after the zone fetched decides nothing and deletes nothing",
            arguments: [false, true])
        func probeQueryFailsAfterTheZoneFetched(_ keyWasReset: Bool) async throws {
            let database = FakeCloudKitDatabase()
            let transport = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            try await transport.create(SyncTransportContract.name, contents: [1])
            if keyWasReset { database.resetEncryptionKey(of: "Watchword") }
            let zoneSaves = database.savedZones
            database.injectFailure(CKError(.networkUnavailable), on: .query)
            await #expect(throws: SyncTransportError.unavailable) { try await transport.startStoreAgain() }
            #expect(database.deletedZones.isEmpty && database.savedZones == zoneSaves)
            #expect(database.zoneNames == ["Watchword"])
            if !keyWasReset {
                #expect(try await transport.fetch(SyncTransportContract.name, maximumLength: 10) == [1])
            }
        }

        /// Review finding SR29: an existing zone that lists nothing under any probe prefix is no evidence that its
        /// records can be read, and none that its key was reset: another device may have started it again a moment ago.
        /// It is left as it is, never deleted.
        @Test("an empty zone is left as it is")
        func startingAgainOverAnEmptyZone() async throws {
            let database = FakeCloudKitDatabase()
            let transport = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            try await transport.create(SyncTransportContract.name, contents: [1])
            try await transport.delete(SyncTransportContract.name)
            let zoneSaves = database.savedZones
            let queries = database.queries.count
            try await transport.startStoreAgain()
            #expect(database.deletedZones.isEmpty && database.savedZones == zoneSaves)
            #expect(database.queries.count - queries == 3, "every probe prefix was looked at")
        }

        @Test("startStoreAgain that cannot reach CloudKit throws the typed error and creates nothing")
        func startingAgainOffline() async throws {
            let database = FakeCloudKitDatabase()
            let transport = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            try await transport.create(SyncTransportContract.name, contents: [1])
            database.purgeZone("Watchword")
            database.injectFailure(CKError(.networkUnavailable))
            await #expect(throws: SyncTransportError.unavailable) { try await transport.startStoreAgain() }
            #expect(database.zoneNames.isEmpty)
            await #expect(throws: SyncTransportError.storeReset) { try await transport.list(prefix: "vault/") }
        }

        @Test("a marker that cannot be read counts as seen: a missing zone is a reset, and nothing is created")
        func unreadableMarker() async throws {
            let database = FakeCloudKitDatabase()
            let transport = FakeCloudKitTransport(database: database, marker: BrokenMarker())
            await #expect(throws: SyncTransportError.storeReset) { try await transport.list(prefix: "vault/") }
            await #expect(throws: SyncTransportError.storeReset) {
                try await transport.create(SyncTransportContract.name, contents: [1])
            }
            #expect(database.zoneNames.isEmpty)
        }

        @Test("an asset that is missing is that object's failure alone")
        func missingAsset() async throws {
            let database = FakeCloudKitDatabase()
            let transport = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            let name = SyncTransportContract.name
            try await transport.create(
                name, contents: Array(repeating: 1, count: FakeCloudKitTransport.inlineLimit + 1))
            let record = try #require(database.storedRecord(try transport.recordIDForTests(name)))
            let asset = try #require(record["payloadAsset"] as? CKAsset)
            try FileManager.default.removeItem(at: try #require(asset.fileURL))
            await #expect(throws: SyncTransportError.objectUnreadable(name)) {
                try await transport.fetch(name, maximumLength: 1 << 20)
            }
        }

        /// Pairs of an error and its meaning. A loop rather than test arguments: `CKError` is not declared `Sendable`.
        static var errorCases: [(CKError, SyncTransportError)] {
            [
                (CKError(.requestRateLimited, userInfo: [CKErrorRetryAfterKey: 12.0]), .rateLimited(retryAfter: 12)),
                (CKError(.zoneBusy), .rateLimited(retryAfter: nil)),
                (CKError(.serviceUnavailable, userInfo: [CKErrorRetryAfterKey: 3.0]), .rateLimited(retryAfter: 3)),
                (CKError(.quotaExceeded), .quotaExceeded),
                (CKError(.notAuthenticated), .notAuthenticated),
                (CKError(.accountTemporarilyUnavailable), .notAuthenticated),
                (CKError(.userDeletedZone), .storeReset),
                (CKError(.zoneNotFound, userInfo: [CKErrorUserDidResetEncryptedDataKey: true]), .storeReset),
                (CKError(.networkUnavailable), .unavailable),
                (CKError(.networkFailure), .unavailable),
                (CKError(.serverRecordChanged), .objectExists("n")),
                (CKError(.permissionFailure), .forbidden("n")),
                (CKError(.limitExceeded), .objectTooLarge("n")),
                (CKError(.badContainer), .forbidden("n")),
                (CKError(.assetFileNotFound), .objectUnreadable("n")),
                (CKError(.assetNotAvailable), .objectUnreadable("n")),
                (
                    CKError(
                        .partialFailure,
                        userInfo: [
                            CKPartialErrorsByItemIDKey: ["x": CKError(.quotaExceeded)] as [AnyHashable: any Error]
                        ]),
                    .quotaExceeded
                ),
            ]
        }

        @Test("CloudKit errors map to the transport's typed errors")
        func errors() {
            for (error, expected) in Self.errorCases {
                #expect(CloudKitErrors.transportError(for: error, name: "n") == expected, "\(error.code)")
            }
            #expect(CloudKitErrors.transportError(for: URLError(.timedOut), name: "n") == .unavailable)
        }

        @Test("throttling and a missing account stop the sync; the engine reports why")
        func failuresReachTheReport() async throws {
            let database = FakeCloudKitDatabase()
            let transport = FakeCloudKitTransport(database: database, marker: InMemorySyncStoreMarker())
            let keys = FakeAccountKeys(seed: 13)
            let vault = SyncTransportContract.vault
            await keys.addVaultKey(vaultID: vault)
            await keys.trust(device: SyncTransportContract.deviceA)
            let client = SyncTestClient(
                deviceID: SyncTransportContract.deviceA, vaultID: vault, keys: keys, transport: transport)
            database.injectFailure(CKError(.requestRateLimited, userInfo: [CKErrorRetryAfterKey: 30.0]))
            let throttled = try await client.sync()
            #expect(throttled.transportFailure == .rateLimited(retryAfter: 30))
            database.injectFailure(CKError(.notAuthenticated))
            #expect(try await client.sync().transportFailure == .notAuthenticated)
            #expect(try await client.sync().transportFailure == nil)
        }

        static var cloudKitContainer: String? {
            ProcessInfo.processInfo.environment["WATCHWORD_CLOUDKIT_CONTAINER"]
        }

        /// The real private database. Needs a signed process with the iCloud (CloudKit) entitlement for the named
        /// container and a signed-in account, which `swift test` and CI lack; set `WATCHWORD_CLOUDKIT_CONTAINER` in a
        /// signed host to run it. Its zone is its own and deleted afterwards.
        @Test(
            "keeps the contract against a real CloudKit development container",
            .enabled(
                if: cloudKitContainer != nil,
                "needs the iCloud entitlement and a signed-in account: set WATCHWORD_CLOUDKIT_CONTAINER in a signed host"
            ))
        func realCloudKit() async throws {
            let database = SystemCloudKitDatabase.privateDatabase(
                containerIdentifier: try #require(Self.cloudKitContainer))
            var zones: [CKRecordZone.ID] = []
            let violations = try await SyncTransportContract.violations {
                let transport = CloudKitTransport(
                    database: database, marker: InMemorySyncStoreMarker(),
                    zoneName: "WatchwordTests-\(UUID().uuidString)")
                zones.append(transport.zoneID)
                return transport
            }
            _ = try? await database.database.modifyRecordZones(saving: [], deleting: zones)
            #expect(violations == [])
        }
    }

    extension CloudKitTransport {
        func recordIDForTests(_ name: String) throws -> CKRecord.ID {
            CKRecord.ID(recordName: try Self.recordName(for: name), zoneID: zoneID)
        }
    }
#endif
