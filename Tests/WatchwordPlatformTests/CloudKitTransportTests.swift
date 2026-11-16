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
                FakeCloudKitTransport(database: FakeCloudKitDatabase())
            }
            #expect(violations == [])
        }

        @Test("every save is of a new record with ifServerRecordUnchanged: created once, never modified")
        func createOnly() async throws {
            let database = FakeCloudKitDatabase()
            let transport = FakeCloudKitTransport(database: database)
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
            let transport = FakeCloudKitTransport(database: database)
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
            let transport = FakeCloudKitTransport(database: database)
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
            let transport = FakeCloudKitTransport(database: database)
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
            let transport = FakeCloudKitTransport(database: database)
            #expect(try await transport.list(prefix: "vault/").isEmpty)
            #expect(try await transport.fetch(SyncTransportContract.name, maximumLength: 10) == nil)
            try await transport.delete(SyncTransportContract.name)
            #expect(database.zoneNames.isEmpty)
            try await transport.create(SyncTransportContract.name, contents: [1])
            #expect(database.zoneNames == ["Watchword"])
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
            let transport = FakeCloudKitTransport(database: database)
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
                let transport = CloudKitTransport(database: database, zoneName: "WatchwordTests-\(UUID().uuidString)")
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
