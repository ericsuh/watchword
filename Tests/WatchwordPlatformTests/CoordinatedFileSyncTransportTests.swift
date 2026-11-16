#if canImport(Darwin)
    import Foundation
    import Testing
    import WatchwordModel
    import WatchwordPlatform
    import WatchwordSync
    import WatchwordTestSupport

    enum CoordinatedFixtures {
        static func temporaryRoot() -> URL {
            URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
                .appendingPathComponent("watchword-coordinated-\(UUID().uuidString)", isDirectory: true)
        }

        /// Puts iCloud's legacy placeholder for `name` under `root`, as iCloud Drive does for an object another device
        /// wrote that is not downloaded here yet.
        static func plantPlaceholder(for name: String, in root: URL) throws {
            let url = try FileSyncTransport(root: root).fileURL(for: name)
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data([0]).write(to: FileSyncTransport.placeholderURL(for: url))
        }

        /// The first `onChange` from a presenter, or `false` after `timeout` (a bound on waiting for an event, not a
        /// delay the test depends on).
        static func firstEvent(_ stream: AsyncStream<Void>, within timeout: Duration) async -> Bool {
            await withTaskGroup(of: Bool.self) { group in
                group.addTask {
                    for await _ in stream { return true }
                    return false
                }
                group.addTask {
                    try? await Task.sleep(for: timeout)
                    return false
                }
                let first = await group.next() ?? false
                group.cancelAll()
                return first
            }
        }
    }

    /// The coordinated iCloud Drive transport in a plain temporary directory (docs/02-architecture.md §7.3): the
    /// transport contract under `NSFileCoordinator`, placeholders of files not downloaded yet, create-once among
    /// concurrent coordinated writers, change notification, and two sync engines over it. A real ubiquity container
    /// needs a signed app with the iCloud entitlement, so download and eviction by iCloud itself are not exercised here.
    @Suite("Coordinated iCloud Drive transport")
    struct CoordinatedFileSyncTransportTests {
        @Test("keeps the sync transport contract under file coordination")
        func contract() async throws {
            let violations = try await SyncTransportContract.violations {
                CoordinatedFileSyncTransport(root: CoordinatedFixtures.temporaryRoot())
            }
            #expect(violations == [])
        }

        @Test("an object not downloaded yet is listed, fetched as absent, blocks a create, and can be deleted")
        func placeholder() async throws {
            let root = CoordinatedFixtures.temporaryRoot()
            let transport = CoordinatedFileSyncTransport(root: root)
            let name = SyncTransportContract.name
            try CoordinatedFixtures.plantPlaceholder(for: name, in: root)
            #expect(try await transport.list(prefix: SyncTransportContract.prefix) == [name])
            #expect(try await transport.fetch(name, maximumLength: 100) == nil)
            await #expect(throws: SyncTransportError.objectExists(name)) {
                try await transport.create(name, contents: [1])
            }
            try await transport.delete(name)
            #expect(try await transport.list(prefix: SyncTransportContract.prefix) == [])
        }

        @Test("of many concurrent creates of one name, exactly one succeeds and nothing is overwritten")
        func concurrentCreates() async throws {
            let transport = CoordinatedFileSyncTransport(root: CoordinatedFixtures.temporaryRoot())
            let name = SyncTransportContract.name
            let outcomes = await withTaskGroup(of: UInt8?.self) { group in
                for writer in UInt8(1)...8 {
                    group.addTask {
                        do {
                            try await transport.create(name, contents: [writer, writer])
                            return writer
                        } catch {
                            return nil
                        }
                    }
                }
                var winners: [UInt8] = []
                for await outcome in group { if let outcome { winners.append(outcome) } }
                return winners
            }
            #expect(outcomes.count == 1)
            let winner = try #require(outcomes.first)
            #expect(try await transport.fetch(name, maximumLength: 10) == [winner, winner])
        }

        @Test("the folder presenter reports an object written under coordination")
        func presenter() async throws {
            let root = CoordinatedFixtures.temporaryRoot()
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            let (stream, continuation) = AsyncStream.makeStream(of: Void.self)
            let presenter = SyncFolderPresenter(root: root) { continuation.yield() }
            presenter.start()
            defer { presenter.stop() }
            try await CoordinatedFileSyncTransport(root: root).create(SyncTransportContract.name, contents: [1])
            #expect(await CoordinatedFixtures.firstEvent(stream, within: .seconds(10)))
        }

        @Test("two sync engines exchange an item through the coordinated folder")
        func engines() async throws {
            let transport = CoordinatedFileSyncTransport(root: CoordinatedFixtures.temporaryRoot())
            let keys = FakeAccountKeys(seed: 11)
            let vault = SyncTransportContract.vault
            await keys.addVaultKey(vaultID: vault)
            await keys.trust(device: SyncTransportContract.deviceA)
            await keys.trust(device: SyncTransportContract.deviceB)
            let a = SyncTestClient(
                deviceID: SyncTransportContract.deviceA, vaultID: vault, keys: keys, transport: transport)
            let b = SyncTestClient(
                deviceID: SyncTransportContract.deviceB, vaultID: vault, keys: keys, transport: transport)
            let item = try await a.save(
                Item(
                    id: UUID(), vaultID: vault, title: "Bank", scopes: [ServiceScope(host: "firstbank.co.uk")],
                    fields: [Field(id: UUID(), kind: .password, label: "Password", value: "hunter22")]))
            #expect(try await a.sync().segmentsWritten == 1)
            let report = try await b.sync()
            #expect(report.applied == 1)
            #expect(try await b.item(item.id) == item)
        }
    }
#endif
