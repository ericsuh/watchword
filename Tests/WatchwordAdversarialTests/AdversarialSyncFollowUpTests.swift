import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// A transport whose listings leave out the names the test chooses, as an eventually consistent provider's listing
/// can, or as a store (A1) that withholds them; fetches, creations and deletions pass through.
actor HidingTransport: SyncTransport {
    let base: InMemorySyncTransport
    var hidden: Set<String> = []
    var unreadable: Set<String> = []

    init(base: InMemorySyncTransport) {
        self.base = base
    }

    func hide(_ names: Set<String>) { hidden = names }
    func makeUnreadable(_ names: Set<String>) { unreadable = names }

    func list(prefix: String) async throws -> [String] {
        await base.list(prefix: prefix).filter { !hidden.contains($0) }
    }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        if unreadable.contains(name) { throw SyncTransportError.objectUnreadable(name) }
        return try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws { try await base.create(name, contents: contents) }

    func delete(_ name: String) async throws { await base.delete(name) }
}

/// The engine's second-round fixes (Z30 to Z39) as their independent review attacked them (docs/06-adversarial-review.md
/// §Z, rows from Z126), over the fakes.
extension AdversarialSyncTests {
    /// Device A publishes `segments` segments; device B merges them, merges a snapshot of its own covering A's stream
    /// to its head, and acknowledges it, so that A may collect everything below its head.
    static func collectableStream(_ f: Fixture, segments: UInt64 = 3) async throws -> SyncTestClient {
        for index in 1...segments {
            try await f.writer.save(Self.login("Item \(index)", password: "p\(index)"))
            try await f.writer.sync()
        }
        let reader = await f.reader()
        try await reader.sync()
        try await f.plant(
            SyncPayload(
                kind: .snapshot, vaultID: Self.vault, author: Self.b, number: 20, vector: [Self.a: segments],
                entries: []),
            signedBy: reader.keyring)
        let acknowledged = try await reader.sync()
        #expect(acknowledged.segmentsWritten == 1, "the reader did not acknowledge: the test proves nothing")
        return reader
    }

    // MARK: - Collection keeps this device's own head (Z126)

    /// Threat: anyone who can create a file under the vault's prefix (A1, or a read-only or former member of a shared
    /// folder), holding no key. One name in the victim's own stream far past its head, which cannot be fetched (a
    /// placeholder not yet downloaded, a file with no read permission). Z31 anchors the victim on its listed head, so
    /// the name held nothing back; but collection kept "the newest" by listed names, so at the next quiet collection
    /// the planted name was the newest and the victim deleted its genuine head. From then on it had no anchor, the
    /// planted name held its publishing back in that vault for good, and with it its deletions in every vault. The
    /// newest kept is this device's own genuine head, never a name.
    @Test("a name planted far ahead in a device's own stream is not kept in place of its head when it collects")
    func plantedNameIsNotTheNewestToKeep() async throws {
        let f = try await Self.fixture()
        let reader = try await Self.collectableStream(f)
        let phantom = f.segmentName(1 << 40)
        await f.transport.tamper(phantom, contents: [1, 2, 3])
        let (store, syncState) = (await f.writer.store, await f.writer.syncState)
        let transport = HidingTransport(base: f.transport)
        await transport.makeUnreadable([phantom])
        let writer = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: transport, store: store,
            syncState: syncState)

        let collecting = try await writer.sync()
        #expect(collecting.collected >= 2, "nothing was collected: the test proves nothing")
        #expect(await f.transport.allObjects[f.segmentName(3)] != nil, "the device's own head was collected")

        let later = try await writer.save(Self.login("Later", password: "y"))
        for _ in 0..<2 {
            let report = try await writer.sync()
            #expect(report.ownStreamUnverified == nil, "a planted name mutes the device once its head is gone")
        }
        try await reader.sync()
        #expect(try await reader.items()[later.id] != nil, "the later edit never arrived")
    }

    /// Threat: none needed but a listing that leaves out one of this device's segments while it collects (an
    /// eventually consistent provider, or A1 withholding it). Collection took the listed numbers it could, so it
    /// deleted the ones above the missing one: a lower segment then stayed listed with higher ones gone, which is
    /// exactly what the anchor (Z31) says cannot happen, and a state put back to that lower number would publish over
    /// a collected one. Only a contiguous run of listed numbers is collected, stopping at the first one missing.
    @Test("collection stops at a segment missing from the listing")
    func collectionStopsAtAGap() async throws {
        let f = try await Self.fixture()
        _ = try await Self.collectableStream(f, segments: 5)
        let (store, syncState) = (await f.writer.store, await f.writer.syncState)
        let transport = HidingTransport(base: f.transport)
        await transport.hide([f.segmentName(2)])
        let writer = SyncTestClient(
            deviceID: Self.a, vaultID: Self.vault, keys: f.keys, transport: transport, store: store,
            syncState: syncState)
        let report = try await writer.sync()
        #expect(report.collected == 1)
        #expect(await f.transport.allObjects[f.segmentName(2)] != nil)
        #expect(
            await f.transport.allObjects[f.segmentName(3)] != nil,
            "a segment above one still listed was collected")
    }
}
