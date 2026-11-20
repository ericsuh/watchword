import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit
@testable import WatchwordSync

/// Conflict copies against the production keyring (docs/02-architecture.md §7.5): which copy of a name counts is
/// decided by Ed25519 over the name and envelope under the account key and a registered device's key, never by which
/// copy the provider calls current.
extension AdversarialVaultSyncTests {
    /// A segment of B's stream at `sequence`, sealed under the vault key and signed by the account key and B's device
    /// key: what a second installation of B would publish under that name.
    static func signedSegment(_ f: Fixture, sequence: UInt64, carrying rows: [StoredRecord]) async throws -> [UInt8] {
        let payload = SyncPayload(
            kind: .segment, vaultID: f.vaultID, author: Self.deviceB, number: sequence, vector: [:],
            entries: rows.map(SyncEntry.init))
        let envelope = try await f.b.session.syncSeal(payload.encoded(), at: payload.location)
        let signature = try await f.b.session.syncSign(envelope, at: payload.location)
        return SignedObject(signature: signature, envelope: envelope).serialized()
    }

    /// Threat: A1 plants copies beside a really signed segment and makes one of them the provider's current version:
    /// noise, the genuine envelope under a stranger's signature, the genuine object of another position, and the
    /// genuine object cut short. A reader that is locked verifies each against the Keychain's copy of the account
    /// key and the registry and stages the genuine one alone; unlocked, it applies it. Nothing else of the sync is
    /// affected.
    @Test("among planted copies only the really signed object is staged while locked, and applied after unlock")
    func plantedCopiesBesideARealSegment() async throws {
        let f = try await Self.fixture()
        let name = f.segmentName(1)
        let location = SyncObjectLocation.segment(vaultID: f.vaultID, author: Self.deviceB, sequence: 1)
        let bytes = try #require(await f.transport.allObjects[name])
        let genuine = try SignedObject.parse(bytes)
        let stranger = Keyset.generate(accountID: UUID())
        let forged = SignedObject(
            signature: try stranger.sign(
                VaultSession.syncSignedMessage(genuine.envelope, at: location), domain: .logSegment),
            envelope: genuine.envelope)
        let other = try await Self.signedSegment(f, sequence: 2, carrying: [])
        await f.transport.tamper(name, contents: Array(repeating: 0xEE, count: 200))
        for copy in [forged.serialized(), other, Array(bytes.dropLast(5)), bytes] {
            await f.transport.plantCopy(name, contents: copy)
        }

        let reader = try await f.reader(locked: true)
        let locked = try await reader.session.sync()
        #expect(locked.rejected.isEmpty && locked.copiesRefused == 4 && locked.forkedObjects.isEmpty)
        let staged = try #require(try await reader.sync?.state.staged(vaultID: f.vaultID))
        #expect(staged.map(\.object) == [genuine] && staged.allSatisfy(\.alternates.isEmpty))
        try await reader.session.unlock(password: TestVault.password)
        let report = try await reader.session.sync()
        #expect(report.applied == 1 && report.rejected.isEmpty)
        #expect(try await reader.session.items().items.map(\.title) == ["Bank"])
        #expect(try await reader.session.sync().copiesExamined == 0)
    }

    /// Threat: a device's stream forks — its second installation, holding the same device key and the account key,
    /// publishes other bytes under a name the first already used — and the provider keeps both. Picking either copy
    /// loses the other's item. With real keys both copies verify, both are merged by a device that had not read the
    /// position, by one that already had, and by the forked device itself, which then hands both on in a snapshot.
    @Test("two really signed copies of one segment are both merged, by every device, and handed on by their author")
    func reallySignedFork() async throws {
        let f = try await Self.fixture()
        let early = try await f.reader()
        try await early.session.sync()
        #expect(try await early.session.items().items.map(\.title) == ["Bank"])

        // What the other installation wrote: an item of its own, sealed as B seals items.
        let fork = try await f.b.session.save(
            Item(
                vaultID: f.vaultID, title: "Written after the restore", scopes: [],
                fields: [Field(kind: .password, label: "Password", value: "fork-secret")]))
        let row = try #require(try await f.b.store.record(RecordKey(recordID: fork.id, kind: .item)))
        let name = f.segmentName(1)
        await f.transport.plantCopy(name, contents: try await Self.signedSegment(f, sequence: 1, carrying: [row]))
        // B itself forgets the item, as its first installation never had it.
        try await f.b.store.commit(StoreChange(deletions: [row.key]))

        let late = try await early.session.sync()
        #expect(late.forkedObjects == [name] && late.rejected.isEmpty && late.applied == 1)
        let fresh = try await f.a.session.sync()
        #expect(fresh.forkedObjects == [name] && fresh.rejected.isEmpty)
        let author = try await f.b.session.sync()
        #expect(author.forkedObjects == [name] && author.snapshotsWritten == 1)
        for device in [early, f.a, f.b] {
            #expect(
                Set(try await device.session.items().items.map(\.title)) == ["Bank", "Written after the restore"])
        }
    }
}
