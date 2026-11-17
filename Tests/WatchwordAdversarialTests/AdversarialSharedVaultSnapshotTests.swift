import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit
@testable import WatchwordSync

/// Snapshots in a shared vault (review finding Z21). An honest device writes none there (`maintainsLog` is off), so
/// one that appears is either from before the vault was shared, written by a device of its owner, or a member's
/// attempt to have its coverage vector and tombstones believed without the judge.
extension AdversarialSharedVaultTests {
    static func deviceID(of account: SharingAccount) async throws -> UUID {
        try #require(try await account.vault.store.loadAccount()?.deviceID)
    }

    /// Seals and signs a snapshot of `vaultID` as `author`'s own device would, and puts it on the transport.
    static func plantSnapshot(
        by author: SharingAccount, in vaultID: UUID, on transport: InMemorySyncTransport, lamport: UInt64,
        vector: [UUID: UInt64], entries: [SyncEntry] = []
    ) async throws {
        let location = SyncObjectLocation.snapshot(
            vaultID: vaultID, author: try await deviceID(of: author), lamport: lamport)
        let payload = SyncPayload(
            kind: .snapshot, vaultID: vaultID, author: location.author, number: lamport, vector: vector,
            entries: entries)
        let envelope = try await author.session.syncSeal(payload.encoded(), at: location)
        let signature = try await author.session.syncSign(envelope, at: location)
        await transport.tamper(
            location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
    }

    /// Threat: A4, a member whose role may write, with one modified client. It publishes a snapshot of the shared
    /// vault, validly sealed and signed, with no entries and a coverage vector naming every other member's device at
    /// 2^48. Believed, each device that merges it stops reading the other streams, and takes the coverage for its own
    /// stream too: its next sequence number becomes 2^48 + 1, a name every reader ignores, so its edits silently stop
    /// replicating, and a replay keeps the number, so that outlasts the member's removal. The snapshot is refused
    /// where it is verified: only the owner's devices could have written one, before the vault was shared.
    @Test("a member's snapshot claiming every stream is refused, and mutes no device")
    func memberSnapshotCoverage() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readWrite])
        let (hostile, third) = (members[0], members[1])
        try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, hostile, third])
        let ownerDevice = try await Self.deviceID(of: owner)
        let thirdDevice = try await Self.deviceID(of: third)
        try await Self.plantSnapshot(
            by: hostile, in: vaultID, on: household.transport, lamport: 1,
            vector: [ownerDevice: 1 << 48, thirdDevice: 1 << 48])

        let report = try await owner.session.syncAll()
        #expect(report.vaults[vaultID]?.rejected.map(\.reason) == [.keyring(.untrustedAuthor(try await Self.deviceID(of: hostile)))])
        try await third.session.sync()
        let later = try await owner.session.save(Item(vaultID: vaultID, title: "Later", scopes: [], fields: []))
        let published = try await owner.session.syncAll()
        #expect(published.vaults[vaultID]?.ownStreamExhausted == false)
        let state = try #require(try await owner.vault.sync?.state.loadState(vaultID: vaultID))
        #expect(state.nextSequence < 64, "the owner's next sequence number was moved to \(state.nextSequence)")
        #expect((state.merged[thirdDevice] ?? 0) < 64)
        try await third.session.sync()
        #expect(try await third.session.items(in: vaultID).items.contains { $0.id == later.id })
        // And the other way: what the third member writes still reaches the owner.
        let reply = try await third.session.save(Item(vaultID: vaultID, title: "Reply", scopes: [], fields: []))
        try await Self.syncAll([third, owner])
        #expect(try await owner.session.items(in: vaultID).items.contains { $0.id == reply.id })
    }

    /// Threat: A4 again. The snapshot carries a tombstone for an item, stamped as the member's own device, whose
    /// erasure summary claims to have seen every device's edits far beyond any made: applied unjudged, it erases the
    /// item on every member's device, edits the member never saw included, and versions that arrive later
    /// (PRD F7.6, S45, S46). From a member it is refused with the snapshot.
    @Test("a tombstone in a member's snapshot erases nothing")
    func memberSnapshotTombstone() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readWrite])
        let (hostile, third) = (members[0], members[1])
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, hostile, third])
        // An edit the hostile member has not been shown.
        try await owner.session.save(
            Self.setting(.password, to: "unseen-by-the-member", in: try await owner.session.item(id: bank.id)))
        try await owner.session.sync()

        let hostileDevice = try await Self.deviceID(of: hostile)
        let high: UInt64 = 5000
        let seen = VersionVector([
            try await Self.deviceID(of: owner): high, try await Self.deviceID(of: third): high, hostileDevice: high,
        ])
        let summary = try ItemErasure(seen: seen, row: high, device: hostileDevice, date: nil).summary()
        let tombstone = SyncEntry.tombstone(
            RecordKey(recordID: bank.id, kind: .item),
            stamp: RecordStamp(version: high + 1, device: hostileDevice, deleted: true), erasure: summary)
        try await Self.plantSnapshot(
            by: hostile, in: vaultID, on: household.transport, lamport: high + 1, vector: [:], entries: [tombstone])

        try await Self.syncAll([third, owner, third])
        for account in [owner, third] {
            #expect(
                try await account.session.item(id: bank.id).field(.password)?.value == "unseen-by-the-member")
        }
    }

    /// Threat: the owner's own device as the insider (or the owner's keys in other hands): a snapshot from the one
    /// account that may sign one, carrying the same over-claiming tombstone. A snapshot's tombstone is judged as a
    /// segment's is (`WriteJudge.admitsErasure`): a claim to have seen a current member's edits that their stream has
    /// not published is held aside, and the item stays.
    @Test("a tombstone in the owner's snapshot is judged like a segment's")
    func ownerSnapshotTombstoneIsJudged() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite])
        let member = members[0]
        let bank = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner])
        let ownerDevice = try await Self.deviceID(of: owner)
        let high: UInt64 = 5000
        let seen = VersionVector([ownerDevice: high, try await Self.deviceID(of: member): high])
        let summary = try ItemErasure(seen: seen, row: high, device: ownerDevice, date: nil).summary()
        let tombstone = SyncEntry.tombstone(
            RecordKey(recordID: bank.id, kind: .item),
            stamp: RecordStamp(version: high + 1, device: ownerDevice, deleted: true), erasure: summary)
        try await Self.plantSnapshot(
            by: owner, in: vaultID, on: household.transport, lamport: high + 1, vector: [:], entries: [tombstone])

        let report = try await member.session.syncAll()
        #expect(report.vaults[vaultID]?.heldAside == [RecordKey(recordID: bank.id, kind: .item)])
        #expect(try await member.session.items(in: vaultID).items.map(\.id) == [bank.id])
    }
}
