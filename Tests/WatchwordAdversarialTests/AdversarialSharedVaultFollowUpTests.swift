import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The engine's second-round fixes (Z30 to Z39) in shared vaults, as their independent review attacked them
// (docs/06-adversarial-review.md §Z, rows from Z126).
extension AdversarialSharedVaultTests {
    /// Where a planted tombstone comes from: the owner's snapshot (the one account whose snapshots a shared vault
    /// reads), or a segment of another member who may write.
    enum TombstoneCarrier: String, CaseIterable, Sendable {
        case ownerSnapshot
        case writerSegment
    }

    /// Seals and signs a segment of `author`'s own device stream at the number after its last published one, as its
    /// own client would, and puts it on the transport.
    static func plantSegment(
        by author: SharingAccount, in vaultID: UUID, on transport: InMemorySyncTransport, entries: [SyncEntry]
    ) async throws {
        let device = try await deviceID(of: author)
        let syncState = try #require(await author.session.syncState)
        let head = try await syncState.loadState(vaultID: vaultID)?.lastPublishedSequence ?? 0
        let location = SyncObjectLocation.segment(vaultID: vaultID, author: device, sequence: head + 1)
        let payload = SyncPayload(
            kind: .segment, vaultID: vaultID, author: device, number: head + 1, vector: [:], entries: entries)
        let envelope = try await author.session.syncSeal(payload.encoded(), at: location)
        let signature = try await author.session.syncSign(envelope, at: location)
        await transport.tamper(
            location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
    }

    /// Threat: the owner's account as the insider, whose snapshots a shared vault reads (as in Z34), or a member who
    /// may write (A4), through a segment of its own stream (S46). A member has joined and edited an item the owner
    /// wrote, and has not published anything yet. The insider's tombstone for the item claims to have seen the
    /// member's device's edits up to 5000. A claim about a current member's edits waits for that member's stream to
    /// carry them, unless the stream "cannot be read from its first segment", and a stream with no segment at all
    /// was taken for one that cannot be read: the claim was believed, on the member's own device too, where the
    /// member's unpublished edit was erased, and everywhere else, where the item was gone. A claim about this
    /// device's own edits is checked against what it published first, whatever else is known; a claim about a stream
    /// that has no segment yet waits for one.
    @Test(
        "a deletion claiming the edits of a member who has never published erases nothing",
        arguments: TombstoneCarrier.allCases)
    func claimAboutAMemberWhoNeverPublished(carrier: TombstoneCarrier) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(
            roles: [.readWrite, .readWrite], seed: carrier == .ownerSnapshot ? 3200 : 3220)
        let (member, writer) = (members[0], members[1])
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, member, writer])
        _ = try await member.session.save(
            Self.setting(.password, to: "not-yet-published", in: try await member.session.item(id: bank.id)))
        let memberDevice = try await Self.deviceID(of: member)
        let memberStream = "vault/\(vaultID.uuidString)/log/\(memberDevice.uuidString)/"
        #expect(
            await household.transport.list(prefix: memberStream).isEmpty,
            "the member has published: the test proves nothing")

        let ownerDevice = try await Self.deviceID(of: owner)
        let high: UInt64 = 5000
        let named = carrier == .ownerSnapshot ? memberDevice : try await Self.deviceID(of: writer)
        let summary = try ItemErasure(
            seen: VersionVector([memberDevice: high, ownerDevice: bank.version]), row: high, device: named, date: nil
        )
        .summary()
        let tombstone = SyncEntry.tombstone(
            RecordKey(recordID: bank.id, kind: .item),
            stamp: RecordStamp(version: high + 1, device: named, deleted: true), erasure: summary)
        switch carrier {
        case .ownerSnapshot:
            try await Self.plantSnapshot(
                by: owner, in: vaultID, on: household.transport, lamport: high + 1, vector: [:], entries: [tombstone])
        case .writerSegment:
            try await Self.plantSegment(by: writer, in: vaultID, on: household.transport, entries: [tombstone])
        }

        // Every other device first: the claim is about a stream that has no segment yet.
        try await owner.session.syncAll()
        #expect(
            try await owner.session.items(in: vaultID).items.map(\.id) == [bank.id],
            "the item was erased on the owner's device")
        let report = try await member.session.syncAll()
        #expect(report.vaults[vaultID]?.heldAside.contains(RecordKey(recordID: bank.id, kind: .item)) == true)
        #expect(
            try await member.session.item(id: bank.id).field(.password)?.value == "not-yet-published",
            "the member's unpublished edit was erased by a deletion claiming to have seen it")

        // Once the member publishes, the claim is judged against what it published, and still does not count.
        try await Self.syncAll([member, owner, writer])
        for account in [owner, writer] {
            #expect(
                try await account.session.item(id: bank.id).field(.password)?.value == "not-yet-published",
                "the member's edit did not survive a deletion claiming more than it published")
        }
    }
}
