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
// (docs/06-adversarial-review.md §Z, rows from Z135).
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

// Review finding Z137: a read-only member's object in another member's stream squatted there for good.
extension AdversarialSharedVaultTests {
    /// Threat: a member the vault never let write (read-only from the start, A4), with a device registered under the
    /// victim's device ID (S33), who signs one segment a little past the victim's head in the victim's stream,
    /// carrying a deletion of an item in the vault. Nothing that member signs counts, so every device refused the
    /// object as it downloaded it and waited at it, and never staged it, so no device ever stepped over it. Z30 kept
    /// the victim publishing until it reached that number; from there every sync met the planted name
    /// (`ownStreamConflict`), for good, the victim's later work reached nobody, its deletions were held back in every
    /// vault, the person read "Up to date.", and it outlasted the member's removal. A segment signed by any account
    /// the chain lists was then taken in and passed over in sequence. Since Z157 the victim's device ID commits to the
    /// victim's account and the member's object verifies nowhere: nothing of it counts or is kept anywhere. At the
    /// number it occupies the victim's stream stops, as at any object anyone can create there (A1), and says so at
    /// every sync (never "Up to date."): its deletions elsewhere wait for its work there (F7.6), nothing is marked
    /// sent, and it all goes out once the object is gone.
    @Test("a read-only member's segment in another member's stream counts nowhere, and the stream waits visibly")
    func readOnlyMemberPlantIsSteppedOver() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 3240)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let victim = try await household.account(seed: 3241)
        let reader = try await household.account(seed: 3242)
        try await owner.invite(victim, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(reader, to: vaultID, as: .readOnly, owner: owner)
        let bank = try await victim.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, victim, reader])
        let victimDevice = try await Self.deviceID(of: victim)
        let rogue = try await household.secondDevice(of: reader, deviceID: victimDevice)
        try await rogue.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await rogue.session.sync()

        let head = try await Self.head(of: victim, in: vaultID)
        let plantedAt = head + 3
        let summary = try ItemErasure(
            seen: VersionVector([victimDevice: 1000]), row: 1000, device: victimDevice, date: nil
        ).summary()
        let deletion = SyncEntry.tombstone(
            RecordKey(recordID: bank.id, kind: .item),
            stamp: RecordStamp(version: 1001, device: victimDevice, deleted: true), erasure: summary)
        let location = SyncObjectLocation.segment(vaultID: vaultID, author: victimDevice, sequence: plantedAt)
        let payload = SyncPayload(
            kind: .segment, vaultID: vaultID, author: victimDevice, number: plantedAt, vector: [:],
            entries: [deletion])
        let adapter = VaultSyncAdapter(session: rogue.session)
        let envelope = try await adapter.seal(payload.encoded(), at: location)
        let signature = try await adapter.sign(envelope, at: location)
        try await household.transport.create(
            location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())

        // The victim writes on, one segment a sync, up to the planted number, and is told there.
        var titles: [String] = []
        for index in 0..<5 {
            var item = Self.bank(in: vaultID)
            item.title = "The victim's own, number \(index)"
            titles.append(try await victim.session.save(item).title)
            try await victim.session.syncAll()
            try await owner.session.syncAll()
        }
        let personal = try #require(await victim.session.personalVaultID)
        let own = try await victim.session.save(Self.bank(in: personal))
        try await victim.session.sync()
        try await victim.session.trash(id: own.id)
        try await victim.session.deletePermanently(id: own.id)
        let blocked = try #require(try await victim.session.syncAll().vaults[vaultID])
        #expect(blocked.ownStreamConflict == plantedAt, "the victim is not told its stream is stopped")
        #expect(try await Self.head(of: victim, in: vaultID) == plantedAt - 1)
        try await Self.syncAll([owner, reader])
        for account in [owner, reader] {
            #expect(Self.refused(location.name, in: try await account.session.syncAll().vaults[vaultID]))
            #expect(try await account.session.item(id: bank.id).title == bank.title, "the planted deletion counted")
        }
        for account in [owner, victim, reader] {
            let kept = try await #require(account.vault.sync?.state).quarantined(vaultID: vaultID)
            #expect(kept.isEmpty, "what a member whose writes never count signed was kept")
        }

        // The object gone, the stream goes on: every edit arrives, and the deletion elsewhere goes out after them.
        await Self.remove(location.name, from: household.transport)
        let last = try #require(try await victim.session.syncAll().vaults[vaultID])
        #expect(last.ownStreamConflict == nil)
        try await victim.session.syncAll()
        let syncState = try #require(victim.vault.sync?.state)
        #expect(try await syncState.pendingDeletions(vaultID: personal).isEmpty, "the deletion never went out")
        try await Self.syncAll([owner, reader])
        for account in [owner, reader] {
            let shown = try await account.session.items(in: vaultID).items.map(\.title)
            #expect(Set(titles).isSubset(of: Set(shown)), "the victim's later work reached nobody")
        }
    }
}
