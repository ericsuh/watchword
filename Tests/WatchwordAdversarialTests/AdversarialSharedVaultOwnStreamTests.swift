import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// Review finding Z30 (docs/06-adversarial-review.md): in a shared vault, an object that verifies in this device's own
// stream is not therefore this device's.
extension AdversarialSharedVaultTests {
    /// The victim's last published number in the vault, as its signed state has it.
    static func head(of account: SharingAccount, in vaultID: UUID) async throws -> UInt64 {
        let syncState = try #require(await account.session.syncState)
        return try #require(try await syncState.loadState(vaultID: vaultID)).lastPublishedSequence
    }

    /// Makes `rogue` publish its next segment at `sequence` of its own stream: an adversary's client numbers as it
    /// likes, and the state it signs is its own.
    static func number(_ rogue: SharingAccount, at sequence: UInt64, in vaultID: UUID) async throws {
        let syncState = try #require(await rogue.session.syncState)
        var state = try await syncState.loadState(vaultID: vaultID) ?? SyncState(vaultID: vaultID)
        state.nextSequence = sequence
        try await syncState.saveState(state)
    }

    /// Threat: a current member who may write (A4), or a former one whose segments still verify (A5). Device IDs
    /// are chosen by devices, so the insider registers a device of their own account under the victim's device ID
    /// (S33) and signs one segment into the stream named after it, a few numbers past the victim's head, or at the
    /// last number a reader lists. The victim's device checked it, found it verified (any listed account's device
    /// under that ID does), and took it for its own: its next number went past the plant, leaving a hole every
    /// reader waits at for good, or out of range, for good. A device numbers its own stream only from objects that
    /// carry its own account's and its own key's signatures; another's in that stream is held aside in its place, as
    /// every other device does, and the stream goes on.
    @Test(
        "a member's segment far ahead in another member's device stream does not move that device's numbering",
        arguments: [false, true])
    func memberPlantAheadInOwnStream(atTheLastNumber: Bool) async throws {
        let setting = try await SquattedStream.make(seed: atTheLastNumber ? 3010 : 3020)
        let (owner, victim, rogue) = (setting.owner, setting.victim, setting.rogue)
        let vaultID = setting.vaultID
        let head = try await Self.head(of: victim, in: vaultID)
        #expect(head > 0)
        let plantedAt = atTheLastNumber ? SyncConfiguration(schemaVersions: [:]).maximumSequence : head + 5
        try await Self.number(rogue, at: plantedAt, in: vaultID)
        var planted = Self.bank(in: vaultID)
        planted.title = "Planted ahead"
        _ = try await rogue.session.save(planted)
        try await rogue.session.sync()
        let plantedName = SyncObjectLocation.segment(
            vaultID: vaultID, author: setting.victimDevice, sequence: plantedAt
        ).name
        #expect(
            await setting.household.transport.list(prefix: setting.stream).contains(plantedName),
            "nothing was planted: the test proves nothing")

        var genuine = Self.bank(in: vaultID)
        genuine.title = "The victim's own, written after the plant"
        genuine = try await victim.session.save(genuine)
        let report = try #require(try await victim.session.syncAll().vaults[vaultID])
        #expect(!report.ownStreamExhausted, "the victim's stream was moved out of range")
        let newHead = try await Self.head(of: victim, in: vaultID)
        #expect(newHead > head && newHead < plantedAt, "the victim numbered from the plant")
        try await Self.syncAll([owner, victim], rounds: 3)
        #expect(
            try await owner.session.items(in: vaultID).items.map(\.title).contains(genuine.title),
            "the victim's later work was published where no reader reads it")
        #expect(!(try await owner.session.items(in: vaultID).items.map(\.title).contains(planted.title)))
    }

    /// Threat: a member the vault never let write (read-only from the start, A4), with a device under the victim's
    /// device ID (S33), who puts one signed object a little past the victim's head in the victim's stream. Nothing
    /// that member signs counts, so the object is refused as `untrustedAuthor`, which the engine read as "cannot
    /// tell whether this is mine": the victim published nothing in that vault at any sync while the object was
    /// listed, and so held back its deletions in every vault, the Personal one included. Signatures that are not
    /// this device's own show that the object is not its own.
    @Test("a read-only member's object in another member's device stream holds back nothing of that device's")
    func readOnlyMemberPlantInOwnStream() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 3030)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let victim = try await household.account(seed: 3031)
        let reader = try await household.account(seed: 3032)
        try await owner.invite(victim, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(reader, to: vaultID, as: .readOnly, owner: owner)
        _ = try await victim.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, victim, reader])
        let victimDevice = try #require(try await victim.vault.store.loadAccount()).deviceID
        let rogue = try await household.secondDevice(of: reader, deviceID: victimDevice)
        try await rogue.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await rogue.session.sync()

        // A read-only member's client publishes nothing; the adversary's writes the object itself.
        let head = try await Self.head(of: victim, in: vaultID)
        let location = SyncObjectLocation.segment(vaultID: vaultID, author: victimDevice, sequence: head + 3)
        let payload = SyncPayload(
            kind: .segment, vaultID: vaultID, author: victimDevice, number: head + 3, vector: [:], entries: [])
        let adapter = VaultSyncAdapter(session: rogue.session)
        let envelope = try await adapter.seal(payload.encoded(), at: location)
        let signature = try await adapter.sign(envelope, at: location)
        try await household.transport.create(
            location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())

        let personal = try #require(await victim.session.personalVaultID)
        var own = Self.bank(in: personal)
        own.title = "The victim's own, in Personal"
        own = try await victim.session.save(own)
        try await victim.session.sync()
        try await victim.session.trash(id: own.id)
        try await victim.session.deletePermanently(id: own.id)
        var genuine = Self.bank(in: vaultID)
        genuine.title = "The victim's own, in the shared vault"
        genuine = try await victim.session.save(genuine)

        let report = try #require(try await victim.session.syncAll().vaults[vaultID])
        #expect(report.ownStreamUnverified == nil, "the victim's publishing waits on someone else's object")
        let syncState = try #require(victim.vault.sync?.state)
        #expect(
            try await syncState.pendingDeletions(vaultID: personal).isEmpty,
            "the victim's deletion in another vault is held back by an object someone else wrote")
        try await owner.session.sync()
        #expect(try await owner.session.items(in: vaultID).items.map(\.title).contains(genuine.title))
    }
}

// Review finding Z34: a snapshot's tombstone was judged as if it were its named device's own, as a segment's is.
extension AdversarialSharedVaultTests {
    /// Threat: the owner's account as the insider (its keys in other hands, or the owner's own device), the one
    /// account whose snapshots a shared vault reads. Its snapshot carries a tombstone for a member's item that names
    /// the *member's* device as its writer, and claims to have seen that device's edits far beyond any it has
    /// published. A tombstone's claims about its own writer's edits are not asked about, which is right for a
    /// segment, whose entries are all its stream's device's; in a snapshot the signer chooses the device. So the
    /// tombstone was admitted on every device, the member's own included: it erased the member's unpublished edit
    /// there, and the item everywhere else. In a snapshot nobody is exempt, and a claim about this device's own edits
    /// that it never published is refused.
    @Test("a tombstone in the owner's snapshot naming a member's device is judged against that device's stream")
    func ownerSnapshotTombstoneNamingAMember() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 3040)
        let member = members[0]
        let bank = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner])
        // An edit the member has not published yet.
        _ = try await member.session.save(
            Self.setting(.password, to: "not-yet-published", in: try await member.session.item(id: bank.id)))

        let memberDevice = try await Self.deviceID(of: member)
        let high: UInt64 = 5000
        let summary = try ItemErasure(
            seen: VersionVector([memberDevice: high]), row: high, device: memberDevice, date: nil
        )
        .summary()
        let tombstone = SyncEntry.tombstone(
            RecordKey(recordID: bank.id, kind: .item),
            stamp: RecordStamp(version: high + 1, device: memberDevice, deleted: true), erasure: summary)
        try await Self.plantSnapshot(
            by: owner, in: vaultID, on: household.transport, lamport: high + 1, vector: [:], entries: [tombstone])

        let report = try await member.session.syncAll()
        #expect(report.vaults[vaultID]?.heldAside.contains(RecordKey(recordID: bank.id, kind: .item)) == true)
        #expect(
            try await member.session.item(id: bank.id).field(.password)?.value == "not-yet-published",
            "the member's unpublished edit was erased by a deletion claiming to be theirs")
        try await owner.session.syncAll()
        #expect(
            try await owner.session.items(in: vaultID).items.map(\.id) == [bank.id],
            "the item was erased on the owner's device")
        #expect(try await owner.session.item(id: bank.id).field(.password)?.value == "not-yet-published")
    }
}
