import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

extension VaultSession {
    /// For tests: the devices whose streams this device does not read in `vaultID`.
    func retiredInVault(_ vaultID: UUID) async -> Set<UUID> {
        await syncRetiredAuthors(vaultID: vaultID)
    }

    /// For tests: whether this device recorded the segment at `sequence` of `device`'s stream.
    func recordedSegment(_ device: UUID, _ sequence: UInt64, in vaultID: UUID) -> Bool {
        sharing.vaults[vaultID]?.index.segment(device: device, sequence: sequence) != nil
    }

    /// For tests: whether the vault's items were last judged against the basis as it stands, with no replay due.
    func judgementIsSettled(_ vaultID: UUID) async -> Bool {
        let basis = await judgedBasis(vaultID)
        guard let vault = sharing.vaults[vaultID] else { return false }
        return !vault.needsReconcile && vault.index.judgedHead == basis
    }
}

// The review of the engine's fourth round (rows Z144 to Z149) in shared vaults (docs/06-adversarial-review.md §Z,
// rows from Z150).
extension AdversarialSharedVaultTests {
    /// Threat: a member of the vault (A4) whose work cannot count, read-only from the start or removed, who registers a
    /// device under another member's device ID in their own registry (S33 allows it) and then revokes it there. Every
    /// registry's revocations were unioned: every device stopped reading the victim's stream, and the victim's own
    /// device was told it was revoked and synced nothing in that vault. Since Z144 a revoked device's values are also
    /// believed without its stream, so a member who may write could have claims stamped with the victim's device
    /// believed. Z150 counted a revocation only from the account whose stream it was; round 5 (M2) found that
    /// test met by a captured stream. Since Z157 no registry but the device's own account's counts the device at all.
    @Test("a member's revocation of another member's device ID stops nothing")
    func memberRevokesAnotherMembersDevice() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 3500)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let victim = try await household.account(seed: 3501)
        let reader = try await household.account(seed: 3502)
        let former = try await household.account(seed: 3503)
        try await owner.invite(victim, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(reader, to: vaultID, as: .readOnly, owner: owner)
        try await owner.invite(former, to: vaultID, as: .readWrite, owner: owner)
        let invitation = Invitation(vaultID: vaultID, ownerAccountID: owner.accountID)
        // The victim's laptop has published in the vault; its phone has joined and written nothing yet.
        _ = try await victim.session.save(Self.bank(in: vaultID))
        let phone = try await household.secondDevice(of: victim)
        try await phone.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await Self.syncAll([owner, victim, phone, reader, former])
        let laptopID = try await Self.deviceID(of: victim)
        let phoneID = try await Self.deviceID(of: phone)

        // The former member lists the laptop's ID while it may write, and is removed; the reader lists the phone's.
        // Each then revokes the device it listed.
        _ = try await household.secondDevice(of: former, deviceID: laptopID)
        _ = try await household.secondDevice(of: reader, deviceID: phoneID)
        try await Self.syncAll([owner, reader, former], rounds: 1)
        #expect(try await owner.session.removeMember(former.accountID, from: vaultID) == .complete)
        try await former.session.revokeDevice(laptopID, password: .keepPassword(current: TestVault.password))
        try await reader.session.revokeDevice(phoneID, password: .keepPassword(current: TestVault.password))
        try await Self.syncAll([owner, reader, former, victim, phone])

        for (name, session) in [("owner", owner.session), ("laptop", victim.session), ("phone", phone.session)] {
            let retired = await session.retiredInVault(vaultID)
            #expect(!retired.contains(laptopID), "the laptop's stream is not read on the \(name)'s device")
            #expect(!retired.contains(phoneID), "the phone's stream is not read on the \(name)'s device")
        }
        var fromLaptop = Self.bank(in: vaultID)
        fromLaptop.title = "Written on the laptop afterwards"
        fromLaptop = try await victim.session.save(fromLaptop)
        var fromPhone = Self.bank(in: vaultID)
        fromPhone.title = "Written on the phone afterwards"
        fromPhone = try await phone.session.save(fromPhone)
        for account in [victim, phone] {
            let report = try #require(try await account.session.syncAll().vaults[vaultID])
            #expect(!report.deviceRevoked, "the victim's device was told it was revoked")
        }
        try await Self.syncAll([owner, reader, victim, phone])
        for (name, account) in [("owner", owner), ("reader", reader), ("laptop", victim), ("phone", phone)] {
            let titles = try await account.session.items(in: vaultID).items.map(\.title)
            #expect(titles.contains(fromLaptop.title), "the laptop's work did not reach the \(name)'s device")
            #expect(titles.contains(fromPhone.title), "the phone's work did not reach the \(name)'s device")
        }
    }
}

// Review finding Z153: a revocation learnt after a version naming the device was held aside changed nothing.
extension AdversarialSharedVaultTests {
    /// Threat: the store (A1), showing a member who joined (or any device) everything but the stream of another
    /// member's laptop, and then the laptop's ordinary loss and revocation; or no adversary, a device whose listing
    /// lags. The owner's version of an item carries the laptop's password value, so that device held it aside waiting
    /// for the laptop's stream. Then the laptop was revoked: its stream is never read again, nothing that device waited
    /// for can arrive, and nothing else made it judge again until some unrelated change of head, while a device that
    /// judged after the revocation believed the value (Z144): the two disagreed about the same segments. A revocation
    /// that starts counting for a device a judgement waited for changes the judged basis, which takes out and replays.
    @Test("a revocation learnt after a version was held aside for that device is judged again")
    func revocationLearntAfterTheHold() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 3600)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let member = try await household.account(seed: 3601)
        let (joiner, view) = try await household.withheldAccount(seed: 3602)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(joiner, to: vaultID, as: .readWrite, owner: owner)
        let laptop = try await household.secondDevice(of: member)
        try await laptop.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await Self.syncAll([owner, member, laptop, joiner])
        let laptopID = try await Self.deviceID(of: laptop)
        await view.withholdNew(under: "vault/\(vaultID.uuidString)/log/\(laptopID.uuidString)/")

        var kept = Self.bank(in: vaultID)
        kept = try await laptop.session.save(Self.setting(.password, to: "laptop-password", in: kept))
        try await Self.syncAll([laptop, owner])
        var renamed = try await owner.session.item(id: kept.id)
        renamed.title = "Renamed by the owner"
        _ = try await owner.session.save(renamed)
        try await Self.syncAll([owner, joiner])
        #expect(
            (try? await joiner.session.item(id: kept.id)) == nil, "the joiner was not waiting: the test proves nothing")

        try await member.session.revokeDevice(laptopID, password: .keepPassword(current: TestVault.password))
        try await Self.syncAll([member, owner, joiner])
        let item = try? await joiner.session.item(id: kept.id)
        #expect(item?.title == "Renamed by the owner", "held aside for a stream that will never be read")
        #expect(item?.field(.password)?.value == "laptop-password")
        // And it settles: no replay at every sync after.
        for _ in 0..<2 {
            try await joiner.session.sync()
            #expect(await joiner.session.judgementIsSettled(vaultID), "the log is replayed at every sync")
        }
    }
}

// Review finding Z151: an owner's stream whose first segments were not here yet was taken for one collected before the
// vault was shared.
extension AdversarialSharedVaultTests {
    /// Threat: a member who may write (A4), with the store (A1) withholding the owner's device's first segment from a
    /// device that joins (or no adversary but a lagging listing). Z144 believed claims about a device of the owner's
    /// account whose first segments are not here, taking them for segments collected before sharing; but a vault
    /// whose log was compacted is never shared (Z42), so nearly always they had merely not arrived. The member's
    /// tombstone claims to have seen the owner's device's edits up to 5000, edits it has not made: on the joiner's
    /// device it was believed and the item erased, while every other device held it aside; when the first segment
    /// arrived, nothing judged again. Only a snapshot merged here that covers the missing segments makes a stream
    /// collected, and an earlier segment arriving later asks for a replay.
    @Test("an owner's stream missing its first segment is not taken for one collected before sharing")
    func ownerStreamMissingItsFirstSegment() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 3700)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let writer = try await household.account(seed: 3701)
        try await owner.invite(writer, to: vaultID, as: .readWrite, owner: owner)
        var bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, writer])
        bank = try await owner.session.save(Self.setting(.password, to: "owner-change", in: bank))
        try await Self.syncAll([owner, writer])
        var edited = try await writer.session.item(id: bank.id)
        edited.title = "Edited by the writer"
        _ = try await writer.session.save(edited)
        try await Self.syncAll([writer, owner])

        let ownerDevice = try await Self.deviceID(of: owner)
        let ownerStream = "vault/\(vaultID.uuidString)/log/\(ownerDevice.uuidString)/"
        let first = try #require(await household.transport.list(prefix: ownerStream).sorted().first)
        let (joiner, view) = try await household.withheldAccount(seed: 3702)
        await view.withhold([first])
        try await owner.invite(joiner, to: vaultID, as: .readWrite, owner: owner)

        let writerDevice = try await Self.deviceID(of: writer)
        let high: UInt64 = 5000
        let summary = try ItemErasure(
            seen: VersionVector([ownerDevice: high, writerDevice: high]), row: high, device: writerDevice, date: nil
        ).summary()
        let tombstone = SyncEntry.tombstone(
            RecordKey(recordID: bank.id, kind: .item),
            stamp: RecordStamp(version: high + 1, device: writerDevice, deleted: true), erasure: summary)
        try await Self.plantSegment(by: writer, in: vaultID, on: household.transport, entries: [tombstone])

        try await Self.syncAll([joiner])
        #expect(
            (try? await joiner.session.item(id: bank.id))?.title == "Edited by the writer",
            "a claim about the owner's edits that do not exist erased the item")
        // The first segment arrives: judged again, and the same as on every other device.
        await view.reveal()
        try await Self.syncAll([joiner, owner])
        for (name, account) in [("joiner", joiner), ("owner", owner)] {
            #expect(
                (try? await account.session.item(id: bank.id))?.title == "Edited by the writer",
                "the item is gone on the \(name)'s device")
        }
        #expect(await joiner.session.judgementIsSettled(vaultID))
    }
}

// Review finding Z152: promoting a read-only member brought Z146's capture back.
extension AdversarialSharedVaultTests {
    /// Threat: a read-only member (A4) who registers a device under a writer's device ID (S33) and signs segment 1 of
    /// that device's stream before the writer has published, and then an ordinary promotion by the owner. Z146 passed
    /// over that segment only while its signer's work could not count: once the member was let write, the planted
    /// segment named the stream on every device, its tombstone counted, and every segment the writer published there
    /// was held aside; Z152 then named streams by who could write when a key was current, and rotated after a
    /// promotion. The writer's device ID commits to the writer's account (Z157): the plant verifies on no device,
    /// before the promotion or after, no rotation is needed, and the promoted member's own later work counts as
    /// anyone's.
    @Test("a planted segment does not take a writer's stream when its read-only signer is promoted")
    func promotionAfterAPlant() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 3800)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let victim = try await household.account(seed: 3801)
        let reader = try await household.account(seed: 3802)
        try await owner.invite(victim, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(reader, to: vaultID, as: .readOnly, owner: owner)
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, victim, reader])
        let victimDevice = try await Self.deviceID(of: victim)
        let rogue = try await household.secondDevice(of: reader, deviceID: victimDevice)
        try await rogue.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await rogue.session.sync()
        let summary = try ItemErasure(
            seen: VersionVector([victimDevice: 1000]), row: 1000, device: victimDevice, date: nil
        ).summary()
        let deletion = SyncEntry.tombstone(
            RecordKey(recordID: bank.id, kind: .item),
            stamp: RecordStamp(version: 1001, device: victimDevice, deleted: true), erasure: summary)
        try await Self.plantSegment(
            by: rogue, as: victimDevice, sequence: 1, in: vaultID, entries: [deletion], on: household.transport)
        let planted = SyncObjectLocation.segment(vaultID: vaultID, author: victimDevice, sequence: 1).name

        let keyBefore = try await owner.session.sharedVaultStatus(vaultID).membership.vaultKeyID
        try await owner.session.changeRole(of: reader.accountID, in: vaultID, to: .readWrite)
        try await Self.syncAll([owner, victim, reader], rounds: 3)
        #expect(try await owner.session.sharedVaultStatus(vaultID).membership.vaultKeyID == keyBefore)
        for (name, account) in [("owner", owner), ("reader", reader), ("victim", victim)] {
            #expect(Self.refused(planted, in: try await account.session.syncAll().vaults[vaultID]))
            #expect(
                (try? await account.session.item(id: bank.id))?.title == bank.title,
                "the planted deletion counted on the \(name)'s device")
        }
        // Gone from the store, the plant leaves the victim's stream as it was, and the victim's work counts.
        await Self.remove(planted, from: household.transport)
        var item = Self.bank(in: vaultID)
        item.title = "The victim's own"
        let own = try await victim.session.save(item)
        try await Self.syncAll([victim, owner, reader])
        for (name, account) in [("owner", owner), ("reader", reader)] {
            #expect(await account.session.streamOwner(victimDevice, in: vaultID) == victim.accountID)
            #expect(
                (try? await account.session.item(id: own.id))?.title == own.title,
                "the victim's work is held aside on the \(name)'s device")
        }
        // The promoted member's own later work counts.
        var later = Self.bank(in: vaultID)
        later.title = "Written by the promoted member"
        later = try await reader.session.save(later)
        try await Self.syncAll([reader, owner, victim])
        for account in [owner, victim] {
            #expect((try? await account.session.item(id: later.id))?.title == later.title)
        }
    }
}

// Review finding Z155: what a member who may never write could add to the signed stream index had no bound.
extension AdversarialSharedVaultTests {
    /// Signs `entries` as `sequence` of `device`'s stream with `signer`'s keys and puts it on the transport.
    static func plantSegment(
        by signer: SharingAccount, as device: UUID, sequence: UInt64, in vaultID: UUID, entries: [SyncEntry] = [],
        on transport: InMemorySyncTransport
    ) async throws {
        let location = SyncObjectLocation.segment(vaultID: vaultID, author: device, sequence: sequence)
        let payload = SyncPayload(
            kind: .segment, vaultID: vaultID, author: device, number: sequence, vector: [:], entries: entries)
        let adapter = VaultSyncAdapter(session: signer.session)
        let envelope = try await adapter.seal(payload.encoded(), at: location)
        let signature = try await adapter.sign(envelope, at: location)
        try await transport.create(
            location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
    }

    /// Threat: a read-only member (A4) who signs segment after segment into the stream of a device of their own.
    /// Since Z146 each was recorded, by digest and signer, in every device's signed index, about 60 bytes apiece with
    /// no limit: past the index's 64 MiB bound it is refused and rebuilt from the log at every load; Z155 recorded them
    /// only below another account's segment in the same stream. A stream is one account's now (Z157), and nothing a
    /// member who may never write signs is recorded at all: no cut runs over it, and a promotion replays the log. The
    /// stream is passed over all the same, and the other streams go on.
    @Test("a read-only member's segments are passed over and never recorded")
    func readOnlyFloodIsNotRecorded() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 3900)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let victim = try await household.account(seed: 3901)
        let reader = try await household.account(seed: 3902)
        try await owner.invite(victim, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(reader, to: vaultID, as: .readOnly, owner: owner)
        _ = try await victim.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, victim, reader])
        let own = try await household.secondDevice(of: reader)
        let ownDevice = try await Self.deviceID(of: own)
        try await own.session.acceptInvitation(
            Invitation(vaultID: vaultID, ownerAccountID: owner.accountID),
            ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await own.session.sync()
        for sequence in 1...12 {
            try await Self.plantSegment(
                by: own, as: ownDevice, sequence: UInt64(sequence), in: vaultID, on: household.transport)
        }
        try await owner.session.sync()
        for sequence in 1...12 {
            #expect(await !owner.session.recordedSegment(ownDevice, UInt64(sequence), in: vaultID))
        }
        #expect(
            try await owner.session.syncAll().vaults[vaultID]?.waiting[ownDevice] == nil, "the stream was not passed")

        var item = Self.bank(in: vaultID)
        item.title = "Written beside the flood"
        item = try await victim.session.save(item)
        try await victim.session.sync()
        try await Self.syncAll([owner], rounds: 2)
        #expect(try await owner.session.item(id: item.id).title == item.title)
        #expect(await owner.session.judgementIsSettled(vaultID))
        try await owner.session.sync()
        #expect(await owner.session.judgementIsSettled(vaultID), "the log is replayed at every sync")
    }
}

// Round 5's Lows (docs/06-adversarial-review.md Z161): the judged basis worked out without this account's registry.
extension AdversarialSharedVaultTests {
    /// Threat: someone with the device's files (A8) who removes what this account's registry needs (here its anchor
    /// in the Keychain; equally a registry row the anchor names), or a failure reading it. The judged basis binds the
    /// revocations a judgement rested on, this account's among them; worked out without the registry it lacked them,
    /// differed from the one settled, and the next take-out removed and replayed every version for nothing, at will.
    /// A basis that cannot be worked out is none: nothing is taken out or settled until the registry reads again.
    @Test("an unreadable own registry takes nothing out and settles nothing")
    func unreadableRegistrySettlesNothing() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 5800)
        let (owner, member) = (home.owner, home.members[0])
        let item = try await owner.session.save(Self.bank(in: home.vaultID))
        try await Self.syncAll([owner, member])
        #expect(await member.session.judgedBasis(home.vaultID) != nil)

        let accountID = member.accountID
        let anchor = try #require(
            try await member.vault.keychain.read(.deviceRegistryAnchor(accountID: accountID), prompt: ""))
        try await member.vault.keychain.delete(.deviceRegistryAnchor(accountID: accountID))
        await member.session.invalidateRegistry()
        #expect(await member.session.judgedBasis(home.vaultID) == nil, "a basis without this account's registry")
        try await member.session.takeOutWhatNoLongerCounts(home.vaultID)
        #expect(try await member.session.item(id: item.id).title == item.title, "an item was taken out")
        #expect(await !member.session.replayIsRequested(home.vaultID))

        try await member.vault.keychain.store(anchor, for: .deviceRegistryAnchor(accountID: accountID))
        await member.session.invalidateRegistry()
        try await member.session.sync()
        #expect(await member.session.judgementIsSettled(home.vaultID))
        #expect(try await member.session.item(id: item.id).title == item.title)
    }
}
