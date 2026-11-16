import Foundation
import SecureMemory
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// Review of the sharing integration (docs/06-adversarial-review.md §I, S36 to S41): attribution of values by their
/// bytes rather than their stamps, erasures that stop counting, key IDs chosen by another vault's owner, registries
/// anchored per vault, and a replay that must outlast a restart. In the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    typealias Fixture = AdversarialSharedVaultTests

    /// A household of an owner, a member who will be removed and a member who stays, both of the latter behind views
    /// of the transport the store controls; the bank item saved by the owner and written once, inside the cut, by
    /// `inCutWriter` (its title). Returns the in-cut revision.
    static func householdBeforeARemoval(
        _ household: SharedVaultHousehold, seed: UInt64, inCutWriter: (SharingAccount, SharingAccount) -> SharingAccount
    ) async throws -> (
        vaultID: UUID, bank: Item, owner: SharingAccount, removed: SharingAccount, removedView: WithholdingTransport,
        member: SharingAccount, memberView: WithholdingTransport, inCut: Revision
    ) {
        let owner = try await household.account(seed: seed)
        let (removed, removedView) = try await household.withheldAccount(seed: seed + 17)
        let (member, memberView) = try await household.withheldAccount(seed: seed + 34)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(removed, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        try await syncAll([owner, removed, member])
        let bank = try await owner.session.save(bank(in: vaultID))
        try await syncAll([owner, removed, member])
        let writer = inCutWriter(removed, member)
        var edit = try await writer.session.item(id: bank.id)
        edit.title = "First Bank (joint)"
        let saved = try await writer.session.save(edit)
        let inCut = try #require(saved.revisions[.title]?.revision)
        try await syncAll([writer, owner, writer.accountID == removed.accountID ? member : removed])
        return (vaultID, bank, owner, removed, removedView, member, memberView, inCut)
    }

    /// Threat: review finding S36. A former member (A5) whose client still writes, with a store (A1) that withholds
    /// the record removing them from them and from the remaining member's device. The former member writes a late
    /// password and labels it, stamp and all, as a revision the remaining member really wrote (their in-cut title
    /// edit), at a higher version; a judge that read whose work a value is from its stamp would count it everywhere
    /// once the remaining member wrote on top. The remaining member's own device refuses it at once — a device knows
    /// what it wrote — and so does every other: no stream of the named device carried those bytes.
    @Test("a late value relabelled as a remaining member's revision counts on no device")
    func relabelledAsARemainingMember() async throws {
        let household = SharedVaultHousehold()
        let setup = try await Self.householdBeforeARemoval(household, seed: 1_000) { _, member in member }
        let (vaultID, bank, owner, removed, member) = (
            setup.vaultID, setup.bank, setup.owner, setup.removed, setup.member
        )
        await setup.removedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await setup.memberView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        #expect(try await owner.session.removeMember(removed.accountID, from: vaultID) == .complete)

        let late = try await removed.session.save(
            Fixture.setting(.password, to: "late-password", in: try await removed.session.item(id: bank.id)))
        let lateRevision = try #require(late.revisions.values.map(\.revision).first { $0.version == late.version })
        try await removed.session.overwriteAsAModifiedClient(late.relabelled(lateRevision, as: setup.inCut))
        try await removed.session.sync()

        // The remaining member's device never merges it: the password claims to be its own write, and is not.
        let report = try await member.session.syncAll()
        #expect(report.vaults[vaultID]?.heldAside.contains(RecordKey(recordID: bank.id, kind: .item)) == true)
        #expect(try await member.session.item(id: bank.id).field(.password)?.value == "bank-password")
        var onTop = try await member.session.item(id: bank.id)
        onTop.notes = "Written on top"
        try await member.session.save(onTop)
        try await member.session.sync()

        try await owner.session.sync()
        await setup.memberView.reveal()
        try await Fixture.syncAll([member, owner, member])
        #expect(try await owner.session.item(id: bank.id).field(.password)?.value == "bank-password")
        #expect(try await member.session.item(id: bank.id).field(.password)?.value == "bank-password")
        #expect(try await owner.session.item(id: bank.id).notes == "Written on top")

        let newcomer = try await household.account(seed: 1_051)
        try await owner.invite(newcomer, to: vaultID, as: .readWrite, owner: owner)
        try await Fixture.syncAll([newcomer, owner, newcomer])
        #expect(try await newcomer.session.item(id: bank.id).field(.password)?.value == "bank-password")
        #expect(try await newcomer.session.item(id: bank.id).title == "First Bank (joint)")
    }

    /// Threat: review finding S36, the other way round. The former member (A5) labels their late password with
    /// their *own* in-cut revision (the title edit they made while they could write), keeping its `seen`, so that
    /// the version that carried that revision is inside the cut. The bytes of the late value were first carried by
    /// their late segment, outside the cut: it counts nowhere once the merging device (behind the store, A1) is shown
    /// the removal, not on the owner's device, and not inside the version the member wrote on top of it.
    @Test("a late value back-dated to its author's in-cut revision counts on no device")
    func backDatedToAnInCutRevision() async throws {
        let household = SharedVaultHousehold()
        let setup = try await Self.householdBeforeARemoval(household, seed: 1_100) { removed, _ in removed }
        let (vaultID, bank, owner, removed, member) = (
            setup.vaultID, setup.bank, setup.owner, setup.removed, setup.member
        )
        await setup.removedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await setup.memberView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        #expect(try await owner.session.removeMember(removed.accountID, from: vaultID) == .complete)

        let late = try await removed.session.save(
            Fixture.setting(.password, to: "late-password", in: try await removed.session.item(id: bank.id)))
        let lateRevision = try #require(late.revisions.values.map(\.revision).first { $0.version == late.version })
        try await removed.session.overwriteAsAModifiedClient(late.relabelled(lateRevision, as: setup.inCut))
        try await removed.session.sync()

        try await member.session.sync()
        var onTop = try await member.session.item(id: bank.id)
        onTop.notes = "Written on top"
        try await member.session.save(onTop)
        try await member.session.sync()

        await setup.memberView.reveal()
        try await Fixture.syncAll([member, owner, member, owner])
        #expect(try await member.session.item(id: bank.id).field(.password)?.value == "bank-password")
        #expect(try await owner.session.item(id: bank.id).field(.password)?.value == "bank-password")
        #expect(try await owner.session.item(id: bank.id).title == "First Bank (joint)")
    }

    /// Threat: review finding S40. A former member (A5), before their client hears of the removal, trashes the bank
    /// item and deletes it permanently; the store (A1) withholds the removal from the remaining member's device,
    /// which merges the deletion and loses the item. Once shown the record, that device must have the item back:
    /// a deletion outside the cut erases nothing anywhere, including through the erasures the engine remembers.
    @Test("a removed member's late permanent deletion is undone on the device that merged it")
    func lateErasureOfARemovedMember() async throws {
        let household = SharedVaultHousehold()
        let setup = try await Self.householdBeforeARemoval(household, seed: 1_200) { removed, _ in removed }
        let (vaultID, bank, owner, removed, member) = (
            setup.vaultID, setup.bank, setup.owner, setup.removed, setup.member
        )
        await setup.removedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await setup.memberView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        #expect(try await owner.session.removeMember(removed.accountID, from: vaultID) == .complete)

        try await removed.session.trash(id: bank.id)
        try await removed.session.deletePermanently(id: bank.id)
        try await removed.session.sync()
        try await member.session.sync()
        #expect(try await member.session.items(in: vaultID).items.allSatisfy { $0.id != bank.id })
        try await owner.session.sync()

        await setup.memberView.reveal()
        try await Fixture.syncAll([member, owner, member], rounds: 2)
        let back = try await member.session.item(id: bank.id)
        #expect(back.trashedAt == nil)
        #expect(back.title == "First Bank (joint)")
        #expect(try await owner.session.item(id: bank.id).trashedAt == nil)
    }

    /// Threat: review finding S37. A former member (A5), behind a store (A1) that withholds the removal, renames the
    /// vault at the same version as a concurrent rename by the remaining member, from a device that orders later. The
    /// remaining member's device then stores the former member's name again as a version of its own, one above both;
    /// a judge that looked only at who wrote the row would count it everywhere. The description is judged by the write
    /// that chose it (`VaultMetadata.writtenBy`), so the late name counts nowhere, on the device that stored it again
    /// as on the owner's.
    @Test("a removed member's late rename, stored again by a device that merged it, counts on no device")
    func lateRenameStoredAgain() async throws {
        let household = SharedVaultHousehold()
        let setup = try await Self.householdBeforeARemoval(household, seed: 1_630) { removed, _ in removed }
        let (vaultID, owner, removed, member) = (setup.vaultID, setup.owner, setup.removed, setup.member)
        let removedDevice = try #require(await removed.session.deviceIDForTest())
        let memberDevice = try #require(await member.session.deviceIDForTest())
        await setup.removedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await setup.memberView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        #expect(try await owner.session.removeMember(removed.accountID, from: vaultID) == .complete)

        try await removed.session.renameVault(id: vaultID, to: "Late name")
        try await member.session.renameVault(id: vaultID, to: "Member's name")
        let key = RecordKey(recordID: vaultID, kind: .vaultMetadata)
        let lateRow = try #require(await removed.session.storedRowForTest(key))
        let memberRow = try #require(await member.session.storedRowForTest(key))
        try #require(lateRow.version == memberRow.version && memberDevice.precedes(removedDevice))
        try await removed.session.sync()
        try await member.session.sync()
        try await member.session.sync()
        #expect(try await member.session.vaults().first { $0.id == vaultID }?.name == "Late name")

        try await owner.session.sync()
        await setup.memberView.reveal()
        try await Fixture.syncAll([member, owner, member, owner])
        // The member's own rename lost to the concurrent one by the description's last-writer-wins rule before their
        // device knew; with the late one not counting, every device shows the last name that does.
        #expect(try await owner.session.vaults().first { $0.id == vaultID }?.name == "Household")
        #expect(try await member.session.vaults().first { $0.id == vaultID }?.name == "Household")
    }

    /// Threat: review finding S38. The owner of another vault (A4 there, anyone who can create an account) gives
    /// their vault's key the ID of a key the invitee already holds for a vault of theirs — key IDs are public, in
    /// grant names and envelope headers. Accepting must refuse it before anything is held: the invitee's own vault
    /// stays readable and writable, and nothing of the lure is adopted.
    @Test("an invitation whose key ID is another vault's here is refused, and that vault is untouched")
    func keyIDOfAnotherVault() async throws {
        let household = SharedVaultHousehold()
        let (bills, owner, members) = try await household.household(roles: [.readWrite], name: "Bills", seed: 1_300)
        let victim = members[0]
        let bank = try await owner.session.save(Fixture.bank(in: bills))
        try await Fixture.syncAll([owner, victim])
        let billsKeyID = try await victim.session.sharedVaultStatus(bills).membership.vaultKeyID

        let attacker = try await household.account(seed: 1_351)
        let lure = try await attacker.session.createVault(name: "Lure").id
        var generator = SeededGenerator(seed: 7)
        let chosen = VaultKey(
            vaultID: lure,
            key: try EncryptionKey(
                keyID: billsKeyID, material: SecureBytes(randomCount: EncryptionKey.byteCount, using: &generator)))
        await attacker.session.replaceResidentKey(of: lure, with: chosen)
        try await attacker.session.shareVault(lure)
        #expect(try await attacker.session.sharedVaultStatus(lure).membership.vaultKeyID == billsKeyID)
        try await attacker.session.verifyContact(victim.accountID, evidence: .safetyNumber(victim.safetyNumber))
        let invitation = try await attacker.session.invite(victim.accountID, to: lure, as: .readWrite)

        await #expect(throws: SharedVaultError.keyIDInUse(billsKeyID)) {
            try await victim.session.acceptInvitation(
                invitation, ownerEvidence: .safetyNumber(attacker.safetyNumber))
        }
        #expect(try await victim.session.item(id: bank.id).field(.password)?.value == "bank-password")
        var edit = try await victim.session.item(id: bank.id)
        edit.title = "Still mine"
        try await victim.session.save(edit)
        #expect(!(try await victim.session.sharedVaultIDs()).contains(lure))
        await victim.session.lock()
        try await victim.session.unlock(password: TestVault.password)
        #expect(try await victim.session.item(id: bank.id).title == "Still mine")
    }

    /// Threat: review finding S39. The owner of one vault (A4 there) is read-only in another that a victim shares
    /// with account X, who may write there. In their own vault they list "X" with keys of their own and publish a
    /// registry under X's account ID signed by those keys. The victim, a member of both, must judge each vault's
    /// objects by the keys *that* vault's chain gives X: what the forged registry lists verifies in the attacker's
    /// vault, and in the other vault is no device of X's at all.
    @Test("two vaults listing one account with different keys each judge by their own")
    func registriesAnchoredPerVault() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 1_400)
        let x = try await household.account(seed: 1_417)
        let attacker = try await household.account(seed: 1_434)
        let victim = try await household.account(seed: 1_451)
        let bills = try await owner.session.createVault(name: "Bills").id
        try await owner.session.shareVault(bills)
        try await owner.invite(x, to: bills, as: .readWrite, owner: owner)
        try await owner.invite(attacker, to: bills, as: .readOnly, owner: owner)
        try await owner.invite(victim, to: bills, as: .readWrite, owner: owner)

        // The attacker's own directory says X's keys are the substitute's.
        var substitute = RegistryFixture(seed: 99, accountID: x.accountID)
        let attackersDirectory = InMemoryKeyBundleDirectory()
        await attackersDirectory.publish(try substitute.keyset.publicKeyBundle())
        await attackersDirectory.publish(victim.bundle)
        await attacker.session.configureSharing(
            SharingSettings(state: attacker.state, contacts: attacker.contacts, directory: attackersDirectory))
        let lure = try await attacker.session.createVault(name: "Lure").id
        try await attacker.session.shareVault(lure)
        try await attacker.session.verifyContact(
            x.accountID, evidence: .safetyNumber(try substitute.keyset.publicKeyBundle().fingerprint.safetyNumber))
        _ = try await attacker.session.invite(x.accountID, to: lure, as: .readWrite)
        try await attacker.session.verifyContact(victim.accountID, evidence: .safetyNumber(victim.safetyNumber))
        let invitation = try await attacker.session.invite(victim.accountID, to: lure, as: .readWrite)
        try await victim.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(attacker.safetyNumber))

        let device = RegistryFixture.deviceID(7)
        let genesis = substitute.genesis(device: device)
        await household.transport.tamper(
            AccountObjectLocation.registryEntry(accountID: x.accountID, id: genesis.id.hex).name,
            contents: genesis.serialized())
        try await Fixture.syncAll([owner, x, attacker, victim])

        func signed(in vaultID: UUID) -> (signature: [UInt8], envelope: [UInt8], location: SyncObjectLocation) {
            let location = SyncObjectLocation.segment(vaultID: vaultID, author: device, sequence: 1)
            let envelope = Array("any envelope".utf8)
            let message = VaultSession.syncSignedMessage(envelope, at: location)
            let account = try! substitute.keyset.sign(message, domain: .logSegment)
            let deviceSignature = try! substitute.key(for: device).sign(
                prepared: DeviceSignatures.signedBytes(domain: .logSegment, deviceID: device, message: message))
            return (DualSignature.encode(account: account, device: deviceSignature), envelope, location)
        }
        let inLure = signed(in: lure)
        try await victim.session.syncVerify(inLure.signature, over: inLure.envelope, at: inLure.location)
        let inBills = signed(in: bills)
        await #expect(throws: (any Error).self) {
            try await victim.session.syncVerify(inBills.signature, over: inBills.envelope, at: inBills.location)
        }
        #expect(await victim.session.listingAccounts(device, in: lure) == [x.accountID])
        #expect(await victim.session.listingAccounts(device, in: bills).isEmpty)
    }

    /// Threat: review finding S41, with the store (A1) delaying one member's stream. A device holds aside a version
    /// carrying a value whose own stream it has not been shown; when that stream arrives, the version must count —
    /// and if the sync is cut short before the replay that makes it count begins (a lock, the app killed), the next
    /// launch must still replay, because the need was written down with the index, not only kept in memory.
    @Test("a replay asked for by a stream that arrived late survives a restart before it runs")
    func replayOutlastsARestart() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 1_500)
        let writer = try await household.account(seed: 1_517)
        let (late, lateView) = try await household.withheldAccount(seed: 1_534)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(writer, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(late, to: vaultID, as: .readWrite, owner: owner)
        let bank = try await owner.session.save(Fixture.bank(in: vaultID))
        try await Fixture.syncAll([owner, writer, late])
        let writerDevice = try #require(await writer.session.deviceIDForTest())
        let writersStream = SyncObjectLocation.vaultPrefix(vaultID) + "log/\(writerDevice.uuidString)/"

        await lateView.withholdNew(under: writersStream)
        var edit = try await writer.session.item(id: bank.id)
        edit.title = "Renamed by the writer"
        try await writer.session.save(edit)
        try await writer.session.sync()
        try await owner.session.sync()
        var notes = try await owner.session.item(id: bank.id)
        notes.notes = "Owner's notes"
        try await owner.session.save(notes)
        try await owner.session.sync()

        // The owner's version carries the writer's title, which no stream shown here carried: held aside.
        try await late.session.sync()
        #expect(try await late.session.item(id: bank.id).notes != "Owner's notes")
        #expect(!(try await late.session.quarantinedVersions()).isEmpty)

        // The stream arrives, and the session locks just after recording it, before anything is merged.
        let tripwire = LockingSharingState(base: late.state)
        await late.session.configureSharing(
            SharingSettings(state: tripwire, contacts: late.contacts, directory: household.directory))
        await lateView.reveal()
        await tripwire.lock(late.session, atIndexWrite: 2)
        _ = try? await late.session.syncAll()
        #expect(try await late.session.state() == .locked)

        let relaunched = late.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: late.state, contacts: late.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        try await relaunched.session.sync()
        let settled = try await relaunched.session.item(id: bank.id)
        #expect(settled.title == "Renamed by the writer")
        #expect(settled.notes == "Owner's notes")
    }
}

extension Item {
    /// The item with every value its writer stamped `from` labelled `to` instead, `seen` kept, one version higher:
    /// what a modified client writes to make a late value look like an earlier one.
    func relabelled(_ from: Revision, as to: Revision) -> Item {
        var item = self
        for (group, stamp) in item.revisions where stamp.revision == from {
            item.revisions[group] = GroupStamp(revision: to, seen: stamp.seen)
        }
        item.version += 1
        return item
    }
}

extension VaultSession {
    /// Seals `item` over the stored row the way a modified client would: no `ItemMerge.stamped`, its sync metadata
    /// as given.
    func overwriteAsAModifiedClient(_ item: Item) async throws {
        guard let account = try await loadAccount(), let keys,
            let key = currentVaultKey(item.vaultID, keys: keys, account: account),
            let existing = try await store.record(RecordKey(recordID: item.id, kind: .item))
        else { throw VaultError.noAccount }
        let sealed = try sealItem(item, vaultKey: key, account: account)
        try await store.commit(StoreChange(upserts: [sealed], expectations: [sealed.key: .version(existing.version)]))
    }

    /// Puts `key` in place of every resident key of `vaultID`, as a client choosing its own key ID would.
    func replaceResidentKey(of vaultID: UUID, with key: VaultKey) {
        guard let current = keys else { return }
        var vaultKeys = current.vaultKeys.filter { $0.value.vaultID != vaultID }
        vaultKeys[key.key.keyID] = key
        keys = UnlockedKeys(accountUnlockKey: current.accountUnlockKey, keyset: current.keyset, vaultKeys: vaultKeys)
    }

    func listingAccounts(_ device: UUID, in vaultID: UUID) async -> [UUID] {
        guard let account = try? await loadAccount() else { return [] }
        let view = try? await registry(account)
        return accountsListing(device, in: vaultID, ownView: view, account: account)
    }

    func storedRowForTest(_ key: RecordKey) async -> StoredRecord? {
        try? await store.record(key)
    }

    func deviceIDForTest() async -> UUID? {
        try? await loadAccount()?.deviceID
    }
}

/// Sharing state that locks a session at its `n`-th write of a stream index from now on: the lock lands inside the
/// session's own sync, between recording a segment and merging it.
actor LockingSharingState: SharingStateStore {
    let base: InMemorySharingStateStore
    private var trigger: (session: VaultSession, remaining: Int)?

    init(base: InMemorySharingStateStore) {
        self.base = base
    }

    func lock(_ session: VaultSession, atIndexWrite count: Int) {
        trigger = (session, count)
    }

    func sharedVaultIDs() async throws -> [UUID] {
        await base.sharedVaultIDs()
    }

    func value(_ key: SharingStateKey, vaultID: UUID) async throws -> [UInt8]? {
        await base.value(key, vaultID: vaultID)
    }

    func setValue(_ value: [UInt8]?, for key: SharingStateKey, vaultID: UUID) async throws {
        await base.setValue(value, for: key, vaultID: vaultID)
        guard key == .streamIndex, let current = trigger else { return }
        if current.remaining <= 1 {
            trigger = nil
            await current.session.lock()
        } else {
            trigger = (current.session, current.remaining - 1)
        }
    }
}
