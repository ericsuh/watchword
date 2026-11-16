import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

/// Shared vaults wired into `VaultSession` and `SyncEngine` (docs/02-architecture.md §8.7, §8.8), attacked through
/// real sessions of different accounts over one transport. The adversaries are those of §2: the sync store (A1), a
/// current member (A4) and a former member (A5), each named with its access in the test's comment.
@Suite("Adversarial: shared vaults through the session", .tags(.adversarial))
struct AdversarialSharedVaultTests {
    static func bank(in vaultID: UUID) -> Item {
        var item = AutoFillFixtures.bank
        item.id = UUID()
        item.vaultID = vaultID
        return item
    }

    static func syncAll(_ accounts: [SharingAccount], rounds: Int = 2) async throws {
        for _ in 0..<rounds {
            for account in accounts { try await account.session.sync() }
        }
    }

    static func setting(_ kind: FieldKind, to value: String, in item: Item) -> Item {
        var item = item
        item.fields = item.fields.map { field in
            var field = field
            if field.kind == kind { field.value = value }
            return field
        }
        return item
    }

    /// Threat: review finding S28 over sync's own objects. A former member (A5) whose client still writes, with a
    /// store (A1) that withholds the record removing them from them and from one remaining read-write member's
    /// device. The former member changes the bank password and adds an item after the removal; the other member's
    /// device merges both (it has not seen the record), then edits the item on top of the late write and publishes.
    /// Once that device is shown the record, the late writes count on no device: not on the owner's, which never
    /// merged them, not on the member's, which takes them out again, and not on a member invited afterwards. What
    /// the former member wrote while they could, inside the cut the owner's device signed, still counts everywhere.
    /// Nothing is destroyed: what does not count is held aside for the person.
    @Test("a removed member's late writes count nowhere, even on a device that merged them before it knew")
    func lateWritesOfARemovedMember() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 500)
        let (removed, removedView) = try await household.withheldAccount(seed: 517)
        let (member, memberView) = try await household.withheldAccount(seed: 534)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(removed, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([owner, removed, member])

        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, removed, member])
        // Written while they could: inside the cut.
        var inCut = try await removed.session.item(id: bank.id)
        inCut.title = "First Bank (joint)"
        try await removed.session.save(inCut)
        try await Self.syncAll([removed, owner, member])
        #expect(try await member.session.item(id: bank.id).title == "First Bank (joint)")

        // The store withholds every sharing object created from now on from the two devices.
        await removedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await memberView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        #expect(try await owner.session.removeMember(removed.accountID, from: vaultID) == .complete)

        // The former member's client has not heard of it, and the store still takes their writes.
        let late = Self.setting(.password, to: "late-password", in: try await removed.session.item(id: bank.id))
        try await removed.session.save(late)
        let planted = try await removed.session.save(
            Item(vaultID: vaultID, title: "Late item", scopes: [], fields: []))
        try await removed.session.sync()

        // The other member's device merges both, and writes on top of the late password.
        try await member.session.sync()
        #expect(try await member.session.item(id: bank.id).field(.password)?.value == "late-password")
        var onTop = try await member.session.item(id: bank.id)
        onTop.notes = "Written on top of the late password"
        try await member.session.save(onTop)
        try await member.session.sync()

        // The owner's device never counts either write, nor the member's version that carries one.
        try await owner.session.sync()
        #expect(try await owner.session.item(id: bank.id).field(.password)?.value == "bank-password")
        #expect(try await owner.session.items(in: vaultID).items.allSatisfy { $0.id != planted.id })
        #expect(!(try await owner.session.quarantinedVersions()).isEmpty)

        // Shown the record, the member's device takes the late writes out again and holds them aside.
        await memberView.reveal()
        try await Self.syncAll([member, owner, member])
        let settled = try await member.session.item(id: bank.id)
        #expect(settled.field(.password)?.value == "bank-password")
        #expect(settled.title == "First Bank (joint)")
        #expect(try await member.session.items(in: vaultID).items.allSatisfy { $0.id != planted.id })
        let heldAside = try await member.session.quarantinedVersions()
        #expect(heldAside.contains { $0.recordID == bank.id })
        #expect(heldAside.contains { $0.recordID == planted.id })
        // Both remaining devices hold the same item.
        let ownerCopy = try await owner.session.item(id: bank.id)
        #expect(ownerCopy.fields == settled.fields && ownerCopy.title == settled.title)

        // A member invited afterwards counts what the cut holds and nothing the former member wrote after it.
        let newcomer = try await household.account(seed: 551)
        try await owner.invite(newcomer, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([newcomer, owner, newcomer])
        let fresh = try await newcomer.session.item(id: bank.id)
        #expect(fresh.title == "First Bank (joint)")
        #expect(fresh.field(.password)?.value == "bank-password")
        #expect(try await newcomer.session.items(in: vaultID).items.allSatisfy { $0.id != planted.id })
    }

    /// Threat: S28 for a demotion, where there is no transport step at all and no new key: a member made read-only
    /// (A4) whose client has not been shown the record, with a store (A1) that hides it from them and from another
    /// member's device, keeps writing. Their writes before the change count everywhere (they are inside the cut the
    /// owner's device signed); the late one counts nowhere, including on the device that merged it before it knew.
    @Test("a demoted member's late write is taken out again on a device that merged it")
    func lateWriteOfADemotedMember() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 900)
        let (demoted, demotedView) = try await household.withheldAccount(seed: 917)
        let (member, memberView) = try await household.withheldAccount(seed: 934)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(demoted, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, demoted, member])
        var before = try await demoted.session.item(id: bank.id)
        before.title = "Written while read-write"
        try await demoted.session.save(before)
        try await Self.syncAll([demoted, owner, member])

        await demotedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await memberView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        try await owner.session.changeRole(of: demoted.accountID, in: vaultID, to: .readOnly)
        try await demoted.session.save(
            Self.setting(.password, to: "late-password", in: try await demoted.session.item(id: bank.id)))
        try await demoted.session.sync()
        try await member.session.sync()
        #expect(try await member.session.item(id: bank.id).field(.password)?.value == "late-password")

        try await owner.session.sync()
        #expect(try await owner.session.item(id: bank.id).field(.password)?.value == "bank-password")
        await memberView.reveal()
        try await Self.syncAll([member, owner, member])
        let settled = try await member.session.item(id: bank.id)
        #expect(settled.field(.password)?.value == "bank-password")
        #expect(settled.title == "Written while read-write")
        #expect(try await owner.session.item(id: bank.id).title == "Written while read-write")
        // Shown the record at last, the demoted member's own client refuses further writes.
        await demotedView.reveal()
        try await demoted.session.sync()
        await #expect(throws: SharedVaultError.writeRefused(.readOnly)) {
            try await demoted.session.save(try await demoted.session.item(id: bank.id))
        }
    }

    /// Threat: a key grant planted by someone the chain does not entitle to send one: the store (A1), or anyone with
    /// create access to the vault's prefix, files grants of a key of their own choosing, under the current key's ID,
    /// to the invitee, ahead of the owner's. Accepting must take the owner's key and nothing else; with only forged
    /// grants on the store, accepting fails rather than adopting a key a stranger holds.
    @Test("a grant from anyone but the entitled sender is never adopted")
    func forgedGrant() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 600)
        let invitee = try await household.account(seed: 617)
        let stranger = try SharingParty(seed: 633)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.session.verifyContact(invitee.accountID, evidence: .safetyNumber(invitee.safetyNumber))
        let invitation = try await owner.session.invite(invitee.accountID, to: vaultID, as: .readWrite)
        let keyID = try await owner.session.sharedVaultStatus(vaultID).membership.vaultKeyID

        var generator = SeededGenerator(seed: 1)
        let strangersKey = VaultKey.generate(vaultID: vaultID, using: &generator)
        let forged = try KeyGrantCodec.encode(
            VaultKeyGrant.seal(strangersKey, to: invitee.bundle, from: stranger.keyset))
        let prefix = SharingObjectLocation.grantPrefix(vaultID: vaultID, keyID: keyID, recipient: invitee.accountID)
        let genuine = await household.transport.list(prefix: prefix)
        #expect(genuine.count == 1)
        // Filed correctly, named by its own digest, so it is looked at first and refused.
        let forgedName = prefix + String(repeating: "0", count: 64)
        await household.transport.tamper(forgedName, contents: forged)
        await household.transport.tamper(
            prefix + SharingObjectLocation.digest(of: forged).map { String(format: "%02x", $0) }.joined(),
            contents: forged)

        // With the genuine grant hidden, accepting fails: no key is adopted from a stranger.
        let genuineBytes = try #require(await household.transport.fetch(genuine[0], maximumLength: 1 << 16))
        await household.transport.tamper(genuine[0], contents: nil)
        await #expect(throws: SharingError.grantNotFound) {
            try await invitee.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(owner.safetyNumber))
        }
        await household.transport.tamper(genuine[0], contents: genuineBytes)
        try await invitee.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(owner.safetyNumber))

        // The invitee reads what the owner writes, so the key it holds is the owner's.
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await owner.session.sync()
        try await invitee.session.sync()
        #expect(try await invitee.session.item(id: bank.id).field(.password)?.value == "bank-password")
    }

    /// Threat: the store (A1) moves objects between two shared vaults of one household: the log segments, the
    /// membership records and the grants of one vault copied under the other's names. Every one is bound to where it
    /// was written (the signature covers a segment's name, a record names its vault, a grant's identity comes from
    /// where it is filed), so the other vault's members see nothing of the first vault in theirs.
    @Test("objects copied from one shared vault into another are refused there")
    func recordSwapBetweenVaults() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 700)
        let member = try await household.account(seed: 717)
        let first = try await owner.session.createVault(name: "Bills").id
        let second = try await owner.session.createVault(name: "Travel").id
        for vaultID in [first, second] {
            try await owner.session.shareVault(vaultID)
            try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        }
        let secret = try await owner.session.save(Self.bank(in: first))
        try await Self.syncAll([owner, member])
        #expect(try await member.session.items(in: second).items.isEmpty)

        let transport = household.transport
        // Each segment of the first vault's log, at the next free place in the same device's stream of the second.
        for name in await transport.list(prefix: SyncObjectLocation.vaultPrefix(first)) {
            guard let location = SyncObjectLocation(name: name), location.kind == .segment else { continue }
            let taken =
                await transport.list(prefix: SyncObjectLocation.vaultPrefix(second)).compactMap {
                    SyncObjectLocation(name: $0)
                }.filter { $0.author == location.author && $0.kind == .segment }.map(\.number).max() ?? 0
            let moved = SyncObjectLocation.segment(vaultID: second, author: location.author, sequence: taken + 1)
            await transport.tamper(moved.name, contents: try await transport.fetch(name, maximumLength: 1 << 24))
        }
        for name in await transport.list(prefix: SharingObjectLocation.vaultPrefix(first)) {
            let copy = name.replacingOccurrences(of: first.uuidString, with: second.uuidString)
            await transport.tamper(copy, contents: try await transport.fetch(name, maximumLength: 1 << 20))
        }
        let before = try await member.session.sharedVaultStatus(second).membership
        let report = try await member.session.syncAll()
        try await member.session.sync()
        #expect(try await member.session.items(in: second).items.isEmpty)
        #expect(try await member.session.sharedVaultStatus(second).membership == before)
        #expect(!(report.vaults[second]?.rejected.isEmpty ?? true))
        #expect((report.sharing[second]?.recordsRejected ?? 0) > 0)
        // The first vault is untouched.
        #expect(try await member.session.item(id: secret.id).vaultID == first)
    }

    /// Threat: none from outside — a lock (the person, or auto-lock; A3's mitigation) lands while a removal is
    /// publishing its grants. The operation must stop at once with nothing half-done that matters: no key in the
    /// clear anywhere (the plan holds none), and the signed plan saved, so the next unlocked sync resumes it and the
    /// removal and rotation complete.
    @Test("a removal interrupted by lock() is resumed by the next sync and completes")
    func rotationInterruptedByLock() async throws {
        let base = InMemorySyncTransport()
        let directory = InMemoryKeyBundleDirectory()
        let tripwire = LockingTransport(base: base)
        let owner = try await SharingAccount.make(over: tripwire, directory: directory, seed: 800)
        let member = try await SharingAccount.make(over: base, directory: directory, seed: 817)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        _ = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, member])

        // Lock as soon as the first grant of the new key is being published.
        await tripwire.lock(
            owner.session, onCreateUnder: SharingObjectLocation.vaultPrefix(vaultID) + "grant/")
        await #expect(throws: (any Error).self) {
            try await owner.session.removeMember(member.accountID, from: vaultID)
        }
        #expect(try await owner.session.state() == .locked)
        #expect(try await owner.session.sharedVaultStatus(vaultID).membership.member(member.accountID) != nil)

        try await owner.session.unlock(password: TestVault.password)
        try await Self.syncAll([owner, member], rounds: 3)
        let status = try await owner.session.sharedVaultStatus(vaultID)
        #expect(status.membership.member(member.accountID) == nil)
        #expect(status.pendingRotation.isEmpty)
        #expect(try await member.session.sharedVaultStatus(vaultID).role == nil)
    }
}

/// A transport that locks a session the first time an object is created under a prefix: the lock lands inside the
/// session's own call, at the suspension where it writes.
actor LockingTransport: SyncTransport {
    let base: InMemorySyncTransport
    private var trigger: (session: VaultSession, prefix: String)?

    init(base: InMemorySyncTransport) {
        self.base = base
    }

    func lock(_ session: VaultSession, onCreateUnder prefix: String) {
        trigger = (session, prefix)
    }

    func list(prefix: String) async throws -> [String] {
        await base.list(prefix: prefix)
    }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws {
        if let trigger, name.hasPrefix(trigger.prefix) {
            self.trigger = nil
            await trigger.session.lock()
        }
        try await base.create(name, contents: contents)
    }

    func delete(_ name: String) async throws {
        await base.delete(name)
    }
}
