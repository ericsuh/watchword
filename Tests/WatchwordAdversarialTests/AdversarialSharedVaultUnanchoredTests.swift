import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordSync
import WatchwordTestSupport

/// A shared vault whose saved ledger does not restore on a member's device (docs/06-adversarial-review.md, V19). In
/// the suite "shared vaults through the session"; the adversaries are those of §2.
extension AdversarialSharedVaultTests {
    /// A member's device whose sharing state still lists `vaultID`, relaunched over `contacts`, unlocked.
    static func relaunch(
        _ member: SharingAccount, directory: InMemoryKeyBundleDirectory, board: (any SharingBoard)? = nil
    ) async throws -> TestVault {
        let relaunched = member.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(
                state: member.state, contacts: member.contacts, directory: directory,
                shareAccess: member.shareAccess, board: board))
        try await relaunched.session.unlock(password: TestVault.password)
        return relaunched
    }

    /// Threat: A8 (write access to the device's files while the app is closed) deletes the owner's pin, so the saved
    /// ledger of a shared vault no longer restores at the next launch (S13 accepts the deletion on the premise that it
    /// puts the owner back in front of the person). The vault has no "shared" flag of its own, so it used to fall back
    /// to being one of the account's own: synced with no judge and with snapshots and collection on, written and
    /// renamed by a member who may not, sealed under the smallest key ID held (perhaps one from before a rotation), and
    /// offered for sharing, which minted a new genesis over the saved owner. The vault is now shared and unavailable:
    /// nothing is written, renamed, published, verified or shared again, an invitation is not accepted without the
    /// owner checked, and it comes back once the owner is checked again.
    @Test("a shared vault whose ledger does not restore is unavailable, never one of the member's own vaults")
    func unrestoredSharedVaultIsUnavailable() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readOnly], seed: 1_270)
        let member = members[0]
        await member.contacts.removePin(for: owner.accountID)
        let ownerRow = await member.state.value(.owner, vaultID: vaultID)
        let ledgerRow = await member.state.value(.ledger, vaultID: vaultID)
        let device = try await Self.relaunch(member, directory: household.directory)
        let session = device.session

        #expect(try await session.sharedVaultIDs().contains(vaultID) == false)
        #expect(try await session.sharedVaultsAwaitingOwnerCheck() == [vaultID])
        // Only the pin is missing, and the screen says so (V33).
        #expect(try await session.unavailableSharedVaults()[vaultID] == .ownerNotChecked(owner: owner.accountID))
        // A read-only member's device writes nothing, renames nothing and shares nothing again.
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            _ = try await session.save(Self.bank(in: vaultID))
        }
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            _ = try await session.renameVault(id: vaultID, to: "Ours now")
        }
        await #expect(throws: SharedVaultError.ledgerUnavailable(vaultID)) {
            try await session.shareVault(vaultID)
        }
        // Accepting the vault's invitation again is the way back (V31), and it needs the owner checked first.
        await #expect(throws: SharingError.fingerprintNotVerified) {
            try await session.acceptInvitation(Invitation(vaultID: vaultID, ownerAccountID: owner.accountID))
        }
        #expect(await member.state.value(.owner, vaultID: vaultID) == ownerRow, "the saved owner is untouched")
        #expect(await member.state.value(.ledger, vaultID: vaultID) == ledgerRow, "the saved ledger is untouched")

        // The owner writes; the member's sync publishes nothing in the vault, snapshots and collects nothing, and
        // takes in nothing it cannot judge.
        let written = try await owner.session.save(Self.bank(in: vaultID))
        try await owner.session.sync()
        let before = Set(await household.transport.list(prefix: SyncObjectLocation.vaultPrefix(vaultID)))
        try await session.sync()
        try await session.sync()
        let after = Set(await household.transport.list(prefix: SyncObjectLocation.vaultPrefix(vaultID)))
        #expect(after == before, "nothing was published, snapshotted or collected in the vault")
        await #expect(throws: VaultError.itemNotFound(written.id), "nothing was taken in unjudged") {
            _ = try await session.item(id: written.id)
        }

        // Checked again, the owner's pin restores the vault, as shared and read-only.
        try await session.verifyContact(owner.accountID, evidence: .safetyNumber(owner.safetyNumber))
        #expect(try await session.sharedVaultIDs().contains(vaultID))
        #expect(try await session.sharedVaultsAwaitingOwnerCheck().isEmpty)
        #expect(try await session.sharedVaultStatus(vaultID).role == .readOnly)
    }

    /// Threat: A8 damages a shared vault's saved ledger (it no longer restores) while the owner's pin stays, A1 serves
    /// impostor keys for the owner, and an attacker nearby runs a session as the owner's account; the person types the
    /// attacker's digits (V14) and chooses "use their new keys" after the warning (V28). With no vault loaded that lists
    /// the owner, the guard found nothing to object to and replaced the owner's pin, after which an invitation from the
    /// attacker for the vault would pass the owner check. Every shared vault is loaded first, and while one cannot be
    /// restored nothing replaces a pin on a session's word.
    @Test("no pin is replaced from a session while a shared vault here cannot be restored")
    func noPinReplacedWhileAVaultIsUnrestored() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 1_340)
        let member = members[0]
        await member.state.tamper(.ledger, vaultID: vaultID, value: Array(repeating: 0x57, count: 64))
        let device = try await Self.relaunch(member, directory: household.directory, board: household.board)

        let impostor = try SharingParty(accountID: owner.accountID, seed: 1_349)
        await household.directory.publish(impostor.bundle)
        var generator = SeededGenerator(seed: 1_350)
        var fake = SharingCodeStarter.draw(as: impostor.bundle, using: &generator, at: Date())
        try await fake.publish(on: household.board, at: Date())
        let joined = try await device.session.joinSharingCodeSession(number: fake.number.digits)
        #expect(joined.partner == owner.accountID)
        try await fake.poll(board: household.board, directory: household.directory, at: Date())
        let shown = try await device.session.refreshSharingCodeSession()
        _ = try fake.enterJoinerCode(try #require(shown.ownCode), at: Date())
        let typed = try await device.session.enterSharingCode(try #require(fake.code))
        #expect(typed.keysDifferFromPin && !typed.pinned)

        await #expect(throws: SharedVaultError.sharingCodeKeysNotListed) {
            try await device.session.replacePinFromSharingCode()
        }
        let pins = VerifiedContacts(store: member.contacts, account: member.bundle)
        let pin = try #require(try await pins.pinned(owner.accountID))
        #expect(pin.bundle.hasSameKeys(as: owner.bundle), "the owner's pin is unchanged")
    }
}

/// A pin store whose reads fail on demand, as damaged or locked-away pins do (A8). Test code only.
actor UnreadablePins: VerifiedContactStore {
    let base: InMemoryVerifiedContactStore
    var failing = true

    init(base: InMemoryVerifiedContactStore) {
        self.base = base
    }

    struct Unreadable: Error {}

    func readable() {
        failing = false
    }

    func pin(for accountID: UUID) async throws -> [UInt8]? {
        guard !failing else { throw Unreadable() }
        return await base.pin(for: accountID)
    }

    func savePin(_ pin: [UInt8], for accountID: UUID) async throws {
        await base.savePin(pin, for: accountID)
    }

    func removePin(for accountID: UUID) async throws {
        await base.removePin(for: accountID)
    }
}

extension AdversarialSharedVaultTests {
    /// Threat: a member whose keys in the chain differ from this device's pin (A4 re-added under keys of their own)
    /// writes, while no comparison of the chain with the pins could be made on the current head: the pin store could
    /// not be read (A8), or an ingest moved the head while a comparison awaited it (V29). `sharedVerify` took a missing
    /// or stale comparison for "nobody substituted" and accepted every member's objects. With no comparison on the
    /// current head nothing verifies; the objects are fetched again, and judged, once one is made.
    @Test("with no member-key comparison on the current head, no other member's object verifies")
    func noComparisonNoVerification() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 1_360)
        let written = try await members[0].session.save(Self.bank(in: vaultID))
        try await members[0].session.sync()

        let pins = UnreadablePins(base: owner.contacts)
        let relaunched = owner.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(
                state: owner.state, contacts: pins, directory: household.directory, shareAccess: owner.shareAccess))
        try await relaunched.session.unlock(password: TestVault.password)
        try await relaunched.session.sync()
        await #expect(throws: VaultError.itemNotFound(written.id), "taken in with no comparison of the member's keys") {
            _ = try await relaunched.session.item(id: written.id)
        }

        await pins.readable()
        try await relaunched.session.sync()
        try await relaunched.session.sync()
        #expect(try await relaunched.session.item(id: written.id).id == written.id)
    }
}

/// A pin store that holds the first read of one account's pin: the value is read when asked, and handed back only
/// once the test releases it, as a load that read the pins before a later write does. Test code only.
actor HeldPinRead: VerifiedContactStore {
    let base: InMemoryVerifiedContactStore
    let held: UUID
    private var holding = true
    private var reached: CheckedContinuation<Void, Never>?
    private var isReached = false
    private var release: CheckedContinuation<Void, Never>?

    init(base: InMemoryVerifiedContactStore, holding account: UUID) {
        self.base = base
        self.held = account
    }

    /// Returns once the held read has been asked for.
    func waitUntilReached() async {
        if isReached { return }
        await withCheckedContinuation { reached = $0 }
    }

    func releaseRead() {
        release?.resume()
        release = nil
    }

    func pin(for accountID: UUID) async throws -> [UInt8]? {
        let value = await base.pin(for: accountID)
        guard accountID == held, holding else { return value }
        holding = false
        isReached = true
        reached?.resume()
        reached = nil
        await withCheckedContinuation { release = $0 }
        return value
    }

    func savePin(_ pin: [UInt8], for accountID: UUID) async throws {
        await base.savePin(pin, for: accountID)
    }

    func removePin(for accountID: UUID) async throws {
        await base.removePin(for: accountID)
    }
}

extension AdversarialSharedVaultTests {
    /// Threat: none from outside; review finding L4 against V19's recovery. A load of the shared vaults that read the
    /// owner's pin (missing, A8) before the person checked the owner again, and finished after, marked the vaults
    /// loaded with the vault unrestored: the pin's request to load again was lost, and the vault stayed closed for the
    /// session though its owner was checked. A load that began before a pin settles nothing.
    @Test("a load of the shared vaults that read the pins before a new pin was made settles nothing")
    func staleLoadSettlesNothing() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readOnly], seed: 1_560)
        let member = members[0]
        await member.contacts.removePin(for: owner.accountID)
        let pins = HeldPinRead(base: member.contacts, holding: owner.accountID)
        let relaunched = member.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: member.state, contacts: pins, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        let session = relaunched.session

        let load = Task { try await session.sharedVaultIDs() }
        await pins.waitUntilReached()
        try await session.verifyContact(owner.accountID, evidence: .safetyNumber(owner.safetyNumber))
        await pins.releaseRead()
        #expect(try await load.value.contains(vaultID) == false, "the load read the pins before the check")
        #expect(try await session.sharedVaultIDs().contains(vaultID), "and the next one restores the vault")
        #expect(try await session.unavailableSharedVaults().isEmpty)
    }
}
