import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The review of round 21 (docs/06-adversarial-review.md Z245): reads of the record store that decide the deletion gate,
// where one that fails was read as "nothing there" and the gate opened. In the suite "shared vaults through the
// session".
extension AdversarialSharedVaultTests {
    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), for a shared vault
    /// that holds a restore's uncarried copy of a move, beside a record store whose listing of the account's vault
    /// directory fails (a busy or damaged database) as the restore's chain of earlier IDs is read (review of round 21,
    /// Z245). The chain row is then the only record of the copy, as in
    /// `unreadableChainRowHoldsWhereItIsTheOnlyRecord` (Z239). `restoredChain(account:)` listed the directory with
    /// `try?`, so a listing that threw returned a chain with no row in it, the gate read the vault as holding nothing a
    /// restore left, and the original's deletion could go out while its copy reached nobody (PRD F7.6). A listing that
    /// fails now fails the chain, and the gate holds. Only the chain's own listing fails here: the release check's
    /// before it reads.
    @Test("a vault directory listing that fails as a restore's chain is read holds the deletions back")
    func directoryListingFailingInTheChainHolds() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 32_220)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        _ = try await member.session.move(itemID: original.id, to: vaultID)

        await member.session.lock()
        await member.contacts.removePin(for: owner.accountID)
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let failing = ListingFailingStore(base: member.vault.store)
        let restored = TestVault(
            store: failing, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: member.vault.sync, seed: 32_221, deviceKeys: member.vault.deviceKeys)
        await restored.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        #expect(try await failing.loadAccount()?.migration == nil, "the move did not finish at the unlock")
        #expect(await member.state.value(.restoredChain, vaultID: vaultID) != nil, "the move wrote no chain row")

        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        var state = try #require(await raw.loadState(vaultID: vaultID))
        #expect(!state.restoredUnpublished.isEmpty, "nothing recorded to carry")
        state.authenticator = Array(repeating: 0, count: state.authenticator.count)
        await raw.tamper(state)

        let account = try #require(try await failing.loadAccount())
        #expect(await restored.session.holdsUnpublishedWork(in: vaultID, account: account), "no hold to begin with")
        // The release check lists the directory first (`restoredWorkReleased`), and reads it; the chain's own
        // listing, next, fails.
        await failing.failListings(of: .vaultDirectory, skipping: 1)
        let held = await restored.session.holdsUnpublishedWork(in: vaultID, account: account)
        await failing.failListings(of: nil)
        #expect(await failing.refused > 0, "no listing failed: nothing is tested")
        #expect(held, "a directory listing that failed inside the chain's read opened the hold")
    }

    /// Threat: none needed but a record store whose listing of a vault's items fails (a busy or damaged database) as
    /// the deletion gate reads this device's own rows there (review of round 21, Z246). The gate listed them with
    /// `try?`, so a listing that threw was read as no row, and an edit of this device's that no sync has sent (a
    /// move's copy among them) held nothing back: the original's deletion could go out ahead of it (PRD F7.6). A
    /// listing that fails now holds, as a state that cannot be read does.
    @Test("an item listing that fails as the deletion gate reads this device's rows holds the deletions back")
    func itemListingFailingInTheGateHolds() async throws {
        let household = SharedVaultHousehold()
        let (_, owner, members) = try await household.household(roles: [.readWrite], seed: 32_230)
        let member = members[0]
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        try await Self.syncAll([member, owner])

        await member.session.lock()
        let failing = ListingFailingStore(base: member.vault.store)
        let relaunched = TestVault(
            store: failing, keychain: member.vault.keychain, biometrics: member.vault.biometrics,
            clock: member.vault.clock, sync: member.vault.sync, seed: 32_231, deviceKeys: member.vault.deviceKeys)
        await relaunched.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        _ = try await relaunched.session.save(Self.bank(in: personal))

        let account = try #require(try await failing.loadAccount())
        #expect(await relaunched.session.holdsUnpublishedWork(in: personal, account: account), "no hold to begin with")
        await failing.failListings(of: .item)
        let held = await relaunched.session.holdsUnpublishedWork(in: personal, account: account)
        await failing.failListings(of: nil)
        #expect(await failing.refused > 0, "no listing failed: nothing is tested")
        #expect(held, "an item listing that failed opened the hold for an edit nobody has received")
    }
}

/// A record store over `base` whose listings of one kind of record throw while armed, after the next `skipping` of
/// them have read, as a busy or damaged database would.
actor ListingFailingStore: RecordStore {
    struct ListingFailed: Error {}

    let base: any RecordStore
    private var failing: EnvelopeKind?
    private var skipping = 0
    private(set) var refused = 0

    init(base: any RecordStore) {
        self.base = base
    }

    /// Listings of `kind` throw from now on, after the next `skipping` of them; `nil` reads every listing again.
    func failListings(of kind: EnvelopeKind?, skipping: Int = 0) {
        failing = kind
        self.skipping = skipping
    }

    func loadAccount() async throws -> AccountRecord? { try await base.loadAccount() }
    func record(_ key: RecordKey) async throws -> StoredRecord? { try await base.record(key) }
    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        if let failing, kind == failing {
            if skipping > 0 {
                skipping -= 1
            } else {
                refused += 1
                throw ListingFailed()
            }
        }
        return try await base.records(in: vaultID, kind: kind)
    }
    func commit(_ change: StoreChange) async throws { try await base.commit(change) }
    func eraseAll() async throws { try await base.eraseAll() }
}
