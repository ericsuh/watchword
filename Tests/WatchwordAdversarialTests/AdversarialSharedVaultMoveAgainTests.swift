import Foundation
import Testing
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

// The review of the merge of round 17 into the branch that keeps conflict copies (docs/06-adversarial-review.md Z216,
// V57): a device move made again after the first attempt's state for a vault was damaged. In the suite "shared vaults
// through the session".
extension AdversarialSharedVaultTests {
    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), between two
    /// attempts at one device move, on an installation restored twice: its first restore's work in a shared vault is
    /// still to carry when the second restore moves the device again, and that move is cut short (a lock) after it
    /// has written the vault's chain row and state. The second attempt finds the vault's state verifying for neither
    /// device ID and read only the rows the ID it moves from left, not those of the ID before it, which the first
    /// restore had recorded (review of the merge of round 17, finding 2; V57): it saved a state that verifies and names
    /// none of that work, the hold reads that state, and the copy was never carried, held deletions back no more, and
    /// reached nobody, though the chain row the first attempt signed still named that ID. The move made again now also
    /// reads the rows of every earlier ID the vault's chain row names: the copy is carried and reaches the owner.
    @Test("a move made again after its vault's state was damaged keeps the work an earlier restore left there")
    func moveMadeAgainKeepsAnEarlierRestoresWork() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 31_500)
        let member = members[0]
        let earliest = try #require(await member.session.deviceIDForTest())
        let saved = try await member.session.save(Self.bank(in: vaultID))
        let key = RecordKey(recordID: saved.id, kind: .item)
        let first = try await Self.restoredOntoOtherHardware(member, household: household, seed: 31_501)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        let recorded = try #require(await raw.loadState(vaultID: vaultID)).restoredUnpublished
        #expect(recorded[key]?.device == earliest, "the first restore recorded nothing to carry: nothing is tested")

        // The second restore, onto other hardware again, whose move a lock cuts short once the vault's state is saved.
        await first.session.lock()
        await first.forgetDeviceKey(accountID: member.accountID)
        let locking = MoveLockingSyncState(base: raw, vaultID: vaultID)
        let second = TestVault(
            store: first.store, keychain: first.keychain, biometrics: first.biometrics, clock: first.clock,
            sync: SyncSettings(state: locking, transport: household.transport), seed: 31_502,
            deviceKeys: first.deviceKeys)
        await second.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: household.directory))
        await locking.lock(second.session)
        _ = try? await second.session.unlock(password: TestVault.password)
        #expect(await locking.locks == 1, "the move was not cut short: nothing is tested")
        var damaged = try #require(await raw.loadState(vaultID: vaultID))
        #expect(damaged.restoredUnpublished[key]?.device == earliest, "the first attempt dropped the earlier work")
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)

        // The move made again, then the syncs that carry and publish.
        if (try? await second.session.state()) != .unlocked {
            try await second.session.unlock(password: TestVault.password)
        }
        _ = try await second.session.syncAll()
        let again = try #require(await raw.loadState(vaultID: vaultID))
        let row = try #require(try await second.store.record(key))
        let kept = again.restoredUnpublished[key] != nil || row.deviceID != earliest
        #expect(kept, "the move made again dropped the earlier restore's work, and nothing carried it")
        _ = try await second.session.syncAll()
        try await Self.syncAll([owner])
        let atOwner = try? await owner.session.item(id: saved.id)
        #expect(atOwner != nil, "the earlier restore's work never reached the owner")
    }
}

/// A sync state store that locks a session once, right after saving a state of one vault that records a restore's
/// work (`SyncState.restoredUnpublished`): a device move cut short after it wrote that vault's chain row and state.
actor MoveLockingSyncState: SyncStateStore {
    let base: any SyncStateStore
    let vaultID: UUID
    private var target: VaultSession?
    private(set) var locks = 0

    init(base: any SyncStateStore, vaultID: UUID) {
        self.base = base
        self.vaultID = vaultID
    }

    func lock(_ session: VaultSession) {
        target = session
    }

    func loadState(vaultID: UUID) async throws -> SyncState? { try await base.loadState(vaultID: vaultID) }

    func saveState(_ state: SyncState) async throws {
        try await base.saveState(state)
        guard state.vaultID == vaultID, !state.restoredUnpublished.isEmpty, let target else { return }
        self.target = nil
        locks += 1
        await target.lock()
    }

    func stage(_ object: StagedObject) async throws { try await base.stage(object) }
    func staged(vaultID: UUID) async throws -> [StagedObject] { try await base.staged(vaultID: vaultID) }
    func unstage(_ locations: [SyncObjectLocation]) async throws { try await base.unstage(locations) }
    func prepared(_ deletion: PendingDeletion) async throws -> PendingDeletion { try await base.prepared(deletion) }
    func addPendingDeletion(_ deletion: PendingDeletion) async throws { try await base.addPendingDeletion(deletion) }

    func pendingDeletions(vaultID: UUID) async throws -> [RecordKey: PendingDeletion] {
        try await base.pendingDeletions(vaultID: vaultID)
    }

    func removePendingDeletions(_ deletions: [RecordKey: RecordStamp], vaultID: UUID) async throws {
        try await base.removePendingDeletions(deletions, vaultID: vaultID)
    }

    func quarantine(_ entry: SyncEntry, vaultID: UUID) async throws -> Bool {
        try await base.quarantine(entry, vaultID: vaultID)
    }

    func quarantined(vaultID: UUID) async throws -> [SyncEntry] { try await base.quarantined(vaultID: vaultID) }

    func discardQuarantined(_ entries: [SyncEntry], vaultID: UUID) async throws {
        try await base.discardQuarantined(entries, vaultID: vaultID)
    }

    func holdsQuarantined(_ entry: SyncEntry, vaultID: UUID) async throws -> Bool {
        try await base.holdsQuarantined(entry, vaultID: vaultID)
    }

    func quarantineUsage(vaultID: UUID) async throws -> QuarantineUsage {
        try await base.quarantineUsage(vaultID: vaultID)
    }

    func stash(vaultID: UUID) async throws -> [UInt8]? { try await base.stash(vaultID: vaultID) }
    func saveStash(_ bytes: [UInt8], vaultID: UUID) async throws { try await base.saveStash(bytes, vaultID: vaultID) }
    func eraseAll() async throws { try await base.eraseAll() }
}
