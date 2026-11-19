import Foundation
import Testing
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The review of PR #22's merge, carried to this branch (docs/06-adversarial-review.md Z249): a sync begun while locked
// that is still running when the unlock registers this restored device and makes, or waits for, the move. In the suite
// "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Threat: a damaged sync state file, or one edited by an attacker with the device's files (A8), on a store
    /// restored twice whose middle ID's state for a shared vault does not verify (as in
    /// `stopWaitingRefusedWhileTheMoveWaits`), and a sync begun while locked (an automatic one at launch) that the
    /// person unlocks during (Z249). Found on PR #22, where a locked sync's download saved the vault's state after the
    /// unlock had registered a new device ID: signed for that ID, it was read as the move's own, begun, or it replaced
    /// the state the move had just saved, and either way the move's record of the first restore's copy was lost and
    /// the original's deletion could go out ahead of it (PRD F7.6). Here a sync decides once, at its start, whether it
    /// may write (`mayWrite`), so one begun locked only downloads, in every vault, whatever happens meanwhile, and a
    /// download saves no state. Pinned whether the unlock's move waits for sharing or is made there.
    @Test(
        "a sync begun locked saves no vault state across the unlock that registers a restored device",
        arguments: [false, true])
    func lockedSyncAcrossTheUnlocksRegistration(sharingFirst: Bool) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 32_270)
        let member = members[0]
        let other = try await household.secondDevice(of: member)
        let personal = try #require(try await member.vault.store.loadAccount()?.personalVaultID)
        let original = try await member.session.save(Self.bank(in: personal))
        try await Self.syncAll([member, owner, other])
        let copy = try await member.session.move(itemID: original.id, to: vaultID)
        let first = try #require(await member.session.deviceIDForTest())
        let middle = try await Self.restoredWithVaultClosed(member, household: household, owner: owner, seed: 32_271)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)

        await middle.session.lock()
        await middle.forgetDeviceKey(accountID: member.accountID)
        var damaged = try #require(await raw.loadState(vaultID: vaultID))
        damaged.authenticator = Array(repeating: 0, count: damaged.authenticator.count)
        await raw.tamper(damaged)
        let hook = TransportListingHook()
        let transport: any SyncTransport = ListingHookedTransport(base: household.transport, hook: hook)
        let settings = SyncSettings(
            state: raw, transport: transport, configuration: try #require(middle.sync).configuration)
        let second = TestVault(
            store: middle.store, keychain: middle.keychain, biometrics: middle.biometrics, clock: middle.clock,
            sync: settings, seed: 32_272, deviceKeys: middle.deviceKeys)
        let sharingSettings = SharingSettings(
            state: member.state, contacts: member.contacts, directory: household.directory)
        if sharingFirst { await second.session.configureSharing(sharingSettings) }

        // The person unlocks while the locked sync lists the shared vault's log.
        let session = second.session
        await hook.onNextListing(of: SyncObjectLocation.vaultPrefix(vaultID)) {
            try? await session.unlock(password: TestVault.password)
        }
        let locked = try await second.session.syncAll()
        #expect(await hook.ran, "the unlock did not land during the sync: nothing is tested")
        #expect(try await second.session.state() == .unlocked, "the unlock did not unlock")
        #expect(locked.vaults[vaultID]?.deferredUntilUnlock == true, "the sync begun locked did more than download")
        let registered = try #require(await second.session.deviceIDForTest())
        #expect(registered != first, "the unlock did not register a new device ID: nothing is tested")
        if sharingFirst {
            #expect(try await second.store.loadAccount()?.migration == nil, "the move was not made at the unlock")
        } else {
            #expect(try await second.store.loadAccount()?.migration != nil, "the move did not wait for sharing")
            #expect(await raw.loadState(vaultID: vaultID) == damaged, "the state was replaced while the move waited")
            await second.session.configureSharing(sharingSettings)
            #expect(try await second.store.loadAccount()?.migration == nil, "configuring sharing did not make the move")
        }
        let state = await raw.loadState(vaultID: vaultID)?.restoredUnpublished ?? [:]
        #expect(state[RecordKey(recordID: copy.id, kind: .item)]?.device == first, "the move's record was lost")
        let report = try await second.session.syncAll()
        #expect(report.deletionsHeldBack.contains(vaultID), "the hold ended")
        #expect(report.restoredWorkWaiting[vaultID] == [copy.id])
        try await other.session.sync()
        #expect((try? await other.session.item(id: original.id)) != nil, "the original was deleted ahead of its copy")
    }
}

/// Runs a step once, inside the next listing of one prefix, before the listing answers.
actor TransportListingHook {
    private var prefix: String?
    private var step: (@Sendable () async -> Void)?
    private(set) var ran = false

    func onNextListing(of prefix: String, _ step: @escaping @Sendable () async -> Void) {
        self.prefix = prefix
        self.step = step
    }

    func take(_ prefix: String) -> (@Sendable () async -> Void)? {
        guard prefix == self.prefix, let step else { return nil }
        self.step = nil
        ran = true
        return step
    }
}

/// A transport over `base` whose listing of a prefix runs `hook`'s step first, once.
struct ListingHookedTransport: SyncTransport {
    let base: any SyncTransport
    let hook: TransportListingHook

    func list(prefix: String) async throws -> [String] {
        if let step = await hook.take(prefix) { await step() }
        return try await base.list(prefix: prefix)
    }
    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        try await base.fetch(name, maximumLength: maximumLength)
    }
    func create(_ name: String, contents: [UInt8]) async throws { try await base.create(name, contents: contents) }
    func delete(_ name: String) async throws { try await base.delete(name) }
}
