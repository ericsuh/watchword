import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

// Review finding Z56 (docs/06-adversarial-review.md): the whole-log check was made once, before the marker that stops
// the account's other devices compacting could be seen by any of them.
extension AdversarialSharedVaultTests {
    /// Threat: none needed; an owner with two devices, and timing. One device shares a vault; the other has not
    /// yet been shown the marker (its sync fetched the account's directory a moment earlier, or the marker's
    /// publication failed and waits for the next sync), still runs the vault as a private one, and compacts its log:
    /// a snapshot, and the segments it covers collected. What those segments carried now has no attribution, and the
    /// first person invited would hold those items aside for good (Z42). The check made when the vault was shared
    /// cannot see this; the one made before the first key is wrapped to anyone can.
    @Test("a log the account's other device compacted after the vault was shared stops the first invitation")
    func logCompactedAfterSharing() async throws {
        let household = SharedVaultHousehold()
        let view = WithholdingTransport(base: household.transport)
        var configuration = SyncSettings(state: InMemorySyncStateStore(), transport: view).configuration
        configuration.snapshotThreshold = 2
        let first = try await SharingAccount.make(
            over: view, directory: household.directory, seed: 930, configuration: configuration)
        let vaultID = try await first.session.createVault(name: "Household").id
        try await first.session.sync()
        let second = try await household.secondDevice(of: first)
        _ = try await second.session.save(Self.bank(in: vaultID))
        try await second.session.sync()
        try await first.session.sync()
        let prefix = SyncObjectLocation.vaultPrefix(vaultID)
        func compacted() async -> Bool {
            await household.transport.list(prefix: prefix).contains { SyncObjectLocation(name: $0)?.kind == .snapshot }
        }
        #expect(await !compacted(), "compacted before the vault was shared: the test proves nothing")

        // The second device shares the vault. The first is not shown the marker yet.
        await view.withholdNew(under: AccountObjectLocation.vaultsPrefix(first.accountID))
        try await second.session.shareVault(vaultID)
        try await second.session.sync()
        for number in 0..<6 {
            var item = Self.bank(in: vaultID)
            item.title = "Written before the marker was seen \(number)"
            _ = try await first.session.save(item)
            try await first.session.sync()
        }
        #expect(await compacted(), "the other device did not compact the log: the test proves nothing")

        // Now it is shown, and takes the vault up.
        await view.reveal()
        try await first.session.sync()
        try await first.session.shareVault(vaultID)
        try await Self.syncAll([first, second])
        try await Self.syncAll([first, second])
        // Nobody has been let in, so there is nobody's work to judge: the owner's devices hold nothing of their own
        // aside, compacted log or not.
        for device in [first, second] {
            #expect(try await device.session.items(in: vaultID).items.count == 7)
            #expect(try await device.session.sharedVaultStatus(vaultID).heldAside == 0)
        }

        let member = try await household.account(seed: 931)
        await #expect(throws: SharedVaultError.historyCompacted(vaultID)) {
            try await second.invite(member, to: vaultID, as: .readWrite, owner: second)
        }
        #expect(
            await household.transport.list(prefix: SharingObjectLocation.vaultPrefix(vaultID) + "grant/").isEmpty,
            "a key was wrapped to someone who would hold the vault's older items aside")
        // The vault goes on as the owner's.
        _ = try await second.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([first, second])
        #expect(try await first.session.items(in: vaultID).items.count == 8)
    }

    /// Threat: the store (A1), or a provider that loses an object: the vault's log was compacted and the snapshot is
    /// no longer listed. The transport shows a log with no snapshot in it, but this device merged streams through
    /// one, and the segments it covered are gone all the same. `requireWholeLog` asks the device's own signed sync
    /// state as well as the listing, and that half must refuse alone.
    @Test("a compacted vault is not shared when its snapshot is no longer listed, by what this device merged")
    func compactedVaultWithItsSnapshotGone() async throws {
        let household = SharedVaultHousehold()
        var configuration = SyncSettings(state: InMemorySyncStateStore(), transport: household.transport).configuration
        configuration.snapshotThreshold = 2
        let owner = try await household.account(seed: 925, configuration: configuration)
        let vaultID = try await owner.session.createVault(name: "Household").id
        for number in 0..<6 {
            var item = Self.bank(in: vaultID)
            item.title = "Item \(number)"
            _ = try await owner.session.save(item)
            try await owner.session.sync()
        }
        let snapshots = await household.transport.list(prefix: SyncObjectLocation.vaultPrefix(vaultID))
            .filter { SyncObjectLocation(name: $0)?.kind == .snapshot }
        #expect(!snapshots.isEmpty, "the vault's log was not compacted: the test proves nothing")
        for name in snapshots { await household.transport.tamper(name, contents: nil) }

        await #expect(throws: SharedVaultError.historyCompacted(vaultID)) {
            try await owner.session.shareVault(vaultID)
        }
        #expect(try await owner.session.sharedVaultIDs().isEmpty)
    }

    /// Threat: none needed; a transport that fails at the wrong moment. The marker is what tells the account's other
    /// devices to stop compacting the vault's log, and it used to be published if it could be and otherwise left to
    /// the next sync, while the chain's first record went out regardless. The chain must not be on the transport
    /// before the marker is, and a share that stopped there is finished by sharing again (Z50).
    @Test("the chain's first record is not published before the account's marker is")
    func markerBeforeTheChain() async throws {
        let household = SharedVaultHousehold()
        let transport = RefusingTransport(base: household.transport)
        let owner = try await SharingAccount.make(over: transport, directory: household.directory, seed: 940)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.sync()
        let directory = AccountObjectLocation.vaultsPrefix(owner.accountID)
        let before = Set(await household.transport.list(prefix: directory))

        await transport.refuseCreates(under: directory)
        await #expect(throws: SyncTransportError.unavailable) {
            try await owner.session.shareVault(vaultID)
        }
        #expect(
            await household.transport.list(prefix: SharingObjectLocation.vaultPrefix(vaultID)).isEmpty,
            "the chain was published while no other device of the account could know the vault is shared")

        await transport.refuseCreates(under: nil)
        try await owner.session.shareVault(vaultID)
        #expect(Set(await household.transport.list(prefix: directory)).subtracting(before).count == 1)
        #expect(await !household.transport.list(prefix: SharingObjectLocation.membershipPrefix(vaultID)).isEmpty)
        _ = try await owner.session.save(Self.bank(in: vaultID))
    }
}

/// A transport that can be told to fail every creation under a prefix, as a store that cannot be reached for it.
actor RefusingTransport: SyncTransport {
    let base: InMemorySyncTransport
    private var refused: String?
    private var failure = SyncTransportError.unavailable

    init(base: InMemorySyncTransport) {
        self.base = base
    }

    func refuseCreates(under prefix: String?, with failure: SyncTransportError = .unavailable) {
        refused = prefix
        self.failure = failure
    }

    func list(prefix: String) async throws -> [String] {
        await base.list(prefix: prefix)
    }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws {
        if let refused, name.hasPrefix(refused) { throw failure }
        try await base.create(name, contents: contents)
    }

    func delete(_ name: String) async throws {
        await base.delete(name)
    }
}
