import Foundation
import Testing
import WatchwordCrypto
import WatchwordHygiene
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// Synced breach-check results (owner decision 10; ADR 0005, amendment of 2026-11-16; docs/02-architecture.md §13.9),
/// attacked through real sessions of different accounts sharing one vault over one transport.
///
/// The adversaries, from docs/02-architecture.md §2:
/// - **A4, a current member of the shared vault**, with the vault key and a device of their own whose writes count.
///   They can read the password, so they can compute its binding and write any observation of their own: a
///   "not found" for a password the victim's device saw breached, dated now or years ahead. They must not be able to
///   hide the breach on the victim's device, or keep that device from checking the password itself for longer than
///   the caps allow; and an observation they forge in the victim device's name must count nowhere.
/// - **A5, a former member** whose client still writes, with a store (A1) that withholds the record removing them:
///   an observation written after their removal must not reach the report of a member who remains (S28).
@Suite("Adversarial: synced breach-check results", .tags(.adversarial))
struct AdversarialSyncedHygieneTests {
    static let interval = ScanPolicy.standard.fullScanInterval
    static let day: TimeInterval = 24 * 60 * 60

    struct Household {
        let household = SharedVaultHousehold()
        let owner: SharingAccount
        let ownerHTTP: FakeHTTPClient
        let member: SharingAccount
        let vaultID: UUID
        let itemID: UUID

        /// The owner's device holds an item with `password` in a vault shared with one read-write member, has
        /// checked it, and both devices have synced.
        static func make(password: String, memberView: Bool = false) async throws -> Household {
            let household = SharedVaultHousehold()
            let (ownerSettings, ownerHTTP) = await HygieneSessionFixture.settings(breached: ["hunter2": 17_043])
            let (memberSettings, _) = await HygieneSessionFixture.settings(breached: ["hunter2": 17_043])
            let owner = try await household.account(seed: 700, hygiene: ownerSettings)
            let member = try await household.account(seed: 717, hygiene: memberSettings)
            let vaultID = try await owner.session.createVault(name: "Household").id
            try await owner.session.shareVault(vaultID)
            try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
            let item = try await owner.session.save(
                HygieneSessionFixture.login(vaultID, title: "Forum", host: "forum.example", password: password))
            _ = try await HygieneSessionFixture.scanUntilIdle(owner.session, clock: owner.vault.clock)
            for account in [owner, member, owner, member] { try await account.session.sync() }
            return Household(
                owner: owner, ownerHTTP: ownerHTTP, member: member, vaultID: vaultID, itemID: item.id)
        }

        func ownerEntry() async throws -> ItemHygiene? {
            try await owner.session.hygieneReport().item(itemID)
        }
    }

    static func isBreached(_ status: BreachStatus?) -> Bool {
        if case .breached = status { return true }
        return false
    }

    /// Threat: A4, a current member who can read the password, syncs an observation of their own saying the
    /// password the owner's device found breached is not, first dated ten years ahead (to postpone the owner's own
    /// checks for ever), then dated now, again every day (to keep postponing them). The owner's device keeps
    /// showing the breach as its own finding throughout. The far-future time postpones nothing: the owner's device
    /// checks again a pass after its own last check. The daily fresh ones postpone its own check by at most the
    /// deferral limit in all (plus the pass it falls in), after which it asks the server itself.
    @Test("a member's forged 'not found', far ahead or fresh every day, neither hides a breach nor stops checks")
    func forgedClearCannotHideABreach() async throws {
        let home = try await Household.make(password: "hunter2")
        let clock = home.owner.vault.clock
        let checkedAt = await clock.now()
        #expect(Self.isBreached(try await home.ownerEntry()?.breachStatus))

        try await home.member.session.forgeScanObservation(
            itemID: home.itemID, occurrences: 0, scannedAt: checkedAt.addingTimeInterval(10 * 365 * Self.day))
        try await home.member.session.sync()
        try await home.owner.session.sync()
        var entry = try await home.ownerEntry()
        #expect(Self.isBreached(entry?.breachStatus))
        #expect(entry?.breachSource == .thisDevice)

        // A pass after its own check, the owner's device checks again: the far-future time counted for nothing.
        let requestsBefore = await home.ownerHTTP.requests.count
        await clock.set(checkedAt.addingTimeInterval(Self.interval + Self.day))
        _ = try await HygieneSessionFixture.scanUntilIdle(home.owner.session, clock: clock)
        #expect(await home.ownerHTTP.requests.count == requestsBefore + 1)

        // Now a fresh "not found" every day. The breach stays; the owner's own check comes within the limit.
        let start = await clock.now()
        var ownCheck: Date?
        for _ in 0..<45 {
            try await home.member.session.forgeScanObservation(
                itemID: home.itemID, occurrences: 0, scannedAt: await clock.now())
            try await home.member.session.sync()
            try await home.owner.session.sync()
            let before = await home.ownerHTTP.requests.count
            _ = try await HygieneSessionFixture.scanUntilIdle(home.owner.session, clock: clock)
            entry = try await home.ownerEntry()
            #expect(Self.isBreached(entry?.breachStatus))
            if await home.ownerHTTP.requests.count > before {
                ownCheck = await clock.now()
                break
            }
            await clock.advance(by: Self.day)
        }
        let checked = try #require(ownCheck)
        // Its own check covered the pass it was in; from then on, synced checks stood in for at most the limit, and
        // the check came with the next pass after that.
        #expect(
            checked.timeIntervalSince(start)
                <= 2 * Self.interval + ScanPolicy.standard.maximumSyncDeferral + Self.day)
        #expect(entry?.breachSource == .thisDevice)
    }

    /// Threat: A4 again, writing an observation in the owner's device's name (its device ID, a revision of its
    /// choosing) that says the breached password is clear, inside a version of the record the member seals and signs.
    /// No segment of the owner's device's stream carried it, and the owner's device does not hold it, so the shared
    /// vault's judge does not count the version (held aside), and the report would not read the owner's own
    /// observation from a synced record in any case.
    @Test("an observation forged in this device's name is held aside and changes nothing")
    func forgedOwnObservation() async throws {
        let home = try await Household.make(password: "hunter2")
        let ownerDevice = try #require(await home.owner.session.account?.deviceID)
        try await home.member.session.forgeScanObservation(
            itemID: home.itemID, occurrences: 0, scannedAt: await home.owner.vault.clock.now(), as: ownerDevice)
        try await home.member.session.sync()
        try await home.owner.session.sync()
        let entry = try await home.ownerEntry()
        #expect(Self.isBreached(entry?.breachStatus))
        #expect(entry?.breachSource == .thisDevice)
        let heldAside = try await home.owner.session.quarantinedVersions()
        #expect(heldAside.contains { $0.recordID == home.itemID && $0.kind == .scanStatus })
    }

    /// Threat: S28 for scan results. A former member (A5) whose client still writes, with a store (A1) that withholds
    /// the record removing them, reports a breach for a password the owner's device found clear, after the removal.
    /// The owner's device never counts it: the report stays clear and the version is held aside.
    @Test("a removed member's late breach report counts nowhere")
    func lateReportOfARemovedMember() async throws {
        let household = SharedVaultHousehold()
        let (ownerSettings, _) = await HygieneSessionFixture.settings()
        let (removedSettings, _) = await HygieneSessionFixture.settings()
        let owner = try await household.account(seed: 800, hygiene: ownerSettings)
        let (removed, removedView) = try await household.withheldAccount(seed: 817, hygiene: removedSettings)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(removed, to: vaultID, as: .readWrite, owner: owner)
        let item = try await owner.session.save(
            HygieneSessionFixture.login(vaultID, title: "Mail", host: "mail.example", password: "Zr8@Wn4&x7#Vq9!"))
        _ = try await HygieneSessionFixture.scanUntilIdle(owner.session, clock: owner.vault.clock)
        for account in [owner, removed, owner, removed] { try await account.session.sync() }

        await removedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        #expect(try await owner.session.removeMember(removed.accountID, from: vaultID) == .complete)
        try await removed.session.forgeScanObservation(
            itemID: item.id, occurrences: 1_000_000, scannedAt: await removed.vault.clock.now())
        try await removed.session.sync()
        try await owner.session.sync()

        let entry = try await owner.session.hygieneReport().item(item.id)
        guard case .clear = entry?.breachStatus else {
            Issue.record("expected clear, got \(String(describing: entry?.breachStatus))")
            return
        }
        #expect(entry?.breachSource == .thisDevice)
        let heldAside = try await owner.session.quarantinedVersions()
        #expect(heldAside.contains { $0.recordID == item.id && $0.kind == .scanStatus })
    }
}

extension VaultSession {
    /// What a member's client can write that the session never would: an observation saying whatever it likes, about
    /// the item's current passwords (computed properly, as someone who can read them can), in its own device's name
    /// or another's, sealed under the vault key and committed as this device's version, for its next sync to publish.
    func forgeScanObservation(itemID: UUID, occurrences: UInt32, scannedAt: Date, as device: UUID? = nil)
        async throws
    {
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let item = try await item(id: itemID)
        let keys = try requireKeys()
        let vaultKey = try await writableVaultKey(item.vaultID, keys: keys, account: account)
        let existing = try await scanStatusRow(for: item)
        let current = try requireKeys()
        var record =
            existing.flatMap { try? openScanStatus($0, keys: current) }
            ?? SyncedScanRecord(itemID: item.id, vaultID: item.vaultID, version: 0)
        let revision = try nextRevision(in: item.vaultID, above: existing, account: account)
        let bindingKey = try ScanBindingKey(HygieneKeys.scanBindingKey(vaultKey: vaultKey))
        defer { bindingKey.zeroise() }
        var results: [ScanBinding: UInt32] = [:]
        for field in ItemAnalyzer.passwordFields(of: item) {
            results[bindingKey.binding(item: item.id, utf8Of: field.value)] = occurrences
        }
        record.record(
            SyncedScanRecord.Observation(
                device: device ?? account.deviceID, revision: revision.version, keyID: vaultKey.key.keyID,
                scannedAt: scannedAt, results: results))
        record.version = revision.version
        let row = try sealScanStatus(record, vaultKey: vaultKey, account: account)
        try await writer(for: account).commit(
            StoreChange(upserts: [row], expectations: [row.key: existing.map { .version($0.version) } ?? .absent]))
    }
}
