import Foundation
import Testing
import WatchwordEnvelope
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// A store that acts at the `n`-th read of the account's vault directory (counted from when it is armed): it locks a
/// session there, or fails the read as a database that cannot be read would. Unarmed, it counts those reads.
actor DirectoryReadHook: RecordStore {
    enum Action: Sendable {
        case lock(VaultSession)
        case fail
    }

    struct Unreadable: Error {}

    let base = InMemoryRecordStore()
    private(set) var directoryReads = 0
    private var armed: (read: Int, action: Action)?

    /// The next sync's `read`-th read of the directory (1 for the first) does `action`.
    func arm(atRead read: Int, _ action: Action) {
        directoryReads = 0
        armed = (read, action)
    }

    func resetCount() { directoryReads = 0 }

    func loadAccount() async throws -> AccountRecord? { try await base.loadAccount() }
    func record(_ key: RecordKey) async throws -> StoredRecord? { try await base.record(key) }

    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        if kind == .vaultDirectory {
            directoryReads += 1
            if let armed, armed.read == directoryReads {
                self.armed = nil
                switch armed.action {
                case .lock(let session): await session.lock()
                case .fail: throw Unreadable()
                }
            }
        }
        return try await base.records(in: vaultID, kind: kind)
    }

    func commit(_ change: StoreChange) async throws { try await base.commit(change) }
    func eraseAll() async throws { await base.eraseAll() }
}

/// What the sync reports of the copies nobody received (`AccountSyncReport.copiesNobodyReceived`, review finding Z171),
/// when the session locks or the directory cannot be read as the report is made (review of round 9, Z174, Z175).
@Suite("Vault session: the copies nobody received, in the sync report")
struct CopiesNobodyReceivedReportTests {
    /// A member of a shared vault holding the owner's item, whose account's registry lists a device ID that does not
    /// commit (a device an older build approved), so the report's scan runs at every sync; and the number of directory
    /// reads one of its syncs makes, the last of which is the report's.
    static func member(_ hook: DirectoryReadHook, seed: UInt64) async throws -> (SharingAccount, UUID, Int) {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: seed)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let member = try await household.account(seed: seed + 17, store: hook)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        _ = try await member.enrolledDevice(
            deviceID: UUID(uuidString: "D1740000-0000-4000-8000-000000000174")!, over: household.transport,
            directory: household.directory)
        var bank = AutoFillFixtures.bank
        bank.id = UUID()
        bank.vaultID = vaultID
        _ = try await owner.session.save(bank)
        try await owner.session.sync()
        try await member.session.sync()
        try await member.session.sync()
        await hook.resetCount()
        let quiet = try await member.session.syncAll()
        #expect(quiet.vaults[vaultID] != nil)
        #expect(quiet.copiesNobodyReceived.isEmpty, "the owner's item was taken for a copy nobody received")
        let reads = await hook.directoryReads
        await hook.resetCount()
        _ = try await member.session.syncAll()
        #expect(await hook.directoryReads == reads, "two quiet syncs read the directory a different number of times")
        return (member, vaultID, reads)
    }

    @Test("a lock as the report is made names no item as a copy nobody received")
    func lockWhileReporting() async throws {
        let hook = DirectoryReadHook()
        let (member, _, reads) = try await Self.member(hook, seed: 17_400)
        await hook.arm(atRead: reads, .lock(member.session))
        let report = try await member.session.syncAll()
        #expect(try await member.session.state() == .locked)
        #expect(report.copiesNobodyReceived.isEmpty, "every item was reported as a copy nobody received")
    }

    @Test("a directory that cannot be read as the report is made still returns the sync's report")
    func unreadableDirectoryWhileReporting() async throws {
        let hook = DirectoryReadHook()
        let (member, vaultID, reads) = try await Self.member(hook, seed: 17_500)
        await hook.arm(atRead: reads, .fail)
        let report = try await member.session.syncAll()
        #expect(report.vaults[vaultID] != nil)
        #expect(report.copiesNobodyReceived.isEmpty)
    }
}
