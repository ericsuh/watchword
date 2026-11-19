import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit
@testable import WatchwordSync

/// The store as other hardware sees it right after a restore: it lists every object, and answers no bytes for the
/// names in `pending` until `download()`, as iCloud Drive does for a placeholder it has not downloaded yet (and
/// CloudKit for an object it could not read this time).
actor PlaceholderTransport: SyncTransport {
    let base: InMemorySyncTransport
    var pending: Set<String> = []

    init(base: InMemorySyncTransport) { self.base = base }

    func hold(_ names: Set<String>) { pending = names }
    func download() { pending = [] }

    func list(prefix: String) async throws -> [String] { await base.list(prefix: prefix) }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        guard !pending.contains(name) else { return nil }
        return try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws { try await base.create(name, contents: contents) }
    func delete(_ name: String) async throws { await base.delete(name) }
}

// The review of V56 and V57 (docs/06-adversarial-review.md V58): what a restore's carry counts as published when the
// earlier ID's stream has a gap at the first sync. In the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Threat: none needed but a backup older than the device's last publish (round 13's M2) restored onto other
    /// hardware, whose first sync finds the earlier ID's first segment of the vault still a placeholder (iCloud Drive
    /// lists an object before it has downloaded it; a fresh restore nearly always meets one). The same with the
    /// backup's sync state edited (A8), so that it says nothing was published. The move starts the vault's state over,
    /// and V56's reach counted only the staged run from position 1, which the placeholder stopped at nothing: the
    /// carry renamed the first rename, published since the backup, as the new ID's work, and every member held the
    /// title the person had replaced beside the one that replaced it (Z198 back again). A position merely not
    /// downloaded stops nothing now: only a name the download refused for its copies does (V58). Fails with the fix
    /// reverted (at fb4cc5b: the owner held both titles, as conflicts).
    @Test(
        "a placeholder of the earlier ID's stream at the first sync after a restore brings back nothing it replaced",
        arguments: [false, true])
    func placeholderAtTheFirstCarryRenamesNothing(stateEdited: Bool) async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite], seed: 19_700)
        let member = members[0]
        let saved = try await member.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([member, owner])
        let oldID = try #require(await member.session.deviceIDForTest())

        var first = try await member.session.item(id: saved.id)
        first.title = "Bank, first"
        _ = try await member.session.save(first)
        var backup = try await Backup.take(of: member, item: saved.id, vaultID: vaultID)
        if stateEdited, var state = backup.state {
            state.authenticator = Array(repeating: 0, count: state.authenticator.count)
            backup = Backup(row: backup.row, state: state, index: backup.index)
        }
        try await Self.syncAll([member, owner])
        var second = try await member.session.item(id: saved.id)
        second.title = "Bank, second"
        _ = try await member.session.save(second)
        try await Self.syncAll([member, owner])

        let stream = await household.transport.allObjects.keys.compactMap(SyncObjectLocation.init(name:)).filter {
            $0.kind == .segment && $0.vaultID == vaultID && $0.author == oldID
        }
        #expect(stream.count >= 3, "the earlier ID published less than the test needs: nothing is tested")
        let lowest = try #require(stream.min { $0.number < $1.number })
        let placeholder = PlaceholderTransport(base: household.transport)
        await placeholder.hold([lowest.name])

        let restored = try await backup.restore(member, household: household, seed: 19_701, transport: placeholder)
        let firstSync = try await restored.session.syncAll()
        #expect(firstSync.vaults[vaultID]?.waiting[oldID] == lowest.number, "no gap at the carry: nothing is tested")
        await placeholder.download()
        _ = try await restored.session.syncAll()
        _ = try await restored.session.syncAll()
        try await Self.syncAll([owner])
        let atOwner = try await owner.session.item(id: saved.id)
        #expect(atOwner.title == "Bank, second")
        #expect(!atOwner.hasConflicts, "the replaced title came back beside the one that replaced it")
        #expect(try await owner.session.quarantine().isEmpty)
        let here = try await restored.session.item(id: saved.id)
        #expect(here.title == "Bank, second")
        #expect(!here.hasConflicts)
    }
}
