import Foundation
import Testing
import WatchwordModel
import WatchwordSharing
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// A shared vault whose owner has moved it on in a later format (docs/02-architecture.md §8.9, §8.10), through real
/// sessions: what the sync store (A1) and other members (A4) can do with records in a later format's clothing. In the
/// suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// A record in a later format after `state`, signed by `signer`'s keyset (the owner's makes it count).
    static func laterFormatRecord(after state: MembershipState, owner signer: SharingAccount) async throws -> [UInt8] {
        let keyset = try #require(await signer.session.keys).keyset
        var record = ForgedRecord(after: state, signer: signer.accountID, operation: .rotateKey)
        record.formatVersion = 3
        record.operation = [7] + ForgedRecord.bytes(UUID())
        return try record.signed(by: keyset)
    }

    /// A well-formed membership name that commits to `bytes`.
    static func membershipName(of bytes: [UInt8], epoch: UInt64, in vaultID: UUID) -> String {
        let digest = SharingObjectLocation.digest(of: bytes).map { String(format: "%02x", $0) }.joined()
        let padded = String(epoch)
        return SharingObjectLocation.membershipPrefix(vaultID)
            + String(repeating: "0", count: 20 - padded.count) + padded + "-\(digest)-\(digest)"
    }

    /// The sync store (A1, which chooses what each device is shown and when) shows a member the owner's later-format
    /// record before the record it follows, so the member cannot yet stop its chain there. If the member remembered
    /// the record as refused, the store would have kept that device on this version's chain for good, writing beside
    /// updated devices. It is offered again once the record it follows arrives, and stops the chain (§8.8 step 1).
    @Test("a later format that arrives before the record it follows stops the chain once that record arrives")
    func laterFormatBeforeItsParent() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 710)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let view = NameHidingTransport(base: household.transport)
        let member = try await SharingAccount.make(over: view, directory: household.directory, seed: 727)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        for account in [owner, member, owner, member] { _ = try await account.session.syncAll() }

        let prefix = SharingObjectLocation.membershipPrefix(vaultID)
        let known = Set(await household.transport.list(prefix: prefix))
        let other = try await household.account(seed: 744)
        try await owner.invite(other, to: vaultID, as: .readOnly, owner: owner)
        let parent = Set(await household.transport.list(prefix: prefix)).subtracting(known)
        #expect(!parent.isEmpty)
        await view.hide(parent)
        let state = try await owner.session.sharedVaultStatus(vaultID).membership
        let later = try await Self.laterFormatRecord(after: state, owner: owner)
        try await household.transport.create(
            Self.membershipName(of: later, epoch: state.epoch + 1, in: vaultID), contents: later)

        _ = try await member.session.syncAll()
        #expect(try await member.session.sharedVaultStatus(vaultID).requiresNewerVersion == false)
        await view.hide([])
        let report = try await member.session.syncAll()
        #expect(report.sharing[vaultID]?.requiresNewerVersion == true)
        let status = try await member.session.sharedVaultStatus(vaultID)
        #expect(status.requiresNewerVersion)
        #expect(status.membership.hash == state.hash)
    }

    /// A member (A4) who is not the owner, or the store (A1) holding no key at all, plants a record in a later
    /// format's clothing to freeze the vault for every device on this version. Only the owner's signature as of the
    /// record it follows stops a chain: the session stays writable and publishes as before.
    @Test("a later format signed by a member, or by nobody, leaves the vault writable through the session")
    func laterFormatImpostorsThroughTheSession() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 760)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let member = try await household.account(seed: 777)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, member])

        let state = try await owner.session.sharedVaultStatus(vaultID).membership
        let bySigner = try await Self.laterFormatRecord(after: state, owner: member)
        var unsigned = ForgedRecord(after: state, signer: owner.accountID, operation: .rotateKey)
        unsigned.formatVersion = 3
        for impostor in [bySigner, unsigned.withSignature([UInt8](repeating: 0x5A, count: 64))] {
            try await household.transport.create(
                Self.membershipName(of: impostor, epoch: state.epoch + 1, in: vaultID), contents: impostor)
        }
        try await Self.syncAll([member, owner])
        for account in [owner, member] {
            let status = try await account.session.sharedVaultStatus(vaultID)
            #expect(!status.requiresNewerVersion)
            #expect(status.writePermission == .allowed)
        }
        var edit = try await member.session.item(id: bank.id)
        edit.notes = "Still writable"
        try await member.session.save(edit)
        try await Self.syncAll([member, owner])
        #expect(try await owner.session.item(id: bank.id).notes == "Still writable")
    }
}

/// A member's view of the household's transport that leaves out the names it is told to.
actor NameHidingTransport: SyncTransport {
    let base: InMemorySyncTransport
    private var hidden: Set<String> = []

    init(base: InMemorySyncTransport) {
        self.base = base
    }

    func hide(_ names: Set<String>) {
        hidden = names
    }

    func list(prefix: String) async throws -> [String] {
        await base.list(prefix: prefix).filter { !hidden.contains($0) }
    }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        guard !hidden.contains(name) else { return nil }
        return try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws {
        try await base.create(name, contents: contents)
    }

    func delete(_ name: String) async throws {
        await base.delete(name)
    }
}
