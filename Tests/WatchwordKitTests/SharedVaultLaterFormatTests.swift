import Foundation
import Testing
import WatchwordModel
import WatchwordSharing
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// A shared vault whose owner has moved it on in a later format (ownership transfer, docs/02-architecture.md §8.9).
/// The owner's decision of 2026-11-16 is that a device on this version fails closed: the ledger stops the chain, and
/// the session treats the vault as read-only, says so, and its sync pass proposes, plans, publishes and seals nothing
/// there, while other members' writes that count on the stopped chain are still merged.
@Suite("Vault session: a shared vault in a later format")
struct SharedVaultLaterFormatTests {
    static func bank(in vaultID: UUID) -> Item {
        var item = AutoFillFixtures.bank
        item.id = UUID()
        item.vaultID = vaultID
        return item
    }

    /// The record a later version of the owner's app would write after `state`: format version 3, this version's
    /// prefix, an operation this version cannot read, and the owner's signature over everything before it.
    static func laterFormat(after state: MembershipState, owner: SharingAccount) async throws -> [UInt8] {
        let keyset = try #require(await owner.session.keys).keyset
        var record = ForgedRecord(after: state, signer: owner.accountID, operation: .rotateKey)
        record.formatVersion = 3
        record.operation = [7] + ForgedRecord.bytes(UUID())
        return try record.signed(by: keyset)
    }

    /// Where a membership object of `bytes` lives: the epoch, then a hash and the object's digest. A later format's
    /// hash cannot be computed by this version; any well-formed name that commits to the contents is offered.
    static func name(of bytes: [UInt8], epoch: UInt64, in vaultID: UUID) -> String {
        let digest = SharingObjectLocation.digest(of: bytes).map { String(format: "%02x", $0) }.joined()
        let padded = String(epoch)
        return SharingObjectLocation.membershipPrefix(vaultID)
            + String(repeating: "0", count: 20 - padded.count) + padded + "-\(digest)-\(digest)"
    }

    static func vaultObjects(_ transport: InMemorySyncTransport, _ vaultID: UUID) async -> Set<String> {
        Set(await transport.list(prefix: "vault/\(vaultID.uuidString)/"))
            .union(await transport.list(prefix: SharingObjectLocation.vaultPrefix(vaultID)))
    }

    @Test("the vault is read-only and reported, nothing is published or planned there, and others' writes still merge")
    func laterFormatMakesTheVaultReadOnly() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 610)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let member = try await household.account(seed: 627)
        // A member whose device does not see the later record yet (the store shows it late): on the chain it
        // follows, it may still write, and what it writes counts on the stopped chain too.
        let (late, lateView) = try await household.withheldAccount(seed: 644)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(late, to: vaultID, as: .readWrite, owner: owner)
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        for account in [owner, member, late, owner, member, late] { try await account.session.sync() }
        #expect(try await member.session.sharedVaultStatus(vaultID).requiresNewerVersion == false)

        // The member edits before it learns of the later format: that edit must not be published afterwards.
        var unpublished = try await member.session.item(id: bank.id)
        unpublished.title = "Edited before the update"
        try await member.session.save(unpublished)

        await lateView.withholdNew(under: SharingObjectLocation.membershipPrefix(vaultID))
        let state = try await member.session.sharedVaultStatus(vaultID).membership
        let later = try await Self.laterFormat(after: state, owner: owner)
        try await household.transport.create(
            Self.name(of: later, epoch: state.epoch + 1, in: vaultID), contents: later)

        // The member's sync: the chain stops, the vault is reported read-only, and nothing reaches the transport.
        let before = await Self.vaultObjects(household.transport, vaultID)
        let report = try await member.session.syncAll()
        #expect(report.sharing[vaultID]?.requiresNewerVersion == true)
        #expect(await Self.vaultObjects(household.transport, vaultID) == before)
        let status = try await member.session.sharedVaultStatus(vaultID)
        #expect(status.requiresNewerVersion)
        #expect(status.writePermission == .refused(.requiresNewerVersion))
        #expect(status.membership.hash == state.hash)
        await #expect(throws: SharedVaultError.writeRefused(.requiresNewerVersion)) {
            var attempt = try await member.session.item(id: bank.id)
            attempt.title = "After the stop"
            try await member.session.save(attempt)
        }
        await #expect(throws: SharingError.requiresNewerVersion) {
            try await member.session.leaveSharedVault(vaultID)
        }
        // Nor is anything moved out of the vault, which would delete it there (review finding Z44).
        let personal = try #require(await member.session.personalVaultID)
        await #expect(throws: SharedVaultError.writeRefused(.requiresNewerVersion)) {
            try await member.session.move(itemID: bank.id, to: personal)
        }
        #expect(try await member.session.items(in: personal).items.isEmpty)
        // A second sync, and one after the later record is no longer listed, still stop there and publish nothing.
        _ = try await member.session.sync()
        #expect(await Self.vaultObjects(household.transport, vaultID) == before)
        #expect(try await member.session.sharedVaultStatus(vaultID).requiresNewerVersion)

        // The owner's device on this version stops too: no rotation, no invitation, no write.
        _ = try await owner.session.sync()
        #expect(try await owner.session.sharedVaultStatus(vaultID).requiresNewerVersion)
        await #expect(throws: SharingError.requiresNewerVersion) {
            _ = try await owner.session.rotateVaultKey(vaultID)
        }
        #expect(await Self.vaultObjects(household.transport, vaultID) == before)

        // The late member still writes on the chain it follows, which is the stopped chain: the stopped devices merge
        // that write, read-only.
        var lateEdit = try await late.session.item(id: bank.id)
        lateEdit.notes = "Written by a member who may still write"
        try await late.session.save(lateEdit)
        _ = try await late.session.sync()
        _ = try await member.session.sync()
        #expect(try await member.session.item(id: bank.id).notes == "Written by a member who may still write")
        #expect(try await member.session.sharedVaultStatus(vaultID).requiresNewerVersion)
    }
}
