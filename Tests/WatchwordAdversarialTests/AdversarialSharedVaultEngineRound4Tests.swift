import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

extension VaultSession {
    /// For tests: the devices whose streams this device does not read in `vaultID`.
    func retiredInVault(_ vaultID: UUID) async -> Set<UUID> {
        await syncRetiredAuthors(vaultID: vaultID)
    }
}

// The review of the engine's fourth round (rows Z144 to Z149) in shared vaults (docs/06-adversarial-review.md §Z,
// rows from Z150).
extension AdversarialSharedVaultTests {
    /// Threat: a member of the vault (A4) whose work cannot count, read-only from the start or removed, who registers a
    /// device under another member's device ID in their own registry (S33 allows it) and then revokes it there. Every
    /// registry's revocations were unioned: every device stopped reading the victim's stream, and the victim's own
    /// device was told it was revoked and synced nothing in that vault. Since Z144 a revoked device's values are also
    /// believed without its stream, so a member who may write could have claims stamped with the victim's device
    /// believed. A revocation counts only from the account the device is: whose stream it is, or, for a stream
    /// nothing was recorded of, every registry that lists it having revoked it.
    @Test("a member's revocation of another member's device ID stops nothing")
    func memberRevokesAnotherMembersDevice() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 3500)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let victim = try await household.account(seed: 3501)
        let reader = try await household.account(seed: 3502)
        let former = try await household.account(seed: 3503)
        try await owner.invite(victim, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(reader, to: vaultID, as: .readOnly, owner: owner)
        try await owner.invite(former, to: vaultID, as: .readWrite, owner: owner)
        let invitation = Invitation(vaultID: vaultID, ownerAccountID: owner.accountID)
        // The victim's laptop has published in the vault; its phone has joined and written nothing yet.
        _ = try await victim.session.save(Self.bank(in: vaultID))
        let phone = try await household.secondDevice(of: victim)
        try await phone.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(owner.safetyNumber))
        try await Self.syncAll([owner, victim, phone, reader, former])
        let laptopID = try await Self.deviceID(of: victim)
        let phoneID = try await Self.deviceID(of: phone)

        // The former member lists the laptop's ID while it may write, and is removed; the reader lists the phone's.
        // Each then revokes the device it listed.
        _ = try await household.secondDevice(of: former, deviceID: laptopID)
        _ = try await household.secondDevice(of: reader, deviceID: phoneID)
        try await Self.syncAll([owner, reader, former], rounds: 1)
        #expect(try await owner.session.removeMember(former.accountID, from: vaultID) == .complete)
        try await former.session.revokeDevice(laptopID, password: .keepPassword(current: TestVault.password))
        try await reader.session.revokeDevice(phoneID, password: .keepPassword(current: TestVault.password))
        try await Self.syncAll([owner, reader, former, victim, phone])

        for (name, session) in [("owner", owner.session), ("laptop", victim.session), ("phone", phone.session)] {
            let retired = await session.retiredInVault(vaultID)
            #expect(!retired.contains(laptopID), "the laptop's stream is not read on the \(name)'s device")
            #expect(!retired.contains(phoneID), "the phone's stream is not read on the \(name)'s device")
        }
        var fromLaptop = Self.bank(in: vaultID)
        fromLaptop.title = "Written on the laptop afterwards"
        fromLaptop = try await victim.session.save(fromLaptop)
        var fromPhone = Self.bank(in: vaultID)
        fromPhone.title = "Written on the phone afterwards"
        fromPhone = try await phone.session.save(fromPhone)
        for account in [victim, phone] {
            let report = try #require(try await account.session.syncAll().vaults[vaultID])
            #expect(!report.deviceRevoked, "the victim's device was told it was revoked")
        }
        try await Self.syncAll([owner, reader, victim, phone])
        for (name, account) in [("owner", owner), ("reader", reader), ("laptop", victim), ("phone", phone)] {
            let titles = try await account.session.items(in: vaultID).items.map(\.title)
            #expect(titles.contains(fromLaptop.title), "the laptop's work did not reach the \(name)'s device")
            #expect(titles.contains(fromPhone.title), "the phone's work did not reach the \(name)'s device")
        }
    }
}
