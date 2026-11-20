import Foundation
import Testing
import WatchwordKit
import WatchwordModel
import WatchwordSharing
import WatchwordSync
import WatchwordTestSupport

/// PRD scenarios S3 and S4 end to end: real `VaultSession`s of different accounts sharing a vault over one
/// `InMemorySyncTransport`, with invitations, fingerprint verification, the membership chain, key grants, the vault's
/// log, role changes and removal with rotation (docs/02-architecture.md §8.8; docs/04-test-plan.md).
@Suite("Shared vaults through VaultSession")
struct SharedVaultScenarioTests {
    static func bank(in vaultID: UUID) -> Item {
        var item = AutoFillFixtures.bank
        item.id = UUID()
        item.vaultID = vaultID
        return item
    }

    static func library(in vaultID: UUID) -> Item {
        var item = AutoFillFixtures.library
        item.id = UUID()
        item.vaultID = vaultID
        return item
    }

    static func syncAll(_ accounts: [SharingAccount], rounds: Int = 2) async throws {
        for _ in 0..<rounds {
            for account in accounts { try await account.session.sync() }
        }
    }

    @Test("S3: a shared bank item is read and updated by both members, and the owner revokes the share")
    func sharedBankAccount() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite])
        let member = members[0]

        // The owner saves the bank item; the member sees every field: password, TOTP, the three answers.
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, member])
        let seen = try await member.session.item(id: bank.id)
        #expect(seen.field(.password)?.value == "bank-password")
        #expect(seen.fields.filter { $0.kind == .securityQuestion }.map(\.value) == ["Rex", "Elm Street", "Ms Okafor"])
        #expect(seen.field(.totp) != nil)
        #expect(try await member.session.vaults().contains { $0.id == vaultID && $0.name == "Household" })

        // Either can update the password, and the other sees it.
        var edited = seen
        edited.fields = edited.fields.map { field in
            var field = field
            if field.kind == .password { field.value = "changed-by-member" }
            return field
        }
        try await member.session.save(edited)
        try await Self.syncAll([member, owner])
        #expect(try await owner.session.item(id: bank.id).field(.password)?.value == "changed-by-member")

        // The owner revokes the share: off the transport's share first, then a new key and the record.
        let status = try await owner.session.removeMember(member.accountID, from: vaultID)
        #expect(status == .complete)
        // Revoked before anything else, and again as the signed plan's first step (§8.6).
        #expect(Set(await owner.shareAccess.revoked.map(\.account)) == [member.accountID])
        #expect(await owner.shareAccess.revoked.first?.account == member.accountID)
        try await Self.syncAll([owner, member])
        let memberView = try await member.session.sharedVaultStatus(vaultID)
        #expect(memberView.role == nil)
        #expect(!memberView.writePermission.isAllowed)
        // Every record was sealed again under a key the member does not hold.
        let ownerStatus = try await owner.session.sharedVaultStatus(vaultID)
        #expect(ownerStatus.pendingRotation.isEmpty)
        #expect(ownerStatus.membership.members.map(\.accountID) == [owner.accountID])

        // What the owner writes afterwards does not reach the former member, and they can no longer write.
        var later = try await owner.session.item(id: bank.id)
        later.fields = later.fields.map { field in
            var field = field
            if field.kind == .password { field.value = "after-removal" }
            return field
        }
        try await owner.session.save(later)
        try await Self.syncAll([owner, member])
        #expect(try await member.session.item(id: bank.id).field(.password)?.value != "after-removal")
        await #expect(throws: SharedVaultError.writeRefused(.notAMember)) {
            var attempt = try await member.session.item(id: bank.id)
            attempt.title = "Former member's edit"
            try await member.session.save(attempt)
        }
        #expect(try await owner.session.item(id: bank.id).title == "First Bank")
    }

    @Test("S4: a library card shared with a read-only member, who reads it, cannot write, and writes once promoted")
    func sharedLibraryCard() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readOnly], seed: 400)
        let (writer, reader) = (members[0], members[1])
        let library = try await owner.session.save(Self.library(in: vaultID))
        try await Self.syncAll([owner, writer, reader])

        for account in [writer, reader] {
            let card = try await account.session.item(id: library.id)
            #expect(card.field(.pin)?.value == "4821")
            #expect(card.field(.accountNumber)?.value == "2 1234 56789 0")
            #expect(card.field(.password)?.value == "library-password")
        }
        // The read-only member's own client refuses the write (F4.5).
        await #expect(throws: SharedVaultError.writeRefused(.readOnly)) {
            var attempt = try await reader.session.item(id: library.id)
            attempt.title = "Read-only edit"
            try await reader.session.save(attempt)
        }
        // The read-write member's edit reaches both.
        var renamed = try await writer.session.item(id: library.id)
        renamed.title = "City library"
        try await writer.session.save(renamed)
        try await Self.syncAll([writer, owner, reader])
        #expect(try await owner.session.item(id: library.id).title == "City library")
        #expect(try await reader.session.item(id: library.id).title == "City library")

        // Promoted, the reader may write, and everyone takes the write.
        try await owner.session.changeRole(of: reader.accountID, in: vaultID, to: .readWrite)
        try await Self.syncAll([owner, reader, writer])
        var promoted = try await reader.session.item(id: library.id)
        promoted.notes = "Renew in March"
        try await reader.session.save(promoted)
        try await Self.syncAll([reader, owner, writer])
        #expect(try await owner.session.item(id: library.id).notes == "Renew in March")
        #expect(try await writer.session.item(id: library.id).notes == "Renew in March")
    }

    @Test("a shared vault is renamed by its owner or an administrator; a member is refused, and the role decides")
    func renamingASharedVault() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(
            roles: [.administrator, .readWrite, .readOnly], seed: 450)
        let (administrator, writer, reader) = (members[0], members[1], members[2])
        let everyone = [owner, administrator, writer, reader]

        // What the screens are told.
        #expect(try await owner.session.sharedVaultStatus(vaultID).mayRename)
        #expect(try await administrator.session.sharedVaultStatus(vaultID).mayRename)
        #expect(try await !writer.session.sharedVaultStatus(vaultID).mayRename)
        #expect(try await !reader.session.sharedVaultStatus(vaultID).mayRename)

        // What the session does: the refusal is typed, and comes before anything is sealed.
        await #expect(throws: SharedVaultError.renameRefused) {
            try await writer.session.renameVault(id: vaultID, to: "Member's name")
        }
        await #expect(throws: SharedVaultError.writeRefused(.readOnly)) {
            try await reader.session.renameVault(id: vaultID, to: "Reader's name")
        }
        try await Self.syncAll(everyone)
        for account in everyone {
            #expect(try await account.session.vaults().first { $0.id == vaultID }?.name == "Household")
        }
        try await administrator.session.renameVault(id: vaultID, to: "Family")
        try await Self.syncAll([administrator] + everyone)
        for account in everyone {
            #expect(try await account.session.vaults().first { $0.id == vaultID }?.name == "Family")
        }

        // A member's own vaults are theirs to name: the Personal vault, and one that is not shared.
        let personal = try #require(try await writer.session.vaults().first { $0.isPersonal })
        #expect(try await writer.session.renameVault(id: personal.id, to: "Mine").name == "Mine")
        let own = try await writer.session.createVault(name: "Garden")
        #expect(try await writer.session.renameVault(id: own.id, to: "Allotment").name == "Allotment")

        // The role decides, in both directions, as soon as the device has the record.
        try await owner.session.changeRole(of: writer.accountID, in: vaultID, to: .administrator)
        try await owner.session.changeRole(of: administrator.accountID, in: vaultID, to: .readWrite)
        try await Self.syncAll(everyone)
        #expect(try await writer.session.sharedVaultStatus(vaultID).mayRename)
        #expect(try await !administrator.session.sharedVaultStatus(vaultID).mayRename)
        await #expect(throws: SharedVaultError.renameRefused) {
            try await administrator.session.renameVault(id: vaultID, to: "Once more")
        }
        try await writer.session.renameVault(id: vaultID, to: "Home")
        try await Self.syncAll([writer] + everyone)
        for account in everyone {
            #expect(try await account.session.vaults().first { $0.id == vaultID }?.name == "Home")
            #expect(try await account.session.quarantinedVersions().isEmpty)
        }

        // A rename made before the device heard that the role had ended is never published: the next sync ingests
        // the record before any log, takes the name out and holds it aside here, and nobody else ever sees it.
        try await writer.session.renameVault(id: vaultID, to: "Not yet synced")
        try await owner.session.changeRole(of: writer.accountID, in: vaultID, to: .readWrite)
        try await Self.syncAll([writer] + everyone)
        for account in everyone {
            #expect(try await account.session.vaults().first { $0.id == vaultID }?.name == "Home")
        }
        #expect(try await writer.session.quarantinedVersions().contains { $0.kind == .vaultMetadata })
        for account in [owner, administrator, reader] {
            #expect(try await account.session.quarantinedVersions().isEmpty)
        }
    }
}
