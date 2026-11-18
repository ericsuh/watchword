import Foundation
import Testing
import WatchwordKit
import WatchwordSharing
import WatchwordSync
import WatchwordTestSupport

/// Vault sharing codes through `VaultSession` (ADR 0010; docs/02-architecture.md §8.4): a session between two real
/// accounts, the pins it makes, the invitation sent inside it and the join, a scan in each direction, and what a lock
/// and a missing board do. The attacks are in "shared vaults through the session".
@Suite("Vault sharing codes through VaultSession")
struct SharingCodeSessionTests {
    @Test("a session pins each account for the other, and the invitation sent inside it joins the vault")
    func inviteThroughASession() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 1_101)
        let invitee = try await household.account(seed: 1_102)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)

        let started = try await owner.session.startSharingCodeSession()
        #expect(started.role == .starter && started.step == .showNumber && started.ownCode == nil)
        let number = try #require(started.number)
        let joined = try await invitee.session.joinSharingCodeSession(number: number)
        #expect(joined.step == .waiting && joined.partner == owner.accountID)
        let answered = try await owner.session.refreshSharingCodeSession()
        #expect(answered.step == .typeTheirCode && answered.partner == invitee.accountID)
        let shown = try await invitee.session.refreshSharingCodeSession()
        #expect(shown.step == .showCodeAndTypeTheirs)
        let accepted = try await owner.session.enterSharingCode(try #require(shown.ownCode))
        #expect(accepted.step == .verified && accepted.pinned && accepted.ownCode != nil)
        await #expect(throws: SharingError.fingerprintNotVerified, "nothing to open before the starter is pinned") {
            _ = try await invitee.session.sharingCodeInvitation()
        }
        let done = try await invitee.session.enterSharingCode(try #require(accepted.ownCode))
        #expect(done.step == .verified && done.pinned)
        #expect(try await invitee.session.sharingCodeInvitation() == nil, "not sent yet")

        let ownerPins = VerifiedContacts(store: owner.contacts, account: owner.bundle)
        let inviteePins = VerifiedContacts(store: invitee.contacts, account: invitee.bundle)
        #expect(try await ownerPins.pinned(invitee.accountID)?.method == .sharingCode)
        #expect(try await inviteePins.pinned(owner.accountID)?.method == .sharingCode)

        let sent = try await owner.session.inviteThroughSharingCode(to: vaultID, as: .readWrite)
        await #expect(throws: SharingError.invitationAlreadyCompleted, "one invitation per session") {
            _ = try await owner.session.inviteThroughSharingCode(to: vaultID, as: .readOnly)
        }
        try await owner.session.sync()
        let received = try #require(try await invitee.session.sharingCodeInvitation())
        #expect(received == sent)
        try await invitee.session.acceptInvitation(received)
        try await invitee.session.sync()
        try await owner.session.sync()
        #expect(try await invitee.session.sharedVaultStatus(vaultID).role == .readWrite)
        #expect(try await owner.session.sharedVaultStatus(vaultID).verifiedMembers?.contains(invitee.accountID) == true)
    }

    @Test("a scan in either direction stands in for typing that direction's code")
    func scansThroughASession() async throws {
        let household = SharedVaultHousehold()
        let starter = try await household.account(seed: 1_111)
        let joiner = try await household.account(seed: 1_112)
        let started = try await starter.session.startSharingCodeSession()
        let joined = try await joiner.session.joinSharingCodeSession(scanned: try #require(started.scanPayload))
        #expect(joined.scanned && joined.pinned && joined.step == .verified, "\(joined)")
        _ = try await starter.session.refreshSharingCodeSession()
        let scanned = try await starter.session.scanSharingPartnerCode(try #require(joined.scanPayload))
        #expect(scanned.step == .verified && scanned.pinned)
        #expect(
            try await VerifiedContacts(store: starter.contacts, account: starter.bundle).pinned(joiner.accountID)?
                .method == .scannedCode)
        #expect(
            try await VerifiedContacts(store: joiner.contacts, account: joiner.bundle).pinned(starter.accountID)?
                .method == .scannedCode)
    }

    @Test("a lock ends the session, and with no board there is none to start")
    func lockAndNoBoard() async throws {
        let household = SharedVaultHousehold()
        let starter = try await household.account(seed: 1_121)
        _ = try await starter.session.startSharingCodeSession()
        #expect(await starter.session.sharingCodeStatus() != nil)
        await starter.session.lock()
        #expect(await starter.session.sharingCodeStatus() == nil)
        try await starter.session.unlock(password: TestVault.password)
        await #expect(throws: SharingCodeError.notReady) { _ = try await starter.session.refreshSharingCodeSession() }

        let bare = TestVault.syncing(over: household.transport, seed: 1_122)
        try await bare.createAccount()
        await bare.session.configureSharing(
            SharingSettings(
                state: InMemorySharingStateStore(), contacts: InMemoryVerifiedContactStore(),
                directory: household.directory))
        await #expect(throws: SharedVaultError.sharingBoardNotConfigured) {
            _ = try await bare.session.startSharingCodeSession()
        }
    }

    @Test("a typed number that is not eight digits starts nothing")
    func badNumber() async throws {
        let household = SharedVaultHousehold()
        let joiner = try await household.account(seed: 1_131)
        for typed in ["1234567", "1234-5678-9", "abcdefgh"] {
            await #expect(throws: SharingCodeError.malformedCode) {
                _ = try await joiner.session.joinSharingCodeSession(number: typed)
            }
        }
        await #expect(throws: SharingCodeError.sessionNotFound) {
            _ = try await joiner.session.joinSharingCodeSession(number: "1234 5678")
        }
        await #expect(throws: SharingCodeError.malformedCode) {
            _ = try await joiner.session.joinSharingCodeSession(scanned: "WWSC1-12345678")
        }
    }
}
