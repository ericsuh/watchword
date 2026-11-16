import Foundation
import Testing
import WatchwordCrypto
import WatchwordInterchange
import WatchwordKit
import WatchwordPresentation
import WatchwordSharing
import WatchwordStore
import WatchwordSync

@Suite("Screen wording: sync status and errors")
struct WordingTests {
    @Test("a sync's one line says what was received and sent, as the UI tests wait for")
    func headline() {
        var report = SyncReport()
        #expect(SyncSummary.describe(report) == "Up to date.")
        report.applied = 2
        report.pushedEntries = 1
        #expect(SyncSummary.describe(report) == "2 change(s) received; 1 change(s) sent.")
        report.transportUnavailable = true
        #expect(SyncSummary.describe(report).contains("could not be reached"))
    }

    @Test("a sync stopped by a newer format says to update the app (ADR 0009)")
    func updateRequired() {
        var vault = SyncReport()
        vault.requiresNewerVersion = true
        var report = AccountSyncReport()
        report.vaults[UUID()] = vault
        let summary = SyncSummary(report)
        #expect(summary.updateRequired)
        #expect(summary.notices.contains(.updateRequired))
        #expect(SyncNotice.updateRequired.text.hasPrefix("Update Watchword"))
    }

    @Test("a shared vault gone on in a later format also says to update the app (§8.9)")
    func sharedVaultLaterFormat() {
        var sharing = SharedVaultSyncReport()
        sharing.requiresNewerVersion = true
        var report = AccountSyncReport()
        report.sharing[UUID()] = sharing
        #expect(SyncSummary(report).updateRequired)
    }

    @Test("a withheld snapshot names the devices to update, this account's by name and others' by ID")
    func snapshotWithheld() throws {
        let known = UUID()
        let foreign = try #require(UUID(uuidString: "1A2B3C4D-0000-4000-8000-000000000000"))
        var vault = SyncReport()
        vault.snapshotWithheld = true
        vault.snapshotWithheldBy = [known, foreign]
        var report = AccountSyncReport()
        report.vaults[UUID()] = vault
        let summary = SyncSummary(report, deviceNames: [known: "Pat's iPad"])
        let notice = try #require(summary.notices.first { $0.id == "snapshotWithheld" })
        #expect(notice == .snapshotWithheld(by: ["Pat's iPad", "a device of another member (1A2B3C4D)"]))
        #expect(notice.text.contains("Pat's iPad"))
    }

    @Test("a password changed elsewhere is a notice, not a promise that changes will be applied at unlock")
    func awaitingNewPassword() {
        var vault = SyncReport()
        vault.deferredUntilUnlock = true
        vault.awaitingNewPassword = true
        var report = AccountSyncReport()
        report.awaitingNewPassword = true
        report.vaults[UUID()] = vault
        let summary = SyncSummary(report)
        #expect(summary.notices.contains(.awaitingNewPassword))
        #expect(!summary.headline.contains("when you unlock"))
    }

    @Test("held-aside and quarantined versions are counted for the person to review (S49)")
    func keptAside() {
        var vault = SyncReport()
        vault.heldAside = [RecordKey(recordID: UUID(), kind: .item)]
        vault.quarantined = [RecordKey(recordID: UUID(), kind: .item)]
        var report = AccountSyncReport()
        report.vaults[UUID()] = vault
        #expect(SyncSummary(report).notices.contains(.keptAside(2)))
    }

    @Test("a wrong password and tampering read the same", arguments: [CryptoError.authenticationFailed])
    func authenticationFailed(error: CryptoError) {
        #expect(ErrorWording.message(for: error) == "Incorrect password.")
    }

    @Test("a shared vault in a later format is worded as read-only until the app is updated")
    func readOnlyLaterFormat() {
        let text = ErrorWording.message(for: SharedVaultError.writeRefused(.requiresNewerVersion))
        #expect(text.contains("newer version") && text.contains("update"))
        #expect(ErrorWording.message(for: SharingError.requiresNewerVersion) == text)
    }

    @Test("a cancelled biometric prompt or task says nothing")
    func cancelled() {
        #expect(ErrorWording.message(for: KeychainError.userCancelled).isEmpty)
        #expect(ErrorWording.message(for: CancellationError()).isEmpty)
    }

    @Test("a password changed on another device asks for the new one")
    func passwordChanged() {
        #expect(ErrorWording.message(for: VaultError.passwordChangedOnAnotherDevice).contains("new password"))
    }
}

@Suite("Screen wording: invitation and fingerprint codes")
struct SharingCodesTests {
    @Test("an invitation survives the trip as text, with spaces and line breaks added on the way")
    func invitationRoundTrip() throws {
        let invitation = Invitation(vaultID: UUID(), ownerAccountID: UUID())
        let text = SharingCodes.text(for: invitation)
        #expect(text.count == 2 * Invitation.encodedLength)
        #expect(SharingCodes.invitation(from: text) == invitation)
        #expect(SharingCodes.invitation(from: text.lowercased()) == invitation)
        let spaced = "  " + text.prefix(20) + "\n" + text.dropFirst(20) + " "
        #expect(SharingCodes.invitation(from: spaced) == invitation)
    }

    @Test(
        "anything but exactly one invitation is refused",
        arguments: ["", "WWIV", String(repeating: "0", count: 74), String(repeating: "G", count: 74), "garbage"])
    func invitationRefused(text: String) {
        #expect(SharingCodes.invitation(from: text) == nil)
    }

    @Test("an invitation with a byte too many or too few is refused")
    func invitationLength() {
        let text = SharingCodes.text(for: Invitation(vaultID: UUID(), ownerAccountID: UUID()))
        #expect(SharingCodes.invitation(from: text + "00") == nil)
        #expect(SharingCodes.invitation(from: String(text.dropLast(2))) == nil)
    }

    @Test("an account is named by its ID or by its fingerprint code, which is kept as evidence")
    func accountReference() throws {
        let id = UUID()
        #expect(
            SharingCodes.account(from: " \(id.uuidString) ") == AccountReference(accountID: id, fingerprintCode: nil))
        #expect(SharingCodes.account(from: "not an account") == nil)
        #expect(SharingCodes.account(from: "WWFP1-" + String(repeating: "0", count: 10)) == nil)
    }

    @Test("a typed safety number is preferred, then a code, then the person's own comparison")
    func evidenceOrder() {
        var confirmation = FingerprintConfirmation()
        #expect(confirmation.evidence(code: nil) == nil)
        confirmation.comparedByEye = true
        #expect(confirmation.evidence(code: nil) == .comparedByEye)
        #expect(confirmation.evidence(code: "WWFP1-X") == .scannedCode("WWFP1-X"))
        confirmation.typedSafetyNumber = " 12345 "
        #expect(confirmation.evidence(code: "WWFP1-X") == .safetyNumber("12345"))
    }

    @Test("a safety number shows as twelve groups of five")
    func groups() {
        let number = (0..<12).map { String(format: "%05d", $0) }.joined(separator: " ")
        #expect(SharingCodes.groups(of: number).count == 12)
    }
}
