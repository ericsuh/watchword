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

    @Test("a device whose own changes are not going out is told so, without the words the UI tests wait for")
    func ownStreamHeldBack() {
        var report = SyncReport()
        report.ownStreamUnverified = 7
        let held = SyncSummary.describe(report)
        #expect(held.contains("held back"))
        report.ownStreamExhausted = true
        let exhausted = SyncSummary.describe(report)
        #expect(exhausted.contains("cannot go out"))
        // Its next place in a vault's sync storage is taken (review finding Z137): the person used to read
        // "Up to date." while nothing went out and deletions were held back.
        report = SyncReport()
        report.ownStreamConflict = 9
        let taken = SyncSummary.describe(report)
        #expect(taken.contains("already taken"))
        // Another account wrote in this device's place in a shared vault (review finding Z146): told, where it was
        // told nothing while every other device held its work aside.
        report = SyncReport()
        report.ownStreamSteppedOver = 1
        let steppedOver = SyncSummary.describe(report)
        #expect(steppedOver.contains("wrote in this device's place"))
        report = SyncReport()
        report.quarantineFull = 3
        report.collided = [RecordKey(recordID: UUID(), kind: .item)]
        let full = SyncSummary.describe(report)
        #expect(full.contains("3 more could not be kept") && full.contains("another vault"))
        for line in [held, exhausted, taken, steppedOver, full] {
            #expect(!line.contains("sent") && !line.contains("received"))
        }
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

    /// Review finding Z37: a device that holds snapshots back for what it keeps aside said nothing, and the summary
    /// read "Up to date." while the stall lasted.
    @Test("a snapshot withheld for what is held aside is a notice, whichever vault said so")
    func snapshotWithheldForReview() {
        var vault = SyncReport()
        vault.snapshotWithheld = true
        vault.snapshotWithheldForQuarantine = true
        var report = AccountSyncReport()
        report.vaults[UUID()] = SyncReport()
        report.vaults[UUID()] = vault
        #expect(report.combined.snapshotWithheldForQuarantine)
        let summary = SyncSummary(report)
        #expect(summary.notices.contains(.snapshotWithheldForReview))
        #expect(SyncNotice.snapshotWithheldForReview.text.contains("Held-Aside Changes"))
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

    @Test("deletions held for a copy nobody received name the copy, its vault and what to do (Z171)")
    func copiesReachedNobody() throws {
        let vaultID = UUID()
        let copy = UUID()
        var report = AccountSyncReport()
        report.deletionsHeldBack = [vaultID]
        report.copiesNobodyReceived = [vaultID: [copy]]
        let summary = SyncSummary(report, vaultNames: [vaultID: "Household"], itemTitles: [copy: "Bank"])
        #expect(!summary.notices.contains(.deletionsHeldBack), "the generic notice hides the reason")
        let notice = try #require(summary.notices.first { $0.id == "copiesReachedNobody" })
        #expect(notice == .copiesReachedNobody([UnreceivedCopy(vault: "Household", title: "Bank")]))
        let text = notice.text
        #expect(text.contains("“Bank” in “Household”"))
        #expect(text.contains("Move it out of the shared vault from this device, or delete it"))
        #expect(text.contains("in every vault"))

        // Names the screen could not read fall back to words, and a vault held back for another reason still says so.
        report.deletionsHeldBack.insert(UUID())
        report.copiesNobodyReceived[vaultID] = [copy, UUID()]
        let unnamed = SyncSummary(report)
        #expect(unnamed.notices.contains(.deletionsHeldBack))
        let fallback = try #require(unnamed.notices.first { $0.id == "copiesReachedNobody" })
        #expect(fallback.text.contains("an item in a shared vault, an item in a shared vault have reached nobody"))
        #expect(fallback.text.contains("Move each out"))
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

    @Test("a device key that could not be read is worded as a retry, never as setting the device up again")
    func deviceKeyUnreadable() {
        let unreadable = ErrorWording.message(for: SharedVaultError.deviceKeyUnreadable)
        let doesNotCommit = ErrorWording.message(for: SharedVaultError.deviceIDDoesNotCommit)
        #expect(unreadable.contains("Try again"))
        #expect(!unreadable.contains("Set it up again"))
        #expect(doesNotCommit.contains("Set it up again"))
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

    /// ADR 0010 (G3): the person's unchecked "they match" is no evidence; the full code typed is the only evidence the
    /// fallback offers, and the device checks it.
    @Test("a typed full vault sharing code is the only evidence the fallback offers")
    func evidenceOrder() {
        var confirmation = FingerprintConfirmation()
        #expect(confirmation.evidence() == nil)
        confirmation.typedSafetyNumber = "   "
        #expect(confirmation.evidence() == nil)
        confirmation.typedSafetyNumber = " 12345 "
        #expect(confirmation.evidence() == .safetyNumber("12345"))
    }

    @Test("every way a vault sharing code session ends is worded, and a wrong code says how many tries are left")
    func sharingCodeWording() {
        let failures: [SharingCodeError] = [
            .sessionNotFound, .sessionTaken, .numbersExhausted, .sameAccount, .malformedMessage, .commitmentMismatch,
            .boardInterference, .tooManyAttempts, .expired, .scannedCodeMismatch, .malformedCode, .notReady,
            .invitationInvalid,
        ]
        for failure in failures {
            #expect(!SharingCodeWording.failure(failure).isEmpty, "\(failure)")
            #expect(ErrorWording.message(for: failure) == SharingCodeWording.failure(failure))
        }
        #expect(SharingCodeWording.wrongCode(attemptsLeft: 2).contains("2 tries left"))
        #expect(SharingCodeWording.wrongCode(attemptsLeft: 1).contains("One try left"))
        #expect(!ErrorWording.message(for: SharedVaultError.sharingBoardNotConfigured).isEmpty)
    }

    @Test("a safety number shows as twelve groups of five")
    func groups() {
        let number = (0..<12).map { String(format: "%05d", $0) }.joined(separator: " ")
        #expect(SharingCodes.groups(of: number).count == 12)
    }
}
