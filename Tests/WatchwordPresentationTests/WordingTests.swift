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

    /// Review of round 11 (Z185): the gate that holds every vault while a restore's move is incomplete was silent.
    /// Review of round 20 (Z243): round 19's text said Watchword finishes the move by itself, which a failure that
    /// lasts (a chain row that cannot be read, a registry that cannot be evaluated) makes untrue; it says the move is
    /// tried again at each sync and each unlock, which holds however the wait ends, a wait for sharing included (it is
    /// tried, and waits). Stop Waiting refused during a move is read in the open, unlocked app, so its message asks
    /// nobody to open and unlock it.
    @Test("a restore whose move is incomplete says that nothing is sent, that it is tried again, and nothing is lost")
    func deviceMigrationIncomplete() {
        var report = AccountSyncReport()
        report.vaults[UUID()] = SyncReport()
        #expect(!SyncSummary(report).notices.contains(.deviceMigrationIncomplete))
        report.deviceMigrationIncomplete = true
        let summary = SyncSummary(report)
        #expect(summary.notices.contains(.deviceMigrationIncomplete))
        let text = SyncNotice.deviceMigrationIncomplete.text
        #expect(text.contains("sends none"))
        #expect(text.contains("Nothing has been lost"))
        #expect(text.contains("tries again at each sync and each unlock"))
        #expect(!text.contains("by itself"), "a failure that lasts never finishes by itself")
        #expect(!text.contains("finishes"), "a failure that lasts never finishes by itself")
        let refused = ErrorWording.message(for: VaultError.deviceMigrationIncomplete)
        #expect(refused.contains("still moving its sync records"), "Stop Waiting refused during a move says why")
        #expect(refused.contains("Try again after the next sync"))
        #expect(!refused.contains("unlock"), "the message is read in the open, unlocked app")
    }

    /// Review of round 25 (Z271): an unlocked sync held back by a restore's incomplete move said "will be applied when
    /// you unlock" to a person whose vault was open, as Z264 found for the key. It says what it waits for; the move's
    /// own notice stays; locked, the line is as before.
    @Test("an unlocked sync held back by a move says it waits for the move, not for an unlock")
    func movePendingWhileUnlocked() {
        var vault = SyncReport()
        vault.deferredUntilUnlock = true
        var report = AccountSyncReport()
        report.vaults[UUID()] = vault
        report.deviceMigrationIncomplete = true
        let locked = SyncSummary(report)
        #expect(locked.headline == "Changes were downloaded and will be applied when you unlock.")

        report.movePendingWhileUnlocked = true
        let summary = SyncSummary(report)
        #expect(
            summary.headline
                == "Changes were downloaded and will be applied once this device has finished moving its sync records.")
        #expect(!summary.headline.contains("unlock"), "an open vault is told to unlock")
        #expect(summary.notices.contains(.deviceMigrationIncomplete))
        #expect(!summary.notices.contains(.deviceRegistering) && !summary.notices.contains(.deviceKeyUnreadable))
    }

    /// Review of round 23 (Z264): an unlocked sync that only downloaded because this device's own key could not be
    /// read, or because it has still to register under a key of its own (a restored store), said "will be applied when
    /// you unlock" to a person whose vault was open. Each says why, and that it is tried again; locked, the line is as
    /// before.
    @Test(
        "a sync held back by this device's own key says why, not when you unlock",
        arguments: zip(
            [OwnDeviceKeyWait.unreadable, .registering],
            [SyncNotice.deviceKeyUnreadable, .deviceRegistering]))
    func ownDeviceKeyWait(wait: OwnDeviceKeyWait, notice: SyncNotice) {
        var vault = SyncReport()
        vault.deferredUntilUnlock = true
        var report = AccountSyncReport()
        report.vaults[UUID()] = vault
        let locked = SyncSummary(report)
        #expect(locked.headline == "Changes were downloaded and will be applied when you unlock.")
        #expect(!locked.notices.contains(notice))

        report.ownDeviceKeyWait = wait
        let summary = SyncSummary(report)
        #expect(!summary.headline.contains("unlock"), "an open vault is told to unlock")
        #expect(summary.headline.contains("downloaded"))
        #expect(summary.notices.contains(notice))
        #expect(summary.notices.filter { $0 == .deviceKeyUnreadable || $0 == .deviceRegistering }.count == 1)
        let text = notice.text
        #expect(text.contains("none are applied or sent"))
        #expect(text.contains("Nothing has been lost"))
        #expect(text.contains("tries again at each sync"))
        #expect(!text.contains("when you unlock"))
        #expect(!text.contains("enrol"), "a key that could not be read is a retry, never a reason to enrol again")
    }

    @Test("a key that could not be read is a retry, and only a registration under way speaks of registering")
    func ownDeviceKeyWording() {
        #expect(SyncNotice.deviceKeyUnreadable.text.contains("could not read its own key"))
        #expect(!SyncNotice.deviceKeyUnreadable.text.contains("regist"))
        // A sync stopped before it downloaded anything can stand beside it (review of round 25, Z271).
        #expect(SyncNotice.deviceKeyUnreadable.text.contains("Until it can, changes are downloaded"))
        #expect(!SyncNotice.deviceKeyUnreadable.text.contains("were downloaded"))
        #expect(SyncNotice.deviceRegistering.text.contains("still registering"))
        #expect(SyncNotice.deviceRegistering.text.contains("each sync and each unlock"))
        #expect(!SyncNotice.deviceRegistering.text.contains("was restored"), "a device may be registering unrestored")
    }

    /// Review of round 24 (Z268): a shared vault's take-out that did not finish holds every deletion back, and the
    /// summary said nothing of it. It says so in its own words: not the generic notice, whose "something moved has not
    /// reached your other devices" is untrue there.
    @Test("a take-out that did not finish says deletions wait, and not that something moved went nowhere")
    func takeOutUnfinished() {
        let vaultID = UUID()
        var report = AccountSyncReport()
        report.vaults[vaultID] = SyncReport()
        #expect(!SyncSummary(report).notices.contains { $0.id == "takeOutUnfinished" })
        report.takeOutUnfinished = [vaultID]
        report.takeOutUnfinishedSentNothing = [vaultID]
        let summary = SyncSummary(report)
        #expect(summary.notices.contains(.takeOutUnfinished(changesWait: true)))
        #expect(!summary.notices.contains(.deletionsHeldBack))
        let text = SyncNotice.takeOutUnfinished(changesWait: true).text
        #expect(text.contains("could not finish checking a shared vault's changes"))
        #expect(text.contains("deletions made on this device wait"))
        // Its own changes there wait too, where the sync sent none of them (Z270).
        #expect(text.contains("and so do its changes in that vault."))
        #expect(text.contains("tries again at each sync"))
        #expect(text.contains("Nothing has been lost"))
        #expect(!text.contains("reached"), "says something has not reached the other devices")
        #expect(!text.contains("by itself"))

        // A vault held back for another reason still says so.
        report.deletionsHeldBack.insert(UUID())
        #expect(SyncSummary(report).notices.contains(.deletionsHeldBack))
    }

    /// Review of round 25 (Z278, finding 6, pre-existing): an edit this device made over a write that stops counting
    /// is taken out and held aside as its own (Z44), and holds every deletion back like a move's copy, under the
    /// generic notice, which said "Something it moved or added": untrue of an edit. It says changed too, and still
    /// names the way out.
    @Test("the generic held-back notice is true of an edit held aside, not only of a move or an addition")
    func deletionsHeldBackWording() {
        var report = AccountSyncReport()
        report.deletionsHeldBack = [UUID()]
        #expect(SyncSummary(report).notices.contains(.deletionsHeldBack))
        let text = SyncNotice.deletionsHeldBack.text
        #expect(text.contains("Something it moved, added or changed has not reached your other devices"))
        #expect(!text.contains("moved or added has"), "an edit held aside is neither moved nor added")
        #expect(text.contains("or was held aside"))
        #expect(text.contains("once you discard it under Held-Aside Changes"))
    }

    /// Review of round 25 (Z273): the notice said "and so do its changes in that vault" where the vault's first pass,
    /// not owed, had published and only the replay's take-out failed, beside a headline saying changes were sent.
    /// Where any such vault sent some in the sync, it says only that changes made there may wait; the deletions wait
    /// in every case.
    @Test("a take-out that did not finish after a pass that sent changes says they may wait, not that they wait")
    func takeOutUnfinishedAfterSending() {
        let sent = UUID()
        let unsent = UUID()
        var report = AccountSyncReport()
        report.vaults[sent] = SyncReport()
        report.takeOutUnfinished = [sent]
        #expect(SyncSummary(report).notices.contains(.takeOutUnfinished(changesWait: false)))
        #expect(!SyncSummary(report).notices.contains(.takeOutUnfinished(changesWait: true)))
        let text = SyncNotice.takeOutUnfinished(changesWait: false).text
        #expect(text.contains("deletions made on this device wait"))
        #expect(text.contains("changes it makes in that vault may wait too."))
        #expect(!text.contains("so do its changes"), "says changes wait that this sync sent")
        #expect(text.contains("tries again at each sync"))
        #expect(text.contains("Nothing has been lost"))

        // A vault that sent nothing beside one that sent some: one notice, in the words true of both.
        report.takeOutUnfinished.insert(unsent)
        report.takeOutUnfinishedSentNothing = [unsent]
        let both = SyncSummary(report).notices.filter { $0.id == "takeOutUnfinished" }
        #expect(both == [.takeOutUnfinished(changesWait: false)])
    }

    /// Review of round 20 (Z240): a chain row of a restore's earlier device IDs that the sharing store cannot read held
    /// the deletions back, or the move, under the generic notice (something moved has not reached the other devices)
    /// or none, both untrue. The vaults it holds are explained by a notice of their own.
    @Test("a restore's record that cannot be read says what waits, and hides the generic notice for its vaults")
    func restoredChainUnreadable() throws {
        let vaultID = UUID()
        var report = AccountSyncReport()
        report.vaults[vaultID] = SyncReport()
        #expect(!SyncSummary(report).notices.contains(.restoredChainUnreadable))
        report.deletionsHeldBack = [vaultID]
        report.restoredChainUnreadable = [vaultID]
        let summary = SyncSummary(report)
        #expect(summary.notices.contains(.restoredChainUnreadable))
        #expect(!summary.notices.contains(.deletionsHeldBack), "the generic notice hides the reason")
        let text = SyncNotice.restoredChainUnreadable.text
        #expect(text.contains("could not read part of its sharing records"))
        // True on a device never restored, whose damaged state asks for the record too (review of round 21, Z250).
        #expect(text.contains("cannot rule out that changes from before a restore"))
        #expect(!text.contains("before it was restored"), "says the device was restored, which it may never have been")
        #expect(text.contains("deletions made on this device wait"))
        #expect(text.contains("tries again at each sync"))
        #expect(text.contains("Nothing has been lost"))
        #expect(!text.contains("by itself"))

        // A vault held back for another reason still says so.
        report.deletionsHeldBack.insert(UUID())
        #expect(SyncSummary(report).notices.contains(.deletionsHeldBack))
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

    @Test("deletions held for a restore's work not yet carried name the item and what ends the wait (round 12, M1)")
    func restoredWorkWaiting() throws {
        let vaultID = UUID()
        let item = UUID()
        var report = AccountSyncReport()
        report.deletionsHeldBack = [vaultID]
        report.restoredWorkWaiting = [vaultID: [item]]
        let summary = SyncSummary(report, vaultNames: [vaultID: "Household"], itemTitles: [item: "Bank"])
        #expect(!summary.notices.contains(.deletionsHeldBack), "the generic notice hides the reason")
        let notice = try #require(summary.notices.first { $0.id == "restoredWorkWaiting" })
        #expect(notice == .restoredWorkWaiting([UnreceivedCopy(vault: "Household", title: "Bank")], stopWaiting: []))
        let text = notice.text
        #expect(text.contains("“Bank” in “Household” holds changes made on this device before it was restored"))
        #expect(text.contains("tries again at each sync"))
        #expect(!text.contains("stop waiting"), "a vault that opens here offers no choice")
        let unnamed = SyncSummary(report).notices.first { $0.id == "restoredWorkWaiting" }
        #expect(unnamed?.text.contains("an item in a shared vault holds") == true)
    }

    /// Review of round 14, L2: Stop Waiting is a choice per vault, offered only for one that will not open here (no
    /// current key, or a disputed owner); a vault waiting on the transport, or on a carry that a sync finishes, is
    /// not offered it, and the confirmation says later edits of those items reach nobody either.
    @Test("the restore's wait offers to stop waiting per vault that will not open, and says what stays where")
    func restoredWorkAction() throws {
        let closed = UUID()
        let opens = UUID()
        let left = UUID()
        var report = AccountSyncReport()
        report.deletionsHeldBack = [closed, opens]
        report.restoredWorkWaiting = [closed: [UUID()], opens: [UUID()]]
        report.restoredWorkMayStopWaiting = [closed]
        report.restoredWorkKeptHere = [left: [UUID()]]
        let summary = SyncSummary(report, vaultNames: [closed: "Club", opens: "Household", left: "Old club"])
        #expect(summary.restoredWorkVaults == [closed])
        let waiting = try #require(summary.notices.first { $0.id == "restoredWorkWaiting" })
        #expect(waiting.actions == [.stopWaitingForRestoredWork(vaultID: closed, vault: "Club")])
        let action = try #require(waiting.actions.first)
        #expect(action.title == "Stop Waiting for “Club”")
        #expect(action.vaultID == closed, "the screen cannot tell one vault's button from another's")
        let confirmation = action.confirmation
        #expect(confirmation.contains("made in “Club” before it was restored stay on this device only"))
        #expect(confirmation.contains("even if the vault opens here again"))
        #expect(confirmation.contains("Neither are changes you make to those items on this device afterwards"))
        #expect(waiting.text.contains("you can choose to stop waiting for it"))
        let kept = try #require(summary.notices.first { $0.id == "restoredWorkKeptHere" })
        #expect(kept.actions.isEmpty)
        #expect(kept.text.contains("an item in “Old club” holds changes made on this device before it was restored"))
        #expect(kept.text.contains("stay on this device only"))

        // A vault whose name cannot be read is still offered, by a fallback; none is offered where none is closed.
        let unnamed = SyncSummary(report).notices.first { $0.id == "restoredWorkWaiting" }
        #expect(unnamed?.actions.map(\.title) == ["Stop Waiting for This Vault"])
        report.restoredWorkMayStopWaiting = []
        let none = SyncSummary(report)
        #expect(none.restoredWorkVaults.isEmpty)
        #expect(none.notices.allSatisfy { $0.actions.isEmpty })
    }

    @Test("vaults whose publishing waits for a restore's carry are named, and nothing is lost (round 14, L4)")
    func publishingHeldForCarry() throws {
        let household = UUID()
        let club = UUID()
        var report = AccountSyncReport()
        report.publishingHeldForCarry = [household]
        let summary = SyncSummary(report, vaultNames: [household: "Household"])
        let notice = try #require(summary.notices.first { $0.id == "publishingHeldForCarry" })
        #expect(notice == .publishingHeldForCarry(["Household"], unnamed: 0))
        #expect(notice.actions.isEmpty)
        let text = notice.text
        #expect(text.contains("Changes made on this device in “Household” are waiting"))
        #expect(text.contains("changes from others there are not shown yet"))
        #expect(text.contains("carrying over the changes it made there before it was restored"))
        #expect(text.contains("Nothing has been lost."))
        #expect(!text.contains("sent") && !text.contains("received"), "the words the UI tests wait for")
        #expect(!summary.notices.contains(.deletionsHeldBack), "publishing held for the carry is not a deletion held")

        report.publishingHeldForCarry = [household, club, UUID()]
        let several = SyncSummary(report, vaultNames: [household: "Household", club: "Club"])
        let listed = try #require(several.notices.first { $0.id == "publishingHeldForCarry" })
        #expect(listed.text.contains("in “Club”, “Household” and a shared vault are waiting"))
        #expect(listed.text.contains("changes from others in those vaults are not shown yet"))
        #expect(listed.text.contains("the changes it made in each before"))
        #expect(SyncSummary(AccountSyncReport()).notices.allSatisfy { $0.id != "publishingHeldForCarry" })
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

    @Test("a typed safety number is preferred to the person's own comparison, and nothing else is evidence")
    func evidenceOrder() throws {
        // The fingerprint on the screen: a comparison by eye is evidence for it and for no other (Z40).
        let shown = try Keyset.generate(accountID: UUID()).publicKeyBundle().fingerprint
        var confirmation = FingerprintConfirmation()
        #expect(confirmation.evidence(showing: shown) == nil)
        confirmation.comparedByEye = true
        #expect(confirmation.evidence(showing: shown) == .comparedByEye(shown: shown))
        confirmation.typedSafetyNumber = " 12345 "
        #expect(confirmation.evidence(showing: shown) == .safetyNumber("12345"))
    }

    @Test("a safety number shows as twelve groups of five")
    func groups() {
        let number = (0..<12).map { String(format: "%05d", $0) }.joined(separator: " ")
        #expect(SharingCodes.groups(of: number).count == 12)
    }
}
