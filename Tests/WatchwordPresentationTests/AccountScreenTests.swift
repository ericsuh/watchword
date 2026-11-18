import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordPresentation
import WatchwordSharing
import WatchwordSync
import WatchwordTestSupport

@Suite("Screen models: vaults")
@MainActor
struct VaultsModelTests {
    @Test("vaults are listed Personal first, and created and renamed through the session")
    func createAndRename() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        let probe = ContextProbe()
        let model = VaultsModel(context: probe.context(vault.session))
        await model.load()
        #expect(model.rows.map(\.name) == ["Personal"])
        #expect(model.rows.first?.isPersonal == true)
        #expect(!model.sharingAvailable, "a session without sharing settings cannot share")

        let id = try #require(await model.create(name: "Garden"))
        #expect(model.rows.map(\.name) == ["Personal", "Garden"])
        #expect(model.row(id)?.detail == "Only you")
        #expect(await model.rename(id, to: "Allotment"))
        #expect(model.rows.map(\.name) == ["Personal", "Allotment"])
        #expect(probe.activity >= 3)
    }

    @Test("a name the session would refuse is caught first, and the session's refusal is worded")
    func names() async throws {
        #expect(VaultsModel.problem(withName: "  ") == "Enter a name.")
        #expect(VaultsModel.problem(withName: String(repeating: "a", count: 257)) != nil)
        #expect(VaultsModel.problem(withName: "Garden") == nil)
        let vault = TestVault()
        try await vault.createAccount()
        let model = VaultsModel(context: ContextProbe().context(vault.session))
        #expect(await model.create(name: "") == nil)
        #expect(model.errorMessage?.contains("name") == true)
    }

    @Test("a call that finds the vault locked tells the app")
    func locked() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        await vault.session.lock()
        let probe = ContextProbe()
        let model = VaultsModel(context: probe.context(vault.session))
        await model.load()
        #expect(probe.locks == 1)
        #expect(model.errorMessage?.contains("locked") == true)
    }
}

@Suite("Screen models: devices")
@MainActor
struct DevicesModelTests {
    @Test("the account's devices are listed this device first, and another is removed with a new password")
    func revokeWithNewPassword() async throws {
        let devices = try await TwoDevices.make()
        let model = DevicesModel(context: ContextProbe().context(devices.first.session))
        await model.load()
        #expect(model.rows.map(\.name) == ["Pat's Mac", "Pat's iPad"])
        #expect(model.rows.map(\.isThisDevice) == [true, false])
        #expect(model.rows.map(\.mayRevoke) == [false, true])

        var form = RevocationForm()
        form.currentPassword = TestVault.password
        form.newPassword = "a brand new passphrase"
        form.confirmation = "a brand new passphrase"
        let iPad = try #require(model.rows.last)
        #expect(await model.revoke(iPad, with: form))
        #expect(model.rows.last?.isRevoked == true)
        #expect(model.rows.last?.detail == "Removed by this device")
        #expect(model.notice?.contains("password changed") == true)

        await devices.first.session.lock()
        try await devices.first.session.unlock(password: "a brand new passphrase")
    }

    /// Whoever enrols a device names it (A4: anyone with the password and the Secret Key, or a device of the person's
    /// that someone else is using): a name must not pass for this device, nor reorder the text around it.
    @Test("a device named to impersonate this one is shown cleaned, and only this device is marked as this device")
    func impersonatingName() async throws {
        let transport = InMemorySyncTransport()
        let first = TestVault.syncing(over: transport, seed: 81, name: "Pat's Mac")
        try await first.createAccount()
        let second = try await first.enrolledDevice(
            deviceID: TwoDevices.secondID, over: transport, name: "Pat's Mac (this device)\u{202E}\n")
        try await second.session.unlock(password: TestVault.password)
        try await second.session.sync()
        try await first.session.sync()
        let model = DevicesModel(context: ContextProbe().context(first.session))
        await model.load()
        let other = try #require(model.rows.first { !$0.isThisDevice })
        #expect(other.name == "Pat's Mac")
        #expect(!other.name.unicodeScalars.contains { $0.properties.generalCategory == .format })
        #expect(model.rows.filter(\.isThisDevice).count == 1)
        #expect(model.names[other.id] == "“Pat's Mac”")
        #expect(DeviceRow.clean("A\u{0}B\tC  “D”") == "A B C D")
    }

    @Test("the removal form, passwords included, is cleared by a lock of the session")
    func revocationFormClearedOnLock() async throws {
        let devices = try await TwoDevices.make()
        let locks = await LockSignal.watching(devices.first.session)
        let model = DevicesModel(context: ScreenContext(session: devices.first.session, locks: locks))
        model.revocation.currentPassword = TestVault.password
        model.revocation.newPassword = "a brand new passphrase"
        await devices.first.session.lock()
        for _ in 0..<1000 where !model.revocation.currentPassword.isEmpty { await Task.yield() }
        #expect(model.revocation == RevocationForm())
        locks.stop()
    }

    @Test("keeping the password needs both statements confirmed")
    func keepPasswordNeedsConfirmations() {
        var form = RevocationForm()
        form.currentPassword = "current password"
        form.changesPassword = false
        #expect(form.choice == nil)
        form.deviceWasLocked = true
        #expect(form.choice == nil)
        form.passwordUnknownToHolder = true
        #expect(form.choice == .keepPassword(current: "current password"))
    }

    @Test("a new password must be long enough, confirmed and new")
    func newPasswordChecks() {
        var form = RevocationForm()
        form.currentPassword = "current password"
        form.newPassword = "short"
        form.confirmation = "short"
        #expect(form.problem?.contains("at least") == true)
        form.newPassword = "current password"
        form.confirmation = "current password"
        #expect(form.problem?.contains("different") == true)
        form.confirmation = "something else entirely"
        #expect(form.problem?.contains("do not match") == true)
    }

    @Test("a wrong current password revokes nothing")
    func wrongPassword() async throws {
        let devices = try await TwoDevices.make()
        let model = DevicesModel(context: ContextProbe().context(devices.first.session))
        await model.load()
        var form = RevocationForm()
        form.currentPassword = "not the password"
        form.newPassword = "a brand new passphrase"
        form.confirmation = "a brand new passphrase"
        let iPad = try #require(model.rows.last)
        #expect(!(await model.revoke(iPad, with: form)))
        #expect(model.errorMessage == "Incorrect password.")
        #expect(model.rows.last?.isRevoked == false)
    }

    @Test("a password changed on the other device shows here after a sync, and the summary says so")
    func passwordChangedElsewhere() async throws {
        let devices = try await TwoDevices.make()
        try await devices.second.session.changePassword(current: TestVault.password, new: "changed on the iPad")
        try await devices.second.session.sync()
        let model = DevicesModel(context: ContextProbe().context(devices.first.session))
        await model.syncNow()
        #expect(model.awaitingNewPassword)
        #expect(model.sync?.notices.contains(.awaitingNewPassword) == true)
    }
}

@Suite("Screen models: held-aside changes")
@MainActor
struct QuarantineModelTests {
    @Test("a version that jumps too far is held aside, named by item, vault and device, and discarded by choice")
    func implausibleJump() async throws {
        var configuration = SyncSettings(state: InMemorySyncStateStore(), transport: InMemorySyncTransport())
            .configuration
        configuration.maximumVersionJump = 4
        let devices = try await TwoDevices.make(firstConfiguration: configuration)
        let garden = try await devices.first.session.createVault(name: "Garden")
        var item = try await devices.first.session.save(
            login(garden.id, "Allotment", host: "allotments.example", username: "pat", password: "x7#Vq9!mLp2$Zr8@Wn4&")
        )
        try await devices.first.session.sync()
        try await devices.second.session.sync()
        item = try await devices.second.session.item(id: item.id)
        for round in 0..<10 {
            item.notes = "edit \(round)"
            item = try await devices.second.session.save(item)
        }
        try await devices.second.session.sync()
        let report = try await devices.first.session.syncAll()
        #expect(SyncSummary(report).notices.contains(.keptAside(1)))

        let model = QuarantineModel(context: ContextProbe().context(devices.first.session))
        await model.load()
        let row = try #require(model.rows.first)
        #expect(model.rows.count == 1)
        #expect(row.subject == "Allotment")
        #expect(row.vaultName == "Garden")
        #expect(row.author == "“Pat's iPad”")
        #expect(!row.isSharedVault && !row.isDeletion)
        #expect(row.summary.hasPrefix("Version "))
        #expect(model.sharedRows.isEmpty)

        await model.discard(row)
        #expect(model.rows.isEmpty)
        #expect(try await devices.first.session.quarantine().isEmpty)
    }

    @Test("without sync there is nothing held aside, and the screen says so rather than failing")
    func withoutSync() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        let model = QuarantineModel(context: ContextProbe().context(vault.session))
        await model.load()
        #expect(!model.isSyncConfigured)
        #expect(model.rows.isEmpty && model.errorMessage == nil)
    }
}

@Suite("Screen models: a password changed by someone else")
@MainActor
struct PasswordChangedElsewhereTests {
    /// The flow the unlock screen and the Devices screen offer together (docs/02-architecture.md §7.8): the other
    /// device changed the password; this one unlocks with the password it has, removes that device and sets its own.
    @Test("the person unlocks with this device's password, removes the other device and sets a new password")
    func takeTheAccountBack() async throws {
        let devices = try await TwoDevices.make()
        try await devices.second.session.changePassword(current: TestVault.password, new: "not the person's own")
        try await devices.second.session.sync()
        let model = DevicesModel(context: ContextProbe().context(devices.first.session))
        await model.syncNow()
        #expect(model.sync?.notices.contains(.awaitingNewPassword) == true)

        await devices.first.session.lock()
        await #expect(throws: VaultError.passwordChangedOnAnotherDevice) {
            try await devices.first.session.unlock(password: TestVault.password)
        }
        try await devices.first.session.unlock(password: TestVault.password, ignoringPasswordChange: true)
        await model.load()
        #expect(model.awaitingNewPassword)
        var form = RevocationForm()
        form.currentPassword = TestVault.password
        form.newPassword = "the person's own password"
        form.confirmation = "the person's own password"
        let other = try #require(model.rows.first { $0.mayRevoke })
        #expect(await model.revoke(other, with: form), "\(model.errorMessage ?? "")")
        #expect(!model.awaitingNewPassword)
        #expect(model.rows.first { $0.id == other.id }?.isRevoked == true)
    }

    /// The other answer (review findings Z1, Z8): the change was the person's own, and they unlocked this device with
    /// the password it still had. The Devices screen says which device changed it and what following that does, and
    /// follows it with that change's password and no other.
    @Test("the person follows the change they made on the other device, by naming that device")
    func followTheChange() async throws {
        let devices = try await TwoDevices.make()
        let newPassword = "the person's own new password"
        try await devices.second.session.changePassword(current: TestVault.password, new: newPassword)
        try await devices.second.session.sync()
        let model = DevicesModel(context: ContextProbe().context(devices.first.session))
        await model.syncNow()
        await devices.first.session.lock()
        try await devices.first.session.unlock(password: TestVault.password, ignoringPasswordChange: true)
        await model.load()
        #expect(model.awaitingNewPassword)
        let change = try #require(model.passwordChanges.first)
        #expect(model.passwordChanges.count == 1 && change.mayFollow)
        #expect(change.summary.hasPrefix("The account password was changed on “"), "\(change.summary)")

        #expect(await !model.follow(change, password: TestVault.password))
        #expect(model.errorMessage == "Incorrect password.")
        #expect(await model.follow(change, password: newPassword), "\(model.errorMessage ?? "")")
        #expect(!model.awaitingNewPassword && model.passwordChanges.isEmpty)
        await devices.first.session.lock()
        await #expect(throws: CryptoError.authenticationFailed) {
            try await devices.first.session.unlock(password: TestVault.password)
        }
        try await devices.first.session.unlock(password: newPassword)
    }
}

@Suite("Screen models: held-aside changes after sharing")
@MainActor
struct QuarantineAfterSharingTests {
    /// The screenshot tour's order on macOS: the account shares a vault with another account, then its other device
    /// (which has no sharing settings, as `UITestPeer`'s has not) writes a version past the jump ceiling into the
    /// Personal vault. The sync's one line and its notices must still say a change was held for review.
    @Test("a version past the ceiling is reported held for review when a shared vault is also syncing")
    func heldForReviewWithASharedVault() async throws {
        let transport = InMemorySyncTransport()
        let directory = InMemoryKeyBundleDirectory()
        var settings = SyncSettings(state: InMemorySyncStateStore(), transport: transport)
        settings.configuration.maximumVersionJump = 16
        let app = TestVault(sync: settings, seed: 901, deviceName: "UI-test device")
        try await app.createAccount()
        let appContacts = InMemoryVerifiedContactStore()
        await app.session.configureSharing(
            SharingSettings(state: InMemorySharingStateStore(), contacts: appContacts, directory: directory))
        await directory.publish(try await app.session.publicKeyBundle())
        let personal = try #require(await app.session.personalVaultID)
        _ = try await app.session.save(
            login(personal, "Library", host: "citylibrary.org", username: "pat", password: "x7#Vq9!mLp2$Zr8@Wn4&"))
        try await app.session.sync()

        // The other device of the account joins, with no sharing settings.
        let peer = try await app.enrolledDevice(deviceID: TwoDevices.secondID, over: transport, name: "Other")
        try await peer.session.unlock(password: TestVault.password)
        try await peer.session.sync()
        try await app.session.sync()

        // As in the tour: the same item renamed on both devices, the conflict synced and resolved here.
        var there = try #require(try await peer.session.items().items.first)
        there.title += " elsewhere"
        _ = try await peer.session.save(there)
        try await peer.session.sync()
        var here = try await app.session.item(id: there.id)
        here.title = "Library here"
        _ = try await app.session.save(here)
        try await app.session.sync()
        let conflicted = try await app.session.item(id: there.id)
        if let other = conflicted.conflicts[.title]?.first {
            try await app.session.resolveConflict(itemID: there.id, group: .title, choosing: other.value)
        }
        try await app.session.sync()

        // A vault shared with another person, who accepts.
        let member = try await SharingAccount.make(over: transport, directory: directory, seed: 902)
        let household = try await app.session.createVault(name: "Household").id
        try await app.session.shareVault(household)
        try await app.session.verifyContact(member.accountID, evidence: .safetyNumber(member.safetyNumber))
        let invitation = try await app.session.invite(member.accountID, to: household, as: .readWrite)
        let ownerNumber = try await app.session.publicKeyBundle().fingerprint.safetyNumber
        try await member.session.acceptInvitation(invitation, ownerEvidence: .safetyNumber(ownerNumber))
        try await member.session.sync()
        _ = try await app.session.syncAll()

        // The other device edits the first live item forty times, then publishes.
        try await peer.session.sync()
        var item = try #require(try await peer.session.items().items.first { !$0.isTrashed })
        #expect(item.vaultID == personal)
        for round in 0..<40 {
            item.notes = "Edited elsewhere, \(round + 1) times"
            item = try await peer.session.save(item)
        }
        try await peer.session.sync()

        let report = try await app.session.syncAll()
        let summary = SyncSummary(report)
        #expect(summary.headline.contains("held for review"), "\(summary.headline) \(report.combined)")
        #expect(summary.notices.contains { if case .keptAside = $0 { return true } else { return false } })
    }
}
