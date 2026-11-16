import Foundation
import Testing
import WatchwordKit
import WatchwordModel
import WatchwordPresentation
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
        #expect(model.rows.map(\.name) == ["Pat's Mac (this device)", "Pat's iPad"])
        #expect(model.rows.map(\.mayRevoke) == [false, true])

        var form = RevocationForm()
        form.currentPassword = TestVault.password
        form.newPassword = "a brand new passphrase"
        form.confirmation = "a brand new passphrase"
        let iPad = try #require(model.rows.last)
        #expect(await model.revoke(iPad, with: form))
        #expect(model.rows.last?.isRevoked == true)
        #expect(model.rows.last?.detail == "Removed by Pat's Mac (this device)")
        #expect(model.notice?.contains("password changed") == true)

        await devices.first.session.lock()
        try await devices.first.session.unlock(password: "a brand new passphrase")
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
        #expect(row.author == "Pat's iPad")
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
}
