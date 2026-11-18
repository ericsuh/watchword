import Foundation
import Testing
import WatchwordKit
import WatchwordModel
import WatchwordPresentation
import WatchwordSync
import WatchwordTestSupport

/// The Devices screen after the sync storage was reset (docs/02-architecture.md §7.10; owner decision, 2026-11-17:
/// re-upload, "but ask the user first"): what the person is told, the question, and the two answers.
@Suite("Screen models: after the sync storage was reset")
@MainActor
struct StoreResetScreenTests {
    struct Devices {
        let store: ResettableSyncTransport
        let first: TestVault
        let second: TestVault
        let personal: UUID
    }

    /// Two devices in step, with two items in the Personal vault and one in a vault called "Work".
    static func devices() async throws -> Devices {
        let store = ResettableSyncTransport()
        let first = TestVault.syncing(over: store, seed: 71, name: "Pat's Mac")
        try await first.createAccount()
        let second = try await first.enrolledDevice(deviceID: TwoDevices.secondID, over: store, name: "Pat's iPad")
        try await second.session.unlock(password: TestVault.password)
        try await second.session.sync()
        let personal = try #require(await first.session.personalVaultID)
        let work = try await first.session.createVault(name: "Work")
        for (vault, title) in [(personal, "Bank"), (personal, "Post"), (work.id, "Payroll")] {
            try await first.session.save(
                login(vault, title, host: "example.com", username: "pat", password: "secret"))
        }
        for _ in 0..<3 {
            try await first.session.sync()
            try await second.session.sync()
        }
        return Devices(store: store, first: first, second: second, personal: personal)
    }

    @Test("a reset is reported as one, with a notice that says nothing was lost or uploaded, and no question unasked")
    func notice() async throws {
        let devices = try await Self.devices()
        await devices.store.reset()
        await devices.store.forgetCreates()
        let model = DevicesModel(context: ContextProbe().context(devices.first.session))
        await model.load()
        #expect(!model.storageNeedsUpload, "nothing is known before a sync")
        await model.syncNow()
        #expect(model.storageNeedsUpload && model.reuploadQuestion == nil)
        let sync = try #require(model.sync)
        #expect(sync.headline == "Sync storage was emptied or reset. Nothing was sent, and nothing was uploaded again.")
        #expect(sync.notices.contains(.storageNeedsUpload))
        let text = SyncNotice.storageNeedsUpload.text
        #expect(text.contains("Nothing on this device has been lost") && text.contains("nothing has been uploaded"))
        // Syncing again and again asks nothing and uploads nothing.
        for _ in 0..<3 { await model.syncNow() }
        #expect(model.reuploadQuestion == nil)
        #expect(await devices.store.created.isEmpty)
        #expect(await devices.store.startsAgain == 0)
    }

    @Test("the question says what is gone, what would be uploaded, and that a yes undoes a deletion made elsewhere")
    func question() async throws {
        let devices = try await Self.devices()
        await devices.store.reset()
        let model = DevicesModel(context: ContextProbe().context(devices.first.session))
        await model.syncNow()
        await model.askToUploadAgain()
        let question = try #require(model.reuploadQuestion)
        #expect(question.title == "Upload your vaults again?")
        #expect(question.explanation.contains("emptied or reset") && question.explanation.contains("on purpose"))
        #expect(question.explanation.contains("Everything is still on this device"))
        #expect(question.upload.contains("3 items in 2 vaults") && question.upload.contains("encrypted"))
        #expect(question.warning.contains("undoes that deletion") && question.warning.contains("deliberately"))
        #expect(question.notUploaded == nil && question.paragraphs.count == 3)
        #expect(question.confirmLabel == "Upload Again" && question.declineLabel == "Not Now")
        #expect(await devices.store.startsAgain == 0, "asking uploads nothing")
    }

    @Test("counts are worded in the singular, deleted vaults are named as such, and shared vaults as not uploaded")
    func wording() {
        let id = UUID()
        func vault(_ items: Int, deleted: Bool = false) -> ReuploadPlan.Vault {
            ReuploadPlan.Vault(id: UUID(), name: "V", isPersonal: false, isDeleted: deleted, itemCount: items)
        }
        let single = ReuploadQuestion(ReuploadPlan(deviceID: id, vaults: [vault(1)], sharedVaults: []))
        #expect(single.upload.contains("1 item in 1 vault,"))
        let mixed = ReuploadQuestion(
            ReuploadPlan(
                deviceID: id, vaults: [vault(2), vault(0, deleted: true)], sharedVaults: [vault(5), vault(1)]))
        #expect(mixed.upload.contains("2 items in 1 vault,"))
        #expect(mixed.upload.contains("the record of 1 deleted vault, so that it stays deleted everywhere"))
        #expect(mixed.notUploaded?.contains("2 shared vaults cannot be uploaded again") == true)
        #expect(mixed.notUploaded?.contains("They stay on this device") == true)
        #expect(mixed.paragraphs.count == 4)
    }

    @Test("Not Now uploads nothing, changes nothing, and leaves the notice and the way back to the question")
    func decline() async throws {
        let devices = try await Self.devices()
        await devices.store.reset()
        await devices.store.forgetCreates()
        let probe = ContextProbe()
        let model = DevicesModel(context: probe.context(devices.first.session))
        await model.syncNow()
        await model.askToUploadAgain()
        #expect(model.reuploadQuestion != nil)
        model.declineUpload()
        #expect(model.reuploadQuestion == nil && model.storageNeedsUpload)
        await model.syncNow()
        #expect(model.storageNeedsUpload)
        #expect(await devices.store.created.isEmpty)
        #expect(await devices.store.startsAgain == 0)
        #expect(try await devices.first.session.items().items.count == 3)
        await model.askToUploadAgain()
        #expect(model.reuploadQuestion != nil)
    }

    @Test("Upload Again uploads once, clears the notice, and the other device reads it and is asked nothing")
    func confirm() async throws {
        let devices = try await Self.devices()
        await devices.store.reset()
        let model = DevicesModel(context: ContextProbe().context(devices.first.session))
        await model.syncNow()
        await model.askToUploadAgain()
        let question = try #require(model.reuploadQuestion)
        #expect(await model.confirmUpload(question))
        #expect(model.reuploadQuestion == nil && !model.storageNeedsUpload && model.errorMessage == nil)
        #expect(model.notice?.contains("uploaded what it holds") == true)
        #expect(await devices.store.startsAgain == 1)

        let other = DevicesModel(context: ContextProbe().context(devices.second.session))
        await other.syncNow()
        #expect(!other.storageNeedsUpload && other.errorMessage == nil)
        #expect(Set(try await devices.second.session.items().items.map(\.title)) == ["Bank", "Post", "Payroll"])
    }

    /// Review finding SR28: any vault left waiting for an unlock kept the success notice away, and a shared vault
    /// whose current key has not arrived is reported that way at every sync, so a complete upload was never told as
    /// one. Only the vaults the upload was for are asked; an unfinished one of those still holds the notice back.
    @Test("the success notice asks only after the vaults the upload was for, never a shared one waiting for its key")
    func successAsksOnlyTheUploadedVaults() {
        let own = ReuploadPlan.Vault(id: UUID(), name: "Personal", isPersonal: true, isDeleted: false, itemCount: 2)
        let shared = ReuploadPlan.Vault(id: UUID(), name: "Family", isPersonal: false, isDeleted: false, itemCount: 1)
        let plan = ReuploadPlan(deviceID: UUID(), vaults: [own], sharedVaults: [shared])
        var report = AccountSyncReport()
        var uploaded = SyncReport()
        uploaded.snapshotsWritten = 1
        var waiting = SyncReport()
        waiting.deferredUntilUnlock = true
        report.vaults = [own.id: uploaded, shared.id: waiting]
        #expect(DevicesModel.uploadFinished(report, uploading: plan), "the shared vault was not part of the upload")
        report.vaults[UUID()] = waiting
        #expect(DevicesModel.uploadFinished(report, uploading: plan), "nor is any vault the plan does not name")
        report.vaults[own.id] = waiting
        #expect(!DevicesModel.uploadFinished(report, uploading: plan), "an uploaded vault that did not run")
        var awaiting = SyncReport()
        awaiting.awaitingNewPassword = true
        report.vaults[own.id] = awaiting
        #expect(!DevicesModel.uploadFinished(report, uploading: plan))
        report.vaults[own.id] = uploaded
        report.transportFailure = .unavailable
        #expect(!DevicesModel.uploadFinished(report, uploading: plan), "a transport that stopped")
        report.transportFailure = nil
        var asking = SyncReport()
        asking.storeLacksObjects = true
        report.vaults[own.id] = asking
        #expect(!DevicesModel.uploadFinished(report, uploading: plan), "a vault still asked about")
    }

    @Test("a yes to a question that no longer describes the device uploads nothing and shows the question anew")
    func staleQuestion() async throws {
        let devices = try await Self.devices()
        await devices.store.reset()
        await devices.store.forgetCreates()
        let model = DevicesModel(context: ContextProbe().context(devices.first.session))
        await model.syncNow()
        await model.askToUploadAgain()
        let shown = try #require(model.reuploadQuestion)
        try await devices.first.session.save(
            login(devices.personal, "Saved since", host: "example.org", username: "pat", password: "secret"))
        #expect(!(await model.confirmUpload(shown)))
        #expect(model.errorMessage?.contains("Nothing was uploaded") == true)
        let renewed = try #require(model.reuploadQuestion)
        #expect(renewed != shown && renewed.upload.contains("4 items in 2 vaults"))
        #expect(await devices.store.startsAgain == 0)
        #expect(await devices.store.created.isEmpty)
        #expect(await model.confirmUpload(renewed))
    }

    @Test("a lock takes the question off the screen, and a yes after it uploads nothing")
    func lockDropsTheQuestion() async throws {
        let devices = try await Self.devices()
        await devices.store.reset()
        await devices.store.forgetCreates()
        let locks = await LockSignal.watching(devices.first.session)
        let probe = ContextProbe()
        let model = DevicesModel(
            context: ScreenContext(
                session: devices.first.session, didLock: probe.context(devices.first.session).didLock, locks: locks))
        await model.syncNow()
        await model.askToUploadAgain()
        let question = try #require(model.reuploadQuestion)
        await devices.first.session.lock()
        for _ in 0..<1000 where model.reuploadQuestion != nil { await Task.yield() }
        #expect(model.reuploadQuestion == nil)
        #expect(!(await model.confirmUpload(question)))
        #expect(model.errorMessage?.contains("locked") == true && probe.locks == 1)
        #expect(await devices.store.startsAgain == 0)
        #expect(await devices.store.created.isEmpty)
        locks.stop()
    }

    @Test("refusals for vaults that cannot be uploaded are worded, and alone they ask nothing")
    func refusals() {
        var report = AccountSyncReport()
        var shared = SyncReport()
        shared.storeLacksObjects = true
        shared.reuploadRefused = .sharedVault
        var large = SyncReport()
        large.storeLacksObjects = true
        large.reuploadRefused = .tooLarge
        report.vaults = [UUID(): shared]
        var summary = SyncSummary(report)
        #expect(!summary.storageNeedsUpload && summary.notices == [.sharedVaultsNotUploaded(1)])
        #expect(SyncNotice.sharedVaultsNotUploaded(1).text.contains("stay on this device"))
        report.vaults[UUID()] = large
        summary = SyncSummary(report)
        #expect(summary.notices.contains(.vaultsTooLargeToUpload(1)) && !summary.storageNeedsUpload)
        var asking = SyncReport()
        asking.storeLacksObjects = true
        report.vaults[UUID()] = asking
        #expect(SyncSummary(report).storageNeedsUpload)
        #expect(ErrorWording.message(for: VaultError.deviceNotRegistered).contains("not registered"))
    }
}
