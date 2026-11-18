import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordPresentation
import WatchwordTestSupport

/// The Emergency Kit screen and the hiding of revealed secrets (Z84, Z86, Z95).
@Suite("Screen models: Emergency Kit and revealed secrets")
@MainActor
struct EmergencyKitScreenTests {
    func temporaryRoot() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
    }

    /// Settings' kit asks for the account password and the session checks it in the same call (Z86).
    @Test("from Settings the kit needs the account password, which goes once handed over")
    func needsPassword() async throws {
        let vault = TestVault()
        let created = try await vault.createAccount()
        let privacy = ScreenPrivacy()
        let model = EmergencyKitModel(context: ContextProbe().context(vault.session), privacy: privacy)
        #expect(model.needsPassword && !model.showsSecretKey && !model.isOnboarding)
        await model.open()
        #expect(model.errorMessage == "Enter your account password." && model.kit == nil)
        model.password = "not the password"
        await model.open()
        #expect(model.errorMessage == "Incorrect password." && model.kit == nil && model.password.isEmpty)
        model.password = TestVault.password
        await model.open()
        #expect(model.kit == created && model.showsSecretKey && model.password.isEmpty)
        model.close()
        #expect(model.kit == nil, "the kit outside onboarding goes with the screen")
    }

    /// The PDF goes the export's way: written into the swept folder and removed after the mover (Z84).
    @Test("the PDF is staged in the swept folder with the options given, and removed after the save and on lock")
    func stagedPDF() async throws {
        let root = temporaryRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let vault = TestVault()
        let created = try await vault.createAccount()
        let locks = await LockSignal.watching(vault.session)
        defer { locks.stop() }
        let staging = StagingFolder(temporaryDirectory: root)
        let model = EmergencyKitModel(
            context: ScreenContext(session: vault.session, locks: locks), privacy: ScreenPrivacy(), kit: created,
            staging: staging)
        #expect(model.isOnboarding && model.showsSecretKey)
        var given: Data.WritingOptions = []
        let render: (EmergencyKit, URL, Data.WritingOptions) throws -> Void = { kit, url, options in
            given = options
            try Data("%PDF \(kit.accountID)".utf8).write(to: url, options: options)
        }
        let url = try model.stagePDF(options: [.atomic], render: render)
        #expect(url.lastPathComponent == EmergencyKitModel.filename)
        #expect(given.contains(.atomic) && given.contains(.withoutOverwriting))
        #expect(staging.stagedFiles() == [url])
        model.finishSaving()
        #expect(staging.stagedFiles().isEmpty && model.kit == created, "onboarding keeps its kit")
        _ = try model.stagePDF(options: [], render: render)
        await vault.session.lock()
        for _ in 0..<1000 where model.kit != nil { await Task.yield() }
        #expect(model.kit == nil && staging.stagedFiles().isEmpty)
        #expect(EmergencyKitModel.storageWarning.contains("iCloud Drive"))
    }

    /// Z95: whoever sees a recording or a shared screen of the unlocked app. A revealed value is hidden at the next
    /// resign-active or capture, and cannot be revealed while the screen is captured.
    @Test("a revealed secret is hidden when the app resigns active or the screen is captured")
    func concealment() async throws {
        let privacy = ScreenPrivacy()
        var revealed = RevealedSecrets<Int>()
        let first = revealed.reveal(1, under: privacy)
        #expect(first && revealed.isRevealed(1, under: privacy))
        privacy.resignedActive()
        #expect(!revealed.isRevealed(1, under: privacy), "an app switch hides it")
        revealed.toggle(1, under: privacy)
        #expect(revealed.isRevealed(1, under: privacy))
        privacy.captureChanged(true)
        #expect(!revealed.isRevealed(1, under: privacy) && !privacy.mayReveal)
        let whileCaptured = revealed.reveal(2, under: privacy)
        #expect(!whileCaptured && !revealed.isRevealed(2, under: privacy), "nothing is revealed while captured")
        privacy.captureChanged(false)
        #expect(!revealed.isRevealed(1, under: privacy), "the end of a capture reveals nothing again")
        let again = revealed.reveal(1, under: privacy)
        #expect(again)
        privacy.captureChanged(false)
        #expect(revealed.isRevealed(1, under: privacy), "a repeated report of no capture hides nothing")
        privacy.locked()
        #expect(!revealed.isRevealed(1, under: privacy))

        let vault = TestVault()
        let kit = try await vault.createAccount()
        let model = EmergencyKitModel(context: ContextProbe().context(vault.session), privacy: privacy, kit: kit)
        #expect(model.showsSecretKey && model.hiddenReason == nil)
        privacy.resignedActive()
        #expect(!model.showsSecretKey && model.hiddenReason?.contains("background") == true)
        model.revealSecretKey()
        #expect(model.showsSecretKey)
        privacy.captureChanged(true)
        model.revealSecretKey()
        #expect(!model.showsSecretKey && model.hiddenReason?.contains("recorded") == true)
    }
}
