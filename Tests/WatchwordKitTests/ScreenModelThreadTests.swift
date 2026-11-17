import Foundation
import Testing
import WatchwordPresentation
import WatchwordTestSupport

@testable import WatchwordKit

/// Records each long step the session runs away from its actor, and whether it ran on the main thread.
final class AwayWorkLog: @unchecked Sendable {
    private let lock = NSLock()
    private var steps: [(AwayWork, Bool)] = []

    func record(_ step: AwayWork) {
        let onMain = Thread.isMainThread
        lock.lock()
        steps.append((step, onMain))
        lock.unlock()
    }

    var entries: [(AwayWork, Bool)] {
        lock.lock()
        defer { lock.unlock() }
        return steps
    }
}

@Suite("Screen models: where the long interchange steps run")
@MainActor
struct ScreenModelThreadTests {
    /// The archive's key derivations (ADR 0008), the password check and the decryption are the longest steps the
    /// screens start: seconds on a phone. Started from the screens' models on the main actor, every one of them runs
    /// in the session's detached work, never on the main thread, which draws the screen and answers the accessibility
    /// queries UI tests make (a timed-out query in the first iOS run raised the question).
    @Test("exporting and restoring an archive from the screen models derive and decrypt off the main thread")
    func archiveStepsRunOffTheMainThread() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        let log = AwayWorkLog()
        await vault.session.setAwayWorkHook { log.record($0) }
        defer { Task { await vault.session.setAwayWorkHook(nil) } }

        let export = ExportModel(context: ScreenContext(session: vault.session))
        await export.load()
        export.kind = .archive
        export.password = TestVault.password
        export.passphrase = "garden shed padlock"
        export.passphraseConfirmation = "garden shed padlock"
        await export.export()
        let archive = try #require(export.archiveBytes, "\(export.errorMessage ?? "")")

        let restore = ImportModel(context: ScreenContext(session: vault.session))
        await restore.load()
        restore.archivePassphrase = "garden shed padlock"
        await restore.readArchive(archive)
        #expect(restore.stage == .review, "\(restore.errorMessage ?? "")")

        let steps = Set(log.entries.map(\.0))
        #expect(steps.isSuperset(of: [.passwordCheck, .archiveKeyDerivation, .archiveParse, .archiveDerivation]))
        #expect(log.entries.allSatisfy { !$0.1 }, "\(log.entries.filter(\.1).map(\.0)) ran on the main thread")
    }
}
