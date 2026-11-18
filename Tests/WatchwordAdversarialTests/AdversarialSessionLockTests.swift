import Foundation
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordKit

/// `lock()` never waits for long work on the session's actor (CLAUDE.md, `VaultSession` invariants), through each
/// public call that does such work: an import file's parse, an archive's parse and key derivation, and the
/// derivations behind an export. A7 chooses the file and its cost; A3, holding the unlocked device, or auto-lock,
/// locks meanwhile. Each test holds the step off the actor (`awayWorkHook`) until the test has locked, so the lock can
/// only have returned if the step was off the actor; the call must then end in `locked`, with nothing staged. With
/// the step back on the actor, the lock waits out the hook's 60-second bound and the test fails. In the suite
/// "interchange through the session".
extension AdversarialSessionInterchangeTests {
    /// Runs `call`, holds it at `step`, locks, and checks that the lock came first and the call ends in `locked`.
    static func lockWins<T: Sendable>(
        at step: AwayWork, in vault: TestVault, _ call: @escaping @Sendable () async throws -> T
    ) async throws {
        let (reached, reaching) = AsyncStream.makeStream(of: Void.self)
        let release = DispatchSemaphore(value: 0)
        let released = Flag()
        await vault.session.setAwayWorkHook { current in
            guard current == step else { return }
            reaching.yield()
            // Bounded, so a regression fails instead of hanging: the lock below never returns while this blocks the
            // actor.
            if release.wait(timeout: .now() + 60) == .success { released.set() }
        }
        let work = Task { try await call() }
        var iterator = reached.makeAsyncIterator()
        _ = await iterator.next()
        await vault.session.lock()
        #expect(await vault.session.keys == nil)
        release.signal()
        await #expect(throws: VaultError.locked) { _ = try await work.value }
        #expect(released.isSet, "lock() returned only after the step had given up waiting")
        #expect(await vault.session.pendingImport == nil)
        await vault.session.setAwayWorkHook(nil)
    }

    static let file = Array(
        """
        Title,URL,Username,Password,Notes,OTPAuth
        Bank,https://bank.example/,wendy,bank-pw,,
        """.utf8)

    @Test("a lock while an import file is parsed takes effect at once, and the preview then fails")
    func lockWinsDuringImportParse() async throws {
        let (vault, personal) = try await Self.vault()
        try await Self.lockWins(at: .importParse, in: vault) {
            try await vault.session.previewImport(Self.file, format: .passwordCSV, into: personal)
        }
    }

    @Test("a lock while an import's entries are compared with the saved items takes effect at once")
    func lockWinsDuringImportReview() async throws {
        let (vault, personal) = try await Self.vault()
        try await vault.session.save(Self.bank(personal))
        try await Self.lockWins(at: .importReview, in: vault) {
            try await vault.session.previewImport(Self.file, format: .passwordCSV, into: personal)
        }
    }

    @Test("a lock while an archive is parsed, or its key derived, takes effect at once, and the preview then fails")
    func lockWinsDuringArchivePreview() async throws {
        for step in [AwayWork.archiveParse, .archiveDerivation] {
            let (vault, personal) = try await Self.vault()
            try await vault.session.save(Self.bank(personal))
            let archive = try await vault.session.exportArchive(
                vaults: [personal], passphrase: Self.passphrase, password: TestVault.password)
            try await Self.lockWins(at: step, in: vault) {
                try await vault.session.previewArchiveImport(
                    archive.bytes, passphrase: Self.passphrase, into: personal)
            }
        }
    }

    @Test("a lock while an export checks the account password, or derives the archive's key, takes effect at once")
    func lockWinsDuringExport() async throws {
        let (vault, personal) = try await Self.vault()
        try await vault.session.save(Self.bank(personal))
        try await Self.lockWins(at: .passwordCheck, in: vault) {
            try await vault.session.exportPlaintext(.onePUX, vaults: [personal], password: TestVault.password)
        }
        for step in [AwayWork.passwordCheck, .archiveKeyDerivation] {
            try await vault.session.unlock(password: TestVault.password)
            try await Self.lockWins(at: step, in: vault) {
                try await vault.session.exportArchive(
                    vaults: [personal], passphrase: Self.passphrase, password: TestVault.password)
            }
        }
    }
}
