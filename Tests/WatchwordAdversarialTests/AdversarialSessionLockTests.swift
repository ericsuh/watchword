import Foundation
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordKit

/// `lock()` never waits for long work on the session's actor (CLAUDE.md, `VaultSession` invariants), through the
/// public call that does it: an archive preview's key derivation (review finding X1), guarded here at the session
/// rather than only at `awayFromSession`. A7 chooses the file and its cost; A3, holding the unlocked device, or auto-lock,
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

    @Test("a lock while an archive's key is derived takes effect at once, and the preview then fails")
    func lockWinsDuringArchivePreview() async throws {
        for step in [AwayWork.archiveDerivation] {
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
}
