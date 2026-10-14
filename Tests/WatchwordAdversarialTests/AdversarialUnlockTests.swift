#if canImport(CryptoKit) && canImport(CommonCrypto)
    import Foundation
    import SecureMemory
    import Testing
    import WatchwordCrypto
    import WatchwordEnvelope
    import WatchwordModel
    import WatchwordStore
    import WatchwordTestSupport

    @testable import WatchwordKit

    /// Milestone 2 adversarial obligations for unlock (docs/04-test-plan.md §6.2).
    ///
    /// Threat model for this suite, from docs/02-architecture.md §2:
    /// - **A3, a thief holding the unlocked device while the app is locked.** Has the app, the screen and the device
    ///   passcode prompt, but not the person's face or finger and not the account password. Must not reach vault
    ///   contents. Quick unlock is the attack surface: anything that unlocks on a *decision* rather than on key material
    ///   the OS released after biometrics is a bypass.
    /// - **A buggy or compromised biometric/Keychain adapter.** Reports success, cancels, or hands back the wrong bytes.
    ///   Must fail closed: the only thing that unlocks is a key chain (LUK → AUK → keyset) that verifies at each link.
    /// - **Time and lifecycle.** Policy expiry (F5.4) and auto-lock (F5.5) must hold even when events race or the clock
    ///   is wound back; a lock must actually zeroise keys, and must win against an unlock already in flight.
    @Suite("Adversarial: unlock and quick unlock", .tags(.adversarial))
    struct AdversarialUnlockTests {
        static func enrolled() async throws -> (TestVault, EmergencyKit) {
            let vault = TestVault()
            let kit = try await vault.createAccount()
            try await vault.session.enableQuickUnlock()
            await vault.session.lock()
            return (vault, kit)
        }

        // MARK: Boolean bypass

        /// Threat: the "boolean bypass" — a biometric layer that says yes without the Keychain releasing the Local Unlock
        /// Key (a hooked LAContext, a buggy adapter, a jailbreak tweak returning success). Here the gate reports an
        /// unchanged enrolment and the policy allows quick unlock, but the Keychain refuses in every way it can. None of
        /// them may unlock, and no key material may appear in the session.
        @Test(
            "a gate that says yes is not enough: without the Keychain releasing the key, nothing unlocks",
            arguments: [FakeKeychain.BiometricOutcome.fail, .cancel, .invalidated])
        func gateAloneNeverUnlocks(_ outcome: FakeKeychain.BiometricOutcome) async throws {
            let (vault, _) = try await Self.enrolled()
            #expect(try await vault.session.status().quickUnlock == .allowed)
            await vault.keychain.script(outcome)
            await #expect(throws: (any Error).self) { try await vault.session.quickUnlock() }
            #expect(try await vault.session.state() == .locked)
            #expect(await vault.session.keys == nil)
        }

        /// Threat: a Keychain (or an attacker able to substitute the item) that releases bytes other than the enrolled
        /// Local Unlock Key — random bytes, all zeros, or a key from a previous enrolment. The AEAD on the wrapped AUK
        /// must reject them, the failure must look like any other authentication failure, and the enrolment must be
        /// destroyed so the same trick cannot be retried.
        @Test(
            "bytes other than the enrolled Local Unlock Key fail authentication and destroy the enrolment",
            arguments: [
                [UInt8](repeating: 0, count: 32), [UInt8](repeating: 0xA5, count: 32), [UInt8](repeating: 1, count: 31),
            ])
        func wrongKeyMaterial(_ bytes: [UInt8]) async throws {
            let (vault, kit) = try await Self.enrolled()
            await vault.keychain.script(.releaseBytes(bytes))
            await #expect(throws: (any Error).self) { try await vault.session.quickUnlock() }
            #expect(try await vault.session.state() == .locked)
            #expect(!(await vault.keychain.contains(.quickUnlockKey(accountID: kit.accountID))))
            #expect(!(await vault.keychain.contains(.quickUnlockState(accountID: kit.accountID))))
            await #expect(throws: VaultError.quickUnlockRefused(.notEnabled)) { try await vault.session.quickUnlock() }
        }

        /// Threat: A3 guessing at the biometric sensor (or a look-alike face). After the configured number of failures
        /// the Local Unlock Key is deleted, not merely ignored, so even a later policy bug cannot revive it; only the
        /// password brings quick unlock back (F5.4).
        @Test("after three failed biometric attempts the key is destroyed and the password is required")
        func failureLimit() async throws {
            let (vault, kit) = try await Self.enrolled()
            await vault.keychain.script(.fail, .fail, .fail)
            for _ in 0..<3 {
                await #expect(throws: VaultError.biometricAuthenticationFailed) {
                    try await vault.session.quickUnlock()
                }
            }
            #expect(!(await vault.keychain.contains(.quickUnlockKey(accountID: kit.accountID))))
            await #expect(throws: VaultError.quickUnlockRefused(.tooManyFailedAttempts)) {
                try await vault.session.quickUnlock()
            }
            #expect(await vault.keychain.biometricPrompts == 3, "no prompt is shown once the limit is reached")
            try await vault.session.unlock(password: TestVault.password)
            await vault.session.lock()
            try await vault.session.quickUnlock()
        }

        // MARK: Expiry (F5.4)

        /// Threat: an enrolment outliving the conditions it was granted under. Each F5.4 trigger — interval expiry, an
        /// app update, a biometric re-enrolment (someone adds their own face), a clock wound back to stay inside the
        /// interval — must refuse *before* any biometric prompt, and must destroy the Local Unlock Key.
        @Test("each expiry reason refuses before prompting and destroys the key")
        func expiryReasons() async throws {
            let cases: [(String, (TestVault) async -> TestVault, QuickUnlockRefusal)] = [
                (
                    "interval",
                    { vault in
                        await vault.clock.advance(by: 14 * 86_400)
                        return vault
                    }, .passwordIntervalExpired
                ),
                ("update", { vault in vault.relaunched(appVersion: "2.0 (1)") }, .appUpdated),
                (
                    "re-enrolment",
                    { vault in
                        await vault.biometrics.set(.enrolled(domainState: [9, 9, 9]))
                        return vault
                    }, .enrolmentChanged
                ),
                (
                    "biometrics off",
                    { vault in
                        await vault.biometrics.set(.unavailable)
                        return vault
                    }, .biometryUnavailable
                ),
                (
                    "clock back",
                    { vault in
                        await vault.clock.advance(by: -60)
                        return vault
                    }, .clockMovedBackwards
                ),
            ]
            for (name, change, reason) in cases {
                let (vault, kit) = try await Self.enrolled()
                let changed = await change(vault)
                await #expect(throws: VaultError.quickUnlockRefused(reason), "\(name)") {
                    try await changed.session.quickUnlock()
                }
                #expect(await vault.keychain.biometricPrompts == 0, "\(name): no prompt")
                #expect(!(await vault.keychain.contains(.quickUnlockKey(accountID: kit.accountID))), "\(name)")
                #expect(try await changed.session.state() == .locked, "\(name)")
            }
        }

        /// Threat: the OS invalidated the item after a biometric enrolment change (`biometryCurrentSet`) but the policy
        /// inputs have not caught up yet. A missing key is final: quick unlock is forgotten, not retried.
        @Test("an item the OS invalidated forgets quick unlock entirely")
        func invalidatedByOS() async throws {
            let (vault, kit) = try await Self.enrolled()
            await vault.keychain.invalidateBiometricItems()
            await #expect(throws: VaultError.quickUnlockRefused(.enrolmentChanged)) {
                try await vault.session.quickUnlock()
            }
            #expect(!(await vault.keychain.contains(.quickUnlockState(accountID: kit.accountID))))
        }

        /// Threat: replay of a quick-unlock enrolment from before a password change — someone who learned the old
        /// password restores the Keychain items they captured earlier (a backup of the Keychain item, or a test of
        /// whether "change password" really revokes anything). Even with the generation counter edited to match, the
        /// old wrapped AUK is bound to the old generation in its authenticated data and names an AUK the account no
        /// longer uses, so nothing unlocks.
        @Test("a quick-unlock enrolment from before a password change cannot be replayed, even with the counter edited")
        func replayAfterPasswordChange() async throws {
            let vault = TestVault()
            let kit = try await vault.createAccount()
            try await vault.session.enableQuickUnlock()
            let oldKey = try #require(await vault.keychain.raw(.quickUnlockKey(accountID: kit.accountID)))
            let oldStateBytes = try #require(await vault.keychain.raw(.quickUnlockState(accountID: kit.accountID)))
            try await vault.session.changePassword(current: TestVault.password, new: "a different long password")
            await vault.session.lock()

            var oldState = try JSONDecoder().decode(QuickUnlockState.self, from: Data(oldStateBytes))
            #expect(oldState.credentialGeneration == 0)
            for generation: UInt64 in [0, 1] {
                oldState.credentialGeneration = generation
                await vault.keychain.overwrite(.quickUnlockKey(accountID: kit.accountID), with: oldKey)
                await vault.keychain.overwrite(
                    .quickUnlockState(accountID: kit.accountID), with: Array(try JSONEncoder().encode(oldState)))
                await #expect(throws: (any Error).self, "generation \(generation)") {
                    try await vault.session.quickUnlock()
                }
                #expect(try await vault.session.state() == .locked)
            }
        }

        // MARK: Password path

        /// Threat: an oracle. A thief (A3) or a sync-store attacker (A1) who can tell "wrong password" from "wrong Secret
        /// Key" from "tampered header" learns which secret to attack. All three must surface as the same error.
        @Test("a wrong password and a wrong Secret Key are indistinguishable")
        func noOracle() async throws {
            let vault = TestVault()
            let kit = try await vault.createAccount()
            await vault.session.lock()
            await #expect(throws: CryptoError.authenticationFailed) {
                try await vault.session.unlock(password: "the wrong password")
            }
            var generator = SeededGenerator(seed: 99)
            let otherKey = SecretKey.generate(using: &generator)
            await vault.keychain.overwrite(.secretKey(accountID: kit.accountID), with: otherKey.bytes.unprotectedCopy())
            await #expect(throws: CryptoError.authenticationFailed) {
                try await vault.session.unlock(password: TestVault.password)
            }
        }

        /// Threat: phishing the new-device flow — someone hands the person an Emergency Kit setup code for an account
        /// the attacker controls. It must be rejected by account ID before any derivation, not adopted.
        @Test("a setup code for another account is refused")
        func foreignSetupCode() async throws {
            let vault = TestVault()
            let kit = try await vault.createAccount()
            await vault.session.lock()
            let foreign = EmergencyKit(accountID: UUID(), secretKey: kit.secretKey, createdAt: kit.createdAt)
            await #expect(throws: VaultError.secretKeyForAnotherAccount) {
                try await vault.session.unlock(password: TestVault.password, secretKey: foreign.setupCode)
            }
        }

        // MARK: Lock and zeroisation (F5.5)

        /// Threat: A3 picking up a phone that was put down unlocked. Backgrounding past the grace period, idling past the
        /// timeout and sleeping must each lock — and locking must zeroise every key buffer, not just drop a reference
        /// (SEC4).
        @Test(
            "auto-lock events lock and zeroise every key",
            arguments: [AutoLockEvent.tick, .systemSleep, .enteringForeground])
        func autoLockZeroises(_ event: AutoLockEvent) async throws {
            let vault = TestVault()
            try await vault.createAccount()
            let keys = try #require(await vault.session.keys)
            await vault.clock.advance(by: 11 * 60)
            let reason = await vault.session.handle(event)
            #expect(reason != nil)
            #expect(try await vault.session.state() == .locked)
            #expect(keys.isZeroised)
        }

        /// Threat: A3 taking a phone the moment it is put down. With no grace period (the iOS default), moving to the
        /// background locks at once, before anyone can bring the app back.
        @Test("backgrounding with no grace period locks immediately")
        func backgroundLocks() async throws {
            let vault = TestVault()
            try await vault.createAccount()
            let keys = try #require(await vault.session.keys)
            #expect(await vault.session.handle(.enteredBackground) == .backgrounded)
            #expect(keys.isZeroised)
        }

        /// Threat: the "lock" button (or a screen lock) pressed while an unlock is still deriving keys. Actors are
        /// re-entrant, so without care the unlock would finish *after* the lock and leave the vault open. The lock must
        /// win and the derived keys must be zeroised.
        @Test("a lock that lands during an unlock wins")
        func lockDuringUnlock() async throws {
            let gated = GatedRecordStore()
            let vault = TestVault(store: gated)
            try await vault.createAccount()
            await vault.session.lock()
            await gated.holdNextVaultKeyRead()
            let unlock = Task { try await vault.session.unlock(password: TestVault.password) }
            await gated.waitUntilHeld()
            await vault.session.lock()
            await gated.release()
            await #expect(throws: VaultError.lockedDuringUnlock) { try await unlock.value }
            #expect(try await vault.session.state() == .locked)
        }

        /// Threat: the same race on a write. A save waiting on the store when the vault locks must not then seal with a
        /// zeroised key (which would trap, or — without the trap — seal under an all-zero key everyone knows).
        @Test("a lock that lands during a save fails the save cleanly")
        func lockDuringSave() async throws {
            let gated = GatedRecordStore()
            let vault = TestVault(store: gated)
            try await vault.createAccount()
            let vaultID = try #require(await vault.session.personalVaultID)
            await gated.holdNextItemRead()
            let save = Task {
                try await vault.session.save(
                    Item(vaultID: vaultID, title: "x", scopes: [ServiceScope(host: "example.com")], fields: []))
            }
            await gated.waitUntilHeld()
            await vault.session.lock()
            await gated.release()
            await #expect(throws: VaultError.locked) { try await save.value }
            try await vault.session.unlock(password: TestVault.password)
            #expect(try await vault.session.items().items.isEmpty)
        }

        /// Threat: deleting someone's vault from an unlocked-but-unattended device. Account deletion re-checks the
        /// password against the stored header and leaves everything intact when it is wrong.
        @Test("account deletion with the wrong password changes nothing")
        func deletionNeedsPassword() async throws {
            let vault = TestVault()
            let kit = try await vault.createAccount()
            await #expect(throws: CryptoError.authenticationFailed) {
                try await vault.session.deleteAccount(password: "not my password")
            }
            #expect(try await vault.store.loadAccount() != nil)
            #expect(await vault.keychain.contains(.secretKey(accountID: kit.accountID)))
        }
    }

    /// A store that can hold one read until the test releases it, to land a `lock()` inside an in-flight operation.
    actor GatedRecordStore: RecordStore {
        private let inner = InMemoryRecordStore()
        private var holdKind: EnvelopeKind?
        private var held: CheckedContinuation<Void, Never>?
        private var heldWaiters: [CheckedContinuation<Void, Never>] = []
        private var isHolding = false

        func holdNextVaultKeyRead() { holdKind = .vaultKeyWrap }
        func holdNextItemRead() { holdKind = .item }

        func waitUntilHeld() async {
            if isHolding { return }
            await withCheckedContinuation { heldWaiters.append($0) }
        }

        func release() {
            held?.resume()
            held = nil
        }

        private func gate(_ kind: EnvelopeKind) async {
            guard holdKind == kind else { return }
            holdKind = nil
            isHolding = true
            for waiter in heldWaiters { waiter.resume() }
            heldWaiters = []
            await withCheckedContinuation { held = $0 }
            isHolding = false
        }

        func loadAccount() async throws -> AccountRecord? { try await inner.loadAccount() }

        func record(_ key: RecordKey) async throws -> StoredRecord? {
            await gate(key.kind)
            return try await inner.record(key)
        }

        func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
            await gate(kind)
            return try await inner.records(in: vaultID, kind: kind)
        }

        func commit(_ change: StoreChange) async throws { try await inner.commit(change) }
        func eraseAll() async throws { try await inner.eraseAll() }
    }
#endif
