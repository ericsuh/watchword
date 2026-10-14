#if canImport(CryptoKit) && canImport(CommonCrypto)
    import Foundation
    import SecureMemory
    import WatchwordCrypto
    import WatchwordEnvelope
    import WatchwordMatching
    import WatchwordModel
    import WatchwordStore

    /// How a new account (or a password change) chooses its PBKDF2 parameters.
    public enum KDFStrategy: Sendable, Hashable {
        /// Time a probe on this device and scale to ≥300 ms, never below the floor (ADR 0003).
        case calibrate
        /// Fixed parameters, still validated against the floor and ceiling. Tests and UI-test launches use
        /// `KDFParameters.baseline`.
        case fixed(KDFParameters)
    }

    public struct VaultConfiguration: Sendable {
        public static let minimumPasswordLength = 10
        /// PRD F1.4.
        public static let historyRetention: TimeInterval = 90 * 24 * 60 * 60
        /// Bounds an item's payload however often it is edited inside the retention window (SEC9). The newest entry,
        /// which holds the previous password, is always kept.
        public static let maximumHistoryEntries = 100
        /// PRD F1.5.
        public static let trashRetention: TimeInterval = 30 * 24 * 60 * 60

        public var appVersion: String
        public var kdf: KDFStrategy
        public var quickUnlock: QuickUnlockSettings
        public var autoLock: AutoLockSettings

        public init(
            appVersion: String,
            kdf: KDFStrategy = .calibrate,
            quickUnlock: QuickUnlockSettings = .standard,
            autoLock: AutoLockSettings = .platformDefault
        ) {
            self.appVersion = appVersion
            self.kdf = kdf
            self.quickUnlock = quickUnlock
            self.autoLock = autoLock
        }
    }

    public enum VaultState: Sendable, Hashable {
        case noAccount
        case locked
        case unlocked
    }

    public struct VaultStatus: Sendable, Hashable {
        public var state: VaultState
        public var accountID: UUID?
        public var emergencyKitConfirmed: Bool
        /// Whether quick unlock is enrolled, and what the policy would say about using it now. `nil` when not enrolled.
        public var quickUnlock: UnlockDecision?
    }

    /// The items of every unlocked vault, and the records that could not be opened. One bad record is reported rather
    /// than hiding the rest of the vault, and is never repaired or overwritten silently.
    public struct ItemListing: Sendable, Hashable {
        public var items: [Item]
        public var unreadable: [UUID]
    }

    /// Key material held while unlocked. Immutable once built; `zeroise()` on lock destroys every buffer
    /// (PRD SEC4, F5.5).
    final class UnlockedKeys: Sendable {
        let accountUnlockKey: EncryptionKey
        let keyset: Keyset
        /// By key ID.
        let vaultKeys: [UUID: VaultKey]

        init(accountUnlockKey: EncryptionKey, keyset: Keyset, vaultKeys: [UUID: VaultKey]) {
            self.accountUnlockKey = accountUnlockKey
            self.keyset = keyset
            self.vaultKeys = vaultKeys
        }

        func zeroise() {
            accountUnlockKey.zeroise()
            keyset.zeroise()
            for key in vaultKeys.values {
                key.zeroise()
            }
        }

        var isZeroised: Bool {
            accountUnlockKey.isZeroised && keyset.isZeroised && vaultKeys.values.allSatisfy(\.key.isZeroised)
        }
    }

    /// The façade every UI target uses, and the one the scenario tests drive (docs/02-architecture.md §10, §15;
    /// docs/04-test-plan.md §2).
    ///
    /// State machine: `noAccount` → `createAccount` → `unlocked`; `locked` → `unlock(password:)` or `quickUnlock()` →
    /// `unlocked`; `unlocked` → `lock()` (or an auto-lock event) → `locked`, which zeroises every key.
    ///
    /// It is an actor, and actors are re-entrant across `await`, so every operation that suspends re-checks the lock
    /// epoch before touching key material again: a `lock()` that lands while an unlock or a save is waiting on the
    /// store or the Keychain wins, and the in-flight operation fails with `locked` rather than resurrecting keys or
    /// reading a zeroised buffer.
    public actor VaultSession {
        let store: any RecordStore
        let keychain: any KeychainStore
        let biometrics: any BiometricGate
        let clock: any WallClock
        let configuration: VaultConfiguration
        private var random: InjectedGenerator

        var keys: UnlockedKeys?
        private var account: AccountRecord?
        private var lockEpoch: UInt64 = 0
        private var lastActivity: Date?
        private var backgroundedAt: Date?
        private var highestVersionSeen: UInt64 = 0

        /// Production passes `SystemRandomNumberGenerator()`; only tests inject anything else (CLAUDE.md).
        public init(
            store: any RecordStore,
            keychain: any KeychainStore,
            biometrics: any BiometricGate,
            clock: any WallClock = SystemWallClock(),
            configuration: VaultConfiguration,
            random: any RandomNumberGenerator & Sendable = SystemRandomNumberGenerator()
        ) {
            self.store = store
            self.keychain = keychain
            self.biometrics = biometrics
            self.clock = clock
            self.configuration = configuration
            self.random = InjectedGenerator(base: random)
        }

        // MARK: - State

        public func state() async throws -> VaultState {
            if keys != nil { return .unlocked }
            return try await loadAccount() == nil ? .noAccount : .locked
        }

        public func status() async throws -> VaultStatus {
            let state = try await state()
            guard let account = try await loadAccount() else {
                return VaultStatus(state: state, accountID: nil, emergencyKitConfirmed: false, quickUnlock: nil)
            }
            var decision: UnlockDecision?
            if let quickState = try await loadQuickUnlockState(accountID: account.accountID) {
                decision = UnlockPolicy.evaluate(
                    now: await clock.now(),
                    state: quickState,
                    currentAppVersion: configuration.appVersion,
                    currentCredentialGeneration: account.credentialGeneration,
                    enrolment: await biometrics.enrolment(),
                    settings: configuration.quickUnlock
                )
            }
            return VaultStatus(
                state: state,
                accountID: account.accountID,
                emergencyKitConfirmed: account.emergencyKitConfirmedAt != nil,
                quickUnlock: decision
            )
        }

        private func loadAccount() async throws -> AccountRecord? {
            if let account { return account }
            account = try await store.loadAccount()
            return account
        }

        private func requireKeys(since epoch: UInt64? = nil) throws -> UnlockedKeys {
            if let epoch, epoch != lockEpoch { throw VaultError.locked }
            guard let keys else { throw VaultError.locked }
            return keys
        }

        // MARK: - Account creation (PRD F5.1)

        /// Creates the account on this device and leaves the vault unlocked. The returned kit must be shown and its
        /// saving confirmed (`confirmEmergencyKitSaved()`).
        public func createAccount(password: String) async throws -> EmergencyKit {
            guard password.count >= VaultConfiguration.minimumPasswordLength else {
                throw VaultError.passwordTooShort(minimum: VaultConfiguration.minimumPasswordLength)
            }
            guard try await loadAccount() == nil else { throw VaultError.accountAlreadyExists }
            let now = await clock.now()
            let epoch = lockEpoch

            let accountID = UUID.random(using: &random)
            let secretKey = SecretKey.generate(using: &random)
            defer { secretKey.zeroise() }
            let kdf = try kdfParameters()
            let salt = randomBytes(kdf.saltLength)
            let unlockKey = try TwoSecretKeyDerivation.accountUnlockKey(
                password: password, secretKey: secretKey, accountID: accountID, parameters: kdf, salt: salt,
                keyID: UUID.random(using: &random))
            let keyset = Keyset.generate(accountID: accountID, using: &random)
            let personalVaultID = UUID.random(using: &random)
            let vaultKey = VaultKey.generate(vaultID: personalVaultID, using: &random)
            let newKeys = UnlockedKeys(
                accountUnlockKey: unlockKey, keyset: keyset, vaultKeys: [vaultKey.key.keyID: vaultKey])

            let record = AccountRecord(
                accountID: accountID,
                deviceID: UUID.random(using: &random),
                personalVaultID: personalVaultID,
                personalVaultKeyID: vaultKey.key.keyID,
                kdf: kdf,
                salt: salt,
                unlockKeyID: unlockKey.keyID,
                wrappedKeyset: try keyset.wrap(with: unlockKey, recordVersion: 0, using: &random),
                keysetVersion: 0,
                credentialGeneration: 0,
                createdAt: now
            )
            let vaultKeyRecord = try vaultKeyRecord(vaultKey, keyset: keyset, deviceID: record.deviceID)
            let kit = EmergencyKit(accountID: accountID, secretKey: secretKey.formatted, createdAt: now)

            // Keychain first: if the store commit then fails, an orphaned Secret Key is harmless and is replaced by
            // the next attempt. The other order could leave an account whose Secret Key exists nowhere, before the
            // person has even seen the Emergency Kit.
            try await keychain.store(
                secretKey.bytes.extracting(0..<SecretKey.byteCount), for: .secretKey(accountID: accountID))
            do {
                try await store.commit(StoreChange(account: .create(record), upserts: [vaultKeyRecord]))
            } catch {
                try? await keychain.delete(.secretKey(accountID: accountID))
                newKeys.zeroise()
                throw error
            }
            account = record
            guard epoch == lockEpoch, keys == nil else {
                newKeys.zeroise()
                throw VaultError.lockedDuringUnlock
            }
            install(newKeys, at: now)
            return kit
        }

        /// Records that the person confirmed saving the Emergency Kit (PRD F5.1).
        public func confirmEmergencyKitSaved() async throws {
            _ = try requireKeys()
            guard var record = try await loadAccount() else { throw VaultError.noAccount }
            guard record.emergencyKitConfirmedAt == nil else { return }
            let expected = record.keysetVersion
            record.emergencyKitConfirmedAt = await clock.now()
            try await store.commit(StoreChange(account: .update(record, expectedKeysetVersion: expected)))
            account = record
        }

        /// The Emergency Kit again, for printing a replacement. Requires the vault to be unlocked.
        public func emergencyKit() async throws -> EmergencyKit {
            let epoch = lockEpoch
            _ = try requireKeys()
            guard let record = try await loadAccount() else { throw VaultError.noAccount }
            guard let bytes = try await keychain.read(.secretKey(accountID: record.accountID), prompt: "") else {
                throw VaultError.secretKeyMissing
            }
            _ = try requireKeys(since: epoch)
            let secretKey = try SecretKey(bytes: bytes)
            defer { secretKey.zeroise() }
            return EmergencyKit(
                accountID: record.accountID, secretKey: secretKey.formatted, createdAt: record.createdAt)
        }

        // MARK: - Unlock (PRD F5.2)

        /// Unlocks with the account password and the Secret Key held in this device's Keychain.
        public func unlock(password: String) async throws {
            try await unlock(password: password, enteredSecretKey: nil)
        }

        /// Unlocks with the password and a Secret Key typed or scanned from the Emergency Kit, for a device whose
        /// Keychain does not hold it (a store restored from backup; Keychain items are device-only, ADR 0004). On
        /// success the Secret Key is saved to this device's Keychain.
        public func unlock(password: String, secretKey text: String) async throws {
            var keyText = text
            if let setup = EmergencyKit.parseSetupCode(text) {
                guard try await loadAccount()?.accountID == setup.accountID else {
                    throw VaultError.secretKeyForAnotherAccount
                }
                keyText = setup.secretKey
            }
            let secretKey = try SecretKey(parsing: keyText)
            defer { secretKey.zeroise() }
            try await unlock(password: password, enteredSecretKey: secretKey)
        }

        private func unlock(password: String, enteredSecretKey: SecretKey?) async throws {
            guard keys == nil else { throw VaultError.alreadyUnlocked }
            let epoch = lockEpoch
            guard let record = try await loadAccount() else { throw VaultError.noAccount }

            let secretKey: SecretKey
            if let enteredSecretKey {
                secretKey = try SecretKey(bytes: enteredSecretKey.bytes.extracting(0..<SecretKey.byteCount))
            } else {
                guard let bytes = try await keychain.read(.secretKey(accountID: record.accountID), prompt: "") else {
                    throw VaultError.secretKeyMissing
                }
                secretKey = try SecretKey(bytes: bytes)
            }
            defer { secretKey.zeroise() }

            let unlockKey = try deriveUnlockKey(password: password, secretKey: secretKey, account: record)
            let newKeys: UnlockedKeys
            do {
                newKeys = try await openKeys(unlockKey: unlockKey, account: record)
            } catch {
                unlockKey.zeroise()
                throw error
            }
            if enteredSecretKey != nil {
                try await keychain.store(
                    secretKey.bytes.extracting(0..<SecretKey.byteCount), for: .secretKey(accountID: record.accountID))
            }
            let now = await clock.now()
            guard epoch == lockEpoch, keys == nil else {
                newKeys.zeroise()
                throw VaultError.lockedDuringUnlock
            }
            install(newKeys, at: now)
            // Best effort: a Keychain hiccup here must not turn a correct password into a failed unlock.
            try? await refreshQuickUnlock(after: now, account: record)
            try? await purgeExpiredTrash()
        }

        /// Quick unlock (PRD F5.3, F5.4): the policy must allow it, then the Keychain must release the Local Unlock Key
        /// after biometric authentication, that key must open the wrapped AUK, and the AUK must open the keyset. No
        /// step is a boolean; each is a key that only the previous step can produce.
        public func quickUnlock(prompt: String = "Unlock Watchword") async throws {
            guard keys == nil else { throw VaultError.alreadyUnlocked }
            let epoch = lockEpoch
            guard let record = try await loadAccount() else { throw VaultError.noAccount }
            let accountID = record.accountID
            guard var state = try await loadQuickUnlockState(accountID: accountID) else {
                throw VaultError.quickUnlockRefused(.notEnabled)
            }
            let now = await clock.now()
            let decision = UnlockPolicy.evaluate(
                now: now,
                state: state,
                currentAppVersion: configuration.appVersion,
                currentCredentialGeneration: record.credentialGeneration,
                enrolment: await biometrics.enrolment(),
                settings: configuration.quickUnlock
            )
            if case .requirePassword(let reason) = decision {
                // Destroy the key rather than merely refusing to use it, so a later bug in this function cannot
                // revive an expired enrolment. Re-enrolment changes are final (F5.3); the others re-enrol on the next
                // password unlock.
                try await suspendQuickUnlock(accountID: accountID, forget: reason == .enrolmentChanged)
                throw VaultError.quickUnlockRefused(reason)
            }

            let releasedKey: SecureBytes?
            do {
                releasedKey = try await keychain.read(.quickUnlockKey(accountID: accountID), prompt: prompt)
            } catch KeychainError.authenticationFailed {
                state.failedAttempts += 1
                try await saveQuickUnlockState(state, accountID: accountID)
                if state.failedAttempts >= configuration.quickUnlock.maximumFailedAttempts {
                    try await suspendQuickUnlock(accountID: accountID, forget: false)
                }
                throw VaultError.biometricAuthenticationFailed
            }
            guard let releasedKey else {
                // Gone: the OS invalidated it after a biometric enrolment change, or it was deleted.
                try await suspendQuickUnlock(accountID: accountID, forget: true)
                throw VaultError.quickUnlockRefused(.enrolmentChanged)
            }

            let newKeys: UnlockedKeys
            do {
                let localKey = try EncryptionKey(keyID: state.unlockKeyID, material: releasedKey)
                defer { localKey.zeroise() }
                let unlockKeyMaterial = try RecordCipher.open(
                    Array(state.wrappedAccountUnlockKey),
                    context: Self.quickUnlockContext(
                        accountID: accountID, state: state, generation: record.credentialGeneration),
                    key: localKey,
                    maximumLength: 1024
                )
                let unlockKey = try EncryptionKey(keyID: state.accountUnlockKeyID, material: unlockKeyMaterial)
                guard unlockKey.keyID == record.unlockKeyID else {
                    unlockKey.zeroise()
                    throw VaultError.quickUnlockRefused(.credentialsChanged)
                }
                do {
                    newKeys = try await openKeys(unlockKey: unlockKey, account: record)
                } catch {
                    unlockKey.zeroise()
                    throw error
                }
            } catch {
                // Whatever the Keychain released did not lead to the keyset: never retry with it.
                try? await suspendQuickUnlock(accountID: accountID, forget: true)
                throw error
            }
            guard epoch == lockEpoch, keys == nil else {
                newKeys.zeroise()
                throw VaultError.lockedDuringUnlock
            }
            install(newKeys, at: now)
            state.failedAttempts = 0
            try? await saveQuickUnlockState(state, accountID: accountID)
        }

        /// Derives AUK. `KDFParameters.validate()` runs inside, before any work (SEC5, SEC9).
        private func deriveUnlockKey(password: String, secretKey: SecretKey, account: AccountRecord) throws
            -> EncryptionKey
        {
            try TwoSecretKeyDerivation.accountUnlockKey(
                password: password,
                secretKey: secretKey,
                accountID: account.accountID,
                parameters: account.kdf,
                salt: account.salt,
                keyID: account.unlockKeyID
            )
        }

        /// Unwraps the keyset under `unlockKey`, then every vault key wrap. Identities come from the storage location
        /// (the account header and each row), never from the wraps (§4).
        private func openKeys(unlockKey: EncryptionKey, account: AccountRecord) async throws -> UnlockedKeys {
            let keyset = try Keyset.unwrap(
                account.wrappedKeyset, accountID: account.accountID, with: unlockKey,
                recordVersion: account.keysetVersion)
            do {
                let rows = try await store.records(in: account.personalVaultID, kind: .vaultKeyWrap)
                var vaultKeys: [UUID: VaultKey] = [:]
                for row in rows {
                    let vaultKey = try VaultKey.unwrap(
                        row.envelope, vaultID: row.vaultID, keyID: row.recordID, with: keyset)
                    vaultKeys[row.recordID] = vaultKey
                }
                guard vaultKeys[account.personalVaultKeyID] != nil else {
                    for key in vaultKeys.values { key.zeroise() }
                    throw VaultError.vaultKeyMissing(vaultID: account.personalVaultID)
                }
                return UnlockedKeys(accountUnlockKey: unlockKey, keyset: keyset, vaultKeys: vaultKeys)
            } catch {
                keyset.zeroise()
                throw error
            }
        }

        private func install(_ newKeys: UnlockedKeys, at now: Date) {
            keys = newKeys
            lastActivity = now
            backgroundedAt = nil
        }

        // MARK: - Lock (PRD F5.5)

        /// Zeroises every key. Safe to call at any time, including while another operation is in flight: that
        /// operation then fails with `locked` or `lockedDuringUnlock`.
        public func lock() {
            lockEpoch &+= 1
            keys?.zeroise()
            keys = nil
            backgroundedAt = nil
        }

        /// Call on user interaction; resets the idle timer.
        public func recordActivity() async {
            lastActivity = await clock.now()
        }

        /// Applies the auto-lock policy to `event`. Returns why it locked, if it did.
        @discardableResult
        public func handle(_ event: AutoLockEvent) async -> LockReason? {
            let now = await clock.now()
            guard keys != nil, let lastActivity else { return nil }
            let reason = AutoLockPolicy.decide(
                event: event, now: now, lastActivity: lastActivity, backgroundedAt: backgroundedAt,
                settings: configuration.autoLock)
            switch event {
            case .enteredBackground: backgroundedAt = now
            case .enteringForeground: backgroundedAt = nil
            case .tick, .systemSleep: break
            }
            if reason != nil {
                lock()
            }
            return reason
        }

        // MARK: - Quick unlock enrolment

        /// Enrols quick unlock: a fresh Local Unlock Key, bound by the OS to the current biometric enrolment, wraps the
        /// AUK. Requires the vault to be unlocked.
        public func enableQuickUnlock() async throws {
            _ = try requireKeys()
            guard let record = try await loadAccount() else { throw VaultError.noAccount }
            try await enrolQuickUnlock(account: record, now: await clock.now(), carrying: nil)
        }

        public func disableQuickUnlock() async throws {
            guard let record = try await loadAccount() else { throw VaultError.noAccount }
            try await suspendQuickUnlock(accountID: record.accountID, forget: true)
        }

        private func enrolQuickUnlock(account: AccountRecord, now: Date, carrying previous: QuickUnlockState?)
            async throws
        {
            let epoch = lockEpoch
            guard case .enrolled(let domainState) = await biometrics.enrolment() else {
                throw VaultError.quickUnlockRefused(.biometryUnavailable)
            }
            let keys = try requireKeys(since: epoch)
            let localKey = EncryptionKey.generate(using: &random)
            defer { localKey.zeroise() }
            var state = QuickUnlockState(
                enrolledAt: previous?.enrolledAt ?? now,
                lastPasswordUnlockAt: now,
                failedAttempts: 0,
                appVersion: configuration.appVersion,
                credentialGeneration: account.credentialGeneration,
                biometricDomainState: Data(domainState),
                unlockKeyID: localKey.keyID,
                accountUnlockKeyID: keys.accountUnlockKey.keyID,
                wrappedAccountUnlockKey: Data()
            )
            state.wrappedAccountUnlockKey = Data(
                try RecordCipher.seal(
                    keys.accountUnlockKey.material,
                    context: Self.quickUnlockContext(
                        accountID: account.accountID, state: state, generation: account.credentialGeneration),
                    key: localKey,
                    using: &random
                ))
            try await keychain.store(
                localKey.material.extracting(0..<EncryptionKey.byteCount),
                for: .quickUnlockKey(accountID: account.accountID))
            try await saveQuickUnlockState(state, accountID: account.accountID)
        }

        /// After a password unlock or change: re-enrol with a fresh key if quick unlock was enrolled and the biometric
        /// enrolment is unchanged; forget it if the enrolment changed (F5.3).
        private func refreshQuickUnlock(after now: Date, account: AccountRecord) async throws {
            guard let previous = try await loadQuickUnlockState(accountID: account.accountID) else { return }
            guard case .enrolled(let domainState) = await biometrics.enrolment(),
                Data(domainState) == previous.biometricDomainState
            else {
                try await suspendQuickUnlock(accountID: account.accountID, forget: true)
                return
            }
            try await enrolQuickUnlock(account: account, now: now, carrying: previous)
        }

        /// Deletes the Local Unlock Key; with `forget`, also the state, so quick unlock is off until re-enabled.
        private func suspendQuickUnlock(accountID: UUID, forget: Bool) async throws {
            try await keychain.delete(.quickUnlockKey(accountID: accountID))
            if forget {
                try await keychain.delete(.quickUnlockState(accountID: accountID))
            }
        }

        private func loadQuickUnlockState(accountID: UUID) async throws -> QuickUnlockState? {
            guard let bytes = try await keychain.read(.quickUnlockState(accountID: accountID), prompt: "") else {
                return nil
            }
            defer { bytes.zeroise() }
            // Not secret, and decoded from a device-only Keychain item; a malformed one is treated as absent.
            return try? JSONDecoder().decode(QuickUnlockState.self, from: Data(bytes.unprotectedCopy()))
        }

        private func saveQuickUnlockState(_ state: QuickUnlockState, accountID: UUID) async throws {
            var encoded = Array(try JSONEncoder().encode(state))
            try await keychain.store(SecureBytes(wiping: &encoded), for: .quickUnlockState(accountID: accountID))
        }

        /// The wrapped AUK is an account-level record named by the AUK's key ID, sealed under the Local Unlock Key and
        /// bound to the credential generation, so a wrap from before a password change cannot be presented as current.
        static func quickUnlockContext(accountID: UUID, state: QuickUnlockState, generation: UInt64) -> EnvelopeContext
        {
            EnvelopeContext(
                recordID: state.accountUnlockKeyID,
                vaultID: accountID,
                schemaVersion: 1,
                kind: .accountHeader,
                keyID: state.unlockKeyID,
                recordVersion: generation
            )
        }

        // MARK: - Password change and account deletion (PRD F10.1, F10.3)

        /// Re-wraps the keyset under a new AUK (new salt, new key ID). Quick unlock enrolled before the change stops
        /// working: the credential generation changes and the old wrapped AUK no longer opens the keyset.
        public func changePassword(current: String, new: String) async throws {
            guard new.count >= VaultConfiguration.minimumPasswordLength else {
                throw VaultError.passwordTooShort(minimum: VaultConfiguration.minimumPasswordLength)
            }
            let epoch = lockEpoch
            let oldKeys = try requireKeys()
            guard let record = try await loadAccount() else { throw VaultError.noAccount }
            let secretKey = try await storedSecretKey(accountID: record.accountID)
            defer { secretKey.zeroise() }
            // The current password is re-verified against the stored header, not against anything in memory.
            let verified = try deriveUnlockKey(password: current, secretKey: secretKey, account: record)
            defer { verified.zeroise() }
            try Keyset.unwrap(
                record.wrappedKeyset, accountID: record.accountID, with: verified, recordVersion: record.keysetVersion
            ).zeroise()

            _ = try requireKeys(since: epoch)
            let kdf = try kdfParameters()
            let salt = randomBytes(kdf.saltLength)
            let newUnlockKey = try TwoSecretKeyDerivation.accountUnlockKey(
                password: new, secretKey: secretKey, accountID: record.accountID, parameters: kdf, salt: salt,
                keyID: UUID.random(using: &random))
            var updated = record
            updated.kdf = kdf
            updated.salt = salt
            updated.unlockKeyID = newUnlockKey.keyID
            updated.keysetVersion = record.keysetVersion + 1
            updated.credentialGeneration = record.credentialGeneration + 1
            do {
                let keys = try requireKeys(since: epoch)
                updated.wrappedKeyset = try keys.keyset.wrap(
                    with: newUnlockKey, recordVersion: updated.keysetVersion, using: &random)
                try await store.commit(
                    StoreChange(account: .update(updated, expectedKeysetVersion: record.keysetVersion)))
            } catch {
                newUnlockKey.zeroise()
                throw error
            }
            account = updated
            guard epoch == lockEpoch, keys === oldKeys else {
                newUnlockKey.zeroise()
                throw VaultError.locked
            }
            keys = UnlockedKeys(accountUnlockKey: newUnlockKey, keyset: oldKeys.keyset, vaultKeys: oldKeys.vaultKeys)
            oldKeys.accountUnlockKey.zeroise()
            try? await refreshQuickUnlock(after: await clock.now(), account: updated)
        }

        /// Erases the local store and every Keychain item after checking the password (PRD F10.3, local part).
        public func deleteAccount(password: String) async throws {
            guard let record = try await loadAccount() else { throw VaultError.noAccount }
            let secretKey = try await storedSecretKey(accountID: record.accountID)
            defer { secretKey.zeroise() }
            let verified = try deriveUnlockKey(password: password, secretKey: secretKey, account: record)
            defer { verified.zeroise() }
            try Keyset.unwrap(
                record.wrappedKeyset, accountID: record.accountID, with: verified, recordVersion: record.keysetVersion
            ).zeroise()
            lock()
            try await store.eraseAll()
            for item in [
                KeychainItem.secretKey(accountID: record.accountID), .quickUnlockKey(accountID: record.accountID),
                .quickUnlockState(accountID: record.accountID),
            ] {
                try await keychain.delete(item)
            }
            account = nil
        }

        private func storedSecretKey(accountID: UUID) async throws -> SecretKey {
            guard let bytes = try await keychain.read(.secretKey(accountID: accountID), prompt: "") else {
                throw VaultError.secretKeyMissing
            }
            return try SecretKey(bytes: bytes)
        }

        // MARK: - Items (PRD F1)

        public var personalVaultID: UUID? {
            account?.personalVaultID
        }

        /// Every item in every unlocked vault, trashed and archived ones included (the UI filters).
        public func items() async throws -> ItemListing {
            let epoch = lockEpoch
            _ = try requireKeys()
            guard let record = try await loadAccount() else { throw VaultError.noAccount }
            let rows = try await store.records(in: record.personalVaultID, kind: .item)
            let keys = try requireKeys(since: epoch)
            var listing = ItemListing(items: [], unreadable: [])
            for row in rows {
                do {
                    listing.items.append(try openItem(row, keys: keys))
                } catch {
                    listing.unreadable.append(row.recordID)
                }
            }
            listing.items.sort { $0.title.localizedStandardCompare($1.title) == .orderedAscending }
            return listing
        }

        public func item(id: UUID) async throws -> Item {
            let epoch = lockEpoch
            _ = try requireKeys()
            guard let row = try await store.record(RecordKey(recordID: id, kind: .item)) else {
                throw VaultError.itemNotFound(id)
            }
            return try openItem(row, keys: try requireKeys(since: epoch))
        }

        /// Creates or updates an item. The vault owns `createdAt`, `modifiedAt`, `version`, `history` and `trashedAt`;
        /// whatever the caller put there is replaced. Scopes are checked against the scope policy here, the one place
        /// they can enter the vault from the UI (PRD F11.2).
        @discardableResult
        public func save(_ draft: Item) async throws -> Item {
            for scope in draft.scopes {
                do {
                    try ScopePolicy.validate(scope)
                } catch let error as ScopeValidationError {
                    throw VaultError.scopeRejected(error)
                }
            }
            return try await write(id: draft.id, vaultID: draft.vaultID, creating: draft) { item, existing, now in
                item = draft
                if let existing {
                    item.createdAt = existing.createdAt
                    item.trashedAt = existing.trashedAt
                    item.history = existing.history
                    if existing.fields != draft.fields {
                        item.history.insert(
                            ItemHistoryEntry(replacedAt: now, version: existing.version, fields: existing.fields), at: 0
                        )
                    }
                } else {
                    item.createdAt = now
                    item.trashedAt = nil
                    item.history = []
                }
            }
        }

        public func trash(id: UUID) async throws {
            try await write(id: id) { item, _, now in item.trashedAt = item.trashedAt ?? now }
        }

        public func restore(id: UUID) async throws {
            try await write(id: id) { item, _, _ in item.trashedAt = nil }
        }

        public func setArchived(_ archived: Bool, id: UUID) async throws {
            try await write(id: id) { item, _, _ in item.archived = archived }
        }

        /// Marks a 2FA recovery code as spent (scenario S2). A new item version, so the change is in the history.
        public func markRecoveryCode(itemID: UUID, fieldID: UUID, index: Int, used: Bool) async throws {
            try await write(id: itemID) { item, existing, now in
                guard let position = item.fields.firstIndex(where: { $0.id == fieldID }) else { return }
                item.fields[position].markRecoveryCode(at: index, used: used)
                if let existing, existing.fields != item.fields {
                    item.history.insert(
                        ItemHistoryEntry(replacedAt: now, version: existing.version, fields: existing.fields), at: 0)
                }
            }
        }

        /// Permanently deletes a trashed item. Items not in the trash are refused, so one call cannot destroy data.
        public func deletePermanently(id: UUID) async throws {
            let item = try await item(id: id)
            guard item.isTrashed else { throw VaultError.itemNotTrashed(id) }
            _ = try requireKeys()
            try await store.commit(StoreChange(deletions: [RecordKey(recordID: id, kind: .item)]))
        }

        /// Deletes items that have been in the trash for 30 days (PRD F1.5). Run after every unlock.
        public func purgeExpiredTrash() async throws {
            let now = await clock.now()
            let expired = try await items().items.filter {
                guard let trashedAt = $0.trashedAt else { return false }
                return now.timeIntervalSince(trashedAt) >= VaultConfiguration.trashRetention
            }
            guard !expired.isEmpty else { return }
            try await store.commit(StoreChange(deletions: expired.map { RecordKey(recordID: $0.id, kind: .item) }))
        }

        /// Read-modify-write of one item: the version moves forward, the history is pruned, and the record is sealed
        /// under the vault's current key.
        @discardableResult
        private func write(
            id: UUID,
            vaultID: UUID? = nil,
            creating draft: Item? = nil,
            _ mutate: (inout Item, Item?, Date) -> Void
        ) async throws -> Item {
            let epoch = lockEpoch
            _ = try requireKeys()
            guard let record = try await loadAccount() else { throw VaultError.noAccount }
            let now = await clock.now()
            let existingRow = try await store.record(RecordKey(recordID: id, kind: .item))
            let keys = try requireKeys(since: epoch)

            let existing = try existingRow.map { try openItem($0, keys: keys) }
            guard var item = existing ?? draft else { throw VaultError.itemNotFound(id) }
            let targetVault = vaultID ?? item.vaultID
            if let existing, existing.vaultID != targetVault { throw VaultError.vaultChangeNotSupported }
            // Milestone 2 has one vault, the personal one; shared vaults bring a per-vault current key (milestone 4).
            guard targetVault == record.personalVaultID,
                let vaultKey = keys.vaultKeys[record.personalVaultKeyID]
            else { throw VaultError.unknownVault(targetVault) }

            mutate(&item, existing, now)
            item.id = id
            item.vaultID = targetVault
            item.modifiedAt = now
            item.history = Self.pruned(item.history, now: now)
            let base = max(highestVersionSeen, existing?.version ?? 0)
            guard base < UInt64.max else { throw VaultError.versionOverflow }
            item.version = base + 1

            let plaintext = try ItemCodec.encode(item)
            let row = StoredRecord(
                recordID: item.id, kind: .item, vaultID: targetVault, keyID: vaultKey.key.keyID, version: item.version,
                deviceID: record.deviceID, envelope: [])
            var sealed = row
            sealed.envelope = try RecordCipher.seal(
                plaintext, context: Self.itemContext(row), key: vaultKey.key, using: &random)
            try await store.commit(StoreChange(upserts: [sealed]))
            highestVersionSeen = max(highestVersionSeen, item.version)
            return item
        }

        private func openItem(_ row: StoredRecord, keys: UnlockedKeys) throws -> Item {
            guard let vaultKey = keys.vaultKeys[row.keyID], vaultKey.vaultID == row.vaultID else {
                throw VaultError.unknownVault(row.vaultID)
            }
            let plaintext = try RecordCipher.open(
                row.envelope, context: Self.itemContext(row), key: vaultKey.key,
                maximumLength: ItemCodec.maximumPayloadLength + 4096)
            defer { plaintext.zeroise() }
            // Decoded fields become Strings, which cannot be zeroised anyway (PRD SEC4); the copy is named so it is
            // searchable.
            let item = try ItemCodec.decode(plaintext.unprotectedCopy())
            guard item.id == row.recordID, item.vaultID == row.vaultID, item.version == row.version else {
                throw VaultError.recordMismatch(row.recordID)
            }
            highestVersionSeen = max(highestVersionSeen, item.version)
            return item
        }

        /// The context an item record must carry, built from its row: where it was found, never what it says.
        static func itemContext(_ row: StoredRecord) -> EnvelopeContext {
            EnvelopeContext(
                recordID: row.recordID,
                vaultID: row.vaultID,
                schemaVersion: ItemCodec.schemaVersion,
                kind: .item,
                keyID: row.keyID,
                recordVersion: row.version
            )
        }

        static func pruned(_ history: [ItemHistoryEntry], now: Date) -> [ItemHistoryEntry] {
            var kept: [ItemHistoryEntry] = []
            for (index, entry) in history.enumerated() {
                let recent = now.timeIntervalSince(entry.replacedAt) < VaultConfiguration.historyRetention
                if index == 0 || recent {
                    kept.append(entry)
                }
                if kept.count == VaultConfiguration.maximumHistoryEntries { break }
            }
            return kept
        }

        // MARK: - Helpers

        private func vaultKeyRecord(_ vaultKey: VaultKey, keyset: Keyset, deviceID: UUID) throws -> StoredRecord {
            StoredRecord(
                recordID: vaultKey.key.keyID,
                kind: .vaultKeyWrap,
                vaultID: vaultKey.vaultID,
                keyID: keyset.symmetricKey.keyID,
                version: 1,
                deviceID: deviceID,
                envelope: try vaultKey.wrap(for: keyset, using: &random)
            )
        }

        private func kdfParameters() throws -> KDFParameters {
            let parameters: KDFParameters
            switch configuration.kdf {
            case .calibrate: parameters = try KDFCalibration.calibrate(clock: ContinuousClock())
            case .fixed(let fixed): parameters = fixed
            }
            try parameters.validate()
            return parameters
        }

        private func randomBytes(_ count: Int) -> [UInt8] {
            SecureBytes(randomCount: count, using: &random).unprotectedCopy()
        }
    }

    /// A concrete wrapper, because the crypto APIs take `inout some RandomNumberGenerator` and an existential cannot be
    /// passed there directly.
    struct InjectedGenerator: RandomNumberGenerator, Sendable {
        var base: any RandomNumberGenerator & Sendable

        mutating func next() -> UInt64 {
            base.next()
        }
    }

    extension UUID {
        /// A version-4 UUID from `generator`, so IDs are reproducible under a seeded test generator.
        static func random(using generator: inout some RandomNumberGenerator) -> UUID {
            var bytes = (0..<2).flatMap { _ in
                let word = generator.next()
                return (0..<8).map { UInt8(truncatingIfNeeded: word >> (8 * $0)) }
            }
            bytes[6] = (bytes[6] & 0x0F) | 0x40
            bytes[8] = (bytes[8] & 0x3F) | 0x80
            return UUID(
                uuid: (
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
                    bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
                ))
        }
    }
#endif
