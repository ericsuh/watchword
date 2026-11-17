import Foundation
import SecureMemory
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordMatching
import WatchwordModel
import WatchwordStore
import WatchwordSync

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
    /// PRD F1.5.
    public static let trashRetention: TimeInterval = 30 * 24 * 60 * 60

    public var appVersion: String
    public var kdf: KDFStrategy
    public var quickUnlock: QuickUnlockSettings
    public var autoLock: AutoLockSettings
    /// What this device is called in the account's list of devices ("Eric's iPhone"). Sealed under the keyset before
    /// it is written anywhere; at most 64 characters are kept.
    public var deviceName: String
    /// Breach checks and the hygiene report (docs/02-architecture.md §13.8); `nil` turns hygiene off.
    public var hygiene: HygieneSettings?

    public init(
        appVersion: String,
        kdf: KDFStrategy = .calibrate,
        quickUnlock: QuickUnlockSettings = .standard,
        autoLock: AutoLockSettings = .platformDefault,
        deviceName: String = "",
        hygiene: HygieneSettings? = nil
    ) {
        self.appVersion = appVersion
        self.kdf = kdf
        self.quickUnlock = quickUnlock
        self.autoLock = autoLock
        self.deviceName = deviceName
        self.hygiene = hygiene
    }
}

/// Where a vault syncs to, and where this device keeps what it knows about that (docs/02-architecture.md §7).
public struct SyncSettings: Sendable {
    public var state: any SyncStateStore
    public var transport: any SyncTransport
    public var configuration: SyncConfiguration

    public init(
        state: any SyncStateStore,
        transport: any SyncTransport,
        configuration: SyncConfiguration = SyncConfiguration(schemaVersions: [
            .item: ItemCodec.schemaVersion, .vaultMetadata: VaultMetadataCodec.schemaVersion,
            .scanStatus: ScanStatusCodec.schemaVersion,
        ])
    ) {
        self.state = state
        self.transport = transport
        self.configuration = configuration
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
public actor VaultSession: SharesExecutor {
    let store: any RecordStore
    let keychain: any KeychainStore
    let biometrics: any BiometricGate
    let clock: any WallClock
    let configuration: VaultConfiguration
    let syncSettings: SyncSettings?
    let deviceKeys: any DeviceKeyStore
    var random: InjectedGenerator

    var keys: UnlockedKeys?
    var account: AccountRecord?
    var lockEpoch: UInt64 = 0
    private var lastActivity: Date?
    private var backgroundedAt: Date?
    /// Lamport high-water mark per vault, so one record with an absurd version cannot freeze writes elsewhere.
    var highestVersionSeen: [UUID: UInt64] = [:]
    /// Whoever asked to be told of every lock (`lockEvents()`), by a number of their own.
    var lockListeners: [Int: AsyncStream<Void>.Continuation] = [:]
    var nextLockListener = 0
    var syncInFlight = false
    /// The device registry as last evaluated from the local store; `nil` whenever it may have changed.
    var registryView: RegistryView?
    /// Registry entries fetched from the transport and found worth nothing (they can never count, or wait on a
    /// parent that is not there), not fetched again by this session until a sync keeps something new: a revoked
    /// device that floods the transport costs each of them one fetch (docs/02-architecture.md §7.8).
    var skippedRegistryEntries: Set<ObjectDigest> = []
    /// The hygiene engine and what drives it (`VaultSession+Hygiene.swift`); built at the first unlock.
    var hygieneRuntime: HygieneRuntime?
    /// The serial executor the session shares with its hygiene engine, so that `lock()` drops the engine's keys
    /// before it returns (`SharesExecutor`; docs/02-architecture.md §13.8).
    package nonisolated let executorOwner = SerialExecutorOwner()
    /// Shared vaults: settings, ledgers, plans, proposals and stream indexes (VaultSession+Sharing.swift).
    var sharing = SharingRuntime()
    /// An import read but not yet committed: drafts with every secret in the file, dropped by `lock()` (§14.1).
    var pendingImport: PendingImport?
    /// Bumped by every preview and `discardImport()`, so a preview still being read when either runs is dropped.
    var importGeneration: UInt64 = 0
    /// Tests only: called inside every step `awayFromSession` runs, off the actor, before the step itself, so a test
    /// can hold one there and show that `lock()` does not wait for it. `nil` in production.
    var awayWorkHook: (@Sendable (AwayWork) -> Void)?

    /// Production passes `SystemRandomNumberGenerator()`; only tests inject anything else (CLAUDE.md).
    public init(
        store: any RecordStore,
        keychain: any KeychainStore,
        biometrics: any BiometricGate,
        clock: any WallClock = SystemWallClock(),
        configuration: VaultConfiguration,
        sync: SyncSettings? = nil,
        deviceKeys: (any DeviceKeyStore)? = nil,
        random: any RandomNumberGenerator & Sendable = SystemRandomNumberGenerator()
    ) {
        self.store = store
        // Until the Secure Enclave adapter exists, a device's signing key is a software key in the Keychain.
        self.deviceKeys = deviceKeys ?? KeychainDeviceKeyStore(keychain: keychain)
        self.keychain = keychain
        self.biometrics = biometrics
        self.clock = clock
        self.configuration = configuration
        self.syncSettings = sync
        self.random = InjectedGenerator(base: random)
    }

    /// The store the session's own writes go through. With sync on, a `DeletionRecordingStore`, so every deletion
    /// the person makes becomes an explicit tombstone for the sync layer to publish; the sync engine writes to
    /// `store` directly, so the deletions it applies are not published again (docs/02-architecture.md §7.1).
    func writer(for account: AccountRecord) -> any RecordStore {
        guard let syncState else { return store }
        return DeletionRecordingStore(base: store, syncState: syncState, deviceID: account.deviceID)
    }

    /// The configured sync state store, behind the wrapper that signs pending deletions as they are recorded and
    /// ignores any that does not verify (`AuthenticatedSyncState`).
    var syncState: (any SyncStateStore)? {
        syncSettings.map { AuthenticatedSyncState(base: $0.state, session: self) }
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

    func loadAccount() async throws -> AccountRecord? {
        if let account { return account }
        account = try await store.loadAccount()
        return account
    }

    func requireKeys(since epoch: UInt64? = nil) throws -> UnlockedKeys {
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
        // The device registry starts here: this device, its own signing key, and the enrolment key the new AUK
        // yields; and the account header as other devices will fetch it (docs/02-architecture.md §7.7, §7.8).
        let genesis: (rows: [StoredRecord], anchor: RegistryAnchor)
        do {
            genesis = try await registryGenesis(account: record, unlockKey: unlockKey, keyset: keyset, now: now)
        } catch {
            newKeys.zeroise()
            throw error
        }

        // Keychain first: if the store commit then fails, an orphaned Secret Key is harmless and is replaced by
        // the next attempt. The other order could leave an account whose Secret Key exists nowhere, before the
        // person has even seen the Emergency Kit.
        try await keychain.store(
            secretKey.bytes.extracting(0..<SecretKey.byteCount), for: .secretKey(accountID: accountID))
        do {
            try await store.commit(
                StoreChange(account: .create(record), upserts: [vaultKeyRecord] + genesis.rows))
        } catch {
            try? await keychain.delete(.secretKey(accountID: accountID))
            try? await deviceKeys.delete(accountID: accountID)
            newKeys.zeroise()
            throw error
        }
        account = record
        registryView = nil
        try? await writeAnchor(genesis.anchor, accountID: accountID)
        guard epoch == lockEpoch, keys == nil else {
            newKeys.zeroise()
            throw VaultError.lockedDuringUnlock
        }
        install(newKeys, at: now)
        try? await refreshSigningKey(account: record, keys: newKeys)
        // Which vaults are shared, read before anything picks a key for one (VaultSession+SharedMarker.swift). Last:
        // nothing after it reads `newKeys`, which a lock during the read would have zeroised.
        await loadSharedMarkersIfNeeded(force: true)
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
    ///
    /// If the password was changed on another device and this one has been told, the old password is refused with
    /// `passwordChangedOnAnotherDevice` and the new one adopts that change. `ignoringPasswordChange` is for the
    /// person who did not make the change: it unlocks with the password this device still has, so they can revoke
    /// the device that made it and set a password of their own (docs/02-architecture.md §7.8).
    public func unlock(password: String, ignoringPasswordChange: Bool = false) async throws {
        try await unlock(
            password: password, enteredSecretKey: nil, ignoringPasswordChange: ignoringPasswordChange)
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
        try await unlock(password: password, enteredSecretKey: secretKey, ignoringPasswordChange: false)
    }

    private func unlock(password: String, enteredSecretKey: SecretKey?, ignoringPasswordChange: Bool)
        async throws
    {
        guard keys == nil else { throw VaultError.alreadyUnlocked }
        let epoch = lockEpoch
        guard var record = try await loadAccount() else { throw VaultError.noAccount }

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

        let opened = try await openAccount(
            password: password, secretKey: secretKey, account: record,
            ignoringPasswordChange: ignoringPasswordChange)
        record = opened.account
        let unlockKey = opened.unlockKey
        let newKeys: UnlockedKeys
        do {
            // The keyset opened, so the header's version is what its writer sealed. Older than the credentials this
            // device already follows means the file was rolled back to a password the person retired.
            do {
                try await refuseRolledBackHeader(record)
            } catch {
                opened.keyset.zeroise()
                throw error
            }
            newKeys = try await openVaultKeys(unlockKey: unlockKey, keyset: opened.keyset, account: record)
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
        try? await refreshSigningKey(account: record, keys: newKeys)
        do {
            try await reconcileAccountObjects(account: record, keys: newKeys)
        } catch VaultError.accountHeaderRolledBack {
            // The one failure that is not best effort: the file holds a header from before a password change this
            // device had already followed (A8). The password that opened it is not the account's any more.
            lock()
            throw VaultError.accountHeaderRolledBack
        } catch {
            // Sync says why (`deviceRegistryUnavailable`); the person keeps access to their vault.
        }
        // Which vaults are shared (VaultSession+SharedMarker.swift); until this has been read, every vault but the
        // Personal one is held closed.
        await loadSharedMarkersIfNeeded(force: true)
        try? await purgeExpiredTrash()
    }

    /// Derives the AUK and opens the keyset: under an account header for a password changed on another device, if
    /// the password opens one (which adopts it), otherwise under the header this device has.
    private func openAccount(
        password: String, secretKey: SecretKey, account record: AccountRecord, ignoringPasswordChange: Bool
    ) async throws -> (unlockKey: EncryptionKey, keyset: Keyset, account: AccountRecord) {
        let candidates = await candidateHeaders(record)
        var attempts = 0
        for candidate in candidates.pending where attempts < Self.maximumHeaderAttempts {
            attempts += 1
            if let adopted = try await adopt(candidate, password: password, secretKey: secretKey, account: record) {
                return adopted
            }
        }
        do {
            let unlockKey = try deriveUnlockKey(password: password, secretKey: secretKey, account: record)
            let keyset: Keyset
            do {
                keyset = try unwrapKeyset(unlockKey: unlockKey, account: record)
            } catch {
                unlockKey.zeroise()
                throw error
            }
            guard candidates.pending.isEmpty || ignoringPasswordChange else {
                unlockKey.zeroise()
                keyset.zeroise()
                throw VaultError.passwordChangedOnAnotherDevice
            }
            return (unlockKey, keyset, record)
        } catch CryptoError.authenticationFailed {
            // Not this device's password. One of a branch the person may have chosen elsewhere?
            for candidate in candidates.forked where attempts < Self.maximumHeaderAttempts {
                attempts += 1
                if let adopted = try await adopt(candidate, password: password, secretKey: secretKey, account: record) {
                    return adopted
                }
            }
            throw CryptoError.authenticationFailed
        }
    }

    /// Tries `password` against a candidate header. If it opens the keyset — the same keyset, for the same personal
    /// vault — the person has confirmed that password change on this device: the header becomes this device's, and
    /// the registry is followed along its credential entry from now on. Returns `nil` if it does not open.
    private func adopt(
        _ candidate: AccountHeaderObject, password: String, secretKey: SecretKey, account record: AccountRecord
    ) async throws -> (unlockKey: EncryptionKey, keyset: Keyset, account: AccountRecord)? {
        guard let view = try? await registry(record),
            let unlockKey = try? TwoSecretKeyDerivation.accountUnlockKey(
                password: password, secretKey: secretKey, accountID: record.accountID, parameters: candidate.kdf,
                salt: candidate.salt, keyID: candidate.unlockKeyID)
        else { return nil }
        guard
            let keyset = try? Keyset.unwrap(
                candidate.wrappedKeyset, accountID: record.accountID, with: unlockKey,
                recordVersion: candidate.keysetVersion)
        else {
            unlockKey.zeroise()
            return nil
        }
        let rows = try await store.records(in: record.accountID, kind: .deviceRegistry)
        guard (try? candidate.openBinding(with: unlockKey)) == record.personalVaultID,
            (try? keyset.publicKeyBundle().signingKey) == view.state.accountSigningKey,
            let followed = try? Self.evaluateRegistry(
                rows.map(\.envelope), accountID: record.accountID, accountKey: view.state.accountSigningKey,
                genesis: view.state.genesis, credential: candidate.credentialID)
        else {
            unlockKey.zeroise()
            keyset.zeroise()
            return nil
        }
        var updated = record
        updated.kdf = candidate.kdf
        updated.salt = candidate.salt
        updated.unlockKeyID = candidate.unlockKeyID
        updated.wrappedKeyset = candidate.wrappedKeyset
        updated.keysetVersion = candidate.keysetVersion
        updated.credentialGeneration = candidate.generation
        do {
            let existing = try await store.record(Self.headerKey(record.accountID))
            let stale = try await store.records(in: record.accountID, kind: .accountHeader)
                .filter { $0.recordID != record.accountID }.map(\.key)
            try await store.commit(
                StoreChange(
                    account: .update(updated, expectedKeysetVersion: record.keysetVersion),
                    upserts: [
                        Self.headerRow(
                            candidate, recordID: record.accountID, version: try Self.version(replacing: existing))
                    ], deletions: stale))
            try await pinRegistry(followed, accountID: record.accountID)
        } catch {
            unlockKey.zeroise()
            keyset.zeroise()
            throw error
        }
        account = updated
        registryView = nil
        return (unlockKey, keyset, updated)
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
        // The password was changed on another device: the key this device would release opens credentials that are
        // no longer the account's. Destroyed, like any refused enrolment; the new password re-enrols.
        if !(await candidateHeaders(record)).pending.isEmpty {
            try await suspendQuickUnlock(accountID: accountID, forget: false)
            throw VaultError.quickUnlockRefused(.credentialsChanged)
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

        // Every prompt that does not end in the key counts, cancels included. With `biometryCurrentSet` and no
        // passcode fallback, the system prompt retries a face or finger internally and a run of failures usually
        // ends in Cancel (`errSecUserCanceled`), not in `errSecAuthFailed`; counting only the latter would let
        // someone who can clear the OS lockout with the device passcode keep trying indefinitely (F5.4).
        let releasedKey: SecureBytes?
        do {
            releasedKey = try await keychain.read(.quickUnlockKey(accountID: accountID), prompt: prompt)
        } catch let error as KeychainError where error == .authenticationFailed || error == .userCancelled {
            state.failedAttempts += 1
            try await saveQuickUnlockState(state, accountID: accountID)
            if state.failedAttempts >= configuration.quickUnlock.maximumFailedAttempts {
                try await suspendQuickUnlock(accountID: accountID, forget: false)
            }
            throw error == .userCancelled ? error : VaultError.biometricAuthenticationFailed
        }
        guard let releasedKey else {
            // Gone: the OS invalidated it after a biometric enrolment change, or it was deleted.
            try await suspendQuickUnlock(accountID: accountID, forget: true)
            throw VaultError.quickUnlockRefused(.enrolmentChanged)
        }

        // The LUK → AUK → keyset chain. A failure here means what the Keychain released does not lead to the keyset,
        // so the enrolment is destroyed and never retried. Failures after the keyset opens (a bad vault-key row in
        // the store) are not the enrolment's fault and leave it alone.
        let unlockKey: EncryptionKey
        let keyset: Keyset
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
            unlockKey = try EncryptionKey(keyID: state.accountUnlockKeyID, material: unlockKeyMaterial)
            guard unlockKey.keyID == record.unlockKeyID else {
                unlockKey.zeroise()
                throw VaultError.quickUnlockRefused(.credentialsChanged)
            }
            do {
                keyset = try unwrapKeyset(unlockKey: unlockKey, account: record)
            } catch {
                unlockKey.zeroise()
                throw error
            }
        } catch {
            try? await suspendQuickUnlock(accountID: accountID, forget: true)
            throw error
        }
        let newKeys: UnlockedKeys
        do {
            do {
                try await refuseRolledBackHeader(record)
            } catch {
                keyset.zeroise()
                throw error
            }
            newKeys = try await openVaultKeys(unlockKey: unlockKey, keyset: keyset, account: record)
        } catch {
            unlockKey.zeroise()
            throw error
        }
        guard epoch == lockEpoch, keys == nil else {
            newKeys.zeroise()
            throw VaultError.lockedDuringUnlock
        }
        install(newKeys, at: now)
        state.failedAttempts = 0
        try? await saveQuickUnlockState(state, accountID: accountID)
        try? await refreshSigningKey(account: record, keys: newKeys)
        do {
            try await reconcileAccountObjects(account: record, keys: newKeys)
        } catch VaultError.accountHeaderRolledBack {
            lock()
            throw VaultError.accountHeaderRolledBack
        } catch {
            // As after a password unlock: sync reports a registry it cannot use.
        }
        await loadSharedMarkersIfNeeded(force: true)
    }

    /// Derives AUK. `KDFParameters.validate()` runs inside, before any work (SEC5, SEC9).
    func deriveUnlockKey(password: String, secretKey: SecretKey, account: AccountRecord) throws
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

    private func unwrapKeyset(unlockKey: EncryptionKey, account: AccountRecord) throws -> Keyset {
        try Keyset.unwrap(
            account.wrappedKeyset, accountID: account.accountID, with: unlockKey,
            recordVersion: account.keysetVersion)
    }

    /// Unwraps the key of every vault in the directory. Identities come from the storage location (each row), never
    /// from the wraps (§4). Only the personal vault's current key is required. Any other wrap that fails to open (a
    /// row planted in the file) is skipped, so one bad row cannot block every unlock. A failure of the required key
    /// is reported as `vaultKeyUnreadable`, never as `authenticationFailed`: the password was already proven by the
    /// keyset.
    private func openVaultKeys(unlockKey: EncryptionKey, keyset: Keyset, account: AccountRecord) async throws
        -> UnlockedKeys
    {
        do {
            var rows = try await store.records(in: account.personalVaultID, kind: .vaultKeyWrap)
            for index in try await store.records(in: account.accountID, kind: .vaultDirectory)
            where index.recordID != account.personalVaultID {
                rows += try await store.records(in: index.recordID, kind: .vaultKeyWrap)
            }
            var vaultKeys: [UUID: VaultKey] = [:]
            for row in rows {
                do {
                    vaultKeys[row.recordID] = try VaultKey.unwrap(
                        row.envelope, vaultID: row.vaultID, keyID: row.recordID, with: keyset)
                } catch  where row.recordID == account.personalVaultKeyID {
                    for key in vaultKeys.values { key.zeroise() }
                    throw VaultError.vaultKeyUnreadable(vaultID: account.personalVaultID)
                } catch {
                    continue
                }
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

    func install(_ newKeys: UnlockedKeys, at now: Date) {
        keys = newKeys
        lastActivity = now
        backgroundedAt = nil
        startHygiene()
    }

    // MARK: - Lock (PRD F5.5)

    /// Zeroises every key. Safe to call at any time, including while another operation is in flight: that
    /// operation then fails with `locked` or `lockedDuringUnlock`.
    public func lock() {
        lockEpoch &+= 1
        keys?.zeroise()
        keys = nil
        pendingImport = nil
        backgroundedAt = nil
        // After the keyset is zeroised, never before (§13.8): nothing the engine does can keep the keys resident.
        stopHygiene()
        for listener in lockListeners.values { listener.yield() }
    }

    /// One element for every lock from now on, whatever caused it (`lock()`, auto-lock, a lock during an operation),
    /// for state outside the session that must go with the keys: a screen's decrypted values, an export's bytes. The
    /// stream ends when its consumer stops listening; at most one unread lock is kept.
    public func lockEvents() -> AsyncStream<Void> {
        let (stream, continuation) = AsyncStream<Void>.makeStream(bufferingPolicy: .bufferingNewest(1))
        let number = nextLockListener
        nextLockListener += 1
        lockListeners[number] = continuation
        continuation.onTermination = { [weak self] _ in
            Task { await self?.stopListening(number) }
        }
        return stream
    }

    private func stopListening(_ number: Int) {
        lockListeners[number] = nil
    }

    /// Call on user interaction. Resets the idle timer — unless the timeout has already passed, in which case it
    /// locks instead: activity must never revive a session that should already have ended (a timer that did not
    /// fire because the window was closed or the app was napping is not a reason to stay open).
    @discardableResult
    public func recordActivity() async -> LockReason? {
        let now = await clock.now()
        guard keys != nil else { return nil }
        if let lastActivity,
            let reason = AutoLockPolicy.decide(
                event: .tick, now: now, lastActivity: lastActivity, backgroundedAt: nil,
                settings: configuration.autoLock)
        {
            lock()
            return reason
        }
        lastActivity = now
        return nil
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
    ///
    /// The password is required, and re-verified against the stored header: enrolment starts the F5.4 password
    /// interval, so a session opened by quick unlock must not be able to restart it, or someone who can present the
    /// enrolled biometric but does not know the password could keep quick unlock alive forever.
    public func enableQuickUnlock(password: String) async throws {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        let secretKey = try await storedSecretKey(accountID: record.accountID)
        defer { secretKey.zeroise() }
        let verified = try deriveUnlockKey(password: password, secretKey: secretKey, account: record)
        defer { verified.zeroise() }
        try unwrapKeyset(unlockKey: verified, account: record).zeroise()
        _ = try requireKeys(since: epoch)
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
    static func quickUnlockContext(accountID: UUID, state: QuickUnlockState, generation: UInt64) -> EnvelopeContext {
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
    ///
    /// The change is the account's, not this device's (docs/02-architecture.md §7.8): it is recorded in the device
    /// registry as a new credential generation, signed by this device and by the enrolment key of the generation it
    /// replaces (which is what proves the current password was known), and the new account header is published at
    /// the next sync. Every other device then refuses the old password and asks for the new one, and a device can
    /// only enrol with the new one. The keyset itself does not change: someone who opened it with the old password
    /// still holds it.
    public func changePassword(current: String, new: String) async throws {
        try await rotateCredentials(current: current, new: new, revoking: nil)
    }

    /// A password change, a device revocation, or both as one step: the revocation first, then the credential
    /// change that names it as its parent, so on every device that follows the new password the revocation is
    /// behind a checkpoint and final (§7.8).
    func rotateCredentials(current: String, new: String?, revoking: UUID?) async throws {
        if let new, new.count < VaultConfiguration.minimumPasswordLength {
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

        let view = try await registry(record)
        guard view.state.standing(of: record.deviceID) == .active else { throw VaultError.deviceRevoked }
        let previousEnrolment = EnrolmentKey.derive(from: verified, accountID: record.accountID)
        defer { previousEnrolment.zeroise() }
        guard view.state.credential.generation == record.credentialGeneration,
            try previousEnrolment.publicKey() == view.state.credential.enrolmentKey
        else { throw VaultError.deviceRegistryUnavailable }

        var parents = view.state.heads
        var rows: [StoredRecord] = []
        if let revoking {
            let keys = try requireKeys(since: epoch)
            let revocation = try await signedRegistryEntry(
                parents: parents, author: .device(record.deviceID), body: .revoke(revoking), account: record,
                keyset: keys.keyset)
            rows.append(Self.registryRow(revocation, account: record))
            parents = [revocation.id]
        }
        guard let new else {
            _ = try requireKeys(since: epoch)
            try await store.commit(StoreChange(upserts: rows))
            registryView = nil
            try await pinRegistry(try await registry(record), accountID: record.accountID)
            return
        }

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
        let credentialID: ObjectDigest
        do {
            var keys = try requireKeys(since: epoch)
            updated.wrappedKeyset = try keys.keyset.wrap(
                with: newUnlockKey, recordVersion: updated.keysetVersion, using: &random)
            let newEnrolment = EnrolmentKey.derive(from: newUnlockKey, accountID: record.accountID)
            defer { newEnrolment.zeroise() }
            let credential = try await signedRegistryEntry(
                parents: parents, author: .device(record.deviceID),
                body: .credential(
                    generation: updated.credentialGeneration, enrolmentKey: try newEnrolment.publicKey(),
                    previous: view.state.credential.id),
                account: record, keyset: keys.keyset, previousCredential: previousEnrolment)
            credentialID = credential.id
            keys = try requireKeys(since: epoch)
            let header = try await makeHeader(
                account: updated, credentialID: credentialID, genesisID: view.state.genesis,
                unlockKey: newUnlockKey, keyset: keys.keyset)
            _ = try requireKeys(since: epoch)
            let existing = try await store.record(Self.headerKey(record.accountID))
            // Headers kept for someone else's password change are beside the point now: this change supersedes or
            // forks them, and the registry says which.
            let candidates = try await store.records(in: record.accountID, kind: .accountHeader)
                .filter { $0.recordID != record.accountID }.map(\.key)
            rows.append(Self.registryRow(credential, account: record))
            rows.append(
                Self.headerRow(header, recordID: record.accountID, version: try Self.version(replacing: existing)))
            try await store.commit(
                StoreChange(
                    account: .update(updated, expectedKeysetVersion: record.keysetVersion), upserts: rows,
                    deletions: candidates))
        } catch {
            newUnlockKey.zeroise()
            throw error
        }
        account = updated
        registryView = nil
        // The new password is committed: from here on, report success whatever happens to the session. Telling the
        // person "nothing changed" now would leave them believing the old password still works (F10.2). If the
        // anchor cannot be written now, the next unlock moves it: the header that opens names the credential.
        try? await writeAnchor(
            RegistryAnchor(
                genesis: view.state.genesis, credential: credentialID, generation: updated.credentialGeneration,
                heads: [credentialID]),
            accountID: record.accountID)
        guard epoch == lockEpoch, let currentKeys = keys, currentKeys.keyset.accountID == oldKeys.keyset.accountID
        else {
            newUnlockKey.zeroise()
            return
        }
        keys = UnlockedKeys(
            accountUnlockKey: newUnlockKey, keyset: currentKeys.keyset, vaultKeys: currentKeys.vaultKeys)
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
        try await writer(for: record).eraseAll()
        try? await eraseHygieneRecords()
        account = nil
        // Every item is attempted even if one fails, so a Keychain error cannot leave the Secret Key behind just
        // because an earlier deletion threw; anything left over is reported.
        registryView = nil
        var leftovers: [KeychainItem] = []
        do {
            try await deviceKeys.delete(accountID: record.accountID)
        } catch {
            leftovers.append(.deviceSigningKey(accountID: record.accountID))
        }
        for item in KeychainItem.all(accountID: record.accountID) {
            do {
                try await keychain.delete(item)
            } catch {
                leftovers.append(item)
            }
        }
        if !leftovers.isEmpty { throw VaultError.keychainCleanupIncomplete(leftovers.count) }
    }

    func storedSecretKey(accountID: UUID) async throws -> SecretKey {
        guard let bytes = try await keychain.read(.secretKey(accountID: accountID), prompt: "") else {
            throw VaultError.secretKeyMissing
        }
        return try SecretKey(bytes: bytes)
    }

    // MARK: - Items (PRD F1)

    public var personalVaultID: UUID? {
        account?.personalVaultID
    }

    /// Every item in every vault of the account, trashed and archived ones included (the UI filters). That includes
    /// what a vault's deletion left behind: such an item is in the trash, its `vaultID` is not among `vaults()`, and
    /// it can be moved to another vault or deleted.
    public func items() async throws -> ItemListing {
        _ = try requireKeys()
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        return try await items(inVaults: Array(try await vaultDirectory(record).keys))
    }

    public func item(id: UUID) async throws -> Item {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let row = try await store.record(RecordKey(recordID: id, kind: .item)) else {
            throw VaultError.itemNotFound(id)
        }
        var inDeletedVault = false
        if let account = try await loadAccount(), row.vaultID != account.personalVaultID {
            inDeletedVault = try await vaultDirectory(account)[row.vaultID]?.isDeleted ?? false
        }
        return Self.presented(try openItem(row, keys: try requireKeys(since: epoch)), inDeletedVault: inDeletedVault)
    }

    /// Creates or updates an item. The vault owns `createdAt`, `modifiedAt`, `version`, `history`, `trashedAt` and
    /// `keptAfterDeletion`; whatever the caller put there is replaced. Scopes are checked against the scope policy here, the one place
    /// they can enter the vault from the UI (PRD F11.2).
    ///
    /// An update must be made from the stored version: a draft whose `version` is not the stored item's (a sync
    /// merged another device's edit while the editor was open) is refused with `versionConflict`, and the editor
    /// reopens the item (Y29).
    @discardableResult
    public func save(_ draft: Item) async throws -> Item {
        // A draft made from an earlier version than the stored one would be stamped as an edit that had seen
        // everything since, and replace it (Y29): refused, for the editor to reopen the item.
        try await save(draft, expecting: .versionIfPresent(draft.version))
    }

    func save(_ draft: Item, expecting expectation: WriteExpectation) async throws -> Item {
        for scope in draft.scopes {
            do {
                try ScopePolicy.validate(scope)
            } catch let error as ScopeValidationError {
                throw VaultError.scopeRejected(error)
            }
        }
        return try await write(id: draft.id, vaultID: draft.vaultID, creating: draft, expecting: expectation) {
            item, existing, now in
            item = draft
            if let existing {
                item.createdAt = existing.createdAt
                item.trashedAt = existing.trashedAt
                item.keptAfterDeletion = existing.keptAfterDeletion
                item.history = existing.history
                if existing.fields != draft.fields {
                    item.history.insert(
                        ItemHistoryEntry(replacedAt: now, version: existing.version, fields: existing.fields), at: 0
                    )
                }
            } else {
                item.createdAt = now
                item.trashedAt = nil
                item.keptAfterDeletion = false
                item.history = []
            }
        }
    }

    /// Moves an item to the trash, the person's choice (confirmed in the UI) that starts the 30-day purge. An item
    /// sync kept in the trash becomes the person's from now.
    public func trash(id: UUID) async throws {
        try await write(id: id) { item, _, now in
            if item.trashedAt == nil || item.keptAfterDeletion { item.trashedAt = now }
            item.keptAfterDeletion = false
        }
    }

    public func restore(id: UUID) async throws {
        try await write(id: id) { item, _, _ in
            item.trashedAt = nil
            item.keptAfterDeletion = false
        }
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
    ///
    /// A deletion is a write: in a shared vault it needs `writePermission` like any other (F4.5), and in one with no
    /// ledger on this device it is refused (review findings Z41, Z44). A deletion made while this account may not
    /// write would take effect here, and wait, signed, to be published the day it may.
    public func deletePermanently(id: UUID) async throws {
        let item = try await item(id: id)
        guard item.isTrashed else { throw VaultError.itemNotTrashed(id) }
        _ = try requireKeys()
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        try await checkSharedWrite(item.vaultID, account: record)
        _ = try requireKeys()
        // Conditional on the version just read, so a restore that lands in between is not silently undone. The item's
        // synced scan results go with it (§13.9).
        try await writer(for: record).commit(
            StoreChange(
                deletions: try await scanStatusKeys(of: [id]),
                conditionalDeletions: [RecordKey(recordID: id, kind: .item): item.version]))
    }

    /// Deletes items that have been in the trash for 30 days (PRD F1.5). Run after every password unlock. Not a
    /// discard without consent (F7.7): only an item the person moved to the trash, confirmed in the UI, knowing
    /// everything in it, is purged. Trash that sync left there (`Item.isTrashedByPerson`) stays until the person
    /// restores, trashes or deletes it.
    public func purgeExpiredTrash() async throws {
        let now = await clock.now()
        let expired = try await items().items.filter {
            guard let trashedAt = $0.trashedAt, $0.isTrashedByPerson else { return false }
            return now.timeIntervalSince(trashedAt) >= VaultConfiguration.trashRetention
        }
        guard !expired.isEmpty, let record = try await loadAccount() else { return }
        // Not in a shared vault this account may not write to now (read-only, a removal owed, a later format, no
        // ledger on this device): the purge is a deletion like any other (Z44), and there the trash is other
        // members' to empty.
        var writable: [UUID: Bool] = [:]
        for vaultID in Set(expired.map(\.vaultID)) {
            writable[vaultID] = (try? await checkSharedWrite(vaultID, account: record)) != nil
        }
        let purged = expired.filter { writable[$0.vaultID] == true }
        guard !purged.isEmpty else { return }
        _ = try requireKeys()
        try await writer(for: record).commit(
            StoreChange(
                deletions: try await scanStatusKeys(of: purged.map(\.id)),
                conditionalDeletions: Dictionary(
                    uniqueKeysWithValues: purged.map { (RecordKey(recordID: $0.id, kind: .item), $0.version) })))
    }

    /// Read-modify-write of one item: the version moves forward and the record is sealed under the vault's current
    /// key. History is never pruned (PRD F1.4: a full audit trail); an item whose payload would outgrow
    /// `ItemCodec.maximumPayloadLength` is refused with `ItemCodecError.payloadTooLarge`, leaving the stored
    /// version as it was.
    @discardableResult
    func write(
        id: UUID,
        vaultID: UUID? = nil,
        creating draft: Item? = nil,
        allowingDeletedVault: Bool = false,
        expecting expectation: WriteExpectation? = nil,
        _ mutate: (inout Item, Item?, Date) -> Void
    ) async throws -> Item {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        let now = await clock.now()
        let existingRow = try await store.record(RecordKey(recordID: id, kind: .item))
        let keys = try requireKeys(since: epoch)
        // Checked against the row this write replaces, and the commit is conditional on that row: together, a
        // compare-and-swap.
        try expectation?.check(existingRow, id: id)

        let existing = try existingRow.map { try openItem($0, keys: keys) }
        guard var item = existing ?? draft else { throw VaultError.itemNotFound(id) }
        let targetVault = vaultID ?? item.vaultID
        if let existing, existing.vaultID != targetVault { throw VaultError.vaultChangeNotSupported }
        // The vault must be one of the account's, with a key this device holds, and not deleted. Shared vaults add
        // the member's role to this check (milestone 4).
        let vaultKey = try await writableVaultKey(
            targetVault, keys: keys, account: record, allowingDeleted: allowingDeletedVault)
        _ = try requireKeys(since: epoch)

        mutate(&item, existing, now)
        item.id = id
        item.vaultID = targetVault
        item.modifiedAt = now
        let revision = try nextRevision(in: targetVault, above: existingRow, account: record)
        item.version = revision.version
        // The vault owns the sync metadata as it owns the version: every group the edit changed is stamped with
        // what this device has seen, the rest keep theirs (PRD F7.4, F7.6). The caller's stamps are ignored.
        item = ItemMerge.stamped(
            item, previous: existing, previousOrigin: existingRow.map(Self.origin), revision: revision)
        try await commitItem(item, replacing: existingRow, vaultKey: vaultKey, account: record)
        return item
    }

    /// The revision of the next write in `vaultID`: above every version this device has seen there, and above the
    /// row being replaced.
    func nextRevision(in vaultID: UUID, above row: StoredRecord?, account: AccountRecord) throws -> Revision {
        let base = max(highestVersionSeen[vaultID] ?? 0, row?.version ?? 0)
        guard base < UInt64.max else { throw VaultError.versionOverflow }
        return Revision(version: base + 1, device: account.deviceID)
    }

    /// Seals `item` as a row written by this device and commits it, conditional on the row it replaces still being
    /// the one read (`StoreChange.expectations`): the actor is re-entrant, and a sync merge may have stored a newer
    /// version while this write was waiting.
    func commitItem(_ item: Item, replacing existing: StoredRecord?, vaultKey: VaultKey, account: AccountRecord)
        async throws
    {
        let sealed = try sealItem(item, vaultKey: vaultKey, account: account)
        var change = StoreChange(upserts: [sealed])
        change.expectations[sealed.key] = existing.map { .version($0.version) } ?? .absent
        try await writer(for: account).commit(change)
        highestVersionSeen[item.vaultID] = max(highestVersionSeen[item.vaultID] ?? 0, item.version)
        await noteHygieneWrite(item)
    }

    func sealItem(_ item: Item, vaultKey: VaultKey, account: AccountRecord) throws -> StoredRecord {
        let plaintext = try ItemCodec.encode(item)
        defer { plaintext.zeroise() }
        var row = StoredRecord(
            recordID: item.id, kind: .item, vaultID: item.vaultID, keyID: vaultKey.key.keyID, version: item.version,
            deviceID: account.deviceID, envelope: [])
        row.envelope = try RecordCipher.seal(
            plaintext, context: Self.itemContext(row), key: vaultKey.key, using: &random)
        return row
    }

    static func origin(_ row: StoredRecord) -> Revision {
        Revision(version: row.version, device: row.deviceID)
    }

    func openItem(_ row: StoredRecord, keys: UnlockedKeys) throws -> Item {
        guard let vaultKey = keys.vaultKeys[row.keyID], vaultKey.vaultID == row.vaultID else {
            throw VaultError.unknownVault(row.vaultID)
        }
        let plaintext = try RecordCipher.open(
            row.envelope, context: Self.itemContext(row), key: vaultKey.key,
            maximumLength: ItemCodec.maximumPayloadLength + 4096)
        defer { plaintext.zeroise() }
        // Decoded fields become Strings, which cannot be zeroised (PRD SEC4); the codec wipes its own buffers.
        let item = try ItemCodec.decode(plaintext)
        guard item.id == row.recordID, item.vaultID == row.vaultID, item.version == row.version else {
            throw VaultError.recordMismatch(row.recordID)
        }
        highestVersionSeen[row.vaultID] = max(highestVersionSeen[row.vaultID] ?? 0, item.version)
        // Sync metadata is a writer's claim (Y30): every reader, the UI included, gets the one reading every device
        // makes of it, never counts above the row's version or values under a group they do not belong to.
        return ItemMerge.canonical(item, origin: Self.origin(row))
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

    func kdfParameters() throws -> KDFParameters {
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
