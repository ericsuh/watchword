#if canImport(CryptoKit) && canImport(CommonCrypto)
    import Foundation
    import WatchwordEnvelope
    import WatchwordKit
    import WatchwordStore
    import WatchwordSync

    /// A `VaultSession` wired to fakes, plus handles on each fake so a test can script or inspect it
    /// (docs/04-test-plan.md §2, "Scenario builders").
    public struct TestVault: Sendable {
        public static let password = "correct horse battery staple"
        public static let appVersion = "1.0 (1)"

        public let session: VaultSession
        public let store: any RecordStore
        public let keychain: FakeKeychain
        public let biometrics: FakeBiometricGate
        public let clock: FakeClock
        /// The sync settings the session was built with, if any.
        public let sync: SyncSettings?

        /// A session over fresh fakes. KDF parameters are the floor (`KDFParameters.baseline`), which is the cheapest
        /// derivation the policy accepts; there is no test-only weaker setting.
        public init(
            store: any RecordStore = InMemoryRecordStore(),
            keychain: FakeKeychain = FakeKeychain(),
            biometrics: FakeBiometricGate = FakeBiometricGate(),
            clock: FakeClock = FakeClock(),
            appVersion: String = TestVault.appVersion,
            sync: SyncSettings? = nil,
            seed: UInt64 = 7
        ) {
            self.store = store
            self.keychain = keychain
            self.biometrics = biometrics
            self.clock = clock
            self.sync = sync
            session = VaultSession(
                store: store,
                keychain: keychain,
                biometrics: biometrics,
                clock: clock,
                configuration: VaultConfiguration(appVersion: appVersion, kdf: .fixed(.baseline)),
                sync: sync,
                random: SeededGenerator(seed: TestEnvironment.seed(fallback: seed))
            )
        }

        /// A session that syncs over `transport`, with in-memory sync state.
        public static func syncing(
            over transport: any SyncTransport, clock: FakeClock = FakeClock(), seed: UInt64 = 7
        ) -> TestVault {
            TestVault(
                clock: clock, sync: SyncSettings(state: InMemorySyncStateStore(), transport: transport), seed: seed)
        }

        /// Another device of this vault's account, syncing over `transport`: the account header and vault-key wraps
        /// copied into a fresh store under a new device ID, and the Secret Key into a fresh Keychain. This stands in
        /// for enrolment from the account header on the transport, which is milestone 3's open work; what it copies is
        /// what that enrolment will deliver. Locked until unlocked with the password.
        public func enrolledDevice(
            deviceID: UUID, over transport: any SyncTransport, clock: FakeClock? = nil, seed: UInt64 = 13
        ) async throws -> TestVault {
            guard var account = try await store.loadAccount() else { throw VaultError.noAccount }
            let wraps = try await store.records(in: account.personalVaultID, kind: .vaultKeyWrap)
            account.deviceID = deviceID
            let newStore = InMemoryRecordStore()
            try await newStore.commit(StoreChange(account: .create(account), upserts: wraps))
            let newKeychain = FakeKeychain()
            if let secretKey = await keychain.raw(.secretKey(accountID: account.accountID)) {
                await newKeychain.overwrite(.secretKey(accountID: account.accountID), with: secretKey)
            }
            return TestVault(
                store: newStore, keychain: newKeychain, clock: clock ?? self.clock,
                sync: SyncSettings(state: InMemorySyncStateStore(), transport: transport), seed: seed)
        }

        /// The same store, Keychain, biometrics and clock seen by a new session: a relaunch, or the app after an update
        /// when `appVersion` differs.
        public func relaunched(appVersion: String = TestVault.appVersion, seed: UInt64 = 11) -> TestVault {
            TestVault(
                store: store, keychain: keychain, biometrics: biometrics, clock: clock, appVersion: appVersion,
                sync: sync, seed: seed)
        }

        /// Creates the account and returns its Emergency Kit; the vault is left unlocked.
        @discardableResult
        public func createAccount(password: String = TestVault.password) async throws -> EmergencyKit {
            try await session.createAccount(password: password)
        }
    }
#endif
