#if canImport(CryptoKit) && canImport(CommonCrypto)
    import Foundation
    import WatchwordEnvelope
    import WatchwordKit
    import WatchwordStore

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

        /// A session over fresh fakes. KDF parameters are the floor (`KDFParameters.baseline`), which is the cheapest
        /// derivation the policy accepts; there is no test-only weaker setting.
        public init(
            store: any RecordStore = InMemoryRecordStore(),
            keychain: FakeKeychain = FakeKeychain(),
            biometrics: FakeBiometricGate = FakeBiometricGate(),
            clock: FakeClock = FakeClock(),
            appVersion: String = TestVault.appVersion,
            seed: UInt64 = 7
        ) {
            self.store = store
            self.keychain = keychain
            self.biometrics = biometrics
            self.clock = clock
            session = VaultSession(
                store: store,
                keychain: keychain,
                biometrics: biometrics,
                clock: clock,
                configuration: VaultConfiguration(appVersion: appVersion, kdf: .fixed(.baseline)),
                random: SeededGenerator(seed: TestEnvironment.seed(fallback: seed))
            )
        }

        /// The same store, Keychain, biometrics and clock seen by a new session: a relaunch, or the app after an update
        /// when `appVersion` differs.
        public func relaunched(appVersion: String = TestVault.appVersion, seed: UInt64 = 11) -> TestVault {
            TestVault(
                store: store, keychain: keychain, biometrics: biometrics, clock: clock, appVersion: appVersion,
                seed: seed)
        }

        /// Creates the account and returns its Emergency Kit; the vault is left unlocked.
        @discardableResult
        public func createAccount(password: String = TestVault.password) async throws -> EmergencyKit {
            try await session.createAccount(password: password)
        }
    }
#endif
