import Foundation
import SecureMemory
import WatchwordCrypto
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
    /// This device's signing key store. By default the production software store over `keychain`, so two vaults
    /// that share a Keychain (a relaunch) are the same device, as on a real one.
    public let deviceKeys: any DeviceKeyStore

    /// A session over fresh fakes. KDF parameters are the floor (`KDFParameters.baseline`), which is the cheapest
    /// derivation the policy accepts; there is no test-only weaker setting.
    public init(
        store: any RecordStore = InMemoryRecordStore(),
        keychain: FakeKeychain = FakeKeychain(),
        biometrics: FakeBiometricGate = FakeBiometricGate(),
        clock: FakeClock = FakeClock(),
        appVersion: String = TestVault.appVersion,
        sync: SyncSettings? = nil,
        seed: UInt64 = 7,
        deviceName: String = "",
        deviceKeys: (any DeviceKeyStore)? = nil
    ) {
        // The nightly seed varies every vault's randomness without making them all the same: two devices built from
        // one seed would share a device key, which the registry refuses.
        let seed = TestEnvironment.seed(fallback: 0) &+ seed
        let deviceKeys =
            deviceKeys ?? KeychainDeviceKeyStore(keychain: keychain, random: SeededGenerator(seed: seed &+ 0x5EED))
        self.store = store
        self.keychain = keychain
        self.biometrics = biometrics
        self.clock = clock
        self.sync = sync
        self.deviceKeys = deviceKeys
        session = VaultSession(
            store: store,
            keychain: keychain,
            biometrics: biometrics,
            clock: clock,
            configuration: VaultConfiguration(
                appVersion: appVersion, kdf: .fixed(.baseline), deviceName: deviceName),
            sync: sync,
            deviceKeys: deviceKeys,
            random: SeededGenerator(seed: seed)
        )
    }

    /// A session that syncs over `transport`, with in-memory sync state.
    public static func syncing(
        over transport: any SyncTransport, clock: FakeClock = FakeClock(), seed: UInt64 = 7, name: String = ""
    ) -> TestVault {
        TestVault(
            clock: clock, sync: SyncSettings(state: InMemorySyncStateStore(), transport: transport), seed: seed,
            deviceName: name)
    }

    /// Another device of this vault's account, enrolled the way a real one is (PRD F5.2): this device publishes the
    /// account header, the device registry and the vault directory with a sync, and the new one joins from the
    /// transport alone, with the account password and the Secret Key off the Emergency Kit. `deviceID` names the new
    /// device, so a test can address its stream. Returned locked, as a device is until someone unlocks it.
    public func enrolledDevice(
        deviceID: UUID, over transport: any SyncTransport, clock: FakeClock? = nil, seed: UInt64? = nil,
        password: String = TestVault.password, name: String = ""
    ) async throws -> TestVault {
        try await session.sync()
        let kit = try await session.emergencyKit()
        // Each device its own randomness, and so its own signing key: the registry refuses one key for two devices.
        let ownSeed =
            seed ?? deviceID.uuidString.utf8.reduce(UInt64(13)) { ($0 &* 1_099_511_628_211) ^ UInt64($1) }
        let device = TestVault(
            clock: clock ?? self.clock, sync: SyncSettings(state: InMemorySyncStateStore(), transport: transport),
            seed: ownSeed, deviceName: name)
        try await device.session.enrol(
            password: password, secretKey: kit.secretKey, accountID: kit.accountID, assigningDeviceID: deviceID)
        await device.session.lock()
        return device
    }

    /// The same store, Keychain, biometrics and clock seen by a new session: a relaunch, or the app after an update
    /// when `appVersion` differs.
    public func relaunched(appVersion: String = TestVault.appVersion, seed: UInt64 = 11) -> TestVault {
        TestVault(
            store: store, keychain: keychain, biometrics: biometrics, clock: clock, appVersion: appVersion,
            sync: sync, seed: seed, deviceKeys: deviceKeys)
    }

    /// Loses this device's signing key, as a store restored onto other hardware does (Keychain items never leave a
    /// device).
    public func forgetDeviceKey(accountID: UUID) async {
        await keychain.delete(.deviceSigningKey(accountID: accountID))
    }

    /// This device's software signing key: what someone who read its Keychain holds.
    public func extractedDeviceKey(accountID: UUID) async -> SoftwareDeviceKey? {
        guard let stored = await keychain.raw(.deviceSigningKey(accountID: accountID)), stored.count == 48 else {
            return nil
        }
        return try? SoftwareDeviceKey(seed: SecureBytes(copying: Array(stored[16...])))
    }

    /// Creates the account and returns its Emergency Kit; the vault is left unlocked.
    @discardableResult
    public func createAccount(password: String = TestVault.password) async throws -> EmergencyKit {
        try await session.createAccount(password: password)
    }
}
