import Foundation
import WatchwordHygiene
import WatchwordKit
import WatchwordModel
import WatchwordStore

/// A `VaultSession` with hygiene on, over fakes: the network is a `FakeHTTPClient` answering as
/// `SimulatedPwnedPasswords` would, and the device-local records are an `InMemoryDeviceLocalStore` a test can read
/// as someone at rest would (docs/02-architecture.md §13.8).
public struct HygieneSessionFixture: Sendable {
    public let session: VaultSession
    public let store: any RecordStore
    public let keychain: FakeKeychain
    public let clock: FakeClock
    public let http: FakeHTTPClient
    public let local: InMemoryDeviceLocalStore
    public let biometrics: FakeBiometricGate

    public init(
        breached: [String: UInt32] = ["password": 3_861_493, "123456": 37_359_195],
        store: any RecordStore = InMemoryRecordStore(), keychain: FakeKeychain = FakeKeychain(),
        clock: FakeClock = FakeClock(), http: FakeHTTPClient? = nil, local: InMemoryDeviceLocalStore? = nil,
        biometrics: FakeBiometricGate = FakeBiometricGate(), seed: UInt64 = 31, scanPolicy: ScanPolicy = .standard
    ) async {
        let suppliedHTTP = http
        let http = suppliedHTTP ?? FakeHTTPClient()
        if suppliedHTTP == nil {
            let simulated = SimulatedPwnedPasswords(breached: breached)
            await http.respond { simulated.reply(to: $0) }
        }
        let local = local ?? InMemoryDeviceLocalStore()
        self.store = store
        self.keychain = keychain
        self.clock = clock
        self.http = http
        self.local = local
        self.biometrics = biometrics
        let seed = TestEnvironment.seed(fallback: 0) &+ seed
        session = VaultSession(
            store: store, keychain: keychain, biometrics: biometrics, clock: clock,
            configuration: VaultConfiguration(
                appVersion: TestVault.appVersion, kdf: .fixed(.baseline),
                hygiene: HygieneSettings(
                    http: http, userAgent: HygieneUserAgent(version: "1.0")!, localStore: local,
                    scanPolicy: scanPolicy)),
            deviceKeys: KeychainDeviceKeyStore(keychain: keychain, random: SeededGenerator(seed: seed &+ 0x5EED)),
            random: SeededGenerator(seed: seed))
    }

    /// The same store, Keychain, clock, network and local records, seen by a new session: a relaunch.
    public func relaunched(seed: UInt64 = 47) async -> HygieneSessionFixture {
        await HygieneSessionFixture(
            breached: [:], store: store, keychain: keychain, clock: clock, http: http, local: local,
            biometrics: biometrics, seed: seed)
    }

    /// Hygiene settings over a fresh `FakeHTTPClient` that answers as `SimulatedPwnedPasswords` would, and a fresh
    /// device-local store: for a `TestVault` that should check passwords (one per device).
    public static func settings(
        breached: [String: UInt32] = ["password": 3_861_493, "123456": 37_359_195], scanPolicy: ScanPolicy = .standard
    ) async -> (settings: HygieneSettings, http: FakeHTTPClient) {
        let http = FakeHTTPClient()
        let simulated = SimulatedPwnedPasswords(breached: breached)
        await http.respond { simulated.reply(to: $0) }
        let settings = HygieneSettings(
            http: http, userAgent: HygieneUserAgent(version: "1.0")!, localStore: InMemoryDeviceLocalStore(),
            scanPolicy: scanPolicy)
        return (settings, http)
    }

    /// Runs `session`'s scheduled step until nothing is due now, advancing `clock` past each wait (at most `limit`
    /// steps). Returns the outcomes of the scans it ran.
    @discardableResult
    public static func scanUntilIdle(_ session: VaultSession, clock: FakeClock, limit: Int = 64) async throws
        -> [ScanOutcome]
    {
        var outcomes: [ScanOutcome] = []
        for _ in 0..<limit {
            switch try await session.runHygieneStep() {
            case .scanned(_, let outcome): outcomes.append(outcome)
            case .wait(let until, _): await clock.set(until.addingTimeInterval(1))
            case .idle: return outcomes
            }
        }
        return outcomes
    }

    /// A login with one password, scoped to `host`.
    public static func login(_ vaultID: UUID, title: String, host: String, password: String) -> Item {
        Item(
            vaultID: vaultID, title: title, scopes: [ServiceScope(host: host)],
            fields: [
                Field(kind: .username, label: "Username", value: "pat@example.com"),
                Field(kind: .password, label: "Password", value: password),
            ])
    }

    /// Runs the scheduled step until nothing is due now, advancing the clock past each wait the scheduler gives (at
    /// most `limit` steps). Returns the outcomes of the scans it ran.
    @discardableResult
    public func scanUntilIdle(limit: Int = 64) async throws -> [ScanOutcome] {
        var outcomes: [ScanOutcome] = []
        for _ in 0..<limit {
            switch try await session.runHygieneStep() {
            case .scanned(_, let outcome): outcomes.append(outcome)
            case .wait(let until, _): await clock.set(until.addingTimeInterval(1))
            case .idle: return outcomes
            }
        }
        return outcomes
    }
}
