import Foundation
import WatchwordEnvelope
import WatchwordKit
import WatchwordModel
import WatchwordPresentation
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

/// A context over `session` that counts activity and locks, so a test can see a model report both.
@MainActor
final class ContextProbe {
    private(set) var activity = 0
    private(set) var locks = 0

    func context(_ session: VaultSession) -> ScreenContext {
        ScreenContext(
            session: session, recordActivity: { [weak self] in self?.activity += 1 },
            didLock: { [weak self] in self?.locks += 1 })
    }
}

func login(_ vaultID: UUID, _ title: String, host: String, username: String, password: String) -> Item {
    Item(
        vaultID: vaultID, title: title, scopes: [ServiceScope(host: host)],
        fields: [
            Field(kind: .username, label: "Username", value: username),
            Field(kind: .password, label: "Password", value: password),
        ])
}

/// Two devices of one account over one transport; the first may be built with its own sync configuration.
struct TwoDevices {
    let transport: InMemorySyncTransport
    let first: TestVault
    let second: TestVault

    static let secondID = UUID(uuid: (0xD0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0xB2))

    static func make(firstConfiguration: SyncConfiguration? = nil) async throws -> TwoDevices {
        let transport = InMemorySyncTransport()
        let settings =
            firstConfiguration.map {
                SyncSettings(state: InMemorySyncStateStore(), transport: transport, configuration: $0)
            }
            ?? SyncSettings(state: InMemorySyncStateStore(), transport: transport)
        let first = TestVault(sync: settings, seed: 71, deviceName: "Pat's Mac")
        try await first.createAccount()
        let second = try await first.enrolledDevice(deviceID: secondID, over: transport, name: "Pat's iPad")
        try await second.session.unlock(password: TestVault.password)
        // The new device's registration goes out with its first sync; the first device learns of it with its own.
        try await second.session.sync()
        try await first.session.sync()
        return TwoDevices(transport: transport, first: first, second: second)
    }
}

/// Counts the locks a `LockSignal` reported to it.
@MainActor
final class LockProbe: LockSensitive {
    private(set) var drops = 0

    func dropOnLock() { drops += 1 }
}

/// A record store that counts its reads of a vault's records and, once armed, locks a session at the `n`-th read from
/// then and waits there until `until` holds (the lock's signal has reached the screen models), so that a lock lands
/// at a chosen point of a model's work. Otherwise an `InMemoryRecordStore`.
actor LockingStore: RecordStore {
    private let base = InMemoryRecordStore()
    private(set) var reads = 0
    private var armed: (read: Int, session: VaultSession, until: @Sendable () async -> Bool)?

    func resetCount() { reads = 0 }

    func arm(atRead read: Int, _ session: VaultSession, until: @escaping @Sendable () async -> Bool) {
        reads = 0
        armed = (read, session, until)
    }

    func loadAccount() async throws -> AccountRecord? { try await base.loadAccount() }
    func record(_ key: RecordKey) async throws -> StoredRecord? { try await base.record(key) }

    func records(in vaultID: UUID, kind: EnvelopeKind) async throws -> [StoredRecord] {
        reads += 1
        if let armed, armed.read == reads {
            self.armed = nil
            await armed.session.lock()
            for _ in 0..<10_000 where !(await armed.until()) { await Task.yield() }
        }
        return try await base.records(in: vaultID, kind: kind)
    }

    func commit(_ change: StoreChange) async throws { try await base.commit(change) }
    func eraseAll() async throws { await base.eraseAll() }
}
