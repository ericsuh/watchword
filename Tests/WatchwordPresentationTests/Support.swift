import Foundation
import WatchwordKit
import WatchwordModel
import WatchwordPresentation
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
