import Foundation
import WatchwordKit
import WatchwordPlatform
import WatchwordStore

/// Builds the `VaultSession` and its ports for this launch (docs/02-architecture.md §15).
///
/// Production wiring: the SQLite store in the App Group container, the system Keychain in the shared access group, and
/// LocalAuthentication. Debug builds launched with `--uitest` instead use in-memory ports and the KDF floor, so UI tests
/// never touch a real vault or Keychain (docs/04-test-plan.md §2). That switch does not exist in Release builds.
enum AppEnvironment {
    case ready(VaultSession)
    /// The App Group container is missing (an unsigned build, or a provisioning problem).
    case unavailable(String)

    static let keychainService = "com.ericsuh.Watchword"

    static var appVersion: String {
        let info = Bundle.main.infoDictionary ?? [:]
        let version = info["CFBundleShortVersionString"] as? String ?? "0"
        let build = info["CFBundleVersion"] as? String ?? "0"
        return "\(version) (\(build))"
    }

    static func make(arguments: [String] = ProcessInfo.processInfo.arguments) -> AppEnvironment {
        #if DEBUG
            if arguments.contains("--uitest") {
                return .ready(
                    VaultSession(
                        store: InMemoryRecordStore(),
                        keychain: InMemoryKeychainStore(),
                        biometrics: UnavailableBiometricGate(),
                        configuration: VaultConfiguration(appVersion: appVersion, kdf: .fixed(.baseline))
                    ))
            }
        #endif
        let info = Bundle.main.infoDictionary ?? [:]
        guard let appGroup = info["WatchwordAppGroup"] as? String, !appGroup.isEmpty,
            let url = AppContainer.databaseURL(appGroup: appGroup)
        else {
            return .unavailable(
                "Watchword cannot reach its shared storage. This build is missing its App Group entitlement.")
        }
        do {
            let store = try SQLiteRecordStore(url: url)
            let keychainGroup = (info["WatchwordKeychainGroup"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            return .ready(
                VaultSession(
                    store: store,
                    keychain: SystemKeychainStore(service: keychainService, accessGroup: keychainGroup),
                    biometrics: LocalAuthenticationGate(),
                    configuration: VaultConfiguration(appVersion: appVersion)
                ))
        } catch {
            return .unavailable("Watchword could not open its vault database.")
        }
    }
}
