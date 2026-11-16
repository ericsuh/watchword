import Foundation
import WatchwordKit
import WatchwordPlatform
import WatchwordStore
import WatchwordSync

/// Builds the `VaultSession` and its ports for this launch (docs/02-architecture.md §15).
///
/// Production wiring: the SQLite store in the App Group container, the system Keychain in the shared access group, and
/// LocalAuthentication. Debug builds launched with `--uitest` instead use in-memory ports and the KDF floor, so UI tests
/// never touch a real vault or Keychain (docs/04-test-plan.md §2), and sync over an in-memory transport shared with a
/// simulated second device (`UITestPeer`). That switch does not exist in Release builds.
///
/// Production builds do not sync yet: the CloudKit and iCloud Drive transports are milestone 3's open work, and the
/// session is built without `SyncSettings` until one exists.
enum AppEnvironment {
    case ready(VaultSession)
    #if DEBUG
        /// A UI-test launch: in-memory ports, and another device of the same account the test drives from Settings.
        case uiTest(VaultSession, UITestPeer)
    #endif
    /// The App Group container is missing (an unsigned build, or a provisioning problem).
    case unavailable(String)

    static let keychainService = "com.ericsuh.Watchword"

    static var appVersion: String {
        let info = Bundle.main.infoDictionary ?? [:]
        let version = info["CFBundleShortVersionString"] as? String ?? "0"
        let build = info["CFBundleVersion"] as? String ?? "0"
        return "\(version) (\(build))"
    }

    #if DEBUG
        /// The appearance a UI-test launch asks to be drawn in whatever the system's is: `--uitest-appearance=light`
        /// or `--uitest-appearance=dark`, beside `--uitest`. The screenshot tour passes one for every set it captures
        /// (docs/04-test-plan.md §5.1), so a set named light is light on a machine in Dark Mode, and a dark set needs
        /// no setting changed. Without the argument, or with any other value, the app follows the system, as every
        /// other UI test does. Like `--uitest` itself, the switch does not exist in Release builds, and it changes
        /// nothing but colours.
        enum UITestAppearance: String {
            case light
            case dark
        }

        static func uiTestAppearance(arguments: [String] = ProcessInfo.processInfo.arguments) -> UITestAppearance? {
            let prefix = "--uitest-appearance="
            guard arguments.contains("--uitest"), let argument = arguments.last(where: { $0.hasPrefix(prefix) }) else {
                return nil
            }
            return UITestAppearance(rawValue: String(argument.dropFirst(prefix.count)))
        }
    #endif

    static func make(arguments: [String] = ProcessInfo.processInfo.arguments) -> AppEnvironment {
        #if DEBUG
            if arguments.contains("--uitest") {
                let store = InMemoryRecordStore()
                let keychain = InMemoryKeychainStore()
                let transport = InMemorySyncTransport()
                return .uiTest(
                    VaultSession(
                        store: store,
                        keychain: keychain,
                        biometrics: UnavailableBiometricGate(),
                        configuration: VaultConfiguration(appVersion: appVersion, kdf: .fixed(.baseline)),
                        sync: SyncSettings(state: InMemorySyncStateStore(), transport: transport)
                    ),
                    UITestPeer(transport: transport))
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
