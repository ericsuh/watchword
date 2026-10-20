import SwiftUI

/// Host process for the app-hosted Keychain tests (`WatchwordKeychainTests` in Apps/project.yml). It does nothing
/// itself: it exists so the hosted test bundle runs in a signed process that carries a `keychain-access-groups`
/// entitlement, which the data-protection Keychain requires and `swift test` cannot have.
@main
struct KeychainHostApp: App {
    var body: some Scene {
        WindowGroup { Text("Watchword Keychain test host") }
    }
}
