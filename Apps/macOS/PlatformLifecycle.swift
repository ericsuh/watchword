import AppKit
import Combine

enum PlatformLifecycle {
    /// The Mac is sleeping or its screen is locking (PRD F5.5).
    static var sleepNotifications: AnyPublisher<Notification, Never> {
        let workspace = NSWorkspace.shared.notificationCenter
        return Publishers.Merge3(
            workspace.publisher(for: NSWorkspace.willSleepNotification),
            workspace.publisher(for: NSWorkspace.screensDidSleepNotification),
            DistributedNotificationCenter.default().publisher(for: Notification.Name("com.apple.screenIsLocked"))
        )
        .eraseToAnyPublisher()
    }
}

extension PlatformLifecycle {
    /// The Mac has no app-switcher snapshot to hide from (F5.7 is an iOS requirement).
    @MainActor
    static func installPrivacyShield() {}
}

/// Quitting with the last window, so the vault's keys cannot outlive every window of the app (F5.5), and clearing our
/// clipboard copy on the way out, since the 60-second clear runs in this process (F5.6).
@MainActor
final class MacAppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationWillTerminate(_ notification: Notification) {
        Clipboard.clearIfOurs()
    }
}
