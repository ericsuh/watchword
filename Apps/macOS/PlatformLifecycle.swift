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
