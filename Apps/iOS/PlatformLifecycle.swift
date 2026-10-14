import Combine
import UIKit

enum PlatformLifecycle {
    /// The device is locking: protected data is about to become unavailable (PRD F5.5, "on screen lock").
    static var sleepNotifications: AnyPublisher<Notification, Never> {
        NotificationCenter.default.publisher(for: UIApplication.protectedDataWillBecomeUnavailableNotification)
            .eraseToAnyPublisher()
    }
}
