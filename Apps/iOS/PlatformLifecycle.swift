import Combine
import SwiftUI
import UIKit

enum PlatformLifecycle {
    /// The device is locking: protected data is about to become unavailable (PRD F5.5, "on screen lock").
    static var sleepNotifications: AnyPublisher<Notification, Never> {
        NotificationCenter.default.publisher(for: UIApplication.protectedDataWillBecomeUnavailableNotification)
            .eraseToAnyPublisher()
    }
}

extension PlatformLifecycle {
    /// Covers every window, sheets included, whenever the app is not active, so the app-switcher snapshot shows no
    /// item or Secret Key (PRD F5.7). A separate window above alert level is the only layer above SwiftUI's sheets.
    @MainActor
    static func installPrivacyShield() {
        let center = NotificationCenter.default
        center.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { PrivacyShield.show() }
        }
        center.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { PrivacyShield.hide() }
        }
    }
}

@MainActor
private enum PrivacyShield {
    static var window: UIWindow?

    static func show() {
        guard window == nil,
            let scene = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }).first
        else { return }
        let shield = UIWindow(windowScene: scene)
        shield.windowLevel = .alert + 1
        shield.rootViewController = UIHostingController(rootView: PrivacyCover())
        shield.isHidden = false
        window = shield
    }

    static func hide() {
        window?.isHidden = true
        window = nil
    }
}
