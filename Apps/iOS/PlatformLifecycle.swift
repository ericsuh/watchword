import Combine
import SwiftUI
import UIKit
import WatchwordPresentation

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
    /// Resigning active also hides every revealed secret again, and so does the screen starting to be recorded,
    /// mirrored or shared, as the scene's `sceneCaptureState` reports it (`ScreenPrivacy`, Z95). `onTerminate` runs
    /// synchronously when the system posts `willTerminateNotification`, which it does not for a suspended app.
    @MainActor
    static func installPrivacyShield(_ privacy: ScreenPrivacy, onTerminate: @escaping @MainActor @Sendable () -> Void) {
        let center = NotificationCenter.default
        center.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated {
                PrivacyShield.show()
                privacy.resignedActive()
            }
        }
        center.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { PrivacyShield.hide() }
        }
        center.addObserver(forName: UIApplication.willTerminateNotification, object: nil, queue: nil) { _ in
            MainActor.assumeIsolated { onTerminate() }
        }
        // Every scene reports for itself, those connected now and every one that connects later (an iPad window);
        // a disconnected one stops counting (Z130). `ScreenPrivacy` counts the screen captured while any one is.
        for case let scene as UIWindowScene in UIApplication.shared.connectedScenes {
            watchCapture(of: scene, privacy)
        }
        center.addObserver(forName: UIScene.willConnectNotification, object: nil, queue: .main) { notification in
            MainActor.assumeIsolated {
                guard let scene = notification.object as? UIWindowScene else { return }
                watchCapture(of: scene, privacy)
            }
        }
        center.addObserver(forName: UIScene.didDisconnectNotification, object: nil, queue: .main) { notification in
            MainActor.assumeIsolated {
                guard let scene = notification.object as? UIScene else { return }
                privacy.sceneDisconnected(AnyHashable(ObjectIdentifier(scene)))
            }
        }
    }

    @MainActor
    private static func watchCapture(of scene: UIWindowScene, _ privacy: ScreenPrivacy) {
        let id = ObjectIdentifier(scene)
        privacy.captureChanged(scene.traitCollection.sceneCaptureState == .active, in: AnyHashable(id))
        _ = scene.registerForTraitChanges([UITraitSceneCaptureState.self]) {
            (scene: UIWindowScene, _: UITraitCollection) in
            privacy.captureChanged(scene.traitCollection.sceneCaptureState == .active, in: AnyHashable(id))
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
