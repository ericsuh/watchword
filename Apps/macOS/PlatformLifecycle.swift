import AppKit
import Combine
import WatchwordPresentation

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
    /// The Mac has no app-switcher snapshot to hide from (F5.7's cover is iOS's). What it does have: a revealed secret
    /// is hidden again whenever the app resigns active (`ScreenPrivacy`), and every window is excluded from screen
    /// capture and from state restoration (`WindowProtection`, Z95, Z96). `onTerminate` runs in
    /// `applicationWillTerminate`, before the process ends.
    @MainActor
    static func installPrivacyShield(_ privacy: ScreenPrivacy, onTerminate: @escaping @MainActor @Sendable () -> Void) {
        MacAppDelegate.terminationHandler = onTerminate
        WindowProtection.protectAll()
        #if DEBUG
            // A UI-test runner on the Mac can take activation from the app mid-test; revealed values stay put there.
            if AppEnvironment.isUITestLaunch { return }
        #endif
        NotificationCenter.default.addObserver(
            forName: NSApplication.didResignActiveNotification, object: nil, queue: .main
        ) { _ in
            MainActor.assumeIsolated { privacy.resignedActive() }
        }
    }
}

/// Every window of the app, sheets and panels included, is left out of screen capture and screen sharing
/// (`sharingType = .none`: a shared screen or recording shows it blank; F5.7, Z95) and is not restorable, so AppKit
/// never writes its state, or a picture of it, under `Saved Application State` at a quit or logout with the vault
/// unlocked (Z96). Applied to every window whenever one becomes key or main. A Debug `--uitest` launch keeps
/// windows capturable, so the screenshot tour and XCUITest's failure screenshots still show them.
@MainActor
enum WindowProtection {
    static func protectAll() {
        for window in NSApplication.shared.windows {
            window.isRestorable = false
            #if DEBUG
                if AppEnvironment.isUITestLaunch { continue }
            #endif
            window.sharingType = .none
        }
    }
}

/// Quitting with the last window, so the vault's keys cannot outlive every window of the app (F5.5), and on the way
/// out dropping what the screen models hold, sweeping the staging folder (Z80) and clearing our clipboard copy, since
/// the 60-second clear runs in this process (F5.6).
@MainActor
final class MacAppDelegate: NSObject, NSApplicationDelegate {
    /// The app model's `prepareForTermination`, set when it starts monitoring.
    static var terminationHandler: (@MainActor @Sendable () -> Void)?

    #if DEBUG
        /// The appearance the screenshot tour asked for (`AppEnvironment.uiTestAppearance`). The application's
        /// appearance, rather than one window's, so sheets and dialogs follow it too.
        func applicationWillFinishLaunching(_ notification: Notification) {
            if let appearance = AppEnvironment.uiTestAppearance() {
                NSApplication.shared.appearance = NSAppearance(named: appearance == .dark ? .darkAqua : .aqua)
            }
        }
    #endif

    func applicationDidFinishLaunching(_ notification: Notification) {
        let center = NotificationCenter.default
        for name in [NSWindow.didBecomeKeyNotification, NSWindow.didBecomeMainNotification] {
            center.addObserver(forName: name, object: nil, queue: .main) { _ in
                MainActor.assumeIsolated { WindowProtection.protectAll() }
            }
        }
        WindowProtection.protectAll()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationWillTerminate(_ notification: Notification) {
        Self.terminationHandler?()
        StagingFolder.standard.sweep()
        Clipboard.clearIfOurs()
    }
}
