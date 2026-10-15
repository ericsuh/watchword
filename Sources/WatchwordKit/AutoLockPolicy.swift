import Foundation

/// Auto-lock settings (PRD F5.5).
public struct AutoLockSettings: Sendable, Hashable, Codable {
    /// Lock after this long without activity. Default 5 minutes on iOS, 10 on macOS.
    public var idleTimeout: TimeInterval
    /// Lock when returning from the background after at least this long (iOS). Zero locks on every backgrounding.
    public var backgroundGracePeriod: TimeInterval
    /// Lock when the screen locks or the Mac sleeps.
    public var lockOnSleep: Bool

    public init(idleTimeout: TimeInterval, backgroundGracePeriod: TimeInterval = 0, lockOnSleep: Bool = true) {
        self.idleTimeout = idleTimeout
        self.backgroundGracePeriod = backgroundGracePeriod
        self.lockOnSleep = lockOnSleep
    }

    public static let iOSDefault = AutoLockSettings(idleTimeout: 5 * 60)
    public static let macOSDefault = AutoLockSettings(idleTimeout: 10 * 60)

    public static var platformDefault: AutoLockSettings {
        #if os(macOS)
            macOSDefault
        #else
            iOSDefault
        #endif
    }
}

/// Something that may end an unlocked session.
public enum AutoLockEvent: Sendable, Hashable {
    /// A periodic check while the app is in use.
    case tick
    /// The app moved to the background.
    case enteredBackground
    /// The app is returning to the foreground.
    case enteringForeground
    /// The screen locked or the system is going to sleep.
    case systemSleep
}

public enum LockReason: Sendable, Hashable {
    case idleTimeout
    case backgrounded
    case systemSleep
    case requested
}

/// Auto-lock as a pure function of the clock and the last events (docs/02-architecture.md §10), so it is tested by
/// advancing a fake clock rather than by sleeping (CLAUDE.md, "Tests").
public enum AutoLockPolicy {
    public static func decide(
        event: AutoLockEvent,
        now: Date,
        lastActivity: Date,
        backgroundedAt: Date?,
        settings: AutoLockSettings
    ) -> LockReason? {
        // A clock that moved backwards cannot show that the timeout has *not* elapsed; lock (fail closed).
        if now < lastActivity { return .idleTimeout }
        switch event {
        case .tick:
            return now.timeIntervalSince(lastActivity) >= settings.idleTimeout ? .idleTimeout : nil
        case .enteredBackground:
            return settings.backgroundGracePeriod <= 0 ? .backgrounded : nil
        case .enteringForeground:
            if now.timeIntervalSince(lastActivity) >= settings.idleTimeout { return .idleTimeout }
            guard let backgroundedAt else { return nil }
            if now < backgroundedAt { return .backgrounded }
            return now.timeIntervalSince(backgroundedAt) >= settings.backgroundGracePeriod ? .backgrounded : nil
        case .systemSleep:
            return settings.lockOnSleep ? .systemSleep : nil
        }
    }
}
