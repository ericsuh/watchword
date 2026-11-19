import Foundation
import WatchwordKit

/// What every screen model is given: the session, and the app's two hooks (docs/02-architecture.md §15).
///
/// The models in this module hold what a screen shows and decide nothing about security: every refusal is the
/// session's, and a model only words it. They import portable modules only, so `swift test` runs them on Linux
/// against real `VaultSession`s, and the SwiftUI views in `Apps/` stay thin enough that what cannot be tested here is
/// layout.
public struct ScreenContext: Sendable {
    public let session: VaultSession
    /// Called on every action a person takes on a screen, so auto-lock measures idleness from it (PRD F5.5).
    public let recordActivity: @MainActor @Sendable () -> Void
    /// Called when a call found the vault locked: the app drops what it shows and returns to the unlock screen.
    public let didLock: @MainActor @Sendable () -> Void
    /// Every lock of the session, for models holding what must go with the keys (`LockSignal.watching`).
    public let locks: LockSignal?

    public init(
        session: VaultSession, recordActivity: @escaping @MainActor @Sendable () -> Void = {},
        didLock: @escaping @MainActor @Sendable () -> Void = {}, locks: LockSignal? = nil
    ) {
        self.session = session
        self.recordActivity = recordActivity
        self.didLock = didLock
        self.locks = locks
    }
}

/// A model that holds what must not outlive the vault's keys: decrypted values, typed passwords, an export's bytes.
@MainActor
public protocol LockSensitive: AnyObject {
    /// Drops all of it. Called on every lock of the session, whether or not any view is still showing the model.
    func dropOnLock()
}

/// Tells the screen models of every lock of the session (review of the account screens, finding 6), so that what
/// they hold goes with the keys and not only when the views that own them are torn down. Models register themselves
/// weakly; the signal never keeps one alive.
@MainActor
public final class LockSignal {
    private struct Entry {
        weak var model: (any LockSensitive)?
    }

    private var entries: [Entry] = []
    private var watch: Task<Void, Never>?
    /// How many times the signal has fired: work that stores what must go with the keys notes it before its awaits and
    /// stores nothing if it changed (review of round 10, Z183). It moves only when the watch runs on the main actor;
    /// `mark(_:)` adds the session's own count, which moves in `lock()` itself.
    public private(set) var generation = 0

    public init() {}

    /// A signal fired by `session.lockEvents()`: every lock, however it came about, from the moment this returns.
    public static func watching(_ session: VaultSession) async -> LockSignal {
        let signal = LockSignal()
        await signal.watch(session)
        return signal
    }

    /// Starts firing on every lock of `session`. Listening begins before this returns, so no lock after it is missed.
    public func watch(_ session: VaultSession) async {
        stop()
        let events = await session.lockEvents()
        watch = Task { [weak self] in
            for await _ in events {
                guard let self else { return }
                self.fire()
            }
        }
    }

    public func register(_ model: any LockSensitive) {
        entries.removeAll { $0.model == nil }
        entries.append(Entry(model: model))
    }

    /// Drops what every registered model holds. The app also calls it on its own lock paths; twice is harmless.
    public func fire() {
        generation &+= 1
        entries.removeAll { $0.model == nil }
        for entry in entries { entry.model?.dropOnLock() }
    }

    /// Stops listening to the session.
    public func stop() {
        watch?.cancel()
        watch = nil
    }

    /// Every lock so far: the signal's fires, and the session's own count (`VaultSession.lockCount`), which `lock()`
    /// moves before any listener hears of it (review of round 11, I1: a continuation the main actor ran ahead of the
    /// signal's watch found the generation unchanged).
    public struct Mark: Hashable, Sendable {
        let fires: Int
        let sessionLocks: UInt64
    }

    /// The locks so far, to compare with `unchanged(since:in:)` once the work is done.
    public func mark(_ session: VaultSession) async -> Mark {
        let sessionLocks = await session.lockCount
        return Mark(fires: generation, sessionLocks: sessionLocks)
    }

    /// Whether neither the signal nor the session has seen a lock since `mark`. Store what must go with the keys only
    /// straight after it answers `true`, with no suspension between: the session's count is read first and the fires
    /// last, so a lock after the read is one whose firing, still to run on the main actor, drops what was stored.
    public func unchanged(since mark: Mark, in session: VaultSession) async -> Bool {
        let sessionLocks = await session.lockCount
        return sessionLocks == mark.sessionLocks && generation == mark.fires
    }
}

/// The one way a model runs a session call: records activity, marks the screen busy, and turns a thrown error into
/// the sentence the screen shows (`ErrorWording`). A lock found on the way is passed to the app.
@MainActor
struct ScreenOperation {
    let context: ScreenContext

    /// Runs `body`, returning `nil` on success and the message to show otherwise. An empty message means the person
    /// cancelled something and nothing needs saying.
    func run(_ body: () async throws -> Void) async -> String? {
        context.recordActivity()
        do {
            try await body()
            return nil
        } catch {
            if case VaultError.locked = error { context.didLock() }
            return ErrorWording.message(for: error)
        }
    }
}

/// A short, stable, readable stand-in for an identifier the person has no name for: the first eight hexadecimal
/// digits of a UUID, as `1A2B3C4D`.
public func shortIdentifier(_ id: UUID) -> String {
    String(id.uuidString.prefix(8))
}
