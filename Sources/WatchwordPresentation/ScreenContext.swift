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
        entries.removeAll { $0.model == nil }
        for entry in entries { entry.model?.dropOnLock() }
    }

    /// Stops listening to the session.
    public func stop() {
        watch?.cancel()
        watch = nil
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
