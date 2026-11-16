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

    public init(
        session: VaultSession, recordActivity: @escaping @MainActor @Sendable () -> Void = {},
        didLock: @escaping @MainActor @Sendable () -> Void = {}
    ) {
        self.session = session
        self.recordActivity = recordActivity
        self.didLock = didLock
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
