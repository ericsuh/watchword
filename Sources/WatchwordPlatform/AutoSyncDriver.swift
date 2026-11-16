import Foundation
import WatchwordKit
import WatchwordSync

/// How a sync the driver started ended, as `AutoSyncPolicy` needs to know it.
public enum AutoSyncOutcome: Sendable, Hashable {
    case succeeded
    case failed
    /// The transport asked for a wait (`SyncTransportError.rateLimited`).
    case throttled(retryAfter: TimeInterval?)

    /// The outcome of a sync that returned `report`: a transport that stopped the sync is a failure, a throttled one
    /// with the wait it asked for.
    public init(_ report: AccountSyncReport) {
        if case .rateLimited(let wait)? = report.transportFailure {
            self = .throttled(retryAfter: wait)
        } else if report.transportUnavailable {
            self = .failed
        } else {
            self = .succeeded
        }
    }

    /// The outcome of a sync that threw `error`.
    public init(_ error: any Error) {
        if let error = error as? SyncTransportError, case .rateLimited(let wait) = error {
            self = .throttled(retryAfter: wait)
        } else {
            self = .failed
        }
    }
}

/// Runs `AutoSyncPolicy` (docs/02-architecture.md §7.9): the timer the policy leaves to the app, and nothing else.
///
/// The app records what happens — `unlocked`, `locked`, `localChange`, and `remoteChangeHint` from a
/// `SyncFolderPresenter` or a CloudKit push — and the driver asks the policy, starts the sync it calls for through
/// `sync`, records how it ended, and arms one timer for the date a `.wait` names. Every decision stays in the policy, a
/// pure function tested on its own; the driver adds no rule of its own. While a sync runs, events are recorded and the
/// next decision waits for it to end. `stop()` cancels the timer; a sync already started runs to its end.
///
/// Time comes from `now` and `sleep`, so tests drive it with a manual clock and nothing sleeps. Portable (no Apple
/// framework), so it is tested on Linux.
///
/// Not wired into the app: production builds do not sync yet (docs/03-implementation-plan.md, milestone 3).
public actor AutoSyncDriver {
    public typealias Sync = @Sendable (AutoSyncMode) async -> AutoSyncOutcome
    /// Returns once `date` has come, or throws when the task is cancelled.
    public typealias Sleep = @Sendable (Date) async throws -> Void

    public let settings: AutoSyncSettings
    private let now: @Sendable () -> Date
    private let sleep: Sleep
    private let sync: Sync
    public private(set) var state = AutoSyncState()
    private var timer: Task<Void, Never>?
    private var stopped = false

    public init(
        settings: AutoSyncSettings = .standard, now: @escaping @Sendable () -> Date = { Date() },
        sleep: @escaping Sleep = AutoSyncDriver.systemSleep, sync: @escaping Sync
    ) {
        self.settings = settings
        self.now = now
        self.sleep = sleep
        self.sync = sync
    }

    /// `Task.sleep` until `date` on the system's clock.
    public static let systemSleep: Sleep = { date in
        let seconds = max(0, date.timeIntervalSinceNow)
        try await Task.sleep(nanoseconds: UInt64(min(seconds, 86_400) * 1_000_000_000))
    }

    /// Records an event the app saw and decides again. `syncStarted`, `syncSucceeded`, `syncFailed` and
    /// `syncThrottled` are the driver's own to record, for the syncs it starts; record a sync the person started with
    /// `syncStarted` and its outcome with `finished(_:)`.
    public func record(_ event: AutoSyncEvent) {
        AutoSyncPolicy.record(event, at: now(), in: &state)
        decide()
    }

    /// Records how a sync ended, whoever started it, and decides again.
    public func finished(_ outcome: AutoSyncOutcome) {
        let event: AutoSyncEvent
        switch outcome {
        case .succeeded: event = .syncSucceeded
        case .failed: event = .syncFailed
        case .throttled(let wait): event = .syncThrottled(retryAfter: wait)
        }
        AutoSyncPolicy.record(event, at: now(), in: &state)
        decide()
    }

    public func stop() {
        stopped = true
        timer?.cancel()
        timer = nil
    }

    private func decide() {
        timer?.cancel()
        timer = nil
        guard !stopped, !state.inFlight else { return }
        switch AutoSyncPolicy.decide(now: now(), state: state, settings: settings) {
        case .sync(let mode, _):
            AutoSyncPolicy.record(.syncStarted, at: now(), in: &state)
            let sync = sync
            Task {
                let outcome = await sync(mode)
                self.finished(outcome)
            }
        case .wait(until: let date?):
            let sleep = sleep
            timer = Task {
                do { try await sleep(date) } catch { return }
                self.timerFired()
            }
        case .wait(until: nil):
            break
        }
    }

    private func timerFired() {
        guard !Task.isCancelled else { return }
        timer = nil
        decide()
    }
}
