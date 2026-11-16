import Foundation

/// When to sync without being asked (PRD F7.5, N3).
public struct AutoSyncSettings: Sendable, Hashable, Codable {
    /// Sync this long after the last local save, so a burst of edits is one sync.
    public var saveDebounce: TimeInterval
    /// A save is never kept waiting longer than this, however long the burst.
    public var maximumSaveDelay: TimeInterval
    /// Sync this long after the transport says something changed remotely; further hints meanwhile are the same sync.
    public var hintDelay: TimeInterval
    /// While unlocked, sync at least this often.
    public var periodicInterval: TimeInterval
    /// While locked, download at least this often (no merging and no publishing without keys, §7.4).
    public var lockedInterval: TimeInterval
    /// No two automatic syncs start closer together than this, whatever triggers them.
    public var minimumInterval: TimeInterval
    /// After a failed sync, wait this long before the next; doubled for every further failure in a row.
    public var backoffBase: TimeInterval
    /// The longest any backoff grows.
    public var backoffMaximum: TimeInterval

    public init(
        saveDebounce: TimeInterval = 5, maximumSaveDelay: TimeInterval = 60, hintDelay: TimeInterval = 2,
        periodicInterval: TimeInterval = 15 * 60, lockedInterval: TimeInterval = 60 * 60,
        minimumInterval: TimeInterval = 10, backoffBase: TimeInterval = 30, backoffMaximum: TimeInterval = 60 * 60
    ) {
        self.saveDebounce = saveDebounce
        self.maximumSaveDelay = maximumSaveDelay
        self.hintDelay = hintDelay
        self.periodicInterval = periodicInterval
        self.lockedInterval = lockedInterval
        self.minimumInterval = minimumInterval
        self.backoffBase = backoffBase
        self.backoffMaximum = backoffMaximum
    }

    public static let standard = AutoSyncSettings()
}

/// Something the app tells the policy about.
public enum AutoSyncEvent: Sendable, Hashable {
    /// The vault was unlocked: merge what was downloaded while locked, publish what is waiting.
    case unlocked
    case locked
    /// The person saved, trashed, moved or deleted something on this device.
    case localChange
    /// The transport says something changed remotely (a CloudKit push, a file presenter callback).
    case remoteChangeHint
    /// A sync the policy asked for (or the person did) has started.
    case syncStarted
    case syncSucceeded
    /// The sync threw, or its report says the transport was unavailable.
    case syncFailed
    /// A failed sync whose transport asked the client to wait (`SyncTransportError.rateLimited`): a failure, whose
    /// backoff is at least the wait asked for, held to `backoffMaximum` (the store's word is a claim, A1).
    case syncThrottled(retryAfter: TimeInterval?)
}

public enum AutoSyncMode: Sendable, Hashable {
    /// Download, merge, publish, maintain.
    case full
    /// Download and check signatures only: the vault is locked (§7.4).
    case downloadOnly
}

public enum AutoSyncReason: Sendable, Hashable {
    case unlocked
    case localChange
    case remoteChange
    case periodic
    /// The last sync failed and its backoff has passed.
    case retry
}

public enum AutoSyncDecision: Sendable, Hashable {
    case sync(AutoSyncMode, AutoSyncReason)
    /// Nothing to do yet. Ask again at `until`, or, when it is `nil`, at the next event.
    case wait(until: Date?)
}

/// What the policy remembers between decisions. A value, so a test builds any history directly.
public struct AutoSyncState: Sendable, Hashable {
    public var isUnlocked = false
    public var inFlight = false
    /// An unlock no sync has followed yet.
    public var unlockPending = false
    /// The first and the latest local change no sync has started after.
    public var firstUnsyncedChangeAt: Date?
    public var lastUnsyncedChangeAt: Date?
    /// The first remote-change hint no sync has started after.
    public var hintAt: Date?
    public var lastStartedAt: Date?
    public var lastFailedAt: Date?
    public var consecutiveFailures = 0
    /// The wait the transport asked for after the last failure, already held within the policy's bounds.
    public var requestedWait: TimeInterval?

    public init() {}
}

/// Automatic syncing as a pure function of the clock and what has happened (docs/02-architecture.md §7.9), in the
/// style of `AutoLockPolicy`: no timers and no threads here. The app records events with `record`, asks `decide`,
/// and arms one timer for the date a `.wait` names; tests advance a clock instead of sleeping.
///
/// - After an unlock: at once, whatever else is pending (the person is waiting, and what was downloaded while locked
///   can now be merged).
/// - After a local change: once `saveDebounce` has passed without another, and never later than `maximumSaveDelay`
///   after the first.
/// - On a remote-change hint: after `hintDelay`, coalescing a burst.
/// - Periodically: every `periodicInterval` while unlocked, every `lockedInterval` while locked.
/// - After a failure: nothing until the backoff passes, then a retry; the backoff doubles with each failure in a row
///   up to `backoffMaximum`, and any success clears it.
/// - While locked, every sync is download-only: merging and publishing need keys (§7.4).
/// - A transport that asks for a wait (CloudKit's `retryAfterSeconds`) lengthens that backoff to the wait, never
///   beyond `backoffMaximum`. An unlock still syncs at once: the person is waiting, and it is one request.
///
/// A clock that moved backwards cannot show that an interval has *not* passed, so every wait measured from a time
/// in the future is treated as over. Syncing early costs a request; waiting for ever would cost the data.
public enum AutoSyncPolicy {
    public static func record(_ event: AutoSyncEvent, at now: Date, in state: inout AutoSyncState) {
        switch event {
        case .unlocked:
            state.isUnlocked = true
            state.unlockPending = true
        case .locked:
            state.isUnlocked = false
            state.unlockPending = false
        case .localChange:
            if state.firstUnsyncedChangeAt == nil { state.firstUnsyncedChangeAt = now }
            state.lastUnsyncedChangeAt = now
        case .remoteChangeHint:
            if state.hintAt == nil { state.hintAt = now }
        case .syncStarted:
            state.inFlight = true
            state.lastStartedAt = now
            // What triggered this sync is consumed by it; a change or a hint that arrives while it runs is new.
            state.unlockPending = false
            state.hintAt = nil
            // Local changes are published only by a sync with keys.
            if state.isUnlocked {
                state.firstUnsyncedChangeAt = nil
                state.lastUnsyncedChangeAt = nil
            }
        case .syncSucceeded:
            state.inFlight = false
            state.consecutiveFailures = 0
            state.lastFailedAt = nil
            state.requestedWait = nil
        case .syncFailed:
            state.inFlight = false
            state.consecutiveFailures += 1
            state.lastFailedAt = now
            state.requestedWait = nil
        case .syncThrottled(let retryAfter):
            state.inFlight = false
            state.consecutiveFailures += 1
            state.lastFailedAt = now
            state.requestedWait = retryAfter.map { $0.isFinite ? max(0, $0) : 0 }
        }
    }

    public static func decide(now: Date, state: AutoSyncState, settings: AutoSyncSettings = .standard)
        -> AutoSyncDecision
    {
        guard !state.inFlight else { return .wait(until: nil) }
        let mode: AutoSyncMode = state.isUnlocked ? .full : .downloadOnly
        // The person just unlocked: nothing is worth making them wait for.
        if state.isUnlocked, state.unlockPending { return .sync(.full, .unlocked) }

        // Nothing automatic before the backoff and the minimum spacing have passed.
        var notBefore = Date.distantPast
        if let started = state.lastStartedAt {
            notBefore = max(notBefore, elapsed(since: started, now: now, interval: settings.minimumInterval))
        }
        if state.consecutiveFailures > 0, let failed = state.lastFailedAt {
            notBefore = max(
                notBefore,
                elapsed(since: failed, now: now, interval: backoff(after: state, settings)))
        }

        var candidates: [(Date, AutoSyncReason)] = []
        if state.consecutiveFailures > 0 {
            candidates.append((notBefore, .retry))
        }
        if state.isUnlocked, let first = state.firstUnsyncedChangeAt, let last = state.lastUnsyncedChangeAt {
            let due = min(
                elapsed(since: last, now: now, interval: settings.saveDebounce),
                elapsed(since: first, now: now, interval: settings.maximumSaveDelay))
            candidates.append((due, .localChange))
        }
        if let hint = state.hintAt {
            candidates.append((elapsed(since: hint, now: now, interval: settings.hintDelay), .remoteChange))
        }
        let interval = state.isUnlocked ? settings.periodicInterval : settings.lockedInterval
        if let started = state.lastStartedAt {
            candidates.append((elapsed(since: started, now: now, interval: interval), .periodic))
        } else {
            candidates.append((Date.distantPast, .periodic))
        }

        // The earliest trigger decides; none can fire before `notBefore`.
        let (due, reason) = candidates.min { $0.0 < $1.0 }!
        let at = max(due, notBefore)
        return at <= now ? .sync(mode, reason) : .wait(until: at)
    }

    /// The backoff for `state`: the doubling backoff, or the transport's requested wait if that is longer, capped at
    /// `backoffMaximum` either way.
    public static func backoff(after state: AutoSyncState, _ settings: AutoSyncSettings) -> TimeInterval {
        let doubling = backoff(after: state.consecutiveFailures, settings)
        guard let requested = state.requestedWait else { return doubling }
        return min(settings.backoffMaximum, max(doubling, requested))
    }

    /// The backoff after `failures` failures in a row: `backoffBase` doubled each time, capped.
    public static func backoff(after failures: Int, _ settings: AutoSyncSettings) -> TimeInterval {
        guard failures > 0 else { return 0 }
        let doublings = min(failures - 1, 30)
        return min(settings.backoffMaximum, settings.backoffBase * Double(UInt64(1) << UInt64(doublings)))
    }

    /// When `interval` after `reference` is over. A reference in the future (the clock moved back) is over now.
    private static func elapsed(since reference: Date, now: Date, interval: TimeInterval) -> Date {
        reference > now ? Date.distantPast : reference.addingTimeInterval(max(0, interval))
    }
}
