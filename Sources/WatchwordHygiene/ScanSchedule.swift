import Foundation

/// What the breach scanner remembers between launches: which version of each item it checked, when, and what the
/// answer was; which items' checks failed, and when; and where the weekly pass stands (PRD F9.2).
///
/// **This is derived from passwords** (a breach count all but names the password), so it is persisted only sealed,
/// under a key that is gone when the vault locks, exactly like an item: the session encodes it and seals it as a
/// local record, and `HygieneEngine` hands it out only while unlocked (docs/adr/0005-hibp-while-locked.md and its
/// amendment). It is per-device state and is not synced: writing a scan time into every item each week would turn
/// the scan into a weekly edit of the whole vault.
///
/// Nothing in it comes from a password directly: no hash, no prefix, no keyed token.
public struct ScanLedger: Hashable, Sendable {
    public static let maximumEntries = 200_000
    public static let maximumResultsPerEntry = 64
    public static let maximumFailureCount = 30

    /// A check that did not complete: which version of the item, when, and how often in a row.
    ///
    /// It is in the ledger, and not in the schedule's memory, because it has to last exactly as long as the results
    /// do. `ScanSchedule` sends an item whose check failed to the back of the queue; if that were forgotten at a
    /// lock (or when the process ends) while the backoff the failure caused was not, every unlock would ask for the
    /// same refused range first, back off, and reach no other item. The session carries the ledger across both, so
    /// the failure goes with it, and no item ID stays in memory while the vault is locked.
    public struct Failure: Hashable, Sendable {
        /// The version whose check failed. The time of its own (`notBefore`) holds this version only: an edit may
        /// have changed the password, and so the range.
        public var itemVersion: UInt64
        /// Failures in a row, from 1 to `maximumFailureCount`.
        public var count: Int
        /// When the item last failed: the later, the further back in the queue.
        public var failedAt: Date
        /// Set only for a failure that asking again cannot fix by itself: not before this.
        public var notBefore: Date?

        public init(itemVersion: UInt64, count: Int, failedAt: Date, notBefore: Date? = nil) {
            self.itemVersion = itemVersion
            self.count = min(max(1, count), ScanLedger.maximumFailureCount)
            self.failedAt = failedAt
            self.notBefore = notBefore
        }
    }

    public struct Entry: Hashable, Sendable {
        /// The item version whose passwords were checked. A result says nothing about any other version.
        public var itemVersion: UInt64
        public var scannedAt: Date
        /// Per password field.
        public var results: [UUID: PwnedPasswordResult]

        public init(itemVersion: UInt64, scannedAt: Date, results: [UUID: PwnedPasswordResult]) {
            self.itemVersion = itemVersion
            self.scannedAt = scannedAt
            self.results = results
        }
    }

    public var entries: [UUID: Entry]
    /// Items whose last check did not complete. An item leaves when a check of it completes, or when it goes.
    public var failures: [UUID: Failure]
    /// When the weekly pass in progress, or the last one, began.
    public var fullScanStartedAt: Date?
    /// When that pass finished; `nil` while it is in progress, which is how an interrupted pass is recognised and
    /// resumed at the next unlock.
    public var fullScanCompletedAt: Date?

    public init(
        entries: [UUID: Entry] = [:], fullScanStartedAt: Date? = nil, fullScanCompletedAt: Date? = nil,
        failures: [UUID: Failure] = [:]
    ) {
        self.entries = entries
        self.failures = failures
        self.fullScanStartedAt = fullScanStartedAt
        self.fullScanCompletedAt = fullScanCompletedAt
    }

    /// The oldest scan among `items`, or `nil` if any of them has never been scanned at its current version: how
    /// stale the report can be (ADR 0005, consequences).
    public func oldestScan(of items: [ScanCandidate]) -> Date? {
        var oldest: Date?
        for item in items {
            guard let entry = entries[item.id], entry.itemVersion == item.version else { return nil }
            oldest = min(oldest ?? entry.scannedAt, entry.scannedAt)
        }
        return oldest
    }
}

/// A breach count all but names the password, so a ledger prints as its size and nothing else (PRD N5). Encoding it
/// (to seal it) is the one way its contents leave the value.
extension ScanLedger: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "ScanLedger(\(entries.count) items, results withheld)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["items": entries.count], displayStyle: .struct) }
}

extension ScanLedger.Entry: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "ScanLedger.Entry(version \(itemVersion), results withheld)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["itemVersion": itemVersion], displayStyle: .struct) }
}

/// Encoded with explicit, encoder-independent shapes (whole seconds, a count where zero means "not found", entries
/// and failures sorted by item), and decoded with bounds. The session seals the encoding, so what is decoded has already been
/// authenticated; the bounds make a damaged or foreign blob a decoding error.
extension ScanLedger: Codable {
    private enum CodingKeys: String, CodingKey {
        case entries, failures, fullScanStartedAt, fullScanCompletedAt
    }

    private struct WireFailure: Codable {
        var item: UUID
        var version: UInt64
        var count: Int
        var failedAt: Int64
        var notBefore: Int64?
    }

    private struct WireEntry: Codable {
        var item: UUID
        var version: UInt64
        var scannedAt: Int64
        var fields: [UUID]
        var occurrences: [UInt32]
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let wire = try container.decode([WireEntry].self, forKey: .entries)
        guard wire.count <= Self.maximumEntries else { throw Self.corrupted(decoder, "too many entries") }
        var entries: [UUID: Entry] = [:]
        for entry in wire {
            guard entry.fields.count == entry.occurrences.count, entry.fields.count <= Self.maximumResultsPerEntry,
                entries[entry.item] == nil, let scannedAt = Self.date(entry.scannedAt)
            else { throw Self.corrupted(decoder, "entry") }
            var results: [UUID: PwnedPasswordResult] = [:]
            for (field, occurrences) in zip(entry.fields, entry.occurrences) {
                guard results[field] == nil else { throw Self.corrupted(decoder, "field listed twice") }
                results[field] = occurrences == 0 ? .notFound : .found(occurrences: occurrences)
            }
            entries[entry.item] = Entry(itemVersion: entry.version, scannedAt: scannedAt, results: results)
        }
        self.entries = entries
        // Absent in a ledger with no failures.
        let wireFailures = try container.decodeIfPresent([WireFailure].self, forKey: .failures) ?? []
        guard wireFailures.count <= Self.maximumEntries else { throw Self.corrupted(decoder, "too many failures") }
        var failures: [UUID: Failure] = [:]
        for failure in wireFailures {
            guard failures[failure.item] == nil, (1...Self.maximumFailureCount).contains(failure.count),
                let failedAt = Self.date(failure.failedAt)
            else { throw Self.corrupted(decoder, "failure") }
            var notBefore: Date?
            if let seconds = failure.notBefore {
                guard let date = Self.date(seconds) else { throw Self.corrupted(decoder, "failure") }
                notBefore = date
            }
            failures[failure.item] = Failure(
                itemVersion: failure.version, count: failure.count, failedAt: failedAt, notBefore: notBefore)
        }
        self.failures = failures
        fullScanStartedAt = try Self.optionalDate(container, .fullScanStartedAt, decoder)
        fullScanCompletedAt = try Self.optionalDate(container, .fullScanCompletedAt, decoder)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        let wire = entries.sorted { $0.key.uuidString < $1.key.uuidString }.map { id, entry in
            let fields = entry.results.keys.sorted { $0.uuidString < $1.uuidString }
            return WireEntry(
                item: id, version: entry.itemVersion, scannedAt: Self.seconds(entry.scannedAt), fields: fields,
                occurrences: fields.map { field in
                    if case .found(let occurrences) = entry.results[field] { return occurrences }
                    return 0
                })
        }
        try container.encode(wire, forKey: .entries)
        if !failures.isEmpty {
            let wireFailures = failures.sorted { $0.key.uuidString < $1.key.uuidString }.map { id, failure in
                WireFailure(
                    item: id, version: failure.itemVersion, count: failure.count,
                    failedAt: Self.seconds(failure.failedAt), notBefore: failure.notBefore.map(Self.seconds))
            }
            try container.encode(wireFailures, forKey: .failures)
        }
        try container.encodeIfPresent(fullScanStartedAt.map(Self.seconds), forKey: .fullScanStartedAt)
        try container.encodeIfPresent(fullScanCompletedAt.map(Self.seconds), forKey: .fullScanCompletedAt)
    }

    private static let secondsLimit: Int64 = 1 << 40

    private static func seconds(_ date: Date) -> Int64 {
        let seconds = date.timeIntervalSince1970.rounded(.down)
        guard seconds.isFinite else { return 0 }
        return Int64(min(max(seconds, 0), Double(secondsLimit - 1)))
    }

    private static func date(_ seconds: Int64) -> Date? {
        guard seconds >= 0, seconds < secondsLimit else { return nil }
        return Date(timeIntervalSince1970: Double(seconds))
    }

    private static func optionalDate(
        _ container: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys, _ decoder: any Decoder
    ) throws -> Date? {
        guard let seconds = try container.decodeIfPresent(Int64.self, forKey: key) else { return nil }
        guard let date = date(seconds) else { throw corrupted(decoder, "date") }
        return date
    }

    private static func corrupted(_ decoder: any Decoder, _ what: String) -> DecodingError {
        DecodingError.dataCorrupted(
            DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "scan ledger: " + what))
    }
}

/// An item the scanner should keep checked: one with at least one password, not in the trash.
public struct ScanCandidate: Hashable, Sendable {
    public let id: UUID
    public let version: UInt64

    public init(id: UUID, version: UInt64) {
        self.id = id
        self.version = version
    }
}

/// How hard the scanner may lean on the range API (PRD F9.2). The API is documented as not rate limited; the limits
/// here are manners, and they bound what a bug or a huge import can do.
public struct ScanPolicy: Hashable, Sendable {
    /// A full re-scan starts this long after the previous one started.
    public let fullScanInterval: TimeInterval
    /// The sustained rate: one range request per this many seconds.
    public let requestSpacing: TimeInterval
    /// Requests that may go at once for created and edited items, before the sustained rate applies.
    public let burst: Int
    /// The weekly pass adds a random wait of up to this long to each request, so a pass is not a metronome.
    public let maximumJitter: TimeInterval
    /// The wait after the first failed request; doubled for each failure in a row, up to `maximumBackoff`.
    public let initialBackoff: TimeInterval
    public let maximumBackoff: TimeInterval
    /// The wait before retrying an item whose range could not be used (too large, malformed, unexpected status);
    /// doubled each time, up to `itemRetryMaximum`. Other items go on being scanned meanwhile. (An item whose check
    /// failed for a reason that may pass, such as a 503, is not timed: it goes to the back of the queue.)
    public let itemRetryInitial: TimeInterval
    public let itemRetryMaximum: TimeInterval
    /// How far ahead of the clock a recorded time may be before it is treated as wrong.
    public let clockTolerance: TimeInterval

    public init(
        fullScanInterval: TimeInterval = 7 * 24 * 60 * 60, requestSpacing: TimeInterval = 2, burst: Int = 5,
        maximumJitter: TimeInterval = 3, initialBackoff: TimeInterval = 60, maximumBackoff: TimeInterval = 3600,
        itemRetryInitial: TimeInterval = 600, itemRetryMaximum: TimeInterval = 24 * 60 * 60,
        clockTolerance: TimeInterval = 300
    ) {
        // Held within sane bounds whatever is passed: a zero spacing would be a request loop.
        self.fullScanInterval = max(60 * 60, fullScanInterval)
        self.requestSpacing = min(max(0.25, requestSpacing), 3600)
        self.burst = min(max(1, burst), 50)
        self.maximumJitter = min(max(0, maximumJitter), 3600)
        self.initialBackoff = min(max(1, initialBackoff), 24 * 60 * 60)
        self.maximumBackoff = min(max(self.initialBackoff, maximumBackoff), 24 * 60 * 60)
        self.itemRetryInitial = min(max(1, itemRetryInitial), 7 * 24 * 60 * 60)
        self.itemRetryMaximum = min(max(self.itemRetryInitial, itemRetryMaximum), 7 * 24 * 60 * 60)
        self.clockTolerance = max(0, clockTolerance)
    }

    public static let standard = ScanPolicy()
}

/// Why an item is due, most urgent first.
public enum ScanReason: Int, Hashable, Sendable, Comparable {
    /// Never scanned: created here, or arrived by sync or import.
    case created = 0
    /// Scanned at an earlier version: edited here, or changed since the last scan (the after-unlock case).
    case changed = 1
    /// The weekly pass has not reached it yet.
    case weekly = 2

    public static func < (lhs: ScanReason, rhs: ScanReason) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public enum ScanWait: Hashable, Sendable {
    /// The scanner's own rate limit.
    case pacing
    /// A request failed, or the server said to stay away.
    case backoff
    /// Everything still due failed recently and is waiting for its own retry time.
    case retry
    /// `HygieneEngine.unlock` is still analysing the items it was given; nothing is decided on part of a vault.
    case analysing
}

public enum ScanDecision: Hashable, Sendable {
    /// Keys are not resident. Nothing may be hashed and nothing is due (ADR 0005).
    case locked
    /// Check this item now.
    case scan(item: UUID, reason: ScanReason)
    /// Something is due, but not before `until`.
    case wait(until: Date, ScanWait)
    /// Every candidate is current. The next full pass starts at `nextFullScanAt` if keys are resident then.
    case idle(nextFullScanAt: Date)
}

/// Where the scanner's rate limit and backoff stand: how many requests it may still make at once, and until when
/// the server (or a failure) has told it to stay away.
///
/// **It outlives a lock.** None of it is derived from a password (it is a count of requests and three times), so
/// nothing requires it to go when the vault locks, and it must not: a phone locks and unlocks many times a day, and
/// a scanner that forgot a `Retry-After` of an hour, or was handed a fresh burst, at every unlock would hammer the
/// API precisely when asked not to (PRD F9.2). `HygieneEngine` keeps it across `lock()` and `unlock()`. It is not
/// persisted: a new process starts with a full burst, which the launch itself spaces out.
///
/// It names no item. Which items' checks failed is in the ledger (`ScanLedger.Failure`), sealed with the results.
public struct ScanPacing: Hashable, Sendable {
    /// Requests that may go now; negative while paying off a step that made several.
    var tokens: Double
    var tokensAsOf: Date?
    /// The weekly pass's next request is not before this (its jitter).
    var weeklyNotBefore: Date?
    var backoffUntil: Date?
    var consecutiveFailures = 0

    /// The longest a backoff can be when it is set: the policy's own maximum, or the longest `Retry-After` honoured.
    /// A backoff further away than this was set by a clock that has since been put back.
    static func backoffLimit(_ policy: ScanPolicy) -> TimeInterval {
        max(policy.maximumBackoff, RetryAfter.bounds.upperBound)
    }

    mutating func refill(now: Date, policy: ScanPolicy) {
        if let asOf = tokensAsOf {
            let elapsed = now.timeIntervalSince(asOf)
            if elapsed > 0 {
                tokens = min(Double(policy.burst), tokens + elapsed / policy.requestSpacing)
            }
        }
        tokensAsOf = now
    }

    mutating func spend(_ requests: Int, now: Date, jitter: Double, policy: ScanPolicy) {
        guard requests > 0 else { return }
        refill(now: now, policy: policy)
        // No floor worth the name: a step that made several requests (an item with several passwords) owes the
        // spacing for each of them, so the sustained rate holds whatever the items look like.
        tokens = max(tokens - Double(requests), -1000)
        let spread = min(max(jitter, 0), 1) * policy.maximumJitter
        weeklyNotBefore = now.addingTimeInterval(policy.requestSpacing + spread)
    }

    /// A request failed: every request waits, doubling for each failure in a row, and never for less than the
    /// server's `Retry-After`. A lock is not a fault of the server, so `.interrupted` changes nothing.
    mutating func backOff(after error: PwnedPasswordsError, now: Date, policy: ScanPolicy) {
        guard error != .interrupted else { return }
        consecutiveFailures = min(consecutiveFailures + 1, 30)
        let exponential = min(policy.maximumBackoff, policy.initialBackoff * pow(2, Double(consecutiveFailures - 1)))
        // The client has already bounded `Retry-After`; this is the bound that does not depend on it having.
        let wait = min(max(exponential, error.retryAfter ?? 0), Self.backoffLimit(policy))
        backoffUntil = now.addingTimeInterval(wait)
    }

    /// Pays for a scan that a lock interrupted (`ScanSchedule.recordInterrupted`), when there is no schedule to
    /// tell: the vault is still locked.
    mutating func recordInterrupted(
        networkRequests: Int, error: PwnedPasswordsError?, now: Date, jitter: Double, policy: ScanPolicy
    ) {
        spend(networkRequests, now: now, jitter: jitter, policy: policy)
        if let error { backOff(after: error, now: now, policy: policy) }
    }
}

/// The scanner's scheduling policy, as a value (PRD F9.2, ADR 0005): given the items, the ledger and the time, what
/// to do next. It owns no timer, thread or clock; the caller asks, acts, and reports back.
///
/// - **Creation and edit.** An item with no ledger entry, or one whose entry is for another version, is due at once
///   and ahead of everything else.
/// - **After unlock.** The same rule: anything that changed while the vault was locked (by sync) has a version the
///   ledger has not seen.
/// - **Weekly.** A pass begins when the previous one began at least `fullScanInterval` ago, whether or not that one
///   finished. An item is due in a pass until it has been scanned since the pass began. A pass that a lock
///   interrupts is still in progress in the ledger, so the next unlock carries on where it stopped, and the
///   following pass is due a week after this one *began*. A pass that cannot finish (an item whose range keeps
///   failing) does not hold up the next one.
/// - **Only while keys are resident.** With `keysResident` false the answer is `.locked`, whatever is due, and the
///   ledger is not touched.
/// - **Rate.** At most `burst` range requests at once, then one per `requestSpacing`; the weekly pass also waits a
///   random extra `maximumJitter`. A failure backs every request off, doubling up to `maximumBackoff`, and never for
///   less than the server's `Retry-After`. Checks answered from the cache cost nothing and wait for nothing. This
///   state is `pacing`, and it outlives a lock (`ScanPacing`). A scan that a lock interrupted still pays for the
///   requests it sent (`recordInterrupted`).
/// - **No item blocks the rest.** An item whose check failed goes to the back of the queue, behind every item that
///   has not failed or failed longer ago, so the backoff paces requests but the next one is for a different item.
///   An item whose range cannot be used at all is also set aside for a time of its own. Which items failed is in
///   the ledger (`ScanLedger.Failure`), so it lasts as long as the backoff does and longer: across a lock, and
///   across a restart. Kept only for the unlocked period, it let one refused range be asked for first at every
///   unlock, with a backoff each time that outlasted the unlock.
/// - **A clock put back is not waited out.** Every remembered time that is further ahead than this policy could
///   have set it is overwritten with the furthest it could have set, once, so the wait is bounded in total and not
///   only per answer.
public struct ScanSchedule: Sendable {
    public let policy: ScanPolicy
    public private(set) var ledger: ScanLedger
    /// The rate limit and backoff as they stand. Hand it to the next schedule (`init(ledger:policy:pacing:)`) so a
    /// lock and unlock does not forget them.
    public private(set) var pacing: ScanPacing

    /// - Parameter pacing: the previous schedule's `pacing`, if there was one in this process; `nil` starts with a
    ///   full burst and no backoff.
    public init(ledger: ScanLedger = ScanLedger(), policy: ScanPolicy = .standard, pacing: ScanPacing? = nil) {
        self.ledger = ledger
        self.policy = policy
        self.pacing = pacing ?? ScanPacing(tokens: Double(policy.burst))
        // Whatever was handed in, the bucket never holds more than the policy's burst.
        self.pacing.tokens = min(self.pacing.tokens, Double(policy.burst))
    }

    /// What to do next. May begin or complete a weekly pass in the ledger.
    public mutating func decide(candidates: [ScanCandidate], keysResident: Bool, now: Date) -> ScanDecision {
        guard keysResident else { return .locked }
        distrustFutureTimes(now: now)
        beginPassIfDue(now: now)
        let passStart = ledger.fullScanCompletedAt == nil ? ledger.fullScanStartedAt : nil

        var due: [(candidate: ScanCandidate, reason: ScanReason, scannedAt: Date?)] = []
        for candidate in candidates {
            if let reason = reason(for: candidate, passStart: passStart, now: now) {
                due.append((candidate, reason, ledger.entries[candidate.id]?.scannedAt))
            }
        }
        guard !due.isEmpty else {
            if ledger.fullScanCompletedAt == nil { ledger.fullScanCompletedAt = now }
            return .idle(nextFullScanAt: (ledger.fullScanStartedAt ?? now).addingTimeInterval(policy.fullScanInterval))
        }

        // The server's wishes come first: nothing is asked while backing off, whatever is due.
        if let until = pacing.backoffUntil, until > now {
            return .wait(until: until, .backoff)
        }

        var eligible: [(candidate: ScanCandidate, reason: ScanReason, scannedAt: Date?)] = []
        var earliestRetry: Date?
        for entry in due {
            // The time of its own is for the version that failed: a later one may hold another password.
            if let failure = ledger.failures[entry.candidate.id], failure.itemVersion == entry.candidate.version,
                let until = failure.notBefore, until > now
            {
                earliestRetry = min(earliestRetry ?? until, until)
            } else {
                eligible.append(entry)
            }
        }
        guard !eligible.isEmpty else {
            var until = earliestRetry ?? now.addingTimeInterval(policy.itemRetryInitial)
            // The next pass makes every other item due again; do not sleep through its start.
            if let started = ledger.fullScanStartedAt {
                let nextPass = started.addingTimeInterval(policy.fullScanInterval)
                if nextPass > now { until = min(until, nextPass) }
            }
            return .wait(until: until, .retry)
        }

        // An item that failed waits behind every item that has not, and behind those that failed longer ago: one
        // prefix the server will not answer must not be asked for again and again while the rest of the vault goes
        // unchecked. This holds whatever version failed: an edit must not buy the item the front of the queue.
        func failedAt(_ item: UUID) -> Date {
            ledger.failures[item]?.failedAt ?? .distantPast
        }
        let next = eligible.min { lhs, rhs in
            let leftFailure = failedAt(lhs.candidate.id)
            let rightFailure = failedAt(rhs.candidate.id)
            if leftFailure != rightFailure { return leftFailure < rightFailure }
            if lhs.reason != rhs.reason { return lhs.reason < rhs.reason }
            let left = lhs.scannedAt ?? .distantPast
            let right = rhs.scannedAt ?? .distantPast
            if left != right { return left < right }
            return lhs.candidate.id.uuidString < rhs.candidate.id.uuidString
        }
        guard let next else { return .idle(nextFullScanAt: now.addingTimeInterval(policy.fullScanInterval)) }

        pacing.refill(now: now, policy: policy)
        if pacing.tokens < 1 {
            return .wait(until: now.addingTimeInterval((1 - pacing.tokens) * policy.requestSpacing), .pacing)
        }
        if next.reason == .weekly, let until = pacing.weeklyNotBefore, until > now {
            return .wait(until: until, .pacing)
        }
        return .scan(item: next.candidate.id, reason: next.reason)
    }

    /// Whether a request for `item` may go now: the same limits as `decide`, for the check a save asks for directly.
    /// `nil` means yes; otherwise when to ask again.
    public mutating func earliestStart(for item: UUID, now: Date) -> Date? {
        distrustFutureTimes(now: now)
        if let until = pacing.backoffUntil, until > now {
            return until
        }
        pacing.refill(now: now, policy: policy)
        if pacing.tokens < 1 { return now.addingTimeInterval((1 - pacing.tokens) * policy.requestSpacing) }
        return nil
    }

    /// Why `candidate` is due, if it is. `nil` while locked is the caller's concern, not this function's.
    public func reason(for candidate: ScanCandidate, now: Date) -> ScanReason? {
        reason(
            for: candidate, passStart: ledger.fullScanCompletedAt == nil ? ledger.fullScanStartedAt : nil, now: now)
    }

    private func reason(for candidate: ScanCandidate, passStart: Date?, now: Date) -> ScanReason? {
        guard let entry = ledger.entries[candidate.id] else { return .created }
        if entry.itemVersion != candidate.version { return .changed }
        if let passStart {
            // A scan dated after now did not happen in this pass, whatever the ledger says: the clock moved.
            if entry.scannedAt < passStart || entry.scannedAt > now.addingTimeInterval(policy.clockTolerance) {
                return .weekly
            }
        }
        return nil
    }

    private mutating func beginPassIfDue(now: Date) {
        guard let started = ledger.fullScanStartedAt else {
            ledger.fullScanStartedAt = now
            ledger.fullScanCompletedAt = nil
            return
        }
        // A week after a pass began, the next one begins, finished or not. Waiting for a pass that cannot finish
        // (one item whose range keeps failing) would mean no other item is ever checked again.
        if now.timeIntervalSince(started) >= policy.fullScanInterval {
            ledger.fullScanStartedAt = now
            ledger.fullScanCompletedAt = nil
            return
        }
        guard started > now else { return }
        // A start time ahead of the clock is a clock that has since been put back, or a ledger from a device whose
        // clock was fast.
        if ledger.fullScanCompletedAt == nil {
            // In progress: the pass began "now" as far as this clock can tell. Left in the future, every scan
            // (dated now) would be before the pass began, so every item would be due again the moment it was
            // scanned, and each time round would ask the server afresh, for as long as the start stayed ahead.
            ledger.fullScanStartedAt = now
        } else if started > now.addingTimeInterval(policy.clockTolerance) {
            // Finished, at a time that has not happened: waiting a week from it could mean never scanning again.
            ledger.fullScanStartedAt = now
            ledger.fullScanCompletedAt = nil
        }
    }

    /// The time the weekly pass in progress began, if one is: cached ranges older than this are not used by it.
    public var passInProgressSince: Date? {
        ledger.fullScanCompletedAt == nil ? ledger.fullScanStartedAt : nil
    }

    /// Records a completed check of every password in `item` at `version`.
    ///
    /// - Parameters:
    ///   - networkRequests: how many range requests it took; none if the cache answered.
    ///   - jitter: a uniform random number in `0..<1` from the caller's generator, for the weekly pass's spacing.
    public mutating func recordScan(
        item: UUID, version: UInt64, results: [UUID: PwnedPasswordResult], networkRequests: Int, now: Date,
        jitter: Double
    ) {
        ledger.entries[item] = ScanLedger.Entry(itemVersion: version, scannedAt: now, results: results)
        ledger.failures[item] = nil
        recordRequests(networkRequests, now: now, jitter: jitter)
    }

    /// Pays for requests that were answered, without recording a result: a scan whose item changed under it.
    public mutating func recordRequests(_ networkRequests: Int, now: Date, jitter: Double) {
        pacing.spend(networkRequests, now: now, jitter: jitter, policy: policy)
        if networkRequests > 0 {
            pacing.consecutiveFailures = 0
            pacing.backoffUntil = nil
        }
    }

    /// Records a check that did not complete. No result is recorded, so the item stays due; the failure itself goes
    /// in the ledger (`ScanLedger.Failure`), which is what sends the item to the back of the queue.
    ///
    /// - Parameter version: the item version whose check failed.
    public mutating func recordFailure(
        item: UUID, version: UInt64, error: PwnedPasswordsError, networkRequests: Int, now: Date, jitter: Double
    ) {
        pacing.spend(networkRequests, now: now, jitter: jitter, policy: policy)
        // A lock is not a fault of the server or of the item.
        guard error != .interrupted else { return }
        pacing.backOff(after: error, now: now, policy: policy)
        // Either way the item goes to the back of the queue (`decide`). One whose range cannot be used is also
        // not asked for again until a time of its own: asking sooner would get the same answer.
        let earlier = ledger.failures[item].flatMap { $0.itemVersion == version ? $0.count : nil } ?? 0
        var failure = ScanLedger.Failure(itemVersion: version, count: earlier + 1, failedAt: now)
        if !error.isRetryable {
            let wait = min(policy.itemRetryMaximum, policy.itemRetryInitial * pow(2, Double(failure.count - 1)))
            failure.notBefore = now.addingTimeInterval(wait)
        }
        // The ledger must stay one that decodes. At the bound, the failure longest ago goes: it is the one that
        // would have been tried next in any case.
        if ledger.failures[item] == nil, ledger.failures.count >= ScanLedger.maximumEntries,
            let oldest = ledger.failures.min(by: { $0.value.failedAt < $1.value.failedAt })
        {
            ledger.failures[oldest.key] = nil
        }
        ledger.failures[item] = failure
    }

    /// Pays for a scan that a lock interrupted: the requests it had sent count against the rate limit, and if the
    /// server's answer to the last was a refusal, the backoff it asked for stands. None of that is derived from a
    /// password. Nothing else is recorded: no result, and nothing about the item, which belonged to the unlocked
    /// period that ended.
    ///
    /// - Parameter error: what the request in flight came back with, if it failed.
    public mutating func recordInterrupted(
        networkRequests: Int, error: PwnedPasswordsError?, now: Date, jitter: Double
    ) {
        pacing.recordInterrupted(
            networkRequests: networkRequests, error: error, now: now, jitter: jitter, policy: policy)
    }

    /// Drops what is remembered about items that no longer exist, or are no longer candidates.
    public mutating func prune(keeping items: Set<UUID>) {
        ledger.entries = ledger.entries.filter { items.contains($0.key) }
        ledger.failures = ledger.failures.filter { items.contains($0.key) }
    }

    /// Forgets one item's result, so it is due again.
    public mutating func forget(_ item: UUID) {
        ledger.entries[item] = nil
        ledger.failures[item] = nil
    }

    /// Overwrites every remembered time that is further ahead of `now` than this policy could have set it.
    ///
    /// Such a time was set by a clock that has since been put back (or, for the ledger, by another clock
    /// altogether). Bounding only the answer, and leaving the time where it was, bounded each wait but not their
    /// sum: after a 429 and a clock put back thirty days, `decide` answered "wait an hour" for thirty days. So the
    /// time itself is replaced, once, by the furthest this policy could have set it, and the wait that follows is
    /// one the policy allows. Entries' scan times and the pass's start are dealt with where they are read
    /// (`reason`, `beginPassIfDue`); the token bucket's own time corrects itself in `refill`.
    private mutating func distrustFutureTimes(now: Date) {
        let backoffLimit = now.addingTimeInterval(ScanPacing.backoffLimit(policy))
        if let until = pacing.backoffUntil, until > backoffLimit { pacing.backoffUntil = backoffLimit }
        let weeklyLimit = now.addingTimeInterval(policy.requestSpacing + policy.maximumJitter)
        if let until = pacing.weeklyNotBefore, until > weeklyLimit { pacing.weeklyNotBefore = weeklyLimit }

        guard !ledger.failures.isEmpty else { return }
        let retryLimit = now.addingTimeInterval(policy.itemRetryMaximum)
        var corrected: [UUID: ScanLedger.Failure] = [:]
        for (item, failure) in ledger.failures {
            var fixed = failure
            // A failure "after now" would sort behind every failure that really happens from here on, for as long
            // as the clock stayed behind it: the item would never come round again. It failed just now.
            if fixed.failedAt > now { fixed.failedAt = now }
            if let until = fixed.notBefore, until > retryLimit { fixed.notBefore = retryLimit }
            if fixed != failure { corrected[item] = fixed }
        }
        for (item, failure) in corrected {
            ledger.failures[item] = failure
        }
    }
}
