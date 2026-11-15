import Foundation

/// What the breach scanner remembers between launches: which version of each item it checked, when, and what the
/// answer was, plus where the weekly pass stands (PRD F9.2).
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
    /// When the weekly pass in progress, or the last one, began.
    public var fullScanStartedAt: Date?
    /// When that pass finished; `nil` while it is in progress, which is how an interrupted pass is recognised and
    /// resumed at the next unlock.
    public var fullScanCompletedAt: Date?

    public init(
        entries: [UUID: Entry] = [:], fullScanStartedAt: Date? = nil, fullScanCompletedAt: Date? = nil
    ) {
        self.entries = entries
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
/// sorted by item), and decoded with bounds. The session seals the encoding, so what is decoded has already been
/// authenticated; the bounds make a damaged or foreign blob a decoding error.
extension ScanLedger: Codable {
    private enum CodingKeys: String, CodingKey {
        case entries, fullScanStartedAt, fullScanCompletedAt
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
public struct ScanPacing: Hashable, Sendable {
    /// Requests that may go now; negative while paying off a step that made several.
    var tokens: Double
    var tokensAsOf: Date?
    /// The weekly pass's next request is not before this (its jitter).
    var weeklyNotBefore: Date?
    var backoffUntil: Date?
    var consecutiveFailures = 0
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
///   state is `pacing`, and it outlives a lock (`ScanPacing`).
/// - **No item blocks the rest.** An item whose check failed goes to the back of the queue, behind every item that
///   has not failed or failed longer ago, so the backoff paces requests but the next one is for a different item.
///   An item whose range cannot be used at all is also set aside for a time of its own.
public struct ScanSchedule: Sendable {
    public let policy: ScanPolicy
    public private(set) var ledger: ScanLedger
    /// The rate limit and backoff as they stand. Hand it to the next schedule (`init(ledger:policy:pacing:)`) so a
    /// lock and unlock does not forget them.
    public private(set) var pacing: ScanPacing

    // Not persisted, and not carried across a lock: which items failed in this unlocked period.
    private var itemRetries: [UUID: ItemRetry] = [:]

    private struct ItemRetry: Sendable {
        var failures: Int
        /// When the item last failed: the later, the further back in the queue.
        var failedAt: Date
        /// Set only for a failure that asking again cannot fix by itself: not before this.
        var notBefore: Date?
    }

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
        if let until = clamped(pacing.backoffUntil, now: now, limit: policy.maximumBackoff), until > now {
            return .wait(until: until, .backoff)
        }

        var eligible: [(candidate: ScanCandidate, reason: ScanReason, scannedAt: Date?)] = []
        var earliestRetry: Date?
        for entry in due {
            if let retry = itemRetries[entry.candidate.id],
                let until = clamped(retry.notBefore, now: now, limit: policy.itemRetryMaximum), until > now
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
        // unchecked. A failure time ahead of the clock is a clock that moved; it sorts as "just now".
        func failedAt(_ item: UUID) -> Date {
            guard let failed = itemRetries[item]?.failedAt else { return .distantPast }
            return min(failed, now)
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

        refill(now: now)
        if pacing.tokens < 1 {
            return .wait(until: now.addingTimeInterval((1 - pacing.tokens) * policy.requestSpacing), .pacing)
        }
        if next.reason == .weekly,
            let until = clamped(
                pacing.weeklyNotBefore, now: now, limit: policy.requestSpacing + policy.maximumJitter),
            until > now
        {
            return .wait(until: until, .pacing)
        }
        return .scan(item: next.candidate.id, reason: next.reason)
    }

    /// Whether a request for `item` may go now: the same limits as `decide`, for the check a save asks for directly.
    /// `nil` means yes; otherwise when to ask again.
    public mutating func earliestStart(for item: UUID, now: Date) -> Date? {
        if let until = clamped(pacing.backoffUntil, now: now, limit: policy.maximumBackoff), until > now {
            return until
        }
        refill(now: now)
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
        itemRetries[item] = nil
        recordRequests(networkRequests, now: now, jitter: jitter)
    }

    /// Pays for requests that were answered, without recording a result: a scan whose item changed under it.
    public mutating func recordRequests(_ networkRequests: Int, now: Date, jitter: Double) {
        spend(networkRequests, now: now, jitter: jitter)
        if networkRequests > 0 {
            pacing.consecutiveFailures = 0
            pacing.backoffUntil = nil
        }
    }

    /// Records a check that did not complete. The ledger is not touched: the item stays due.
    public mutating func recordFailure(
        item: UUID, error: PwnedPasswordsError, networkRequests: Int, now: Date, jitter: Double
    ) {
        spend(networkRequests, now: now, jitter: jitter)
        // A lock is not a fault of the server or of the item.
        guard error != .interrupted else { return }
        pacing.consecutiveFailures = min(pacing.consecutiveFailures + 1, 30)
        let exponential = min(
            policy.maximumBackoff, policy.initialBackoff * pow(2, Double(pacing.consecutiveFailures - 1)))
        pacing.backoffUntil = now.addingTimeInterval(max(exponential, error.retryAfter ?? 0))
        // Either way the item goes to the back of the queue (`decide`). One whose range cannot be used is also
        // not asked for again until a time of its own: asking sooner would get the same answer.
        let failures = min((itemRetries[item]?.failures ?? 0) + 1, 30)
        var retry = ItemRetry(failures: failures, failedAt: now, notBefore: nil)
        if !error.isRetryable {
            let wait = min(policy.itemRetryMaximum, policy.itemRetryInitial * pow(2, Double(failures - 1)))
            retry.notBefore = now.addingTimeInterval(wait)
        }
        itemRetries[item] = retry
    }

    /// Drops what is remembered about items that no longer exist, or are no longer candidates.
    public mutating func prune(keeping items: Set<UUID>) {
        ledger.entries = ledger.entries.filter { items.contains($0.key) }
        itemRetries = itemRetries.filter { items.contains($0.key) }
    }

    /// Forgets one item's result, so it is due again.
    public mutating func forget(_ item: UUID) {
        ledger.entries[item] = nil
        itemRetries[item] = nil
    }

    private mutating func spend(_ requests: Int, now: Date, jitter: Double) {
        guard requests > 0 else { return }
        refill(now: now)
        // No floor worth the name: a step that made several requests (an item with several passwords) owes the
        // spacing for each of them, so the sustained rate holds whatever the items look like.
        pacing.tokens = max(pacing.tokens - Double(requests), -1000)
        let spread = min(max(jitter, 0), 1) * policy.maximumJitter
        pacing.weeklyNotBefore = now.addingTimeInterval(policy.requestSpacing + spread)
    }

    private mutating func refill(now: Date) {
        if let asOf = pacing.tokensAsOf {
            let elapsed = now.timeIntervalSince(asOf)
            if elapsed > 0 {
                pacing.tokens = min(Double(policy.burst), pacing.tokens + elapsed / policy.requestSpacing)
            }
        }
        pacing.tokensAsOf = now
    }

    /// `date`, unless it is further away than this run could have set it: then the clock moved, and the wait is cut
    /// to the longest one the policy allows.
    private func clamped(_ date: Date?, now: Date, limit: TimeInterval) -> Date? {
        guard let date else { return nil }
        return min(date, now.addingTimeInterval(limit))
    }
}
