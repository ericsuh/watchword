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
    /// doubled each time, up to `itemRetryMaximum`. Other items go on being scanned meanwhile.
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

/// The scanner's scheduling policy, as a value (PRD F9.2, ADR 0005): given the items, the ledger and the time, what
/// to do next. It owns no timer, thread or clock; the caller asks, acts, and reports back.
///
/// - **Creation and edit.** An item with no ledger entry, or one whose entry is for another version, is due at once
///   and ahead of everything else.
/// - **After unlock.** The same rule: anything that changed while the vault was locked (by sync) has a version the
///   ledger has not seen.
/// - **Weekly.** A pass begins when the previous one began at least `fullScanInterval` ago. An item is due in a pass
///   until it has been scanned since the pass began. A pass that a lock interrupts is still in progress in the
///   ledger, so the next unlock carries on where it stopped, and the following pass is due a week after this one
///   *began*.
/// - **Only while keys are resident.** With `keysResident` false the answer is `.locked`, whatever is due, and the
///   ledger is not touched.
/// - **Rate.** At most `burst` range requests at once, then one per `requestSpacing`; the weekly pass also waits a
///   random extra `maximumJitter`. A failure backs every request off, doubling up to `maximumBackoff`, and never for
///   less than the server's `Retry-After`. Checks answered from the cache cost nothing and wait for nothing.
public struct ScanSchedule: Sendable {
    public let policy: ScanPolicy
    public private(set) var ledger: ScanLedger

    // None of this is persisted: it describes this run's requests.
    private var tokens: Double
    private var tokensAsOf: Date?
    private var weeklyNotBefore: Date?
    private var backoffUntil: Date?
    private var consecutiveFailures = 0
    private var itemRetries: [UUID: ItemRetry] = [:]

    private struct ItemRetry: Sendable {
        var failures: Int
        var notBefore: Date
    }

    public init(ledger: ScanLedger = ScanLedger(), policy: ScanPolicy = .standard) {
        self.ledger = ledger
        self.policy = policy
        tokens = Double(policy.burst)
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
        if let until = clamped(backoffUntil, now: now, limit: policy.maximumBackoff), until > now {
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
            return .wait(until: earliestRetry ?? now.addingTimeInterval(policy.itemRetryInitial), .retry)
        }

        let next = eligible.min { lhs, rhs in
            if lhs.reason != rhs.reason { return lhs.reason < rhs.reason }
            let left = lhs.scannedAt ?? .distantPast
            let right = rhs.scannedAt ?? .distantPast
            if left != right { return left < right }
            return lhs.candidate.id.uuidString < rhs.candidate.id.uuidString
        }
        guard let next else { return .idle(nextFullScanAt: now.addingTimeInterval(policy.fullScanInterval)) }

        refill(now: now)
        if tokens < 1 {
            return .wait(until: now.addingTimeInterval((1 - tokens) * policy.requestSpacing), .pacing)
        }
        if next.reason == .weekly,
            let until = clamped(weeklyNotBefore, now: now, limit: policy.requestSpacing + policy.maximumJitter),
            until > now
        {
            return .wait(until: until, .pacing)
        }
        return .scan(item: next.candidate.id, reason: next.reason)
    }

    /// Whether a request for `item` may go now: the same limits as `decide`, for the check a save asks for directly.
    /// `nil` means yes; otherwise when to ask again.
    public mutating func earliestStart(for item: UUID, now: Date) -> Date? {
        if let until = clamped(backoffUntil, now: now, limit: policy.maximumBackoff), until > now { return until }
        refill(now: now)
        if tokens < 1 { return now.addingTimeInterval((1 - tokens) * policy.requestSpacing) }
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
        // A start time in the future is a clock that has since been put back; waiting for it could mean never
        // scanning again.
        let startedInFuture = started > now.addingTimeInterval(policy.clockTolerance)
        let intervalElapsed = now.timeIntervalSince(started) >= policy.fullScanInterval
        if startedInFuture || (ledger.fullScanCompletedAt != nil && intervalElapsed) {
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
        spend(networkRequests, now: now, jitter: jitter)
        if networkRequests > 0 {
            consecutiveFailures = 0
            backoffUntil = nil
        }
    }

    /// Records a check that did not complete. The ledger is not touched: the item stays due.
    public mutating func recordFailure(
        item: UUID, error: PwnedPasswordsError, networkRequests: Int, now: Date, jitter: Double
    ) {
        spend(networkRequests, now: now, jitter: jitter)
        // A lock is not a fault of the server or of the item.
        guard error != .interrupted else { return }
        consecutiveFailures = min(consecutiveFailures + 1, 30)
        let exponential = min(policy.maximumBackoff, policy.initialBackoff * pow(2, Double(consecutiveFailures - 1)))
        backoffUntil = now.addingTimeInterval(max(exponential, error.retryAfter ?? 0))
        if !error.isRetryable {
            let failures = min((itemRetries[item]?.failures ?? 0) + 1, 30)
            let wait = min(policy.itemRetryMaximum, policy.itemRetryInitial * pow(2, Double(failures - 1)))
            itemRetries[item] = ItemRetry(failures: failures, notBefore: now.addingTimeInterval(wait))
        }
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
        tokens = max(tokens - Double(requests), -1000)
        let spread = min(max(jitter, 0), 1) * policy.maximumJitter
        weeklyNotBefore = now.addingTimeInterval(policy.requestSpacing + spread)
    }

    private mutating func refill(now: Date) {
        if let asOf = tokensAsOf {
            let elapsed = now.timeIntervalSince(asOf)
            if elapsed > 0 { tokens = min(Double(policy.burst), tokens + elapsed / policy.requestSpacing) }
        }
        tokensAsOf = now
    }

    /// `date`, unless it is further away than this run could have set it: then the clock moved, and the wait is cut
    /// to the longest one the policy allows.
    private func clamped(_ date: Date?, now: Date, limit: TimeInterval) -> Date? {
        guard let date else { return nil }
        return min(date, now.addingTimeInterval(limit))
    }
}
