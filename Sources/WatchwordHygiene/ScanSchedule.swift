import Foundation

/// What the breach scanner remembers between launches: which version of each item it checked, when, and what the
/// answer was; which items' checks failed, and when; and where the weekly pass stands (PRD F9.2).
///
/// **This is derived from passwords** (a breach count all but names the password), so it is persisted only sealed,
/// under a key that is gone when the vault locks, exactly like an item: the session encodes it and seals it as a
/// local record, and `HygieneEngine` hands it out only while unlocked (docs/adr/0005-hibp-while-locked.md and its
/// amendment). It is per-device state and is not synced: writing a scan time into every item each week would turn
/// the scan into a weekly edit of the whole vault. What other devices learn of this device's checks travels in a
/// record of its own (`SyncedScanRecord`, docs/02-architecture.md §13.9), and what this device learns of theirs is
/// weighed against this ledger, never written over it.
///
/// No hash and no prefix of a password. It does hold keyed digests (`ScanBinding`, under a key derived from the reuse
/// key), which tie each result to the password it judged; sealed under the device-local key, they say nothing to
/// anyone who could not decrypt the items anyway.
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
        /// The item version whose passwords were checked. Without `bindings` (a ledger from before they were kept),
        /// a result says nothing about any other version.
        public var itemVersion: UInt64
        public var scannedAt: Date
        /// Per password field.
        public var results: [UUID: PwnedPasswordResult]
        /// Per password field, the binding of the password that was checked (`ScanBinding`, under this device's own
        /// binding key). With them, a result counts for the password it judged at whatever version the item is now,
        /// and for no other password: an edit of the notes leaves it standing, a changed password does not.
        public var bindings: [UUID: ScanBinding]

        public init(
            itemVersion: UInt64, scannedAt: Date, results: [UUID: PwnedPasswordResult],
            bindings: [UUID: ScanBinding] = [:]
        ) {
            self.itemVersion = itemVersion
            self.scannedAt = scannedAt
            self.results = results
            self.bindings = bindings
        }

        /// The result this check reached for the password bound by `binding`, the worse one if two fields held it;
        /// `nil` if it did not check that password.
        func result(for binding: ScanBinding) -> PwnedPasswordResult? {
            var found: PwnedPasswordResult?
            for (field, bound) in bindings where bound == binding {
                guard let result = results[field] else { continue }
                if case .found(let count) = result {
                    if case .found(let earlier) = found, earlier >= count { continue }
                    found = result
                } else if found == nil {
                    found = result
                }
            }
            return found
        }
    }

    /// A breach another device of the vault reported for one of an item's passwords, as this device took it in
    /// (`HygieneEngine.updateSynced`). Kept here, sealed, so that the report goes on showing it whatever later records
    /// say: only this device's own later check of the password removes it (ADR 0005, amendment of 2026-11-16).
    public struct Reported: Hashable, Sendable {
        public var occurrences: UInt32
        /// When the reporting device checked, by its clock, never later than this device's clock when it took the
        /// report in.
        public var reportedAt: Date

        public init(occurrences: UInt32, reportedAt: Date) {
            self.occurrences = max(1, occurrences)
            self.reportedAt = reportedAt
        }
    }

    public var entries: [UUID: Entry]
    /// Items whose last check did not complete. An item leaves when a check of it completes, or when it goes.
    public var failures: [UUID: Failure]
    /// Breaches other devices reported, per item and password binding (this device's own binding key). A password
    /// leaves when this device checks it itself, or when the item no longer holds it.
    public var reported: [UUID: [ScanBinding: Reported]]
    /// Since when this device has let other devices' checks stand in for its own check of an item. Bounded by
    /// `ScanPolicy.maximumSyncDeferral`: past it, this device checks the item itself, which clears the mark. So a
    /// synced result postpones this device's check, never replaces it.
    public var deferred: [UUID: Date]
    /// When the weekly pass in progress, or the last one, began.
    public var fullScanStartedAt: Date?
    /// When that pass finished; `nil` while it is in progress, which is how an interrupted pass is recognised and
    /// resumed at the next unlock.
    public var fullScanCompletedAt: Date?

    public init(
        entries: [UUID: Entry] = [:], fullScanStartedAt: Date? = nil, fullScanCompletedAt: Date? = nil,
        failures: [UUID: Failure] = [:], reported: [UUID: [ScanBinding: Reported]] = [:], deferred: [UUID: Date] = [:]
    ) {
        self.entries = entries
        self.failures = failures
        self.reported = reported
        self.deferred = deferred
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
        case entries, failures, fullScanStartedAt, fullScanCompletedAt, reported, deferred
    }

    private struct WireReported: Codable {
        var item: UUID
        var bindings: [String]
        var occurrences: [UInt32]
        var reportedAt: [Int64]
    }

    private struct WireDeferred: Codable {
        var item: UUID
        var since: Int64
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
        /// Parallel to `fields`; absent in a ledger from before bindings were kept.
        var bindings: [String]?
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
            var bindings: [UUID: ScanBinding] = [:]
            if let wireBindings = entry.bindings {
                guard wireBindings.count == entry.fields.count else { throw Self.corrupted(decoder, "bindings") }
                for (field, hex) in zip(entry.fields, wireBindings) {
                    guard let binding = ScanBinding(hex: hex) else { throw Self.corrupted(decoder, "binding") }
                    bindings[field] = binding
                }
            }
            entries[entry.item] = Entry(
                itemVersion: entry.version, scannedAt: scannedAt, results: results, bindings: bindings)
        }
        self.entries = entries
        let wireReported = try container.decodeIfPresent([WireReported].self, forKey: .reported) ?? []
        guard wireReported.count <= Self.maximumEntries else { throw Self.corrupted(decoder, "too many reports") }
        var reported: [UUID: [ScanBinding: Reported]] = [:]
        for report in wireReported {
            guard reported[report.item] == nil, !report.bindings.isEmpty,
                report.bindings.count <= Self.maximumResultsPerEntry,
                report.occurrences.count == report.bindings.count, report.reportedAt.count == report.bindings.count
            else { throw Self.corrupted(decoder, "report") }
            var bound: [ScanBinding: Reported] = [:]
            for index in report.bindings.indices {
                guard let binding = ScanBinding(hex: report.bindings[index]), bound[binding] == nil,
                    report.occurrences[index] > 0, let at = Self.date(report.reportedAt[index])
                else { throw Self.corrupted(decoder, "report") }
                bound[binding] = Reported(occurrences: report.occurrences[index], reportedAt: at)
            }
            reported[report.item] = bound
        }
        self.reported = reported
        let wireDeferred = try container.decodeIfPresent([WireDeferred].self, forKey: .deferred) ?? []
        guard wireDeferred.count <= Self.maximumEntries else { throw Self.corrupted(decoder, "too many deferrals") }
        var deferred: [UUID: Date] = [:]
        for mark in wireDeferred {
            guard deferred[mark.item] == nil, let since = Self.date(mark.since) else {
                throw Self.corrupted(decoder, "deferral")
            }
            deferred[mark.item] = since
        }
        self.deferred = deferred
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
            // Bindings only when every field has one, which is how the engine records them.
            let bindings = fields.compactMap { entry.bindings[$0]?.hex }
            return WireEntry(
                item: id, version: entry.itemVersion, scannedAt: Self.seconds(entry.scannedAt), fields: fields,
                occurrences: fields.map { field in
                    if case .found(let occurrences) = entry.results[field] { return occurrences }
                    return 0
                }, bindings: bindings.count == fields.count && !fields.isEmpty ? bindings : nil)
        }
        try container.encode(wire, forKey: .entries)
        if !reported.isEmpty {
            let wireReported = reported.sorted { $0.key.uuidString < $1.key.uuidString }.compactMap {
                item, bound -> WireReported? in
                let ordered = bound.sorted { $0.key < $1.key }.prefix(Self.maximumResultsPerEntry)
                guard !ordered.isEmpty else { return nil }
                return WireReported(
                    item: item, bindings: ordered.map(\.key.hex), occurrences: ordered.map(\.value.occurrences),
                    reportedAt: ordered.map { Self.seconds($0.value.reportedAt) })
            }
            try container.encode(wireReported, forKey: .reported)
        }
        if !deferred.isEmpty {
            let wireDeferred = deferred.sorted { $0.key.uuidString < $1.key.uuidString }.map {
                WireDeferred(item: $0.key, since: Self.seconds($0.value))
            }
            try container.encode(wireDeferred, forKey: .deferred)
        }
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
    /// When every password the item holds now was last checked, as far as anything besides the ledger entry for this
    /// very version can tell: this device's own check of the same passwords at an earlier version, and checks other
    /// devices of the vault synced (`HygieneEngine`, which bounds them: none dated beyond the clock's tolerance, none
    /// later than now, and none at all once `ScanPolicy.maximumSyncDeferral` has run out). `nil` if some password is
    /// covered by nothing. It counts for a weekly pass if it is from since the pass began or from within the last
    /// `fullScanInterval`.
    public let coveredAt: Date?

    public init(id: UUID, version: UInt64, coveredAt: Date? = nil) {
        self.id = id
        self.version = version
        self.coveredAt = coveredAt
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
    /// How far ahead of the clock a recorded time may be before it is treated as wrong. A synced scan time further
    /// ahead than this is ignored altogether.
    public let clockTolerance: TimeInterval
    /// The longest other devices' synced checks may stand in for this device's own check of an item. Each synced
    /// check postpones this device's own by at most a pass (`fullScanInterval`: a check counts for the pass it is
    /// in), and all of them together by at most this (and the pass it ends in), so a vault member who keeps reporting
    /// "not found" cannot keep this device from ever asking itself. Never less than `fullScanInterval`.
    public let maximumSyncDeferral: TimeInterval

    public init(
        fullScanInterval: TimeInterval = 7 * 24 * 60 * 60, requestSpacing: TimeInterval = 2, burst: Int = 5,
        maximumJitter: TimeInterval = 3, initialBackoff: TimeInterval = 60, maximumBackoff: TimeInterval = 3600,
        itemRetryInitial: TimeInterval = 600, itemRetryMaximum: TimeInterval = 24 * 60 * 60,
        clockTolerance: TimeInterval = 300, maximumSyncDeferral: TimeInterval = 28 * 24 * 60 * 60
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
        self.clockTolerance = min(max(0, clockTolerance), 24 * 60 * 60)
        self.maximumSyncDeferral = min(max(self.fullScanInterval, maximumSyncDeferral), 365 * 24 * 60 * 60)
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
        let entry = ledger.entries[candidate.id]
        let own = entry.flatMap { $0.itemVersion == candidate.version ? $0.scannedAt : nil }
        guard own != nil || candidate.coveredAt != nil else { return entry == nil ? .created : .changed }
        guard let passStart else { return nil }
        // A scan dated after now did not happen in this pass, whatever the ledger says: the clock moved.
        let latest = now.addingTimeInterval(policy.clockTolerance)
        if let own, own >= passStart, own <= latest { return nil }
        // A check of the same passwords at another version, or another device's, counts for this pass if it ran
        // since the pass began or within the last interval: a device's first pass begins when it first asks, and a
        // check another device made the day before is as good as one made since. Either way the next check of each
        // password is due at most one interval after the last one anywhere.
        if let covered = candidate.coveredAt, covered <= latest,
            covered >= passStart || covered >= now.addingTimeInterval(-policy.fullScanInterval)
        {
            return nil
        }
        return .weekly
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

    /// Brings the schedule's own times up to `now` (a clock put back, a weekly pass due to begin) without deciding
    /// anything: what `decide` does first, for a caller that asks `reason(for:now:)` before it decides.
    public mutating func advance(now: Date) {
        distrustFutureTimes(now: now)
        beginPassIfDue(now: now)
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
    ///   - bindings: per field, the binding of the password checked; this device's own check of each of them
    ///     replaces any breach another device reported for it.
    public mutating func recordScan(
        item: UUID, version: UInt64, results: [UUID: PwnedPasswordResult], bindings: [UUID: ScanBinding] = [:],
        networkRequests: Int, now: Date, jitter: Double
    ) {
        ledger.entries[item] = ScanLedger.Entry(
            itemVersion: version, scannedAt: now, results: results, bindings: bindings)
        ledger.failures[item] = nil
        ledger.deferred[item] = nil
        if var reports = ledger.reported[item] {
            for binding in bindings.values { reports[binding] = nil }
            ledger.reported[item] = reports.isEmpty ? nil : reports
        }
        recordRequests(networkRequests, now: now, jitter: jitter)
    }

    /// Takes in a breach another device reported for the password bound by `binding` (this device's binding), checked
    /// at `at` by that device's clock and already bounded by the caller. Ignored if this device's own check of that
    /// password is newer and found it clear: its own newer check is the one thing that outranks a reported breach.
    /// Returns whether the ledger changed.
    @discardableResult
    public mutating func recordReported(
        item: UUID, binding: ScanBinding, occurrences: UInt32, at: Date
    ) -> Bool {
        if let entry = ledger.entries[item], let own = entry.result(for: binding), entry.scannedAt > at {
            if own == .notFound { return false }
        }
        var reports = ledger.reported[item] ?? [:]
        let previous = reports[binding]
        let merged = ScanLedger.Reported(
            occurrences: max(previous?.occurrences ?? 0, occurrences),
            reportedAt: max(previous?.reportedAt ?? at, at))
        guard merged != previous else { return false }
        if previous == nil, reports.count >= ScanLedger.maximumResultsPerEntry { return false }
        if ledger.reported[item] == nil, ledger.reported.count >= ScanLedger.maximumEntries { return false }
        reports[binding] = merged
        ledger.reported[item] = reports
        return true
    }

    /// Keeps only the reports for passwords the item still holds (`bindings`, this device's).
    public mutating func keepReports(of item: UUID, for bindings: Set<ScanBinding>) -> Bool {
        guard let reports = ledger.reported[item] else { return false }
        let kept = reports.filter { bindings.contains($0.key) }
        guard kept.count != reports.count else { return false }
        ledger.reported[item] = kept.isEmpty ? nil : kept
        return true
    }

    /// Since when synced checks have stood in for this device's own check of `item`, marking now if they had not.
    /// `nil` once they have done so for longer than `maximumSyncDeferral`: this device checks the item itself.
    public mutating func syncDeferral(of item: UUID, now: Date) -> Date? {
        guard let since = ledger.deferred[item] else {
            if ledger.deferred.count < ScanLedger.maximumEntries { ledger.deferred[item] = now }
            return now
        }
        return now.timeIntervalSince(since) > policy.maximumSyncDeferral ? nil : since
    }

    /// Whether `item` is marked as deferring to synced checks.
    public func isDeferring(_ item: UUID) -> Bool {
        ledger.deferred[item] != nil
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
        ledger.reported = ledger.reported.filter { items.contains($0.key) }
        ledger.deferred = ledger.deferred.filter { items.contains($0.key) }
    }

    /// Forgets one item's result, so it is due again.
    public mutating func forget(_ item: UUID) {
        ledger.entries[item] = nil
        ledger.failures[item] = nil
        ledger.reported[item] = nil
        ledger.deferred[item] = nil
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

        // A deferral mark after now would let synced checks stand in for this device's own for as long as the clock
        // stays behind it, and a report dated after now would outrank this device's own checks: both happened now.
        if ledger.deferred.values.contains(where: { $0 > now }) {
            ledger.deferred = ledger.deferred.mapValues { min($0, now) }
        }
        if ledger.reported.values.contains(where: { $0.values.contains { $0.reportedAt > now } }) {
            ledger.reported = ledger.reported.mapValues { reports in
                reports.mapValues {
                    ScanLedger.Reported(occurrences: $0.occurrences, reportedAt: min($0.reportedAt, now))
                }
            }
        }
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
