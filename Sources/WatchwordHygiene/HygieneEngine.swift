import Foundation
import SecureMemory
import WatchwordModel

public enum HygieneEngineError: Error, Equatable, Sendable {
    /// Keys are not resident: nothing may be hashed, analysed or handed out.
    case locked
}

/// What one call to `HygieneEngine.scan` did.
public enum ScanOutcome: Hashable, Sendable {
    /// Keys are not resident. Nothing was hashed and nothing was sent.
    case locked
    /// Another scan is in flight; this engine runs one at a time.
    case busy
    /// The item has no password, or is in the trash.
    case nothingToCheck
    /// The rate limit or a backoff says not before `until`. Nothing was hashed and nothing was sent.
    case deferred(until: Date)
    /// Every password in the item was checked and the ledger has the answers.
    case scanned(breachedPasswords: Int, networkRequests: Int)
    /// A check did not complete; the item stays due and the schedule has backed off.
    case failed(PwnedPasswordsError)
    /// The vault locked while the scan was in flight. The response, if any, was dropped: nothing was stored.
    case interrupted
}

/// The part of hygiene that has state: what the session drives between unlock and lock (PRD F9.1 to F9.3,
/// docs/02-architecture.md §13, docs/adr/0005-hibp-while-locked.md).
///
/// It owns no timer and starts nothing by itself. The session calls `unlock` with the items it has decrypted, then
/// loops on `next(now:)`: scan the item it names (fetching that item's plaintext for the call), or wait until the
/// time it gives; calls `update` and `scan` when an item is saved; persists `ledger()` (sealed) when it changes; and
/// calls `lock()` when the vault locks.
///
/// **Only while keys are resident.** Everything derived from a password (analyses, reuse tokens, the ledger, the
/// report) lives in one optional that `lock()` sets to `nil` after zeroising the reuse key. Every entry point that
/// hashes checks that optional first, and a scan re-checks it after every suspension, so a lock that lands while a
/// request is in flight wins: the response is discarded, nothing is cached and the ledger is untouched. Passwords
/// themselves are never kept: `scan` reads them from the item it is handed and drops them when it returns.
public actor HygieneEngine {
    private struct Resident {
        let reuseKey: ReuseKey
        let analyzer: ItemAnalyzer
        var analyses: [UUID: ItemAnalysis] = [:]
        var reuse = ReuseIndex()
        var schedule: ScanSchedule
    }

    private let client: PwnedPasswordsClient
    private let policy: HygienePolicy
    private let scanPolicy: ScanPolicy
    private var random: any RandomNumberGenerator
    private var resident: Resident?
    /// Incremented by every `lock()`. A scan compares it before and after each suspension.
    private var epoch: UInt64 = 0
    private var scanning = false

    /// - Parameter random: for the weekly pass's jitter only. Production passes the system generator; tests a seeded
    ///   one.
    public init<R: RandomNumberGenerator & Sendable>(
        client: PwnedPasswordsClient, policy: HygienePolicy = HygienePolicy(), scanPolicy: ScanPolicy = .standard,
        random: R = SystemRandomNumberGenerator()
    ) {
        self.client = client
        self.policy = policy
        self.scanPolicy = scanPolicy
        self.random = random
    }

    public var isUnlocked: Bool {
        resident != nil
    }

    // MARK: Unlock and lock

    /// Keys are now resident.
    ///
    /// - Parameters:
    ///   - reuseKey: at least 32 bytes derived from the keyset for this purpose. The engine takes it over and
    ///     zeroises it on `lock()`.
    ///   - ledger: the scan ledger the session unsealed, or an empty one.
    ///   - items: every item in every unlocked vault, decrypted. Trashed items are ignored. The engine keeps an
    ///     analysis of each, not the item.
    public func unlock(reuseKey: SecureBytes, ledger: ScanLedger, items: [Item], now: Date) throws {
        let key = try ReuseKey(reuseKey)
        lock()
        // Locking zeroised the previous key. If the caller handed that same buffer in again, it is not a key now.
        guard !reuseKey.isZeroised else { throw ReuseKeyError.zeroised }
        var state = Resident(
            reuseKey: key, analyzer: ItemAnalyzer(estimator: StrengthEstimator(now: now), policy: policy),
            schedule: ScanSchedule(ledger: ledger, policy: scanPolicy))
        for item in items where !item.isTrashed {
            let analysis = state.analyzer.analyse(item, reuseKey: key)
            state.analyses[item.id] = analysis
            state.reuse.set(analysis.reuseTokens, for: item.id)
        }
        // Results for items that no longer exist, or no longer have a password, describe nothing.
        state.schedule.prune(keeping: Set(state.analyses.values.filter { !$0.passwords.isEmpty }.map(\.id)))
        resident = state
    }

    /// Keys are going away. Zeroises the reuse key and drops everything derived from a password. A scan in flight
    /// finds out when its request returns, and stores nothing.
    public func lock() {
        epoch &+= 1
        resident?.reuseKey.zeroise()
        resident = nil
    }

    // MARK: Items

    /// An item was created, edited, restored, trashed or changed by sync.
    public func update(_ item: Item) throws {
        let updated: Void? = withResident { state in
            if item.isTrashed {
                state.analyses[item.id] = nil
                state.reuse.remove(item.id)
                state.schedule.forget(item.id)
            } else {
                let analysis = state.analyzer.analyse(item, reuseKey: state.reuseKey)
                state.analyses[item.id] = analysis
                state.reuse.set(analysis.reuseTokens, for: item.id)
                if analysis.passwords.isEmpty { state.schedule.forget(item.id) }
            }
        }
        guard updated != nil else { throw HygieneEngineError.locked }
    }

    /// Runs `body` on the resident state, in place, or returns `nil` while locked. The state is taken out of the
    /// property for the duration so that it is uniquely referenced: mutating a copy would duplicate every analysis on
    /// every call. Nothing suspends in here, so no other caller can see the property empty.
    private func withResident<T>(_ body: (inout Resident) -> T) -> T? {
        guard var state = resident else { return nil }
        resident = nil
        defer { resident = state }
        return body(&state)
    }

    /// An item was permanently deleted.
    public func remove(_ id: UUID) {
        resident?.analyses[id] = nil
        resident?.reuse.remove(id)
        resident?.schedule.forget(id)
    }

    /// The items already using `password`, for the editor to warn before a reused password is saved.
    public func items(using password: String) throws -> [UUID] {
        guard let state = resident else { throw HygieneEngineError.locked }
        return state.reuse.items(sharing: state.reuseKey.token(forUTF8Of: password))
    }

    // MARK: Scanning

    /// What the scanner should do now (`ScanSchedule.decide`). `.locked` whenever keys are not resident.
    public func next(now: Date) -> ScanDecision {
        guard resident != nil else { return .locked }
        if scanning { return .wait(until: now.addingTimeInterval(scanPolicy.requestSpacing), .pacing) }
        let decision = withResident { state in
            let candidates = state.analyses.values.filter { !$0.passwords.isEmpty }.map(\.candidate)
            return state.schedule.decide(candidates: candidates, keysResident: true, now: now)
        }
        return decision ?? .locked
    }

    /// Checks every password in `item` against Pwned Passwords and records the answers.
    ///
    /// This is both the step `next(now:)` asks for and the check a save triggers; either way it honours the same
    /// rate limit and backoff, so a burst of saves cannot become a burst of requests.
    public func scan(_ item: Item, now: Date) async -> ScanOutcome {
        guard resident != nil else { return .locked }
        guard !scanning else { return .busy }
        guard (try? update(item)) != nil else { return .locked }
        enum Start {
            case nothingToCheck
            case deferred(Date)
            case go(freshAfter: Date?)
        }
        let start: Start? = withResident { state in
            guard let analysis = state.analyses[item.id], !analysis.passwords.isEmpty else { return .nothingToCheck }
            if let until = state.schedule.earliestStart(for: item.id, now: now) { return .deferred(until) }
            // The weekly pass asks the server again: a cached range from before the pass began does not count.
            let weekly = state.schedule.reason(for: analysis.candidate, now: now) == .weekly
            return .go(freshAfter: weekly ? state.schedule.passInProgressSince : nil)
        }
        let freshAfter: Date?
        switch start {
        case nil: return .locked
        case .nothingToCheck: return .nothingToCheck
        case .deferred(let until): return .deferred(until: until)
        case .go(let fresh): freshAfter = fresh
        }

        scanning = true
        defer { scanning = false }
        let started = epoch
        var results: [UUID: PwnedPasswordResult] = [:]
        var requests = 0
        var breached = 0
        for field in ItemAnalyzer.passwordFields(of: item) {
            // Hashing happens here and nowhere earlier, and only if the vault is still unlocked.
            guard isCurrent(started) else { return .interrupted }
            let digest = PasswordDigest(utf8Of: field.value)
            do {
                let check = try await client.check(digest, now: now, freshAfter: freshAfter) { [weak self] in
                    await self?.isCurrent(started) ?? false
                }
                if check.source == .network { requests += 1 }
                if check.result.isBreached { breached += 1 }
                results[field.id] = check.result
            } catch {
                guard isCurrent(started) else { return .interrupted }
                let failure = error as? PwnedPasswordsError ?? .transport
                guard failure != .interrupted else { return .interrupted }
                resident?.schedule.recordFailure(
                    item: item.id, error: failure, networkRequests: requests + 1, now: now, jitter: jitter())
                return .failed(failure)
            }
        }
        guard isCurrent(started) else { return .interrupted }
        resident?.schedule.recordScan(
            item: item.id, version: item.version, results: results, networkRequests: requests, now: now,
            jitter: jitter())
        return .scanned(breachedPasswords: breached, networkRequests: requests)
    }

    private func isCurrent(_ started: UInt64) -> Bool {
        epoch == started && resident != nil
    }

    private func jitter() -> Double {
        Double(random.next() >> 11) / Double(UInt64(1) << 53)
    }

    // MARK: Results

    /// The report as of `now`.
    public func report(now: Date) throws -> HygieneReport {
        guard let state = resident else { throw HygieneEngineError.locked }
        return HygieneReport.make(
            analyses: Array(state.analyses.values), ledger: state.schedule.ledger, now: now, policy: policy)
    }

    /// The scan ledger, for the session to seal and store. Throws while locked: with keys absent there is nothing
    /// to persist and nothing to seal it with.
    public func ledger() throws -> ScanLedger {
        guard let state = resident else { throw HygieneEngineError.locked }
        return state.schedule.ledger
    }
}
