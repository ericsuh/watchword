import Foundation
import SecureMemory
import WatchwordModel

public enum HygieneEngineError: Error, Equatable, Sendable {
    /// Keys are not resident: nothing may be hashed, analysed or handed out.
    case locked
    /// `unlock` is still analysing the items it was given, so a report now would be of part of the vault.
    case analysing
}

/// What one call to `HygieneEngine.scan` did.
public enum ScanOutcome: Hashable, Sendable {
    /// Keys are not resident. Nothing was hashed and nothing was sent.
    case locked
    /// Another scan is in flight, or `unlock` is still analysing; this engine does one thing at a time. The item
    /// stays due, and `next(now:)` will name it.
    case busy
    /// The item has no password, or is in the trash.
    case nothingToCheck
    /// The rate limit or a backoff says not before `until`. Nothing was hashed and nothing was sent.
    case deferred(until: Date)
    /// Every password in the item was checked and the ledger has the answers.
    case scanned(breachedPasswords: Int, networkRequests: Int)
    /// A check did not complete; the item stays due and the schedule has backed off.
    case failed(PwnedPasswordsError)
    /// The vault locked while the scan was in flight. The response, if any, was dropped: nothing was stored. The
    /// requests it had sent still count against the rate limit, and a refusal's `Retry-After` still stands.
    case interrupted
    /// The copy handed in is not the item as the engine knows it: an older version than one it has analysed, or a
    /// copy from before the item was trashed or deleted, or the item was saved again while its ranges were being
    /// fetched. Nothing was recorded for it. Fetch the item again and ask `next(now:)`.
    case stale
}

/// The part of hygiene that has state: what the session drives between unlock and lock (PRD F9.1 to F9.3,
/// docs/02-architecture.md §13, docs/adr/0005-hibp-while-locked.md).
///
/// It owns no timer and starts nothing by itself. The session calls `unlock` with the items it has decrypted, then
/// loops on `next(now:)`: scan the item it names (fetching that item's plaintext for the call), or wait until the
/// time it gives; calls `update` and `scan` when an item is saved; persists `ledger()` (sealed) when it changes,
/// which a failed scan does as well as a completed one; and calls `lock()` when the vault locks.
///
/// **Only while keys are resident.** Everything derived from a password (analyses, reuse tokens, the ledger, the
/// report) lives in one optional that `lock()` sets to `nil` after zeroising the reuse key, and `lock()` then tells
/// the prefix cache to forget what it holds in memory: which prefixes were asked for is twenty bits of each
/// password's hash (ADR 0005, amendment). Every entry point that hashes checks that optional first, and a scan
/// re-checks it after every suspension, so a lock that lands while a request is in flight wins: the response is
/// discarded, nothing is cached and the ledger is untouched. Passwords themselves are never kept: `scan` reads them
/// from the item it is handed and drops them when it returns.
///
/// **`lock()` never waits long.** An actor runs one call at a time, so `lock()` waits for whatever call is running
/// to reach a suspension. `unlock` analyses one item and then suspends, every item, and stops as soon as it finds
/// the vault locked or its task cancelled; every other call does a bounded amount of work on one item (at most
/// sixteen passwords of at most 64 analysed characters). Even so, the session must not make its own lock wait for
/// this actor: it zeroises the keyset first and locks the engine after, so that nothing here can keep the vault's
/// keys resident.
///
/// **A lock that cannot wait at all.** The session's `lock()` is synchronous, and a lock in a task after it would
/// leave the reuse key and every analysis resident until that task ran: through the rest of whatever the session is
/// doing, or for as long as the process stays suspended in the background. So the session builds its engine on its
/// own serial executor (`init(…, sharingExecutorWith:)`, `SharesExecutor`), and from its `lock()`, already on that
/// executor, calls
/// `dropKeys()` synchronously: everything derived from a password is gone before the session's `lock()` returns,
/// and `lock()` afterwards only has the prefix cache forget what it holds.
///
/// **Stale copies are refused.** The session fetches an item and then calls `update` or `scan`, and the actor is
/// re-entrant, so a save of the same item can land in between. The engine remembers the highest version of each
/// item it has been shown; an older copy changes nothing (`update` returns `false`, `scan` returns `.stale`), so it
/// can neither replace a newer analysis nor mark a newer password as checked.
///
/// What survives a lock is `ScanPacing` and nothing else: the rate limit and the server's `Retry-After` are not
/// derived from a password, and forgetting them at every unlock would turn each unlock into a burst of requests. A
/// scan that a lock interrupts still pays into it for the requests it sent. Which items' checks failed is not kept
/// here across a lock: it is in the ledger (`ScanLedger.Failure`), so **the session must seal and store `ledger()`
/// after a scan that fails as well as after one that succeeds**, and hand the stored ledger to the next `unlock`.
/// That is what keeps one refused range from being asked for first at every unlock (and every launch), with the
/// rest of the vault never reached.
///
/// **Whenever the engine goes from unlocked to locked, the prefix cache is emptied**, whichever call did it:
/// `lock()`, an `unlock` over an engine that was already unlocked (which is a lock first), or an `unlock` that was
/// cancelled. The one exception is `dropKeys()`, which cannot suspend, and whose caller calls `lock()` next.
public actor HygieneEngine: SharesExecutor {
    private struct Resident {
        let reuseKey: ReuseKey
        let analyzer: ItemAnalyzer
        var analyses: [UUID: ItemAnalysis] = [:]
        var reuse = ReuseIndex()
        var schedule: ScanSchedule
        /// The highest version of each item seen since unlock, trashed and deleted items included.
        var versions: [UUID: UInt64] = [:]
        /// Items that were trashed or deleted at the version above: a copy of that version that is not trashed is
        /// the item from before it went.
        var gone: Set<UUID> = []
        /// `unlock` has not finished analysing its items.
        var loading = true
        /// What other devices of each item's vault reported, for the version the session matched it against.
        var synced: [UUID: SyncedScanEvidence] = [:]
        /// The ledger changed outside a scan (a report taken in, a deferral marked) and has not been handed out
        /// since (`takeChangedLedger`).
        var ledgerChanged = false
    }

    private enum Applied {
        case analysed
        case removed
        case stale
    }

    private let client: PwnedPasswordsClient
    private let policy: HygienePolicy
    private let scanPolicy: ScanPolicy
    private let checkpoint: @Sendable () async -> Void
    private var random: any RandomNumberGenerator
    private var resident: Resident?
    /// The rate limit and backoff, kept across `lock()`; `nil` until the first lock.
    private var pacing: ScanPacing?
    /// Incremented by every `lock()`. A scan compares it before and after each suspension.
    private var epoch: UInt64 = 0
    private var scanning = false
    /// The owner of the serial executor the engine runs on: the session's, or (by default) one of its own.
    package nonisolated let executorOwner: SerialExecutorOwner

    /// - Parameter random: for the weekly pass's jitter only. Production passes the system generator; tests a seeded
    ///   one.
    public init<R: RandomNumberGenerator & Sendable>(
        client: PwnedPasswordsClient, policy: HygienePolicy = HygienePolicy(), scanPolicy: ScanPolicy = .standard,
        random: R = SystemRandomNumberGenerator()
    ) {
        self.init(client: client, policy: policy, scanPolicy: scanPolicy, random: random) { await Task.yield() }
    }

    /// An engine that runs on `owner`'s serial executor, so that an actor sharing it can call `dropKeys()`
    /// synchronously (`VaultSession`; docs/02-architecture.md §13.8).
    package init<R: RandomNumberGenerator & Sendable>(
        client: PwnedPasswordsClient, policy: HygienePolicy, scanPolicy: ScanPolicy, random: R,
        sharingExecutorWith owner: SerialExecutorOwner
    ) {
        self.init(
            client: client, policy: policy, scanPolicy: scanPolicy, random: random, executorOwner: owner
        ) { await Task.yield() }
    }

    /// - Parameter checkpoint: what `unlock` awaits between items, so that other calls (`lock()` above all) can
    ///   run. Production yields; a test passes a gate, to put a lock at a known item without sleeping.
    init<R: RandomNumberGenerator & Sendable>(
        client: PwnedPasswordsClient, policy: HygienePolicy, scanPolicy: ScanPolicy, random: R,
        executorOwner: SerialExecutorOwner? = nil, checkpoint: @escaping @Sendable () async -> Void
    ) {
        self.executorOwner = executorOwner ?? SerialExecutorOwner()
        self.client = client
        self.policy = policy
        self.scanPolicy = scanPolicy
        self.random = random
        self.checkpoint = checkpoint
    }

    public var isUnlocked: Bool {
        resident != nil
    }

    /// Whether `unlock` is still analysing the items it was given.
    public var isAnalysing: Bool {
        resident?.loading ?? false
    }

    // MARK: Unlock and lock

    /// Keys are now resident. Returns once every item has been analysed.
    ///
    /// The engine is unlocked from the start of this call, and analyses one item at a time, suspending after each
    /// so that `lock()`, `update` and `remove` can run in between. Until it returns, `next` answers `.wait(…,
    /// .analysing)`, `scan` answers `.busy` and `report` throws `.analysing`. Call it from a task of no higher
    /// priority than the one that locks.
    ///
    /// If the engine is already unlocked, this is a lock first, exactly as `lock()` does it: the previous reuse key
    /// is zeroised, everything derived under it is dropped and the prefix cache is emptied, before anything of the
    /// new unlock exists. So an unlock that then fails or is cancelled leaves what a lock leaves.
    ///
    /// - Parameters:
    ///   - reuseKey: at least 32 bytes derived from the keyset for this purpose. The engine takes it over and
    ///     zeroises it on `lock()`.
    ///   - ledger: the scan ledger the session unsealed (the one it stored after the last scan, failed ones
    ///     included), or an empty one.
    ///   - items: every item in every unlocked vault, decrypted. Trashed items are ignored. The engine keeps an
    ///     analysis of each, not the item.
    /// - Throws: `ReuseKeyError` for a key that is not one; `HygieneEngineError.locked` if `lock()` (or another
    ///   `unlock`) ran before this one finished; `CancellationError` if the task was cancelled, in which case the
    ///   engine is left locked and the prefix cache empty.
    ///   - synced: what other devices reported about the items' passwords (`SyncedScanEvidence`), each for the item
    ///     version the session matched it against; taken in as `updateSynced` would, once the items are analysed.
    public func unlock(
        reuseKey: SecureBytes, ledger: ScanLedger, items: [Item], synced: [SyncedScanEvidence] = [], now: Date
    ) async throws {
        let key = try ReuseKey(reuseKey)
        // `lock()` suspends on the cache, and another `unlock` can get in meanwhile; it is locked out in its turn.
        // When the loop ends nothing is resident and every state that was has had its cache emptied (or is having
        // it emptied by the `lock()` that dropped it), and nothing suspends between here and the new state.
        while resident != nil {
            await lock()
        }
        // Locking zeroised the previous key. If the caller handed that same buffer in again, it is not a key now.
        guard !reuseKey.isZeroised else { throw ReuseKeyError.zeroised }
        try Task.checkCancellation()
        epoch &+= 1
        resident = Resident(
            reuseKey: key, analyzer: ItemAnalyzer(estimator: StrengthEstimator(now: now), policy: policy),
            schedule: ScanSchedule(ledger: ledger, policy: scanPolicy, pacing: pacing))
        let started = epoch
        for item in items {
            guard !Task.isCancelled else {
                // Nothing can have been cached since this unlock began (`scan` is `.busy` until it returns), but
                // "locked" means "cache empty" on every path, without that argument.
                if isCurrent(started) { await lock() }
                throw CancellationError()
            }
            withResident { state in
                // An `update` or `remove` that ran while this loop was suspended has the newer word on the item.
                if state.versions[item.id] == nil, state.gone.contains(item.id) { return }
                if state.versions[item.id] == item.version { return }
                _ = Self.apply(item, to: &state)
            }
            await checkpoint()
            guard isCurrent(started) else { throw HygieneEngineError.locked }
        }
        withResident { state in
            // Results for items that no longer exist, or no longer have a password, describe nothing.
            state.schedule.prune(keeping: Set(state.analyses.values.filter { !$0.passwords.isEmpty }.map(\.id)))
            for evidence in synced { _ = Self.takeIn(evidence, to: &state, now: now) }
            state.loading = false
        }
    }

    /// Keys are going away. Zeroises the reuse key and drops everything derived from a password, at once; then
    /// has the prefix cache forget what it holds in memory. A scan in flight finds out when its request returns, and
    /// stores nothing.
    public func lock() async {
        dropResident()
        await client.lockCache()
    }

    /// The synchronous part of `lock()`, for a caller on the engine's executor that cannot wait (the session's
    /// `lock()`, through `assumeIsolated`): zeroises the reuse key and drops everything derived from a password. A
    /// scan or unlock in flight finds the engine locked when it resumes. Call `lock()` afterwards as well, to empty
    /// the prefix cache.
    package func dropKeys() {
        dropResident()
    }

    /// The synchronous part of locking: after this, nothing derived from a password is reachable from the engine.
    private func dropResident() {
        epoch &+= 1
        if let state = resident {
            pacing = state.schedule.pacing
            state.reuseKey.zeroise()
        }
        resident = nil
    }

    // MARK: Items

    /// An item was created, edited, restored, trashed or changed by sync.
    ///
    /// - Returns: `false` if the copy is stale (the engine has seen a newer version of the item, or this version
    ///   after it was trashed or deleted) and nothing changed.
    @discardableResult
    public func update(_ item: Item) throws -> Bool {
        guard let applied = withResident({ state in Self.apply(item, to: &state) }) else {
            throw HygieneEngineError.locked
        }
        return applied != .stale
    }

    /// Takes `item` into the resident state, unless it is a stale copy.
    private static func apply(_ item: Item, to state: inout Resident) -> Applied {
        if let seen = state.versions[item.id] {
            if item.version < seen { return .stale }
            if item.version == seen, state.gone.contains(item.id), !item.isTrashed { return .stale }
        }
        state.versions[item.id] = item.version
        guard !item.isTrashed else {
            state.gone.insert(item.id)
            state.analyses[item.id] = nil
            state.reuse.remove(item.id)
            state.schedule.forget(item.id)
            return .removed
        }
        state.gone.remove(item.id)
        let analysis = state.analyzer.analyse(item, reuseKey: state.reuseKey)
        state.analyses[item.id] = analysis
        state.reuse.set(analysis.reuseTokens, for: item.id)
        // Evidence matched against another version says nothing about this one's passwords; the session matches
        // again. Reports stay for the passwords the item still holds.
        if state.synced[item.id]?.itemVersion != item.version { state.synced[item.id] = nil }
        if state.schedule.keepReports(of: item.id, for: Set(analysis.passwords.map(\.ledgerBinding))) {
            state.ledgerChanged = true
        }
        if analysis.passwords.isEmpty { state.schedule.forget(item.id) }
        return .analysed
    }

    /// Takes in what other devices reported about `evidence.itemID`'s passwords, if it was matched against the
    /// version the engine knows: kept for the schedule and the report, and every breach in it remembered in the
    /// ledger (`ScanSchedule.recordReported`), where only this device's own later check removes it.
    private static func takeIn(_ evidence: SyncedScanEvidence, to state: inout Resident, now: Date) -> Bool {
        guard let analysis = state.analyses[evidence.itemID], analysis.version == evidence.itemVersion,
            !state.gone.contains(evidence.itemID)
        else { return false }
        state.synced[evidence.itemID] = evidence
        let tolerance = state.schedule.policy.clockTolerance
        for password in analysis.passwords {
            for observation in evidence.fields[password.fieldID] ?? [] {
                guard let bounded = PasswordBreachEvidence.bounded(observation, now: now, tolerance: tolerance),
                    case .found(let occurrences) = bounded.result
                else { continue }
                if state.schedule.recordReported(
                    item: evidence.itemID, binding: password.ledgerBinding, occurrences: occurrences,
                    at: bounded.scannedAt)
                {
                    state.ledgerChanged = true
                }
            }
        }
        return true
    }

    /// Runs `body` on the resident state, in place, or returns `nil` while locked. The state is taken out of the
    /// property for the duration so that it is uniquely referenced: mutating a copy would duplicate every analysis on
    /// every call. Nothing suspends in here, so no other caller can see the property empty.
    @discardableResult
    private func withResident<T>(_ body: (inout Resident) -> T) -> T? {
        guard var state = resident else { return nil }
        resident = nil
        defer { resident = state }
        return body(&state)
    }

    /// What other devices of the item's vault reported about its passwords (`SyncedScanEvidence.matching`), for the
    /// version it was matched against.
    ///
    /// - Returns: `false` if the engine knows the item at another version, or not at all, and ignored it.
    @discardableResult
    public func updateSynced(_ evidence: SyncedScanEvidence, now: Date) throws -> Bool {
        guard let taken = withResident({ Self.takeIn(evidence, to: &$0, now: now) }) else {
            throw HygieneEngineError.locked
        }
        return taken
    }

    /// The ledger, if something other than a scan changed it since it was last handed out here (a breach another
    /// device reported, a deferral to synced checks marked): for the session to seal and store, so that
    /// what it says lasts across a restart. `nil` if nothing did.
    public func takeChangedLedger() throws -> ScanLedger? {
        guard let changed = resident?.ledgerChanged else { throw HygieneEngineError.locked }
        guard changed else { return nil }
        return withResident { state in
            state.ledgerChanged = false
            return state.schedule.ledger
        }
    }

    /// An item was permanently deleted. A copy of it from before the deletion is refused from now on.
    public func remove(_ id: UUID) {
        withResident { state in
            state.synced[id] = nil
            state.gone.insert(id)
            state.analyses[id] = nil
            state.reuse.remove(id)
            state.schedule.forget(id)
        }
    }

    /// The items already using `password`, for the editor to warn before a reused password is saved.
    public func items(using password: String) throws -> [UUID] {
        guard let state = resident else { throw HygieneEngineError.locked }
        return state.reuse.items(sharing: state.reuseKey.token(forUTF8Of: password))
    }

    // MARK: Scanning

    /// What the scanner should do now (`ScanSchedule.decide`). `.locked` whenever keys are not resident.
    public func next(now: Date) -> ScanDecision {
        // (A copy of the resident state must not outlive these checks: it would make every later change copy the
        // analyses and the ledger.)
        guard let loading = resident?.loading else { return .locked }
        // Deciding on part of the vault could declare a pass finished that has not looked at most of it.
        if loading { return .wait(until: now.addingTimeInterval(scanPolicy.requestSpacing), .analysing) }
        if scanning { return .wait(until: now.addingTimeInterval(scanPolicy.requestSpacing), .pacing) }
        let decision = withResident { state in
            state.schedule.advance(now: now)
            let candidates = state.analyses.values.filter { !$0.passwords.isEmpty }.map {
                Self.candidate(for: $0, in: &state, now: now)
            }
            return state.schedule.decide(candidates: candidates, keysResident: true, now: now)
        }
        return decision ?? .locked
    }

    /// The item as the schedule sees it: when its passwords were last checked, by this device or, for a bounded
    /// time, by others (ADR 0005, amendment of 2026-11-16).
    ///
    /// This device's own checks count first. Synced checks count only where they would make the item not due when
    /// this device's own would not, and then for at most `ScanPolicy.maximumSyncDeferral` in all
    /// (`ScanSchedule.syncDeferral`); each is dated no later than now and none further ahead than the clock's
    /// tolerance, so a far-future scan time postpones nothing past the next pass.
    private static func candidate(for analysis: ItemAnalysis, in state: inout Resident, now: Date) -> ScanCandidate {
        let evidence = ItemBreachEvidence(
            analysis, ledger: state.schedule.ledger, synced: state.synced[analysis.id], now: now,
            tolerance: state.schedule.policy.clockTolerance)
        // This device's own check of this very version is the ledger entry the schedule reads itself, by the pass;
        // one of the same passwords at another version is handed in.
        let versionChecked = state.schedule.ledger.entries[analysis.id]?.itemVersion == analysis.version
        let own = ScanCandidate(
            id: analysis.id, version: analysis.version, coveredAt: versionChecked ? nil : evidence.ownCoveredAt)
        // Not due on this device's own checks (or no pass is in progress): nothing synced is standing in. A deferral
        // already marked stays marked; only this device's own check ends it, so the limit counts from the first
        // time synced checks stood in, however many passes come and go meanwhile.
        guard state.schedule.reason(for: own, now: now) != nil else { return own }
        guard let covered = evidence.coveredAt else { return own }
        let synced = ScanCandidate(id: analysis.id, version: analysis.version, coveredAt: covered)
        guard state.schedule.reason(for: synced, now: now) == nil else { return own }
        let marked = state.schedule.isDeferring(analysis.id)
        let deferring = state.schedule.syncDeferral(of: analysis.id, now: now) != nil
        if !marked { state.ledgerChanged = true }
        return deferring ? synced : own
    }

    /// Checks every password in `item` against Pwned Passwords and records the answers.
    ///
    /// This is both the step `next(now:)` asks for and the check a save triggers; either way it honours the same
    /// rate limit and backoff, so a burst of saves cannot become a burst of requests.
    public func scan(_ item: Item, now: Date) async -> ScanOutcome {
        guard let loading = resident?.loading else { return .locked }
        guard !scanning, !loading else { return .busy }
        enum Start {
            case stale
            case nothingToCheck
            case deferred(Date)
            case go(freshAfter: Date?)
        }
        let start: Start? = withResident { state in
            switch Self.apply(item, to: &state) {
            case .stale: return .stale
            case .removed: return .nothingToCheck
            case .analysed: break
            }
            guard let analysis = state.analyses[item.id], !analysis.passwords.isEmpty else { return .nothingToCheck }
            if let until = state.schedule.earliestStart(for: item.id, now: now) { return .deferred(until) }
            // The weekly pass asks the server again: a cached range from before the pass began does not count.
            let candidate = Self.candidate(for: analysis, in: &state, now: now)
            let weekly = state.schedule.reason(for: candidate, now: now) == .weekly
            return .go(freshAfter: weekly ? state.schedule.passInProgressSince : nil)
        }
        let freshAfter: Date?
        switch start {
        case nil: return .locked
        case .stale: return .stale
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
            guard isCurrent(started) else {
                settleInterrupted(requests: requests, failure: nil, now: now)
                return .interrupted
            }
            let digest = PasswordDigest(utf8Of: field.value)
            do {
                let check = try await client.check(digest, now: now, freshAfter: freshAfter) { [weak self] in
                    await self?.isCurrent(started) ?? false
                }
                if check.source == .network { requests += 1 }
                if check.result.isBreached { breached += 1 }
                // Field IDs are whatever the item says, and nothing makes them distinct. Two password fields with
                // one ID share one result, so it is the worse of the two: a breached password must never be
                // overwritten by the clean one that happens to follow it.
                results[field.id] = Self.worse(results[field.id], check.result)
            } catch {
                let failure = error as? PwnedPasswordsError ?? .transport
                // The client throws only after it has made its request, so that request is paid for either way.
                guard isCurrent(started), failure != .interrupted else {
                    settleInterrupted(requests: requests + 1, failure: failure, now: now)
                    return .interrupted
                }
                resident?.schedule.recordFailure(
                    item: item.id, version: item.version, error: failure, networkRequests: requests + 1, now: now,
                    jitter: jitter())
                return .failed(failure)
            }
        }
        guard isCurrent(started) else {
            settleInterrupted(requests: requests, failure: nil, now: now)
            return .interrupted
        }
        // The actor was free while the requests were in flight. If the item was saved, trashed or deleted
        // meanwhile, these answers are about passwords it no longer has.
        let unchanged = withResident { state in
            state.versions[item.id] == item.version && !state.gone.contains(item.id)
        }
        guard unchanged == true else {
            resident?.schedule.recordRequests(requests, now: now, jitter: jitter())
            return .stale
        }
        let bindings = withResident { state in
            Dictionary(
                (state.analyses[item.id]?.passwords ?? []).map { ($0.fieldID, $0.ledgerBinding) },
                uniquingKeysWith: { first, _ in first })
        }
        resident?.schedule.recordScan(
            item: item.id, version: item.version, results: results, bindings: bindings ?? [:],
            networkRequests: requests, now: now, jitter: jitter())
        return .scanned(breachedPasswords: breached, networkRequests: requests)
    }

    /// A lock interrupted a scan. Its answers are dropped, but the requests it sent were sent: they are charged to
    /// the rate limit, and a refusal's backoff is kept, wherever the pacing now lives (with the engine while locked,
    /// with the new schedule if the vault has been unlocked again). Without this, locking during each request
    /// would let any number of requests go at once, and drop a `Retry-After` that arrived just after a lock.
    /// Nothing else is written: not the ledger, and nothing about the item.
    private func settleInterrupted(requests: Int, failure: PwnedPasswordsError?, now: Date) {
        let refusal = failure == .interrupted ? nil : failure
        guard requests > 0 || refusal != nil else { return }
        let jitter = jitter()
        if resident != nil {
            resident?.schedule.recordInterrupted(networkRequests: requests, error: refusal, now: now, jitter: jitter)
        } else {
            pacing?.recordInterrupted(
                networkRequests: requests, error: refusal, now: now, jitter: jitter, policy: scanPolicy)
        }
    }

    private static func worse(_ earlier: PwnedPasswordResult?, _ later: PwnedPasswordResult) -> PwnedPasswordResult {
        switch (earlier, later) {
        case (.found(let first), .found(let second)): return .found(occurrences: max(first, second))
        case (.found, .notFound): return earlier ?? later
        case (.notFound, _), (nil, _): return later
        }
    }

    private func isCurrent(_ started: UInt64) -> Bool {
        epoch == started && resident != nil
    }

    private func jitter() -> Double {
        Double(random.next() >> 11) / Double(UInt64(1) << 53)
    }

    // MARK: Results

    /// The report as of `now`. Throws `.analysing` until `unlock` has returned: a report of the items analysed so
    /// far would call the vault cleaner than it is.
    public func report(now: Date) throws -> HygieneReport {
        guard let state = resident else { throw HygieneEngineError.locked }
        guard !state.loading else { throw HygieneEngineError.analysing }
        return HygieneReport.make(
            analyses: Array(state.analyses.values), ledger: state.schedule.ledger, now: now, policy: policy,
            synced: state.synced, clockTolerance: scanPolicy.clockTolerance)
    }

    /// The scan ledger, for the session to seal and store. Throws while locked: with keys absent there is nothing
    /// to persist and nothing to seal it with.
    public func ledger() throws -> ScanLedger {
        guard let state = resident else { throw HygieneEngineError.locked }
        return state.schedule.ledger
    }
}
