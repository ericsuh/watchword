import Foundation
import SecureMemory
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordHygiene
import WatchwordModel
import WatchwordStore

/// What the session needs to check passwords against Pwned Passwords and keep the hygiene report
/// (docs/02-architecture.md §13.8). The network is the `HTTPClient` port, injected here; the URLSession adapter is
/// `WatchwordPlatform`'s. `localStore` holds this device's sealed scan ledger and prefix cache.
public struct HygieneSettings: Sendable {
    public var http: any HTTPClient
    public var userAgent: HygieneUserAgent
    public var localStore: any DeviceLocalStore
    public var policy: HygienePolicy
    public var scanPolicy: ScanPolicy
    /// The persisted prefix cache's bounds (`InMemoryPwnedRangeCache`'s defaults): beyond either, the oldest go.
    public var cacheCapacity: Int
    public var cacheMaximumBytes: Int

    public init(
        http: any HTTPClient, userAgent: HygieneUserAgent, localStore: any DeviceLocalStore,
        policy: HygienePolicy = HygienePolicy(), scanPolicy: ScanPolicy = .standard,
        cacheCapacity: Int = InMemoryPwnedRangeCache.defaultCapacity,
        cacheMaximumBytes: Int = InMemoryPwnedRangeCache.defaultMaximumBytes
    ) {
        self.http = http
        self.userAgent = userAgent
        self.localStore = localStore
        self.policy = policy
        self.scanPolicy = scanPolicy
        self.cacheCapacity = max(1, cacheCapacity)
        self.cacheMaximumBytes = max(0, cacheMaximumBytes)
    }
}

/// What one scheduled hygiene step did (`VaultSession.runHygieneStep()`).
public enum HygieneStep: Sendable, Hashable {
    /// The scheduler named this item, and the engine checked it (or said why not).
    case scanned(item: UUID, ScanOutcome)
    /// Something is due, but not before `until`. Call again then.
    case wait(until: Date, ScanWait)
    /// Every item is current; the next weekly pass starts at `nextFullScanAt`.
    case idle(nextFullScanAt: Date)
}

/// The hygiene engine and what the session keeps to drive it. Actor-isolated to the session: the device-local key
/// lives here, is used only on the actor, and is zeroised by `lock()` with the keyset.
struct HygieneRuntime {
    struct Known: Hashable {
        var version: UInt64
        var inDeletedVault: Bool
    }

    let engine: HygieneEngine
    let settings: HygieneSettings
    /// The device-local key; `nil` while locked, and until the engine's unlock task has read the device secret.
    var localKey: EncryptionKey?
    /// The engine's `unlock`, running in a task of its own; cancelled by `lock()`.
    var unlockTask: Task<Void, Never>?
    /// The engine's `lock()`, which the next unlock waits for.
    var lockTask: Task<Void, Never>?
    /// The lock epoch for which the engine finished analysing the vault.
    var readyEpoch: UInt64?
    /// What the engine was last shown of each item, so a reconcile decrypts only what changed.
    var known: [UUID: Known] = [:]
}

/// The prefix cache the engine's client uses: sealed records in the device-local store, read and written only
/// through the session, which seals and opens them on its own actor and refuses while locked. It holds nothing
/// itself, so its `lock()` has nothing to drop: once the session's keys are gone, no prefix is readable (ADR 0005,
/// amendment). The session is held weakly, so the cache cannot keep it alive.
actor SealedPwnedRangeCache: PwnedRangeCache {
    private weak var session: VaultSession?

    init(session: VaultSession) {
        self.session = session
    }

    func cachedRange(for prefix: PwnedRangePrefix) async -> CachedPwnedRange? {
        await session?.hygieneCachedRange(prefix)
    }

    func store(_ entry: CachedPwnedRange) async {
        await session?.hygieneCacheStore(entry)
    }

    func remove(_ prefix: PwnedRangePrefix) async {
        await session?.hygieneCacheRemove([prefix.value])
    }

    func removeAll() async {
        await session?.hygieneCacheRemove(nil)
    }

    func lock() async {}
}

/// The sealed index of the prefix cache: for each prefix, when it was fetched and how large its record is, so
/// eviction needs no record opened. `"WWRI"`, a version byte, a count, then 3 + 8 + 4 bytes an entry, big-endian.
struct RangeCacheIndex: Hashable {
    struct Entry: Hashable {
        var fetchedAt: Int64
        var size: UInt32
    }

    static let magic = Array("WWRI".utf8)
    static let maximumEntries = 4096
    var entries: [UInt32: Entry] = [:]

    func encoded() -> [UInt8] {
        var out = Self.magic + [1]
        out += Self.bigEndian(UInt64(entries.count), bytes: 4)
        for (prefix, entry) in entries.sorted(by: { $0.key < $1.key }) {
            out += Self.bigEndian(UInt64(prefix), bytes: 3)
            out += Self.bigEndian(UInt64(bitPattern: entry.fetchedAt), bytes: 8)
            out += Self.bigEndian(UInt64(entry.size), bytes: 4)
        }
        return out
    }

    init() {}

    /// Exact: every length and count checked, a prefix listed once, within the twenty bits a prefix has.
    init?(decoding bytes: [UInt8]) {
        guard bytes.count >= 9, Array(bytes[0..<4]) == Self.magic, bytes[4] == 1 else { return nil }
        let count = Int(Self.read(bytes, 5, 4))
        guard count <= Self.maximumEntries, bytes.count == 9 + count * 15 else { return nil }
        for index in 0..<count {
            let offset = 9 + index * 15
            let prefix = UInt32(Self.read(bytes, offset, 3))
            guard prefix < 1 << 20, entries[prefix] == nil else { return nil }
            entries[prefix] = Entry(
                fetchedAt: Int64(bitPattern: Self.read(bytes, offset + 3, 8)),
                size: UInt32(Self.read(bytes, offset + 11, 4)))
        }
    }

    private static func bigEndian(_ value: UInt64, bytes: Int) -> [UInt8] {
        (0..<bytes).map { UInt8(truncatingIfNeeded: value >> UInt64(8 * (bytes - 1 - $0))) }
    }

    private static func read(_ bytes: [UInt8], _ offset: Int, _ count: Int) -> UInt64 {
        bytes[offset..<(offset + count)].reduce(0) { $0 << 8 | UInt64($1) }
    }
}

// Hygiene in the session (PRD F9.1 to F9.3; docs/02-architecture.md §13.8; ADR 0005 and its amendment).
//
// The session owns one `HygieneEngine` for its lifetime (so the engine's pacing survives a lock). At every unlock it
// derives the reuse key from the keyset (`DeviceLocalKeys.hygieneReuseKey`, never the raw key) and starts the
// engine's `unlock` in a task of its own, which derives the device-local key from the keyset and this device's
// Keychain secret and unseals the scan ledger; `lock()` zeroises the keyset first, then drops the engine's keys (the
// engine runs on the session's executor), then the local key, cancels that task and has the engine empty its cache,
// never the other way round. Saves update the
// engine; every query reconciles it with the store first, so a sync merge, a deletion or anything else that changed
// a row is reflected in what the person is shown. Nothing here runs by itself: the UI or a background task calls
// `runHygieneStep()`, and the engine's schedule decides whether anything is sent.
extension VaultSession {
    static let hygieneLedgerLimit = 48 << 20
    static let hygieneRangeLimit = 2 << 20
    static let hygieneIndexLimit = 64 << 10

    // MARK: - Unlock and lock

    /// After `install`: keys are resident. Derives the engine's keys now, on the actor, and starts its unlock.
    func startHygiene() {
        guard let settings = configuration.hygiene, let keys else { return }
        if hygieneRuntime == nil {
            let client = PwnedPasswordsClient(
                http: settings.http, cache: SealedPwnedRangeCache(session: self), userAgent: settings.userAgent)
            hygieneRuntime = HygieneRuntime(
                engine: HygieneEngine(
                    client: client, policy: settings.policy, scanPolicy: settings.scanPolicy, random: random,
                    sharingExecutorWith: executorOwner),
                settings: settings)
        }
        guard var runtime = hygieneRuntime else { return }
        let epoch = lockEpoch
        runtime.unlockTask?.cancel()
        runtime.localKey?.zeroise()
        runtime.localKey = nil
        runtime.readyEpoch = nil
        runtime.known = [:]
        let reuseKey = DeviceLocalKeys.hygieneReuseKey(keyset: keys.keyset)
        let previousLock = runtime.lockTask
        runtime.unlockTask = Task(priority: .utility) {
            await previousLock?.value
            await self.unlockHygieneEngine(reuseKey: reuseKey, since: epoch)
        }
        hygieneRuntime = runtime
    }

    /// From `lock()`, after the keyset is zeroised. Synchronous: the lock never waits for the engine. The engine runs
    /// on this session's executor (`SharesExecutor`), so its reuse key and analyses are dropped here, before `lock()`
    /// returns; the task only has it empty the prefix cache. With the drop in that task, everything derived from a
    /// password stayed resident for as long as the session was busy or the process suspended (review finding L2).
    func stopHygiene() {
        guard var runtime = hygieneRuntime else { return }
        runtime.engine.assumeIsolated { $0.dropKeys() }
        runtime.localKey?.zeroise()
        runtime.localKey = nil
        runtime.unlockTask?.cancel()
        runtime.unlockTask = nil
        runtime.readyEpoch = nil
        runtime.known = [:]
        let engine = runtime.engine
        let previousLock = runtime.lockTask
        runtime.lockTask = Task {
            await previousLock?.value
            await engine.lock()
        }
        hygieneRuntime = runtime
    }

    private func unlockHygieneEngine(reuseKey: SecureBytes, since epoch: UInt64) async {
        guard let engine = hygieneRuntime?.engine, epoch == lockEpoch, keys != nil else {
            reuseKey.zeroise()
            return
        }
        await installLocalKey(since: epoch)
        let ledger = await loadScanLedger(since: epoch) ?? ScanLedger()
        let listing: ItemListing
        let deleted: Set<UUID>
        do {
            listing = try await items()
            guard let account = try await loadAccount() else { throw VaultError.noAccount }
            deleted = Set(try await vaultDirectory(account).filter { $0.value.isDeleted }.keys)
            _ = try requireKeys(since: epoch)
        } catch {
            reuseKey.zeroise()
            return
        }
        hygieneRuntime?.known = Dictionary(
            listing.items.map {
                ($0.id, HygieneRuntime.Known(version: $0.version, inDeletedVault: deleted.contains($0.vaultID)))
            }, uniquingKeysWith: { first, _ in first })
        do {
            try await engine.unlock(reuseKey: reuseKey, ledger: ledger, items: listing.items, now: await clock.now())
        } catch {
            reuseKey.zeroise()
            return
        }
        guard epoch == lockEpoch, keys != nil else { return }
        hygieneRuntime?.readyEpoch = epoch
    }

    /// Derives the device-local key from the keyset and this device's secret, which it reads from the Keychain
    /// (creating it the first time). Without the secret (the Keychain refused), there is no local key for this unlock:
    /// the engine runs from an empty ledger and nothing is cached or stored, which is the safe reading.
    private func installLocalKey(since epoch: UInt64) async {
        guard let account else { return }
        guard let secret = try? await deviceLocalSecret(accountID: account.accountID) else { return }
        defer { secret.zeroise() }
        guard epoch == lockEpoch, let keys, self.account?.deviceID == account.deviceID,
            let key = try? DeviceLocalKeys.deviceLocalKey(
                keyset: keys.keyset, deviceSecret: secret, deviceID: account.deviceID)
        else { return }
        hygieneRuntime?.localKey?.zeroise()
        hygieneRuntime?.localKey = key
    }

    /// This device's secret for its local records (`KeychainItem.deviceLocalSecret`). The Keychain is the only place
    /// it is kept: never in the store, never synced. One of any other length is replaced (it would open nothing).
    private func deviceLocalSecret(accountID: UUID) async throws -> SecureBytes {
        let item = KeychainItem.deviceLocalSecret(accountID: accountID)
        if let stored = try await keychain.read(item, prompt: "") {
            if stored.count == DeviceLocalKeys.deviceSecretLength { return stored }
            stored.zeroise()
        }
        let fresh = SecureBytes(randomCount: DeviceLocalKeys.deviceSecretLength, using: &random)
        do {
            try await keychain.store(fresh, for: item)
        } catch {
            fresh.zeroise()
            throw error
        }
        return fresh
    }

    /// Waits for the engine's unlock of this unlock, then brings it up to date with the store. Throws `locked` if the
    /// vault locked meanwhile, or the engine could not be unlocked.
    private func readyHygiene() async throws -> (HygieneEngine, UInt64) {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let runtime = hygieneRuntime else {
            throw configuration.hygiene == nil ? VaultError.hygieneNotConfigured : VaultError.locked
        }
        await runtime.unlockTask?.value
        _ = try requireKeys(since: epoch)
        guard hygieneRuntime?.readyEpoch == epoch else { throw VaultError.locked }
        try await reconcileHygiene(since: epoch)
        return (runtime.engine, epoch)
    }

    /// Shows the engine every item whose row changed since it was last shown, and removes what is gone. Rows are
    /// compared by version (and whether their vault was deleted, which changes how the item is presented), so only
    /// changed items are decrypted.
    func reconcileHygiene(since epoch: UInt64? = nil) async throws {
        let epoch = epoch ?? lockEpoch
        guard let engine = hygieneRuntime?.engine, hygieneRuntime?.readyEpoch == epoch else { return }
        _ = try requireKeys(since: epoch)
        guard let account = try await loadAccount() else { return }
        let directory = try await vaultDirectory(account)
        var rows: [StoredRecord] = []
        for vaultID in directory.keys {
            rows += try await store.records(in: vaultID, kind: .item)
        }
        let keys = try requireKeys(since: epoch)
        guard let known = hygieneRuntime?.known else { return }
        var seen: Set<UUID> = []
        var changed: [(Item, HygieneRuntime.Known)] = []
        for row in rows {
            seen.insert(row.recordID)
            let now = HygieneRuntime.Known(
                version: row.version, inDeletedVault: directory[row.vaultID]?.isDeleted ?? false)
            guard known[row.recordID] != now, let item = try? openItem(row, keys: keys) else { continue }
            changed.append((Self.presented(item, inDeletedVault: now.inDeletedVault), now))
        }
        let gone = Set(known.keys).subtracting(seen)
        for id in gone {
            await engine.remove(id)
            guard epoch == lockEpoch else { return }
            hygieneRuntime?.known[id] = nil
        }
        for (item, state) in changed {
            guard (try? await engine.update(item)) != nil, epoch == lockEpoch else { return }
            hygieneRuntime?.known[item.id] = state
        }
    }

    /// After a commit of `item`: the engine sees the new version at once (an edit is due for a check).
    func noteHygieneWrite(_ item: Item) async {
        let epoch = lockEpoch
        guard let engine = hygieneRuntime?.engine, hygieneRuntime?.readyEpoch == epoch else { return }
        guard (try? await engine.update(item)) != nil, epoch == lockEpoch else { return }
        hygieneRuntime?.known[item.id] = HygieneRuntime.Known(version: item.version, inDeletedVault: false)
    }

    /// Erases the sealed ledger and cache: the account is being deleted.
    func eraseHygieneRecords() async throws {
        try await configuration.hygiene?.localStore.deleteAll()
    }

    // MARK: - What the UI calls

    /// The hygiene report (PRD F9.3): every unlocked item's findings and the totals behind them. Waits for the engine
    /// to finish analysing the vault after an unlock, and reconciles it with the store first.
    public func hygieneReport() async throws -> HygieneReport {
        let (engine, epoch) = try await readyHygiene()
        let now = await clock.now()
        _ = try requireKeys(since: epoch)
        do {
            return try await engine.report(now: now)
        } catch HygieneEngineError.locked {
            throw VaultError.locked
        }
    }

    /// The items already using `password`, for the editor to warn before a reused password is saved (PRD F9.2).
    public func itemsUsingPassword(_ password: String) async throws -> [UUID] {
        let (engine, _) = try await readyHygiene()
        do {
            return try await engine.items(using: password)
        } catch HygieneEngineError.locked {
            throw VaultError.locked
        }
    }

    /// One step of the breach scan, for the UI or a background task to call (there is no timer in the session): asks
    /// the engine's schedule what is due, checks that item if anything is, and stores the sealed ledger after a check
    /// that completed or failed. Returns when to call again. Nothing is sent while locked, and a scan that a lock
    /// interrupts records nothing (the engine drops its answers; the session, without keys, writes nothing).
    public func runHygieneStep() async throws -> HygieneStep {
        let (engine, epoch) = try await readyHygiene()
        let now = await clock.now()
        _ = try requireKeys(since: epoch)
        switch await engine.next(now: now) {
        case .locked:
            throw VaultError.locked
        case .wait(let until, let reason):
            return .wait(until: until, reason)
        case .idle(let next):
            return .idle(nextFullScanAt: next)
        case .scan(let id, _):
            let item: Item
            do {
                item = try await self.item(id: id)
            } catch VaultError.itemNotFound {
                // Deleted since the engine last saw it: the next reconcile removes it.
                try await reconcileHygiene(since: epoch)
                return .scanned(item: id, .stale)
            }
            _ = try requireKeys(since: epoch)
            let outcome = await engine.scan(item, now: now)
            switch outcome {
            case .scanned, .failed:
                // Failed checks too: the failure in the ledger keeps one refused range from being asked for first at
                // every unlock and every launch (§13.3).
                await storeScanLedger(since: epoch)
            case .stale:
                try? await reconcileHygiene(since: epoch)
            case .locked, .busy, .nothingToCheck, .deferred, .interrupted:
                break
            }
            return .scanned(item: id, outcome)
        }
    }

    // MARK: - Sealed local records

    static func localContext(name: UUID, accountID: UUID, key: EncryptionKey) -> EnvelopeContext {
        // `accountHeader`, as for quick unlock's wrapped AUK: an account-level record kept on this device only, under
        // a key nothing else is sealed with.
        EnvelopeContext(
            recordID: name, vaultID: accountID, schemaVersion: 1, kind: .accountHeader, keyID: key.keyID,
            recordVersion: 0)
    }

    private struct LocalSealing {
        let key: EncryptionKey
        let accountID: UUID
        let store: any DeviceLocalStore
    }

    /// The device-local key and this account, if the vault is still unlocked at `epoch`. Asked again after every
    /// suspension, before the key is used.
    private func localSealing(since epoch: UInt64) -> LocalSealing? {
        guard epoch == lockEpoch, keys != nil, let account, let runtime = hygieneRuntime,
            let key = runtime.localKey, !key.isZeroised
        else { return nil }
        return LocalSealing(key: key, accountID: account.accountID, store: runtime.settings.localStore)
    }

    private func sealLocal(_ plaintext: SecureBytes, name: UUID, since epoch: UInt64) async throws {
        guard let local = localSealing(since: epoch) else { throw VaultError.locked }
        let envelope = try RecordCipher.seal(
            plaintext, context: Self.localContext(name: name, accountID: local.accountID, key: local.key),
            key: local.key, using: &random)
        try await local.store.write(envelope, as: name)
    }

    /// The plaintext of the record under `name`, or `nil` if there is none, it does not open under this device's key
    /// at this name, or the vault locked meanwhile.
    private func openLocal(name: UUID, maximumLength: Int, since epoch: UInt64) async -> SecureBytes? {
        guard let store = localSealing(since: epoch)?.store,
            let envelope = try? await store.read(name), envelope.count <= maximumLength + 4096,
            let local = localSealing(since: epoch)
        else { return nil }
        return try? RecordCipher.open(
            envelope, context: Self.localContext(name: name, accountID: local.accountID, key: local.key),
            key: local.key, maximumLength: maximumLength)
    }

    func localName(_ label: String, _ message: [UInt8] = [], since epoch: UInt64) -> UUID? {
        guard let local = localSealing(since: epoch) else { return nil }
        return DeviceLocalKeys.recordName(label, message, key: local.key)
    }

    /// The scan ledger this device stored, or `nil` (none, or not this device's, or damaged): an empty ledger is the
    /// safe reading, since everything is then due for a check.
    func loadScanLedger(since epoch: UInt64) async -> ScanLedger? {
        guard let name = localName("scan-ledger", since: epoch),
            let plaintext = await openLocal(name: name, maximumLength: Self.hygieneLedgerLimit, since: epoch)
        else { return nil }
        defer { plaintext.zeroise() }
        return try? JSONDecoder().decode(ScanLedger.self, from: Data(plaintext.unprotectedCopy()))
    }

    private func storeScanLedger(since epoch: UInt64) async {
        guard let engine = hygieneRuntime?.engine, let ledger = try? await engine.ledger(),
            let name = localName("scan-ledger", since: epoch), var encoded = try? Array(JSONEncoder().encode(ledger))
        else { return }
        let plaintext = SecureBytes(wiping: &encoded)
        defer { plaintext.zeroise() }
        try? await sealLocal(plaintext, name: name, since: epoch)
    }

    private static func prefixBytes(_ value: UInt32) -> [UInt8] {
        [UInt8(value >> 16 & 0xFF), UInt8(value >> 8 & 0xFF), UInt8(value & 0xFF)]
    }

    private func loadCacheIndex(since epoch: UInt64) async -> RangeCacheIndex {
        guard let name = localName("range-index", since: epoch),
            let plaintext = await openLocal(name: name, maximumLength: Self.hygieneIndexLimit, since: epoch)
        else { return RangeCacheIndex() }
        defer { plaintext.zeroise() }
        return RangeCacheIndex(decoding: plaintext.unprotectedCopy()) ?? RangeCacheIndex()
    }

    private func storeCacheIndex(_ index: RangeCacheIndex, since epoch: UInt64) async throws {
        guard let name = localName("range-index", since: epoch) else { throw VaultError.locked }
        var encoded = index.encoded()
        let plaintext = SecureBytes(wiping: &encoded)
        defer { plaintext.zeroise() }
        try await sealLocal(plaintext, name: name, since: epoch)
    }

    func hygieneCachedRange(_ prefix: PwnedRangePrefix) async -> CachedPwnedRange? {
        let epoch = lockEpoch
        guard let name = localName("range", Self.prefixBytes(prefix.value), since: epoch),
            let plaintext = await openLocal(name: name, maximumLength: Self.hygieneRangeLimit, since: epoch)
        else { return nil }
        defer { plaintext.zeroise() }
        // The record opened under this name, which is derived from the prefix; the decoded prefix must agree.
        guard let entry = try? CachedPwnedRange(decoding: plaintext.unprotectedCopy()), entry.range.prefix == prefix
        else { return nil }
        return entry
    }

    func hygieneCacheStore(_ entry: CachedPwnedRange) async {
        let epoch = lockEpoch
        let prefix = entry.range.prefix.value
        guard let settings = hygieneRuntime?.settings,
            let name = localName("range", Self.prefixBytes(prefix), since: epoch)
        else { return }
        var bytes = entry.encoded()
        let size = bytes.count
        guard size <= Self.hygieneRangeLimit else { return }
        let plaintext = SecureBytes(wiping: &bytes)
        defer { plaintext.zeroise() }
        do {
            try await sealLocal(plaintext, name: name, since: epoch)
            var index = await loadCacheIndex(since: epoch)
            let fetchedAt = Int64(entry.fetchedAt.timeIntervalSince1970.rounded(.down))
            index.entries[prefix] = RangeCacheIndex.Entry(fetchedAt: fetchedAt, size: UInt32(size))
            // Expired entries answer nothing (`PwnedPasswordsClient.cacheLifetime`); then the oldest beyond the
            // bounds, the prefix breaking ties so eviction is deterministic.
            var evicted = index.entries.filter {
                Double(fetchedAt - $0.value.fetchedAt) >= PwnedPasswordsClient.cacheLifetime
            }.map(\.key)
            for key in evicted { index.entries[key] = nil }
            let ordered = index.entries.sorted {
                ($0.value.fetchedAt, $0.key) < ($1.value.fetchedAt, $1.key)
            }
            var total = ordered.reduce(0) { $0 + Int($1.value.size) }
            var count = ordered.count
            for (key, value) in ordered where count > settings.cacheCapacity || total > settings.cacheMaximumBytes {
                guard key != prefix || count > 1 else { break }
                index.entries[key] = nil
                evicted.append(key)
                count -= 1
                total -= Int(value.size)
            }
            if !evicted.isEmpty {
                let names = evicted.compactMap { localName("range", Self.prefixBytes($0), since: epoch) }
                try await settings.localStore.delete(names)
            }
            try await storeCacheIndex(index, since: epoch)
        } catch {
            // Failing to store is not an error (`PwnedRangeCache.store`). A record written without its index line is
            // found by name all the same, and replaced or erased with the account.
        }
    }

    /// Removes the named prefixes, or every cached range for `nil`.
    func hygieneCacheRemove(_ prefixes: [UInt32]?) async {
        let epoch = lockEpoch
        guard let settings = hygieneRuntime?.settings else { return }
        var index = await loadCacheIndex(since: epoch)
        let targets = prefixes ?? Array(index.entries.keys)
        let names = targets.compactMap { localName("range", Self.prefixBytes($0), since: epoch) }
        guard names.count == targets.count else { return }
        try? await settings.localStore.delete(names)
        for prefix in targets { index.entries[prefix] = nil }
        try? await storeCacheIndex(index, since: epoch)
    }

    // MARK: - Tests

    /// Waits for the engine's pending unlock or lock to finish (tests only: nothing in the session waits on it).
    func hygieneSettled() async {
        await hygieneRuntime?.unlockTask?.value
        await hygieneRuntime?.lockTask?.value
    }

    var hygieneEngine: HygieneEngine? {
        hygieneRuntime?.engine
    }
}
