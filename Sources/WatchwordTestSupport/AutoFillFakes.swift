import Foundation
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel

/// One clock for the vault session and the AutoFill model.
extension FakeClock: AutoFillClock {}

/// An in-memory `CredentialVault` that keeps the promises `VaultSession` makes (docs/02-architecture.md §9.1): it
/// owns versions, timestamps and history, checks every scope against the scope policy, and writes as a
/// compare-and-swap. Tests script the rest: lock it, lock it in the middle of a request, plant a record no honest
/// client would write, or make the next save fail.
public actor FakeCredentialVault: CredentialVault {
    public let vaultID: UUID
    private let clock: FakeClock
    private var stored: [UUID: Item] = [:]
    private var order: [UUID] = []
    private var locked = false
    private var backedUp: Bool
    private var readsUntilLock: Int?
    private var nextSaveError: CredentialVaultError?
    /// Successful saves, in order.
    public private(set) var saves: [Item] = []
    public private(set) var readCount = 0

    public init(vaultID: UUID = UUID(), clock: FakeClock = FakeClock(), backedUp: Bool = true, items: [Item] = []) {
        self.vaultID = vaultID
        self.clock = clock
        self.backedUp = backedUp
        for item in items {
            stored[item.id] = item
            order.append(item.id)
        }
    }

    // MARK: CredentialVault

    public func credentialItems() throws -> [Item] {
        try requireUnlocked()
        readCount += 1
        let items = order.compactMap { stored[$0] }
        if let remaining = readsUntilLock {
            if remaining <= 1 {
                locked = true
                readsUntilLock = nil
            } else {
                readsUntilLock = remaining - 1
            }
        }
        return items
    }

    public func credentialItem(id: UUID) throws -> Item {
        try requireUnlocked()
        guard let item = stored[id] else { throw CredentialVaultError.itemNotFound(id) }
        return item
    }

    public func defaultVaultID() throws -> UUID {
        try requireUnlocked()
        return vaultID
    }

    public func isBackedUp() throws -> Bool {
        try requireUnlocked()
        return backedUp
    }

    @discardableResult
    public func saveCredentialItem(_ item: Item, replacingVersion: UInt64?) async throws -> Item {
        try requireUnlocked()
        if let error = nextSaveError {
            nextSaveError = nil
            throw error
        }
        for scope in item.scopes {
            do {
                try ScopePolicy.validate(scope)
            } catch let error as ScopeValidationError {
                throw CredentialVaultError.scopeRejected(error)
            }
        }
        let now = await clock.now()
        try requireUnlocked()
        let existing = stored[item.id]
        guard existing?.version == replacingVersion else { throw CredentialVaultError.versionConflict(item.id) }
        var saved = item
        saved.modifiedAt = now
        if let existing {
            saved.version = existing.version + 1
            saved.createdAt = existing.createdAt
            saved.trashedAt = existing.trashedAt
            saved.keptAfterDeletion = existing.keptAfterDeletion
            saved.history = existing.history
            if existing.fields != item.fields {
                saved.history.insert(
                    ItemHistoryEntry(replacedAt: now, version: existing.version, fields: existing.fields), at: 0)
            }
        } else {
            saved.version = 1
            saved.createdAt = now
            saved.trashedAt = nil
            saved.keptAfterDeletion = false
            saved.history = []
            order.append(item.id)
        }
        stored[item.id] = saved
        saves.append(saved)
        return saved
    }

    // MARK: Scripting

    public func lock() {
        locked = true
    }

    public func unlock() {
        locked = false
    }

    /// Locks the vault as the `count`-th read from now returns: the lock that lands while a request is in flight.
    public func lockAfterReads(_ count: Int) {
        readsUntilLock = count
    }

    public func setBackedUp(_ value: Bool) {
        backedUp = value
    }

    public func failNextSave(with error: CredentialVaultError) {
        nextSaveError = error
    }

    /// Stores `item` exactly as given, with no policy check: what a hostile vault member or a careless import could
    /// have written. Bumps nothing.
    public func plant(_ item: Item) {
        if stored[item.id] == nil { order.append(item.id) }
        stored[item.id] = item
    }

    /// Reads past the lock, for assertions.
    public func item(_ id: UUID) -> Item? {
        stored[id]
    }

    public var allItems: [Item] {
        order.compactMap { stored[$0] }
    }

    private func requireUnlocked() throws {
        if locked { throw CredentialVaultError.locked }
    }
}

/// A credential identity store a test can read back (docs/02-architecture.md §9.1, "Published identities").
public actor FakeCredentialIdentityPublisher: CredentialIdentityPublisher {
    private var storeState: CredentialIdentityStoreState
    public private(set) var published: [CredentialIdentity] = []
    public private(set) var replaceAllCalls = 0
    public private(set) var incrementalCalls = 0
    private var failing = false

    public init(isEnabled: Bool = true, supportsIncrementalUpdates: Bool = true) {
        storeState = CredentialIdentityStoreState(
            isEnabled: isEnabled, supportsIncrementalUpdates: supportsIncrementalUpdates)
    }

    public func state() -> CredentialIdentityStoreState {
        storeState
    }

    public func replaceAll(with identities: [CredentialIdentity]) throws {
        if failing { throw CredentialVaultError.failed("identity store") }
        replaceAllCalls += 1
        published = identities
    }

    public func apply(_ difference: IdentityDifference) throws {
        if failing { throw CredentialVaultError.failed("identity store") }
        incrementalCalls += 1
        published.removeAll { difference.removals.contains($0) }
        published.append(contentsOf: difference.additions)
    }

    public func setFailing(_ value: Bool) {
        failing = value
    }

    public func setState(isEnabled: Bool, supportsIncrementalUpdates: Bool) {
        storeState = CredentialIdentityStoreState(
            isEnabled: isEnabled, supportsIncrementalUpdates: supportsIncrementalUpdates)
    }
}
