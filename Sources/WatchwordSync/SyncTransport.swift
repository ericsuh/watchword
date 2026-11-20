import Foundation

public enum SyncTransportError: Error, Equatable, Sendable {
    /// `create` found an object under the name already. Objects are immutable; the writer must not overwrite.
    case objectExists(String)
    /// The transport cannot be reached now (offline, account signed out, provider unavailable). Retry later.
    case unavailable
    /// The transport refused the write (for example a read-only share, milestone 4).
    case forbidden(String)
    /// The object is larger than the reader accepts; refused before it is read (SEC9).
    case objectTooLarge(String)
    /// A name or path the transport will not touch (a symlink, a name outside the layout).
    case invalidName(String)
    /// The service asked the client to slow down (CloudKit's `requestRateLimited`, `zoneBusy` or
    /// `serviceUnavailable`), for `retryAfter` seconds when it said how long. A wait the service states is a claim by
    /// the store (A1): `AutoSyncPolicy` holds it within its own backoff bounds.
    case rateLimited(retryAfter: TimeInterval?)
    /// The person's storage is full: nothing can be created until they free space. Reads still work, but the sync
    /// stops where the write failed, so nothing after it is published out of order.
    case quotaExceeded
    /// No account is signed in to the transport, or it is restricted or not ready yet (CloudKit's `notAuthenticated`,
    /// `accountTemporarilyUnavailable`). The person has to act; retrying alone will not help.
    case notAuthenticated
    /// The store's data was reset: the person deleted it (CloudKit's `userDeletedZone`), or the service discarded the
    /// key that protected it (`userDidResetEncryptedDataKey`). A transport never recreates such a store by itself
    /// (docs/02-architecture.md §7.2): whether to upload again is the person's decision, and only
    /// `SyncTransport.startStoreAgain`, called on that decision, ends it (§7.10).
    case storeReset
    /// More than one copy of one object verifies where the engine cannot merge them: a shared vault, whose write
    /// cuts bind one digest per position (docs/02-architecture.md §7.5, "Conflict copies"). The engine's reason for
    /// refusing the object; no transport throws it, since a transport chooses between copies no more than it trusts
    /// one (`SyncTransport.fetchCopies`).
    case conflictingVersions(String)
    /// One object cannot be read now (a CloudKit asset that is missing or not available, a coordinated read of one
    /// file that failed or timed out). Refused like a damaged object: its stream waits at it, everything else syncs.
    case objectUnreadable(String)
    /// A listing went past the transport's bounds (pages, raw results, or names): a store answering without end (A1)
    /// must not keep a sync running for ever. Stops the sync like `unavailable`.
    case listingTooLarge(String)

    /// Whether the error stops a sync where it stands, as `unavailable` always has, rather than refusing one object:
    /// the transport as a whole cannot be used now. The engine then still merges what it downloaded earlier and
    /// publishes nothing (`SyncReport.transportUnavailable`, with the reason in `transportFailure`).
    public var stopsSync: Bool {
        switch self {
        case .unavailable, .rateLimited, .quotaExceeded, .notAuthenticated, .storeReset, .listingTooLarge: return true
        case .objectExists, .forbidden, .objectTooLarge, .invalidName, .conflictingVersions, .objectUnreadable:
            return false
        }
    }

    /// The wait the service asked for, if it did.
    public var retryAfter: TimeInterval? {
        if case .rateLimited(let seconds) = self { return seconds }
        return nil
    }
}

/// The sync transport port (docs/02-architecture.md §7, §15): a flat namespace of immutable, opaque objects.
///
/// Transports carry ciphertext only (§1 principle 2, PRD F7.3). Everything the core hands a transport is a
/// `SignedObject` around a sealed envelope; a transport never sees a key, a title or a field value, and nothing it
/// returns is trusted until the engine has checked the signature, the envelope context and the payload.
///
/// Implementations: `InMemorySyncTransport` (tests, simulations, previews), `FileSyncTransport` (a directory), and in
/// `WatchwordPlatform` its coordinated wrapper for iCloud Drive (`CoordinatedFileSyncTransport`) and
/// `CloudKitTransport` (milestone 3's Mac half). Adapters stay thin: every check that decides what to trust is the
/// engine's, so each transport only maps names to storage and the provider's failures to `SyncTransportError`.
///
/// There is deliberately no "update": an object, once created, is never modified, only deleted by its author.
///
/// A provider can still end up holding more than one copy under one name (iCloud Drive keeps both when a name is
/// created twice before it has synced, as a conflict version or a renamed file; A1 can plant either). A transport
/// that can hold such copies says so (`listWithCopies`) and hands every copy over as bytes (`fetchCopies`); it never
/// chooses between them and never resolves the conflict. Which copies count is the engine's decision
/// (docs/02-architecture.md §7.5, "Conflict copies").
public protocol SyncTransport: Sendable {
    /// Names of every object whose name begins with `prefix`, in no particular order.
    func list(prefix: String) async throws -> [String]
    /// An object's bytes, or `nil` if there is none (including one deleted since `list`). `maximumLength` is the most
    /// the caller will read; larger objects throw `objectTooLarge` without being read. Where the provider holds
    /// several copies, this is the one it calls current.
    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]?
    /// Creates an object. Fails with `objectExists` if one is already there: objects are written once.
    func create(_ name: String, contents: [UInt8]) async throws
    /// Deletes an object (garbage collection of the writer's own superseded objects), with every copy the provider
    /// holds under its name. Succeeds if it is absent.
    func delete(_ name: String) async throws
    /// `list`, and for each name the provider holds anything besides the one current object under, how many copies
    /// it holds in all. Metadata only: nothing is read. The default is `list` with no such names.
    func listWithCopies(prefix: String) async throws -> SyncListing
    /// Every copy the provider holds under `name`, the current one first: at most `maximumCopies`, each at most
    /// `maximumLength` bytes. A copy over either bound is counted in `omitted`, and one that cannot be read *now* (its
    /// contents not downloaded yet, a read that failed) in `unread`, after asking the provider for it where it can;
    /// neither fails the call, so a planted copy cannot hide the others. The engine looks at a name with unread copies
    /// again at its next sync, and its author does not collect it meanwhile (review finding R11). No copies and none
    /// omitted or unread means there is no object. The default is the one `fetch` returns.
    func fetchCopies(_ name: String, maximumLength: Int, maximumCopies: Int) async throws -> SyncObjectCopies
    /// Starts a store again that was reset (`storeReset`): the one call that may recreate a store this device has
    /// seen and then found missing. Called only on the person's confirmed decision to upload again
    /// (`VaultSession.reuploadAfterStoreReset`, docs/02-architecture.md §7.10), never by a sync. It uploads nothing
    /// itself. The default does nothing: most transports have no store to recreate.
    func startStoreAgain() async throws
}

/// What a transport lists under a prefix (`SyncTransport.listWithCopies`).
public struct SyncListing: Sendable, Hashable {
    /// As `SyncTransport.list`: in no particular order, and a name may repeat.
    public var names: [String]
    /// The names with anything besides the one current object under them, and the number of copies under each in
    /// all. A claim by the store (A1), used only to decide what to look at.
    public var copied: [String: Int]

    public init(names: [String] = [], copied: [String: Int] = [:]) {
        self.names = names
        self.copied = copied
    }
}

/// The copies a transport holds under one name (`SyncTransport.fetchCopies`). Bytes and nothing else: the transport
/// does not say which is genuine, and the engine does not ask.
public struct SyncObjectCopies: Sendable, Hashable {
    public var copies: [[UInt8]]
    /// Copies not returned for good: past the caller's count, over its size limit, or not a file at all.
    public var omitted: Int
    /// Copies not returned because they cannot be read now and may be later: not downloaded yet, or a read that
    /// failed. Never taken as examined (review finding R11).
    public var unread: Int

    public init(copies: [[UInt8]] = [], omitted: Int = 0, unread: Int = 0) {
        self.copies = copies
        self.omitted = omitted
        self.unread = unread
    }
}

extension SyncTransport {
    public func startStoreAgain() async throws {}

    public func listWithCopies(prefix: String) async throws -> SyncListing {
        SyncListing(names: try await list(prefix: prefix))
    }

    public func fetchCopies(_ name: String, maximumLength: Int, maximumCopies: Int) async throws -> SyncObjectCopies {
        do {
            guard let bytes = try await fetch(name, maximumLength: maximumLength) else { return SyncObjectCopies() }
            return maximumCopies > 0 ? SyncObjectCopies(copies: [bytes]) : SyncObjectCopies(omitted: 1)
        } catch SyncTransportError.objectTooLarge {
            return SyncObjectCopies(omitted: 1)
        }
    }
}

/// A transport in memory. Shared by every simulated device that should see the same store; wrap it in a
/// fault-injecting view (`WatchwordTestSupport.SimulatedNetwork`) to model partitions and a hostile server.
public actor InMemorySyncTransport: SyncTransport {
    private var objects: [String: [UInt8]] = [:]
    /// Copies beside (or without) the current object of a name, as iCloud Drive keeps a conflict version or a
    /// renamed second create.
    private var otherCopies: [String: [[UInt8]]] = [:]
    /// Copies the store lists under a name and cannot hand over yet, as iCloud Drive lists a conflict version whose
    /// contents are not downloaded: counted, and returned as `unread`, until `makeCopiesReadable`.
    private var unreadableCopies: [String: [[UInt8]]] = [:]

    public init() {}

    public func list(prefix: String) -> [String] {
        Set(objects.keys).union(otherCopies.keys).union(unreadableCopies.keys).filter { $0.hasPrefix(prefix) }.sorted()
    }

    public func listWithCopies(prefix: String) -> SyncListing {
        var listing = SyncListing(names: list(prefix: prefix))
        for name in Set(otherCopies.keys).union(unreadableCopies.keys) where name.hasPrefix(prefix) {
            listing.copied[name] =
                (otherCopies[name]?.count ?? 0) + (unreadableCopies[name]?.count ?? 0) + (objects[name] == nil ? 0 : 1)
        }
        return listing
    }

    public func fetchCopies(_ name: String, maximumLength: Int, maximumCopies: Int) -> SyncObjectCopies {
        var found = SyncObjectCopies()
        for bytes in (objects[name].map { [$0] } ?? []) + (otherCopies[name] ?? []) {
            if found.copies.count < maximumCopies, bytes.count <= maximumLength {
                found.copies.append(bytes)
            } else {
                found.omitted += 1
            }
        }
        found.unread = unreadableCopies[name]?.count ?? 0
        return found
    }

    public func fetch(_ name: String, maximumLength: Int) throws -> [UInt8]? {
        guard let bytes = objects[name] else { return nil }
        guard bytes.count <= maximumLength else { throw SyncTransportError.objectTooLarge(name) }
        return bytes
    }

    public func create(_ name: String, contents: [UInt8]) throws {
        guard objects[name] == nil else { throw SyncTransportError.objectExists(name) }
        objects[name] = contents
    }

    public func delete(_ name: String) {
        objects[name] = nil
        otherCopies[name] = nil
        unreadableCopies[name] = nil
    }

    // MARK: - Test seams: what anyone with write access to the store (A1) can do.

    /// Every object, for inspecting what reached the store.
    public var allObjects: [String: [UInt8]] {
        objects
    }

    /// Writes or overwrites an object without any checks.
    public func tamper(_ name: String, contents: [UInt8]?) {
        objects[name] = contents
    }

    /// Adds a copy beside whatever is under `name`: a conflict version, or a second create the provider renamed.
    public func plantCopy(_ name: String, contents: [UInt8]) {
        otherCopies[name, default: []].append(contents)
    }

    /// The copies under `name` that are not its current object.
    public func plantedCopies(_ name: String) -> [[UInt8]] {
        otherCopies[name] ?? []
    }

    /// Adds a copy beside whatever is under `name` that is listed and cannot be read yet: a conflict version whose
    /// contents iCloud has not downloaded.
    public func plantUnreadableCopy(_ name: String, contents: [UInt8]) {
        unreadableCopies[name, default: []].append(contents)
    }

    /// Takes back the last copy `plantUnreadableCopy` left under `name`: A1 changing the count it lists.
    public func withdrawUnreadableCopy(_ name: String) {
        guard var copies = unreadableCopies[name], !copies.isEmpty else { return }
        copies.removeLast()
        unreadableCopies[name] = copies.isEmpty ? nil : copies
    }

    /// The copies `plantUnreadableCopy` left under `name` can be read from now on.
    public func makeCopiesReadable(_ name: String) {
        otherCopies[name, default: []] += unreadableCopies[name] ?? []
        unreadableCopies[name] = nil
    }

    /// Removes every object and copy: a store that was reset, or a folder that was emptied.
    public func removeEverything() {
        objects = [:]
        otherCopies = [:]
        unreadableCopies = [:]
    }
}
