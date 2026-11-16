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
    /// (docs/02-architecture.md §7.2): whether to upload again is the person's decision.
    case storeReset
    /// The provider holds more than one version of one object (an iCloud Drive conflict, `NSFileVersion`): an
    /// immutable object was written twice. The transport chooses neither; the object is refused like a damaged one.
    case conflictingVersions(String)

    /// Whether the error stops a sync where it stands, as `unavailable` always has, rather than refusing one object:
    /// the transport as a whole cannot be used now. The engine then still merges what it downloaded earlier and
    /// publishes nothing (`SyncReport.transportUnavailable`, with the reason in `transportFailure`).
    public var stopsSync: Bool {
        switch self {
        case .unavailable, .rateLimited, .quotaExceeded, .notAuthenticated, .storeReset: return true
        case .objectExists, .forbidden, .objectTooLarge, .invalidName, .conflictingVersions: return false
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
public protocol SyncTransport: Sendable {
    /// Names of every object whose name begins with `prefix`, in no particular order.
    func list(prefix: String) async throws -> [String]
    /// An object's bytes, or `nil` if there is none (including one deleted since `list`). `maximumLength` is the most
    /// the caller will read; larger objects throw `objectTooLarge` without being read.
    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]?
    /// Creates an object. Fails with `objectExists` if one is already there: objects are written once.
    func create(_ name: String, contents: [UInt8]) async throws
    /// Deletes an object (garbage collection of the writer's own superseded objects). Succeeds if it is absent.
    func delete(_ name: String) async throws
}

/// A transport in memory. Shared by every simulated device that should see the same store; wrap it in a
/// fault-injecting view (`WatchwordTestSupport.SimulatedNetwork`) to model partitions and a hostile server.
public actor InMemorySyncTransport: SyncTransport {
    private var objects: [String: [UInt8]] = [:]

    public init() {}

    public func list(prefix: String) -> [String] {
        objects.keys.filter { $0.hasPrefix(prefix) }.sorted()
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
}
