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
}

/// The sync transport port (docs/02-architecture.md §7, §15): a flat namespace of immutable, opaque objects.
///
/// Transports carry ciphertext only (§1 principle 2, PRD F7.3). Everything the core hands a transport is a
/// `SignedObject` around a sealed envelope; a transport never sees a key, a title or a field value, and nothing it
/// returns is trusted until the engine has checked the signature, the envelope context and the payload.
///
/// Implementations: `InMemorySyncTransport` (tests, simulations, previews), `FileSyncTransport` (a directory: iCloud
/// Drive or a Files-app folder once wrapped in file coordination), and `CloudKitTransport` (milestone 3's Mac half).
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
