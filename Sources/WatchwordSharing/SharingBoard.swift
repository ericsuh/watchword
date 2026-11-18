import Foundation

/// Where a vault sharing code session's messages meet (ADR 0010, docs/02-architecture.md §8.4): a public, untrusted
/// store of small objects, fetched by exact name and created once, never overwritten and never listed. It is adversary
/// A1's ground like the key directory beside it: anyone may read, drop, delay, replace or invent an object, and answer
/// two devices differently. Nothing the session believes rests on the board; what it does rest on is the people's
/// channel and the transcript both devices hash.
///
/// The port has no listing on purpose: a session is found by its number alone, so finding sessions means guessing
/// among 10^8 names (ADR 0010, "Sniping and denial of service"). No production adapter exists yet, for the board or the
/// directory (docs/03-implementation-plan.md, milestone 4); `InMemorySharingBoard` serves tests and the UI-test
/// household.
public protocol SharingBoard: Sendable {
    /// Creates `name` with `contents`. Throws `SharingBoardError.taken` if anything is under the name already: an
    /// object is never overwritten.
    func create(_ name: String, contents: [UInt8]) async throws
    /// The object under exactly `name`, or `nil` if there is none. One over `maximumLength` bytes is
    /// `SharingBoardError.tooLarge`, refused before it is read whole.
    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]?
}

/// Why the board refused.
public enum SharingBoardError: Error, Hashable, Sendable {
    /// Something is under the name already.
    case taken
    case tooLarge
    /// The board could not be reached; the session may try again.
    case unavailable
}

/// The names of one session's objects on the board: `vault-sharing/<number>/<part>`, the number exactly eight ASCII
/// digits. The board keeps no other names for a session, so a session's whole footprint is these four.
public enum SharingBoardName {
    static let prefix = "vault-sharing/"

    public static func commit(_ number: SharingSessionNumber) -> String { name(number, "commit") }
    public static func reply(_ number: SharingSessionNumber) -> String { name(number, "reply") }
    public static func reveal(_ number: SharingSessionNumber) -> String { name(number, "reveal") }
    public static func invitation(_ number: SharingSessionNumber) -> String { name(number, "invitation") }

    static func name(_ number: SharingSessionNumber, _ part: String) -> String {
        prefix + number.digits + "/" + part
    }
}

/// A board in memory, for tests, simulations and the UI-test household. The seams below are what whoever runs a real
/// board (A1) can do.
public actor InMemorySharingBoard: SharingBoard {
    private var objects: [String: [UInt8]] = [:]
    private var refusing = false

    public init() {}

    public func create(_ name: String, contents: [UInt8]) throws {
        guard !refusing else { throw SharingBoardError.unavailable }
        guard objects[name] == nil else { throw SharingBoardError.taken }
        objects[name] = contents
    }

    public func fetch(_ name: String, maximumLength: Int) throws -> [UInt8]? {
        guard !refusing else { throw SharingBoardError.unavailable }
        guard let bytes = objects[name] else { return nil }
        guard bytes.count <= maximumLength else { throw SharingBoardError.tooLarge }
        return bytes
    }

    // MARK: - Test seams: what the board's operator (A1) can do.

    /// Every object, for inspecting what reached the board.
    public var allObjects: [String: [UInt8]] { objects }

    /// Writes, overwrites or (with `nil`) removes an object without any checks.
    public func tamper(_ name: String, contents: [UInt8]?) {
        objects[name] = contents
    }

    /// From now on every call fails as unreachable, or works again.
    public func refuseService(_ refuse: Bool) {
        refusing = refuse
    }
}
