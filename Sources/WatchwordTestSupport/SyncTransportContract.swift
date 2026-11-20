import Foundation
import WatchwordSync

/// The `SyncTransport` contract (docs/02-architecture.md §7), as checks any test target can run against any transport:
/// immutable objects in a flat namespace, listed by prefix, fetched within a limit, created once, deleted by name.
/// `WatchwordSyncTests` runs it against the portable transports; `WatchwordPlatformTests` against the coordinated
/// iCloud Drive transport and `CloudKitTransport` over its fake database. Each check returns what it found wrong, so a
/// suite asserts the list is empty and the message names the transport.
public enum SyncTransportContract {
    public static let vault = UUID(uuidString: "0A0A0A0A-0000-4000-8000-00000000000A")!
    public static let otherVault = UUID(uuidString: "0B0B0B0B-0000-4000-8000-00000000000B")!
    public static let deviceA = UUID(uuidString: "D0000000-0000-4000-8000-0000000000A0")!
    public static let deviceB = UUID(uuidString: "D0000000-0000-4000-8000-0000000000B0")!

    public static var name: String { SyncObjectLocation.segment(vaultID: vault, author: deviceA, sequence: 1).name }
    public static var prefix: String { SyncObjectLocation.vaultPrefix(vault) }

    /// Every check, by name, each on a fresh transport from `make`.
    public static func violations(_ make: () async throws -> any SyncTransport) async throws -> [String] {
        var found: [String] = []
        found += try await roundTrip(try await make())
        found += try await immutable(try await make())
        found += try await sizeLimit(try await make())
        found += try await deletion(try await make())
        found += try await singleCopies(try await make())
        return found
    }

    /// Every transport, whether or not it can hold several copies of a name: an object with one copy is listed with
    /// no copies beside it and fetched as that one copy, and bounds are counted, never thrown.
    public static func singleCopies(_ transport: any SyncTransport) async throws -> [String] {
        var found: [String] = []
        let missing = try await transport.fetchCopies(name, maximumLength: 100, maximumCopies: 4)
        if missing != SyncObjectCopies() { found.append("a missing object has copies: \(missing)") }
        try await transport.create(name, contents: [1, 2, 3])
        let listing = try await transport.listWithCopies(prefix: prefix)
        if Set(listing.names) != [name] { found.append("listWithCopies named \(listing.names)") }
        if !listing.copied.isEmpty { found.append("one object listed with copies: \(listing.copied)") }
        if try await transport.fetchCopies(name, maximumLength: 100, maximumCopies: 4)
            != SyncObjectCopies(copies: [[1, 2, 3]])
        {
            found.append("fetchCopies of one object did not give its bytes once")
        }
        if try await transport.fetchCopies(name, maximumLength: 2, maximumCopies: 4) != SyncObjectCopies(omitted: 1) {
            found.append("a copy over the limit was not counted as omitted")
        }
        return found
    }

    /// A transport that can hold several copies of a name, given a way to put one beside an object (`plant`, which
    /// stands for the provider or for A1): every copy is listed in the count and handed over, the current one first;
    /// the bounds hold per copy; a plain `fetch` still reads the current object; and `delete` removes them all.
    public static func heldCopies(
        _ transport: any SyncTransport, plant: (String, [UInt8]) async throws -> Void
    ) async throws -> [String] {
        var found: [String] = []
        try await transport.create(name, contents: [1])
        try await plant(name, [2, 2])
        try await plant(name, Array(repeating: 3, count: 101))
        let other = SyncObjectLocation.segment(vaultID: vault, author: deviceA, sequence: 2).name
        try await transport.create(other, contents: [9])
        let listing = try await transport.listWithCopies(prefix: prefix)
        if Set(listing.names) != [name, other] { found.append("names with copies listed as \(listing.names)") }
        if listing.copied != [name: 3] { found.append("copies counted as \(listing.copied)") }
        if Set(try await transport.list(prefix: prefix)) != [name, other] { found.append("list changed by copies") }
        let copies = try await transport.fetchCopies(name, maximumLength: 100, maximumCopies: 8)
        if copies != SyncObjectCopies(copies: [[1], [2, 2]], omitted: 1) {
            found.append("copies fetched as \(copies)")
        }
        let bounded = try await transport.fetchCopies(name, maximumLength: 100, maximumCopies: 1)
        if bounded != SyncObjectCopies(copies: [[1]], omitted: 2) { found.append("count bound gave \(bounded)") }
        if try await transport.fetch(name, maximumLength: 100) != [1] { found.append("fetch is not the current copy") }
        do {
            try await transport.create(name, contents: [7])
            found.append("an object with copies was overwritten")
        } catch SyncTransportError.objectExists {
        } catch {
            found.append("a create over copies threw \(error)")
        }
        try await transport.delete(name)
        let after = try await transport.listWithCopies(prefix: prefix)
        if Set(after.names) != [other] || !after.copied.isEmpty { found.append("copies outlived their object") }
        if try await transport.fetchCopies(name, maximumLength: 100, maximumCopies: 8) != SyncObjectCopies() {
            found.append("copies fetched after deletion")
        }
        return found
    }

    public static func roundTrip(_ transport: any SyncTransport) async throws -> [String] {
        var found: [String] = []
        if try await !transport.list(prefix: prefix).isEmpty { found.append("a new transport lists objects") }
        if try await transport.fetch(name, maximumLength: 100) != nil { found.append("a missing object fetched") }
        try await transport.create(name, contents: [1, 2, 3])
        let other = SyncObjectLocation.snapshot(vaultID: otherVault, author: deviceB, lamport: 9)
        try await transport.create(other.name, contents: [4])
        let account = AccountObjectLocation.vaultDeletion(accountID: vault, vaultID: otherVault, author: deviceB)
        try await transport.create(account.name, contents: [5])
        let listed = try await transport.list(prefix: prefix)
        if listed != [name] { found.append("listing by prefix gave \(listed)") }
        if try await transport.list(prefix: "vault/").count != 2 { found.append("listing vault/ did not give both") }
        if try await transport.list(prefix: "account/") != [account.name] { found.append("account objects not listed") }
        if try await transport.fetch(name, maximumLength: 100) != [1, 2, 3] {
            found.append("bytes did not round-trip")
        }
        if try await transport.fetch(account.name, maximumLength: 100) != [5] { found.append("account object lost") }
        return found
    }

    public static func immutable(_ transport: any SyncTransport) async throws -> [String] {
        var found: [String] = []
        try await transport.create(name, contents: [1])
        do {
            try await transport.create(name, contents: [2])
            found.append("an object was overwritten")
        } catch SyncTransportError.objectExists(let existing) {
            if existing != name { found.append("objectExists named \(existing)") }
        } catch {
            found.append("a second create threw \(error), not objectExists")
        }
        if try await transport.fetch(name, maximumLength: 100) != [1] { found.append("the first object changed") }
        return found
    }

    public static func sizeLimit(_ transport: any SyncTransport) async throws -> [String] {
        try await transport.create(name, contents: Array(repeating: 7, count: 101))
        do {
            _ = try await transport.fetch(name, maximumLength: 100)
            return ["an object over the limit was returned"]
        } catch SyncTransportError.objectTooLarge(let refused) where refused == name {
            return []
        } catch {
            return ["an object over the limit threw \(error), not objectTooLarge"]
        }
    }

    public static func deletion(_ transport: any SyncTransport) async throws -> [String] {
        try await transport.create(name, contents: [1])
        try await transport.delete(name)
        try await transport.delete(name)
        var found: [String] = []
        if try await !transport.list(prefix: prefix).isEmpty { found.append("a deleted object is still listed") }
        if try await transport.fetch(name, maximumLength: 100) != nil { found.append("a deleted object fetched") }
        return found
    }
}
