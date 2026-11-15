import Crypto
import Foundation
import SecureMemory

public enum ReuseKeyError: Error, Equatable, Sendable {
    /// Fewer than 32 bytes: not a key.
    case tooShort
    /// Already zeroised: a key from before the last lock.
    case zeroised
}

/// The key the reuse index is computed under (docs/02-architecture.md §13): 32 bytes or more that the session derives
/// from the keyset's symmetric key for this purpose alone, so it exists only while the vault is unlocked.
public struct ReuseKey: Sendable {
    public static let minimumLength = 32

    let bytes: SecureBytes

    /// Takes over `bytes`: whoever holds the key (in practice `HygieneEngine`) zeroises it on lock.
    public init(_ bytes: SecureBytes) throws {
        guard bytes.count >= Self.minimumLength else { throw ReuseKeyError.tooShort }
        guard !bytes.isZeroised else { throw ReuseKeyError.zeroised }
        self.bytes = bytes
    }

    /// `HMAC-SHA-256(key, UTF-8 of password)`: equal for equal passwords, and without the key says nothing about
    /// either.
    func token(forUTF8Of password: String) -> ReuseToken {
        let message = SecureBytes(copying: password.utf8)
        defer { message.zeroise() }
        let code = HMAC<SHA256>.authenticationCode(for: message, using: bytes.symmetricKey)
        return ReuseToken(bytes: Array(code))
    }

    func zeroise() {
        bytes.zeroise()
    }
}

/// A keyed fingerprint of one password, for finding the same password on two items.
///
/// In memory only, by construction: it is not `Codable`, it prints as `ReuseToken(redacted)`, and nothing in this
/// module writes one anywhere. With the key gone it is noise; with the key it would confirm a guess, which is why
/// both go at lock.
public struct ReuseToken: Hashable, Sendable {
    let bytes: [UInt8]
}

extension ReuseToken: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "ReuseToken(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

/// Which items use which password (PRD F9.3): a map from `ReuseToken` to item IDs, rebuilt at each unlock and never
/// persisted (docs/adr/0005-hibp-while-locked.md).
public struct ReuseIndex: Sendable {
    private var itemsByToken: [ReuseToken: Set<UUID>] = [:]
    private var tokensByItem: [UUID: Set<ReuseToken>] = [:]

    public init() {}

    /// Replaces what the index knows about `item`. A password used twice inside one item is not reuse.
    public mutating func set(_ tokens: Set<ReuseToken>, for item: UUID) {
        remove(item)
        guard !tokens.isEmpty else { return }
        tokensByItem[item] = tokens
        for token in tokens {
            itemsByToken[token, default: []].insert(item)
        }
    }

    public mutating func remove(_ item: UUID) {
        for token in tokensByItem.removeValue(forKey: item) ?? [] {
            itemsByToken[token]?.remove(item)
            if itemsByToken[token]?.isEmpty == true { itemsByToken[token] = nil }
        }
    }

    public mutating func removeAll() {
        itemsByToken.removeAll()
        tokensByItem.removeAll()
    }

    /// The other items that use the password behind `token`, in a stable order.
    public func items(sharing token: ReuseToken, besides item: UUID? = nil) -> [UUID] {
        (itemsByToken[token] ?? []).filter { $0 != item }.sorted { $0.uuidString < $1.uuidString }
    }

    /// Every set of two or more items that share a password, each sorted, and the sets sorted by their first member.
    public var reusedGroups: [[UUID]] {
        itemsByToken.values.filter { $0.count > 1 }
            .map { $0.sorted { $0.uuidString < $1.uuidString } }
            .sorted { ($0.first?.uuidString ?? "") < ($1.first?.uuidString ?? "") }
    }

    public var isEmpty: Bool {
        tokensByItem.isEmpty
    }
}

extension ReuseIndex: CustomStringConvertible, CustomReflectable {
    public var description: String { "ReuseIndex(\(tokensByItem.count) items, redacted)" }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}
