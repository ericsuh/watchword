import Foundation

/// Where an account-level object lives on a transport (docs/02-architecture.md §7.7): the objects a second device of
/// the account needs before it holds any vault key, beside the per-vault logs of `SyncObjectLocation`.
///
/// - `account/<accountID>/header/<generation>-<deviceID>` — the account header a device published for a credential
///   generation: KDF parameters, salt and the wrapped keyset.
/// - `account/<accountID>/registry/<entryID>` — one entry of the device registry, named by the SHA-256 of its bytes
///   (64 lower-case hexadecimal digits), so an entry can be neither altered nor moved.
/// - `account/<accountID>/vault/<vaultID>/key/<keyID>/<deviceID>` — a vault key wrapped under the keyset's symmetric
///   key, vouched for by the device named last.
/// - `account/<accountID>/vault/<vaultID>/deleted/<deviceID>` — the vault was deleted, as stated by that device.
/// - `account/<accountID>/vault/<vaultID>/shared/<deviceID>` — the vault is governed by a membership chain (shared),
///   as stated by that device, with the chain's owner (docs/02-architecture.md §8.10).
///
/// As with sync objects, names come from a store that may be hostile (A1) and parsing is exact: numbers are 20
/// zero-padded digits, UUIDs are in canonical upper case, and anything that does not re-encode to the same string is
/// not an account object. Every object is created once and never overwritten. Names reveal the account ID, vault,
/// key and device IDs and the credential generation to the transport; nothing else.
public enum AccountObjectLocation: Hashable, Sendable {
    case header(accountID: UUID, generation: UInt64, author: UUID)
    case registryEntry(accountID: UUID, id: String)
    case vaultKey(accountID: UUID, vaultID: UUID, keyID: UUID, author: UUID)
    case vaultDeletion(accountID: UUID, vaultID: UUID, author: UUID)
    case vaultShared(accountID: UUID, vaultID: UUID, author: UUID)

    public static func accountPrefix(_ accountID: UUID) -> String {
        "account/\(accountID.uuidString)/"
    }

    public static func headerPrefix(_ accountID: UUID) -> String {
        accountPrefix(accountID) + "header/"
    }

    public static func registryPrefix(_ accountID: UUID) -> String {
        accountPrefix(accountID) + "registry/"
    }

    public static func vaultsPrefix(_ accountID: UUID) -> String {
        accountPrefix(accountID) + "vault/"
    }

    public var accountID: UUID {
        switch self {
        case .header(let id, _, _), .registryEntry(let id, _), .vaultKey(let id, _, _, _),
            .vaultDeletion(let id, _, _), .vaultShared(let id, _, _):
            return id
        }
    }

    public var name: String {
        switch self {
        case .header(let accountID, let generation, let author):
            return Self.headerPrefix(accountID) + "\(SyncObjectLocation.padded(generation))-\(author.uuidString)"
        case .registryEntry(let accountID, let id):
            return Self.registryPrefix(accountID) + id
        case .vaultKey(let accountID, let vaultID, let keyID, let author):
            return Self.vaultsPrefix(accountID) + "\(vaultID.uuidString)/key/\(keyID.uuidString)/\(author.uuidString)"
        case .vaultDeletion(let accountID, let vaultID, let author):
            return Self.vaultsPrefix(accountID) + "\(vaultID.uuidString)/deleted/\(author.uuidString)"
        case .vaultShared(let accountID, let vaultID, let author):
            return Self.vaultsPrefix(accountID) + "\(vaultID.uuidString)/shared/\(author.uuidString)"
        }
    }

    /// Parses a name exactly; returns `nil` for anything that is not the canonical name of an account object.
    public init?(name: String) {
        let parts = name.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 4, parts[0] == "account", let accountID = SyncObjectLocation.uuid(parts[1]) else {
            return nil
        }
        switch parts[2] {
        case "header":
            let pieces = parts[3].split(separator: "-", maxSplits: 1).map(String.init)
            guard parts.count == 4, pieces.count == 2, let generation = SyncObjectLocation.number(pieces[0]),
                let author = SyncObjectLocation.uuid(pieces[1])
            else { return nil }
            self = .header(accountID: accountID, generation: generation, author: author)
        case "registry":
            guard parts.count == 4, Self.isEntryID(parts[3]) else { return nil }
            self = .registryEntry(accountID: accountID, id: parts[3])
        case "vault":
            guard parts.count >= 6, let vaultID = SyncObjectLocation.uuid(parts[3]) else { return nil }
            switch parts[4] {
            case "key":
                guard parts.count == 7, let keyID = SyncObjectLocation.uuid(parts[5]),
                    let author = SyncObjectLocation.uuid(parts[6])
                else { return nil }
                self = .vaultKey(accountID: accountID, vaultID: vaultID, keyID: keyID, author: author)
            case "deleted":
                guard parts.count == 6, let author = SyncObjectLocation.uuid(parts[5]) else { return nil }
                self = .vaultDeletion(accountID: accountID, vaultID: vaultID, author: author)
            case "shared":
                guard parts.count == 6, let author = SyncObjectLocation.uuid(parts[5]) else { return nil }
                self = .vaultShared(accountID: accountID, vaultID: vaultID, author: author)
            default:
                return nil
            }
        default:
            return nil
        }
        guard self.name == name else { return nil }
    }

    /// 64 lower-case hexadecimal digits: the SHA-256 a registry entry is named by.
    static func isEntryID(_ text: String) -> Bool {
        text.utf8.count == 64 && text.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }
}
