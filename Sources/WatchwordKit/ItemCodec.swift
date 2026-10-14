import Foundation
import WatchwordModel

public enum ItemCodecError: Error, Equatable, Sendable {
    case payloadTooLarge(Int)
    case malformedPayload
}

/// The plaintext payload of an `.item` envelope (docs/02-architecture.md §5).
///
/// JSON rather than the canonical CBOR the envelope's authenticated data uses, deliberately: the payload is never
/// signed or compared, only decrypted and decoded, so it needs no canonical form; and decoding it needs a parser for
/// strings, nested arrays and maps, which `CBORValue` intentionally lacks (attacker-supplied CBOR never reaches a
/// parser of ours). Foundation's `JSONDecoder` is that parser.
///
/// The payload only reaches the decoder after AEAD authentication, but authentication proves only that someone holding
/// the vault key wrote it — from milestone 4 that includes every member of a shared vault (A4), so the decoder still
/// treats it as hostile input: a size cap before decoding, and identity checks against the storage location after.
public enum ItemCodec {
    /// Bound into each record's authenticated data as `schemaVersion`; a record relabelled with another fails closed.
    public static let schemaVersion: UInt64 = 1
    /// Items are kilobytes; a passkey with a large blob and long notes stays well under this (SEC9).
    public static let maximumPayloadLength = 1 << 20

    public static func encode(_ item: Item) throws -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .secondsSince1970
        let bytes = Array(try encoder.encode(item))
        guard bytes.count <= maximumPayloadLength else { throw ItemCodecError.payloadTooLarge(bytes.count) }
        return bytes
    }

    public static func decode(_ bytes: some Collection<UInt8>) throws -> Item {
        guard bytes.count <= maximumPayloadLength else { throw ItemCodecError.payloadTooLarge(bytes.count) }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        do {
            return try decoder.decode(Item.self, from: Data(bytes))
        } catch {
            throw ItemCodecError.malformedPayload
        }
    }
}
