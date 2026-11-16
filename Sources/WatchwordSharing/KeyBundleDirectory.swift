import Foundation
import WatchwordCrypto

/// The published form of an account's public keys (docs/02-architecture.md §8.4).
///
/// ```
/// magic "WWKB"  formatVersion u8 = 1  accountID 16  X25519 key 32  Ed25519 key 32  self-signature 64
/// ```
///
/// Fixed length, so the parser's bound is equality. Parsing validates (`PublicKeyBundle.init`), and the account ID
/// must be the one the caller looked up: the directory is a store like any other (A1), and the identity of what it
/// returns comes from the question asked, never from the answer.
public enum KeyBundleCodec {
    static let magic: [UInt8] = Array("WWKB".utf8)
    static let formatVersion: UInt8 = 1
    public static let encodedLength = 4 + 1 + 16 + 32 + 32 + 64

    public static func encode(_ bundle: PublicKeyBundle) -> [UInt8] {
        magic + [formatVersion] + bundle.accountID.sharingBytes + bundle.agreementKey + bundle.signingKey
            + bundle.selfSignature
    }

    /// Parses the bundle published for `accountID`. A bundle for another account is `directoryMismatch`; one that is
    /// malformed, carries a weak key or a bad self-signature throws from `PublicKeyBundle.init` (`CryptoError`).
    public static func parse(_ bytes: [UInt8], expecting accountID: UUID) throws -> PublicKeyBundle {
        guard bytes.count <= encodedLength else { throw SharingFormatError.tooLarge(bytes.count) }
        var reader = SharingReader(bytes)
        try reader.header(magic: magic, version: formatVersion)
        let found = try reader.uuid()
        let agreementKey = try reader.read(32)
        let signingKey = try reader.read(32)
        let selfSignature = try reader.read(64)
        try reader.finish()
        guard found == accountID else { throw SharingError.directoryMismatch(asked: accountID, returned: found) }
        return try PublicKeyBundle(
            accountID: found, agreementKey: agreementKey, signingKey: signingKey, selfSignature: selfSignature)
    }
}

/// Where accounts publish their public keys, looked up by account ID (docs/02-architecture.md §8.4, §15). The port's
/// production adapter is the account record on the transport (CloudKit's public database, or a file in a shared
/// folder); it is untrusted, which is why what it returns is only ever a *candidate* until the person has compared
/// fingerprints (PRD F4.2, SEC3).
public protocol KeyBundleDirectory: Sendable {
    /// The bytes published for `accountID` (`KeyBundleCodec`), or `nil` if the account has published none.
    func publishedBundle(for accountID: UUID) async throws -> [UInt8]?
}

extension KeyBundleDirectory {
    /// Looks up and validates `accountID`'s published bundle. The result is unverified: a candidate for fingerprint
    /// comparison, nothing more.
    public func candidateBundle(for accountID: UUID) async throws -> PublicKeyBundle {
        guard let bytes = try await publishedBundle(for: accountID) else {
            throw SharingError.unknownAccount(accountID)
        }
        return try KeyBundleCodec.parse(bytes, expecting: accountID)
    }
}

/// A directory in memory, for tests, simulations and previews.
public actor InMemoryKeyBundleDirectory: KeyBundleDirectory {
    private var bundles: [UUID: [UInt8]] = [:]

    public init() {}

    public func publish(_ bundle: PublicKeyBundle) {
        bundles[bundle.accountID] = KeyBundleCodec.encode(bundle)
    }

    public func publishedBundle(for accountID: UUID) -> [UInt8]? {
        bundles[accountID]
    }

    /// Test seam: what whoever runs the directory (A1) can do. Stores arbitrary bytes under an account ID.
    public func tamper(_ accountID: UUID, contents: [UInt8]?) {
        bundles[accountID] = contents
    }
}
