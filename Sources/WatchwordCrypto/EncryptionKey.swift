import Foundation
import SecureMemory

/// A 256-bit symmetric key and the ID that envelopes name it by (docs/02-architecture.md §4). Used for the Account
/// Unlock Key, the keyset's symmetric key (Ksym) and vault keys.
///
/// The bytes live in `SecureBytes`, so `zeroise()` on lock destroys them immediately rather than whenever CryptoKit's
/// own copy is released; CryptoKit keys are created per operation from these bytes.
///
/// Each key carries the `NonceLedger` of every nonce sealed under it. Copies of the value share the ledger, so the
/// nonce-reuse tripwire covers every seal under this key, whoever performs it (review finding R3). A key rebuilt from
/// storage (an unwrap) starts a fresh ledger, so a session should unwrap each key once and keep that value.
public struct EncryptionKey: Sendable {
    public static let byteCount = 32

    public let keyID: UUID
    package let material: SecureBytes
    package let nonceLedger = NonceLedger()

    public init(keyID: UUID, material: SecureBytes) throws {
        guard material.count == EncryptionKey.byteCount else { throw CryptoError.invalidKeyLength(material.count) }
        self.keyID = keyID
        self.material = material
    }

    /// Nonces sealed under this key so far, across all copies of the value.
    public var sealCount: Int {
        nonceLedger.count
    }

    public static func generate<R: RandomNumberGenerator>(using generator: inout R) -> EncryptionKey {
        let keyID = UUID.randomVersion4(using: &generator)
        // Cannot throw: the length is right by construction.
        return try! EncryptionKey(
            keyID: keyID, material: SecureBytes(randomCount: EncryptionKey.byteCount, using: &generator))
    }

    public func zeroise() {
        material.zeroise()
    }

    public var isZeroised: Bool {
        material.isZeroised
    }
}
