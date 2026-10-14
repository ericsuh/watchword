#if canImport(CryptoKit)
    import CryptoKit
    import Foundation
    import SecureMemory
    import WatchwordEnvelope

    /// A vault's 256-bit record key (docs/02-architecture.md §4). Item records are sealed under it with
    /// `RecordCipher.seal(_:context:key:)`; a rotation creates a new `VaultKey` with a new key ID.
    public struct VaultKey: Sendable {
        public static let schemaVersion: UInt64 = 1
        /// Generous upper bound on a wrapped vault key envelope, enforced before parsing (SEC9).
        static let maximumWrappedLength = 1024

        public let vaultID: UUID
        public let key: EncryptionKey

        public init(vaultID: UUID, key: EncryptionKey) {
            self.vaultID = vaultID
            self.key = key
        }

        public static func generate<R: RandomNumberGenerator>(vaultID: UUID, using generator: inout R) -> VaultKey {
            VaultKey(vaultID: vaultID, key: .generate(using: &generator))
        }

        public static func generate(vaultID: UUID) -> VaultKey {
            var generator = SystemRandomNumberGenerator()
            return generate(vaultID: vaultID, using: &generator)
        }

        public func zeroise() {
            key.zeroise()
        }

        // MARK: - Wrapping under the owner's Ksym

        /// Context of the owner's own wrap: the record is the vault key (by its key ID) in its vault, encrypted under Ksym.
        public static func wrapContext(vaultID: UUID, keyID: UUID, keysetKeyID: UUID) -> EnvelopeContext {
            EnvelopeContext(
                recordID: keyID, vaultID: vaultID, schemaVersion: schemaVersion, kind: .vaultKeyWrap, keyID: keysetKeyID
            )
        }

        /// Wraps this key for the account that owns it (the personal vault, and an owner's copy of a shared vault's key).
        public func wrap<R: RandomNumberGenerator>(for keyset: Keyset, using generator: inout R) throws -> [UInt8] {
            try RecordCipher.seal(
                key.material,
                context: VaultKey.wrapContext(
                    vaultID: vaultID, keyID: key.keyID, keysetKeyID: keyset.symmetricKey.keyID),
                key: keyset.symmetricKey,
                using: &generator
            )
        }

        public func wrap(for keyset: Keyset) throws -> [UInt8] {
            var generator = SystemRandomNumberGenerator()
            return try wrap(for: keyset, using: &generator)
        }

        /// `vaultID` and `keyID` come from where the wrap was found, never from the wrap itself.
        public static func unwrap(_ envelope: [UInt8], vaultID: UUID, keyID: UUID, with keyset: Keyset) throws
            -> VaultKey
        {
            let material = try RecordCipher.open(
                envelope,
                context: wrapContext(vaultID: vaultID, keyID: keyID, keysetKeyID: keyset.symmetricKey.keyID),
                key: keyset.symmetricKey,
                maximumLength: maximumWrappedLength
            )
            return VaultKey(vaultID: vaultID, key: try EncryptionKey(keyID: keyID, material: material))
        }
    }
#endif
