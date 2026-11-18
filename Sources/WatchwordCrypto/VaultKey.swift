import Crypto
import Foundation
import SecureMemory
import WatchwordEnvelope

/// A vault's 256-bit record key (docs/02-architecture.md §4). Item records are sealed under it with
/// `RecordCipher.seal(_:context:key:)`; a rotation creates a new `VaultKey` with a new key ID.
public struct VaultKey: Sendable {
    public static let schemaVersion: UInt64 = 1
    /// The schema version in the wrap context of a key that reached this account through a vault's membership chain
    /// (`arrivedByGrant`). The context is the wrap's authenticated data, so the fact travels with the key and cannot
    /// be taken off it: not by someone with the device's files (A8), who would need Ksym to seal the key again, and
    /// not by a store that serves the account's vault directory (A1), which could otherwise withhold a separate
    /// marker and serve the key (review finding Z41).
    public static let grantedSchemaVersion: UInt64 = 2
    /// Generous upper bound on a wrapped vault key envelope, enforced before parsing (SEC9).
    static let maximumWrappedLength = 1024

    public let vaultID: UUID
    public let key: EncryptionKey
    /// Whether the key came to this account from another account's grant (`VaultKeyGrant.open`), which is to say
    /// the vault is governed by a membership chain. Kept through `wrap` and `unwrap`, on every device of the account:
    /// a device that holds such a key and no verified ledger for its vault must hold the vault closed
    /// (docs/02-architecture.md §8.10). `false` for a key the account generated, the genesis key of a vault it went
    /// on to share included; that vault's directory marker says so instead.
    public let arrivedByGrant: Bool

    public init(vaultID: UUID, key: EncryptionKey, arrivedByGrant: Bool = false) {
        self.vaultID = vaultID
        self.key = key
        self.arrivedByGrant = arrivedByGrant
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

    /// Whether `other` is the same key: the same vault, key ID and key bytes, compared in constant time. A key ID is
    /// public and, in a shared vault, chosen by whoever introduced the key, so the ID alone never shows that two
    /// keys are one.
    public func hasSameMaterial(as other: VaultKey) -> Bool {
        vaultID == other.vaultID && key.keyID == other.key.keyID
            && key.material.constantTimeEquals(other.key.material)
    }

    // MARK: - Wrapping under the owner's Ksym

    /// Context of the account's own wrap: the record is the vault key (by its key ID) in its vault, encrypted under
    /// Ksym. A key that arrived by grant is wrapped under `grantedSchemaVersion`.
    public static func wrapContext(vaultID: UUID, keyID: UUID, keysetKeyID: UUID, arrivedByGrant: Bool = false)
        -> EnvelopeContext
    {
        EnvelopeContext(
            recordID: keyID, vaultID: vaultID, schemaVersion: arrivedByGrant ? grantedSchemaVersion : schemaVersion,
            kind: .vaultKeyWrap, keyID: keysetKeyID
        )
    }

    /// Whether `envelope` is, by its header and context, a wrap of `keyID` for `vaultID` under the keyset key it
    /// names, of either class. Needs no key: what a locked device checks before it stores a wrap from the transport.
    public static func checkWrapForm(_ envelope: [UInt8], vaultID: UUID, keyID: UUID) throws {
        let header = try EnvelopeHeader.parse(envelope, expecting: .vaultKeyWrap).header
        var failure: (any Error)?
        for granted in [false, true] {
            do {
                _ = try Envelope.parse(
                    envelope,
                    expecting: wrapContext(
                        vaultID: vaultID, keyID: keyID, keysetKeyID: header.keyID, arrivedByGrant: granted),
                    maximumLength: maximumWrappedLength)
                return
            } catch {
                failure = failure ?? error
            }
        }
        throw failure ?? CryptoError.authenticationFailed
    }

    /// Wraps this key for the account that holds it (the personal vault, an owner's copy of a shared vault's key, a
    /// member's copy of a key a grant gave them).
    public func wrap<R: RandomNumberGenerator>(for keyset: Keyset, using generator: inout R) throws -> [UInt8] {
        try RecordCipher.seal(
            key.material,
            context: VaultKey.wrapContext(
                vaultID: vaultID, keyID: key.keyID, keysetKeyID: keyset.symmetricKey.keyID,
                arrivedByGrant: arrivedByGrant),
            key: keyset.symmetricKey,
            using: &generator
        )
    }

    public func wrap(for keyset: Keyset) throws -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return try wrap(for: keyset, using: &generator)
    }

    /// `vaultID` and `keyID` come from where the wrap was found, never from the wrap itself. Whether the key arrived
    /// by grant is what the wrap authenticates: the class whose context its header embeds, and then the AEAD over
    /// that header. A wrap of neither form fails as it always did, on the account's own context.
    public static func unwrap(_ envelope: [UInt8], vaultID: UUID, keyID: UUID, with keyset: Keyset) throws
        -> VaultKey
    {
        var formFailure: (any Error)?
        for granted in [false, true] {
            let context = wrapContext(
                vaultID: vaultID, keyID: keyID, keysetKeyID: keyset.symmetricKey.keyID, arrivedByGrant: granted)
            do {
                _ = try Envelope.parse(envelope, expecting: context, maximumLength: maximumWrappedLength)
            } catch {
                formFailure = formFailure ?? error
                continue
            }
            let material = try RecordCipher.open(
                envelope, context: context, key: keyset.symmetricKey, maximumLength: maximumWrappedLength)
            return VaultKey(
                vaultID: vaultID, key: try EncryptionKey(keyID: keyID, material: material), arrivedByGrant: granted)
        }
        throw formFailure ?? CryptoError.authenticationFailed
    }
}
