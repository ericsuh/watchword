import Crypto
import Foundation
import SecureMemory

/// Keys for what one device keeps for itself and never syncs (docs/02-architecture.md §13.8, ADR 0005 and its
/// amendment): the hygiene engine's reuse key, and the key that seals this device's local records (the scan ledger
/// and the Pwned Passwords prefix cache).
///
/// ```
/// reuse key      = HKDF-SHA256(ikm: Ksym, salt: accountID, info: "WW-hygiene-reuse-v1"), 32 bytes
/// local key ‖ ID = HKDF-SHA256(ikm: Ksym ‖ device secret, salt: accountID ‖ deviceID,
///                              info: "WW-device-local-v1"), 48 bytes
/// record name    = HMAC-SHA256(local key, "WW-local-name-v1" ‖ 0x00 ‖ label ‖ 0x00 ‖ message)[0..<16]
/// ```
///
/// Each has a label of its own, so none of them is the raw keyset key or can stand in for another derivation from
/// it. The reuse key never leaves memory, so the keyset alone is enough for it. The local key is not: every device of
/// the account holds the same keyset, and a device ID is no secret (it is on every row and stream the device writes),
/// so a key derived from those two alone could be derived by any other device of the account, a revoked one included
/// (revocation does not take the keyset back, §7.8), which could then read this device's ledger and plant one of its
/// own (review finding K1, docs/06-adversarial-review.md). So the local key also takes the **device secret**: 32
/// random bytes this device made for itself and keeps in its Keychain (`KeychainItem.deviceLocalSecret`, device-only,
/// never synced, never on a transport). It takes both: the secret alone (someone reading this device's Keychain) opens
/// nothing either. A password change keeps the keyset and the secret, and so keeps the key: the ledger survives it.
/// A store restored onto other hardware arrives without the secret, and its records open as nothing.
///
/// Record names are keyed digests, so that a name on disk says nothing about what it names (a prefix cache entry's
/// name would otherwise be twenty bits of a password's hash).
///
/// `package`, not `public`: the session is the only caller, and these are escapes of key material from a keyset.
package enum DeviceLocalKeys {
    static let reuseInfo = Array("WW-hygiene-reuse-v1".utf8)
    static let localInfo = Array("WW-device-local-v1".utf8)
    static let nameDomain = Array("WW-local-name-v1".utf8)
    /// The length of the device secret.
    package static let deviceSecretLength = 32

    /// The hygiene engine's reuse key: HMAC tokens of passwords are computed under it, in memory only. The caller
    /// hands the buffer to the engine, which zeroises it on lock.
    package static func hygieneReuseKey(keyset: Keyset) -> SecureBytes {
        SecureBytes(
            copying: HKDF<SHA256>.deriveKey(
                inputKeyMaterial: keyset.symmetricKey.material.symmetricKey,
                salt: keyset.accountID.byteArray,
                info: reuseInfo,
                outputByteCount: 32
            ))
    }

    /// The key this device seals its local records under, with a key ID derived alongside it (the ID is in the clear
    /// in every envelope header, and is independent of the key's bytes).
    ///
    /// - Parameter deviceSecret: this device's secret from its Keychain, `deviceSecretLength` bytes; read here, not
    ///   kept.
    /// - Throws: `CryptoError.invalidKeyLength` for a secret of any other length.
    package static func deviceLocalKey(
        keyset: Keyset, deviceSecret: SecureBytes, deviceID: UUID
    ) throws -> EncryptionKey {
        guard deviceSecret.count == deviceSecretLength else {
            throw CryptoError.invalidKeyLength(deviceSecret.count)
        }
        let inputKeyMaterial = SecureBytes.concatenating([keyset.symmetricKey.material, deviceSecret])
        defer { inputKeyMaterial.zeroise() }
        let derived = SecureBytes(
            copying: HKDF<SHA256>.deriveKey(
                inputKeyMaterial: inputKeyMaterial.symmetricKey,
                salt: keyset.accountID.byteArray + deviceID.byteArray,
                info: localInfo,
                outputByteCount: EncryptionKey.byteCount + 16
            ))
        defer { derived.zeroise() }
        var idBytes = derived.extracting(EncryptionKey.byteCount..<(EncryptionKey.byteCount + 16)).unprotectedCopy()
        idBytes[6] = (idBytes[6] & 0x0F) | 0x80
        idBytes[8] = (idBytes[8] & 0x3F) | 0x80
        return try EncryptionKey(
            keyID: UUID(byteArray: idBytes), material: derived.extracting(0..<EncryptionKey.byteCount))
    }

    /// The name of a local record, keyed by the local key so that it reveals nothing about `message`.
    package static func recordName(_ label: String, _ message: [UInt8] = [], key: EncryptionKey) -> UUID {
        let input = nameDomain + [0x00] + Array(label.utf8) + [0x00] + message
        let code = HMAC<SHA256>.authenticationCode(for: input, using: key.material.symmetricKey)
        var bytes = Array(Array(code)[0..<16])
        bytes[6] = (bytes[6] & 0x0F) | 0x80
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return UUID(byteArray: bytes)
    }
}
