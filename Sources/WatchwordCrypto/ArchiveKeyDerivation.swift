import Crypto
import Foundation
import SecureMemory
import WatchwordEnvelope

/// The key that wraps an encrypted Watchword archive's own key: a passphrase the person chooses for the archive,
/// combined with the account's Secret Key, as two-secret derivation combines the account password with it
/// (docs/02-architecture.md §14.1, ADR 0008, PRD F8.4).
///
/// ```
/// salt' = HKDF-SHA256(ikm: salt, salt: archiveID, info: "WW-archive-salt-v1")
/// Kp    = PBKDF2-HMAC-SHA256(NFKD(passphrase), salt', iterations)
/// Ks    = HKDF-SHA256(ikm: SK, salt: accountID, info: "WW-archive-2SKD-v1")
/// AWK   = HKDF-SHA256(ikm: Kp ‖ Ks, salt: archiveID ‖ accountID, info: "WW-archive-key-v1")
/// ```
///
/// Why the Secret Key and not the passphrase alone: an archive is a file, and the likeliest place for a backup file
/// is the cloud drive the vault already syncs through, which is adversary A1's. The account's ciphertext there is out
/// of reach of offline guessing because of the Secret Key; a passphrase-only archive beside it would be the one
/// object A1 could guess at, protected by the person's choice of passphrase and nothing else. With the Secret Key
/// in the derivation the archive is no weaker than the account, at the price that restoring one needs the Emergency
/// Kit, which restoring an account needs anyway.
///
/// Every info string differs from the account's (`WW-salt-v1`, `WW-2SKD-v1`, `WW-AUK-v1`), and the archive ID salts
/// both the PBKDF2 input and the combination, so no choice of passphrase, salt or parameters in a crafted archive
/// header makes this key equal an Account Unlock Key, and no two archives share a key.
///
/// `KDFParameters.validate()` runs first: an archive is a file from anywhere (A7), and its header can neither weaken
/// the derivation below the floor nor turn it into a hang above the ceiling (SEC5, SEC9).
public enum ArchiveKeyDerivation {
    static let saltInfo = Array("WW-archive-salt-v1".utf8)
    static let secretKeyInfo = Array("WW-archive-2SKD-v1".utf8)
    static let combineInfo = Array("WW-archive-key-v1".utf8)

    public static func wrappingKey(
        passphrase: String,
        secretKey: SecretKey,
        archiveID: UUID,
        accountID: UUID,
        parameters: KDFParameters,
        salt: [UInt8],
        keyID: UUID
    ) throws -> EncryptionKey {
        try parameters.validate()
        guard salt.count == parameters.saltLength else {
            throw CryptoError.saltLengthMismatch(expected: parameters.saltLength, actual: salt.count)
        }
        var utf8 = Array(passphrase.decomposedStringWithCompatibilityMapping.utf8)
        guard !utf8.isEmpty else { throw CryptoError.emptyPassword }
        let passphraseBytes = SecureBytes(wiping: &utf8)
        defer { passphraseBytes.zeroise() }
        let archiveSalt = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: salt), salt: archiveID.byteArray, info: saltInfo,
            outputByteCount: 32)
        let passphraseKey = try PBKDF2.sha256(
            password: passphraseBytes, salt: SecureBytes(copying: archiveSalt).unprotectedCopy(),
            iterations: parameters.iterations, outputByteCount: EncryptionKey.byteCount)
        defer { passphraseKey.zeroise() }
        let secretKeyKey = SecureBytes(
            copying: HKDF<SHA256>.deriveKey(
                inputKeyMaterial: secretKey.bytes.symmetricKey, salt: accountID.byteArray, info: secretKeyInfo,
                outputByteCount: EncryptionKey.byteCount))
        defer { secretKeyKey.zeroise() }
        let combined = SecureBytes.concatenating([passphraseKey, secretKeyKey])
        defer { combined.zeroise() }
        let wrappingKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: combined.symmetricKey, salt: archiveID.byteArray + accountID.byteArray,
            info: combineInfo, outputByteCount: EncryptionKey.byteCount)
        return try EncryptionKey(keyID: keyID, material: SecureBytes(copying: wrappingKey))
    }
}
