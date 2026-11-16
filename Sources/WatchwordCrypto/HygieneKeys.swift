import Crypto
import Foundation
import SecureMemory

/// The key a vault's synced breach-check results are bound under (docs/02-architecture.md §13.9; ADR 0005, amendment
/// of 2026-11-16):
///
/// ```
/// scan binding key = HKDF-SHA256(ikm: vault key, salt: vaultID ‖ keyID, info: "WW-hygiene-scan-binding-v1"), 32 bytes
/// ```
///
/// Every member holding the vault key derives the same key, so each can tell whether another member's result is about
/// the password it holds; nobody without that vault key can, so a binding inside a record is not an offline-crackable
/// hash of the password. A result names the key its bindings are under, and a reader derives from that key, which it
/// keeps after a rotation, so results survive a rotation's re-seal. A label of its own: it is neither the vault key nor
/// any other derivation from it.
///
/// `package`, not `public`: the session is the only caller, and this is an escape of key material from a vault key.
package enum HygieneKeys {
    static let scanBindingInfo = Array("WW-hygiene-scan-binding-v1".utf8)

    /// The caller hands the buffer to a `ScanBindingKey` and zeroises it.
    package static func scanBindingKey(vaultKey: VaultKey) -> SecureBytes {
        SecureBytes(
            copying: HKDF<SHA256>.deriveKey(
                inputKeyMaterial: vaultKey.key.material.symmetricKey,
                salt: vaultKey.vaultID.byteArray + vaultKey.key.keyID.byteArray,
                info: scanBindingInfo,
                outputByteCount: 32
            ))
    }
}
