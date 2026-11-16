import Crypto
import Foundation
import SecureMemory

/// How a device signs (docs/02-architecture.md §6 `deviceSigningKey`, §7.8). Raw values are part of the registry
/// format; never renumber them.
public enum DeviceSignatureAlgorithm: UInt8, Sendable, Hashable, CaseIterable {
    /// A software key: 32-byte public key, 64-byte signature. What `SoftwareDeviceKey` makes, for devices without a
    /// Secure Enclave and for every test.
    case ed25519 = 1
    /// A Secure Enclave key: the 65-byte X9.63 uncompressed public key, and ECDSA over SHA-256 as the 64-byte raw
    /// `r ‖ s` with `s` in the lower half of the group order. The adapter that makes these is Apple-only and arrives
    /// with the platform work; verification is here so every device can check them.
    case p256ECDSA = 2
}

/// A device's public signing key as the registry records it. Constructing one validates it: lengths, that an Ed25519
/// key is not of small order (one signature would verify for every message), and that a P-256 key is a point on the
/// curve. A `DevicePublicKey` value has therefore passed those checks.
public struct DevicePublicKey: Sendable, Hashable {
    public static let maximumLength = 65

    public let algorithm: DeviceSignatureAlgorithm
    public let rawRepresentation: [UInt8]

    public init(algorithm: DeviceSignatureAlgorithm, rawRepresentation: [UInt8]) throws {
        switch algorithm {
        case .ed25519:
            try Signatures.validateSigningKey(rawRepresentation)
            guard (try? Curve25519.Signing.PublicKey(rawRepresentation: rawRepresentation)) != nil else {
                throw CryptoError.invalidPublicKey
            }
        case .p256ECDSA:
            guard rawRepresentation.count == 65, rawRepresentation[0] == 0x04,
                (try? P256.Signing.PublicKey(x963Representation: rawRepresentation)) != nil
            else { throw CryptoError.invalidPublicKey }
        }
        self.algorithm = algorithm
        self.rawRepresentation = rawRepresentation
    }
}

/// Signatures made by a device key. Every one covers `"WW-devsig-v1" ‖ 0x00 ‖ domain ‖ deviceID ‖ message`, so a
/// device's signature for one purpose, or as one device, never verifies for another (docs/02-architecture.md §4).
public enum DeviceSignatures {
    static let prefix = Array("WW-devsig-v1".utf8)

    /// Half the order of the P-256 group, big-endian: an ECDSA signature's `s` must not exceed it. `(r, s)` and
    /// `(r, n − s)` both verify, and registry entries are named by the hash of their bytes, so accepting both would
    /// let anyone holding one entry mint a second name for it.
    static let p256HalfOrder: [UInt8] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
    ]

    /// The bytes a device key signs for `message`. A `DeviceKeyStore` signs exactly these.
    public static func signedBytes(domain: SignatureDomain, deviceID: UUID, message: [UInt8]) -> [UInt8] {
        prefix + [0x00, domain.rawValue] + deviceID.byteArray + message
    }

    /// Verifies a device's signature. The caller must already trust `key` for `deviceID` (the device registry).
    public static func verify(
        _ signature: [UInt8],
        for message: [UInt8],
        domain: SignatureDomain,
        deviceID: UUID,
        key: DevicePublicKey
    ) throws {
        let signed = signedBytes(domain: domain, deviceID: deviceID, message: message)
        switch key.algorithm {
        case .ed25519:
            guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: key.rawRepresentation),
                signature.count == 64, publicKey.isValidSignature(signature, for: signed)
            else { throw CryptoError.signatureInvalid }
        case .p256ECDSA:
            guard signature.count == 64, isLowS(Array(signature[32...])),
                let publicKey = try? P256.Signing.PublicKey(x963Representation: key.rawRepresentation),
                let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
                publicKey.isValidSignature(parsed, for: signed)
            else { throw CryptoError.signatureInvalid }
        }
    }

    /// Whether a big-endian 32-byte `s` is at most half the group order. Not secret, so not constant-time.
    static func isLowS(_ s: [UInt8]) -> Bool {
        guard s.count == p256HalfOrder.count else { return false }
        for (byte, limit) in zip(s, p256HalfOrder) where byte != limit {
            return byte < limit
        }
        return true
    }
}

/// A device signing key held in software: an Ed25519 seed in `SecureBytes` (docs/02-architecture.md §7.8). It is what
/// a device without a Secure Enclave uses, and what the package's `KeychainDeviceKeyStore` keeps in the Keychain; a
/// Secure Enclave key never has this form, because its private half never leaves the enclave.
public struct SoftwareDeviceKey: Sendable {
    public static let seedLength = 32

    let seed: SecureBytes

    public init(seed: SecureBytes) throws {
        guard seed.count == Self.seedLength else { throw CryptoError.invalidKeyLength(seed.count) }
        self.seed = seed
    }

    public static func generate<R: RandomNumberGenerator>(using generator: inout R) -> SoftwareDeviceKey {
        // Cannot throw: the length is right by construction.
        try! SoftwareDeviceKey(seed: SecureBytes(randomCount: seedLength, using: &generator))
    }

    /// A copy of the seed, for the Keychain.
    public func seedCopy() -> SecureBytes {
        seed.extracting(0..<Self.seedLength)
    }

    public func publicKey() throws -> DevicePublicKey {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        return try DevicePublicKey(algorithm: .ed25519, rawRepresentation: Array(key.publicKey.rawRepresentation))
    }

    /// Signs bytes already prepared by `DeviceSignatures.signedBytes`.
    public func sign(prepared bytes: [UInt8]) throws -> [UInt8] {
        Array(try Curve25519.Signing.PrivateKey(rawRepresentation: seed).signature(for: bytes))
    }

    public func zeroise() {
        seed.zeroise()
    }
}

/// The key that proves knowledge of the account's current credentials (docs/02-architecture.md §7.8): an Ed25519 key
/// derived from the Account Unlock Key, so whoever can derive the AUK — the account password and the Secret Key —
/// can sign with it, and nobody else can.
///
/// ```
/// seed = HKDF-SHA256(ikm: AUK, salt: accountID, info: "WW-enrol-v1")
/// ```
///
/// Its public half is published in the device registry by the entry that starts each credential generation. A new
/// device signs its own registration with it (PRD F5.2), and a password change is signed with the key of the
/// generation it replaces, so a device that merely holds the keyset cannot change the account's password for
/// everyone. A new password gives a new AUK and so a new key; the old one stops being accepted.
public struct EnrolmentKey: Sendable {
    static let info = Array("WW-enrol-v1".utf8)

    let seed: SecureBytes

    public static func derive(from unlockKey: EncryptionKey, accountID: UUID) -> EnrolmentKey {
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: unlockKey.material.symmetricKey,
            salt: accountID.byteArray,
            info: info,
            outputByteCount: 32
        )
        return EnrolmentKey(seed: SecureBytes(copying: derived))
    }

    public func publicKey() throws -> [UInt8] {
        Array(try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey.rawRepresentation)
    }

    public func sign(_ message: [UInt8], domain: SignatureDomain) throws -> [UInt8] {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        return Array(try key.signature(for: Signatures.signedBytes(domain: domain, message: message)))
    }

    public func zeroise() {
        seed.zeroise()
    }
}
