#if canImport(CryptoKit)
    import CryptoKit
    import Foundation

    /// What a signature is for. Every Ed25519 signature covers `"WW-sig-v1" ‖ 0x00 ‖ domain ‖ message`, so a signature
    /// made for one purpose never verifies for another — a membership record cannot be replayed as a log segment or a
    /// key grant (docs/02-architecture.md §4, §8). Raw values are part of the format; never renumber them.
    public enum SignatureDomain: UInt8, Sendable, CaseIterable {
        case publicKeyBundle = 1
        case vaultKeyGrant = 2
        case membership = 3
        case logSegment = 4
    }

    public enum Signatures {
        static let prefix = Array("WW-sig-v1".utf8)

        static func signedBytes(domain: SignatureDomain, message: [UInt8]) -> [UInt8] {
            prefix + [0x00, domain.rawValue] + message
        }

        /// Verifies `signature` over `message` for `domain` against a raw 32-byte Ed25519 public key, which the caller
        /// must already trust (a fingerprint-verified `PublicKeyBundle`).
        public static func verify(
            _ signature: [UInt8],
            for message: [UInt8],
            domain: SignatureDomain,
            signingKey: [UInt8]
        ) throws {
            guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: signingKey) else {
                throw CryptoError.invalidPublicKey
            }
            guard publicKey.isValidSignature(signature, for: signedBytes(domain: domain, message: message)) else {
                throw CryptoError.signatureInvalid
            }
        }
    }
#endif
