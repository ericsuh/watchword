#if canImport(CryptoKit) || os(Linux)
    #if canImport(CryptoKit)
        import CryptoKit
    #else
        import Crypto
    #endif
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

        /// Encodings of the eight small-order points of edwards25519, including the non-canonical ones (y ≥ p), compared
        /// with the sign bit cleared (libsodium's `has_small_order` list; each checked to satisfy 8·P = O). For such a key,
        /// a signature with R the identity and S = 0 verifies for every message, so a published key of this kind would make
        /// that member's membership records, log segments and grants forgeable by anyone (review finding R4).
        static let smallOrderEncodings: [[UInt8]] = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ].map { hex in
            stride(from: 0, to: hex.count, by: 2).map { offset in
                let start = hex.index(hex.startIndex, offsetBy: offset)
                return UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16)!
            }
        }

        /// Rejects keys of the wrong length and small-order keys.
        static func validateSigningKey(_ raw: [UInt8]) throws {
            guard raw.count == 32 else { throw CryptoError.invalidPublicKey }
            var masked = raw
            masked[31] &= 0x7F
            guard !smallOrderEncodings.contains(masked) else { throw CryptoError.weakSigningKey }
        }

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
            try validateSigningKey(signingKey)
            guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: signingKey) else {
                throw CryptoError.invalidPublicKey
            }
            guard publicKey.isValidSignature(signature, for: signedBytes(domain: domain, message: message)) else {
                throw CryptoError.signatureInvalid
            }
        }
    }
#endif
