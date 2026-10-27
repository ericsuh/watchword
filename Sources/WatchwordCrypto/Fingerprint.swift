#if canImport(CryptoKit) || os(Linux)
    #if canImport(CryptoKit)
        import CryptoKit
    #else
        import Crypto
    #endif
    import Foundation
    import SecureMemory

    /// What two people compare out of band before sharing a vault (docs/02-architecture.md §8, PRD F4.2, SEC3).
    ///
    /// `SHA-512("WW-fingerprint-v1" ‖ accountID ‖ X25519 public key ‖ Ed25519 public key)`, truncated to 60 bytes and
    /// shown as twelve groups of five digits (each group is a 40-bit big-endian chunk mod 100,000). SHA-512 rather than
    /// SHA-256 because a 60-digit safety number needs 60 bytes of digest. All inputs are fixed-length, so the
    /// concatenation is unambiguous. Equality is constant-time.
    public struct Fingerprint: Sendable, Equatable {
        public static let groupCount = 12
        static let domain = Array("WW-fingerprint-v1".utf8)

        let digest: [UInt8]

        init(accountID: UUID, agreementKey: [UInt8], signingKey: [UInt8]) {
            var hasher = SHA512()
            hasher.update(data: Fingerprint.domain)
            hasher.update(data: accountID.byteArray)
            hasher.update(data: agreementKey)
            hasher.update(data: signingKey)
            digest = Array(Array(hasher.finalize()).prefix(Fingerprint.groupCount * 5))
        }

        /// Sixty digits in twelve space-separated groups of five.
        public var safetyNumber: String {
            (0..<Fingerprint.groupCount).map { group in
                let chunk = digest[(group * 5)..<(group * 5 + 5)].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
                let digits = String(chunk % 100_000)
                return String(repeating: "0", count: 5 - digits.count) + digits
            }.joined(separator: " ")
        }

        public static func == (lhs: Fingerprint, rhs: Fingerprint) -> Bool {
            ConstantTime.equal(lhs.digest, rhs.digest)
        }
    }
#endif
