import Crypto
import Foundation
import Testing
import WatchwordTestSupport

@testable import WatchwordCrypto

/// Known-answer tests for each primitive Watchword composes, so a platform change in any of them is caught
/// independently of the round-trip tests. Every expected value is from the cited RFC or, where none fits, from an
/// independent implementation (Python `cryptography` / `hashlib`).
@Suite("Primitive known answers")
struct PrimitiveKnownAnswerTests {
    @Test("HKDF-SHA256 matches RFC 5869 test case 1")
    func hkdf() {
        let okm = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: [UInt8](repeating: 0x0B, count: 22)),
            salt: Array(0x00...0x0C) as [UInt8],
            info: Array(0xF0...0xF9) as [UInt8],
            outputByteCount: 42
        )
        #expect(
            okm
                == SymmetricKey(
                    data: [UInt8](
                        hex: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
                ))
    }

    @Test(
        "AES-256-GCM matches GCM test case 14 and an independent vector",
        arguments: [
            (
                [UInt8](repeating: 0, count: 32), [UInt8](repeating: 0, count: 12), [UInt8](),
                [UInt8](repeating: 0, count: 16),
                "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
            ),
            (
                Array(0..<32), Array(100..<112), Array("WW-aad".utf8), Array("watchword known answer".utf8),
                "3f7aaa05119e39ec5a423486b51204dd23ac757dee1e3cea1025bb41e285f88a04ad33913b29"
            ),
        ])
    func aesGCM(_ key: [UInt8], _ nonce: [UInt8], _ aad: [UInt8], _ plaintext: [UInt8], _ expected: String) throws {
        let sealed = try AES.GCM.seal(
            plaintext, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: nonce), authenticating: aad)
        #expect(Array(sealed.ciphertext) + Array(sealed.tag) == [UInt8](hex: expected))
    }

    @Test("X25519 matches RFC 7748 §6.1")
    func x25519() throws {
        let alice = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: [UInt8](hex: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        let bob = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: [UInt8](hex: "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
        #expect(
            Array(alice.publicKey.rawRepresentation)
                == [UInt8](hex: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
        #expect(
            Array(bob.publicKey.rawRepresentation)
                == [UInt8](hex: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"))
        let shared = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey)
        #expect(shared == [UInt8](hex: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"))
    }

    /// CryptoKit's Ed25519 signatures are randomised, so the RFC signatures are checked by verification, and the
    /// public-key derivation by equality.
    @Test(
        "Ed25519 matches RFC 8032 §7.1 tests 1 and 2",
        arguments: [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ),
        ])
    func ed25519(_ secret: String, _ publicKey: String, _ message: String, _ signature: String) throws {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: [UInt8](hex: secret))
        #expect(Array(key.publicKey.rawRepresentation) == [UInt8](hex: publicKey))
        #expect(key.publicKey.isValidSignature([UInt8](hex: signature), for: [UInt8](hex: message)))
        let ours = try key.signature(for: [UInt8](hex: message))
        #expect(key.publicKey.isValidSignature(ours, for: [UInt8](hex: message)))
    }

    static let hpkeRecipient = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

    /// The first vector is from Python `cryptography`'s HPKE (which takes no associated data); the second from an
    /// independent RFC 9180 implementation that was itself checked against the first.
    @Test(
        "HPKE base mode X25519/HKDF-SHA256/AES-256-GCM opens independent vectors",
        arguments: [
            (
                "a0bd069e0660c54e7910d99a9e8d328301dc2fb628a8335c9ce65405381e7e12",
                "391673794a747e54e62d6e6a32fdab563921ac18bb202c0e8419a5a6e9d678", "", Array("vault key bytes".utf8)
            ),
            (
                "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b",
                "33c30b988f433492dcc5e44b4ad118e053156d6bc5cf52e35b49d88a647cbfcfcb0cc0be4ebae02f8e8a3ca0fb00cc3b",
                "WW-aad", Array(0..<32)
            ),
        ])
    func hpke(_ encapsulated: String, _ ciphertext: String, _ aad: String, _ expected: [UInt8]) throws {
        let recipientKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: [UInt8](hex: PrimitiveKnownAnswerTests.hpkeRecipient))
        #expect(
            Array(recipientKey.publicKey.rawRepresentation)
                == [UInt8](hex: "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"))
        var recipient = try HPKE.Recipient(
            privateKey: recipientKey,
            ciphersuite: VaultKeyGrant.ciphersuite,
            info: Data("WW-hpke-kat".utf8),
            encapsulatedKey: Data([UInt8](hex: encapsulated))
        )
        let opened = try recipient.open([UInt8](hex: ciphertext), authenticating: Array(aad.utf8))
        #expect(Array(opened) == expected)
    }
}
