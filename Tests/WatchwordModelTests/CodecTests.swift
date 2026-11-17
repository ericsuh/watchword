import Foundation
import Testing

@testable import WatchwordModel

@Suite("Binary text encodings")
struct BinaryTextTests {
    /// RFC 4648 §10 test vectors.
    @Test(
        "Base32 matches RFC 4648",
        arguments: zip(
            ["", "f", "fo", "foo", "foob", "fooba", "foobar"],
            ["", "MY", "MZXQ", "MZXW6", "MZXW6YQ", "MZXW6YTB", "MZXW6YTBOI"]
        ))
    func base32Vectors(_ plain: String, _ encoded: String) {
        #expect(Base32.encode(Array(plain.utf8)) == encoded)
        #expect(Base32.decode(encoded) == Data(plain.utf8))
        #expect(Base32.decode(encoded.lowercased()) == Data(plain.utf8))
    }

    @Test("Base32 accepts trailing padding and nothing else unusual")
    func base32Strictness() {
        #expect(Base32.decode("MZXW6YQ=") == Data("foob".utf8))
        // Impossible lengths, characters outside the alphabet, padding in the middle, non-zero trailing bits.
        for bad in ["M", "MZX", "MZXW6Y", "MZXW1", "MZ=XQ", "MZXQ MZXQ", "MZ", "MB"] {
            #expect(Base32.decode(bad) == nil, "\(bad)")
        }
    }

    /// RFC 4648 §10 vectors, unpadded, plus the two characters that differ from standard base64.
    @Test(
        "Base64url matches RFC 4648",
        arguments: zip(
            ["", "f", "fo", "foo", "foob", "fooba", "foobar"],
            ["", "Zg", "Zm8", "Zm9v", "Zm9vYg", "Zm9vYmE", "Zm9vYmFy"]
        ))
    func base64URLVectors(_ plain: String, _ encoded: String) {
        #expect(Base64URL.encode(Array(plain.utf8)) == encoded)
        #expect(Base64URL.decode(encoded) == Data(plain.utf8))
    }

    @Test("Base64url has one spelling per value")
    func base64URLStrictness() {
        #expect(Base64URL.encode([0xFB, 0xFF, 0xBF]) == "-_-_")
        #expect(Base64URL.decode("-_-_") == Data([0xFB, 0xFF, 0xBF]))
        // Padding, the standard alphabet, whitespace, an impossible length and non-zero trailing bits.
        for bad in ["Zg==", "+/+/", "Zm 9v", "Zm9vY", "Zh", "Zm9=", "Zg\n"] {
            #expect(Base64URL.decode(bad) == nil, "\(bad)")
        }
    }
}

@Suite("OTP parameters")
struct OTPParametersTests {
    // RFC 6238 Appendix B's SHA-1 seed, "12345678901234567890".
    static let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    @Test("parses a full URI")
    func parsesFullURI() throws {
        let uri =
            "otpauth://totp/Example:alice@example.com?secret=\(Self.secret)&issuer=Example&algorithm=SHA256"
            + "&digits=8&period=60"
        let parameters = try OTPParameters(uri: uri)
        #expect(parameters.secret == Data("12345678901234567890".utf8))
        #expect(parameters.algorithm == .sha256)
        #expect(parameters.digits == 8)
        #expect(parameters.period == 60)
        #expect(parameters.issuer == "Example")
        #expect(parameters.account == "alice@example.com")
    }

    @Test("defaults are SHA-1, six digits, thirty seconds; grouped and lower-case secrets are accepted")
    func defaults() throws {
        let parameters = try OTPParameters(uri: "otpauth://totp/alice?secret=gezd%20gnbv-gy3tqojqgezdgnbvgy3tqojq")
        #expect(parameters.algorithm == .sha1)
        #expect(parameters.digits == 6)
        #expect(parameters.period == 30)
        #expect(parameters.issuer == nil)
        #expect(parameters.account == "alice")
        #expect(parameters.secret == Data("12345678901234567890".utf8))
    }

    @Test("round-trips through its canonical URI")
    func roundTrip() throws {
        let original = try OTPParameters(
            secret: Data("12345678901234567890".utf8), algorithm: .sha512, digits: 7, period: 45,
            issuer: "AWS & Co", account: "root@example.com")
        #expect(try OTPParameters(uri: original.uri) == original)
    }

    /// The label is split at its first colon, so names that contain one need care to survive formatting.
    @Test(
        "names with colons, and missing names, round-trip",
        arguments: [
            ("A:B", "x"), ("A:B", nil), (nil, "a:b"), ("Example", "a:b:c"), ("Example", nil), (nil, nil),
            (nil, "plain"), ("", ""),
        ] as [(String?, String?)])
    func namesRoundTrip(_ issuer: String?, _ account: String?) throws {
        let original = try OTPParameters(
            secret: Data("12345678901234567890".utf8), issuer: issuer, account: account)
        let parsed = try OTPParameters(uri: original.uri)
        #expect(parsed == original)
        #expect(parsed.issuer == (issuer?.isEmpty == false ? issuer : nil))
        #expect(parsed.account == (account?.isEmpty == false ? account : nil))
    }

    @Test(
        "hostile or unusable URIs are refused with a reason",
        arguments: zip(
            [
                "https://example.com/?secret=\(secret)",
                "otpauth://hotp/a?secret=\(secret)&counter=1",
                "otpauth://totp/a",
                "otpauth://totp/a?secret=",
                "otpauth://totp/a?secret=not!base32",
                "otpauth://totp/a?secret=MZXW6YTB",
                "otpauth://totp/a?secret=\(secret)&algorithm=MD5",
                "otpauth://totp/a?secret=\(secret)&digits=40",
                "otpauth://totp/a?secret=\(secret)&digits=six",
                "otpauth://totp/a?secret=\(secret)&period=0",
                "otpauth://totp/a?secret=\(secret)&period=-30",
                "otpauth://totp/a?secret=\(secret)&secret=\(secret)",
                "otpauth://totp/a?secret=\(secret)&x=" + String(repeating: "a", count: 5000),
            ],
            [
                OTPAuthError.notAnOTPAuthURI, .unsupportedType("hotp"), .missingSecret, .missingSecret,
                .malformedSecret, .secretLength(5), .unsupportedAlgorithm("MD5"), .digitsOutOfRange("40"),
                .digitsOutOfRange("six"), .periodOutOfRange("0"), .periodOutOfRange("-30"),
                .duplicateParameter("secret"), .tooLong,
            ]
        ))
    func refusals(_ uri: String, _ expected: OTPAuthError) {
        #expect(throws: expected) { try OTPParameters(uri: uri) }
    }

    @Test("only a TOTP field has parameters")
    func fieldAccessor() throws {
        let field = Field(kind: .totp, label: "One-time code", value: "otpauth://totp/a?secret=\(Self.secret)")
        #expect(try field.otpParameters().digits == 6)
        let password = Field(kind: .password, label: "Password", value: field.value)
        #expect(throws: OTPAuthError.notAnOTPAuthURI) { try password.otpParameters() }
    }
}

@Suite("Passkey credential field")
struct PasskeyCredentialTests {
    static func sample(prf: Bool = true) throws -> PasskeyCredential {
        try PasskeyCredential(
            credentialID: Data((0..<32).map { UInt8($0) }),
            relyingPartyID: "Google.com",
            userHandle: Data([1, 2, 3, 4]),
            userName: "alice@example.com",
            userDisplayName: "Alice",
            privateKeyPKCS8: Data(repeating: 0x30, count: 138),
            createdAt: Date(timeIntervalSince1970: 1_760_000_000.75),
            prfSecret: prf ? Data(repeating: 7, count: 32) : nil,
            largeBlob: nil)
    }

    @Test("round-trips through a field, with the relying party lower-cased and the date in whole seconds")
    func roundTrip() throws {
        let credential = try Self.sample()
        #expect(credential.relyingPartyID == "google.com")
        #expect(credential.createdAt == Date(timeIntervalSince1970: 1_760_000_000))
        let field = try Field.passkey(credential)
        #expect(field.kind == .passkey)
        #expect(try field.passkeyCredential() == credential)
        #expect(try Field.passkey(Self.sample(prf: false)).passkeyCredential().prfSecret == nil)
    }

    @Test("the stored form is sorted JSON with unpadded base64url")
    func storedForm() throws {
        let value = try Self.sample().fieldValue()
        #expect(
            value.hasPrefix(#"{"createdAt":1760000000,"credentialID":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","#))
        #expect(!value.contains("="))
    }

    @Test("out-of-bounds values are refused by name")
    func bounds() throws {
        let base = try Self.sample()
        func rebuilt(_ change: (inout PasskeyCredential) -> Void) throws -> PasskeyCredential {
            var copy = base
            change(&copy)
            return try PasskeyCredential(
                credentialID: copy.credentialID, relyingPartyID: copy.relyingPartyID, userHandle: copy.userHandle,
                userName: copy.userName, userDisplayName: copy.userDisplayName,
                privateKeyPKCS8: copy.privateKeyPKCS8, createdAt: copy.createdAt, prfSecret: copy.prfSecret,
                largeBlob: copy.largeBlob)
        }
        #expect(throws: PasskeyCodingError.invalid("credentialID")) { try rebuilt { $0.credentialID = Data([1]) } }
        #expect(throws: PasskeyCodingError.invalid("credentialID")) {
            try rebuilt { $0.credentialID = Data(count: 1024) }
        }
        #expect(throws: PasskeyCodingError.invalid("relyingPartyID")) { try rebuilt { $0.relyingPartyID = "" } }
        #expect(throws: PasskeyCodingError.invalid("userHandle")) { try rebuilt { $0.userHandle = Data(count: 65) } }
        #expect(throws: PasskeyCodingError.invalid("userHandle")) { try rebuilt { $0.userHandle = Data() } }
        #expect(throws: PasskeyCodingError.invalid("privateKey")) { try rebuilt { $0.privateKeyPKCS8 = Data() } }
        #expect(throws: PasskeyCodingError.invalid("privateKey")) {
            try rebuilt { $0.privateKeyPKCS8 = Data(count: 513) }
        }
        #expect(throws: PasskeyCodingError.invalid("prfSecret")) { try rebuilt { $0.prfSecret = Data(count: 31) } }
        #expect(throws: PasskeyCodingError.invalid("largeBlob")) {
            try rebuilt { $0.largeBlob = Data(count: 16 * 1024 + 1) }
        }
    }

    @Test(
        "malformed field values are refused",
        arguments: [
            "", "{}", "[]", #"{"createdAt":"now"}"#,
            #"{"createdAt":1,"credentialID":"AA==","privateKey":"MA","rpID":"a.example","userDisplayName":"","userHandle":"AQ","userName":""}"#,
        ])
    func malformed(_ value: String) {
        #expect(throws: PasskeyCodingError.self) { try PasskeyCredential(fieldValue: value) }
    }

    @Test("a stored relying party ID with upper-case letters is refused, not folded")
    func mixedCaseStoredRelyingParty() throws {
        let value = try Self.sample().fieldValue().replacingOccurrences(of: "google.com", with: "Google.com")
        #expect(throws: PasskeyCodingError.invalid("relyingPartyID")) { try PasskeyCredential(fieldValue: value) }
    }

    @Test("oversized field values are refused before decoding, and other kinds are not passkeys")
    func sizeAndKind() {
        let huge = String(repeating: " ", count: PasskeyCredential.maximumFieldLength + 1)
        #expect(throws: PasskeyCodingError.tooLong) { try PasskeyCredential(fieldValue: huge) }
        let field = Field(kind: .password, label: "Password", value: "{}")
        #expect(throws: PasskeyCodingError.notAPasskeyField) { try field.passkeyCredential() }
    }
}
