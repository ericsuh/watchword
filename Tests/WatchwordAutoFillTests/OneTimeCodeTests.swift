import Foundation
import Testing
import WatchwordAutoFill
import WatchwordModel

@Suite("One-time codes (TOTP)")
struct OneTimeCodeTests {
    /// RFC 6238 appendix B: the secret is the ASCII digits repeated to the hash's block of 20, 32 or 64 bytes.
    static func rfcSecret(_ algorithm: OTPParameters.Algorithm) -> Data {
        let length: Int
        switch algorithm {
        case .sha1: length = 20
        case .sha256: length = 32
        case .sha512: length = 64
        }
        return Data(Array(repeating: Array("1234567890".utf8), count: 7).joined().prefix(length))
    }

    struct Vector: Sendable, CustomTestStringConvertible {
        var time: TimeInterval
        var algorithm: OTPParameters.Algorithm
        var code: String

        var testDescription: String { "\(algorithm.rawValue) at \(Int(time))" }
    }

    /// The table of RFC 6238 appendix B, complete: six instants, three hash functions, eight digits, 30 seconds.
    static let rfc6238: [Vector] = [
        Vector(time: 59, algorithm: .sha1, code: "94287082"),
        Vector(time: 59, algorithm: .sha256, code: "46119246"),
        Vector(time: 59, algorithm: .sha512, code: "90693936"),
        Vector(time: 1_111_111_109, algorithm: .sha1, code: "07081804"),
        Vector(time: 1_111_111_109, algorithm: .sha256, code: "68084774"),
        Vector(time: 1_111_111_109, algorithm: .sha512, code: "25091201"),
        Vector(time: 1_111_111_111, algorithm: .sha1, code: "14050471"),
        Vector(time: 1_111_111_111, algorithm: .sha256, code: "67062674"),
        Vector(time: 1_111_111_111, algorithm: .sha512, code: "99943326"),
        Vector(time: 1_234_567_890, algorithm: .sha1, code: "89005924"),
        Vector(time: 1_234_567_890, algorithm: .sha256, code: "91819424"),
        Vector(time: 1_234_567_890, algorithm: .sha512, code: "93441116"),
        Vector(time: 2_000_000_000, algorithm: .sha1, code: "69279037"),
        Vector(time: 2_000_000_000, algorithm: .sha256, code: "90698825"),
        Vector(time: 2_000_000_000, algorithm: .sha512, code: "38618901"),
        Vector(time: 20_000_000_000, algorithm: .sha1, code: "65353130"),
        Vector(time: 20_000_000_000, algorithm: .sha256, code: "77737706"),
        Vector(time: 20_000_000_000, algorithm: .sha512, code: "47863826"),
    ]

    @Test("matches every vector of RFC 6238 appendix B", arguments: rfc6238)
    func rfc6238Vectors(_ vector: Vector) throws {
        let parameters = try OTPParameters(
            secret: Self.rfcSecret(vector.algorithm), algorithm: vector.algorithm, digits: 8, period: 30)
        let code = try TOTP.code(for: parameters, at: Date(timeIntervalSince1970: vector.time))
        #expect(code.code == vector.code)
    }

    /// RFC 4226 appendix D: HOTP values for counters 0 to 9, which are TOTP codes at `counter × 30` seconds.
    @Test(
        "six-digit codes match RFC 4226 appendix D",
        arguments: zip(
            0..<10,
            ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]))
    func rfc4226Vectors(_ counter: Int, _ expected: String) throws {
        let parameters = try OTPParameters(secret: Self.rfcSecret(.sha1))
        let code = try TOTP.code(for: parameters, at: Date(timeIntervalSince1970: TimeInterval(counter * 30)))
        #expect(code.code == expected)
    }

    /// Computed with Python's `hmac` and `hashlib` (the script is in `PasskeyAuthenticatorTests`): seven digits with a
    /// 60-second period, and a SHA-512 code with a leading digit the truncation could have dropped.
    @Test("other digit counts and periods match an independent implementation")
    func independentVectors() throws {
        let seven = try OTPParameters(
            secret: Data("0123456789abcdefghij".utf8), algorithm: .sha256, digits: 7, period: 60)
        #expect(try TOTP.code(for: seven, at: Date(timeIntervalSince1970: 1_700_000_000)).code == "6406702")
        let six = try OTPParameters(secret: Data(1...20), algorithm: .sha512)
        #expect(try TOTP.code(for: six, at: Date(timeIntervalSince1970: 1_800_000_015)).code == "134289")
    }

    @Test("the code of a field comes from its otpauth URI")
    func fromField() throws {
        let field = Field(
            kind: .totp, label: "Code",
            value: "otpauth://totp/Example:pat?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&algorithm=SHA1")
        let code = try TOTP.code(for: try field.otpParameters(), at: Date(timeIntervalSince1970: 59))
        #expect(code.code == "94287082")
    }

    @Test("seconds remaining count down to the next period and never reach zero")
    func remaining() throws {
        let parameters = try OTPParameters(secret: Self.rfcSecret(.sha1))
        func at(_ time: TimeInterval) throws -> OneTimeCode {
            try TOTP.code(for: parameters, at: Date(timeIntervalSince1970: time))
        }
        #expect(try at(0).secondsRemaining == 30)
        #expect(try at(1).secondsRemaining == 29)
        #expect(try at(29).secondsRemaining == 1)
        #expect(try at(29.9).secondsRemaining == 1)
        #expect(try at(30).secondsRemaining == 30)
        #expect(try at(29).validUntil == Date(timeIntervalSince1970: 30))
        #expect(try at(29).code == at(0).code)
        #expect(try at(30).code != at(29).code)

        let slow = try OTPParameters(secret: Self.rfcSecret(.sha1), period: 300)
        #expect(try TOTP.code(for: slow, at: Date(timeIntervalSince1970: 301)).secondsRemaining == 299)
        #expect(try TOTP.code(for: slow, at: Date(timeIntervalSince1970: 301)).period == 300)
    }

    @Test("every code has exactly the configured number of digits", arguments: 6...8)
    func digitCount(_ digits: Int) throws {
        let parameters = try OTPParameters(secret: Self.rfcSecret(.sha1), digits: digits)
        for step in 0..<200 {
            let code = try TOTP.code(for: parameters, at: Date(timeIntervalSince1970: TimeInterval(step * 30))).code
            #expect(code.count == digits)
            #expect(code.allSatisfy { $0.isASCII && $0.isNumber })
        }
    }

    @Test(
        "a clock that reads before 1970, or nothing finite, yields no code",
        arguments: [-1, -1e9, .infinity, -.infinity, .nan, 1e13])
    func timeOutOfRange(_ time: TimeInterval) throws {
        let parameters = try OTPParameters(secret: Self.rfcSecret(.sha1))
        #expect(throws: OneTimeCodeError.timeOutOfRange) {
            try TOTP.code(for: parameters, at: Date(timeIntervalSince1970: time))
        }
    }
}
