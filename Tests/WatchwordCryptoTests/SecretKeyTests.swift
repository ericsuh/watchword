import Foundation
import SecureMemory
import Testing
import WatchwordTestSupport

@testable import WatchwordCrypto

@Suite("Secret Key format")
struct SecretKeyTests {
    /// Expected strings from an independent Python implementation of the base-31 encoding and GF(31) checksum.
    @Test(
        "formats known keys",
        arguments: zip(
            [
                "000102030405060708090a0b0c0d0e0f", "ffffffffffffffffffffffffffffffff",
                "00000000000000000000000000000000",
            ],
            [
                "WW-222A5A-T7UZR-SFT4B-J48XR-4T7TP-PW", "WW-KQGTVB-ZM585-JJ38Q-RUAXW-S3NG9-YM",
                "WW-222222-22222-22222-22222-22222-22",
            ]
        ))
    func knownFormats(_ hex: String, _ expected: String) throws {
        let key = try SecretKey(bytes: SecureBytes(copying: [UInt8](hex: hex)))
        #expect(key.formatted == expected)
        #expect(Array(try SecretKey(parsing: expected).bytes) == [UInt8](hex: hex))
    }

    @Test("every generated key round-trips through its formatted form")
    func roundTrip() throws {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 7))
        for _ in 0..<TestEnvironment.iterations(standard: 500, long: 50_000) {
            let key = SecretKey.generate(using: &generator)
            let text = key.formatted
            #expect(text.count == 2 + 1 + 26 + 2 + 5)
            #expect(text.split(separator: "-").map(\.count) == [2, 6, 5, 5, 5, 5, 2])
            #expect(Array(try SecretKey(parsing: text).bytes) == Array(key.bytes))
        }
    }

    @Test("parsing tolerates case, spaces and missing separators, and nothing else")
    func lenientParsing() throws {
        let canonical = "WW-222A5A-T7UZR-SFT4B-J48XR-4T7TP-PW"
        let expected = Array(try SecretKey(parsing: canonical).bytes)
        for variant in [
            canonical.lowercased(), canonical.replacingOccurrences(of: "-", with: " "),
            "WW222A5AT7UZRSFT4BJ48XR4T7TPPW",
        ] {
            #expect(Array(try SecretKey(parsing: variant).bytes) == expected)
        }
    }

    @Test(
        "rejects characters outside the alphabet without echoing them",
        arguments: ["0", "1", "I", "L", "O", "_", "\u{FF37}", "\u{0410}"])
    func invalidCharacters(_ bad: String) {
        let text = "WW-222A5A-T7UZR-SFT4B-J48XR-4T7TP-PW".replacingOccurrences(of: "T7UZR", with: "T\(bad)UZR")
        #expect(throws: SecretKeyError.invalidCharacter(position: 9)) { try SecretKey(parsing: text) }
    }

    @Test("rejects a wrong length and a missing prefix")
    func lengthAndPrefix() {
        #expect(throws: SecretKeyError.wrongLength(28)) { try SecretKey(parsing: "222A5A-T7UZR-SFT4B-J48XR-4T7TP-PW") }
        #expect(throws: SecretKeyError.wrongLength(29)) {
            try SecretKey(parsing: "WW-222A5A-T7UZR-SFT4B-J48XR-4T7TP-P")
        }
        #expect(throws: SecretKeyError.missingPrefix) { try SecretKey(parsing: "AB-222A5A-T7UZR-SFT4B-J48XR-4T7TP-PW") }
    }

    @Test("rejects values of 2^128 and above even with a correct checksum")
    func outOfRange() {
        let digits = [UInt8](repeating: 30, count: 26)
        let (c1, c2) = SecretKey.checksum(digits)
        let text = "WW" + String(decoding: (digits + [c1, c2]).map { SecretKey.alphabet[Int($0)] }, as: UTF8.self)
        #expect(throws: SecretKeyError.valueOutOfRange) { try SecretKey(parsing: text) }
    }

    @Test("every single-character substitution is caught by the checksum")
    func singleSubstitutions() {
        let symbols = Array("222A5AT7UZRSFT4BJ48XR4T7TPPW".utf8)
        for position in symbols.indices {
            for replacement in SecretKey.alphabet where replacement != symbols[position] {
                var mutated = symbols
                mutated[position] = replacement
                let text = "WW" + String(decoding: mutated, as: UTF8.self)
                #expect(throws: SecretKeyError.checksumMismatch) { try SecretKey(parsing: text) }
            }
        }
    }

    @Test("every adjacent transposition is caught by the checksum")
    func transpositions() {
        var generator = SeededGenerator(seed: 11)
        for _ in 0..<50 {
            let symbols = Array(
                SecretKey.generate(using: &generator).formatted.replacingOccurrences(of: "-", with: "").utf8
            )
            .dropFirst(2)
            let base = Array(symbols)
            for position in 0..<(base.count - 1) where base[position] != base[position + 1] {
                var mutated = base
                mutated.swapAt(position, position + 1)
                let text = "WW" + String(decoding: mutated, as: UTF8.self)
                #expect(throws: SecretKeyError.checksumMismatch) { try SecretKey(parsing: text) }
            }
        }
    }

    @Test("any two substituted characters are caught by the checksum")
    func doubleSubstitutions() {
        var generator = SeededGenerator(seed: TestEnvironment.seed(fallback: 13))
        let base = Array("222A5AT7UZRSFT4BJ48XR4T7TPPW".utf8)
        for _ in 0..<TestEnvironment.iterations(standard: 5_000, long: 500_000) {
            let first = Int.random(in: 0..<base.count, using: &generator)
            var second = Int.random(in: 0..<(base.count - 1), using: &generator)
            if second >= first { second += 1 }
            var mutated = base
            for position in [first, second] {
                let choices = SecretKey.alphabet.filter { $0 != base[position] }
                mutated[position] = choices.randomElement(using: &generator)!
            }
            let text = "WW" + String(decoding: mutated, as: UTF8.self)
            #expect(throws: SecretKeyError.checksumMismatch) { try SecretKey(parsing: text) }
        }
    }

    @Test("generation uses all 128 bits")
    func generationCoversAllBits() {
        var generator = SeededGenerator(seed: 17)
        var seenOnes = [Bool](repeating: false, count: 128)
        var seenZeros = [Bool](repeating: false, count: 128)
        for _ in 0..<64 {
            let bytes = Array(SecretKey.generate(using: &generator).bytes)
            for bit in 0..<128 {
                if bytes[bit / 8] >> (bit % 8) & 1 == 1 { seenOnes[bit] = true } else { seenZeros[bit] = true }
            }
        }
        #expect(seenOnes.allSatisfy { $0 } && seenZeros.allSatisfy { $0 })
    }

    @Test("the key must be exactly 16 bytes")
    func byteCount() {
        #expect(throws: SecretKeyError.wrongByteCount(15)) { try SecretKey(bytes: SecureBytes(count: 15)) }
    }
}
