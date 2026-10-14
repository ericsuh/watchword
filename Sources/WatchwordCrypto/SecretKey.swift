import Foundation
import SecureMemory

public enum SecretKeyError: Error, Equatable, Sendable {
    /// Position among the significant characters (separators skipped). The character itself is deliberately not
    /// carried: an error that reaches a log must not leak part of a Secret Key.
    case invalidCharacter(position: Int)
    case wrongLength(Int)
    case missingPrefix
    /// The two check characters do not match: almost certainly a typo.
    case checksumMismatch
    /// The 26 data characters encode a number of 2^128 or more, which no generated key can be.
    case valueOutOfRange
    case wrongByteCount(Int)
}

/// The 128-bit second secret of 2SKD (docs/02-architecture.md §4, PRD F5.1, ADR 0004).
///
/// Display format: `WW-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-CC` — the prefix, 26 data characters, and two check characters,
/// from a 31-symbol alphabet with no `0`, `1`, `I`, `L` or `O`. The data characters are the key's 128-bit value in base
/// 31, most significant first (31^26 ≈ 2^128.8, so every key fits and the decoder rejects anything above 2^128 − 1).
///
/// The check characters form a two-symbol code over GF(31): with α = 3 (a primitive root mod 31) and data digits
/// d₀…d₂₅, `c₁ = Σ dᵢ·α^(i+1)` and `c₂ = Σ dᵢ·α^(2(i+1))`, mod 31. Any one or two wrong characters anywhere — which
/// includes every adjacent transposition — changes at least one check value, because the 2×2 system they would have to
/// satisfy has a non-zero determinant whenever the two positions differ. It catches typos; it is not a MAC and needs
/// not be: the key itself is the secret.
///
/// Parsing accepts lower case, hyphens and ASCII spaces, and nothing else. Formatting and parsing convert through
/// stack integers and short-lived arrays that are wiped; the formatted `String` itself cannot be wiped (PRD SEC4) and
/// exists only to be shown on the Emergency Kit.
public struct SecretKey: Sendable {
    public static let prefix = "WW"
    public static let byteCount = 16
    public static let dataCharacterCount = 26
    public static let checksumCharacterCount = 2
    public static let alphabet: [UInt8] = Array("23456789ABCDEFGHJKMNPQRSTUVWXYZ".utf8)
    /// Group sizes after the prefix: five data groups, then the check group.
    static let groupSizes = [6, 5, 5, 5, 5, 2]

    package let bytes: SecureBytes

    public init(bytes: SecureBytes) throws {
        guard bytes.count == SecretKey.byteCount else { throw SecretKeyError.wrongByteCount(bytes.count) }
        self.bytes = bytes
    }

    public static func generate<R: RandomNumberGenerator>(using generator: inout R) -> SecretKey {
        try! SecretKey(bytes: SecureBytes(randomCount: byteCount, using: &generator))
    }

    public static func generate() -> SecretKey {
        var generator = SystemRandomNumberGenerator()
        return generate(using: &generator)
    }

    public init(parsing text: String) throws {
        let prefix = Array(SecretKey.prefix.utf8)
        let expectedLength = prefix.count + SecretKey.dataCharacterCount + SecretKey.checksumCharacterCount
        // Reserved once and never grown, so no reallocation leaves a freed, unwiped copy of part of the key behind
        // (review finding R8). Symbols past the expected length are counted, not stored.
        var symbols: [UInt8] = []
        symbols.reserveCapacity(expectedLength)
        defer { SecretKey.wipe(&symbols) }
        var significant = 0
        for scalar in text.unicodeScalars where scalar != "-" && scalar != " " {
            guard scalar.isASCII, SecretKey.value(ofSymbol: SecretKey.uppercased(UInt8(scalar.value))) != nil else {
                throw SecretKeyError.invalidCharacter(position: significant)
            }
            if significant < expectedLength {
                symbols.append(SecretKey.uppercased(UInt8(scalar.value)))
            }
            significant += 1
        }
        guard significant == expectedLength else { throw SecretKeyError.wrongLength(significant) }
        guard symbols[0..<prefix.count].elementsEqual(prefix) else { throw SecretKeyError.missingPrefix }

        var data = symbols[prefix.count..<(prefix.count + SecretKey.dataCharacterCount)].map {
            SecretKey.value(ofSymbol: $0)!
        }
        defer { SecretKey.wipe(&data) }
        var given = symbols[(prefix.count + SecretKey.dataCharacterCount)...].map { SecretKey.value(ofSymbol: $0)! }
        defer { SecretKey.wipe(&given) }
        let (c1, c2) = SecretKey.checksum(data)
        guard ConstantTime.equal([c1, c2], given) else { throw SecretKeyError.checksumMismatch }

        var raw = try SecretKey.bytes(fromDigits: data)
        self.bytes = SecureBytes(wiping: &raw)
    }

    /// `WW-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX-CC`.
    public var formatted: String {
        var digits = SecretKey.digits(of: bytes)
        defer { SecretKey.wipe(&digits) }
        let (c1, c2) = SecretKey.checksum(digits)
        var all = digits + [c1, c2]
        defer { SecretKey.wipe(&all) }
        var groups = [SecretKey.prefix]
        var offset = 0
        for size in SecretKey.groupSizes {
            let symbols = all[offset..<(offset + size)].map { SecretKey.alphabet[Int($0)] }
            groups.append(String(decoding: symbols, as: UTF8.self))
            offset += size
        }
        return groups.joined(separator: "-")
    }

    public func zeroise() {
        bytes.zeroise()
    }

    // MARK: - Encoding

    /// The key as 26 base-31 digits, most significant first.
    static func digits(of bytes: SecureBytes) -> [UInt8] {
        var high: UInt64 = 0
        var low: UInt64 = 0
        for index in 0..<8 {
            high = high << 8 | UInt64(bytes[index])
            low = low << 8 | UInt64(bytes[index + 8])
        }
        var digits = [UInt8](repeating: 0, count: dataCharacterCount)
        for position in stride(from: dataCharacterCount - 1, through: 0, by: -1) {
            let (highQuotient, highRemainder) = high.quotientAndRemainder(dividingBy: 31)
            let (lowQuotient, remainder) = UInt64(31).dividingFullWidth((high: highRemainder, low: low))
            high = highQuotient
            low = lowQuotient
            digits[position] = UInt8(remainder)
        }
        return digits
    }

    /// Inverse of `digits(of:)`; throws if the value does not fit in 128 bits.
    static func bytes(fromDigits digits: [UInt8]) throws -> [UInt8] {
        var high: UInt64 = 0
        var low: UInt64 = 0
        var overflow = false
        for digit in digits {
            let (lowCarry, lowProduct) = low.multipliedFullWidth(by: 31)
            let (highProduct, o1) = high.multipliedReportingOverflow(by: 31)
            let (newLow, carry) = lowProduct.addingReportingOverflow(UInt64(digit))
            let (partial, o2) = highProduct.addingReportingOverflow(lowCarry)
            let (newHigh, o3) = partial.addingReportingOverflow(carry ? 1 : 0)
            overflow = overflow || o1 || o2 || o3
            high = newHigh
            low = newLow
        }
        guard !overflow else { throw SecretKeyError.valueOutOfRange }
        var raw = [UInt8](repeating: 0, count: byteCount)
        for index in 0..<8 {
            raw[index] = UInt8(truncatingIfNeeded: high >> UInt64(56 - 8 * index))
            raw[index + 8] = UInt8(truncatingIfNeeded: low >> UInt64(56 - 8 * index))
        }
        return raw
    }

    static func checksum(_ digits: [UInt8]) -> (UInt8, UInt8) {
        var first = 0
        var second = 0
        var power = 1
        for digit in digits {
            power = power * 3 % 31
            first = (first + Int(digit) * power) % 31
            second = (second + Int(digit) * power * power) % 31
        }
        return (UInt8(first), UInt8(second))
    }

    private static func uppercased(_ byte: UInt8) -> UInt8 {
        (0x61...0x7A).contains(byte) ? byte - 0x20 : byte
    }

    static func value(ofSymbol symbol: UInt8) -> UInt8? {
        alphabet.firstIndex(of: symbol).map { UInt8($0) }
    }

    private static func wipe(_ array: inout [UInt8]) {
        for index in array.indices {
            array[index] = 0
        }
    }
}
