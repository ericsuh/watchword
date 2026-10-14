import Foundation

/// The nightly workflow's knobs (CLAUDE.md, "Tests"): `WATCHWORD_LONG_TESTS=1` widens iteration budgets and
/// `WATCHWORD_TEST_SEED` varies randomised runs.
public enum TestEnvironment {
    public static var isLongRun: Bool {
        ProcessInfo.processInfo.environment["WATCHWORD_LONG_TESTS"] == "1"
    }

    /// The nightly seed when set, otherwise `fallback`, so ordinary runs stay reproducible.
    public static func seed(fallback: UInt64) -> UInt64 {
        ProcessInfo.processInfo.environment["WATCHWORD_TEST_SEED"].flatMap(UInt64.init) ?? fallback
    }

    /// `standard` normally, `long` in the nightly run.
    public static func iterations(standard: Int, long: Int) -> Int {
        isLongRun ? long : standard
    }
}

extension Array where Element == UInt8 {
    /// Decodes a hex string written in a test vector; whitespace is ignored. Traps on malformed input.
    public init(hex: String) {
        let digits = hex.filter { !$0.isWhitespace }
        precondition(digits.count.isMultiple(of: 2), "odd-length hex")
        var bytes: [UInt8] = []
        var index = digits.startIndex
        while index < digits.endIndex {
            let next = digits.index(index, offsetBy: 2)
            bytes.append(UInt8(digits[index..<next], radix: 16)!)
            index = next
        }
        self = bytes
    }

    public var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
