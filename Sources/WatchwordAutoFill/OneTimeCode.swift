import Crypto
import Foundation
import WatchwordModel

public enum OneTimeCodeError: Error, Hashable, Sendable {
    /// The clock reads a time no counter can be computed from: before 1970, not finite, or absurdly far ahead.
    case timeOutOfRange
}

/// One time-based one-time password and how long it stays valid (PRD F6.3).
public struct OneTimeCode: Hashable, Sendable, CustomStringConvertible, CustomReflectable {
    /// The digits, left-padded with zeros to the configured length.
    public let code: String
    /// Seconds each code is valid for.
    public let period: Int
    /// Whole seconds until the next code, from 1 to `period`.
    public let secondsRemaining: Int
    /// The instant the next code starts.
    public let validUntil: Date

    public var description: String { "OneTimeCode(redacted)" }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

/// TOTP (RFC 6238) over the HOTP truncation of RFC 4226 §5.3, for the parameters `OTPParameters` has already bounded
/// (digits 6 to 8, period 15 to 300 seconds, a secret of at least 80 bits).
///
/// Pure: the time is an argument, so the callers inject a clock and tests use the RFC's own instants.
public enum TOTP {
    /// Far enough ahead that no real clock reads it, and small enough that every later computation fits in 64 bits.
    static let maximumTime: TimeInterval = 1e12

    public static func code(for parameters: OTPParameters, at date: Date) throws -> OneTimeCode {
        let time = date.timeIntervalSince1970
        guard time.isFinite, time >= 0, time <= maximumTime else { throw OneTimeCodeError.timeOutOfRange }
        let seconds = UInt64(time.rounded(.down))
        let period = UInt64(parameters.period)
        let counter = seconds / period
        let remaining = Int(period - seconds % period)

        var message = [UInt8](repeating: 0, count: 8)
        for index in 0..<8 {
            message[7 - index] = UInt8(truncatingIfNeeded: counter >> (8 * UInt64(index)))
        }
        let key = SymmetricKey(data: parameters.secret)
        let digest: [UInt8]
        switch parameters.algorithm {
        case .sha1: digest = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256: digest = Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512: digest = Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }

        // Dynamic truncation: the low nibble of the last byte picks four bytes, whose top bit is dropped.
        let offset = Int(digest[digest.count - 1] & 0x0F)
        let binary =
            (UInt32(digest[offset] & 0x7F) << 24) | (UInt32(digest[offset + 1]) << 16)
            | (UInt32(digest[offset + 2]) << 8) | UInt32(digest[offset + 3])
        var modulus: UInt32 = 1
        for _ in 0..<parameters.digits {
            modulus *= 10
        }
        let digits = String(binary % modulus)
        let code = String(repeating: "0", count: parameters.digits - digits.count) + digits
        return OneTimeCode(
            code: code, period: parameters.period, secondsRemaining: remaining,
            validUntil: Date(timeIntervalSince1970: TimeInterval(seconds) + TimeInterval(remaining)))
    }
}
