import Foundation
import WatchwordModel

/// What the operating system hands a credential provider: either a bare domain or a full URL
/// (mirrors `ASCredentialServiceIdentifier.IdentifierType`, without importing AuthenticationServices
/// so this module stays platform-independent and testable with `swift test`).
public enum ServiceIdentifierKind: Sendable, Hashable {
    case domain
    case url
}

public struct ServiceIdentifier: Sendable, Hashable {
    public var identifier: String
    public var kind: ServiceIdentifierKind

    public init(_ identifier: String, kind: ServiceIdentifierKind) {
        self.identifier = identifier
        self.kind = kind
    }
}

public enum HostNormalizationError: Error, Hashable, Sendable {
    case empty
    case containsUserInfo
    case unsupportedScheme(String)
    case noHost
    case invalidHost(String)
    /// An ASCII character was percent-encoded. Decoding such an escape can invent structure that
    /// is not visible in the URL the person sees — `x.amazon%2Ecom` decodes to `x.amazon.com` and
    /// would otherwise match an `amazon.com` scope.
    case asciiPercentEscape(String)
    case hostTooLong(Int)
    case labelTooLong(String)
}

/// Turns a service identifier into a `NormalizedHost` for scope matching.
///
/// Fails closed: anything that is not unambiguously a hostname (user-info tricks such as
/// `https://amazon.com@evil.example/`, non-web schemes, ASCII percent-escapes, control characters,
/// over-long labels) is rejected rather than guessed at.
///
/// Note on internationalised hosts: Foundation applies IDNA-style compatibility mapping when it
/// parses a URL, so `ＡMAZON.com` (fullwidth) and `amazon\u{212A}.com` (Kelvin sign) arrive already
/// folded to `amazon.com`, matching what a browser resolves. Characters that IDNA keeps distinct,
/// such as Cyrillic `а`, stay distinct and therefore never match an ASCII scope. That is the safe
/// outcome for matching, but it is silent, so `PhishingDetector` exists to turn that silence into
/// a warning.
public enum HostNormalizer {
    private static let allowedSchemes: Set<String> = ["http", "https"]

    /// DNS limits, which also bound the work any matching pass can be made to do.
    static let maxHostLength = 253
    static let maxLabelLength = 63

    /// Characters that carry structure in an authority and must never appear inside a host.
    private static let structuralCharacters: Set<Character> = [
        "/", "\\", "@", ":", "%", "?", "#", "[", "]", "&", "=", "\"", "'", "<", ">", "{", "}", "|", "^", "`", ",", ";",
    ]

    /// Space, tab, CR, LF only. Foundation's `whitespacesAndNewlines` also strips U+200B, which
    /// would silently turn `amazon.com\u{200B}` into a match for `amazon.com`; trimming must
    /// never be able to invent a match, so the exotic characters are left in place for
    /// `isForbiddenScalar` to reject.
    private static let asciiWhitespace: Set<Character> = [" ", "\t", "\r", "\n"]

    public static func normalize(_ identifier: ServiceIdentifier) throws -> NormalizedHost {
        let trimmed = String(
            identifier.identifier
                .drop(while: { asciiWhitespace.contains($0) })
                .reversed()
                .drop(while: { asciiWhitespace.contains($0) })
                .reversed())
        guard !trimmed.isEmpty else { throw HostNormalizationError.empty }

        switch identifier.kind {
        case .domain:
            try rejectASCIIPercentEscapes(in: trimmed)
            return try validate(host: trimmed)
        case .url:
            guard let components = URLComponents(string: trimmed) else {
                throw HostNormalizationError.invalidHost(trimmed)
            }
            if components.user != nil || components.password != nil {
                throw HostNormalizationError.containsUserInfo
            }
            guard let scheme = components.scheme?.lowercased(), allowedSchemes.contains(scheme) else {
                throw HostNormalizationError.unsupportedScheme(components.scheme ?? "")
            }
            // Check the still-encoded form: `host` has already been percent-decoded, so by the
            // time we see it an `%2E` is indistinguishable from a dot the person actually typed.
            if let encoded = components.percentEncodedHost {
                try rejectASCIIPercentEscapes(in: encoded)
            }
            guard let host = components.host, !host.isEmpty else {
                throw HostNormalizationError.noHost
            }
            return try validate(host: host)
        }
    }

    /// Permits percent-escapes only for non-ASCII bytes, which is how Foundation represents an
    /// IDN host (`%D0%B0mazon.com`). Any escape in the ASCII range is rejected.
    static func rejectASCIIPercentEscapes(in raw: String) throws {
        let characters = Array(raw)
        var index = 0
        while index < characters.count {
            guard characters[index] == "%" else {
                index += 1
                continue
            }
            guard index + 2 < characters.count,
                let high = characters[index + 1].hexDigitValue,
                let low = characters[index + 2].hexDigitValue
            else {
                throw HostNormalizationError.invalidHost(raw)
            }
            guard high * 16 + low >= 0x80 else {
                throw HostNormalizationError.asciiPercentEscape(raw)
            }
            index += 3
        }
    }

    /// Lower-cases, strips trailing dots, and rejects anything that is not shaped like a host.
    static func validate(host raw: String) throws -> NormalizedHost {
        let host = ServiceScope.canonicalHost(raw)
        guard !host.isEmpty else { throw HostNormalizationError.noHost }

        // IPv6 literals may arrive bracketed (`[::1]`) or bare (`::1`) depending on the parser.
        var candidate = host
        if candidate.hasPrefix("["), candidate.hasSuffix("]") {
            candidate = String(candidate.dropFirst().dropLast())
        }
        if candidate.contains(":") {
            let hexOrSeparator = candidate.allSatisfy { $0.isHexDigit || $0 == ":" || $0 == "." }
            let colonCount = candidate.filter { $0 == ":" }.count
            guard hexOrSeparator, colonCount >= 2 else { throw HostNormalizationError.invalidHost(raw) }
            return NormalizedHost(vouchedFor: candidate)
        }

        guard candidate.utf8.count <= maxHostLength else {
            throw HostNormalizationError.hostTooLong(candidate.utf8.count)
        }
        guard !candidate.contains(where: { structuralCharacters.contains($0) }) else {
            throw HostNormalizationError.invalidHost(raw)
        }
        guard !candidate.unicodeScalars.contains(where: isForbiddenScalar) else {
            throw HostNormalizationError.invalidHost(raw)
        }

        let labels = candidate.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.allSatisfy({ !$0.isEmpty }) else {
            throw HostNormalizationError.invalidHost(raw)
        }
        if let overlong = labels.first(where: { $0.utf8.count > maxLabelLength }) {
            throw HostNormalizationError.labelTooLong(String(overlong))
        }
        return NormalizedHost(vouchedFor: candidate)
    }

    /// C0/C1 controls, DEL, whitespace, and the zero-width and bidi formatting characters that
    /// let a host render as something other than what it is.
    private static func isForbiddenScalar(_ scalar: Unicode.Scalar) -> Bool {
        if scalar.value <= 0x1F || scalar.value == 0x7F { return true }
        if scalar.value >= 0x80 && scalar.value <= 0x9F { return true }
        if Character(scalar).isWhitespace { return true }
        switch scalar.value {
        // Zero-width space / non-joiner / joiner, word joiner, BOM.
        case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF:
            return true
        // Bidi overrides and isolates.
        case 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069:
            return true
        // Soft hyphen.
        case 0x00AD:
            return true
        default:
            return false
        }
    }
}
