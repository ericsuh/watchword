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
/// a warning. A bare domain is parsed the same way (`mapLikeAURL`), so a host normalises alike whichever kind of
/// identifier carries it.
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
        let trimmed = trimmedText(of: identifier)
        guard !trimmed.isEmpty else { throw HostNormalizationError.empty }

        switch identifier.kind {
        case .domain:
            try rejectASCIIPercentEscapes(in: trimmed)
            let shaped = try validate(host: trimmed)
            return try mapLikeAURL(domain: trimmed, shaped: shaped)
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

    /// Whether `identifier` names a web page loaded over plain `http`: a URL whose scheme is `http`, in any case. A
    /// domain identifier (an app's associated domain, a published identity) carries no scheme and is never one. Read
    /// with the same trimming and parsing as `normalize`, so the two cannot disagree about which URL this is.
    public static func isPlainHTTPPage(_ identifier: ServiceIdentifier) -> Bool {
        guard identifier.kind == .url, let components = URLComponents(string: trimmedText(of: identifier)) else {
            return false
        }
        return components.scheme?.lowercased() == "http"
    }

    private static func trimmedText(of identifier: ServiceIdentifier) -> String {
        String(
            identifier.identifier
                .drop(while: { asciiWhitespace.contains($0) })
                .reversed()
                .drop(while: { asciiWhitespace.contains($0) })
                .reversed())
    }

    /// A domain identifier normalises to exactly what the same host gives as a URL, `https://<domain>/`.
    ///
    /// Foundation's URL parsing maps a host as IDNA does (fullwidth letters and the ideographic full stop folded,
    /// compatibility characters decomposed, valid punycode decoded); a bare domain used to be lower-cased only. So
    /// one host had two normalised forms: `ＡMAZON.com` was `ａmazon.com` as a domain and `amazon.com` as a URL, and
    /// a scope saved from one never matched a request made with the other (and an import's bare-host scope came back
    /// as another host from an export of it). Parsing the domain the same way makes the two agree by construction,
    /// whatever a platform's Foundation maps.
    ///
    /// `shaped` has already passed every check on the raw domain, so the URL built here is a scheme and a host and
    /// nothing else; what Foundation reads back is checked again all the same. An IPv6 literal has no such URL form
    /// and keeps `shaped`. When Foundation finds no host, an all-ASCII domain keeps `shaped` too, unchanged from what
    /// it always normalised to (a label IDNA refuses, such as malformed punycode, must stay visible to
    /// `PhishingDetector`, and the URL form of it matches nothing); a non-ASCII one is refused, since how it would
    /// resolve is unknown.
    static func mapLikeAURL(domain: String, shaped: NormalizedHost) throws -> NormalizedHost {
        if shaped.value.contains(":") { return shaped }
        guard
            let components = URLComponents(string: "https://\(domain)/"),
            components.user == nil, components.password == nil, components.port == nil,
            components.path == "/", components.query == nil, components.fragment == nil,
            let host = components.host, !host.isEmpty
        else {
            if domain.unicodeScalars.allSatisfy(\.isASCII) { return shaped }
            throw HostNormalizationError.invalidHost(domain)
        }
        if let encoded = components.percentEncodedHost {
            try rejectASCIIPercentEscapes(in: encoded)
        }
        return try validate(host: host)
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
