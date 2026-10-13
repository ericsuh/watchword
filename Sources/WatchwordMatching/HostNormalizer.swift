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

public enum HostNormalizationError: Error, Equatable, Sendable {
    case empty
    case containsUserInfo
    case unsupportedScheme(String)
    case noHost
    case invalidHost(String)
}

/// Turns a service identifier into a canonical host string for scope matching.
///
/// Fails closed: anything that is not clearly a hostname (user-info tricks such as
/// `https://amazon.com@evil.example/`, non-web schemes, percent-encoding, embedded whitespace)
/// is rejected rather than guessed at.
public enum HostNormalizer {
    private static let allowedSchemes: Set<String> = ["http", "https"]

    public static func normalize(_ identifier: ServiceIdentifier) throws -> String {
        let trimmed = identifier.identifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw HostNormalizationError.empty }

        switch identifier.kind {
        case .domain:
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
            guard let host = components.host, !host.isEmpty else {
                throw HostNormalizationError.noHost
            }
            return try validate(host: host)
        }
    }

    /// Lower-cases, strips trailing dots, and rejects hosts containing characters that cannot
    /// appear in a hostname. Non-ASCII hosts are accepted as-is (lower-cased); IDNA mapping is a
    /// follow-up, and until then exact comparison guarantees that a homograph never matches an
    /// ASCII scope.
    static func validate(host raw: String) throws -> String {
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
            return candidate
        }

        let forbidden: Set<Character> = ["/", "\\", "@", ":", "%", "?", "#", "[", "]", " ", "\t", "\n", "\r"]
        guard !candidate.contains(where: { forbidden.contains($0) }) else {
            throw HostNormalizationError.invalidHost(raw)
        }
        guard !candidate.contains(where: { $0.isWhitespace || $0.isNewline }) else {
            throw HostNormalizationError.invalidHost(raw)
        }
        let labels = candidate.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.allSatisfy({ !$0.isEmpty }) else {
            throw HostNormalizationError.invalidHost(raw)
        }
        return candidate
    }
}
