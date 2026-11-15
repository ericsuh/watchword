import Foundation

/// What a site is known to offer beyond a password.
public struct SiteCapabilities: OptionSet, Hashable, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// Two-step verification with an authenticator app (TOTP), which Watchword can hold.
    public static let oneTimeCodes = SiteCapabilities(rawValue: 1 << 0)
    /// Signing in with a passkey in place of the password.
    public static let passkeys = SiteCapabilities(rawValue: 1 << 1)
}

/// The seam for "is this site known to support two-step verification or passkeys?" (PRD F9.3, F11.8).
///
/// The answer is only ever advice in the report. It never feeds matching, AutoFill or any decision about a secret, so
/// a wrong or stale entry costs a misplaced suggestion and nothing else.
public protocol SiteDirectory: Sendable {
    /// What is known about `host` (a hostname, any case). Empty means unknown, not unsupported.
    func capabilities(ofHost host: String) -> SiteCapabilities
}

/// Knows nothing. The default: without a directory the report makes no claim about any site.
public struct NoSiteDirectory: SiteDirectory {
    public init() {}

    public func capabilities(ofHost host: String) -> SiteCapabilities {
        []
    }
}

/// A small, dated selection of well-known services from the 2factorauth directories (`SiteDirectoryData.swift` has
/// the source, the retrieval date and the licences).
///
/// Opt-in: a list like this ages, so the app decides whether to use it and says in the report where the claim comes
/// from. It is a few hundred rows, not the directory; adopting the full, regularly updated dataset is a supply-chain
/// decision of the same kind as the public suffix list (CLAUDE.md).
public struct EmbeddedSiteDirectory: SiteDirectory {
    static let table: [String: SiteCapabilities] = {
        var table: [String: SiteCapabilities] = [:]
        for line in rows.split(separator: "\n", omittingEmptySubsequences: true) {
            let parts = line.split(separator: " ")
            guard parts.count == 2 else { continue }
            var capabilities: SiteCapabilities = []
            if parts[1].contains("t") { capabilities.insert(.oneTimeCodes) }
            if parts[1].contains("p") { capabilities.insert(.passkeys) }
            table[String(parts[0])] = capabilities
        }
        return table
    }()

    public init() {}

    /// The entry for `host` itself or, failing that, for the nearest domain above it: `signin.aws.amazon.com` finds
    /// `aws.amazon.com` before `amazon.com`. Matching is by whole labels, so `notgithub.com` does not find
    /// `github.com`.
    public func capabilities(ofHost host: String) -> SiteCapabilities {
        var name = Substring(host.lowercased())
        while name.hasSuffix(".") { name = name.dropLast() }
        guard !name.isEmpty, name.utf8.count <= 253 else { return [] }
        while true {
            if let found = Self.table[String(name)] { return found }
            guard let dot = name.firstIndex(of: ".") else { return [] }
            name = name[name.index(after: dot)...]
        }
    }
}
