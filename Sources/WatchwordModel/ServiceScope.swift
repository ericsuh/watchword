import Foundation

/// A hostname (or hostname pattern) that an item applies to.
///
/// Scopes are the unit of AutoFill matching. An item may carry several scopes; the most specific
/// matching scope decides the item's rank (see `docs/02-architecture.md` §9).
public struct ServiceScope: Hashable, Codable, Sendable {
    /// Lower-cased host without scheme, port, path, or trailing dot (e.g. `signin.aws.amazon.com`).
    public var host: String
    /// When `true`, hosts that end in `"." + host` also match.
    public var includeSubdomains: Bool
    /// Hosts that must never match this scope even if they are subdomains of `host`.
    public var excludedHosts: Set<String>

    public init(host: String, includeSubdomains: Bool = true, excludedHosts: Set<String> = []) {
        self.host = ServiceScope.canonicalHost(host)
        self.includeSubdomains = includeSubdomains
        self.excludedHosts = Set(excludedHosts.map(ServiceScope.canonicalHost))
    }

    /// Lower-cases and strips a single trailing dot. Does not perform IDNA; see `HostNormalizer`.
    public static func canonicalHost(_ raw: String) -> String {
        var value = raw.lowercased()
        while value.hasSuffix(".") {
            value.removeLast()
        }
        return value
    }

    /// Number of DNS labels in `host` (`a.b.c` → 3).
    public var labelCount: Int {
        host.isEmpty ? 0 : host.split(separator: ".", omittingEmptySubsequences: false).count
    }
}
