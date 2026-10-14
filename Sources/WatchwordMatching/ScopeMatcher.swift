import Foundation
import WatchwordModel

/// The result of matching one scope against a requested host.
public struct ScopeMatch: Sendable, Hashable {
    public let scope: ServiceScope
    /// Higher is more specific. Exact host: `2 × labels + 1`; subdomain match: `2 × labels`.
    public let specificity: Int
    public let isExact: Bool
}

public enum ScopeMatcher {
    /// Returns a match if `host` falls inside `scope`, honouring exclusions.
    ///
    /// Takes a `NormalizedHost` so that an un-normalised, attacker-influenced string cannot reach
    /// the comparison (PRD SEC6).
    public static func match(_ scope: ServiceScope, host: NormalizedHost) -> ScopeMatch? {
        let host = host.value
        guard !host.isEmpty, !scope.host.isEmpty else { return nil }

        if isExcluded(host, by: scope) { return nil }

        if host == scope.host {
            return ScopeMatch(scope: scope, specificity: 2 * scope.labelCount + 1, isExact: true)
        }
        if scope.includeSubdomains, host.hasSuffix("." + scope.host) {
            return ScopeMatch(scope: scope, specificity: 2 * scope.labelCount, isExact: false)
        }
        return nil
    }

    static func isExcluded(_ host: String, by scope: ServiceScope) -> Bool {
        for excluded in scope.excludedHosts where !excluded.isEmpty {
            if host == excluded || host.hasSuffix("." + excluded) {
                return true
            }
        }
        return false
    }
}
