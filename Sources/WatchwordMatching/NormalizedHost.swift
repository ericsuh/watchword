import Foundation

/// A host that has been through `HostNormalizer` and is safe to match against stored scopes.
///
/// Matching and ranking accept only this type, so a caller cannot accidentally match against a
/// raw, attacker-influenced string (PRD SEC6). The initializer is deliberately not public:
/// production code obtains values through `HostNormalizer.normalize(_:)`, which fails closed on
/// anything that is not unambiguously a hostname.
public struct NormalizedHost: Hashable, Sendable, CustomStringConvertible {
    /// Lower-cased, percent-decoded, trailing-dot-stripped host.
    public let value: String

    /// Only `HostNormalizer` (and tests, via `@testable`) may vouch for a string.
    init(vouchedFor value: String) {
        self.value = value
    }

    public var description: String { value }

    /// DNS labels, outermost last (`a.b.com` → `["a", "b", "com"]`).
    public var labels: [String] {
        value.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
    }

    public var labelCount: Int { value.isEmpty ? 0 : labels.count }

    /// `true` when every scalar is ASCII. Non-ASCII hosts are legitimate (IDN) but are the
    /// substrate for homograph attacks, so the phishing detector treats them with suspicion.
    public var isASCII: Bool { value.allSatisfy(\.isASCII) }
}
