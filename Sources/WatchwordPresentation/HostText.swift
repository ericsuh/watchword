import Foundation
import WatchwordKit
import WatchwordMatching
import WatchwordModel

/// Hosts as a person should read them before trusting one (PRD F11.2; docs/05-anti-phishing.md): the ASCII form, in
/// which a Cyrillic `а` cannot pass for a Latin `a`, and the registrable domain, the part that says whose site it is.
public enum HostText {
    /// `host` with every label outside ASCII in its punycode form (RFC 3492, `xn--`), so that what is shown is what
    /// resolves. Lower-cased, as scopes are.
    public static func ascii(_ host: String) -> String {
        ServiceScope.canonicalHost(host).split(separator: ".", omittingEmptySubsequences: false).map { label in
            label.allSatisfy(\.isASCII) ? String(label) : "xn--" + punycode(String(label))
        }
        .joined(separator: ".")
    }

    /// The registrable domain of `host` (an ASCII host): the public suffix and the label to its left
    /// (`citylibrary.org` in `www.citylibrary.org`, `acme.github.io`), by the embedded suffix list. The whole host if
    /// it has fewer labels.
    public static func registrableDomain(of host: String) -> String {
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count > 2 else { return host }
        for suffixLength in stride(from: min(3, labels.count - 1), through: 2, by: -1)
        where PublicSuffix.isPublicSuffix(labels.suffix(suffixLength).joined(separator: ".")) {
            return labels.suffix(suffixLength + 1).joined(separator: ".")
        }
        return labels.suffix(2).joined(separator: ".")
    }

    /// How far a scope reaches, in words: "and its subdomains", "this address only", and the exclusions in ASCII.
    public static func reach(of scope: ServiceScope) -> String {
        guard scope.includeSubdomains else { return "this address only" }
        guard !scope.excludedHosts.isEmpty else { return "and its subdomains" }
        return "and its subdomains, except " + scope.excludedHosts.map(ascii).sorted().joined(separator: ", ")
    }

    /// RFC 3492 §6.3, for one label. Scopes are bounded (`HostNormalizer` limits labels to 63 bytes), so no overflow
    /// check beyond the RFC's is needed; one that fails falls back to the label's scalars in hexadecimal, which is
    /// still ASCII and still not the look-alike.
    static func punycode(_ label: String) -> String {
        let base = 36
        let tMin = 1
        let tMax = 26
        let skew = 38
        let damp = 700
        let input = label.unicodeScalars.map { Int($0.value) }
        var output = input.filter { $0 < 0x80 }.map { Character(Unicode.Scalar(UInt8($0))) }
        let basic = output.count
        var handled = basic
        if basic > 0 { output.append("-") }
        func digit(_ value: Int) -> Character {
            Character(Unicode.Scalar(UInt8(value < 26 ? value + 97 : value + 22)))
        }
        func adapt(_ delta: Int, _ count: Int, _ first: Bool) -> Int {
            var delta = first ? delta / damp : delta / 2
            delta += delta / count
            var k = 0
            while delta > ((base - tMin) * tMax) / 2 {
                delta /= base - tMin
                k += base
            }
            return k + (base - tMin + 1) * delta / (delta + skew)
        }
        var n = 0x80
        var delta = 0
        var bias = 72
        while handled < input.count {
            guard let m = input.filter({ $0 >= n }).min() else { break }
            let (product, overflow) = (m - n).multipliedReportingOverflow(by: handled + 1)
            guard !overflow else { return input.map { String($0, radix: 16) }.joined(separator: "-") }
            delta += product
            n = m
            for scalar in input {
                if scalar < n { delta += 1 }
                if scalar == n {
                    var q = delta
                    var k = base
                    while true {
                        let t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias)
                        if q < t { break }
                        output.append(digit(t + (q - t) % (base - t)))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    output.append(digit(q))
                    bias = adapt(delta, handled + 1, handled == basic)
                    delta = 0
                    handled += 1
                }
            }
            delta += 1
            n += 1
        }
        return String(output)
    }
}

/// A host about to become a scope of an item, as a screen shows it before the person accepts it: ASCII, the
/// registrable domain picked out, how far the scope reaches, and a warning when it resembles a site already saved
/// without being it, which then needs a second confirmation. Used wherever a host enters an item by the person's
/// hand or from a file: the import's merge and its new entries, and the item editor (PRD F11.7).
///
/// The resemblance is judged against `SavedSites`, the gate's own view of what is saved (review finding Z65): not
/// the trash, not a scope the policy refuses, and a scope in a shared vault recognises a host for that vault only.
public struct MergeHost: Hashable, Sendable, Identifiable {
    /// The host as the scope stores it: the key `MergeChoices.hosts` takes.
    public let host: String
    public let ascii: String
    /// `ascii` split for display: what is left of the registrable domain (with its dot), and the domain.
    public let prefix: String
    public let registrable: String
    public let includesSubdomains: Bool
    public let excludedHosts: [String]
    /// Why this host may not be what it looks like; `nil` when nothing saved resembles it.
    public let warning: String?
    /// The saved hosts it resembles, sorted; empty when the warning is about the address itself.
    public let resembles: [String]
    public var id: String { host }

    public var needsConfirmation: Bool { warning != nil }

    /// "and its subdomains", "this address only", and the exclusions.
    public var reach: String {
        HostText.reach(
            of: ServiceScope(host: host, includeSubdomains: includesSubdomains, excludedHosts: Set(excludedHosts)))
    }

    /// - Parameters:
    ///   - sites: What is saved, as the session gives it (`VaultSession.savedSites()`), prepared.
    ///   - otherScopes: The scopes the item would hold beside this one.
    ///   - inSharedVault: Whether the item is in a vault other accounts write.
    public init(
        _ scope: ServiceScope, among sites: SavedSites.Prepared, beside otherScopes: [ServiceScope] = [],
        inSharedVault: Bool = false
    ) {
        let (warning, resembles) = Self.warning(
            for: scope.host, ascii: HostText.ascii(scope.host), among: sites, beside: otherScopes,
            inSharedVault: inSharedVault)
        self.init(scope, warning: warning, resembles: resembles)
    }

    /// Against items that are all the person's own, as stored: for tests and previews.
    public init(_ scope: ServiceScope, against saved: [Item]) {
        self.init(
            scope, among: SavedSites(stored: saved, ownVaults: Set(saved.map(\.vaultID))).prepared())
    }

    /// A host the session has already judged (an import preview's `ImportConcern.lookAlikeHosts`): shown in ASCII,
    /// with the warning when the session reported one and none otherwise.
    public init(_ scope: ServiceScope, judged confirmation: HostConfirmation?) {
        self.init(
            scope, warning: confirmation.map { Self.wording(resembling: $0.resembles.sorted()) },
            resembles: confirmation?.resembles.sorted() ?? [])
    }

    /// A host the session reported as needing confirmation (`VaultError.hostsNeedConfirmation`), for the editor's
    /// dialog: shown in ASCII with the same words.
    public init(_ scope: ServiceScope, resembling names: [String]) {
        self.init(scope, warning: Self.wording(resembling: names.sorted()), resembles: names.sorted())
    }

    private init(_ scope: ServiceScope, warning: String?, resembles: [String]) {
        host = scope.host
        ascii = HostText.ascii(scope.host)
        registrable = HostText.registrableDomain(of: ascii)
        prefix = ascii.count > registrable.count ? String(ascii.dropLast(registrable.count)) : ""
        includesSubdomains = scope.includeSubdomains
        excludedHosts = scope.excludedHosts.map(HostText.ascii).sorted()
        self.resembles = resembles
        self.warning = warning
    }

    static let unreadable = "This address could not be checked. Do not accept it unless you are sure whose site it is."

    static func wording(resembling names: [String]) -> String {
        if !names.isEmpty {
            return "This looks like " + names.joined(separator: ", ")
                + " but is a different address. Accepting it would offer this item's password there."
        }
        return "This address uses characters from other alphabets, so what you see may not be where it goes."
    }

    static func warning(
        for host: String, ascii: String, among sites: SavedSites.Prepared, beside otherScopes: [ServiceScope],
        inSharedVault: Bool
    ) -> (String?, [String]) {
        guard (try? HostNormalizer.normalize(ServiceIdentifier(host, kind: .domain))) != nil else {
            return (unreadable, [])
        }
        // Both spellings: Foundation may or may not have decoded a punycode label, and either can be the one a
        // saved scope resembles.
        var names: Set<String> = []
        var suspicious = false
        for spelling in ascii == host ? [host] : [host, ascii] {
            if case .needsConfirmation(let resembles) = sites.standing(
                ofNewHost: spelling, beside: otherScopes, inSharedVault: inSharedVault)
            {
                suspicious = true
                names.formUnion(resembles)
            }
        }
        guard suspicious else { return (nil, []) }
        let sorted = names.sorted()
        return (wording(resembling: sorted), sorted)
    }
}
