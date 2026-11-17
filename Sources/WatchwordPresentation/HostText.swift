import Foundation
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

/// A host a merge would add to an existing item, as the duplicate screen shows it before the person accepts it:
/// ASCII, the registrable domain picked out, how far the scope reaches, and a warning when it resembles a site already
/// saved without being it (`PhishingDetector`), which then needs a second confirmation.
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
    public var id: String { host }

    public var needsConfirmation: Bool { warning != nil }

    /// "and its subdomains", "this address only", and the exclusions.
    public var reach: String {
        guard includesSubdomains else { return "this address only" }
        guard !excludedHosts.isEmpty else { return "and its subdomains" }
        return "and its subdomains, except " + excludedHosts.joined(separator: ", ")
    }

    public init(_ scope: ServiceScope, against saved: [Item]) {
        host = scope.host
        ascii = HostText.ascii(scope.host)
        registrable = HostText.registrableDomain(of: ascii)
        prefix = ascii.count > registrable.count ? String(ascii.dropLast(registrable.count)) : ""
        includesSubdomains = scope.includeSubdomains
        excludedHosts = scope.excludedHosts.map(HostText.ascii).sorted()
        warning = Self.warning(for: scope.host, ascii: ascii, against: saved)
    }

    static func warning(for host: String, ascii: String, against saved: [Item]) -> String? {
        guard let normalized = try? HostNormalizer.normalize(ServiceIdentifier(host, kind: .domain)) else {
            return "This address could not be checked. Do not accept it unless you are sure whose site it is."
        }
        let assessments =
            [PhishingDetector.assess(host: normalized, againstItemsIn: saved)]
            + (ascii != host
                ? [
                    (try? HostNormalizer.normalize(ServiceIdentifier(ascii, kind: .domain))).map {
                        PhishingDetector.assess(host: $0, againstItemsIn: saved)
                    } ?? .unrecognized
                ] : [])
        var names: Set<String> = []
        var suspicious = false
        for case .suspicious(_, let impersonating) in assessments {
            suspicious = true
            names.formUnion(impersonating)
        }
        if !host.allSatisfy(\.isASCII) || ascii.split(separator: ".").contains(where: { $0.hasPrefix("xn--") }) {
            suspicious = true
        }
        guard suspicious else { return nil }
        if !names.isEmpty {
            return "This looks like " + names.sorted().joined(separator: ", ")
                + " but is a different address. Accepting it would offer this item's password there."
        }
        return "This address uses characters from other alphabets, so what you see may not be where it goes."
    }
}
