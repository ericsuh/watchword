import Foundation
import WatchwordModel

/// Why a host looks like an impersonation of something the person has saved.
public enum PhishingSignal: Hashable, Sendable {
    /// The host collapses to the same visual skeleton as a saved scope (`arnazon.com`,
    /// `amaz0n.com`, `аmazon.com` with a Cyrillic first letter).
    case confusableWithSavedScope(String)
    /// The host mixes characters from more than one script, which no legitimate registrable
    /// domain needs to do and which is the substrate for homograph attacks.
    case mixedScript
    /// The host is punycode-encoded, so what renders is not what resolves.
    case punycode(String)
    /// A saved scope is within a small edit distance of this host (`amazom.com`).
    case nearMiss(savedScope: String, distance: Int)
    /// A saved scope's distinctive label appears in the host, but not in the registrable
    /// position: `amazon.com.evil.example`, `secure-amazon.example`, `amazon-login.example`.
    case savedNameOutOfPosition(savedScope: String, label: String)
}

public enum PhishingAssessment: Hashable, Sendable {
    /// The host matches a saved scope. Normal AutoFill applies.
    case recognized
    /// Nothing saved resembles this host. Offer nothing, say nothing alarming.
    case unrecognized
    /// The host resembles something saved but is not it. The UI must warn before revealing,
    /// copying, or filling any secret (PRD F11.3).
    case suspicious(signals: Set<PhishingSignal>, impersonating: [String])

    public var isSuspicious: Bool {
        if case .suspicious = self { return true }
        return false
    }

    /// `true` when the host resembles a specific saved site, so the warning can name it. A
    /// suspicious host without a named target (punycode, mixed script) warrants a weaker
    /// "cannot verify this address" message instead.
    public var impersonatesSavedSite: Bool {
        if case .suspicious(_, let impersonating) = self { return !impersonating.isEmpty }
        return false
    }
}

/// Detects look-alike hosts so the app can warn instead of staying silent.
///
/// Scope matching already guarantees the app never *fills* a credential on a host an item is not
/// scoped to. The residual risk is the person: on `аmazon.com` the app finds no match, shows
/// nothing, and the person reaches for the clipboard or types the password by hand. This type
/// turns that silence into an explicit "this looks like Amazon but is not the Amazon you saved".
///
/// Pure, offline, and deterministic: no network, no telemetry, no list to fetch.
public enum PhishingDetector {
    /// Single-character visual confusables, mapped to an ASCII representative.
    ///
    /// Foundation's URL parsing already folds the IDNA compatibility cases (fullwidth Latin, the
    /// Kelvin sign) to ASCII, so this table covers what IDNA deliberately keeps distinct:
    /// Cyrillic and Greek look-alikes, plus the leetspeak digit substitutions phishing kits use.
    static let confusables: [Character: Character] = [
        // Cyrillic.
        "а": "a", "в": "b", "с": "c", "е": "e", "н": "h", "к": "k", "м": "m", "о": "o",
        "р": "p", "ѕ": "s", "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ԁ": "d",
        "ɡ": "g", "ß": "b", "ԛ": "q", "ա": "w", "ո": "n",
        // Greek.
        "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p",
        "σ": "o", "τ": "t", "υ": "u", "χ": "x", "γ": "y", "η": "n",
        // Digits used as letters.
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "b", "7": "t", "8": "b", "9": "g",
    ]

    /// Multi-character confusables, applied after the single-character pass. Deliberately only
    /// the two highest-value pairs: each extra entry widens the chance that two unrelated hosts
    /// collapse to the same skeleton, which spends the warning's credibility.
    static let digraphs: [(String, String)] = [("rn", "m"), ("vv", "w")]

    /// Collapses a host to a comparable visual skeleton.
    static func skeleton(_ host: String) -> String {
        let folded =
            host
            .lowercased()
            .folding(options: [.diacriticInsensitive, .widthInsensitive, .caseInsensitive], locale: nil)
        var mapped = String(folded.map { confusables[$0] ?? $0 })
        for (from, to) in digraphs {
            mapped = mapped.replacingOccurrences(of: from, with: to)
        }
        return mapped
    }

    /// The label a person would recognise as the name of the site: the label immediately to the
    /// left of the public suffix (`amazon` in `amazon.co.uk`).
    static func distinctiveLabel(of host: String) -> String? {
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return labels.first }
        // Walk in from the right past the public suffix.
        for suffixLength in stride(from: min(3, labels.count - 1), through: 1, by: -1) {
            let suffix = labels.suffix(suffixLength).joined(separator: ".")
            if PublicSuffix.isPublicSuffix(suffix) {
                let remainder = labels.dropLast(suffixLength)
                return remainder.last
            }
        }
        return labels.dropLast().last
    }

    public static func assess(host: NormalizedHost, against scopes: [ServiceScope]) -> PhishingAssessment {
        // A real match is never phishing, whatever it looks like.
        for scope in scopes where ScopeMatcher.match(scope, host: host) != nil {
            return .recognized
        }

        var signals = Set<PhishingSignal>()
        var impersonating = Set<String>()

        let hostValue = host.value
        let hostSkeleton = skeleton(hostValue)
        let hostLabels = Set(host.labels.flatMap { $0.split(separator: "-").map(String.init) })

        if !host.isASCII && isMixedScript(hostValue) {
            signals.insert(.mixedScript)
        }
        if let punycodeLabel = host.labels.first(where: { $0.hasPrefix("xn--") }) {
            signals.insert(.punycode(punycodeLabel))
        }

        for scope in scopes {
            let scopeHost = scope.host
            guard !scopeHost.isEmpty else { continue }
            let scopeSkeleton = skeleton(scopeHost)

            if hostSkeleton == scopeSkeleton {
                signals.insert(.confusableWithSavedScope(scopeHost))
                impersonating.insert(scopeHost)
                continue
            }

            let hostName = distinctiveLabel(of: hostSkeleton)
            let scopeName = distinctiveLabel(of: scopeSkeleton)

            // The same name under a different public suffix (`amazon.de` against a saved
            // `amazon.com`) is a plausible regional site, not an impersonation. Nothing below
            // applies in that case.
            if let hostName, let scopeName, hostName == scopeName {
                continue
            }

            // A near-miss on the recognisable name: `amazom.com`, `firstbamk.co.uk`.
            if let hostName, let scopeName, scopeName.count >= 5, hostName.count >= 5 {
                let distance = editDistance(hostName, scopeName, limit: 2)
                if distance > 0 && distance <= 2 {
                    signals.insert(.nearMiss(savedScope: scopeHost, distance: distance))
                    impersonating.insert(scopeHost)
                }
            }

            // The saved site's name appears in a label where it carries no authority:
            // `amazon.com.evil.example`, `secure-amazon.example`.
            let plainScopeName = distinctiveLabel(of: scopeHost)
            if let plainScopeName, plainScopeName.count >= 4, hostLabels.contains(plainScopeName) {
                signals.insert(.savedNameOutOfPosition(savedScope: scopeHost, label: plainScopeName))
                impersonating.insert(scopeHost)
            }
        }

        // Any signal is worth surfacing. A punycode or mixed-script host with no resemblance to
        // anything saved still cannot be visually verified by the person, so it is reported —
        // with an empty `impersonating` list, which lets the UI phrase a weaker warning.
        guard signals.isEmpty else {
            return .suspicious(signals: signals, impersonating: impersonating.sorted())
        }
        return .unrecognized
    }

    public static func assess(host: NormalizedHost, againstItemsIn items: [Item]) -> PhishingAssessment {
        assess(host: host, against: items.flatMap(\.scopes))
    }

    /// `true` when any single label draws letters from more than one writing system.
    ///
    /// The test is per-label, as in UTS #39. Checking the whole host would flag every real
    /// internationalised domain, because the top-level label is Latin even when the name is not
    /// (`\u{0430}\u{043C}\u{0430}\u{0437}\u{043E}\u{043D}.com`). A label that mixes Cyrillic and
    /// Latin, however, is the homograph attack itself.
    static func isMixedScript(_ host: String) -> Bool {
        for label in host.split(separator: ".") {
            var scripts = Set<Script>()
            for scalar in label.unicodeScalars {
                if let script = Script(scalar), script != .common {
                    scripts.insert(script)
                }
            }
            if scripts.count > 1 { return true }
        }
        return false
    }

    enum Script: Hashable {
        case common
        case latin
        case greek
        case cyrillic
        case armenian
        case hebrew
        case arabic
        case han
        case kana
        case hangul
        case other

        init?(_ scalar: Unicode.Scalar) {
            let value = scalar.value
            switch value {
            case 0x30...0x39, 0x2D, 0x2E, 0x5F:
                self = .common
            case 0x41...0x5A, 0x61...0x7A, 0x00C0...0x024F, 0x1E00...0x1EFF:
                self = .latin
            case 0x0370...0x03FF, 0x1F00...0x1FFF:
                self = .greek
            case 0x0400...0x052F, 0x2DE0...0x2DFF, 0xA640...0xA69F:
                self = .cyrillic
            case 0x0530...0x058F:
                self = .armenian
            case 0x0590...0x05FF:
                self = .hebrew
            case 0x0600...0x06FF, 0x0750...0x077F:
                self = .arabic
            case 0x3400...0x4DBF, 0x4E00...0x9FFF, 0xF900...0xFAFF:
                self = .han
            case 0x3040...0x30FF, 0x31F0...0x31FF:
                self = .kana
            case 0x1100...0x11FF, 0xAC00...0xD7AF:
                self = .hangul
            default:
                self = .other
            }
        }
    }

    /// Levenshtein distance, abandoned once it exceeds `limit` (returns `limit + 1`).
    static func editDistance(_ lhs: String, _ rhs: String, limit: Int) -> Int {
        let a = Array(lhs)
        let b = Array(rhs)
        if abs(a.count - b.count) > limit { return limit + 1 }
        if a.isEmpty { return b.count }
        if b.isEmpty { return a.count }

        var previous = Array(0...b.count)
        var current = [Int](repeating: 0, count: b.count + 1)
        for i in 1...a.count {
            current[0] = i
            var rowMinimum = current[0]
            for j in 1...b.count {
                let substitution = previous[j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1)
                current[j] = min(previous[j] + 1, current[j - 1] + 1, substitution)
                rowMinimum = min(rowMinimum, current[j])
            }
            if rowMinimum > limit { return limit + 1 }
            swap(&previous, &current)
        }
        return previous[b.count]
    }
}
