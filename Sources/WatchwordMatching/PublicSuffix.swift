import Foundation
import WatchwordModel

/// Guards against scopes so broad that they would offer a credential on an unrelated site.
///
/// A scope of `com` with subdomains enabled matches every `.com` host; a scope of `co.uk` matches
/// every British site. On a host where the person has no specific entry, such a scope becomes the
/// top-ranked match and the app would offer a real credential on an attacker's page. Scope
/// creation therefore refuses these outright (PRD F11.2).
///
/// This is a deliberately small, embedded list, not the full Public Suffix List. It covers the
/// suffixes a person is realistically able to type by accident plus the common "anyone can host
/// here" domains. Adopting the full PSL means taking on a ~14,000-entry third-party data file and
/// a refresh process, which is a supply-chain decision of its own: see
/// `docs/07-supply-chain.md` and the open question in `docs/02-architecture.md`.
public enum PublicSuffix {
    /// Country-code second-level domains: suffixes in the ICANN section of the Public Suffix List, which every
    /// operating system and browser agrees are not sites.
    static let countryCodeSecondLevel: Set<String> = [
        "co.uk", "org.uk", "me.uk", "gov.uk", "ac.uk", "net.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "lg.jp",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
        "co.za", "org.za", "web.za", "gov.za",
        "com.br", "net.br", "org.br", "gov.br",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "co.in", "net.in", "org.in", "gov.in", "ac.in",
        "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw", "com.my", "com.ph",
        "co.kr", "or.kr", "go.kr",
        "co.il", "org.il", "gov.il",
        "com.es", "com.pl", "com.ua", "com.ru", "com.pt", "com.co", "com.pe", "com.ve",
    ]

    /// Shared hosting and app platforms: distinct tenants, so one tenant must never be treated as a subdomain of
    /// another. These are a private party's suffixes; another party's list may or may not carry each of them.
    static let sharedHosting: Set<String> = [
        "github.io", "gitlab.io", "pages.dev", "workers.dev", "netlify.app", "vercel.app",
        "herokuapp.com", "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com",
        "firebaseapp.com", "web.app", "appspot.com", "run.app", "glitch.me", "repl.co",
        "blogspot.com", "wordpress.com", "tumblr.com", "myshopify.com", "squarespace.com",
        "wixsite.com", "weebly.com", "notion.site", "substack.com", "bandcamp.com",
        "sharepoint.com", "zendesk.com", "freshdesk.com", "atlassian.net", "myjetbrains.com",
        "duckdns.org", "ddns.net", "no-ip.org", "dynu.net", "serveo.net", "ngrok.io", "ngrok.app",
        "trycloudflare.com", "localhost.run", "loca.lt",
    ]

    /// Multi-label suffixes under which registrations are public.
    static let multiLabel: Set<String> = countryCodeSecondLevel.union(sharedHosting)

    /// Hosts that are a public suffix in their own right, i.e. nothing may be registered at this
    /// exact name, so a scope for it can only be over-broad.
    static let singleLabelException: Set<String> = ["localhost"]

    /// `true` when `host` is itself a public suffix (`com`, `co.uk`, `github.io`).
    public static func isPublicSuffix(_ host: String) -> Bool {
        let host = ServiceScope.canonicalHost(host)
        guard !host.isEmpty else { return false }
        if multiLabel.contains(host) { return true }
        // Any single-label host is either a TLD (`com`) or a non-routable name (`localhost`).
        return host.split(separator: ".").count == 1
    }

    /// The shortest name that anyone's rules could take to be the site `host` belongs to, or `nil` when the host
    /// cannot belong to one (a single label, an IP address).
    ///
    /// For when a decision is made by a party whose public-suffix list is not ours, such as the operating system
    /// choosing the pages on which to offer a published credential identity (docs/02-architecture.md §9.2): the
    /// answer must be at least as wide as theirs, so it errs wide. It is the last two labels, or the last three under
    /// a country-code second-level domain. The shared-hosting suffixes are deliberately *not* honoured here: whether
    /// another party treats `zendesk.com` as a suffix is unknown, so `acme.zendesk.com` is taken to share a site
    /// with every other tenant. A country-code suffix missing from the list errs the same way.
    public static func broadestSite(of host: NormalizedHost) -> String? {
        let labels = host.labels
        guard labels.count >= 2, labels.allSatisfy({ !$0.isEmpty }), !host.value.contains(":"),
            let last = labels.last, !last.allSatisfy(\.isNumber)
        else { return nil }
        let lastTwo = labels.suffix(2).joined(separator: ".")
        guard countryCodeSecondLevel.contains(lastTwo) else { return lastTwo }
        guard labels.count >= 3 else { return nil }
        return labels.suffix(3).joined(separator: ".")
    }
}

public enum ScopeValidationError: Error, Equatable, Sendable {
    case empty
    /// The host is a public suffix, so a scope for it spans unrelated owners.
    case publicSuffix(String)
    /// A single-label host cannot identify a site.
    case singleLabel(String)
    /// `includeSubdomains` on a host that is one label below a public suffix is fine
    /// (`amazon.com`), but the scope host itself must not be the suffix.
    case notAHostname(String)
}

/// Validates a scope at the moment it is created or edited, which is the only place a
/// dangerously broad scope can enter the system.
public enum ScopePolicy {
    /// Throws when `scope` would match hosts belonging to unrelated owners.
    public static func validate(_ scope: ServiceScope) throws {
        let host = scope.host
        guard !host.isEmpty else { throw ScopeValidationError.empty }

        // A scope must look like a hostname before any suffix reasoning applies.
        guard (try? HostNormalizer.validate(host: host)) != nil else {
            throw ScopeValidationError.notAHostname(host)
        }

        if PublicSuffix.singleLabelException.contains(host) {
            throw ScopeValidationError.publicSuffix(host)
        }
        if host.split(separator: ".").count == 1 {
            throw ScopeValidationError.singleLabel(host)
        }
        if PublicSuffix.isPublicSuffix(host) {
            throw ScopeValidationError.publicSuffix(host)
        }
    }

    /// Non-throwing form for UI validation.
    public static func isAcceptable(_ scope: ServiceScope) -> Bool {
        (try? validate(scope)) != nil
    }
}
