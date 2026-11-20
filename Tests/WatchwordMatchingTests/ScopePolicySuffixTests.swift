import Testing
import WatchwordMatching
import WatchwordModel

/// The scope policy on a host the embedded suffix list names (review finding Z63). A scope spans unrelated owners
/// only when it includes subdomains: `wordpress.com` exactly is WordPress's own sign-in host, and refusing it left
/// the person with no saved login, no passkey and no look-alike warning for the site, copying the password by hand.
@Suite("Scope policy: hosts on the suffix list")
struct ScopePolicySuffixTests {
    @Test(
        "a suffix that is its operator's sign-in site is a scope for that host, never for its tenants",
        arguments: ["wordpress.com", "substack.com", "tumblr.com", "bandcamp.com", "zendesk.com"])
    func sharedHostingExactHost(_ host: String) {
        #expect(ScopePolicy.isAcceptable(ServiceScope(host: host, includeSubdomains: false)))
        #expect(!ScopePolicy.isAcceptable(ServiceScope(host: host, includeSubdomains: true)))
        #expect(ScopePolicy.newScope(forHost: host) == ServiceScope(host: host, includeSubdomains: false))
    }

    /// A country-code second-level domain, a top-level domain, `localhost` and a hosting suffix with no site of its
    /// own at the bare name are nobody's sign-in host, so a scope for one is refused however far it reaches.
    @Test(
        "a suffix that is nobody's site is refused either way",
        arguments: ["co.uk", "com.au", "com", "localhost", "github.io", "herokuapp.com"])
    func noSite(_ host: String) {
        #expect(!ScopePolicy.isAcceptable(ServiceScope(host: host, includeSubdomains: false)))
        #expect(!ScopePolicy.isAcceptable(ServiceScope(host: host, includeSubdomains: true)))
        #expect(ScopePolicy.newScope(forHost: host).includeSubdomains)
    }

    @Test("an ordinary host's new scope includes its subdomains", arguments: ["amazon.com", "tenant.github.io"])
    func ordinaryHost(_ host: String) {
        #expect(ScopePolicy.newScope(forHost: host) == ServiceScope(host: host, includeSubdomains: true))
    }

    /// Once the site can be saved, its look-alikes are judged against it like any other's.
    @Test("a look-alike of a sign-in site at a shared-hosting suffix is suspicious")
    func lookAlike() throws {
        let saved = [ServiceScope(host: "wordpress.com", includeSubdomains: false)]
        let host = try HostNormalizer.normalize(ServiceIdentifier("wordpres.com", kind: .domain))
        #expect(PhishingDetector.assess(host: host, against: saved).isSuspicious)
        let own = try HostNormalizer.normalize(ServiceIdentifier("wordpress.com", kind: .domain))
        #expect(PhishingDetector.assess(host: own, against: saved) == .recognized)
    }

}
