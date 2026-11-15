import Testing
import WatchwordMatching
import WatchwordModel

/// `PublicSuffix.broadestSite(of:)` answers for a party whose suffix list is not ours, so every case here checks that
/// it errs wide: a wrong answer may put two unrelated hosts in one site, never two halves of one site apart.
@Suite("Public suffix: the broadest site of a host")
struct PublicSuffixSiteTests {
    static func site(_ host: String) throws -> String? {
        PublicSuffix.broadestSite(of: try HostNormalizer.normalize(ServiceIdentifier(host, kind: .domain)))
    }

    @Test(
        "the site is the last two labels, or the last three under a country-code second-level domain",
        arguments: zip(
            [
                "amazon.com", "www.amazon.com", "signin.aws.amazon.com", "firstbank.co.uk", "www.firstbank.co.uk",
                "a.b.c.example.com.au", "library.example.org",
            ],
            [
                "amazon.com", "amazon.com", "amazon.com", "firstbank.co.uk", "firstbank.co.uk", "example.com.au",
                "example.org",
            ]))
    func site(_ host: String, _ expected: String) throws {
        #expect(try Self.site(host) == expected)
    }

    /// Whether another party treats a private suffix as one is unknown, so its tenants are taken to share a site.
    @Test(
        "tenants of a shared host share a site",
        arguments: zip(
            ["acme.zendesk.com", "alice.github.io", "x.y.pages.dev"], ["zendesk.com", "github.io", "pages.dev"]))
    func sharedHosting(_ host: String, _ expected: String) throws {
        #expect(try Self.site(host) == expected)
        // The suffix itself is still refused as a scope, so no item can be scoped to that whole "site".
        #expect(!ScopePolicy.isAcceptable(ServiceScope(host: expected)))
    }

    @Test("a multi-label hosting suffix is taken with the rest of its registrable domain")
    func multiLabelHostingSuffix() throws {
        #expect(try Self.site("bucket.s3.amazonaws.com") == "amazonaws.com")
    }

    @Test("a country-code suffix the list does not carry errs wide")
    func unknownCountryCodeSuffix() throws {
        #expect(try Self.site("bank.com.fj") == "com.fj")
        #expect(try Self.site("www.bank.com.fj") == "com.fj")
    }

    @Test("a suffix, a single label and an IP address belong to no site", arguments: ["co.uk", "com", "localhost"])
    func noSite(_ host: String) throws {
        #expect(try Self.site(host) == nil)
    }

    @Test("an IPv4 address belongs to no site")
    func address() throws {
        guard let host = try? HostNormalizer.normalize(ServiceIdentifier("192.168.1.10", kind: .domain)) else {
            return
        }
        #expect(PublicSuffix.broadestSite(of: host) == nil)
    }
}
