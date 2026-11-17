import Foundation
import Testing
import WatchwordModel
import WatchwordPresentation

@Suite("Screen models: hosts a merge would add")
struct MergeHostTests {
    /// Known answers from Python's `str.encode("punycode")` (an independent implementation of RFC 3492).
    @Test(
        "a label outside ASCII is shown in its punycode form",
        arguments: zip(
            ["аmazon.com", "bücher.example", "münchen.de", "пример.рф", "例え.jp", "ü.example", "plain.example"],
            [
                "xn--mazon-3ve.com", "xn--bcher-kva.example", "xn--mnchen-3ya.de", "xn--e1afmkfd.xn--p1ai",
                "xn--r8jz45g.jp", "xn--tda.example", "plain.example",
            ]))
    func punycode(host: String, ascii: String) {
        #expect(HostText.ascii(host) == ascii)
    }

    @Test(
        "the registrable domain is the label left of the public suffix, with the suffix",
        arguments: zip(
            ["www.citylibrary.org", "login.amazon.co.uk", "acme.github.io", "example.com", "a.b.c.example.com"],
            ["citylibrary.org", "amazon.co.uk", "acme.github.io", "example.com", "example.com"]))
    func registrable(host: String, domain: String) {
        #expect(HostText.registrableDomain(of: host) == domain)
    }

    @Test("a Cyrillic look-alike of a saved site is shown in ASCII and warned about")
    func lookAlike() {
        let saved = [Item(vaultID: UUID(), title: "Amazon", scopes: [ServiceScope(host: "amazon.com")], fields: [])]
        let host = MergeHost(ServiceScope(host: "аmazon.com"), against: saved)
        #expect(host.ascii == "xn--mazon-3ve.com")
        #expect(host.registrable == "xn--mazon-3ve.com" && host.prefix.isEmpty)
        let warning = try? #require(host.warning)
        #expect(warning?.contains("amazon.com") == true)
        #expect(host.needsConfirmation)
    }

    @Test("an ordinary new host is not warned about, and says how far it reaches")
    func ordinary() {
        let saved = [
            Item(vaultID: UUID(), title: "Library", scopes: [ServiceScope(host: "citylibrary.org")], fields: [])
        ]
        let host = MergeHost(
            ServiceScope(
                host: "www.citylibrary.org", includeSubdomains: true, excludedHosts: ["staff.citylibrary.org"]),
            against: saved)
        #expect(host.warning == nil && !host.needsConfirmation)
        #expect(host.prefix == "www." && host.registrable == "citylibrary.org")
        #expect(host.reach == "and its subdomains, except staff.citylibrary.org")
        let exact = MergeHost(ServiceScope(host: "catalogue.example", includeSubdomains: false), against: saved)
        #expect(exact.reach == "this address only")
    }
}
