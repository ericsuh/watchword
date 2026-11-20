import Foundation
import Testing
import WatchwordMatching
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

    /// Review finding Z65. A7's file offers a saved Amazon item the host `amaz0n.com`. The look-alike check used to
    /// run against the stored items as they are: an item scoped `com` that another member synced (the gate ignores
    /// it), or a trashed item scoped to the look-alike, made the host "recognised" before any resemblance was looked
    /// for, so no warning and no second confirmation appeared.
    @Test("a policy-refused or trashed scope does not make a look-alike recognised")
    func refusedAndTrashedScopes() {
        let vault = UUID()
        let amazon = Item(vaultID: vault, title: "Amazon", scopes: [ServiceScope(host: "amazon.com")], fields: [])
        let broad = Item(vaultID: vault, title: "Planted", scopes: [ServiceScope(host: "com")], fields: [])
        var trashed = Item(vaultID: vault, title: "Old", scopes: [ServiceScope(host: "amaz0n.com")], fields: [])
        trashed.trashedAt = Date(timeIntervalSince1970: 1)
        for saved in [[amazon, broad], [amazon, trashed]] {
            let host = MergeHost(ServiceScope(host: "amaz0n.com"), against: saved)
            #expect(host.warning?.contains("amazon.com") == true)
        }
    }

    /// The same file, helped by A4: a member of a shared vault saves an item scoped to the look-alike itself, which
    /// passes the scope policy and is not in the trash. It recognises the host for its own vault only: against the
    /// person's own Amazon item the host is still a look-alike. (Where the Amazon item is in that same shared vault,
    /// the member could have edited it directly, and the host is theirs to vouch for.)
    @Test("a member's item scoped to the look-alike does not make it recognised for the person's own item")
    func memberPlantedScope() {
        let own = UUID()
        let shared = UUID()
        let amazon = Item(vaultID: own, title: "Amazon", scopes: [ServiceScope(host: "amazon.com")], fields: [])
        let planted = Item(vaultID: shared, title: "Amazon", scopes: [ServiceScope(host: "amaz0n.com")], fields: [])
        let sites = SavedSites(stored: [amazon, planted], ownVaults: [own]).prepared()
        let host = MergeHost(ServiceScope(host: "amaz0n.com"), among: sites)
        #expect(host.resembles == ["amazon.com"])
        #expect(host.needsConfirmation)
        // Taken as one pool, as it was: recognised, no warning.
        #expect(MergeHost(ServiceScope(host: "amaz0n.com"), against: [amazon, planted]).warning == nil)
    }
}
