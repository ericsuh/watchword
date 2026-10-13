import Foundation
import Testing
import WatchwordModel
@testable import WatchwordMatching

@Suite("Adversarial: AutoFill service matching", .tags(.adversarial))
struct AdversarialMatchingTests {
    static let vault = UUID()
    static let amazon = Item(
        vaultID: vault, title: "Amazon",
        scopes: [ServiceScope(host: "amazon.com")],
        fields: [Field(kind: .password, label: "password", value: "retail")]
    )
    static let aws = Item(
        vaultID: vault, title: "AWS",
        scopes: [ServiceScope(host: "signin.aws.amazon.com", includeSubdomains: false)],
        fields: [Field(kind: .password, label: "password", value: "root")]
    )
    static let items = [amazon, aws]

    static let userInfoURLs = [
        "https://amazon.com@evil.example/",
        "https://amazon.com:password@evil.example/",
        "http://user@amazon.com.evil.example/",
    ]

    @Test("user-info trick never yields a credential", arguments: userInfoURLs)
    func userInfo(_ url: String) {
        let (ranking, error) = ItemRanker.rank(items: Self.items, identifier: ServiceIdentifier(url, kind: .url))
        #expect(ranking.isEmpty)
        #expect(error != nil)
    }

    static let lookAlikeHosts = [
        "amazon.com.evil.example",
        "evil-amazon.com",
        "amazon.co",
        "amazoncom",
        "xn--mazon-1nf.com",  // IDN encoding of a homograph
        "аmazon.com",  // Cyrillic 'а'
        "amazon.com\u{200B}",  // zero-width space
    ]

    @Test("look-alike hosts do not match", arguments: lookAlikeHosts)
    func lookAlikes(_ host: String) {
        let ranking = ItemRanker.rank(items: Self.items, host: host)
        #expect(ranking.isEmpty, "\(host) matched \(ranking.primary.map(\.item.title))")
    }

    @Test(
        "non-web schemes are refused",
        arguments: ["ftp://amazon.com/", "file:///etc/passwd", "data:text/html,amazon.com", "javascript:alert(1)"])
    func schemes(_ url: String) {
        let (ranking, _) = ItemRanker.rank(items: Self.items, identifier: ServiceIdentifier(url, kind: .url))
        #expect(ranking.isEmpty)
    }

    static let malformedDomains = [
        "amazon.com/", "amazon.com@x", "amazon.com:443", "ama zon.com", "amazon..com", ".amazon.com", "amazon.com%2F",
    ]

    @Test("hosts with embedded control characters or separators are refused", arguments: malformedDomains)
    func malformedDomains(_ host: String) {
        let (ranking, error) = ItemRanker.rank(items: Self.items, identifier: ServiceIdentifier(host, kind: .domain))
        #expect(ranking.isEmpty)
        #expect(error != nil)
    }

    @Test("a shadowed item is never selectable even if the UI asks for it")
    func shadowedNotSelectable() {
        #expect(!ItemRanker.isSelectable(Self.amazon, for: "signin.aws.amazon.com", among: Self.items))
    }

    @Test("an item that does not match the host is never selectable")
    func unrelatedNotSelectable() {
        #expect(!ItemRanker.isSelectable(Self.aws, for: "www.amazon.com", among: Self.items))
        #expect(!ItemRanker.isSelectable(Self.aws, for: "signin.aws.amazon.com.evil.example", among: Self.items))
    }

    @Test("an empty or dotted scope never matches everything")
    func degenerateScopes() {
        let scopes = [ServiceScope(host: ""), ServiceScope(host: ".")]
        let wildcard = Item(vaultID: Self.vault, title: "wildcard", scopes: scopes, fields: [])
        let ranking = ItemRanker.rank(items: [wildcard], host: "example.com")
        #expect(ranking.isEmpty)
    }

    @Test("very long hostnames are handled in bounded time")
    func longHost() {
        let host = String(repeating: "a.", count: 5_000) + "amazon.com"
        let start = Date()
        let ranking = ItemRanker.rank(items: Self.items, host: host)
        #expect(ranking.primary.map(\.item.title) == ["Amazon"])
        #expect(Date().timeIntervalSince(start) < 1.0)
    }
}
