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

    static func host(_ value: String) throws -> NormalizedHost {
        try HostNormalizer.normalize(ServiceIdentifier(value, kind: .domain))
    }

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
        "\u{0430}mazon.com",  // Cyrillic 'а'
    ]

    @Test("look-alike hosts do not match", arguments: lookAlikeHosts)
    func lookAlikes(_ value: String) throws {
        let ranking = ItemRanker.rank(items: Self.items, host: try Self.host(value))
        #expect(ranking.isEmpty, "\(value) matched \(ranking.primary.map(\.item.title))")
    }

    @Test(
        "non-web schemes are refused",
        arguments: ["ftp://amazon.com/", "file:///etc/passwd", "data:text/html,amazon.com", "javascript:alert(1)"])
    func schemes(_ url: String) {
        let (ranking, _) = ItemRanker.rank(items: Self.items, identifier: ServiceIdentifier(url, kind: .url))
        #expect(ranking.isEmpty)
    }

    static let malformedDomainInputs = [
        "amazon.com/", "amazon.com@x", "amazon.com:443", "ama zon.com", "amazon..com", ".amazon.com", "amazon.com%2F",
    ]

    @Test("hosts with embedded control characters or separators are refused", arguments: malformedDomainInputs)
    func malformedDomains(_ value: String) {
        let (ranking, error) = ItemRanker.rank(items: Self.items, identifier: ServiceIdentifier(value, kind: .domain))
        #expect(ranking.isEmpty)
        #expect(error != nil)
    }

    @Test("a shadowed item is never selectable even if the UI asks for it")
    func shadowedNotSelectable() throws {
        let host = try Self.host("signin.aws.amazon.com")
        #expect(!ItemRanker.isSelectable(Self.amazon, for: host, among: Self.items))
    }

    @Test("an item that does not match the host is never selectable")
    func unrelatedNotSelectable() throws {
        #expect(!ItemRanker.isSelectable(Self.aws, for: try Self.host("www.amazon.com"), among: Self.items))
        #expect(
            !ItemRanker.isSelectable(
                Self.aws, for: try Self.host("signin.aws.amazon.com.evil.example"), among: Self.items))
    }

    @Test("an empty or dotted scope never matches everything")
    func degenerateScopes() throws {
        let scopes = [ServiceScope(host: ""), ServiceScope(host: ".")]
        let wildcard = Item(vaultID: Self.vault, title: "wildcard", scopes: scopes, fields: [])
        let ranking = ItemRanker.rank(items: [wildcard], host: try Self.host("example.com"))
        #expect(ranking.isEmpty)
    }

    @Test("very long hostnames are refused rather than matched or ground over")
    func longHost() {
        let value = String(repeating: "a.", count: 5_000) + "amazon.com"
        let (ranking, error) = ItemRanker.rank(items: Self.items, identifier: ServiceIdentifier(value, kind: .domain))
        #expect(ranking.isEmpty)
        #expect(error != nil)
    }
}
