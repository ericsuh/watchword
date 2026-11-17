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

    /// A2 on the network path serves a page of the right site over plain `http`, where it can read whatever is
    /// filled. The gate refuses it before matching, for the decision and for an explicit choice alike (PRD F6.9);
    /// the same host over `https`, or as an app's domain, is matched as before.
    @Test(
        "an http page is refused by decide and by authorize, whatever is scoped to it",
        arguments: ["http://amazon.com/", "HTTP://www.amazon.com/ap/signin", "http://signin.aws.amazon.com:80/"])
    func plainHTTP(_ url: String) {
        let identifier = ServiceIdentifier(url, kind: .url)
        guard case .refuse(.insecurePage) = AutoFillGate.decide(for: identifier, among: Self.items) else {
            Issue.record("\(url) was not refused as insecure")
            return
        }
        for item in Self.items {
            guard case .failure(.insecurePage) = AutoFillGate.authorize(item, for: identifier, among: Self.items) else {
                Issue.record("\(url) authorised \(item.title)")
                continue
            }
        }
        let secure = ServiceIdentifier(
            url.lowercased().replacingOccurrences(of: "http://", with: "https://"), kind: .url)
        if case .refuse(let refusal) = AutoFillGate.decide(for: secure, among: Self.items) {
            Issue.record("\(secure.identifier) was refused: \(refusal)")
        }
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

    /// Threat: A4, a member of a shared vault who may write, plants an item scoped one label below the victim's own
    /// login (review finding Z60). Ranked as one pool it was the single most specific match: the gate filled it, and
    /// refused the victim's own login even when chosen. A vault is a trust domain: the planted item shadows nothing
    /// outside its vault, so the gate's answer is a choice between the two and each stays selectable. The person's
    /// own more specific item still wins over a shared vault's, which is their statement to make.
    @Test("an item of a shared vault never becomes the silent winner over the person's own")
    func sharedVaultIsATrustDomain() throws {
        let shared = UUID()
        let planted = Item(
            vaultID: shared, title: "Amazon",
            scopes: [ServiceScope(host: "www.amazon.com", includeSubdomains: false)],
            fields: [Field(kind: .password, label: "password", value: "planted")])
        let items = [Self.amazon, planted]
        let page = ServiceIdentifier("https://www.amazon.com/ap/signin", kind: .url)

        guard case .chooseAmong(let matches) = AutoFillGate.decide(for: page, among: items, sharedVaults: [shared])
        else {
            Issue.record("a member's item was filled, or the person's own was refused")
            return
        }
        #expect(Set(matches.map(\.item.id)) == [Self.amazon.id, planted.id])
        for item in items {
            #expect(throws: Never.self) {
                try AutoFillGate.authorize(item, for: page, among: items, sharedVaults: [shared]).get()
                try AutoFillGate.authorizeOneTimeCode(item, for: page, among: items, sharedVaults: [shared]).get()
            }
        }
        // The other way round the person's own exact item is the one fill, and the shared vault's is refused.
        let sharedWide = Item(
            vaultID: shared, title: "Household Amazon", scopes: [ServiceScope(host: "amazon.com")],
            fields: [Field(kind: .password, label: "password", value: "household")])
        let console = ServiceIdentifier("https://signin.aws.amazon.com/", kind: .url)
        let decision = AutoFillGate.decide(for: console, among: [sharedWide, Self.aws], sharedVaults: [shared])
        #expect(decision == .fill(RankedMatch(item: Self.aws, match: try #require(
            ScopeMatcher.match(Self.aws.scopes[0], host: try Self.host("signin.aws.amazon.com"))), isShadowed: false)))
        #expect(throws: FillRefusal.self) {
            try AutoFillGate.authorize(sharedWide, for: console, among: [sharedWide, Self.aws], sharedVaults: [shared])
                .get()
        }
    }

    /// Threat: A4 with A6. A scope for `amaz0n.com` in a shared vault made that host a match, so the gate filled the
    /// shared item there and reported the host as recognised, although the victim's own vault holds `amazon.com`.
    /// A member's scope does not vouch for a look-alike of another vault's site: the gate refuses the host as
    /// `resemblesSavedSite`, for a decision and for an explicit choice, and names what it resembles.
    @Test(
        "the gate refuses a host only a shared vault is scoped to when it resembles the person's own site",
        arguments: ["amaz0n.com", "arnazon.com", "\u{0430}mazon.com", "amazon.com.evil.example"])
    func memberScopedLookAlike(_ lookAlike: String) throws {
        let shared = UUID()
        let planted = Item(
            vaultID: shared, title: "Amazon", scopes: [ServiceScope(host: lookAlike)],
            fields: [Field(kind: .password, label: "password", value: "planted")])
        let items = [Self.amazon, planted]
        let page = ServiceIdentifier(lookAlike, kind: .domain)

        guard case .refuse(.resemblesSavedSite(let assessment)) = AutoFillGate.decide(
            for: page, among: items, sharedVaults: [shared])
        else {
            Issue.record("offered on \(lookAlike)")
            return
        }
        #expect(assessment.isSuspicious)
        #expect(
            AutoFillGate.authorize(planted, for: page, among: items, sharedVaults: [shared])
                == .failure(.resemblesSavedSite(assessment)))
        // The person's own item scoped to the host is their word for it.
        let vouched = Item(vaultID: Self.vault, title: "Mine", scopes: [ServiceScope(host: lookAlike)], fields: [])
        #expect(AutoFillGate.decide(for: page, among: items + [vouched], sharedVaults: [shared]) != .refuse(
            .resemblesSavedSite(assessment)))
        #expect(
            (try? AutoFillGate.authorize(planted, for: page, among: items + [vouched], sharedVaults: [shared]).get())
                != nil)
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
