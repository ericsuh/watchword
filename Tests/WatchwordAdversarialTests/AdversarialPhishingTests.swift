import Foundation
import Testing
import WatchwordModel

@testable import WatchwordMatching

/// Phishing resistance (PRD F11). Two separate guarantees are tested here:
///
/// 1. The app never hands a secret to a look-alike site, however the host is dressed up.
/// 2. The app does not stay *silent* on a look-alike site. Silence is what makes a person
///    fall back to copying the password by hand, which is the failure the attacker wants.
@Suite("Adversarial: phishing resistance", .tags(.adversarial))
struct AdversarialPhishingTests {
    static let vault = UUID()

    static let amazon = Item(
        vaultID: vault, title: "Amazon",
        scopes: [ServiceScope(host: "amazon.com")],
        fields: [
            Field(kind: .password, label: "password", value: "retail-password"),
            Field(kind: .totp, label: "code", value: "otpauth://totp/Amazon?secret=RETAIL"),
        ]
    )
    static let bank = Item(
        vaultID: vault, title: "Bank",
        scopes: [ServiceScope(host: "firstbank.co.uk")],
        fields: [Field(kind: .password, label: "password", value: "bank-password")]
    )
    static let items = [amazon, bank]
    static let scopes = items.flatMap(\.scopes)

    static func host(_ value: String) throws -> NormalizedHost {
        try HostNormalizer.normalize(ServiceIdentifier(value, kind: .domain))
    }

    // MARK: - Nothing is ever filled on a look-alike

    static let impersonatingHosts = [
        "arnazon.com",  // rn rendered as m
        "amaz0n.com",  // zero for o
        "\u{0430}mazon.com",  // Cyrillic а
        "amazon.com.evil.example",  // real domain as a subdomain label
        "secure-amazon.example",  // brand in a hyphenated label
        "amazon-login.example",
        "amazom.com",  // one-character typo
        "xn--mazon-1nf.com",  // punycode homograph
        "firstbank.co.uk.evil.example",
        "firstbamk.co.uk",
    ]

    @Test("no credential is offered on an impersonating host", arguments: impersonatingHosts)
    func neverFills(_ value: String) {
        let identifier = ServiceIdentifier(value, kind: .domain)
        let decision = AutoFillGate.decide(for: identifier, among: Self.items)
        #expect(!decision.isFill, "\(value) produced a fill decision")

        // And the per-item authorization chokepoint refuses too, even if a buggy UI asked.
        for item in Self.items {
            if case .success = AutoFillGate.authorize(item, for: identifier, among: Self.items) {
                Issue.record("\(item.title) was authorized on \(value)")
            }
        }
    }

    @Test("a one-time code is withheld on an impersonating host", arguments: impersonatingHosts)
    func neverReleasesOneTimeCode(_ value: String) {
        let identifier = ServiceIdentifier(value, kind: .domain)
        let result = AutoFillGate.authorizeOneTimeCode(Self.amazon, for: identifier, among: Self.items)
        switch result {
        case .success:
            Issue.record("one-time code released on \(value)")
        case .failure:
            break
        }
    }

    // MARK: - The person is warned rather than left in silence

    @Test("an impersonating host is reported as suspicious, not merely unknown", arguments: impersonatingHosts)
    func warnsInsteadOfSilence(_ value: String) throws {
        let assessment = PhishingDetector.assess(host: try Self.host(value), against: Self.scopes)
        #expect(assessment.isSuspicious, "\(value) was not flagged; the person would see silence")
        if case .suspicious(let signals, _) = assessment {
            #expect(!signals.isEmpty)
        }
    }

    /// These name a specific saved site, so the warning can say which one is being imitated.
    @Test(
        "a host imitating a saved site names its target",
        arguments: [
            "arnazon.com", "amaz0n.com", "\u{0430}mazon.com", "amazon.com.evil.example",
            "secure-amazon.example", "amazon-login.example", "amazom.com",
            "firstbank.co.uk.evil.example", "firstbamk.co.uk",
        ])
    func namesTheImitatedSite(_ value: String) throws {
        let assessment = PhishingDetector.assess(host: try Self.host(value), against: Self.scopes)
        #expect(assessment.impersonatesSavedSite, "\(value) did not name a target")
    }

    /// Punycode cannot be decoded without an IDNA table, so it gets the weaker warning rather
    /// than a claim about which site it imitates.
    /// Threat: A4, a member of a shared vault, or A7 through an item a member imported: a scope for the look-alike
    /// itself, in a vault other accounts write, used to make the host `recognized` before any resemblance was
    /// computed (review findings Z60, Z65). A scope recognises a host for its own vault only. The person's own
    /// scope for the host recognises it for everyone, and a shared vault's scope that resembles nothing saved
    /// elsewhere is an ordinary match.
    @Test(
        "a scope in a shared vault does not make a look-alike of another vault's site recognised",
        arguments: impersonatingHosts)
    func sharedVaultScopeDoesNotRecognise(_ value: String) throws {
        let shared = UUID()
        let host = try Self.host(value)
        let planted = Item(vaultID: shared, title: "Planted", scopes: [ServiceScope(host: host.value)], fields: [])
        let assessment = PhishingDetector.assess(
            host: host, againstItemsIn: Self.items + [planted], sharedVaults: [shared])
        #expect(assessment.isSuspicious, "\(value)")
        // Wherever the look-alike can be read (everything but punycode Foundation left encoded), the site is named.
        #expect(assessment.impersonatesSavedSite || host.value.contains("xn--"), "\(value)")
        // Taken as one pool, as it was: recognised.
        #expect(PhishingDetector.assess(host: host, againstItemsIn: Self.items + [planted]) == .recognized)

        let vouched = Item(vaultID: Self.vault, title: "Mine", scopes: [ServiceScope(host: host.value)], fields: [])
        #expect(
            PhishingDetector.assess(
                host: host, againstItemsIn: Self.items + [planted, vouched], sharedVaults: [shared]) == .recognized)
        // A second shared vault that holds the real site is protected from the first in the same way.
        let other = UUID()
        let theirs = Self.items.map { item -> Item in
            var copy = item
            copy.vaultID = other
            return copy
        }
        #expect(
            PhishingDetector.assess(host: host, againstItemsIn: theirs + [planted], sharedVaults: [shared, other])
                .isSuspicious)
        // In one shared vault alone, a member who can add the host could as well edit the item it resembles: only
        // a host that cannot be read at all is still refused there.
        let sameVault = Self.items.map { item -> Item in
            var copy = item
            copy.vaultID = shared
            return copy
        }
        let within = PhishingDetector.assess(host: host, againstItemsIn: sameVault + [planted], sharedVaults: [shared])
        #expect(!within.impersonatesSavedSite)
    }

    /// Threat: the same member, with a homograph of a site that only the shared vault holds, so no other vault's
    /// scope names it. A label that mixes scripts cannot be verified by eye whoever saved it; a member's scope for
    /// it is not the person's word. An ordinary host in a shared vault is an ordinary match.
    @Test("a shared vault's scope is an ordinary match unless the host cannot be read")
    func sharedVaultScopeForAnUnrelatedHost() throws {
        let shared = UUID()
        let streaming = Item(
            vaultID: shared, title: "Streaming",
            scopes: [ServiceScope(host: "streaming.example"), ServiceScope(host: "\u{0430}pple-tv.example")],
            fields: [])
        for value in ["streaming.example", "tv.streaming.example"] {
            #expect(
                PhishingDetector.assess(
                    host: try Self.host(value), againstItemsIn: Self.items + [streaming], sharedVaults: [shared])
                    == .recognized, "\(value)")
        }
        #expect(
            PhishingDetector.assess(
                host: try Self.host("\u{0430}pple-tv.example"), againstItemsIn: Self.items + [streaming],
                sharedVaults: [shared]) == .suspicious(signals: [.mixedScript], impersonating: []))
        #expect(
            PhishingDetector.assess(
                host: try Self.host("unrelated.example"), againstItemsIn: Self.items + [streaming],
                sharedVaults: [shared]) == .unrecognized)
    }

    @Test("a punycode host is flagged even without a named target")
    func punycodeIsFlagged() throws {
        let assessment = PhishingDetector.assess(host: try Self.host("xn--mazon-1nf.com"), against: Self.scopes)
        #expect(assessment.isSuspicious)
        guard case .suspicious(let signals, _) = assessment else { return }
        #expect(signals.contains(.punycode("xn--mazon-1nf")))
    }

    @Test("the refusal carries the assessment so the UI can explain itself")
    func refusalExplainsItself() {
        let decision = AutoFillGate.decide(
            for: ServiceIdentifier("arnazon.com", kind: .domain), among: Self.items)
        guard case .refuse(.noMatchingItem(let assessment)) = decision else {
            Issue.record("expected a refusal carrying an assessment, got \(decision)")
            return
        }
        #expect(assessment.isSuspicious)
        let expected = PhishingAssessment.suspicious(
            signals: [.confusableWithSavedScope("amazon.com")], impersonating: ["amazon.com"])
        #expect(assessment == expected)
    }

    @Test("a genuine host is recognized and fills normally")
    func genuineHostStillWorks() throws {
        let identifier = ServiceIdentifier("www.amazon.com", kind: .domain)
        #expect(PhishingDetector.assess(host: try Self.host("www.amazon.com"), against: Self.scopes) == .recognized)
        guard case .fill(let match) = AutoFillGate.decide(for: identifier, among: Self.items) else {
            Issue.record("genuine host did not fill")
            return
        }
        #expect(match.item.title == "Amazon")
    }

    @Test(
        "an unrelated site is not flagged, so warnings stay meaningful",
        arguments: ["example.com", "wikipedia.org", "news.bbc.co.uk", "some-startup.io"])
    func unrelatedHostsAreQuiet(_ value: String) throws {
        let assessment = PhishingDetector.assess(host: try Self.host(value), against: Self.scopes)
        #expect(assessment == .unrecognized, "\(value) produced a false phishing warning")
    }

    /// A regional sibling of a saved site is a plausible place to be, not an attack.
    @Test("same name under a different public suffix is not flagged", arguments: ["amazon.de", "amazon.co.jp"])
    func regionalSiblingsAreQuiet(_ value: String) throws {
        let assessment = PhishingDetector.assess(host: try Self.host(value), against: Self.scopes)
        #expect(!assessment.isSuspicious, "\(value) produced a false phishing warning")
    }

    // MARK: - Skeleton and script machinery

    static let lookAlikeSpellings = [
        "arnazon.com", "amaz0n.com", "\u{0430}mazon.com", "paypa1.com", "vvhatsapp.com",
    ]
    static let genuineSpellings = [
        "amazon.com", "amazon.com", "amazon.com", "paypal.com", "whatsapp.com",
    ]

    /// Uses the documented two-collection `zip` form rather than an array of tuples, which keeps
    /// the test compiling across the Swift Testing versions in the CI matrix.
    @Test("visual skeletons collapse confusables", arguments: zip(lookAlikeSpellings, genuineSpellings))
    func skeletons(_ lookAlike: String, _ genuine: String) {
        #expect(PhishingDetector.skeleton(lookAlike) == PhishingDetector.skeleton(genuine))
    }

    @Test("mixed-script hosts are detected")
    func mixedScript() {
        #expect(PhishingDetector.isMixedScript("\u{0430}mazon.com"))
        #expect(!PhishingDetector.isMixedScript("amazon.com"))
        #expect(!PhishingDetector.isMixedScript("\u{0430}\u{043C}\u{0430}\u{0437}\u{043E}\u{043D}.com"))
    }

    @Test("the distinctive label skips the public suffix")
    func distinctiveLabel() {
        #expect(PhishingDetector.distinctiveLabel(of: "firstbank.co.uk") == "firstbank")
        #expect(PhishingDetector.distinctiveLabel(of: "www.amazon.com") == "amazon")
        #expect(PhishingDetector.distinctiveLabel(of: "tenant.github.io") == "tenant")
    }

    @Test("edit distance abandons early and never reports beyond the limit")
    func boundedEditDistance() {
        #expect(PhishingDetector.editDistance("amazon", "amazom", limit: 2) == 1)
        #expect(PhishingDetector.editDistance("amazon", "wikipedia", limit: 2) == 3)
        #expect(PhishingDetector.editDistance("", "abc", limit: 2) == 3)
    }

    // MARK: - Over-broad scopes cannot be created in the first place

    @Test(
        "a scope that spans unrelated owners is refused",
        arguments: ["com", "co.uk", "github.io", "herokuapp.com", "localhost", "appspot.com"])
    func overBroadScopesRefused(_ value: String) {
        #expect(!ScopePolicy.isAcceptable(ServiceScope(host: value)), "\(value) was accepted as a scope")
    }

    @Test(
        "a normal site scope is accepted",
        arguments: ["amazon.com", "firstbank.co.uk", "signin.aws.amazon.com", "tenant.github.io"])
    func normalScopesAccepted(_ value: String) {
        #expect(ScopePolicy.isAcceptable(ServiceScope(host: value)), "\(value) was rejected as a scope")
    }

    /// The reason over-broad scopes matter: a `com` scope would otherwise become the top match on
    /// an attacker's domain where the person has nothing saved.
    @Test("an over-broad scope would have matched an attacker's host")
    func demonstratesWhyPolicyExists() throws {
        let overBroad = Item(
            vaultID: Self.vault, title: "Everything",
            scopes: [ServiceScope(host: "com", includeSubdomains: true)],
            fields: [Field(kind: .password, label: "password", value: "p")])
        let ranking = ItemRanker.rank(items: [overBroad], host: try Self.host("evil.com"))
        #expect(!ranking.isEmpty, "precondition: the matcher does match such a scope")
        #expect(!ScopePolicy.isAcceptable(overBroad.scopes[0]), "so policy must stop it being created")
    }
}

enum PhishingTestFailure: Error {
    case authorizedOnPhishingHost(String, String)
}
