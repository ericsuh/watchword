import XCTest

@testable import WatchwordMatching

final class HostNormalizerTests: XCTestCase {
    private func normalize(_ value: String, kind: ServiceIdentifierKind = .domain) throws -> String {
        try HostNormalizer.normalize(ServiceIdentifier(value, kind: kind)).value
    }

    func testDomainIdentifierIsLowercasedAndTrailingDotStripped() throws {
        XCTAssertEqual(try normalize("WWW.Amazon.COM."), "www.amazon.com")
    }

    func testURLIdentifierExtractsHostIgnoringPathQueryAndPort() throws {
        let host = try normalize("https://signin.aws.amazon.com:443/signin?redirect=x#frag", kind: .url)
        XCTAssertEqual(host, "signin.aws.amazon.com")
    }

    func testIPv6LiteralIsAccepted() throws {
        XCTAssertEqual(try normalize("http://[::1]:8080/", kind: .url), "::1")
    }

    func testEmptyIdentifierIsRejected() {
        XCTAssertThrowsError(try normalize("   ")) { error in
            XCTAssertEqual(error as? HostNormalizationError, .empty)
        }
    }

    func testDomainWithPathIsRejected() {
        XCTAssertThrowsError(try normalize("amazon.com/login"))
    }

    /// `URLComponents.host` percent-decodes, so an encoded dot would otherwise invent a label
    /// boundary that is invisible in the URL the person sees.
    func testEncodedDotCannotInventALabelBoundary() throws {
        XCTAssertThrowsError(try normalize("https://x.amazon%2Ecom/", kind: .url)) { error in
            XCTAssertEqual(error as? HostNormalizationError, .asciiPercentEscape("x.amazon%2Ecom"))
        }
        XCTAssertThrowsError(try normalize("https://amazon.com%00.evil.example/", kind: .url))
    }

    /// Percent-escapes for non-ASCII bytes are how Foundation represents an IDN host, so they
    /// must keep working.
    func testNonASCIIPercentEscapesAreAccepted() throws {
        XCTAssertEqual(try normalize("https://\u{0430}mazon.com/", kind: .url), "\u{0430}mazon.com")
    }

    /// Foundation applies IDNA compatibility mapping during parsing; these fold to ASCII exactly
    /// as a browser resolves them, so matching them is correct rather than a homograph hole.
    func testIDNACompatibilityMappingIsHonoured() throws {
        XCTAssertEqual(try normalize("https://\u{FF21}MAZON.com/", kind: .url), "amazon.com")
        XCTAssertEqual(try normalize("https://amazon\u{212A}.com/", kind: .url), "amazonk.com")
    }

    /// One host has one normalised form, whether the OS hands it over as a domain or as a URL: a scope saved from
    /// one must match a request made with the other, and neither may match where the other would not. As a domain,
    /// these were lower-cased only (`ａmazon.com`, `x。com`, a Greek symbol IDNA decomposes), so they never met
    /// their URL forms; the fuzzer found the last one through an import's bare-host scope coming back from its own
    /// export as another host.
    func testDomainAndURLFormsOfAHostNormaliseAlike() throws {
        let hosts = [
            "\u{FF21}MAZON.com", "amazon\u{212A}.com", "x\u{3002}example.com", "a\u{FF0E}example.com",
            "htxconcealed\u{03D3}tringo.uk", "\u{01C4}.example.com", "\u{0430}mazon.com", "Stra\u{00DF}e.de",
            "WWW.Amazon.COM.", "_dmarc.example.com", "127.0.0.1",
        ]
        for host in hosts {
            let asURL = try normalize("https://\(host)/", kind: .url)
            XCTAssertEqual(try normalize(host), asURL, "\(host.debugDescription) normalises differently as a domain")
        }
        XCTAssertEqual(try normalize("\u{FF21}MAZON.com"), "amazon.com")
    }

    /// A non-ASCII domain that the URL parser cannot read as a host is refused rather than kept as typed: how it
    /// would resolve is unknown, and normalisation must not guess.
    func testUnmappableNonASCIIDomainIsRejected() {
        XCTAssertThrowsError(try normalize("https://a\u{2024}b.com/", kind: .url))
        XCTAssertThrowsError(try normalize("a\u{2024}b.com"))
        XCTAssertThrowsError(try normalize("a\u{FF0F}b.com"))
    }

    func testZeroWidthAndBidiCharactersAreRejected() {
        for sneaky in ["amazon.com\u{200B}", "amazon\u{200D}.com", "\u{202E}amazon.com", "amazon\u{00AD}.com"] {
            XCTAssertThrowsError(try normalize(sneaky), "\(sneaky.debugDescription) should be rejected")
        }
    }

    func testOverlongHostsAndLabelsAreRejected() {
        let longLabel = String(repeating: "a", count: 64)
        XCTAssertThrowsError(try normalize("\(longLabel).com")) { error in
            XCTAssertEqual(error as? HostNormalizationError, .labelTooLong(longLabel))
        }
        let longHost = Array(repeating: "abcdefgh", count: 40).joined(separator: ".")
        XCTAssertThrowsError(try normalize(longHost)) { error in
            guard case .hostTooLong = error as? HostNormalizationError else {
                return XCTFail("expected hostTooLong, got \(error)")
            }
        }
    }

    func testUserInfoIsRejected() {
        XCTAssertThrowsError(try normalize("https://amazon.com@evil.example/", kind: .url)) { error in
            XCTAssertEqual(error as? HostNormalizationError, .containsUserInfo)
        }
    }
}
