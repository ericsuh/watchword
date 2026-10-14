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
