import Foundation

/// The only hosts this module ever names in a request (PRD N5: the only network destinations besides sync are the
/// Have I Been Pwned services).
///
/// There is no public initialiser: a caller cannot make a request to anywhere else, and no setting, environment
/// variable or server response can change where one goes.
public struct HygieneHost: Hashable, Sendable {
    public let name: String

    private init(_ name: String) {
        self.name = name
    }

    /// The Pwned Passwords range API (PRD F9.1). Receives five hexadecimal characters of a SHA-1 and nothing else.
    public static let pwnedPasswords = HygieneHost("api.pwnedpasswords.com")
    /// The breached-account API (PRD F9.4). Receives an email address, and only when the person asks for that lookup.
    public static let haveIBeenPwned = HygieneHost("haveibeenpwned.com")
}

/// An `https` URL on one of the two fixed hosts. The scheme is not stored because there is no other.
public struct HTTPSURL: Hashable, Sendable {
    public let host: HygieneHost
    /// The path and, if any, the query: already percent-encoded, starting with `/`.
    public let path: String

    /// Only the two factories below make one, each from a constant and a value whose type already limits what it
    /// can hold, so nothing a caller supplies can add a host, a query, a fragment or a control character.
    private init(host: HygieneHost, path: String) {
        self.host = host
        self.path = path
    }

    /// `https://api.pwnedpasswords.com/range/XXXXX`: the constant path and five hexadecimal characters.
    static func pwnedRange(_ prefix: PwnedRangePrefix) -> HTTPSURL {
        HTTPSURL(host: .pwnedPasswords, path: "/range/" + prefix.description)
    }

    /// `https://haveibeenpwned.com/api/v3/breachedaccount/<address>?truncateResponse=false`, the address as one
    /// percent-encoded path segment.
    static func breachedAccount(_ address: EmailAddress) -> HTTPSURL {
        HTTPSURL(
            host: .haveIBeenPwned,
            path: "/api/v3/breachedaccount/" + encodedPathSegment(address.value) + "?truncateResponse=false")
    }

    public var absoluteString: String {
        "https://" + host.name + path
    }

    static func isUnreserved(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
            UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"),
            UInt8(ascii: "~"):
            return true
        default:
            return false
        }
    }

    /// Percent-encodes everything outside RFC 3986's unreserved set, so the result is one path segment whatever the
    /// input held (`/`, `?`, `#`, `%` and non-ASCII bytes included).
    static func encodedPathSegment(_ text: String) -> String {
        let hex = Array("0123456789ABCDEF".utf8)
        var out: [UInt8] = []
        for byte in text.utf8 {
            if isUnreserved(byte) {
                out.append(byte)
            } else {
                out.append(UInt8(ascii: "%"))
                out.append(hex[Int(byte >> 4)])
                out.append(hex[Int(byte & 0x0F)])
            }
        }
        return String(decoding: out, as: UTF8.self)
    }
}

/// One request, exactly as it would leave the device (docs/02-architecture.md §13).
///
/// It is a value, so tests assert on the whole of what a real adapter would send: there is no other channel by which
/// this module reaches the network.
///
/// Printing one shows the method, the host and the header names only. A header value may be the person's API key and
/// a path their email address, and neither belongs in a log (PRD N5).
public struct HTTPRequest: Hashable, Sendable {
    public enum Method: String, Sendable {
        case get = "GET"
    }

    public let method: Method
    public let url: HTTPSURL
    /// Header names as sent. Values are single-line printable ASCII by construction.
    public let headers: [String: String]
    /// The adapter must stop reading, and fail, once the decoded body exceeds this many bytes. The clients check
    /// again: a response larger than this is refused whatever the adapter did.
    public let maximumResponseBytes: Int

    init(url: HTTPSURL, headers: [String: String], maximumResponseBytes: Int) {
        self.method = .get
        self.url = url
        self.headers = headers
        self.maximumResponseBytes = maximumResponseBytes
    }

    /// Whether `value` can be a header value: printable ASCII, no line breaks, not empty, bounded.
    static func isHeaderValue(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty, bytes.count <= 256 else { return false }
        return bytes.allSatisfy { $0 >= 0x20 && $0 < 0x7F }
    }
}

extension HTTPRequest: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String {
        let names = headers.keys.sorted().joined(separator: ", ")
        return "\(method.rawValue) https://\(url.host.name) (path withheld) [\(names)]"
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

public struct HTTPResponse: Hashable, Sendable {
    public var status: Int
    public var headers: [String: String]
    public var body: [UInt8]

    public init(status: Int, headers: [String: String] = [:], body: [UInt8] = []) {
        self.status = status
        self.headers = headers
        self.body = body
    }

    /// The value of a header, matching its name without regard to case. With several spellings of one name present,
    /// the one that sorts first is used, so the answer does not depend on dictionary order.
    public func header(_ name: String) -> String? {
        let wanted = name.lowercased()
        return headers.filter { $0.key.lowercased() == wanted }.min { $0.key < $1.key }?.value
    }
}

/// The network port (docs/02-architecture.md §15). This module has no other way out: it imports no networking API.
///
/// What a production adapter owes the callers, because none of it can be checked from this side:
/// - send exactly the request given: this method, this URL, these headers and no others it can avoid (no cookies, no
///   stored credentials, no `Referer`);
/// - use an ephemeral session with no cache and no cookie storage, and ordinary system TLS validation;
/// - never follow a redirect: both APIs answer directly, and a redirect would send the request, headers included, to
///   a host this module did not choose. Return the 3xx response as it is;
/// - stop at `maximumResponseBytes` of *decoded* body and throw, so a compressed response cannot expand without limit;
/// - give up after a bounded time (tens of seconds), so a server that never answers cannot hold a scan open;
/// - never log the URL, the headers or the body.
///
/// Throwing means the request did not complete (offline, timeout, TLS failure, over the size limit); the clients
/// treat every thrown error alike, as "try again later".
public protocol HTTPClient: Sendable {
    func send(_ request: HTTPRequest) async throws -> HTTPResponse
}

/// `Watchword/<version>`, the `User-Agent` both APIs require (PRD F9.1).
public struct HygieneUserAgent: Hashable, Sendable {
    public let value: String

    /// `nil` unless `version` is 1 to 32 characters of `0-9 A-Z a-z . - +`: nothing that could break out of the
    /// header.
    public init?(version: String) {
        let bytes = Array(version.utf8)
        guard (1...32).contains(bytes.count) else { return nil }
        let allowed = bytes.allSatisfy { byte in
            switch byte {
            case UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "A")...UInt8(ascii: "Z"),
                UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "."), UInt8(ascii: "-"), UInt8(ascii: "+"):
                return true
            default:
                return false
            }
        }
        guard allowed else { return nil }
        value = "Watchword/" + version
    }
}

/// How long to wait before asking again, as a server stated it in `Retry-After`, held within bounds: a hostile or
/// broken server can neither make the scanner spin (a zero or negative wait) nor switch it off (a wait of years).
enum RetryAfter {
    static let bounds: ClosedRange<TimeInterval> = 1...3600

    /// The number of seconds in a `Retry-After` value, clamped to `bounds`. Only the delta-seconds form is read; a
    /// date, or anything else, gives `nil` and the caller's default applies.
    static func seconds(_ value: String?) -> TimeInterval? {
        guard let value else { return nil }
        var digits = ArraySlice(value.utf8)
        while let first = digits.first, first == UInt8(ascii: " ") || first == UInt8(ascii: "\t") {
            digits = digits.dropFirst()
        }
        while let last = digits.last, last == UInt8(ascii: " ") || last == UInt8(ascii: "\t") {
            digits = digits.dropLast()
        }
        guard !digits.isEmpty, digits.allSatisfy({ $0 >= UInt8(ascii: "0") && $0 <= UInt8(ascii: "9") }) else {
            return nil
        }
        // More digits than any wait we would honour: the upper bound, without parsing.
        guard digits.count <= 9 else { return bounds.upperBound }
        var seconds = 0
        for digit in digits {
            seconds = seconds * 10 + Int(digit - UInt8(ascii: "0"))
        }
        return clamped(TimeInterval(seconds))
    }

    static func clamped(_ interval: TimeInterval) -> TimeInterval {
        min(max(interval, bounds.lowerBound), bounds.upperBound)
    }
}
