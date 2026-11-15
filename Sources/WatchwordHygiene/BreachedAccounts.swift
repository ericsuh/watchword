import Foundation

/// An email address in the one shape the breached-account lookup will send: something `@` something, at most 254
/// bytes, with no white space or control characters. Anything else is refused, not repaired.
public struct EmailAddress: Hashable, Sendable {
    public static let maximumLength = 254

    public let value: String

    public init?(_ text: String) {
        let bytes = Array(text.utf8)
        guard (3...Self.maximumLength).contains(bytes.count) else { return nil }
        let parts = text.split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else { return nil }
        for scalar in text.unicodeScalars {
            if scalar.value < 0x21 || scalar.value == 0x7F { return nil }
            if scalar.properties.isWhitespace || scalar.properties.generalCategory == .control { return nil }
            if scalar.properties.generalCategory == .format { return nil }
        }
        value = text
    }
}

/// The person's Have I Been Pwned API key (PRD F9.4).
///
/// It prints as `HIBPAPIKey(redacted)` and reflects as nothing; it is neither `Codable` nor `Hashable`. Where it is
/// kept between launches is the session's decision (sealed in the vault, or the Keychain); this type only carries it to
/// the one header it belongs in.
public struct HIBPAPIKey: Sendable {
    let value: String

    /// `nil` unless `text` is 16 to 128 ASCII letters and digits (the service issues 32 hexadecimal characters):
    /// nothing that could end the header or start another.
    public init?(_ text: String) {
        let bytes = Array(text.utf8)
        guard (16...128).contains(bytes.count) else { return nil }
        let allowed = bytes.allSatisfy { byte in
            switch byte {
            case UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "A")...UInt8(ascii: "Z"),
                UInt8(ascii: "a")...UInt8(ascii: "z"):
                return true
            default:
                return false
            }
        }
        guard allowed else { return nil }
        value = text
    }
}

extension HIBPAPIKey: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "HIBPAPIKey(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

/// The person's decision, made now, to send one address to Have I Been Pwned.
///
/// The range API sends five characters of a hash; this lookup sends an identifier, and the service learns that
/// someone asked about it. So it is opt-in *per call* (PRD F9.4): the lookup takes one of these and nothing else
/// names the address, which means there is no way to call it without writing, at the call site, that the person
/// confirmed sending exactly this address. Nothing in this module makes one, and no scan or schedule ever looks an
/// address up.
public struct IdentifierDisclosure: Hashable, Sendable {
    public let address: EmailAddress

    private init(address: EmailAddress) {
        self.address = address
    }

    /// For the UI action in which the person asks for this address to be looked up, and for nothing else.
    public static func confirmedByPerson(sending address: EmailAddress) -> IdentifierDisclosure {
        IdentifierDisclosure(address: address)
    }
}

/// One breach an address appears in, reduced to bounded plain text.
///
/// The service's HTML description and logo path are deliberately not carried: nothing from the network is rendered
/// as markup or fetched.
public struct AccountBreach: Hashable, Sendable {
    /// The service's stable name for the breach.
    public let name: String
    public let title: String
    /// The breached site's domain, if the service names one.
    public let domain: String?
    /// `YYYY-MM-DD`, if the service gave a date of that shape.
    public let breachDate: String?
    public let accountCount: UInt64?
    /// What was exposed ("Email addresses", "Passwords", …).
    public let dataClasses: [String]
    public let isVerified: Bool
    public let isSensitive: Bool
}

public enum BreachedAccountError: Error, Equatable, Sendable {
    /// HTTP 401: the service did not accept the API key.
    case keyRejected
    /// HTTP 403.
    case forbidden
    /// HTTP 429. Ask again after this long.
    case rateLimited(retryAfter: TimeInterval)
    /// HTTP 5xx.
    case serverUnavailable(status: Int, retryAfter: TimeInterval)
    /// The request did not complete.
    case transport
    /// Any other status, redirects included.
    case unexpectedStatus(Int)
    case responseTooLarge
    case malformedResponse
}

/// The optional breached-account lookup (PRD F9.4):
/// `GET https://haveibeenpwned.com/api/v3/breachedaccount/<address>?truncateResponse=false` with the person's key in
/// `hibp-api-key` and the same `User-Agent` as the range client.
///
/// Nothing is cached and nothing is stored: the answer is about an identifier, and it goes back to the caller only.
public struct BreachedAccountClient: Sendable {
    static let maximumResponseBytes = 2 * 1024 * 1024
    static let maximumBreaches = 2000
    static let maximumDataClasses = 64
    static let defaultRateLimitWait: TimeInterval = 10
    static let defaultUnavailableWait: TimeInterval = 300

    private let http: any HTTPClient
    private let userAgent: HygieneUserAgent

    public init(http: any HTTPClient, userAgent: HygieneUserAgent) {
        self.http = http
        self.userAgent = userAgent
    }

    /// The one request a lookup makes.
    public func request(disclosing disclosure: IdentifierDisclosure, apiKey: HIBPAPIKey) -> HTTPRequest {
        HTTPRequest(
            url: .breachedAccount(disclosure.address),
            headers: ["hibp-api-key": apiKey.value, "User-Agent": userAgent.value],
            maximumResponseBytes: Self.maximumResponseBytes)
    }

    /// The breaches the disclosed address appears in, newest first; empty if the service knows of none.
    ///
    /// - Throws: `BreachedAccountError`, and nothing else.
    public func breaches(
        disclosing disclosure: IdentifierDisclosure, apiKey: HIBPAPIKey
    ) async throws -> [AccountBreach] {
        let request = request(disclosing: disclosure, apiKey: apiKey)
        let response: HTTPResponse
        do {
            response = try await http.send(request)
        } catch {
            throw BreachedAccountError.transport
        }
        switch response.status {
        case 200:
            break
        case 404:
            // The service's way of saying "in no breach".
            return []
        case 401:
            throw BreachedAccountError.keyRejected
        case 403:
            throw BreachedAccountError.forbidden
        case 429:
            let wait = RetryAfter.seconds(response.header("Retry-After")) ?? Self.defaultRateLimitWait
            throw BreachedAccountError.rateLimited(retryAfter: wait)
        case 500...599:
            let wait = RetryAfter.seconds(response.header("Retry-After")) ?? Self.defaultUnavailableWait
            throw BreachedAccountError.serverUnavailable(status: response.status, retryAfter: wait)
        default:
            throw BreachedAccountError.unexpectedStatus(response.status)
        }
        guard response.body.count <= request.maximumResponseBytes else { throw BreachedAccountError.responseTooLarge }
        return try Self.parse(response.body)
    }

    static func parse(_ body: [UInt8]) throws -> [AccountBreach] {
        guard body.count <= maximumResponseBytes else { throw BreachedAccountError.responseTooLarge }
        let wire: [WireBreach]
        do {
            wire = try JSONDecoder().decode([WireBreach].self, from: Data(body))
        } catch {
            throw BreachedAccountError.malformedResponse
        }
        guard wire.count <= maximumBreaches else { throw BreachedAccountError.responseTooLarge }
        var seen = Set<String>()
        var breaches: [AccountBreach] = []
        for entry in wire {
            let name = plainText(entry.name, limit: 128)
            // A breach with no name cannot be told from another; one named twice is listed once.
            guard !name.isEmpty, seen.insert(name).inserted else { continue }
            let title = plainText(entry.title ?? "", limit: 256)
            let domain = plainText(entry.domain ?? "", limit: 253)
            breaches.append(
                AccountBreach(
                    name: name,
                    title: title.isEmpty ? name : title,
                    domain: domain.isEmpty ? nil : domain,
                    breachDate: entry.breachDate.flatMap(isoDate),
                    accountCount: entry.accountCount,
                    dataClasses: (entry.dataClasses ?? []).prefix(maximumDataClasses)
                        .map { plainText($0, limit: 128) }.filter { !$0.isEmpty },
                    isVerified: entry.isVerified ?? false,
                    isSensitive: entry.isSensitive ?? false))
        }
        return breaches.sorted { lhs, rhs in
            if lhs.breachDate != rhs.breachDate { return (lhs.breachDate ?? "") > (rhs.breachDate ?? "") }
            return Array(lhs.name.utf8).lexicographicallyPrecedes(Array(rhs.name.utf8))
        }
    }

    /// `text` without control or formatting characters (bidirectional overrides included: this is shown to a
    /// person), cut to `limit` characters.
    static func plainText(_ text: String, limit: Int) -> String {
        var scalars = String.UnicodeScalarView()
        var kept = 0
        for scalar in text.unicodeScalars {
            guard kept < limit else { break }
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .surrogate, .privateUse, .unassigned:
                continue
            default:
                scalars.append(scalar)
                kept += 1
            }
        }
        return String(scalars).trimmingCharacters(in: .whitespaces)
    }

    /// `text` if it is `YYYY-MM-DD` with a plausible month and day.
    static func isoDate(_ text: String) -> String? {
        let bytes = Array(text.utf8)
        guard bytes.count == 10, bytes[4] == UInt8(ascii: "-"), bytes[7] == UInt8(ascii: "-") else { return nil }
        func number(_ range: Range<Int>) -> Int? {
            var value = 0
            for byte in bytes[range] {
                guard byte >= UInt8(ascii: "0"), byte <= UInt8(ascii: "9") else { return nil }
                value = value * 10 + Int(byte - UInt8(ascii: "0"))
            }
            return value
        }
        guard number(0..<4) != nil, let month = number(5..<7), let day = number(8..<10) else { return nil }
        guard (1...12).contains(month), (1...31).contains(day) else { return nil }
        return text
    }

    /// The fields read from the service's breach model. Only the name is required; a field of the wrong type is
    /// treated as absent.
    private struct WireBreach: Decodable {
        var name: String
        var title: String?
        var domain: String?
        var breachDate: String?
        var accountCount: UInt64?
        var dataClasses: [String]?
        var isVerified: Bool?
        var isSensitive: Bool?

        enum CodingKeys: String, CodingKey {
            case name = "Name"
            case title = "Title"
            case domain = "Domain"
            case breachDate = "BreachDate"
            case accountCount = "PwnCount"
            case dataClasses = "DataClasses"
            case isVerified = "IsVerified"
            case isSensitive = "IsSensitive"
        }

        init(from decoder: any Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            name = try container.decode(String.self, forKey: .name)
            title = try? container.decode(String.self, forKey: .title)
            domain = try? container.decode(String.self, forKey: .domain)
            breachDate = try? container.decode(String.self, forKey: .breachDate)
            accountCount = try? container.decode(UInt64.self, forKey: .accountCount)
            dataClasses = try? container.decode([String].self, forKey: .dataClasses)
            isVerified = try? container.decode(Bool.self, forKey: .isVerified)
            isSensitive = try? container.decode(Bool.self, forKey: .isSensitive)
        }
    }
}
