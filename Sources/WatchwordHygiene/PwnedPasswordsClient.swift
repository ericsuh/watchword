import Foundation

/// Why a breach check did not produce an answer. Never "not breached": a check that could not be completed is
/// unknown, and the item stays due.
public enum PwnedPasswordsError: Error, Hashable, Sendable {
    /// HTTP 429. Ask again after this long (the server's `Retry-After`, within bounds).
    case rateLimited(retryAfter: TimeInterval)
    /// HTTP 5xx. Ask again after this long.
    case serverUnavailable(status: Int, retryAfter: TimeInterval)
    /// The request did not complete: offline, timed out, TLS failure, or a body over the size limit.
    case transport
    /// Any other status. A redirect is one of these: the client does not follow it.
    case unexpectedStatus(Int)
    /// The body was larger than a range can be.
    case responseTooLarge
    /// The body was not a range.
    case malformedResponse
    /// The caller withdrew permission while the request was in flight (the vault locked). Nothing was stored.
    case interrupted

    /// Whether asking again later can succeed without anything changing on this side.
    public var isRetryable: Bool {
        switch self {
        case .rateLimited, .serverUnavailable, .transport: return true
        case .unexpectedStatus, .responseTooLarge, .malformedResponse, .interrupted: return false
        }
    }

    /// How long the server asked the client to stay away, if it did.
    public var retryAfter: TimeInterval? {
        switch self {
        case .rateLimited(let interval), .serverUnavailable(_, let interval): return interval
        case .transport, .unexpectedStatus, .responseTooLarge, .malformedResponse, .interrupted: return nil
        }
    }
}

/// One answered check.
public struct PwnedCheck: Hashable, Sendable {
    public enum Source: Hashable, Sendable {
        /// Answered from the prefix cache: nothing left the device.
        case cache
        /// One range request was made.
        case network
    }

    public let result: PwnedPasswordResult
    public let source: Source
    /// When the range that answered was fetched.
    public let rangeFetchedAt: Date
}

/// The Pwned Passwords range client (PRD F9.1, docs/02-architecture.md §13).
///
/// What leaves the device for one check is one `GET https://api.pwnedpasswords.com/range/XXXXX`, where `XXXXX` is the
/// first five hexadecimal characters of the password's SHA-1, with `Add-Padding: true` (so the response's size says
/// nothing about the range) and `User-Agent: Watchword/<version>`. Nothing else: no cookie, no identifier, no other
/// header. The host, the scheme and the path's shape are constants of this type; no parameter, setting or response
/// changes them, and a redirect is refused.
///
/// The comparison with the range happens here, on the device (`PwnedRange.result(for:)`).
public struct PwnedPasswordsClient: Sendable {
    /// How long a cached range answers checks (PRD F9.1).
    public static let cacheLifetime: TimeInterval = 7 * 24 * 60 * 60
    /// When the server gives no usable `Retry-After`.
    static let defaultRateLimitWait: TimeInterval = 60
    static let defaultUnavailableWait: TimeInterval = 300

    private let http: any HTTPClient
    private let cache: any PwnedRangeCache
    private let userAgent: HygieneUserAgent

    public init(http: any HTTPClient, cache: any PwnedRangeCache, userAgent: HygieneUserAgent) {
        self.http = http
        self.cache = cache
        self.userAgent = userAgent
    }

    /// The one request this client makes for `prefix`.
    public func request(for prefix: PwnedRangePrefix) -> HTTPRequest {
        HTTPRequest(
            url: .pwnedRange(prefix),
            headers: ["Add-Padding": "true", "User-Agent": userAgent.value],
            maximumResponseBytes: PwnedRangeParser.maximumBytes)
    }

    /// Whether the password behind `digest` is in the breach corpus.
    ///
    /// - Parameters:
    ///   - now: the time, from the caller's clock; cache expiry is measured against it.
    ///   - freshAfter: if given, a cached range fetched before this is not used. The weekly re-scan passes the time
    ///     its pass began, so the pass really asks again while still asking once per prefix.
    ///   - stillAuthorised: asked after the network returns and before anything is stored or answered, and again
    ///     once the range is in the cache. `HygieneEngine` passes "the vault has not locked since this check
    ///     began", so a lock during the request or the store wins: the response is dropped, the cache does not keep
    ///     it, and the check throws `.interrupted`.
    /// - Throws: `PwnedPasswordsError`, and nothing else.
    public func check(
        _ digest: PasswordDigest, now: Date, freshAfter: Date? = nil,
        stillAuthorised: @Sendable () async -> Bool = { true }
    ) async throws -> PwnedCheck {
        let prefix = digest.prefix
        if let cached = await cache.cachedRange(for: prefix), Self.isUsable(cached, now: now, freshAfter: freshAfter),
            let result = cached.range.result(for: digest)
        {
            return PwnedCheck(result: result, source: .cache, rangeFetchedAt: cached.fetchedAt)
        }
        let range = try await fetchRange(prefix)
        guard await stillAuthorised() else { throw PwnedPasswordsError.interrupted }
        guard let result = range.result(for: digest) else { throw PwnedPasswordsError.malformedResponse }
        await cache.store(CachedPwnedRange(range: range, fetchedAt: now))
        // Asked again, because the store suspended: a lock that landed between the question above and the entry
        // reaching the cache has already emptied the cache, and this entry would have outlived it. Whenever the
        // lock came, either it runs after this store (and removes the entry) or this check runs after it.
        guard await stillAuthorised() else {
            await cache.remove(prefix)
            throw PwnedPasswordsError.interrupted
        }
        return PwnedCheck(result: result, source: .network, rangeFetchedAt: now)
    }

    /// The vault is locking: the cache drops whatever it holds in memory (`PwnedRangeCache.lock`). Which prefixes
    /// were looked up is derived from the person's passwords, so it goes when the keys go (ADR 0005, amendment).
    public func lockCache() async {
        await cache.lock()
    }

    /// A cached range answers only if it is for the right prefix (a cache is storage, and storage can be wrong), was
    /// fetched in the last seven days, and not in the future: a clock that went backwards, or a planted entry dated
    /// years ahead, must not make an entry immortal.
    static func isUsable(_ cached: CachedPwnedRange, now: Date, freshAfter: Date?) -> Bool {
        let age = now.timeIntervalSince(cached.fetchedAt)
        guard age >= 0, age < cacheLifetime else { return false }
        if let freshAfter, cached.fetchedAt < freshAfter { return false }
        return true
    }

    /// Fetches and parses one range. No cache, no hashing: the prefix is all it is given.
    func fetchRange(_ prefix: PwnedRangePrefix) async throws -> PwnedRange {
        let request = request(for: prefix)
        let response: HTTPResponse
        do {
            response = try await http.send(request)
        } catch {
            throw PwnedPasswordsError.transport
        }
        switch response.status {
        case 200:
            break
        case 429:
            let wait = RetryAfter.seconds(response.header("Retry-After")) ?? Self.defaultRateLimitWait
            throw PwnedPasswordsError.rateLimited(retryAfter: wait)
        case 500...599:
            let wait = RetryAfter.seconds(response.header("Retry-After")) ?? Self.defaultUnavailableWait
            throw PwnedPasswordsError.serverUnavailable(status: response.status, retryAfter: wait)
        default:
            throw PwnedPasswordsError.unexpectedStatus(response.status)
        }
        // The adapter was told the limit; this is the check that does not depend on it having listened.
        guard response.body.count <= request.maximumResponseBytes else { throw PwnedPasswordsError.responseTooLarge }
        do {
            return try PwnedRangeParser.parse(response.body, prefix: prefix).range
        } catch PwnedRangeParseError.tooLarge, PwnedRangeParseError.tooManyLines {
            throw PwnedPasswordsError.responseTooLarge
        } catch {
            throw PwnedPasswordsError.malformedResponse
        }
    }
}
