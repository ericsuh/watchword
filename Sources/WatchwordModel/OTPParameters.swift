import Foundation

public enum OTPAuthError: Error, Equatable, Sendable {
    case tooLong
    case notAnOTPAuthURI
    /// `hotp` and anything else that is not `totp`: counter-based codes need a counter synced on every use, which a
    /// multi-device vault cannot promise.
    case unsupportedType(String)
    case missingSecret
    case malformedSecret
    case secretLength(Int)
    case unsupportedAlgorithm(String)
    case digitsOutOfRange(String)
    case periodOutOfRange(String)
    case duplicateParameter(String)
}

/// The parameters of a time-based one-time password (RFC 6238), as carried by a `.totp` field's `otpauth://totp/…`
/// URI (PRD F1.2). Parsing and formatting only; computing a code needs HMAC and lives in `WatchwordAutoFill`.
///
/// The URI comes from a QR code, an import file or another member of a shared vault, so the parser is bounded on both
/// sides (SEC9): a `period` of zero would divide by zero, a `digits` of 40 would overflow, and an empty secret would
/// produce codes anyone can compute.
public struct OTPParameters: Hashable, Sendable {
    public enum Algorithm: String, Sendable, CaseIterable {
        case sha1 = "SHA1"
        case sha256 = "SHA256"
        case sha512 = "SHA512"
    }

    public static let maximumURILength = 4096
    /// RFC 4226 asks for 128 bits; deployed services still issue 80, so that is the floor.
    public static let secretLengthRange = 10...128
    public static let digitsRange = 6...8
    public static let periodRange = 15...300

    /// The shared secret, decoded.
    public var secret: Data
    public var algorithm: Algorithm
    public var digits: Int
    /// Seconds each code is valid for.
    public var period: Int
    public var issuer: String?
    public var account: String?

    public init(
        secret: Data, algorithm: Algorithm = .sha1, digits: Int = 6, period: Int = 30, issuer: String? = nil,
        account: String? = nil
    ) throws {
        guard OTPParameters.secretLengthRange.contains(secret.count) else {
            throw OTPAuthError.secretLength(secret.count)
        }
        guard OTPParameters.digitsRange.contains(digits) else { throw OTPAuthError.digitsOutOfRange(String(digits)) }
        guard OTPParameters.periodRange.contains(period) else { throw OTPAuthError.periodOutOfRange(String(period)) }
        self.secret = secret
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.issuer = issuer
        self.account = account
    }

    /// Parses `otpauth://totp/Issuer:account?secret=BASE32&issuer=…&algorithm=…&digits=…&period=…`. Unknown
    /// parameters are ignored; a known parameter given twice is refused rather than resolved by position.
    public init(uri: String) throws {
        guard uri.utf8.count <= OTPParameters.maximumURILength else { throw OTPAuthError.tooLong }
        guard let components = URLComponents(string: uri), components.scheme?.lowercased() == "otpauth",
            let type = components.host?.lowercased()
        else { throw OTPAuthError.notAnOTPAuthURI }
        guard type == "totp" else { throw OTPAuthError.unsupportedType(type) }

        var parameters: [String: String] = [:]
        for item in components.queryItems ?? [] {
            let name = item.name.lowercased()
            guard ["secret", "issuer", "algorithm", "digits", "period"].contains(name) else { continue }
            guard parameters.updateValue(item.value ?? "", forKey: name) == nil else {
                throw OTPAuthError.duplicateParameter(name)
            }
        }
        guard let encoded = parameters["secret"], !encoded.isEmpty else { throw OTPAuthError.missingSecret }
        // Authenticator apps display secrets in groups; spaces and hyphens between groups are not part of the value.
        let compact = encoded.filter { $0 != " " && $0 != "-" }
        guard let secret = Base32.decode(compact) else { throw OTPAuthError.malformedSecret }

        var algorithm = Algorithm.sha1
        if let name = parameters["algorithm"] {
            let folded = name.uppercased().replacingOccurrences(of: "-", with: "")
            guard let known = Algorithm(rawValue: folded) else { throw OTPAuthError.unsupportedAlgorithm(name) }
            algorithm = known
        }
        var digits = 6
        if let text = parameters["digits"] {
            guard let value = Int(text) else { throw OTPAuthError.digitsOutOfRange(text) }
            digits = value
        }
        var period = 30
        if let text = parameters["period"] {
            guard let value = Int(text) else { throw OTPAuthError.periodOutOfRange(text) }
            period = value
        }

        // The label is `/Issuer:account` or `/account`; the `issuer` parameter wins over the label's prefix.
        var label = components.path
        if label.hasPrefix("/") { label.removeFirst() }
        var issuer = parameters["issuer"].flatMap { $0.isEmpty ? nil : $0 }
        var account: String? = label.isEmpty ? nil : label
        if let colon = label.firstIndex(of: ":") {
            let prefix = String(label[..<colon]).trimmingCharacters(in: CharacterSet(charactersIn: " "))
            let rest = String(label[label.index(after: colon)...]).trimmingCharacters(
                in: CharacterSet(charactersIn: " "))
            issuer = issuer ?? (prefix.isEmpty ? nil : prefix)
            account = rest.isEmpty ? nil : rest
        }
        try self.init(
            secret: secret, algorithm: algorithm, digits: digits, period: period, issuer: issuer, account: account)
    }

    /// The canonical URI: every parameter explicit, the secret upper-case and unpadded.
    public var uri: String {
        var components = URLComponents()
        components.scheme = "otpauth"
        components.host = "totp"
        switch (issuer, account) {
        case (let issuer?, let account?): components.path = "/\(issuer):\(account)"
        case (nil, let account?): components.path = "/\(account)"
        case (let issuer?, nil): components.path = "/\(issuer):"
        case (nil, nil): components.path = "/"
        }
        var query = [URLQueryItem(name: "secret", value: Base32.encode(secret))]
        if let issuer {
            query.append(URLQueryItem(name: "issuer", value: issuer))
        }
        query.append(URLQueryItem(name: "algorithm", value: algorithm.rawValue))
        query.append(URLQueryItem(name: "digits", value: String(digits)))
        query.append(URLQueryItem(name: "period", value: String(period)))
        components.queryItems = query
        return components.string ?? ""
    }
}

extension Field {
    /// The parameters of a `.totp` field. Throws for any other kind, and for a value that is not a usable
    /// `otpauth://totp/` URI.
    public func otpParameters() throws -> OTPParameters {
        guard kind == .totp else { throw OTPAuthError.notAnOTPAuthURI }
        return try OTPParameters(uri: value)
    }
}
