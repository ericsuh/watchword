import Foundation

public enum KDFAlgorithm: String, Codable, Sendable, Hashable {
    /// CommonCrypto PBKDF2 with HMAC-SHA256 (ADR 0003).
    case pbkdf2HmacSha256 = "PBKDF2-HMAC-SHA256"
}

public enum KDFValidationError: Error, Equatable, Sendable {
    case iterationsBelowMinimum(UInt32, minimum: UInt32)
    /// A header asking for far more work than any device would calibrate to is an availability
    /// attack: a compromised sync store sets it and every unlock afterwards hangs.
    case iterationsAboveMaximum(UInt32, maximum: UInt32)
    case saltTooShort(Int, minimum: Int)
    case saltTooLong(Int, maximum: Int)
    case outputLengthUnsupported(Int)
}

/// Parameters stored in the account header. Enforced floors prevent a tampered header from
/// weakening key derivation (PRD SEC5).
public struct KDFParameters: Codable, Sendable, Hashable {
    public static let minimumIterations: UInt32 = 650_000
    /// Roughly 40x the floor: enough headroom for calibration on fast hardware and for raising
    /// the floor over time, while bounding a hostile header to seconds rather than hours.
    public static let maximumIterations: UInt32 = 25_000_000
    public static let minimumSaltLength = 16
    public static let maximumSaltLength = 1024
    public static let outputLength = 32

    public var algorithm: KDFAlgorithm
    public var iterations: UInt32
    public var saltLength: Int
    public var outputLength: Int

    public init(
        algorithm: KDFAlgorithm = .pbkdf2HmacSha256,
        iterations: UInt32,
        saltLength: Int = 32,
        outputLength: Int = KDFParameters.outputLength
    ) {
        self.algorithm = algorithm
        self.iterations = iterations
        self.saltLength = saltLength
        self.outputLength = outputLength
    }

    /// The parameters a freshly created account uses before device calibration raises them.
    public static let baseline = KDFParameters(iterations: minimumIterations)

    public func validate() throws {
        if iterations < KDFParameters.minimumIterations {
            throw KDFValidationError.iterationsBelowMinimum(iterations, minimum: KDFParameters.minimumIterations)
        }
        if iterations > KDFParameters.maximumIterations {
            throw KDFValidationError.iterationsAboveMaximum(iterations, maximum: KDFParameters.maximumIterations)
        }
        if saltLength < KDFParameters.minimumSaltLength {
            throw KDFValidationError.saltTooShort(saltLength, minimum: KDFParameters.minimumSaltLength)
        }
        if saltLength > KDFParameters.maximumSaltLength {
            throw KDFValidationError.saltTooLong(saltLength, maximum: KDFParameters.maximumSaltLength)
        }
        if outputLength != KDFParameters.outputLength {
            throw KDFValidationError.outputLengthUnsupported(outputLength)
        }
    }

    /// Decoding a header validates it, so an out-of-policy header never reaches the KDF.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let algorithm = try container.decode(KDFAlgorithm.self, forKey: .algorithm)
        let iterations = try container.decode(UInt32.self, forKey: .iterations)
        let saltLength = try container.decode(Int.self, forKey: .saltLength)
        let outputLength = try container.decode(Int.self, forKey: .outputLength)
        let params = KDFParameters(
            algorithm: algorithm, iterations: iterations, saltLength: saltLength, outputLength: outputLength)
        try params.validate()
        self = params
    }

    private enum CodingKeys: String, CodingKey {
        case algorithm, iterations, saltLength, outputLength
    }
}
