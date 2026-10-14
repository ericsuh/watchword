#if canImport(CryptoKit) && canImport(CommonCrypto)
    import Foundation
    import SecureMemory
    import WatchwordEnvelope

    /// Picks PBKDF2 iterations for a new account from a timed probe on this device (ADR 0003: at least 650,000 and at
    /// least 300 ms on the creating device).
    ///
    /// The result is always inside `KDFParameters`' two-sided bounds: a slow device gets the floor, never less, and a
    /// broken clock that reports zero time gets the floor rather than the ceiling, because the floor is already the
    /// security baseline and the ceiling is only an availability bound.
    public enum KDFCalibration {
        public static let targetDuration: Duration = .milliseconds(300)
        public static let probeIterations: UInt32 = 50_000

        /// Pure core of calibration, separated so it is testable without timing anything.
        public static func iterations(
            probeIterations: UInt32,
            probeDuration: Duration,
            target: Duration = targetDuration
        ) -> UInt32 {
            let probeSeconds = seconds(probeDuration)
            let targetSeconds = seconds(target)
            guard probeIterations > 0, probeSeconds > 0, targetSeconds > 0 else {
                return KDFParameters.minimumIterations
            }
            let needed = (Double(probeIterations) * targetSeconds / probeSeconds).rounded(.up)
            guard needed.isFinite else { return KDFParameters.maximumIterations }
            let clamped = min(
                max(needed, Double(KDFParameters.minimumIterations)), Double(KDFParameters.maximumIterations))
            return UInt32(clamped)
        }

        /// Times one PBKDF2 probe with `clock` and scales it to `target`. Production passes `ContinuousClock()`.
        public static func calibrate<C: Clock>(
            clock: C,
            target: Duration = targetDuration,
            saltLength: Int = 32
        ) throws -> KDFParameters where C.Duration == Duration {
            var generator = SystemRandomNumberGenerator()
            let password = SecureBytes(randomCount: 32, using: &generator)
            let salt = Array(SecureBytes(randomCount: saltLength, using: &generator))
            let elapsed = try clock.measure {
                try PBKDF2.sha256(password: password, salt: salt, iterations: probeIterations, outputByteCount: 32)
                    .zeroise()
            }
            password.zeroise()
            let parameters = KDFParameters(
                iterations: iterations(probeIterations: probeIterations, probeDuration: elapsed, target: target),
                saltLength: saltLength
            )
            try parameters.validate()
            return parameters
        }

        static func seconds(_ duration: Duration) -> Double {
            let components = duration.components
            return Double(components.seconds) + Double(components.attoseconds) / 1e18
        }
    }
#endif
