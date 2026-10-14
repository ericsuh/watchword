#if canImport(LocalAuthentication)
    import LocalAuthentication

    /// `LAContext.canEvaluatePolicy(_:error:)`, whose error out-parameter is an `AutoreleasingUnsafeMutablePointer` even
    /// when `nil` is passed, so ADR 0001 puts the call here. `WatchwordPlatform.LocalAuthenticationGate` uses it to read
    /// the biometric enrolment; nothing here authenticates.
    public enum LocalAuthenticationBridge {
        public static func canEvaluate(_ policy: LAPolicy, in context: LAContext) -> Bool {
            unsafe (context.canEvaluatePolicy(policy, error: nil))
        }
    }
#endif
