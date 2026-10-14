import Foundation

/// Settings for quick-unlock expiry (PRD F5.4).
public struct QuickUnlockSettings: Sendable, Hashable, Codable {
    /// The password is required again this long after it was last entered. Default 14 days.
    public var passwordInterval: TimeInterval
    /// Consecutive failed biometric attempts that disable quick unlock until the password is entered. Default 3.
    public var maximumFailedAttempts: Int

    public init(passwordInterval: TimeInterval = 14 * 24 * 60 * 60, maximumFailedAttempts: Int = 3) {
        self.passwordInterval = passwordInterval
        self.maximumFailedAttempts = maximumFailedAttempts
    }

    public static let standard = QuickUnlockSettings()
}

/// What quick unlock was enrolled against, kept in the Keychain beside the Local Unlock Key (docs/02-architecture.md
/// §6). Everything here is a policy input or ciphertext; the Local Unlock Key itself is a separate, biometry-bound item.
public struct QuickUnlockState: Sendable, Hashable, Codable {
    public var enrolledAt: Date
    public var lastPasswordUnlockAt: Date
    public var failedAttempts: Int
    /// The app version that enrolled; an update requires the password again.
    public var appVersion: String
    /// `AccountRecord.credentialGeneration` at enrolment; a password or Secret Key change requires the password again.
    public var credentialGeneration: UInt64
    /// `LAContext.evaluatedPolicyDomainState` at enrolment.
    public var biometricDomainState: Data
    /// Key ID of the Local Unlock Key.
    public var unlockKeyID: UUID
    /// Key ID of the Account Unlock Key that `wrappedAccountUnlockKey` contains.
    public var accountUnlockKeyID: UUID
    /// AUK sealed under the Local Unlock Key (an `.accountHeader` envelope).
    public var wrappedAccountUnlockKey: Data

    public init(
        enrolledAt: Date,
        lastPasswordUnlockAt: Date,
        failedAttempts: Int,
        appVersion: String,
        credentialGeneration: UInt64,
        biometricDomainState: Data,
        unlockKeyID: UUID,
        accountUnlockKeyID: UUID,
        wrappedAccountUnlockKey: Data
    ) {
        self.enrolledAt = enrolledAt
        self.lastPasswordUnlockAt = lastPasswordUnlockAt
        self.failedAttempts = failedAttempts
        self.appVersion = appVersion
        self.credentialGeneration = credentialGeneration
        self.biometricDomainState = biometricDomainState
        self.unlockKeyID = unlockKeyID
        self.accountUnlockKeyID = accountUnlockKeyID
        self.wrappedAccountUnlockKey = wrappedAccountUnlockKey
    }
}

/// Why quick unlock is refused and the password is required (PRD F5.3, F5.4).
public enum QuickUnlockRefusal: Error, Sendable, Hashable {
    case notEnabled
    case biometryUnavailable
    case enrolmentChanged
    case credentialsChanged
    case appUpdated
    /// The clock reads earlier than the last password unlock. The interval cannot be measured, so it is treated as
    /// expired rather than as zero.
    case clockMovedBackwards
    case passwordIntervalExpired
    case tooManyFailedAttempts
}

public enum UnlockDecision: Sendable, Hashable {
    case allowed
    case requirePassword(QuickUnlockRefusal)
}

/// The quick-unlock policy as a pure function (docs/02-architecture.md §10), so every expiry reason of F5.4 is a table
/// test rather than a device experiment. The AutoFill extension evaluates the same function.
///
/// Passing this policy is necessary but never sufficient: the Keychain must still release the Local Unlock Key, and that
/// key must still open the wrapped AUK, which must still open the keyset.
public enum UnlockPolicy {
    public static func evaluate(
        now: Date,
        state: QuickUnlockState?,
        currentAppVersion: String,
        currentCredentialGeneration: UInt64,
        enrolment: BiometricEnrolment,
        settings: QuickUnlockSettings
    ) -> UnlockDecision {
        guard let state else { return .requirePassword(.notEnabled) }
        guard case .enrolled(let domainState) = enrolment else { return .requirePassword(.biometryUnavailable) }
        // Compared as bytes; the domain state is an opaque OS value, not a secret.
        guard Data(domainState) == state.biometricDomainState else { return .requirePassword(.enrolmentChanged) }
        guard state.credentialGeneration == currentCredentialGeneration else {
            return .requirePassword(.credentialsChanged)
        }
        guard state.appVersion == currentAppVersion else { return .requirePassword(.appUpdated) }
        let elapsed = now.timeIntervalSince(state.lastPasswordUnlockAt)
        guard elapsed >= 0 else { return .requirePassword(.clockMovedBackwards) }
        guard elapsed < settings.passwordInterval else { return .requirePassword(.passwordIntervalExpired) }
        guard state.failedAttempts < settings.maximumFailedAttempts else {
            return .requirePassword(.tooManyFailedAttempts)
        }
        return .allowed
    }
}
