import Foundation
import SecureMemory

/// The Keychain items Watchword keeps per account (docs/02-architecture.md §6). All are device-only
/// (`WhenPasscodeSetThisDeviceOnly`, never synchronisable; ADR 0004) and in the access group shared with the AutoFill
/// extension.
public enum KeychainItem: Hashable, Sendable {
    /// The 16-byte Secret Key. No access-control prompt: unlocking already requires the password.
    case secretKey(accountID: UUID)
    /// The 32-byte Local Unlock Key that wraps the Account Unlock Key for quick unlock. Released by the OS only after
    /// biometric authentication against the *current* enrolment (`biometryCurrentSet`), so re-enrolment destroys it
    /// (PRD F5.3).
    case quickUnlockKey(accountID: UUID)
    /// `QuickUnlockState`: the wrapped AUK and the policy inputs of F5.4. Not secret on its own (it is useless without
    /// the Local Unlock Key) but kept in the Keychain so the failure counter cannot be reset by editing a file.
    case quickUnlockState(accountID: UUID)

    public var accountID: UUID {
        switch self {
        case .secretKey(let id), .quickUnlockKey(let id), .quickUnlockState(let id): return id
        }
    }
}

public enum KeychainError: Error, Equatable, Sendable {
    /// The person dismissed the biometric prompt. Not counted as a failed attempt.
    case userCancelled
    /// Biometric authentication failed. Counted towards the F5.4 limit.
    case authenticationFailed
    /// Biometrics are locked out, unavailable or not enrolled.
    case biometryUnavailable
    /// The device is locked, so the item's accessibility class does not allow access right now.
    case interactionNotAllowed
    /// Anything else, with the raw status for diagnostics. Never carries item contents.
    case unexpectedStatus(Int32)
}

/// Keychain port (docs/02-architecture.md §15). Production: `WatchwordPlatform.SystemKeychainStore`.
///
/// Reading `.quickUnlockKey` is the biometric check. There is deliberately no separate "did biometrics succeed"
/// boolean anywhere in the unlock path (§1 principle 4): the only thing that unlocks is key material the OS released.
public protocol KeychainStore: Sendable {
    /// Stores `value`, replacing any existing item.
    func store(_ value: SecureBytes, for item: KeychainItem) async throws
    /// The item's bytes, or `nil` if there is none (including an item the OS invalidated after re-enrolment).
    /// `prompt` is the reason shown by a biometric prompt for `.quickUnlockKey`; it is ignored for other items.
    func read(_ item: KeychainItem, prompt: String) async throws -> SecureBytes?
    /// Deletes the item; succeeds if it does not exist.
    func delete(_ item: KeychainItem) async throws
}

/// What the device's biometric enrolment looks like right now.
public enum BiometricEnrolment: Sendable, Hashable {
    /// Biometrics (or, on the Mac, a paired Watch) can authenticate. `domainState` changes whenever the enrolled set
    /// changes (`LAContext.evaluatedPolicyDomainState`).
    case enrolled(domainState: [UInt8])
    case unavailable
}

/// Biometric capability port. Production: `WatchwordPlatform.LocalAuthenticationGate`.
///
/// It reports enrolment only; it cannot authorise anything. Authentication happens inside the Keychain read of the
/// Local Unlock Key, which is what makes the "boolean bypass" impossible to express (docs/04-test-plan.md §6.2).
public protocol BiometricGate: Sendable {
    func enrolment() async -> BiometricEnrolment
}

/// Wall-clock port, for the policy decisions measured in days (F5.4) and minutes (F5.5). Tests advance a fake.
public protocol WallClock: Sendable {
    func now() async -> Date
}

public struct SystemWallClock: WallClock {
    public init() {}

    public func now() -> Date {
        Date()
    }
}
