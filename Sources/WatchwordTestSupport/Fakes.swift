import Foundation
import SecureMemory
import WatchwordKit

/// A wall clock tests move by hand, so time-based policy (F5.4 expiry, F5.5 auto-lock, F1.4/F1.5 retention) is tested
/// without sleeping (CLAUDE.md, "Tests").
public actor FakeClock: WallClock {
    private var current: Date

    public init(_ start: Date = Date(timeIntervalSince1970: 1_800_000_000)) {
        current = start
    }

    public func now() -> Date {
        current
    }

    public func advance(by interval: TimeInterval) {
        current = current.addingTimeInterval(interval)
    }

    public func set(_ date: Date) {
        current = date
    }
}

/// A biometric gate whose enrolment the test controls (docs/04-test-plan.md §2).
public actor FakeBiometricGate: BiometricGate {
    private var state: BiometricEnrolment

    public init(_ state: BiometricEnrolment = .enrolled(domainState: [0x01, 0x02, 0x03])) {
        self.state = state
    }

    public func enrolment() -> BiometricEnrolment {
        state
    }

    public func set(_ state: BiometricEnrolment) {
        self.state = state
    }
}

/// A Keychain that simulates what the real one does to the quick-unlock item (docs/04-test-plan.md §2): scripted
/// biometric outcomes, invalidation on enrolment change, and a way to make it release the wrong bytes.
public actor FakeKeychain: KeychainStore {
    /// What the next biometric prompt (a read of `.quickUnlockKey`) does.
    public enum BiometricOutcome: Sendable {
        case succeed
        case fail
        case cancel
        /// The OS released something, but not the stored key: models a Keychain that has been tampered with or a
        /// buggy adapter. Unlock must still fail.
        case releaseBytes([UInt8])
        /// The item is gone, as after `biometryCurrentSet` invalidation.
        case invalidated
    }

    private var items: [KeychainItem: [UInt8]] = [:]
    private var outcomes: [BiometricOutcome] = []
    public private(set) var biometricPrompts = 0
    public private(set) var prompts: [String] = []

    public init() {}

    public func store(_ value: SecureBytes, for item: KeychainItem) {
        items[item] = value.unprotectedCopy()
    }

    public func read(_ item: KeychainItem, prompt: String) throws -> SecureBytes? {
        guard case .quickUnlockKey = item else {
            return items[item].map { SecureBytes(copying: $0) }
        }
        biometricPrompts += 1
        prompts.append(prompt)
        let outcome = outcomes.isEmpty ? .succeed : outcomes.removeFirst()
        switch outcome {
        case .succeed: return items[item].map { SecureBytes(copying: $0) }
        case .fail: throw KeychainError.authenticationFailed
        case .cancel: throw KeychainError.userCancelled
        case .releaseBytes(let bytes): return SecureBytes(copying: bytes)
        case .invalidated:
            items[item] = nil
            return nil
        }
    }

    public func delete(_ item: KeychainItem) {
        items[item] = nil
    }

    // MARK: Scripting

    public func script(_ outcomes: BiometricOutcome...) {
        self.outcomes.append(contentsOf: outcomes)
    }

    /// Drops every biometry-bound item, as the OS does when the enrolled set changes.
    public func invalidateBiometricItems() {
        for key in items.keys {
            if case .quickUnlockKey = key { items[key] = nil }
        }
    }

    public func contains(_ item: KeychainItem) -> Bool {
        items[item] != nil
    }

    public func raw(_ item: KeychainItem) -> [UInt8]? {
        items[item]
    }

    public func overwrite(_ item: KeychainItem, with bytes: [UInt8]) {
        items[item] = bytes
    }

    public var isEmpty: Bool {
        items.isEmpty
    }
}
