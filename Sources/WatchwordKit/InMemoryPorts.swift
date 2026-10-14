import Foundation
import SecureMemory

/// A `KeychainStore` held in process memory, for SwiftUI previews and UI-test launches of the app (which construct
/// themselves without the system Keychain; docs/04-test-plan.md §2). Values are kept in `SecureBytes` copies and
/// zeroised when replaced or deleted. It has no biometric binding at all, so it must never back a real account: the
/// app only builds it in Debug configurations.
public actor InMemoryKeychainStore: KeychainStore {
    private var items: [KeychainItem: SecureBytes] = [:]

    public init() {}

    public func store(_ value: SecureBytes, for item: KeychainItem) {
        items[item]?.zeroise()
        items[item] = value.extracting(0..<value.count)
    }

    public func read(_ item: KeychainItem, prompt: String) -> SecureBytes? {
        items[item].map { $0.extracting(0..<$0.count) }
    }

    public func delete(_ item: KeychainItem) {
        items[item]?.zeroise()
        items[item] = nil
    }
}

/// A `BiometricGate` for devices, simulators and previews without biometrics.
public struct UnavailableBiometricGate: BiometricGate {
    public init() {}

    public func enrolment() -> BiometricEnrolment {
        .unavailable
    }
}
