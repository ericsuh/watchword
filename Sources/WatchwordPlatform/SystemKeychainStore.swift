#if canImport(Security) && canImport(LocalAuthentication)
    import Foundation
    import LocalAuthentication
    import Security
    import SecureMemory
    import WatchwordKit

    /// The production `KeychainStore` (docs/02-architecture.md §6, ADR 0004).
    ///
    /// Every item is a generic password in the data-protection Keychain (`kSecUseDataProtectionKeychain`, so macOS
    /// gets iOS semantics), in the access group shared with the AutoFill extension, never synchronisable, and
    /// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`: it never leaves this device, is unreadable while the device is
    /// locked, and is destroyed if the device passcode is removed.
    ///
    /// The Local Unlock Key additionally carries an access control of `biometryCurrentSet` (iOS) or `biometryCurrentSet
    /// or companion` (macOS, F5.3: Touch ID or a paired Apple Watch). The OS releases it only after authenticating
    /// against the enrolment that existed when it was stored, and invalidates it when that enrolment changes.
    public struct SystemKeychainStore: KeychainStore {
        public let service: String
        /// `nil` uses the app's default access group (the first in its entitlement).
        public let accessGroup: String?

        public init(service: String, accessGroup: String?) {
            self.service = service
            self.accessGroup = accessGroup
        }

        public func store(_ value: SecureBytes, for item: KeychainItem) throws {
            try delete(item)
            var attributes = baseQuery(for: item)
            attributes.merge(try Self.protectionAttributes(for: item)) { _, new in new }
            // The Security framework takes the secret as CFData; this copy is the price of using the Keychain at all.
            attributes[kSecValueData as String] = Data(value.unprotectedCopy())
            let status = SecItemAdd(attributes as CFDictionary, nil)
            guard status == errSecSuccess else { throw Self.error(for: status) }
        }

        public func read(_ item: KeychainItem, prompt: String) throws -> SecureBytes? {
            var query = baseQuery(for: item)
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            let context = LAContext()
            if case .quickUnlockKey = item {
                context.localizedReason = prompt
            } else {
                // No item but the Local Unlock Key may ever show UI.
                context.interactionNotAllowed = true
            }
            query[kSecUseAuthenticationContext as String] = context
            switch KeychainBridge.copyData(matching: query as CFDictionary) {
            case .found(let bytes): return bytes
            case .notFound: return nil
            case .failure(let status): throw Self.error(for: status)
            }
        }

        public func delete(_ item: KeychainItem) throws {
            let status = SecItemDelete(baseQuery(for: item) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { throw Self.error(for: status) }
        }

        // MARK: - Queries (pure, so the security-relevant attributes are unit-tested)

        /// The attributes that identify an item.
        public func baseQuery(for item: KeychainItem) -> [String: Any] {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: Self.accountName(for: item),
                kSecAttrSynchronizable as String: false,
                kSecUseDataProtectionKeychain as String: true,
            ]
            if let accessGroup {
                query[kSecAttrAccessGroup as String] = accessGroup
            }
            return query
        }

        static func accountName(for item: KeychainItem) -> String {
            switch item {
            case .secretKey(let id): return "secret-key." + id.uuidString
            case .quickUnlockKey(let id): return "quick-unlock-key." + id.uuidString
            case .quickUnlockState(let id): return "quick-unlock-state." + id.uuidString
            }
        }

        /// Accessibility, or for the Local Unlock Key an access control that includes it.
        public static func protectionAttributes(for item: KeychainItem) throws -> [String: Any] {
            guard case .quickUnlockKey = item else {
                return [kSecAttrAccessible as String: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly]
            }
            guard
                let access = SecAccessControlCreateWithFlags(
                    nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, biometricFlags, nil)
            else { throw KeychainError.biometryUnavailable }
            return [kSecAttrAccessControl as String: access]
        }

        public static var biometricFlags: SecAccessControlCreateFlags {
            #if os(macOS)
                if #available(macOS 15, *) {
                    return [.biometryCurrentSet, .or, .companion]
                }
                return [.biometryCurrentSet, .or, .watch]
            #else
                return [.biometryCurrentSet]
            #endif
        }

        public static func error(for status: OSStatus) -> KeychainError {
            switch status {
            case errSecUserCanceled: return .userCancelled
            case errSecAuthFailed: return .authenticationFailed
            case errSecInteractionNotAllowed: return .interactionNotAllowed
            case errSecNotAvailable: return .biometryUnavailable
            default: return .unexpectedStatus(status)
            }
        }
    }

    /// The production `BiometricGate`: reports whether biometrics (or, on the Mac, a paired Watch) can authenticate and
    /// the opaque hash of the current enrolment. It never authenticates anything itself; the Keychain does.
    public struct LocalAuthenticationGate: BiometricGate {
        public init() {}

        public func enrolment() -> BiometricEnrolment {
            let context = LAContext()
            guard LocalAuthenticationBridge.canEvaluate(Self.policy, in: context) else { return .unavailable }
            if #available(macOS 15, iOS 18, *) {
                var state = Data()
                state.append(context.domainState.biometry.stateHash ?? Data())
                #if os(macOS)
                    state.append(context.domainState.companion.stateHash ?? Data())
                #endif
                return .enrolled(domainState: Array(state))
            }
            return .enrolled(domainState: Array(context.evaluatedPolicyDomainState ?? Data()))
        }

        static var policy: LAPolicy {
            #if os(macOS)
                if #available(macOS 15, *) {
                    return .deviceOwnerAuthenticationWithBiometricsOrCompanion
                }
                return .deviceOwnerAuthenticationWithBiometricsOrWatch
            #else
                return .deviceOwnerAuthenticationWithBiometrics
            #endif
        }
    }
#endif
