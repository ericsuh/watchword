#if canImport(Security) && canImport(LocalAuthentication)
    import Foundation
    import Security
    import SecureMemory
    import Testing
    import WatchwordKit
    import WatchwordPlatform

    /// The real Keychain. The data-protection Keychain needs a signed process with a Keychain entitlement, which
    /// `swift test` does not have (`errSecMissingEntitlement`); there the round trip is skipped and only the query
    /// shape is checked (in the adversarial suite). The app-hosted test targets run it for real.
    @Suite("System Keychain store")
    struct SystemKeychainStoreTests {
        static let store = SystemKeychainStore(
            service: "com.ericsuh.Watchword.tests.\(UUID().uuidString)", accessGroup: nil)

        static var isEntitled: Bool {
            let probe = SecItemAdd(
                [
                    kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "entitlement-probe",
                    kSecAttrAccount as String: UUID().uuidString, kSecUseDataProtectionKeychain as String: true,
                    kSecValueData as String: Data([1]),
                ] as CFDictionary, nil)
            return probe != errSecMissingEntitlement
        }

        @Test("store, read, replace and delete a device-only item", .enabled(if: isEntitled))
        func roundTrip() async throws {
            let item = KeychainItem.secretKey(accountID: UUID())
            try await Self.store.store(SecureBytes(copying: [1, 2, 3]), for: item)
            #expect(try await Self.store.read(item, prompt: "")?.unprotectedCopy() == [1, 2, 3])
            try await Self.store.store(SecureBytes(copying: [4, 5]), for: item)
            #expect(try await Self.store.read(item, prompt: "")?.unprotectedCopy() == [4, 5])
            try await Self.store.delete(item)
            #expect(try await Self.store.read(item, prompt: "") == nil)
            try await Self.store.delete(item)
        }

        @Test("error statuses map to typed errors")
        func errorMapping() {
            #expect(SystemKeychainStore.error(for: errSecUserCanceled) == .userCancelled)
            #expect(SystemKeychainStore.error(for: errSecAuthFailed) == .authenticationFailed)
            #expect(SystemKeychainStore.error(for: errSecInteractionNotAllowed) == .interactionNotAllowed)
            #expect(SystemKeychainStore.error(for: -1) == .unexpectedStatus(-1))
        }
    }
#endif
