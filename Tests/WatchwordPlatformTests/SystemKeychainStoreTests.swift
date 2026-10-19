#if canImport(Security) && canImport(LocalAuthentication)
    import Foundation
    import Security
    import SecureMemory
    import Testing
    import WatchwordKit
    import WatchwordPlatform

    /// The real Keychain. The data-protection Keychain needs a signed process with a Keychain entitlement, which
    /// `swift test` does not have (`errSecMissingEntitlement`); there the round trip is skipped and only the query
    /// shape is checked (in the adversarial suite). `mise run app:test-keychain --team <ID>` runs it for real, inside
    /// the `WatchwordKeychainHost` app (Apps/project.yml), whose only entitlement is its own Keychain access group.
    @Suite("System Keychain store")
    struct SystemKeychainStoreTests {
        static let store = SystemKeychainStore(
            service: "com.ericsuh.Watchword.tests.\(UUID().uuidString)", accessGroup: nil)

        /// Set by `app:test-keychain` (as `TEST_RUNNER_WATCHWORD_REQUIRE_KEYCHAIN`), so a signing mistake that drops
        /// the entitlement fails the signed run instead of quietly skipping the round trip.
        static var keychainRequired: Bool {
            ProcessInfo.processInfo.environment["WATCHWORD_REQUIRE_KEYCHAIN"] == "1"
        }

        /// Every probe item, whatever its account: the service names it, so a delete with this query also removes
        /// any an earlier run left behind.
        static var probeQuery: [String: Any] {
            [
                kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: "entitlement-probe",
                kSecUseDataProtectionKeychain as String: true,
            ]
        }

        /// Whether this process may use the data-protection Keychain. The probe item is deleted again, so an entitled
        /// run leaves nothing in the developer's Keychain.
        static var isEntitled: Bool {
            var item = probeQuery
            item[kSecAttrAccount as String] = "probe"
            item[kSecValueData as String] = Data([1])
            let status = SecItemAdd(item as CFDictionary, nil)
            _ = SecItemDelete(probeQuery as CFDictionary)
            return status != errSecMissingEntitlement
        }

        @Test("the signed run has the Keychain entitlement and the probe cleans up", .enabled(if: keychainRequired))
        func entitled() throws {
            try #require(Self.isEntitled, "errSecMissingEntitlement: the test host was signed without its access group")
            #expect(SecItemDelete(Self.probeQuery as CFDictionary) == errSecItemNotFound, "the probe left an item")
        }

        @Test("store, read, replace and delete a device-only item", .enabled(if: isEntitled))
        func roundTrip() throws {
            let item = KeychainItem.secretKey(accountID: UUID())
            try Self.store.store(SecureBytes(copying: [1, 2, 3]), for: item)
            #expect(try Self.store.read(item, prompt: "")?.unprotectedCopy() == [1, 2, 3])
            try Self.store.store(SecureBytes(copying: [4, 5]), for: item)
            #expect(try Self.store.read(item, prompt: "")?.unprotectedCopy() == [4, 5])
            try Self.store.delete(item)
            #expect(try Self.store.read(item, prompt: "") == nil)
            try Self.store.delete(item)
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
