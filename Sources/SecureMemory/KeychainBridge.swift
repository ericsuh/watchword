#if canImport(Security)
    import Foundation
    import Security

    /// The one Keychain call whose signature needs a raw pointer (docs/02-architecture.md §6).
    ///
    /// `SecItemCopyMatching` returns its result through an `UnsafeMutablePointer<CFTypeRef?>` out-parameter, so under
    /// ADR 0001 the call lives here. Everything else about the Keychain — query construction, access-control flags,
    /// accessibility classes, error mapping — is ordinary safe code in `WatchwordPlatform.SystemKeychainStore`.
    ///
    /// Secret data comes back already in `SecureBytes`, so the only unprotected copy on our side of the call is the
    /// `CFData` the Security framework itself allocated, which is released as soon as this function returns.
    public enum KeychainBridge {
        public enum ReadResult: Sendable {
            case found(SecureBytes)
            case notFound
            /// Any other `OSStatus`, for the caller to map (`errSecUserCanceled`, `errSecAuthFailed`, …).
            case failure(OSStatus)
        }

        /// Runs `SecItemCopyMatching` for a query that sets `kSecReturnData` and `kSecMatchLimitOne`.
        public static func copyData(matching query: CFDictionary) -> ReadResult {
            var result: CFTypeRef?
            let status = unsafe (SecItemCopyMatching(query, &result))
            switch status {
            case errSecSuccess:
                guard let data = result as? Data else { return .failure(errSecInternalError) }
                return .found(SecureBytes(copying: data))
            case errSecItemNotFound:
                return .notFound
            default:
                return .failure(status)
            }
        }
    }
#endif
