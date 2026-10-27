#if DEBUG
    import Foundation
    import WatchwordKit
    import WatchwordModel
    import WatchwordStore
    import WatchwordSync

    /// Another device of the UI-test account, in the same process: a second `VaultSession` with its own in-memory
    /// store, Keychain and sync state, syncing over the transport the app syncs over (docs/04-test-plan.md §5). It
    /// lets an XCUITest make a change "elsewhere", so conflicts and merges can be driven through the real UI and the
    /// real keyring. Debug builds launched with `--uitest` only.
    ///
    /// Enrolment copies the account header, the vault-key wraps and the Secret Key from the app's in-memory ports:
    /// what enrolment from the account header on the transport will deliver once it exists (milestone 3, open). The
    /// peer unlocks with the password the test passes in `WATCHWORD_UITEST_PASSWORD`.
    actor UITestPeer {
        static let passwordVariable = "WATCHWORD_UITEST_PASSWORD"

        let primaryStore: InMemoryRecordStore
        let primaryKeychain: InMemoryKeychainStore
        let transport: InMemorySyncTransport
        private var session: VaultSession?

        init(
            primaryStore: InMemoryRecordStore, primaryKeychain: InMemoryKeychainStore, transport: InMemorySyncTransport
        ) {
            self.primaryStore = primaryStore
            self.primaryKeychain = primaryKeychain
            self.transport = transport
        }

        /// Syncs, appends `suffix` to the title of every item not in the trash, and syncs again.
        func renameItems(appending suffix: String) async throws {
            let peer = try await enrolled()
            try await peer.sync()
            for item in try await peer.items().items where !item.isTrashed {
                var edited = item
                edited.title += suffix
                try await peer.save(edited)
            }
            try await peer.sync()
        }

        private func enrolled() async throws -> VaultSession {
            if let session { return session }
            guard var account = await primaryStore.loadAccount() else { throw VaultError.noAccount }
            let wraps = await primaryStore.records(in: account.personalVaultID, kind: .vaultKeyWrap)
            account.deviceID = UUID()
            let store = InMemoryRecordStore()
            try await store.commit(StoreChange(account: .create(account), upserts: wraps))
            let keychain = InMemoryKeychainStore()
            let item = KeychainItem.secretKey(accountID: account.accountID)
            if let secretKey = await primaryKeychain.read(item, prompt: "") {
                await keychain.store(secretKey, for: item)
            }
            let peer = VaultSession(
                store: store, keychain: keychain, biometrics: UnavailableBiometricGate(),
                configuration: VaultConfiguration(appVersion: "uitest-peer", kdf: .fixed(.baseline)),
                sync: SyncSettings(state: InMemorySyncStateStore(), transport: transport))
            try await peer.unlock(password: ProcessInfo.processInfo.environment[Self.passwordVariable] ?? "")
            session = peer
            return peer
        }
    }
#endif
