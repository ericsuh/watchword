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
    /// It joins the account as any new device does (`VaultSession.enrol`): from the transport, the password the test
    /// passes in `WATCHWORD_UITEST_PASSWORD` and the Emergency Kit's setup code, so it registers itself in the device
    /// registry and the app's device accepts what it signs. The app must have synced once first, so the account's
    /// objects are on the transport.
    actor UITestPeer {
        static let passwordVariable = "WATCHWORD_UITEST_PASSWORD"

        let transport: InMemorySyncTransport
        private var session: VaultSession?

        init(transport: InMemorySyncTransport) {
            self.transport = transport
        }

        /// Syncs, appends `suffix` to the title of every item not in the trash, and syncs again.
        func renameItems(appending suffix: String, kit: EmergencyKit) async throws {
            let peer = try await enrolled(kit: kit)
            try await peer.sync()
            for item in try await peer.items().items where !item.isTrashed {
                var edited = item
                edited.title += suffix
                try await peer.save(edited)
            }
            try await peer.sync()
        }

        private func enrolled(kit: EmergencyKit) async throws -> VaultSession {
            if let session { return session }
            let peer = VaultSession(
                store: InMemoryRecordStore(), keychain: InMemoryKeychainStore(), biometrics: UnavailableBiometricGate(),
                configuration: VaultConfiguration(appVersion: "uitest-peer", kdf: .fixed(.baseline)),
                sync: SyncSettings(state: InMemorySyncStateStore(), transport: transport))
            try await peer.enrol(
                password: ProcessInfo.processInfo.environment[Self.passwordVariable] ?? "", secretKey: kit.setupCode)
            session = peer
            return peer
        }
    }
#endif
