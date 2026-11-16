#if DEBUG
    import Foundation
    import WatchwordCrypto
    import WatchwordHygiene
    import WatchwordKit
    import WatchwordModel
    import WatchwordSharing
    import WatchwordStore
    import WatchwordSync

    /// The rest of the UI-test household, in the same process: another device of the app's account, and another
    /// person's account that a vault can be shared with (docs/04-test-plan.md §5). Each is a `VaultSession` with its
    /// own in-memory store, Keychain and sync state, syncing over the transport the app syncs over, so an XCUITest can
    /// make a change "elsewhere" (a rename, a password change, an implausible version, accepting an invitation) and see
    /// it arrive through the real UI, the real keyring and the real sharing protocol. Debug builds launched with
    /// `--uitest` only; the Settings section that drives it exists only there.
    ///
    /// The other device joins the account as any new device does (`VaultSession.enrol`): from the transport, the
    /// password the test passes in `WATCHWORD_UITEST_PASSWORD` and the Emergency Kit's setup code, so it registers
    /// itself in the device registry and the app's device accepts what it signs. The app must have synced once first,
    /// so the account's objects are on the transport.
    actor UITestPeer {
        static let passwordVariable = "WATCHWORD_UITEST_PASSWORD"
        /// The app's `SyncConfiguration.maximumVersionJump` in a UI-test launch; `makeImplausibleEdit` jumps further.
        static let maximumVersionJump: UInt64 = 16
        static let appDeviceName = "UI-test device"
        static let peerDeviceName = "Other UI-test device"
        /// The password the other person's account is created with. Never typed into the app.
        static let householdPassword = "household member password"

        /// The password `changePassword` sets on the other device.
        static let changedPassword = "changed on the other device"

        let transport: InMemorySyncTransport
        /// The key directory both accounts publish their bundles in (the account record on a real transport).
        let directory: InMemoryKeyBundleDirectory
        private var session: VaultSession?
        private var member: VaultSession?

        init(transport: InMemorySyncTransport, directory: InMemoryKeyBundleDirectory) {
            self.transport = transport
            self.directory = directory
        }

        /// The app session's sharing settings: its own state and pins, over the household's directory.
        static func appSharing(directory: InMemoryKeyBundleDirectory) -> SharingSettings {
            SharingSettings(
                state: InMemorySharingStateStore(), contacts: InMemoryVerifiedContactStore(), directory: directory)
        }

        private var password: String {
            ProcessInfo.processInfo.environment[Self.passwordVariable] ?? ""
        }

        // MARK: The other device

        /// Joins the account and syncs, so the app's Devices screen lists it after its own next sync.
        func join(kit: EmergencyKit) async throws {
            try await enrolled(kit: kit).sync()
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

        /// Changes the account password on the other device to `changedPassword` and publishes the change, so the
        /// app's next sync sees a password it has not been given (`passwordChangedOnAnotherDevice`).
        func changePassword(kit: EmergencyKit) async throws {
            let peer = try await enrolled(kit: kit)
            try await peer.sync()
            try await peer.changePassword(current: password, new: Self.changedPassword)
            try await peer.sync()
        }

        /// Edits the first live item `40` times without syncing in between, then publishes it: one version further
        /// above the vault's newest than `maximumVersionJump` allows, which the app holds aside (review finding U5).
        func makeImplausibleEdit(kit: EmergencyKit) async throws {
            let peer = try await enrolled(kit: kit)
            try await peer.sync()
            guard var item = try await peer.items().items.first(where: { !$0.isTrashed }) else { return }
            for round in 0..<40 {
                item.notes = "Edited elsewhere, \(round + 1) times"
                item = try await peer.save(item)
            }
            try await peer.sync()
        }

        private func enrolled(kit: EmergencyKit) async throws -> VaultSession {
            if let session { return session }
            let peer = VaultSession(
                store: InMemoryRecordStore(), keychain: InMemoryKeychainStore(), biometrics: UnavailableBiometricGate(),
                configuration: VaultConfiguration(
                    appVersion: "uitest-peer", kdf: .fixed(.baseline), deviceName: Self.peerDeviceName),
                sync: SyncSettings(state: InMemorySyncStateStore(), transport: transport))
            try await peer.enrol(password: password, secretKey: kit.setupCode)
            session = peer
            return peer
        }

        // MARK: The other person

        /// The other person's account ID, for the invite screen, after creating their account and publishing both
        /// accounts' key bundles in the directory.
        func householdAccountID(publishing appBundle: PublicKeyBundle) async throws -> UUID {
            await directory.publish(appBundle)
            let member = try await householdMember()
            return try await member.publicKeyBundle().accountID
        }

        /// The other person accepts `invitation`, having compared the owner's safety number with the app's by eye.
        func acceptInvitation(_ invitation: Invitation) async throws {
            let member = try await householdMember()
            try await member.acceptInvitation(invitation, ownerEvidence: .comparedByEye)
            try await member.sync()
        }

        private func householdMember() async throws -> VaultSession {
            if let member { return member }
            let created = VaultSession(
                store: InMemoryRecordStore(), keychain: InMemoryKeychainStore(), biometrics: UnavailableBiometricGate(),
                configuration: VaultConfiguration(
                    appVersion: "uitest-member", kdf: .fixed(.baseline), deviceName: "Household member's device"),
                sync: SyncSettings(state: InMemorySyncStateStore(), transport: transport))
            _ = try await created.createAccount(password: Self.householdPassword)
            try await created.confirmEmergencyKitSaved()
            await created.configureSharing(
                SharingSettings(
                    state: InMemorySharingStateStore(), contacts: InMemoryVerifiedContactStore(), directory: directory))
            await directory.publish(try await created.publicKeyBundle())
            // Publishes the account's registry, which the owner checks this account's signatures against.
            try await created.sync()
            member = created
            return created
        }
    }

    /// Pwned Passwords for a UI-test launch, without the network: the range holding SHA-1("password") reports it seen
    /// 3,861,493 times (the suffix is from `hashlib.sha1(b"password")`), and every other range holds padding only.
    /// The scan, the schedule and the report run as they would against the service.
    struct UITestPwnedPasswords: HTTPClient {
        static let breachedPrefix = "5BAA6"
        static let breachedSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

        func send(_ request: HTTPRequest) async throws -> HTTPResponse {
            let marker = "/range/"
            guard request.url.host == .pwnedPasswords, request.url.path.hasPrefix(marker) else {
                return HTTPResponse(status: 400)
            }
            let prefix = String(request.url.path.dropFirst(marker.count))
            var lines = (0..<20).map { index in
                let digits = String(index, radix: 16, uppercase: true)
                return String(repeating: "0", count: 35 - digits.count) + digits + ":0"
            }
            if prefix == Self.breachedPrefix { lines.append(Self.breachedSuffix + ":3861493") }
            return HTTPResponse(
                status: 200, headers: ["Content-Type": "text/plain"], body: Array(lines.joined(separator: "\r\n").utf8))
        }
    }
#endif
