#if canImport(CryptoKit) && canImport(CommonCrypto)
    import Foundation
    import Testing
    import WatchwordCrypto
    import WatchwordModel
    import WatchwordStore
    import WatchwordTestSupport

    @testable import WatchwordKit

    func login(_ vaultID: UUID, title: String = "Example", host: String = "example.com", password: String = "pw-1")
        -> Item
    {
        Item(
            vaultID: vaultID, title: title, scopes: [ServiceScope(host: host)],
            fields: [
                Field(kind: .username, label: "Username", value: "someone@example.com"),
                Field(kind: .password, label: "Password", value: password),
            ])
    }

    @Suite("Vault session: account and unlock")
    struct VaultSessionAccountTests {
        @Test("creating an account leaves the vault unlocked and returns a parseable Emergency Kit")
        func create() async throws {
            let vault = TestVault()
            #expect(try await vault.session.state() == .noAccount)
            let kit = try await vault.createAccount()
            #expect(try await vault.session.state() == .unlocked)
            let parsed = try SecretKey(parsing: kit.secretKey)
            #expect(await vault.keychain.raw(.secretKey(accountID: kit.accountID)) == parsed.bytes.unprotectedCopy())
            let status = try await vault.session.status()
            #expect(status.accountID == kit.accountID)
            #expect(!status.emergencyKitConfirmed)
            try await vault.session.confirmEmergencyKitSaved()
            #expect(try await vault.session.status().emergencyKitConfirmed)
        }

        @Test("short passwords are refused")
        func shortPassword() async throws {
            await #expect(throws: VaultError.passwordTooShort(minimum: 10)) {
                try await TestVault().createAccount(password: "123456789")
            }
        }

        @Test("a second account cannot be created over the first")
        func secondAccount() async throws {
            let vault = TestVault()
            try await vault.createAccount()
            await #expect(throws: VaultError.accountAlreadyExists) {
                try await vault.relaunched().createAccount()
            }
        }

        @Test("lock then unlock with the password; the wrong password fails as authentication")
        func lockUnlock() async throws {
            let vault = TestVault()
            try await vault.createAccount()
            await vault.session.lock()
            #expect(try await vault.session.state() == .locked)
            await #expect(throws: CryptoError.authenticationFailed) {
                try await vault.session.unlock(password: "not the password")
            }
            try await vault.session.unlock(password: TestVault.password)
            #expect(try await vault.session.state() == .unlocked)
            await #expect(throws: VaultError.alreadyUnlocked) {
                try await vault.session.unlock(password: TestVault.password)
            }
        }

        @Test("a relaunched session unlocks the persisted account")
        func relaunch() async throws {
            let vault = TestVault()
            try await vault.createAccount()
            let saved = try await vault.session.save(login(try #require(await vault.session.personalVaultID)))
            let relaunched = vault.relaunched()
            #expect(try await relaunched.session.state() == .locked)
            try await relaunched.session.unlock(password: TestVault.password)
            #expect(try await relaunched.session.item(id: saved.id) == saved)
        }

        @Test("a device without the Secret Key unlocks with the one from the Emergency Kit, and keeps it")
        func restoredBackup() async throws {
            let vault = TestVault()
            let kit = try await vault.createAccount()
            await vault.session.lock()
            await vault.keychain.delete(.secretKey(accountID: kit.accountID))
            let restored = vault.relaunched()
            await #expect(throws: VaultError.secretKeyMissing) {
                try await restored.session.unlock(password: TestVault.password)
            }
            try await restored.session.unlock(password: TestVault.password, secretKey: kit.setupCode)
            #expect(await vault.keychain.contains(.secretKey(accountID: kit.accountID)))
            await restored.session.lock()
            try await restored.session.unlock(password: TestVault.password)
        }

        @Test("the Emergency Kit can be shown again while unlocked, and not while locked")
        func reshowKit() async throws {
            let vault = TestVault()
            let kit = try await vault.createAccount()
            #expect(try await vault.session.emergencyKit() == kit)
            await vault.session.lock()
            await #expect(throws: VaultError.locked) { try await vault.session.emergencyKit() }
        }

        @Test("changing the password re-wraps the keyset; only the new password unlocks")
        func changePassword() async throws {
            let vault = TestVault()
            try await vault.createAccount()
            let item = try await vault.session.save(login(try #require(await vault.session.personalVaultID)))
            await #expect(throws: CryptoError.authenticationFailed) {
                try await vault.session.changePassword(current: "wrong password!", new: "a brand new password")
            }
            try await vault.session.changePassword(current: TestVault.password, new: "a brand new password")
            let account = try #require(try await vault.store.loadAccount())
            #expect(account.keysetVersion == 1)
            #expect(account.credentialGeneration == 1)
            await vault.session.lock()
            await #expect(throws: CryptoError.authenticationFailed) {
                try await vault.session.unlock(password: TestVault.password)
            }
            try await vault.session.unlock(password: "a brand new password")
            #expect(try await vault.session.item(id: item.id) == item)
        }

        @Test("deleting the account needs the password and erases the store and Keychain")
        func deleteAccount() async throws {
            let vault = TestVault()
            try await vault.createAccount()
            try await vault.session.enableQuickUnlock(password: TestVault.password)
            await #expect(throws: CryptoError.authenticationFailed) {
                try await vault.session.deleteAccount(password: "wrong password!")
            }
            #expect(try await vault.session.state() == .unlocked)
            try await vault.session.deleteAccount(password: TestVault.password)
            #expect(try await vault.session.state() == .noAccount)
            #expect(await vault.keychain.isEmpty)
        }
    }

    @Suite("Vault session: quick unlock")
    struct VaultSessionQuickUnlockTests {
        @Test("quick unlock opens the vault after biometric success")
        func quickUnlock() async throws {
            let vault = TestVault()
            try await vault.createAccount()
            try await vault.session.enableQuickUnlock(password: TestVault.password)
            await vault.session.lock()
            #expect(try await vault.session.status().quickUnlock == .allowed)
            try await vault.session.quickUnlock(prompt: "Unlock your vault")
            #expect(try await vault.session.state() == .unlocked)
            #expect(await vault.keychain.prompts == ["Unlock your vault"])
        }

        @Test("a cancelled prompt counts as a failed attempt, and still surfaces as a cancel")
        func cancel() async throws {
            let vault = TestVault()
            try await vault.createAccount()
            try await vault.session.enableQuickUnlock(password: TestVault.password)
            await vault.session.lock()
            await vault.keychain.script(.cancel, .cancel, .cancel)
            for _ in 0..<3 {
                await #expect(throws: KeychainError.userCancelled) { try await vault.session.quickUnlock() }
            }
            await #expect(throws: VaultError.quickUnlockRefused(.tooManyFailedAttempts)) {
                try await vault.session.quickUnlock()
            }
        }

        @Test("a success resets the failure count")
        func successResets() async throws {
            let vault = TestVault()
            try await vault.createAccount()
            try await vault.session.enableQuickUnlock(password: TestVault.password)
            await vault.session.lock()
            await vault.keychain.script(.fail, .fail, .succeed, .fail, .fail, .succeed)
            for _ in 0..<2 {
                await #expect(throws: VaultError.biometricAuthenticationFailed) {
                    try await vault.session.quickUnlock()
                }
            }
            try await vault.session.quickUnlock()
            await vault.session.lock()
            for _ in 0..<2 {
                await #expect(throws: VaultError.biometricAuthenticationFailed) {
                    try await vault.session.quickUnlock()
                }
            }
            try await vault.session.quickUnlock()
        }

        @Test("quick unlock needs biometrics to enable")
        func needsBiometrics() async throws {
            let vault = TestVault(biometrics: FakeBiometricGate(.unavailable))
            try await vault.createAccount()
            await #expect(throws: VaultError.quickUnlockRefused(.biometryUnavailable)) {
                try await vault.session.enableQuickUnlock(password: TestVault.password)
            }
        }

        @Test("enabling quick unlock needs the account password")
        func needsPassword() async throws {
            let vault = TestVault()
            try await vault.createAccount()
            await #expect(throws: CryptoError.authenticationFailed) {
                try await vault.session.enableQuickUnlock(password: "not the password")
            }
            #expect(try await vault.session.status().quickUnlock == nil)
        }

        @Test("a password unlock after expiry re-enrols quick unlock with a fresh key")
        func reenrol() async throws {
            let vault = TestVault()
            let kit = try await vault.createAccount()
            try await vault.session.enableQuickUnlock(password: TestVault.password)
            let firstKey = try #require(await vault.keychain.raw(.quickUnlockKey(accountID: kit.accountID)))
            await vault.session.lock()
            await vault.clock.advance(by: 15 * 86_400)
            await #expect(throws: VaultError.quickUnlockRefused(.passwordIntervalExpired)) {
                try await vault.session.quickUnlock()
            }
            try await vault.session.unlock(password: TestVault.password)
            let secondKey = try #require(await vault.keychain.raw(.quickUnlockKey(accountID: kit.accountID)))
            #expect(firstKey != secondKey)
            await vault.session.lock()
            try await vault.session.quickUnlock()
        }

        @Test("disabling removes both Keychain items")
        func disable() async throws {
            let vault = TestVault()
            let kit = try await vault.createAccount()
            try await vault.session.enableQuickUnlock(password: TestVault.password)
            try await vault.session.disableQuickUnlock()
            #expect(!(await vault.keychain.contains(.quickUnlockKey(accountID: kit.accountID))))
            #expect(!(await vault.keychain.contains(.quickUnlockState(accountID: kit.accountID))))
            #expect(try await vault.session.status().quickUnlock == nil)
        }
    }

    @Suite("Vault session: items")
    struct VaultSessionItemTests {
        static func unlocked() async throws -> (TestVault, UUID) {
            let vault = TestVault()
            try await vault.createAccount()
            return (vault, try #require(await vault.session.personalVaultID))
        }

        @Test("create, read, list and update an item; the vault owns versions and timestamps")
        func crud() async throws {
            let (vault, vaultID) = try await Self.unlocked()
            var draft = login(vaultID)
            draft.version = 999
            draft.createdAt = .distantPast
            let created = try await vault.session.save(draft)
            #expect(created.version == 1)
            #expect(created.createdAt == (await vault.clock.now()))
            #expect(try await vault.session.items().items == [created])

            await vault.clock.advance(by: 60)
            var edited = created
            edited.title = "Renamed"
            let updated = try await vault.session.save(edited)
            #expect(updated.version == 2)
            #expect(updated.createdAt == created.createdAt)
            #expect(updated.modifiedAt == created.modifiedAt.addingTimeInterval(60))
            #expect(updated.history.isEmpty, "a title change does not touch field history")
            #expect(try await vault.session.item(id: created.id) == updated)
        }

        @Test("field changes are kept in history for good, however old or many (F1.4: a full audit trail)")
        func history() async throws {
            let (vault, vaultID) = try await Self.unlocked()
            var item = try await vault.session.save(login(vaultID, password: "first"))
            for password in ["second", "third"] {
                await vault.clock.advance(by: 86_400)
                item.fields[1].value = password
                item = try await vault.session.save(item)
            }
            #expect(item.history.map { $0.fields[1].value } == ["second", "first"])
            await vault.clock.advance(by: 3 * 365 * 86_400)
            item.title = "touch"
            item = try await vault.session.save(item)
            #expect(item.history.map { $0.fields[1].value } == ["second", "first"], "nothing expires with age")

            for edit in 0..<150 {
                item.fields[1].value = "pw-\(edit)"
                item = try await vault.session.save(item)
            }
            #expect(item.history.count == 152, "nothing is dropped by count")
            #expect(item.history.last?.fields[1].value == "first")
            #expect(try await vault.session.item(id: item.id).history == item.history)
        }

        @Test("an edit that would outgrow the payload limit is refused, never made room for by pruning (F1.4, SEC9)")
        func historyNeverPrunedToFit() async throws {
            let (vault, vaultID) = try await Self.unlocked()
            let large = String(repeating: "x", count: 200_000)
            var item = try await vault.session.save(login(vaultID, password: large + "0"))
            var saved = item
            var refused = false
            for edit in 1...8 {
                item.fields[1].value = large + "\(edit)"
                do {
                    saved = try await vault.session.save(item)
                } catch let error as ItemCodecError {
                    guard case .payloadTooLarge = error else { throw error }
                    refused = true
                    break
                }
            }
            #expect(refused, "six 200 kB versions exceed the 1 MiB payload")
            let stored = try await vault.session.item(id: item.id)
            #expect(stored == saved, "the refused edit left the stored version as it was")
            #expect(stored.history.count == saved.history.count)
            #expect(stored.history.last?.fields[1].value == large + "0", "the oldest version is still there")
        }

        @Test("the caller cannot rewrite history")
        func historyIsVaultOwned() async throws {
            let (vault, vaultID) = try await Self.unlocked()
            var item = try await vault.session.save(login(vaultID, password: "first"))
            item.fields[1].value = "second"
            item = try await vault.session.save(item)
            item.history = []
            item = try await vault.session.save(item)
            #expect(item.history.count == 1)
        }

        @Test("trash, restore, purge after 30 days, and permanent delete only from the trash (F1.5)")
        func trash() async throws {
            let (vault, vaultID) = try await Self.unlocked()
            let keep = try await vault.session.save(login(vaultID, title: "Keep"))
            let drop = try await vault.session.save(login(vaultID, title: "Drop"))
            await #expect(throws: VaultError.itemNotTrashed(keep.id)) {
                try await vault.session.deletePermanently(id: keep.id)
            }
            try await vault.session.trash(id: keep.id)
            try await vault.session.restore(id: keep.id)
            try await vault.session.trash(id: drop.id)
            #expect(try await vault.session.item(id: drop.id).isTrashed)
            await vault.clock.advance(by: 29 * 86_400)
            try await vault.session.purgeExpiredTrash()
            #expect(try await vault.session.items().items.count == 2)
            await vault.clock.advance(by: 86_400)
            await vault.session.lock()
            try await vault.session.unlock(password: TestVault.password)
            #expect(try await vault.session.items().items.map(\.id) == [keep.id])
        }

        @Test("archiving is a flag, not a deletion")
        func archive() async throws {
            let (vault, vaultID) = try await Self.unlocked()
            let item = try await vault.session.save(login(vaultID))
            try await vault.session.setArchived(true, id: item.id)
            #expect(try await vault.session.item(id: item.id).archived)
        }

        @Test("items cannot be written to an unknown vault or moved between vaults")
        func vaults() async throws {
            let (vault, vaultID) = try await Self.unlocked()
            let elsewhere = UUID()
            await #expect(throws: VaultError.unknownVault(elsewhere)) {
                try await vault.session.save(login(elsewhere))
            }
            var item = try await vault.session.save(login(vaultID))
            item.vaultID = elsewhere
            await #expect(throws: VaultError.vaultChangeNotSupported) { try await vault.session.save(item) }
        }

        @Test("nothing is readable or writable while locked")
        func locked() async throws {
            let (vault, vaultID) = try await Self.unlocked()
            let item = try await vault.session.save(login(vaultID))
            await vault.session.lock()
            await #expect(throws: VaultError.locked) { try await vault.session.items() }
            await #expect(throws: VaultError.locked) { try await vault.session.item(id: item.id) }
            await #expect(throws: VaultError.locked) { try await vault.session.save(item) }
        }

        @Test("a missing item is reported by ID")
        func missing() async throws {
            let (vault, _) = try await Self.unlocked()
            let id = UUID()
            await #expect(throws: VaultError.itemNotFound(id)) { try await vault.session.item(id: id) }
        }
    }
#endif
