#if canImport(CryptoKit) && canImport(CommonCrypto) && canImport(SQLite3)
    import Foundation
    import SecureMemory
    import Testing
    import WatchwordCrypto
    import WatchwordEnvelope
    import WatchwordModel
    import WatchwordPlatform
    @testable import WatchwordStore
    import WatchwordTestSupport

    @testable import WatchwordKit

    /// Milestone 2 adversarial obligations for the local store (docs/04-test-plan.md §6.1 applied to the store, §6.2).
    ///
    /// Threat model: **an attacker with read/write access to the App Group database file but not to the Keychain or the
    /// password** — local malware running as the user on macOS (A8, while the app is locked), a tampered backup that is
    /// restored, or the same capabilities a sync-store attacker (A1) will have over these records from milestone 3. They
    /// can edit any column, swap or copy rows and envelopes, delete rows, and rewrite the account header. They must not
    /// learn any field value or title, and every edit must fail closed: a refused record, a typed error, or the same
    /// `authenticationFailed` a wrong password gives — never a record presented as something it is not. Each tamper
    /// below goes through a raw SQLite connection, exactly as such an attacker would.
    @Suite("Adversarial: local vault store", .tags(.adversarial))
    struct AdversarialVaultStoreTests {
        struct Fixture {
            let vault: TestVault
            let url: URL
            let raw: SQLiteConnection
            let vaultID: UUID
            let first: Item
            let second: Item
        }

        static func fixture() async throws -> Fixture {
            let url = FileManager.default.temporaryDirectory
                .appendingPathComponent("watchword-adversarial-\(UUID().uuidString)")
                .appendingPathComponent("Watchword.sqlite")
            let vault = TestVault(store: try SQLiteRecordStore(url: url))
            try await vault.createAccount()
            let vaultID = try #require(await vault.session.personalVaultID)
            let first = try await vault.session.save(
                Item(
                    vaultID: vaultID, title: "Bank", scopes: [ServiceScope(host: "firstbank.co.uk")],
                    fields: [Field(kind: .password, label: "Password", value: "bank-secret-1")]))
            let second = try await vault.session.save(
                Item(
                    vaultID: vaultID, title: "Library", scopes: [ServiceScope(host: "citylibrary.org")],
                    fields: [Field(kind: .pin, label: "PIN", value: "4321")]))
            return Fixture(
                vault: vault, url: url, raw: try SQLiteConnection(path: SQLiteRecordStore.resolvingSymlinks(url.path)),
                vaultID: vaultID, first: first,
                second: second)
        }

        static func blob(_ id: UUID) -> SQLiteValue {
            let u = id.uuid
            return .blob([u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15])
        }

        /// Threat: confidentiality at rest (SEC1). Nothing in the file — not a password, not a title, not a host — may be
        /// readable without the keys.
        @Test("no title, host or field value appears anywhere in the database files")
        func noPlaintextOnDisk() async throws {
            let fixture = try await Self.fixture()
            try fixture.raw.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            var bytes: [UInt8] = []
            for suffix in ["", "-wal", "-shm"] {
                if let data = FileManager.default.contents(atPath: fixture.url.path + suffix) { bytes += data }
            }
            for secret in ["bank-secret-1", "4321", "Bank", "Library", "firstbank", "citylibrary", TestVault.password] {
                let needle = Array(secret.utf8)
                let found = bytes.indices.dropLast(needle.count).contains {
                    bytes[$0..<($0 + needle.count)].elementsEqual(needle)
                }
                #expect(!found, "\(secret) found in the database")
            }
        }

        /// Threat: record swap (SEC2). The attacker exchanges two items' ciphertexts so the bank password shows up under
        /// the library item (or is filled on the library's site). Both rows must become unreadable; neither may open as
        /// the other.
        @Test("swapping two records' envelopes makes both unreadable")
        func swapEnvelopes() async throws {
            let f = try await Self.fixture()
            let rows = try f.raw.query(
                "SELECT record_id, envelope FROM records WHERE kind = 0 ORDER BY record_id")
            try f.raw.query("UPDATE records SET envelope = ? WHERE record_id = ?", [rows[1][1], rows[0][0]])
            try f.raw.query("UPDATE records SET envelope = ? WHERE record_id = ?", [rows[0][1], rows[1][0]])
            let listing = try await f.vault.session.items()
            #expect(listing.items.isEmpty)
            #expect(Set(listing.unreadable) == [f.first.id, f.second.id])
        }

        /// Threat: relabelling. The attacker edits a row's storage columns — presents it as a newer version (to win a
        /// later merge), names a different key, or moves it to another record ID — leaving the envelope alone. The
        /// context is rebuilt from the columns and compared before decryption, so each edit fails closed.
        @Test(
            "editing a row's version, key or record ID makes it unreadable",
            arguments: [
                "UPDATE records SET version = version + 1 WHERE record_id = ?",
                "UPDATE records SET key_id = randomblob(16) WHERE record_id = ?",
                "UPDATE records SET record_id = randomblob(16) WHERE record_id = ?",
            ])
        func relabel(_ sql: String) async throws {
            let f = try await Self.fixture()
            try f.raw.query(sql, [Self.blob(f.first.id)])
            let listing = try await f.vault.session.items()
            #expect(listing.items.map(\.id) == [f.second.id])
            #expect(listing.unreadable.count == 1)
        }

        /// Threat: kind confusion. An item envelope copied into a key-wrap row (or the reverse) must not be parsed as the
        /// other kind; the kind byte is checked before any payload is touched.
        @Test("an item envelope planted as a vault-key wrap is refused and does not unlock")
        func kindConfusion() async throws {
            let f = try await Self.fixture()
            let account = try #require(try await f.vault.store.loadAccount())
            let item = try f.raw.query("SELECT envelope FROM records WHERE record_id = ?", [Self.blob(f.first.id)])
            try f.raw.query(
                "UPDATE records SET envelope = ? WHERE kind = 1 AND record_id = ?",
                [item[0][0], Self.blob(account.personalVaultKeyID)])
            await f.vault.session.lock()
            await #expect(throws: EnvelopeError.kindMismatch(expected: .vaultKeyWrap, actual: .item)) {
                try await f.vault.session.unlock(password: TestVault.password)
            }
        }

        /// Threat: deleting the vault key wrap to provoke a "repair" that generates a fresh key and silently orphans the
        /// existing items. The session refuses to unlock rather than invent a key.
        @Test("a missing vault key wrap is an error, not a reason to make a new key")
        func missingVaultKey() async throws {
            let f = try await Self.fixture()
            try f.raw.query("DELETE FROM records WHERE kind = 1")
            await f.vault.session.lock()
            await #expect(throws: VaultError.vaultKeyMissing(vaultID: f.vaultID)) {
                try await f.vault.session.unlock(password: TestVault.password)
            }
            #expect(try await f.vault.store.records(in: f.vaultID, kind: .item).count == 2)
        }

        /// Threat: KDF downgrade and its mirror image (SEC5, SEC9). Lowering the iteration count would make a stolen
        /// header cheaper to attack; raising it to the maximum `UInt32` would make every unlock hang. Both are refused
        /// with a typed error before any derivation.
        @Test(
            "a tampered KDF iteration count is refused before deriving, in both directions",
            arguments: zip(
                [Int64(1_000), Int64(UInt32.max)],
                [
                    KDFValidationError.iterationsBelowMinimum(1_000, minimum: KDFParameters.minimumIterations),
                    .iterationsAboveMaximum(UInt32.max, maximum: KDFParameters.maximumIterations),
                ]))
        func kdfTamper(_ iterations: Int64, _ expected: KDFValidationError) async throws {
            let f = try await Self.fixture()
            try f.raw.query("UPDATE account SET kdf_iterations = ?", [.integer(iterations)])
            let relaunched = f.vault.relaunched()
            let start = ContinuousClock.now
            await #expect(throws: expected) { try await relaunched.session.unlock(password: TestVault.password) }
            #expect(ContinuousClock.now - start < .seconds(5))
        }

        /// Threat: header substitution. A different salt, or the wrapped keyset of another account (or of this account
        /// before a password change), must fail exactly like a wrong password: no oracle about which part was changed.
        @Test(
            "a substituted salt, keyset or key ID fails like a wrong password",
            arguments: [
                "UPDATE account SET salt = randomblob(32)",
                "UPDATE account SET wrapped_keyset = randomblob(length(wrapped_keyset))",
                "UPDATE account SET keyset_version = keyset_version + 1",
                "UPDATE account SET account_id = randomblob(16)",
            ])
        func headerSubstitution(_ sql: String) async throws {
            let f = try await Self.fixture()
            try f.raw.execute(sql)
            do {
                try await f.vault.relaunched().session.unlock(password: TestVault.password)
                Issue.record("unlocked with a substituted header")
            } catch let error as CryptoError {
                #expect(error == .authenticationFailed)
            } catch is EnvelopeError {
                // Relabelled header fields fail the context comparison before decryption.
            } catch VaultError.secretKeyMissing {
                // A different account ID names a Keychain item this device does not have.
            }
        }

        /// Threat: a writer who holds the vault key but lies in the plaintext — from milestone 4, any member of a shared
        /// vault (A4). The record is properly sealed for row A but its payload claims to be item B, hoping the UI or the
        /// AutoFill index trusts the payload's ID. The vault compares the decrypted identity with the storage location.
        @Test("a correctly sealed record whose payload claims another identity is refused")
        func plaintextLiesAboutIdentity() async throws {
            let f = try await Self.fixture()
            let keys = try #require(await f.vault.session.keys)
            let account = try #require(try await f.vault.store.loadAccount())
            let vaultKey = try #require(keys.vaultKeys[account.personalVaultKeyID])
            var liar = f.second
            liar.version = f.first.version + 1
            let row = StoredRecord(
                recordID: f.first.id, kind: .item, vaultID: f.vaultID, keyID: vaultKey.key.keyID,
                version: f.first.version + 1, deviceID: account.deviceID, envelope: [])
            var sealed = row
            sealed.envelope = try RecordCipher.seal(
                try ItemCodec.encode(liar), context: VaultSession.itemContext(row), key: vaultKey.key)
            try await f.vault.store.commit(StoreChange(upserts: [sealed]))
            let listing = try await f.vault.session.items()
            #expect(listing.unreadable == [f.first.id])
            await #expect(throws: VaultError.recordMismatch(f.first.id)) {
                try await f.vault.session.item(id: f.first.id)
            }
        }

        /// Threat: values this code would never have written (a hand-edited file), such as an unknown KDF algorithm
        /// name. They are reported as malformed, not coerced into something usable.
        @Test("structurally invalid rows are reported, not repaired")
        func malformedRows() async throws {
            let f = try await Self.fixture()
            try f.raw.execute("UPDATE account SET kdf_algorithm = 'MD5'")
            await #expect(throws: RecordStoreError.malformedRow("account.kdf_algorithm")) {
                try await f.vault.store.loadAccount()
            }
        }

        /// Threat: A8 planting a symlink at the database path so the app's writes land in a file the attacker chose
        /// (or reads come from one). The store refuses to open through a symlink.
        @Test("the store refuses to open a database path that is a symlink")
        func symlinkRefused() throws {
            let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
                "ww-link-\(UUID().uuidString)")
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let target = directory.appendingPathComponent("elsewhere.sqlite")
            _ = try SQLiteRecordStore(url: target)
            let link = directory.appendingPathComponent("Watchword.sqlite")
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
            #expect(throws: SQLiteConnection.Failure.self) { _ = try SQLiteRecordStore(url: link) }
        }

        /// Threat: an over-broad scope (PRD F11.2). A scope of `com` or `github.io` would make this item the top match on
        /// an attacker's domain where nothing more specific is saved. The vault refuses it at save time, the one place a
        /// scope enters from the UI.
        @Test(
            "the vault refuses scopes that span unrelated owners",
            arguments: ["com", "co.uk", "github.io", "localhost"])
        func overBroadScope(_ host: String) async throws {
            let f = try await Self.fixture()
            var item = f.first
            item.scopes.append(ServiceScope(host: host))
            await #expect(throws: VaultError.self) { try await f.vault.session.save(item) }
            #expect(try await f.vault.session.item(id: f.first.id).scopes == f.first.scopes)
        }
    }

    /// Adversarial obligations for the Keychain adapter (docs/03-implementation-plan.md, working agreements).
    ///
    /// Threat model: **an iCloud-account compromise (A1) and a thief who knows the device passcode (A2/A3).** If any item
    /// were synchronisable, the Secret Key would sit beside the vault ciphertext in one Apple account and collapse 2SKD
    /// to a single secret (ADR 0004). If the Local Unlock Key's access control allowed a passcode fallback
    /// (`.userPresence`, `.devicePasscode`) or any biometric enrolment (`.biometryAny`), a shoulder-surfed passcode or a
    /// newly added face would quick-unlock the vault.
    @Suite("Adversarial: Keychain item protection", .tags(.adversarial))
    struct AdversarialKeychainAttributeTests {
        static let store = SystemKeychainStore(service: "test.watchword", accessGroup: "TEAMID.test.watchword")
        static let accountID = UUID()
        static let items: [KeychainItem] = [
            .secretKey(accountID: accountID), .quickUnlockKey(accountID: accountID),
            .quickUnlockState(accountID: accountID),
        ]

        @Test("every item is device-only, non-synchronisable and in the shared access group")
        func deviceOnly() throws {
            for item in Self.items {
                let query = Self.store.baseQuery(for: item)
                #expect(query[kSecAttrSynchronizable as String] as? Bool == false)
                #expect(query[kSecUseDataProtectionKeychain as String] as? Bool == true)
                #expect(query[kSecAttrAccessGroup as String] as? String == "TEAMID.test.watchword")
                let protection = try SystemKeychainStore.protectionAttributes(for: item)
                if case .quickUnlockKey = item {
                    #expect(protection[kSecAttrAccessControl as String] != nil)
                    #expect(protection[kSecAttrAccessible as String] == nil)
                } else {
                    #expect(
                        protection[kSecAttrAccessible as String] as? String
                            == kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String)
                }
            }
        }

        @Test("the Local Unlock Key needs the current biometric set, with no passcode or any-biometry fallback")
        func biometricFlags() {
            let flags = SystemKeychainStore.biometricFlags
            #expect(flags.contains(.biometryCurrentSet))
            #expect(!flags.contains(.userPresence))
            #expect(!flags.contains(.devicePasscode))
            #expect(!flags.contains(.biometryAny))
            #expect(!flags.contains(.applicationPassword))
        }
    }
#endif
