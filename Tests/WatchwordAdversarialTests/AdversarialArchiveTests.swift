import Foundation
import SecureMemory
import Testing
import WatchwordEnvelope
import WatchwordInterchange
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordCrypto
@testable import WatchwordKit

/// The encrypted Watchword archive attacked as a file (docs/02-architecture.md §14.1, ADR 0008; PRD F8.4, SEC5,
/// SEC9).
///
/// Adversaries (docs/02-architecture.md §2): **A1**, the cloud drive the archive was saved to, holding its bytes and
/// no passphrase or Secret Key, free to truncate, reorder, splice and rewrite them; **A7**, anyone who hands the
/// person an archive file, including one cut from another archive or made by another account.
@Suite("Adversarial: encrypted Watchword archive", .tags(.adversarial))
struct AdversarialArchiveTests {
    static let passphrase = "the archive's own passphrase"
    static let secretKey = try! SecretKey(bytes: SecureBytes(copying: Array(0x10..<0x20)))
    static let accountID = UUID(uuidString: "ACC00000-0000-4000-8000-0000000000A1")!
    static let texts = ["first entry", "the second, which is longer", "third"]

    static func seal(
        _ texts: [String] = texts, archiveID: UUID = UUID(uuidString: "A2C00000-0000-4000-8000-000000000001")!,
        secretKey: SecretKey = secretKey, accountID: UUID = accountID, seed: UInt64 = 5
    ) throws -> [UInt8] {
        var generator = SeededGenerator(seed: seed)
        return try AccountArchive.seal(
            texts.map { SecureBytes(copying: Array($0.utf8)) }, archiveID: archiveID, accountID: accountID,
            createdAt: Date(timeIntervalSince1970: 1_800_000_000), passphrase: passphrase, secretKey: secretKey,
            parameters: .baseline, using: &generator)
    }

    /// Where each part of a sealed archive starts, read from the layout in `AccountArchive`'s documentation rather
    /// than from the parser.
    struct Layout {
        let bytes: [UInt8]
        static let iterations = 46
        static let salt = 52
        var wrappedLength: Int { Int(bytes[116]) | Int(bytes[117]) << 8 }
        var count: Int { 118 + wrappedLength }
        var manifest: Int { count + 4 }
        var manifestLength: Int { Int(bytes[manifest]) | Int(bytes[manifest + 1]) << 8 }
        var entries: Int { manifest + 2 + manifestLength }

        /// Each entry's byte range (identifier, length and envelope).
        var entryRanges: [Range<Int>] {
            var ranges: [Range<Int>] = []
            var offset = entries
            while offset < bytes.count {
                let length = (0..<4).reduce(0) { $0 | Int(bytes[offset + 16 + $1]) << (8 * $1) }
                ranges.append(offset..<(offset + 20 + length))
                offset += 20 + length
            }
            return ranges
        }
    }

    static func littleEndian(_ value: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
    }

    /// A1 cuts the file anywhere. Every cut is refused by the parser, before any key is derived; none traps.
    @Test("a truncated archive is refused before any derivation, wherever it is cut")
    func truncated() throws {
        let bytes = try Self.seal()
        let layout = Layout(bytes: bytes)
        var cuts = [0, 3, 4, 20, 50, 100, layout.count + 2, layout.manifest + 5, layout.entries, bytes.count - 1]
        cuts += layout.entryRanges.map(\.lowerBound) + layout.entryRanges.map { $0.lowerBound + 18 }
        for cut in cuts {
            #expect(throws: AccountArchiveError.self, "cut at \(cut)") {
                _ = try AccountArchive.parse(Array(bytes[..<cut]))
            }
        }
        // Dropping a whole entry and rewriting the count to match: the manifest binds the count, so it no longer
        // sits where it was sealed.
        var shorter = Array(bytes[..<layout.entryRanges[2].lowerBound])
        shorter.replaceSubrange(layout.count..<(layout.count + 4), with: Self.littleEndian(2))
        #expect(throws: AccountArchiveError.envelope(.contextMismatch)) { _ = try AccountArchive.parse(shorter) }
        var longer = bytes
        longer.append(0)
        #expect(throws: AccountArchiveError.trailingBytes) { _ = try AccountArchive.parse(longer) }
    }

    /// A1 reorders the entries, or moves one entry's identifier onto another's envelope. Each envelope's
    /// authenticated data names its position and its identifier, so both fail at parse.
    @Test("reordered or relabelled entries are refused at parse")
    func reordered() throws {
        let bytes = try Self.seal()
        let ranges = Layout(bytes: bytes).entryRanges
        var swapped = Array(bytes[..<ranges[0].lowerBound])
        swapped += bytes[ranges[1]] + bytes[ranges[0]] + bytes[ranges[2]]
        #expect(throws: AccountArchiveError.envelope(.contextMismatch)) { _ = try AccountArchive.parse(swapped) }
        var relabelled = bytes
        let firstID = Array(bytes[ranges[0].lowerBound..<(ranges[0].lowerBound + 16)])
        let secondID = Array(bytes[ranges[1].lowerBound..<(ranges[1].lowerBound + 16)])
        relabelled.replaceSubrange(ranges[0].lowerBound..<(ranges[0].lowerBound + 16), with: secondID)
        relabelled.replaceSubrange(ranges[1].lowerBound..<(ranges[1].lowerBound + 16), with: firstID)
        #expect(throws: AccountArchiveError.envelope(.contextMismatch)) { _ = try AccountArchive.parse(relabelled) }
    }

    /// A7 splices an entry from another archive (another key) into this one, at the same position: the envelope
    /// names a key the header does not, and is refused before decryption.
    @Test("an entry from another archive is refused at parse")
    func recordSwap() throws {
        let bytes = try Self.seal()
        let other = try Self.seal(
            ["something else", "the second, which is longer", "third"],
            archiveID: UUID(uuidString: "A2C00000-0000-4000-8000-000000000002")!, seed: 6)
        let mine = Layout(bytes: bytes).entryRanges
        let theirs = Layout(bytes: other).entryRanges
        var spliced = Array(bytes[..<mine[0].lowerBound])
        spliced += other[theirs[0]] + bytes[mine[1]] + bytes[mine[2]]
        let archive = try AccountArchive.parse(bytes)
        let theirKeyID = try AccountArchive.parse(other).archiveKeyID
        #expect(
            throws: AccountArchiveError.envelope(.keyMismatch(expected: archive.archiveKeyID, actual: theirKeyID))
        ) { _ = try AccountArchive.parse(spliced) }
        // An item record from the vault, put where an entry goes, is the wrong kind.
        var generator = SeededGenerator(seed: 8)
        let key = try EncryptionKey(
            keyID: archive.archiveKeyID, material: SecureBytes(randomCount: 32, using: &generator))
        defer { key.zeroise() }
        let item = try RecordCipher.seal(
            Array("an item".utf8),
            context: EnvelopeContext(
                recordID: UUID(), vaultID: archive.archiveID, schemaVersion: 1, kind: .item, keyID: key.keyID),
            key: key)
        var planted = Array(bytes[..<mine[2].lowerBound])
        planted += bytes[mine[2].lowerBound..<(mine[2].lowerBound + 16)] + Self.littleEndian(UInt32(item.count)) + item
        #expect(throws: AccountArchiveError.envelope(.kindMismatch(expected: .archive, actual: .item))) {
            _ = try AccountArchive.parse(planted)
        }
    }

    /// A7 rewrites the KDF parameters: below the floor to make guessing cheap, above the ceiling to make a restore
    /// hang. Both are refused before any derivation; a value inside the bounds changes the key, so it fails as a
    /// wrong passphrase does.
    @Test("KDF parameters outside the bounds are refused before deriving; inside them they change the key")
    func kdfTampered() throws {
        let bytes = try Self.seal()
        func with(iterations: UInt32) -> [UInt8] {
            var copy = bytes
            copy.replaceSubrange(Layout.iterations..<(Layout.iterations + 4), with: Self.littleEndian(iterations))
            return copy
        }
        let floor = KDFParameters.minimumIterations
        let ceiling = KDFParameters.maximumIterations
        #expect(throws: AccountArchiveError.kdf(.iterationsBelowMinimum(floor - 1, minimum: floor))) {
            _ = try AccountArchive.parse(with(iterations: floor - 1))
        }
        #expect(throws: AccountArchiveError.kdf(.iterationsAboveMaximum(UInt32.max, maximum: ceiling))) {
            _ = try AccountArchive.parse(with(iterations: UInt32.max))
        }
        #expect(throws: CryptoError.authenticationFailed) {
            _ = try AccountArchive.parse(with(iterations: floor + 1)).open(
                passphrase: Self.passphrase, secretKey: Self.secretKey)
        }
        var shortSalt = bytes
        shortSalt.replaceSubrange((Layout.salt - 2)..<(Layout.salt + 32), with: [8, 0] + Array(repeating: 0, count: 8))
        #expect(throws: AccountArchiveError.kdf(.saltTooShort(8, minimum: 16))) {
            _ = try AccountArchive.parse(shortSalt)
        }
    }

    /// A1 cannot tell a wrong guess from a tampered file, and neither can the person: a wrong passphrase, a wrong
    /// Secret Key, an altered salt, creation time or ciphertext all fail as one `authenticationFailed`.
    @Test("a wrong passphrase is indistinguishable from tampering")
    func indistinguishable() throws {
        let bytes = try Self.seal()
        let layout = Layout(bytes: bytes)
        let otherKey = try SecretKey(bytes: SecureBytes(copying: Array(0x30..<0x40)))
        var attempts: [(String, [UInt8], String, SecretKey)] = [
            ("wrong passphrase", bytes, "the archive's own passphrasE", Self.secretKey),
            ("empty passphrase", bytes, "", Self.secretKey),
            ("wrong Secret Key", bytes, Self.passphrase, otherKey),
        ]
        for (name, offset) in [
            ("created at", 40), ("salt", Layout.salt + 3), ("wrapped key", layout.count - 1),
            ("manifest", layout.entries - 1), ("entry", layout.entryRanges[1].upperBound - 1),
        ] {
            var copy = bytes
            copy[offset] ^= 0x01
            attempts.append((name, copy, Self.passphrase, Self.secretKey))
        }
        for (name, archive, passphrase, key) in attempts {
            #expect(throws: CryptoError.authenticationFailed, "\(name)") {
                _ = try AccountArchive.parse(archive).open(passphrase: passphrase, secretKey: key)
            }
        }
    }

    /// A7 hands over an archive another account made. Without that account's Secret Key it does not open; and its
    /// header cannot be relabelled as this account's, because the manifest's authenticated data names the account.
    @Test("an archive from another account opens only with that account's Secret Key")
    func anotherAccount() throws {
        let theirKey = try SecretKey(bytes: SecureBytes(copying: Array(0x50..<0x60)))
        let theirAccount = UUID(uuidString: "ACC00000-0000-4000-8000-0000000000B2")!
        let theirs = try Self.seal(secretKey: theirKey, accountID: theirAccount)
        #expect(throws: CryptoError.authenticationFailed) {
            _ = try AccountArchive.parse(theirs).open(passphrase: Self.passphrase, secretKey: Self.secretKey)
        }
        var relabelled = theirs
        relabelled.replaceSubrange(21..<37, with: Self.bytes(Self.accountID))
        #expect(throws: AccountArchiveError.envelope(.contextMismatch)) { _ = try AccountArchive.parse(relabelled) }
        #expect(try AccountArchive.parse(theirs).open(passphrase: Self.passphrase, secretKey: theirKey).count == 3)
    }

    /// A7 claims more entries than the file could hold, so that a parser that trusts the count reserves memory
    /// for them: refused on the count against the bytes that remain.
    @Test("an entry count the file cannot hold is refused before anything is allocated for it")
    func countBomb() throws {
        let bytes = try Self.seal()
        let layout = Layout(bytes: bytes)
        for count in [UInt32(AccountArchive.maximumEntries), UInt32.max] {
            var copy = bytes
            copy.replaceSubrange(layout.count..<(layout.count + 4), with: Self.littleEndian(count))
            #expect(throws: AccountArchiveError.self) { _ = try AccountArchive.parse(copy) }
        }
    }

    static func bytes(_ id: UUID) -> [UInt8] {
        let u = id.uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }
}

/// Import and export through `VaultSession`, attacked (docs/02-architecture.md §14.1; PRD F8.1–F8.4, F11.2).
///
/// Adversaries: **A7**, the author of an import file or archive the person is talked into importing (including an
/// archive made with an account of their own, handed over with its Emergency Kit), who controls every byte of it;
/// **A3**, someone holding the device while the app is unlocked, who does not know the account password.
///
/// Serialised: each lock test holds a cooperative-pool thread in a blocking wait (that is what proves the work is off
/// the actor), and run side by side on a three-core runner they took every thread of the pool, so `lock()` itself
/// could not be scheduled until their 60-second bounds ran out. One at a time, they hold one thread at most.
@Suite("Adversarial: interchange through the session", .serialized, .tags(.adversarial))
struct AdversarialSessionInterchangeTests {
    static let passphrase = "the archive's own passphrase"

    static func vault() async throws -> (TestVault, UUID) {
        let vault = TestVault()
        try await vault.createAccount()
        return (vault, try #require(await vault.session.personalVaultID))
    }

    static func bank(_ vaultID: UUID) -> Item {
        Item(
            vaultID: vaultID, title: "Bank", scopes: [ServiceScope(host: "bank.example")],
            fields: [
                Field(kind: .username, label: "Username", value: "wendy"),
                Field(kind: .password, label: "Password", value: "the-real-bank-pw"),
            ])
    }

    /// A7's archive (with its Kit), or a 1PUX or CXF file, dates its item in the year 9000 and, in the archive,
    /// gives a field an `autofill.lastReport` far in the future (Z85). Kept as written, the date pinned the item's
    /// `modifiedAt` on every device for good (sync takes the later), kept the "old password" check from firing, and
    /// the metadata rate-limited that field's relying-party reports for ever. Now the session bounds every date the
    /// file keeps by its clock, and the archive's AutoFill state is not restored; both are reported.
    @Test("a file cannot date an item in the future or restore the AutoFill extension's state")
    func futureDatesAndDeviceState() async throws {
        let (vault, personal) = try await Self.vault()
        let future = Date(timeIntervalSince1970: 221_845_392_000)
        var forged = Self.bank(personal)
        forged.createdAt = future
        forged.modifiedAt = future
        forged.fields[1].meta = ["autofill.lastReport": "221845392000", "autofill.reportedUnused": "1", "keep": "x"]
        forged.history = [
            ItemHistoryEntry(
                replacedAt: future, version: 1,
                fields: [Field(kind: .password, label: "Password", value: "old", meta: ["autofill.lastReport": "1"])])
        ]
        let attackerKey = SecretKey.generate()
        var generator = SeededGenerator(seed: 10)
        let archive = try AccountArchive.seal(
            [SecureBytes.concatenating([SecureBytes(copying: [2]), try ItemCodec.encode(forged)])], archiveID: UUID(),
            accountID: UUID(), createdAt: Date(timeIntervalSince1970: 0), passphrase: Self.passphrase,
            secretKey: attackerKey, parameters: .baseline, using: &generator)
        let restored = try await vault.session.createVault(name: "Restored")
        let preview = try await vault.session.previewArchiveImport(
            archive, passphrase: Self.passphrase, secretKey: attackerKey.formatted, into: restored.id)
        let warnings = preview.report.warnings.map(\.warning)
        #expect(warnings.contains(.futureDateBounded) && warnings.contains(.autoFillStateNotRestored(count: 3)))
        let outcome = try await vault.session.commitImport(preview.id, decisions: [:])
        let created = try await vault.session.item(id: try #require(outcome.created.first))
        let now = await vault.clock.now()
        #expect(created.createdAt <= now && created.modifiedAt <= now)
        #expect(created.history.allSatisfy { $0.replacedAt <= now })
        #expect(created.fields[1].meta == ["keep": "x"])
        #expect(created.history.allSatisfy { $0.fields.allSatisfy { $0.meta.isEmpty } })
        // An edit afterwards is dated by this device's clock, not pinned in the year 9000.
        await vault.clock.advance(by: 60)
        var edited = created
        edited.title = "Bank, edited"
        let saved = try await vault.session.save(edited)
        #expect(saved.modifiedAt == (await vault.clock.now()))

        // A plaintext file's dates are bounded the same way.
        let file =
            #"{"version":{"major":1,"minor":0},"exporterRpId":"x.example","exporterDisplayName":"X","timestamp":1,"#
            + #""accounts":[{"id":"YQ","username":"","email":"","collections":[],"items":[{"id":"aQ","title":"Dated","#
            + #""creationAt":221845392000,"modifiedAt":221845392000,"credentials":["#
            + #"{"type":"basic-auth","username":{"fieldType":"string","value":"pat"}}]}]}]}"#
        let plain = try await vault.session.previewImport(
            Array(file.utf8), format: .credentialExchange, into: restored.id)
        #expect(plain.report.warnings.map(\.warning).contains(.futureDateBounded), "\(plain.report.warnings)")
    }

    /// A7's archive, sealed under an account of the attacker's own and handed over with its Secret Key: it names an
    /// item ID the victim already holds, a vault ID of the victim's, sync metadata claiming huge counters and a
    /// conflict, and a scope the policy refuses. None of it reaches the vault: the import is a new item, with a new
    /// ID, in the vault the person chose, scoped as the policy allows, stamped by this device alone.
    @Test("an archive cannot choose an item's identity, vault, scopes or sync metadata")
    func hostileArchive() async throws {
        let (vault, personal) = try await Self.vault()
        let existing = try await vault.session.save(Self.bank(personal))
        var forged = Self.bank(personal)
        forged.id = existing.id
        forged.title = "Bank (forged)"
        forged.scopes = [ServiceScope(host: "com"), ServiceScope(host: "bank.example")]
        forged.fields[1].value = "attacker-chosen"
        forged.version = 1 << 40
        forged.clock = VersionVector([UUID(): 1 << 40])
        forged.conflicts = [
            .title: [
                ConflictingValue(
                    stamp: GroupStamp(revision: Revision(version: 1 << 40, device: UUID()), seen: VersionVector()),
                    value: .title("planted"))
            ]
        ]
        let attackerKey = SecretKey.generate()
        var generator = SeededGenerator(seed: 9)
        let encoded = try ItemCodec.encode(forged)
        let archive = try AccountArchive.seal(
            [SecureBytes.concatenating([SecureBytes(copying: [2]), encoded])], archiveID: UUID(), accountID: UUID(),
            createdAt: Date(timeIntervalSince1970: 0), passphrase: Self.passphrase, secretKey: attackerKey,
            parameters: .baseline, using: &generator)

        let preview = try await vault.session.previewArchiveImport(
            archive, passphrase: Self.passphrase, secretKey: attackerKey.formatted, into: personal)
        // It resembles the bank login, so the person must decide; keeping both is the choice that changes nothing.
        let match = try #require(preview.matches.first)
        #expect(match.existingID == existing.id)
        let outcome = try await vault.session.commitImport(preview.id, decisions: [match.importedID: .keepBoth])
        let created = try await vault.session.item(id: try #require(outcome.created.first))
        #expect(created.id != existing.id)
        #expect(try await vault.session.item(id: existing.id).field(.password)?.value == "the-real-bank-pw")
        #expect(created.scopes.map(\.host) == ["bank.example"])
        #expect(created.conflicts.isEmpty && created.title == "Bank (forged)")
        #expect(created.version < 1 << 20)
        #expect(created.clock.entries.values.allSatisfy { $0 < 1 << 20 })
    }

    /// A7's CSV names the bank's host and the person's own login name, so it matches the bank item, and carries a
    /// password of the attacker's and a sign-in URL that leads to the attacker's site. Merged without a choice, it
    /// adds no host, no URL and no sign-in field, and an export of the bank item afterwards names no other host.
    @Test("a merge without the person's choices widens nothing, here or in a later export")
    func mergeNeverWidens() async throws {
        let (vault, personal) = try await Self.vault()
        let existing = try await vault.session.save(Self.bank(personal))
        let file = Array(
            """
            Title,URL,Username,Password,Notes,OTPAuth
            Bank,https://bank.example/login?next=https://evil.example/,wendy,phished,,
            """.utf8)
        let preview = try await vault.session.previewImport(file, format: .passwordCSV, into: personal)
        let match = try #require(preview.matches.first)
        #expect(match.hasNewSignInFields && match.hasNewURLFields)
        let outcome = try await vault.session.commitImport(
            preview.id, decisions: [match.importedID: .merge(into: existing.id)])
        #expect(outcome.merged == [existing.id])
        let merged = try await vault.session.item(id: existing.id)
        #expect(merged.scopes == existing.scopes)
        #expect(merged.fields == existing.fields)
        let export = try await vault.session.exportPlaintext(
            .applePasswordsCSV, vaults: [personal], password: TestVault.password)
        #expect(!String(decoding: export.bytes, as: UTF8.self).contains("evil.example"))
    }

    /// A7 hands the person an archive whose cleartext header asks for the most iterations the bounds allow (25M,
    /// seconds of PBKDF2 on a phone), and nothing in it is authenticated until that derivation ends. The person, or
    /// auto-lock, locks meanwhile: the lock takes effect at once, with the vault keys zeroised, rather than waiting
    /// behind the file's choice of cost on the session's actor (review finding X1). The derivation runs through
    /// `awayFromSession`; here a stand-in for it blocks until the test has locked, so the lock can only have
    /// returned if the work was off the actor.
    @Test("a lock while an archive's key is derived takes effect at once, and the preview then fails")
    func lockWinsDuringArchiveDerivation() async throws {
        let (vault, _) = try await Self.vault()
        let epoch = await vault.session.lockEpoch
        let (started, starting) = AsyncStream.makeStream(of: Void.self)
        let release = DispatchSemaphore(value: 0)
        let released = Flag()
        let work = Task {
            try await vault.session.awayFromSession(.archiveDerivation, since: epoch) { () -> Int in
                starting.yield()
                // Bounded, so a regression fails instead of hanging: the lock below never returns while this
                // blocks the actor.
                if release.wait(timeout: .now() + 60) == .success { released.set() }
                return 1
            }
        }
        var iterator = started.makeAsyncIterator()
        _ = await iterator.next()
        await vault.session.lock()
        #expect(await vault.session.keys == nil)
        release.signal()
        await #expect(throws: VaultError.locked) { try await work.value }
        #expect(released.isSet, "lock() returned only after the work had given up waiting")
    }

    /// The session derives an export's wrapping key off its actor and hands it to `seal` (follow-up to X1). A caller
    /// that passes a key derived under another salt, archive or account, or a salt of the wrong length, must not get
    /// an archive that opens under someone else's derivation or is silently unreadable without error: the salt is
    /// checked, and the header names what was derived, so an archive whose key does not match it opens for nobody
    /// (`authenticationFailed`, as tampering).
    @Test("an archive sealed with a pre-derived key opens only under the derivation its header names")
    func preDerivedWrappingKey() throws {
        var generator = SeededGenerator(seed: 41)
        let (secretKey, accountID) = (AdversarialArchiveTests.secretKey, AdversarialArchiveTests.accountID)
        let archiveID = UUID()
        let salt = SecureBytes(randomCount: KDFParameters.baseline.saltLength, using: &generator).unprotectedCopy()
        func key(for archive: UUID, salt: [UInt8]) throws -> EncryptionKey {
            try ArchiveKeyDerivation.wrappingKey(
                passphrase: Self.passphrase, secretKey: secretKey, archiveID: archive,
                accountID: accountID,
                parameters: .baseline, salt: salt, keyID: UUID())
        }
        func seal(_ wrappingKey: EncryptionKey, salt: [UInt8]) throws -> [UInt8] {
            try AccountArchive.seal(
                entryCount: 1, payload: { _ in SecureBytes(copying: Array("entry".utf8)) }, archiveID: archiveID,
                accountID: accountID, createdAt: Date(timeIntervalSince1970: 1_800_000_000),
                wrappingKey: wrappingKey, salt: salt, parameters: .baseline, using: &generator)
        }
        let honest = try AccountArchive.parse(try seal(try key(for: archiveID, salt: salt), salt: salt))
        let opened = try honest.open(passphrase: Self.passphrase, secretKey: secretKey)
        #expect(opened.map(\.count) == [5])

        #expect(throws: CryptoError.saltLengthMismatch(expected: salt.count, actual: 3)) {
            _ = try seal(try key(for: archiveID, salt: salt), salt: [1, 2, 3])
        }
        var otherSalt = salt
        otherSalt[0] ^= 1
        for wrong in [try key(for: UUID(), salt: salt), try key(for: archiveID, salt: otherSalt)] {
            let archive = try AccountArchive.parse(try seal(wrong, salt: salt))
            #expect(throws: CryptoError.authenticationFailed) {
                _ = try archive.open(passphrase: Self.passphrase, secretKey: secretKey)
            }
        }
    }

    /// The same path end to end: A7 raises an archive's iteration count within the bounds (parse accepts it), and
    /// the preview, deriving off the actor, fails as authentication and leaves the session unlocked with nothing
    /// staged.
    @Test("an archive whose iteration count was raised fails as authentication through the session")
    func raisedIterations() async throws {
        let (vault, personal) = try await Self.vault()
        let key = SecretKey.generate()
        var generator = SeededGenerator(seed: 12)
        let archive = try AccountArchive.seal(
            [SecureBytes(copying: [1])], archiveID: UUID(), accountID: UUID(),
            createdAt: Date(timeIntervalSince1970: 0), passphrase: Self.passphrase, secretKey: key,
            parameters: KDFParameters(iterations: KDFParameters.minimumIterations), using: &generator)
        var ceiling = archive
        ceiling.replaceSubrange(
            AdversarialArchiveTests.Layout.iterations..<(AdversarialArchiveTests.Layout.iterations + 4),
            with: AdversarialArchiveTests.littleEndian(KDFParameters.minimumIterations * 2))
        #expect(throws: Never.self) { _ = try AccountArchive.parse(ceiling) }
        await #expect(throws: CryptoError.authenticationFailed) {
            try await vault.session.previewArchiveImport(
                ceiling, passphrase: Self.passphrase, secretKey: key.formatted, into: personal)
        }
        #expect(await vault.session.keys != nil)
        #expect(await vault.session.pendingImport == nil)
    }

    /// A3 holds the unlocked device and asks for a plaintext export or an archive under a passphrase of their
    /// own. Neither is made without the account password, and a wrong one fails as authentication.
    @Test("no export, plaintext or archive, without the account password")
    func exportNeedsPassword() async throws {
        let (vault, personal) = try await Self.vault()
        try await vault.session.save(Self.bank(personal))
        for format in [PlaintextExportFormat.onePUX, .applePasswordsCSV] {
            await #expect(throws: CryptoError.authenticationFailed) {
                try await vault.session.exportPlaintext(format, vaults: [personal], password: "not the password")
            }
        }
        await #expect(throws: CryptoError.authenticationFailed) {
            try await vault.session.exportArchive(
                vaults: [personal], passphrase: Self.passphrase, password: "a guess at the password")
        }
    }

    /// A3 comes to a device whose import preview was left on screen and then auto-locked: the drafts, every secret
    /// in the file, went with the lock, and nothing reads them back after the next unlock.
    @Test("a lock leaves nothing of a preview to read or commit")
    func previewAfterLock() async throws {
        let (vault, personal) = try await Self.vault()
        let existing = try await vault.session.save(Self.bank(personal))
        let file = Array("Title,URL,Username,Password,Notes,OTPAuth\nBank,https://bank.example/,wendy,pw2,,\n".utf8)
        let preview = try await vault.session.previewImport(file, format: .passwordCSV, into: personal)
        let match = try #require(preview.matches.first)
        await vault.session.lock()
        #expect(await vault.session.pendingImport == nil)
        try await vault.session.unlock(password: TestVault.password)
        await #expect(throws: InterchangeSessionError.noPendingImport) {
            try await vault.session.importAdditions(
                preview: preview.id, importedID: match.importedID, existingID: existing.id)
        }
        await #expect(throws: InterchangeSessionError.noPendingImport) {
            try await vault.session.commitImport(preview.id, decisions: [match.importedID: .keepBoth])
        }
    }
}

/// A flag one thread sets and another reads, for a test that blocks a thread on purpose.
final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    func set() {
        lock.lock()
        value = true
        lock.unlock()
    }

    var isSet: Bool {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}
