import Foundation
import SecureMemory
import Testing
import WatchwordEnvelope
import WatchwordTestSupport

@testable import WatchwordCrypto

@Suite("Encrypted archive key derivation")
struct ArchiveKeyDerivationTests {
    static let secretKey = try! SecretKey(bytes: SecureBytes(copying: Array(0..<16)))
    static let salt = Array(0x40..<0x60) as [UInt8]
    static let archiveID = UUID(uuidString: "A0A1A2A3-A4A5-4A6A-8A8A-A9AAABACADAE")!
    static let accountID = UUID(uuidString: "00112233-4455-4677-8899-AABBCCDDEEFF")!

    static func derive(
        _ passphrase: String, secretKey: SecretKey = secretKey, archiveID: UUID = archiveID,
        accountID: UUID = accountID
    ) throws -> [UInt8] {
        Array(
            try ArchiveKeyDerivation.wrappingKey(
                passphrase: passphrase, secretKey: secretKey, archiveID: archiveID, accountID: accountID,
                parameters: .baseline, salt: salt, keyID: UUID()
            ).material)
    }

    /// Expected keys from Python `cryptography` 50 (OpenSSL's PBKDF2 and HKDF) over the derivation as specified in
    /// docs/02-architecture.md §14.1, never from this code: `HKDF(salt, archiveID, "WW-archive-salt-v1")`, PBKDF2 of
    /// the NFKD passphrase at 650,000 iterations, `HKDF(SK, accountID, "WW-archive-2SKD-v1")`, and
    /// `HKDF(Kp ‖ Ks, archiveID ‖ accountID, "WW-archive-key-v1")`. The second vector is Python's
    /// `unicodedata.normalize("NFKD", …)` of a passphrase that NFKD changes: a precomposed "é" and the "ﬁ" ligature
    /// (U+FB01), which decompose to "e" + U+0301 and "fi". Derived from that input, the expected key holds only if
    /// the passphrase is normalised, and with NFKD (NFC would keep the ligature); its decomposed spelling, typed
    /// on another keyboard, must give the same key (review finding X6).
    @Test("matches an independent implementation of the derivation")
    func knownAnswer() throws {
        #expect(
            try Self.derive("correct horse battery staple")
                == [UInt8](hex: "3da66ec3ec9b9dd2b9e578fbc54d5281d650018c5bccacce9750544fdcfbd834"))
        let normalised = [UInt8](hex: "1ea1a0b0a9106a8e300736dc8b69c61ecc616929f291b9daab0d604de8f7b8be")
        #expect(try Self.derive("Caf\u{E9} \u{FB01}") == normalised)
        #expect(try Self.derive("Cafe\u{0301} fi") == normalised)
    }

    @Test("is not the Account Unlock Key of the same inputs, and every input changes it")
    func domainSeparated() throws {
        let base = try Self.derive("pw")
        let unlockKey = try TwoSecretKeyDerivation.accountUnlockKey(
            password: "pw", secretKey: Self.secretKey, accountID: Self.accountID, parameters: .baseline,
            salt: Self.salt, keyID: UUID())
        #expect(Array(unlockKey.material) != base)
        #expect(try Self.derive("pW") != base)
        let other = try SecretKey(bytes: SecureBytes(copying: Array(1...16)))
        #expect(try Self.derive("pw", secretKey: other) != base)
        #expect(try Self.derive("pw", archiveID: UUID()) != base)
        #expect(try Self.derive("pw", accountID: UUID()) != base)
    }

    @Test("refuses parameters outside the two-sided bounds before deriving anything")
    func bounds() {
        for iterations in [KDFParameters.minimumIterations - 1, KDFParameters.maximumIterations + 1] {
            #expect(throws: KDFValidationError.self) {
                _ = try ArchiveKeyDerivation.wrappingKey(
                    passphrase: "pw", secretKey: Self.secretKey, archiveID: Self.archiveID,
                    accountID: Self.accountID, parameters: KDFParameters(iterations: iterations), salt: Self.salt,
                    keyID: UUID())
            }
        }
    }
}

@Suite("Encrypted archive format")
struct AccountArchiveTests {
    static let passphrase = "a passphrase for the archive"

    static func payloads(_ texts: [String]) -> [SecureBytes] {
        texts.map { SecureBytes(copying: Array($0.utf8)) }
    }

    static func sealed(_ texts: [String], seed: UInt64 = 1) throws -> [UInt8] {
        var generator = SeededGenerator(seed: seed)
        return try AccountArchive.seal(
            payloads(texts), archiveID: ArchiveKeyDerivationTests.archiveID,
            accountID: ArchiveKeyDerivationTests.accountID, createdAt: Date(timeIntervalSince1970: 1_800_000_000),
            passphrase: passphrase, secretKey: ArchiveKeyDerivationTests.secretKey, parameters: .baseline,
            using: &generator)
    }

    @Test("opens what it sealed, in order, and reads the header back")
    func roundTrip() throws {
        let texts = ["first", "", "third entry, a little longer"]
        let archive = try AccountArchive.parse(try Self.sealed(texts))
        #expect(archive.archiveID == ArchiveKeyDerivationTests.archiveID)
        #expect(archive.accountID == ArchiveKeyDerivationTests.accountID)
        #expect(archive.createdAt == Date(timeIntervalSince1970: 1_800_000_000))
        #expect(archive.kdf == .baseline)
        #expect(archive.entryCount == 3)
        let opened = try archive.open(passphrase: Self.passphrase, secretKey: ArchiveKeyDerivationTests.secretKey)
        #expect(opened.map { String(decoding: $0.unprotectedCopy(), as: UTF8.self) } == texts)
    }

    /// An archive written by an independent Python implementation of the format in docs/02-architecture.md §14.1
    /// (`cryptography` 50's AES-GCM, HKDF and PBKDF2, its own CBOR and envelope encoding; fixed keys and nonces), so
    /// the layout, every authenticated-data binding and the manifest are checked against the specification rather
    /// than against this code. The same bytes are the `archive` fuzz target's seed (`Fuzz/Corpus/archive`).
    static let independentArchive = [UInt8](
        hex: """
            5757415201a0a1a2a3a4a54a6a8a8aa9aaabacadae00112233445546778899aabbccddeeff00d2496b000000000110eb0900200040\
            4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f11111111111141118111111111111111222222222222\
            42228222222222222222920057574531010009111111111111411181111111111111110000000000000000000000003d00a6015022\
            2222222222422282222222222222220250a0a1a2a3a4a54a6a8a8aa9aaabacadae030104090550111111111111411181111111111111\
            1106006dae88768c07df33f921f0b2bcfd976722651b6bc4cc04574734ba47aa8b3c51b4204d231b62bca30f1d76614b3cda280200\
            0000b20057574531010009222222222222422282222222222222220000000000000000000000103d00a60150a0a1a2a3a4a54a6a8a\
            8aa9aaabacadae025000112233445546778899aabbccddeeff030204090550222222222222422282222222222222220602bc1c6950\
            9a556c35a823012a4660c14ca13cb6da9bd53055701547c9e07679a8daf3f47281634b85f3971aac788c02e06628a336c51f6ab02e\
            464271eb5d4a49c323037717ca3a88c99df7d831b88fc1333333333333433383333333333333317e00000057574531010009222222\
            222222422282222222222222220000000000000000000000013d00a60150333333333333433383333333333333310250a0a1a2a3a4\
            a54a6a8a8aa9aaabacadae030304090550222222222222422282222222222222220601d0c9f126f78571280786e80672dd2ffec0b7\
            8ba713827924b203f008333333333333433383333333333333327f0000005757453101000922222222222242228222222222222222\
            0000000000000000000000023d00a60150333333333333433383333333333333320250a0a1a2a3a4a54a6a8a8aa9aaabacadae0303\
            04090550222222222222422282222222222222220602e3dc4df29e66323110fe9b597f8d6d0e8e897a4ebc0006c5212f049c9d
            """)

    @Test("opens an archive another implementation wrote from the specification")
    func independentImplementation() throws {
        let archive = try AccountArchive.parse(Self.independentArchive)
        #expect(archive.archiveID == ArchiveKeyDerivationTests.archiveID)
        #expect(archive.accountID == ArchiveKeyDerivationTests.accountID)
        #expect(archive.createdAt == Date(timeIntervalSince1970: 1_800_000_000))
        let opened = try archive.open(
            passphrase: "correct horse battery staple", secretKey: ArchiveKeyDerivationTests.secretKey)
        #expect(
            opened.map { $0.unprotectedCopy() } == [[1] + Array("first entry".utf8), [2] + Array("second entry".utf8)])
    }

    /// Review finding X3: every `SecureBytes` is at least a page, so an archive's plaintexts must not all be held at
    /// once. Each one `seal` asks for, and each one `open` hands over, is zeroised as soon as it has been used.
    @Test("holds one entry's plaintext at a time, sealing and opening")
    func oneEntryAtATime() throws {
        let texts = ["first", "second", "third"]
        var produced: [SecureBytes] = []
        var previousZeroised: [Bool] = []
        var generator = SeededGenerator(seed: 2)
        let bytes = try AccountArchive.seal(
            entryCount: texts.count,
            payload: { index in
                previousZeroised.append(produced.allSatisfy(\.isZeroised))
                let payload = SecureBytes(copying: Array(texts[index].utf8))
                produced.append(payload)
                return payload
            },
            archiveID: ArchiveKeyDerivationTests.archiveID, accountID: ArchiveKeyDerivationTests.accountID,
            createdAt: Date(timeIntervalSince1970: 1_800_000_000), passphrase: Self.passphrase,
            secretKey: ArchiveKeyDerivationTests.secretKey, parameters: .baseline, using: &generator)
        #expect(produced.count == 3 && produced.allSatisfy(\.isZeroised))
        #expect(previousZeroised == [true, true, true], "each entry was zeroised before the next was asked for")
        previousZeroised = []

        var handed: [SecureBytes] = []
        var read: [String] = []
        try AccountArchive.parse(bytes).open(
            passphrase: Self.passphrase, secretKey: ArchiveKeyDerivationTests.secretKey
        ) { payload in
            previousZeroised.append(handed.allSatisfy(\.isZeroised))
            handed.append(payload)
            read.append(String(decoding: payload.unprotectedCopy(), as: UTF8.self))
        }
        #expect(read == texts)
        #expect(handed.count == 3 && handed.allSatisfy(\.isZeroised))
        #expect(previousZeroised == [true, true, true], "each entry was zeroised before the next was opened")
    }

    @Test("an empty archive is still a sealed one")
    func empty() throws {
        let archive = try AccountArchive.parse(try Self.sealed([]))
        #expect(try archive.open(passphrase: Self.passphrase, secretKey: ArchiveKeyDerivationTests.secretKey).isEmpty)
    }

    @Test("the plaintext appears nowhere in the file")
    func encrypted() throws {
        let marker = "the-secret-in-the-archive"
        let bytes = try Self.sealed([marker])
        let needle = Array(marker.utf8)
        #expect(!bytes.indices.dropLast(needle.count).contains { Array(bytes[$0..<($0 + needle.count)]) == needle })
    }
}
