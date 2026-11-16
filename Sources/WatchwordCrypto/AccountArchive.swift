import Crypto
import Foundation
import SecureMemory
import WatchwordEnvelope

/// Why an encrypted Watchword archive did not parse. An archive is a file from anywhere (adversary A7, and A1 when
/// it sits in a cloud drive), so these are all decided on the bytes alone, before any key is derived.
public enum AccountArchiveError: Error, Equatable, Sendable {
    case truncated
    case badMagic
    case unsupportedVersion(UInt8)
    case unsupportedKDF(UInt8)
    /// KDF parameters outside the two-sided bounds: below the floor (a downgrade) or above the ceiling (a hang).
    case kdf(KDFValidationError)
    /// Larger than `AccountArchive.maximumLength`; refused before anything is copied.
    case tooLarge(Int)
    case tooManyEntries(Int)
    case entryTooLarge(Int)
    case trailingBytes
    /// Two entries with one identifier, or a field no writer produces (a creation time beyond the year 9999).
    case notCanonical
    /// An envelope in the archive that is not the one its place in the archive says it is: another kind, another
    /// key, or authenticated data naming another archive, entry or position (a swapped or reordered entry).
    case envelope(EnvelopeError)
}

/// The encrypted Watchword archive: a whole-account backup that only Watchword reads (docs/02-architecture.md §14.1,
/// ADR 0008, PRD F8.4). Versioned, portable, and made of the same envelopes as the vault.
///
/// ```
/// magic "WWAR"  formatVersion u8 = 1
/// archiveID 16  accountID 16  createdAt u64 (seconds since 1970)
/// kdfAlgorithm u8 (1 = PBKDF2-HMAC-SHA256)  iterations u32  salt (u16 length)
/// wrapKeyID 16  archiveKeyID 16
/// wrappedKey (u16 length)     the archive key, sealed under the key ArchiveKeyDerivation derives       schema 1
/// entryCount u32
/// ── the header: everything above ──
/// manifest (u16 length)       sealed under the archive key: SHA-256(header) ‖ SHA-256(entries)          schema 2
/// entries                     entryCount × (entryID 16, envelope (u32 length)), each sealed under the
///                             archive key, at recordVersion = its position counting from one             schema 3
/// ```
///
/// Every envelope is of kind `.archive`, and its authenticated data binds where it is: the wrap names the archive
/// key and the archive; the manifest the archive, the account and the entry count; each entry its own identifier,
/// the archive and its position. So:
///
/// - **Before any derivation** (`parse`) every length is bounded and checked against what remains, the entry count
///   against the bytes that could hold it, the KDF parameters on both sides (a floor against a downgrade, a ceiling
///   against an archive that turns a restore into a hang), and every envelope's kind, key and authenticated data
///   against the place it was found. An entry moved to another position or another archive fails here.
/// - **After derivation** (`open`) the wrap must open (a wrong passphrase, a wrong Secret Key, an archive made for
///   another account and a header altered in any field the key depends on all fail as one
///   `CryptoError.authenticationFailed`), then the manifest, whose digests cover every other byte of the header and
///   of the entries, in order. A truncated, extended or reordered archive, or one with an entry from another
///   archive under the same key, fails there, as the same error, before a single entry is decrypted.
///
/// Nothing in the clear is secret (identifiers, a time, KDF parameters, ciphertext sizes), and nothing in the clear
/// is believed: identities come from the header the caller parsed, and the caller checks the account ID against the
/// account it expects.
public struct AccountArchive: Sendable {
    /// A household's whole account is tens of megabytes; this bounds what a hostile file can make a restore read.
    public static let maximumLength = 256 << 20
    public static let maximumEntries = 200_000
    /// One entry: an item at its largest (`ItemCodec`'s 1 MiB) and room for the envelope and a type byte.
    public static let maximumEntryLength = (1 << 20) + (64 << 10)
    static let maximumWrappedLength = 1024
    static let magic = Array("WWAR".utf8)
    static let formatVersion: UInt8 = 1
    static let wrapSchemaVersion: UInt64 = 1
    static let manifestSchemaVersion: UInt64 = 2
    static let entrySchemaVersion: UInt64 = 3
    /// 9999-12-31T23:59:59Z.
    static let latestTimestamp: UInt64 = 253_402_300_799
    /// The smallest an entry can be: its identifier, its length and an envelope holding an empty plaintext.
    static let minimumEntryLength = 16 + 4 + EnvelopeHeader.fixedPrefixLength + Envelope.tagLength

    public let archiveID: UUID
    /// The account whose Secret Key the archive is sealed under.
    public let accountID: UUID
    public let createdAt: Date
    public let kdf: KDFParameters
    public var entryCount: Int { entries.count }

    let salt: [UInt8]
    let wrapKeyID: UUID
    let archiveKeyID: UUID
    let wrappedKey: [UInt8]
    let manifest: [UInt8]
    let entries: [(id: UUID, envelope: [UInt8])]
    /// SHA-256 of the header bytes and of the entries' bytes, as parsed: what the manifest must say.
    let expectedManifest: [UInt8]

    // MARK: - Writing

    /// Seals `entryCount` payloads, in order, into a new archive for `accountID` under a fresh archive key wrapped
    /// under the key derived from `passphrase` and `secretKey` with `parameters` (validated first) and a fresh salt.
    ///
    /// `payload` is called once per entry, in order, and what it returns is zeroised as soon as it is sealed, so an
    /// export holds one entry's plaintext in protected storage at a time: every `SecureBytes` is at least a page
    /// (16 KiB on arm64 Darwin), and an archive of 200,000 small items built as an array would need 3 GiB of them.
    public static func seal<R: RandomNumberGenerator>(
        entryCount: Int, payload: (Int) throws -> SecureBytes, archiveID: UUID, accountID: UUID, createdAt: Date,
        passphrase: String, secretKey: SecretKey, parameters: KDFParameters, using generator: inout R
    ) throws -> [UInt8] {
        try parameters.validate()
        guard entryCount >= 0, entryCount <= maximumEntries else {
            throw AccountArchiveError.tooManyEntries(entryCount)
        }
        let salt = SecureBytes(randomCount: parameters.saltLength, using: &generator).unprotectedCopy()
        let wrapKeyID = UUID.randomVersion4(using: &generator)
        let wrappingKey = try ArchiveKeyDerivation.wrappingKey(
            passphrase: passphrase, secretKey: secretKey, archiveID: archiveID, accountID: accountID,
            parameters: parameters, salt: salt, keyID: wrapKeyID)
        defer { wrappingKey.zeroise() }
        let archiveKey = EncryptionKey.generate(using: &generator)
        defer { archiveKey.zeroise() }
        let wrapped = try RecordCipher.seal(
            archiveKey.material,
            context: wrapContext(archiveID: archiveID, archiveKeyID: archiveKey.keyID, wrapKeyID: wrapKeyID),
            key: wrappingKey, using: &generator)

        var entriesBytes: [UInt8] = []
        for index in 0..<entryCount {
            let entryID = UUID.randomVersion4(using: &generator)
            let plaintext = try payload(index)
            defer { plaintext.zeroise() }
            let envelope = try RecordCipher.seal(
                plaintext,
                context: entryContext(
                    archiveID: archiveID, entryID: entryID, index: index, archiveKeyID: archiveKey.keyID),
                key: archiveKey, using: &generator)
            guard envelope.count <= maximumEntryLength else {
                throw AccountArchiveError.entryTooLarge(envelope.count)
            }
            entriesBytes += entryID.byteArray + AccountBytes.littleEndian(UInt32(envelope.count)) + envelope
        }

        var header = magic
        header.append(formatVersion)
        header += archiveID.byteArray + accountID.byteArray
        let seconds = UInt64(max(0, min(createdAt.timeIntervalSince1970.rounded(.down), Double(latestTimestamp))))
        header += AccountBytes.littleEndian(seconds)
        header.append(1)
        header += AccountBytes.littleEndian(parameters.iterations) + AccountBytes.field(salt)
        header += wrapKeyID.byteArray + archiveKey.keyID.byteArray
        header += AccountBytes.field(wrapped)
        header += AccountBytes.littleEndian(UInt32(entryCount))

        let manifest = try RecordCipher.seal(
            AccountBytes.sha256(header) + AccountBytes.sha256(entriesBytes),
            context: manifestContext(
                archiveID: archiveID, accountID: accountID, archiveKeyID: archiveKey.keyID,
                entryCount: entryCount),
            key: archiveKey, using: &generator)
        let archive = header + AccountBytes.field(manifest) + entriesBytes
        guard archive.count <= maximumLength else { throw AccountArchiveError.tooLarge(archive.count) }
        return archive
    }

    /// `seal(entryCount:payload:...)` over an array, for tests and small archives. The caller's buffers are copied
    /// and left as they were.
    static func seal<R: RandomNumberGenerator>(
        _ payloads: [SecureBytes], archiveID: UUID, accountID: UUID, createdAt: Date, passphrase: String,
        secretKey: SecretKey, parameters: KDFParameters, using generator: inout R
    ) throws -> [UInt8] {
        try seal(
            entryCount: payloads.count, payload: { payloads[$0].extracting(0..<payloads[$0].count) },
            archiveID: archiveID, accountID: accountID, createdAt: createdAt, passphrase: passphrase,
            secretKey: secretKey, parameters: parameters, using: &generator)
    }

    // MARK: - Reading

    /// Parses an archive exactly and checks everything that can be checked without a key: lengths, counts, the KDF
    /// parameters' two-sided bounds, and every envelope's kind, key and authenticated data against its place.
    public static func parse(_ bytes: [UInt8]) throws -> AccountArchive {
        guard bytes.count <= maximumLength else { throw AccountArchiveError.tooLarge(bytes.count) }
        do {
            return try parseChecked(bytes)
        } catch AccountFormatError.truncated {
            throw AccountArchiveError.truncated
        } catch AccountFormatError.tooLong {
            // A salt, wrapped key or manifest longer than any writer makes.
            throw AccountArchiveError.notCanonical
        } catch let error as EnvelopeError {
            throw AccountArchiveError.envelope(error)
        }
    }

    private static func parseChecked(_ bytes: [UInt8]) throws -> AccountArchive {
        var reader = AccountByteReader(bytes)
        guard try reader.read(4) == magic else { throw AccountArchiveError.badMagic }
        let version = try reader.byte()
        guard version == formatVersion else { throw AccountArchiveError.unsupportedVersion(version) }
        let archiveID = try reader.uuid()
        let accountID = try reader.uuid()
        let seconds = try reader.uint64()
        guard seconds <= latestTimestamp else { throw AccountArchiveError.notCanonical }
        let algorithm = try reader.byte()
        guard algorithm == 1 else { throw AccountArchiveError.unsupportedKDF(algorithm) }
        let iterations = try reader.uint32()
        let salt = try reader.field(maximum: KDFParameters.maximumSaltLength)
        let kdf = KDFParameters(iterations: iterations, saltLength: salt.count)
        do {
            try kdf.validate()
        } catch let error as KDFValidationError {
            throw AccountArchiveError.kdf(error)
        }
        let wrapKeyID = try reader.uuid()
        let archiveKeyID = try reader.uuid()
        let wrappedKey = try reader.field(maximum: maximumWrappedLength)
        let count = Int(try reader.uint32())
        guard count <= maximumEntries else { throw AccountArchiveError.tooManyEntries(count) }
        let headerEnd = reader.offset
        let manifest = try reader.field(maximum: maximumWrappedLength)
        // Before anything is allocated for them: the entries claimed must fit in what is left.
        guard count * minimumEntryLength <= reader.remaining else { throw AccountArchiveError.truncated }
        let entriesStart = reader.offset

        var entries: [(id: UUID, envelope: [UInt8])] = []
        entries.reserveCapacity(count)
        var seen = Set<UUID>()
        for index in 0..<count {
            let entryID = try reader.uuid()
            guard seen.insert(entryID).inserted else { throw AccountArchiveError.notCanonical }
            let length = Int(try reader.uint32())
            guard length <= maximumEntryLength else { throw AccountArchiveError.entryTooLarge(length) }
            let envelope = try reader.read(length)
            _ = try Envelope.parse(
                envelope,
                expecting: entryContext(
                    archiveID: archiveID, entryID: entryID, index: index, archiveKeyID: archiveKeyID),
                maximumLength: maximumEntryLength)
            entries.append((entryID, envelope))
        }
        guard reader.remaining == 0 else { throw AccountArchiveError.trailingBytes }
        _ = try Envelope.parse(
            wrappedKey,
            expecting: wrapContext(archiveID: archiveID, archiveKeyID: archiveKeyID, wrapKeyID: wrapKeyID),
            maximumLength: maximumWrappedLength)
        _ = try Envelope.parse(
            manifest,
            expecting: manifestContext(
                archiveID: archiveID, accountID: accountID, archiveKeyID: archiveKeyID, entryCount: count),
            maximumLength: maximumWrappedLength)

        return AccountArchive(
            archiveID: archiveID, accountID: accountID, createdAt: Date(timeIntervalSince1970: TimeInterval(seconds)),
            kdf: kdf, salt: salt, wrapKeyID: wrapKeyID, archiveKeyID: archiveKeyID, wrappedKey: wrappedKey,
            manifest: manifest, entries: entries,
            expectedManifest: AccountBytes.sha256(Array(bytes[..<headerEnd]))
                + AccountBytes.sha256(Array(bytes[entriesStart...])))
    }

    /// Derives the wrapping key from `passphrase` and `secretKey` (the Secret Key of `accountID`, the account the
    /// header names), opens the archive key, checks the manifest against every byte parsed, and only then opens
    /// the entries, in order, handing each plaintext to `body` and zeroising it as soon as `body` returns: a restore
    /// holds one entry's plaintext in protected storage at a time, however many entries the archive has. Every
    /// failure from the derivation on is `CryptoError.authenticationFailed`: a wrong passphrase, a wrong Secret Key
    /// and a tampered archive are not told apart.
    ///
    /// The manifest covers every entry's ciphertext, so an entry that fails to open after it was checked can only
    /// have been sealed that way by someone holding the archive key; `body` may then have seen earlier entries, and
    /// the caller discards what it built from them when this throws.
    ///
    /// The derivation costs what the header's iteration count says, up to `KDFParameters.maximumIterations`, before
    /// anything in the file is authenticated: a caller that holds keys runs this away from them (the session does,
    /// off its actor, so `lock()` is not kept waiting behind a file's choice of cost).
    public func open(passphrase: String, secretKey: SecretKey, each body: (SecureBytes) -> Void) throws {
        let wrappingKey: EncryptionKey
        do {
            wrappingKey = try ArchiveKeyDerivation.wrappingKey(
                passphrase: passphrase, secretKey: secretKey, archiveID: archiveID, accountID: accountID,
                parameters: kdf, salt: salt, keyID: wrapKeyID)
        } catch CryptoError.emptyPassword {
            throw CryptoError.authenticationFailed
        }
        defer { wrappingKey.zeroise() }
        do {
            let material = try RecordCipher.open(
                wrappedKey,
                context: Self.wrapContext(archiveID: archiveID, archiveKeyID: archiveKeyID, wrapKeyID: wrapKeyID),
                key: wrappingKey, maximumLength: Self.maximumWrappedLength)
            guard material.count == EncryptionKey.byteCount else {
                material.zeroise()
                throw CryptoError.authenticationFailed
            }
            let archiveKey = try EncryptionKey(keyID: archiveKeyID, material: material)
            defer { archiveKey.zeroise() }
            let manifestPlaintext = try RecordCipher.open(
                manifest,
                context: Self.manifestContext(
                    archiveID: archiveID, accountID: accountID, archiveKeyID: archiveKeyID, entryCount: entryCount),
                key: archiveKey, maximumLength: Self.maximumWrappedLength)
            // Digests of bytes that are not secret.
            let digests = manifestPlaintext.unprotectedCopy()
            manifestPlaintext.zeroise()
            guard digests == expectedManifest else { throw CryptoError.authenticationFailed }
            for (index, entry) in entries.enumerated() {
                let plaintext = try RecordCipher.open(
                    entry.envelope,
                    context: Self.entryContext(
                        archiveID: archiveID, entryID: entry.id, index: index, archiveKeyID: archiveKeyID),
                    key: archiveKey, maximumLength: Self.maximumEntryLength)
                body(plaintext)
                plaintext.zeroise()
            }
        } catch {
            throw CryptoError.authenticationFailed
        }
    }

    /// Every entry's plaintext at once, each in its own protected buffer: for tests and small archives only (see
    /// `open(passphrase:secretKey:each:)`).
    func open(passphrase: String, secretKey: SecretKey) throws -> [SecureBytes] {
        var opened: [SecureBytes] = []
        do {
            try open(passphrase: passphrase, secretKey: secretKey) { opened.append($0.extracting(0..<$0.count)) }
        } catch {
            for payload in opened { payload.zeroise() }
            throw error
        }
        return opened
    }

    // MARK: - Contexts

    static func wrapContext(archiveID: UUID, archiveKeyID: UUID, wrapKeyID: UUID) -> EnvelopeContext {
        EnvelopeContext(
            recordID: archiveKeyID, vaultID: archiveID, schemaVersion: wrapSchemaVersion, kind: .archive,
            keyID: wrapKeyID)
    }

    static func manifestContext(archiveID: UUID, accountID: UUID, archiveKeyID: UUID, entryCount: Int)
        -> EnvelopeContext
    {
        EnvelopeContext(
            recordID: archiveID, vaultID: accountID, schemaVersion: manifestSchemaVersion, kind: .archive,
            keyID: archiveKeyID, recordVersion: UInt64(entryCount))
    }

    static func entryContext(archiveID: UUID, entryID: UUID, index: Int, archiveKeyID: UUID) -> EnvelopeContext {
        EnvelopeContext(
            recordID: entryID, vaultID: archiveID, schemaVersion: entrySchemaVersion, kind: .archive,
            keyID: archiveKeyID, recordVersion: UInt64(index) + 1)
    }
}
