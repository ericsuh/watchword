import Foundation
import WatchwordEnvelope
import WatchwordKit
import WatchwordModel
import WatchwordStore
import WatchwordSync

/// A keyed checksum for the sync fakes: every byte of key and message changes the result, so tampering is caught in
/// tests the way AES-GCM and Ed25519 catch it in production. It is **not** cryptography — it exists so the whole sync
/// engine runs under `swift test` on Linux, where CryptoKit does not (docs/03-implementation-plan.md, rule 3). The
/// production adapters are milestone 3's Mac half.
public enum FakeMAC {
    public static func tag(key: [UInt8], message: [UInt8], length: Int = 16) -> [UInt8] {
        var output: [UInt8] = []
        var lane: UInt64 = 0
        while output.count < length {
            var state: UInt64 = 0xCBF2_9CE4_8422_2325 ^ (lane &* 0x9E37_79B9_7F4A_7C15)
            for byte in key + [0xFF] + message {
                state = mix((state ^ UInt64(byte)) &* 0x0000_0100_0000_01B3)
            }
            state = mix(state ^ UInt64(message.count))
            output += (0..<8).map { UInt8(truncatingIfNeeded: state >> (8 * $0)) }
            lane += 1
        }
        return Array(output.prefix(length))
    }

    static func mix(_ value: UInt64) -> UInt64 {
        var z = value &+ 0x9E37_79B9_7F4A_7C15
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// Envelope sealing for the fakes: a real `EnvelopeHeader` and `Envelope.parse` (so every context check is the
/// production one), with the AEAD replaced by a keystream and a `FakeMAC` tag over the whole header and ciphertext.
public enum FakeCipher {
    public static func seal(_ plaintext: [UInt8], context: EnvelopeContext, key: [UInt8], nonce: [UInt8]) throws
        -> [UInt8]
    {
        let header = try EnvelopeHeader(
            kind: context.kind, keyID: context.keyID, nonce: nonce, aad: context.canonicalAAD())
        let ciphertext = keystream(key: key, nonce: nonce, count: plaintext.count).enumerated().map {
            $0.element ^ plaintext[$0.offset]
        }
        let tag = FakeMAC.tag(key: key, message: header.serialized() + ciphertext)
        return try Envelope(header: header, ciphertext: ciphertext + tag).serialized()
    }

    public static func open(_ bytes: [UInt8], context: EnvelopeContext, key: [UInt8], maximumLength: Int) throws
        -> [UInt8]
    {
        let envelope = try Envelope.parse(bytes, expecting: context, maximumLength: maximumLength)
        let split = envelope.ciphertext.count - Envelope.tagLength
        let ciphertext = Array(envelope.ciphertext[..<split])
        guard
            FakeMAC.tag(key: key, message: envelope.authenticatedData + ciphertext)
                == Array(envelope.ciphertext[split...])
        else { throw SyncKeyringError.authenticationFailed }
        return keystream(key: key, nonce: envelope.header.nonce, count: ciphertext.count).enumerated().map {
            $0.element ^ ciphertext[$0.offset]
        }
    }

    static func keystream(key: [UInt8], nonce: [UInt8], count: Int) -> [UInt8] {
        var generator = SeededGenerator(
            seed: FakeMAC.tag(key: key, message: nonce, length: 8).enumerated().reduce(0) {
                $0 | UInt64($1.element) << (8 * UInt64($1.offset))
            })
        var bytes: [UInt8] = []
        bytes.reserveCapacity(count + 8)
        while bytes.count < count {
            let word = generator.next()
            bytes += (0..<8).map { UInt8(truncatingIfNeeded: word >> (8 * $0)) }
        }
        return Array(bytes.prefix(count))
    }
}

/// The keys one account's devices share in the fakes: vault keys, and the directory of devices trusted to sign.
public actor FakeAccountKeys {
    private var vaultKeys: [UUID: [UUID: [UInt8]]] = [:]
    private var currentKey: [UUID: UUID] = [:]
    private var deviceSecrets: [UUID: [UInt8]] = [:]
    private var generator: SeededGenerator

    public init(seed: UInt64 = 1) {
        generator = SeededGenerator(seed: seed)
    }

    /// Creates a vault key and makes it the vault's current key.
    @discardableResult
    public func addVaultKey(vaultID: UUID) -> UUID {
        let keyID = randomUUID()
        vaultKeys[vaultID, default: [:]][keyID] = randomBytes(32)
        currentKey[vaultID] = keyID
        return keyID
    }

    /// Enrols a device: it can sign, and its signatures verify.
    public func trust(device: UUID) {
        if deviceSecrets[device] == nil { deviceSecrets[device] = randomBytes(32) }
    }

    /// Removes a device from the directory; its signatures stop verifying.
    public func revoke(device: UUID) {
        deviceSecrets[device] = nil
    }

    func key(vaultID: UUID, keyID: UUID) -> [UInt8]? {
        vaultKeys[vaultID]?[keyID]
    }

    func current(vaultID: UUID) -> (UUID, [UInt8])? {
        guard let keyID = currentKey[vaultID], let key = vaultKeys[vaultID]?[keyID] else { return nil }
        return (keyID, key)
    }

    func secret(device: UUID) -> [UInt8]? {
        deviceSecrets[device]
    }

    func nonce() -> [UInt8] {
        randomBytes(EnvelopeHeader.nonceLength)
    }

    private func randomBytes(_ count: Int) -> [UInt8] {
        (0..<count).map { _ in UInt8(truncatingIfNeeded: generator.next()) }
    }

    private func randomUUID() -> UUID {
        let b = randomBytes(16)
        return UUID(
            uuid: (
                b[0], b[1], b[2], b[3], b[4], b[5], b[6] & 0x0F | 0x40, b[7], b[8] & 0x3F | 0x80, b[9], b[10], b[11],
                b[12], b[13], b[14], b[15]
            ))
    }
}

/// `SyncKeyring` for one device over `FakeAccountKeys`, with a lock switch: locked, it still verifies signatures but
/// cannot seal, open or sign (§7.4).
public actor FakeSyncKeyring: SyncKeyring {
    public let deviceID: UUID
    public let keys: FakeAccountKeys
    public private(set) var isLocked = false

    public init(deviceID: UUID, keys: FakeAccountKeys) {
        self.deviceID = deviceID
        self.keys = keys
    }

    public func lock() {
        isLocked = true
    }

    public func unlock() {
        isLocked = false
    }

    public func seal(_ payload: [UInt8], at location: SyncObjectLocation) async throws -> [UInt8] {
        guard !isLocked else { throw SyncKeyringError.locked }
        guard let (keyID, key) = await keys.current(vaultID: location.vaultID) else {
            throw SyncKeyringError.unknownKey(location.vaultID)
        }
        return try FakeCipher.seal(
            payload, context: location.envelopeContext(keyID: keyID), key: key, nonce: await keys.nonce())
    }

    public func open(_ envelope: [UInt8], context: EnvelopeContext) async throws -> [UInt8] {
        guard !isLocked else { throw SyncKeyringError.locked }
        guard let key = await keys.key(vaultID: context.vaultID, keyID: context.keyID) else {
            throw SyncKeyringError.unknownKey(context.keyID)
        }
        return try FakeCipher.open(envelope, context: context, key: key, maximumLength: Envelope.maximumLength)
    }

    public func sign(_ envelope: [UInt8], at location: SyncObjectLocation) async throws -> [UInt8] {
        guard !isLocked else { throw SyncKeyringError.locked }
        guard location.author == deviceID, let secret = await keys.secret(device: deviceID) else {
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
        return FakeMAC.tag(key: secret, message: envelope, length: 64)
    }

    public func verify(_ signature: [UInt8], over envelope: [UInt8], at location: SyncObjectLocation) async throws {
        guard let secret = await keys.secret(device: location.author) else {
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
        guard FakeMAC.tag(key: secret, message: envelope, length: 64) == signature else {
            throw SyncKeyringError.authenticationFailed
        }
    }

    // MARK: - Item records, as `VaultSession` seals them, for the fake merger and test clients.

    public static func itemContext(_ row: StoredRecord) -> EnvelopeContext {
        EnvelopeContext(
            recordID: row.recordID, vaultID: row.vaultID, schemaVersion: ItemCodec.schemaVersion, kind: .item,
            keyID: row.keyID, recordVersion: row.version)
    }

    /// Seals `item` as a row written by this device.
    public func sealItem(_ item: Item) async throws -> StoredRecord {
        guard !isLocked else { throw SyncKeyringError.locked }
        guard let (keyID, key) = await keys.current(vaultID: item.vaultID) else {
            throw SyncKeyringError.unknownKey(item.vaultID)
        }
        var row = StoredRecord(
            recordID: item.id, kind: .item, vaultID: item.vaultID, keyID: keyID, version: item.version,
            deviceID: deviceID, envelope: [])
        let plaintext = try ItemCodec.encode(item)
        defer { plaintext.zeroise() }
        row.envelope = try FakeCipher.seal(
            plaintext.unprotectedCopy(), context: Self.itemContext(row), key: key, nonce: await keys.nonce())
        return row
    }

    /// Opens an item row, with `VaultSession`'s identity check against the row.
    public func openItem(_ row: StoredRecord) async throws -> Item {
        guard !isLocked else { throw SyncKeyringError.locked }
        guard let key = await keys.key(vaultID: row.vaultID, keyID: row.keyID) else {
            throw SyncKeyringError.unknownKey(row.keyID)
        }
        let plaintext = try FakeCipher.open(
            row.envelope, context: Self.itemContext(row), key: key, maximumLength: ItemCodec.maximumPayloadLength + 4096
        )
        let item = try ItemCodec.decode(plaintext)
        guard item.id == row.recordID, item.vaultID == row.vaultID, item.version == row.version else {
            throw SyncKeyringError.authenticationFailed
        }
        return item
    }
}

/// The merger `VaultSession` will be, over the fake keyring: open both versions, `ItemMerge.merge`, seal the result
/// (docs/02-architecture.md §7.1). The production one is milestone 3's Mac half.
public struct FakeItemMerger: RecordMerger {
    public let keyring: FakeSyncKeyring

    public init(keyring: FakeSyncKeyring) {
        self.keyring = keyring
    }

    public func merge(local: StoredRecord, remote: StoredRecord) async throws -> MergeDecision {
        let remoteItem = try await keyring.openItem(remote)
        let localItem: Item
        do {
            localItem = try await keyring.openItem(local)
        } catch SyncKeyringError.locked {
            throw SyncKeyringError.locked
        } catch {
            // A local row that does not open is damage, not a version: the remote one replaces it.
            if remote.version > local.version { return .adoptRemote }
            let item = ItemMerge.written(
                remoteItem, as: Revision(version: local.version + 1, device: keyring.deviceID))
            return .replace(try await keyring.sealItem(item))
        }
        let merged = ItemMerge.merge(
            localItem, origin: Revision(version: local.version, device: local.deviceID),
            remoteItem, origin: Revision(version: remote.version, device: remote.deviceID))
        if ItemMerge.sameState(merged, remoteItem), remote.version > local.version { return .adoptRemote }
        if ItemMerge.sameState(merged, localItem) { return .keepLocal }
        let item = ItemMerge.written(
            merged, as: Revision(version: max(local.version, remote.version) + 1, device: keyring.deviceID))
        return .replace(try await keyring.sealItem(item))
    }

    /// The item's version vector, as JSON.
    public func erasureSummary(of record: StoredRecord) async throws -> [UInt8] {
        let item = try await keyring.openItem(record)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return Array(try encoder.encode(ItemMerge.effectiveClock(item, origin: Self.origin(record))))
    }

    public func resolveErasure(_ summary: [UInt8], of record: StoredRecord) async throws -> ErasureDecision {
        let item = try await keyring.openItem(record)
        // A summary that does not decode claims to have seen nothing, so nothing is erased because of it.
        let erased = (try? JSONDecoder().decode(VersionVector.self, from: Data(summary))) ?? VersionVector()
        if ItemMerge.isCovered(item, origin: Self.origin(record), byErasure: erased) { return .erase }
        if item.isTrashed { return .keep }
        // Above the record and above any erasure of what the erased vector names (an erasure is one past the row).
        let version = max(record.version, erased.entries.values.max() ?? 0) + 2
        var trashed = item
        trashed.trashedAt = item.modifiedAt
        trashed = ItemMerge.stamped(
            trashed, previous: item, previousOrigin: Self.origin(record),
            revision: Revision(version: version, device: keyring.deviceID))
        trashed.version = version
        return .replace(try await keyring.sealItem(trashed))
    }

    static func origin(_ record: StoredRecord) -> Revision {
        Revision(version: record.version, device: record.deviceID)
    }
}
