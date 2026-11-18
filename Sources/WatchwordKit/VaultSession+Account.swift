import Foundation
import SecureMemory
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordStore
import WatchwordSync

/// A device of the account, for the Devices screen (docs/02-architecture.md §7.8).
public struct DeviceInfo: Sendable, Hashable, Identifiable {
    public var id: UUID
    /// The name the device registered with; empty if it cannot be read.
    public var name: String
    public var addedAt: Date?
    public var isThisDevice: Bool
    public var isRevoked: Bool
    /// The device that registered it, or `nil` if it registered itself with the account password and Secret Key.
    public var addedBy: UUID?
    public var revokedBy: UUID?
}

/// A device's ID and public signing key, made before it joins the account so that a registered device can vouch
/// for it.
public struct DeviceIdentity: Sendable, Hashable {
    public var id: UUID
    public var key: DevicePublicKey

    public init(id: UUID, key: DevicePublicKey) {
        self.id = id
        self.key = key
    }
}

/// A password change made on another device that this one does not follow (`VaultSession.pendingPasswordChanges`).
public struct PendingPasswordChange: Sendable, Hashable, Identifiable {
    public var id: UUID { device }
    /// The device that made the change.
    public var device: UUID
    /// The name that device registered with; empty while locked or if it cannot be read.
    public var deviceName: String
    public var generation: UInt64
    /// Whether the change branches off before the credentials this device follows (made at the same time as a
    /// change this device has already followed, or with a password since retired) rather than after them.
    public var isFork: Bool
    /// Whether the registry replays along the change at all. One that does not can never be followed.
    public var canBeFollowed: Bool
    /// The devices this device knows that are revoked in the registry as the change leaves it.
    public var revokedDevices: [UUID]
    /// This device is among them: the change is refused here (`passwordChangeRevokesThisDevice`).
    public var revokesThisDevice: Bool
    /// Whether the device that made it was registered before the password change this device follows, as that
    /// change sealed it, rather than after it (review finding Z13). A device registered after it may have been
    /// registered with the password it retired, by whoever else knew that password; the list puts these second.
    public var registeredBeforeFollowed: Bool
    /// Whether `canBeFollowed`, `revokedDevices` and `revokesThisDevice` were worked out: each costs a replay of the
    /// registry, so the list does that for its first `maximumChangesDescribed` rows only, and
    /// `describePasswordChange(by:)` does it for the one the person selects. Until then they say nothing.
    public var isDescribed: Bool
}

/// What becomes of the account password when a device is revoked (docs/02-architecture.md §7.8). Both choices take
/// the current password: removing a device is not something an unattended, unlocked session should be able to do.
public enum RevocationPasswordChoice: Sendable, Hashable {
    /// The person confirms the device was locked when it left their hands, and that nobody who may hold it knows the
    /// account password. Then the device has no account key and can write nothing, and the password may stay.
    case keepPassword(current: String)
    /// Change the account password in the same step. Required whenever the device may have been unlocked by someone
    /// else or its password may be known: whoever opened the keyset still has the account key, and only a password
    /// they do not know stops them from registering another device with it.
    case change(current: String, new: String)
}

/// What this device trusts of the registry, kept in the Keychain (`KeychainItem.deviceRegistryAnchor`).
///
/// `"WWRA3" ‖ genesis 32 ‖ credential 32 ‖ generation u64 ‖ headCount u16 ‖ heads ‖ pendingCount u8 ‖ pending ‖
/// intentFlag u8 ‖ (intent credential 32 ‖ intent header 32)?`, little-endian. An anchor written before `intent`
/// existed (`"WWRA2"`, nothing after `pending`) is read as one with no step under way, and one written before
/// `pending` existed (`"WWRA1"`, nothing after the heads) as one that has also seen no change.
struct RegistryAnchor: Equatable, Sendable {
    static let magic = Array("WWRA3".utf8)
    static let secondMagic = Array("WWRA2".utf8)
    static let firstMagic = Array("WWRA1".utf8)
    static let maximumHeads = 256
    static let maximumPending = 16

    /// A step of this device's own that moves it to another credential entry (adopting a password change, or making
    /// one), written here **before** the store commits it (review finding Z9). The local file is A8's, so a header
    /// row ahead of the anchor is this device's own step only if the Keychain says so: `credential` is the entry the
    /// step follows and `header` the SHA-256 of the exact header row it commits. A crash between the commit and the
    /// pin leaves an intent that the next read completes (the row is that header) or discards (the row is still the
    /// one the anchor follows); a row that is neither is not this device's step, and a password change is pending.
    struct Intent: Equatable, Sendable {
        var credential: ObjectDigest
        var header: ObjectDigest
    }

    var genesis: ObjectDigest
    var credential: ObjectDigest
    /// The generation of `credential`. The account header in the local file must not be older than this: that is
    /// checked at unlock without needing a single registry entry, so deleting them from the file hides nothing.
    var generation: UInt64
    /// The newest entries applied. The local store must still hold them, and so everything they descend from.
    var heads: [ObjectDigest]
    /// Password changes that follow `credential` and that this device has seen and not been given (the credential
    /// entries' IDs, at most `maximumPending` of them). While there is one, the password this device follows and
    /// quick unlock are refused, whatever the local file holds by then: a pending change is no entry on the followed
    /// chain, so `heads` does not notice its rows being deleted (review finding Z3). It is emptied only by this
    /// device coming to follow another credential entry.
    var pending: [ObjectDigest]
    /// This device's own step under way, if any (`Intent`).
    var intent: Intent?

    func encoded() -> [UInt8] {
        let kept = heads.sorted().prefix(Self.maximumHeads)
        var out = Self.magic + genesis.bytes + credential.bytes
        out += (0..<8).map { UInt8(truncatingIfNeeded: generation >> (8 * $0)) }
        out += [UInt8(truncatingIfNeeded: kept.count), UInt8(truncatingIfNeeded: kept.count >> 8)]
        for head in kept { out += head.bytes }
        out.append(UInt8(truncatingIfNeeded: pending.count))
        for change in pending { out += change.bytes }
        if let intent {
            out += [1] + intent.credential.bytes + intent.header.bytes
        } else {
            out.append(0)
        }
        return out
    }

    init(
        genesis: ObjectDigest, credential: ObjectDigest, generation: UInt64, heads: [ObjectDigest],
        pending: [ObjectDigest] = [], intent: Intent? = nil
    ) {
        self.genesis = genesis
        self.credential = credential
        self.generation = generation
        self.heads = heads.sorted()
        self.pending = Array(Set(pending).sorted().prefix(Self.maximumPending))
        self.intent = intent
    }

    init?(bytes: [UInt8]) {
        let fixed = Self.magic.count + 2 * ObjectDigest.byteCount + 8 + 2
        guard bytes.count >= fixed else { return nil }
        let magic = Array(bytes[..<Self.magic.count])
        guard magic == Self.magic || magic == Self.secondMagic || magic == Self.firstMagic else { return nil }
        var offset = Self.magic.count
        func digest(_ offset: inout Int) -> ObjectDigest? {
            guard bytes.count >= offset + ObjectDigest.byteCount else { return nil }
            defer { offset += ObjectDigest.byteCount }
            return ObjectDigest(bytes: Array(bytes[offset..<(offset + ObjectDigest.byteCount)]))
        }
        guard let genesis = digest(&offset), let credential = digest(&offset) else { return nil }
        let generation = (0..<8).reduce(UInt64(0)) { $0 | UInt64(bytes[offset + $1]) << (8 * UInt64($1)) }
        offset += 8
        let count = Int(bytes[offset]) | Int(bytes[offset + 1]) << 8
        offset += 2
        guard count <= Self.maximumHeads, bytes.count >= offset + count * ObjectDigest.byteCount else { return nil }
        var heads: [ObjectDigest] = []
        for _ in 0..<count {
            guard let head = digest(&offset) else { return nil }
            heads.append(head)
        }
        var pending: [ObjectDigest] = []
        if magic != Self.firstMagic {
            guard offset < bytes.count else { return nil }
            let pendingCount = Int(bytes[offset])
            offset += 1
            guard pendingCount <= Self.maximumPending,
                bytes.count >= offset + pendingCount * ObjectDigest.byteCount
            else { return nil }
            for _ in 0..<pendingCount {
                guard let change = digest(&offset) else { return nil }
                pending.append(change)
            }
        }
        var intent: Intent?
        if magic == Self.magic {
            guard offset < bytes.count else { return nil }
            let flag = bytes[offset]
            offset += 1
            switch flag {
            case 0:
                break
            case 1:
                guard let credential = digest(&offset), let header = digest(&offset) else { return nil }
                intent = Intent(credential: credential, header: header)
            default:
                return nil
            }
        }
        guard offset == bytes.count else { return nil }
        self.init(
            genesis: genesis, credential: credential, generation: generation, heads: heads, pending: pending,
            intent: intent)
    }
}

/// The registry as evaluated on this device, with the entries it was evaluated from.
struct RegistryView: Sendable {
    var state: DeviceRegistryState
    var entries: [ObjectDigest: RegistryEntry]
}

/// Two signatures over one message: the account's Ed25519 key and the writing device's own key
/// (docs/02-architecture.md §7.8). `0x02 ‖ account signature (64) ‖ device signature`.
enum DualSignature {
    static let version: UInt8 = 2

    static func encode(account: [UInt8], device: [UInt8]) -> [UInt8] {
        [version] + account + device
    }

    static func decode(_ bytes: [UInt8]) -> (account: [UInt8], device: [UInt8])? {
        guard bytes.count > 65, bytes.count <= 1 + 64 + 128, bytes[0] == version else { return nil }
        return (Array(bytes[1..<65]), Array(bytes[65...]))
    }
}

/// What the account-level half of a sync did (docs/02-architecture.md §7.7).
public struct AccountObjectsReport: Sendable, Equatable {
    public var registryEntriesFetched = 0
    public var registryEntriesPublished = 0
    public var headerPublished = false
    /// Account headers for a password changed elsewhere, kept until the person enters that password here.
    public var candidateHeadersFetched = 0
    public var vaultKeysFetched = 0
    public var vaultKeysPublished = 0
    public var vaultDeletionsFetched = 0
    public var vaultDeletionsPublished = 0
    /// Objects under the account's prefix that were refused: not what their name says, or not signed by the account
    /// key and a registered device.
    public var rejected: [String] = []
    /// Names under the account's prefix that are not account objects.
    public var ignoredNames = 0

    public init() {}
}

// The account's own objects (docs/02-architecture.md §7.7, §7.8): the device registry, the published account
// header, and enrolment of a new device from the transport.
extension VaultSession {
    static let zeroUUID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    static let directoryObjectMaximumLength = 4096
    static let deletionMarker = Array("WWVD1-deleted".utf8)
    /// Key derivations spent on candidate account headers in one unlock or enrolment: each costs as much as the
    /// header's KDF parameters ask, up to the ceiling (SEC9). One per authoring device, on its newest header, so a
    /// device that publishes a chain of changes spends one of them and no more (review finding Z1).
    static let maximumHeaderAttempts = 3
    /// Authoring devices whose candidate header a sync fetches and keeps (one each, its newest). A change by a
    /// device beyond that is still listed and can still be followed by naming the device, which fetches its header
    /// then (`followPasswordChange`).
    static let maximumCandidateAuthors = 64
    /// The password changes `pendingPasswordChanges` describes in full: each costs a replay of the registry. Every
    /// change is listed whatever this is (Z13); the rest are described one at a time (`describePasswordChange`).
    static let maximumChangesDescribed = 16
    /// Header names looked at during enrolment before giving up; the store may hold any number of planted ones.
    static let maximumHeadersConsidered = 64

    // MARK: - Registry: loading and pinning

    /// The account's public signing key from a source the local file cannot alter: the keyset while unlocked, the
    /// Keychain copy while locked.
    func trustedAccountSigningKey(_ account: AccountRecord) async -> [UInt8]? {
        if let keys { return try? keys.keyset.publicKeyBundle().signingKey }
        guard let stored = try? await keychain.read(.accountSigningKey(accountID: account.accountID), prompt: "")
        else { return nil }
        defer { stored.zeroise() }
        return stored.unprotectedCopy()
    }

    func readAnchor(_ accountID: UUID) async -> RegistryAnchor? {
        guard let stored = try? await keychain.read(.deviceRegistryAnchor(accountID: accountID), prompt: "") else {
            return nil
        }
        defer { stored.zeroise() }
        return RegistryAnchor(bytes: stored.unprotectedCopy())
    }

    func writeAnchor(_ anchor: RegistryAnchor, accountID: UUID) async throws {
        var bytes = anchor.encoded()
        try await keychain.store(SecureBytes(wiping: &bytes), for: .deviceRegistryAnchor(accountID: accountID))
    }

    /// The anchor as this device follows it, with any step of its own that was under way settled first (review
    /// finding Z9, `RegistryAnchor.Intent`). Every decision about what the device trusts reads this, never the raw
    /// Keychain value, so a row ahead of the anchor counts as this device's own only where the Keychain named it.
    ///
    /// - The local header row is the one the intent named, byte for byte, and the account row matches it: the step
    ///   was committed. The anchor moves to it (pinned along its credential entry, the intent cleared), and is
    ///   returned so even if the Keychain cannot be written now. If the registry cannot be evaluated along it, the
    ///   intent stays and the device is in the middle of a step: a change is pending and no candidate is tried.
    /// - The account row is still at the anchor's generation: the step was never committed, and the intent is
    ///   dropped.
    /// - Anything else is left as it is, intent and all, and judged as a password change pending.
    func trustedAnchor(_ account: AccountRecord) async -> RegistryAnchor? {
        guard var anchor = await readAnchor(account.accountID) else { return nil }
        guard let intent = anchor.intent else { return anchor }
        let stored = try? await storedHeader(account)
        if let stored, ObjectDigest(hashing: stored.row.envelope) == intent.header,
            stored.header.credentialID == intent.credential, stored.header.genesisID == anchor.genesis,
            stored.header.unlockKeyID == account.unlockKeyID, stored.header.generation == account.credentialGeneration,
            stored.header.keysetVersion == account.keysetVersion
        {
            guard let accountKey = await trustedAccountSigningKey(account),
                let rows = try? await store.records(in: account.accountID, kind: .deviceRegistry),
                let view = try? Self.evaluateRegistry(
                    rows.map(\.envelope), accountID: account.accountID, accountKey: accountKey,
                    genesis: anchor.genesis, credential: intent.credential)
            else { return anchor }
            let completed = RegistryAnchor(
                genesis: view.state.genesis, credential: view.state.credential.id,
                generation: view.state.credential.generation, heads: view.state.heads,
                pending: view.state.pendingCredentials.map(\.id))
            try? await writeAnchor(completed, accountID: account.accountID)
            registryView = nil
            return completed
        }
        if account.keysetVersion == anchor.generation, account.credentialGeneration == anchor.generation,
            stored?.header.credentialID == anchor.credential
        {
            anchor.intent = nil
            try? await writeAnchor(anchor, accountID: account.accountID)
        }
        return anchor
    }

    /// The registry as this device sees it: the entries in the local store, replayed from the genesis entry and
    /// along the credentials the Keychain anchor names. Needs public keys only, so it works while locked. Throws
    /// `deviceRegistryUnavailable` when there is no anchor or account key to trust, or when the store no longer
    /// holds the entries the anchor names — a file rolled back to before a revocation (A8) is refused, not believed.
    func registry(_ account: AccountRecord) async throws -> RegistryView {
        if let registryView { return registryView }
        guard let accountKey = await trustedAccountSigningKey(account),
            let anchor = await trustedAnchor(account)
        else { throw VaultError.deviceRegistryUnavailable }
        let rows = try await store.records(in: account.accountID, kind: .deviceRegistry)
        let view = try Self.evaluateRegistry(
            rows.map(\.envelope), accountID: account.accountID, accountKey: accountKey, genesis: anchor.genesis,
            credential: anchor.credential, requiredHeads: anchor.heads)
        registryView = view
        return view
    }

    /// Forgets the evaluated registry, so the next use reads the local store again.
    func invalidateRegistry() {
        registryView = nil
    }

    static func evaluateRegistry(
        _ raw: [[UInt8]], accountID: UUID, accountKey: [UInt8], genesis: ObjectDigest, credential: ObjectDigest,
        requiredHeads: [ObjectDigest] = []
    ) throws -> RegistryView {
        let entries = DeviceRegistry.admit(raw, accountID: accountID, accountSigningKey: accountKey)
        guard
            let state = try? DeviceRegistry.evaluate(
                entries, accountID: accountID, accountSigningKey: accountKey, genesis: genesis,
                credential: credential),
            requiredHeads.allSatisfy(state.connectedEntries.contains)
        else { throw VaultError.deviceRegistryUnavailable }
        return RegistryView(state: state, entries: entries)
    }

    /// Records what was just evaluated as what this device has seen, so the local store cannot be rolled back
    /// behind it: the newest entries applied, and the password changes it has not been given. Those are remembered
    /// for as long as this device follows the same credential entry, whatever the store shows later; a view along
    /// another credential entry starts the list again (the device adopted a change, or made one).
    ///
    /// A step of this device's own still under way (`RegistryAnchor.Intent`) is kept unless `view` is along the
    /// credential entry it names, which is what completes it.
    func pinRegistry(_ view: RegistryView, accountID: UUID) async throws {
        let previous = await readAnchor(accountID)
        var pending = view.state.pendingCredentials.map(\.id)
        if let previous, previous.credential == view.state.credential.id { pending += previous.pending }
        let intent = previous?.intent.flatMap { $0.credential == view.state.credential.id ? nil : $0 }
        let anchor = RegistryAnchor(
            genesis: view.state.genesis, credential: view.state.credential.id,
            generation: view.state.credential.generation, heads: view.state.heads, pending: pending, intent: intent)
        if previous != anchor {
            try await writeAnchor(anchor, accountID: accountID)
        }
    }

    /// Whether the account password was changed on another device and this one has not been given it (§7.8). Asked
    /// before the password this device follows is accepted, before quick unlock, and by sync before it merges or
    /// publishes.
    ///
    /// Answered from the Keychain's anchor first, and only then from the registry in the local file (review finding
    /// Z3): the file is A8's, and a pending change is the one part of the registry whose rows can be deleted without
    /// the anchor's heads noticing. A registry that cannot be evaluated hides nothing the anchor has recorded. It is
    /// keyed on the registry's credential entries, never on whether the change's *header* has arrived: the transport
    /// can withhold that (A1) while the entry is here.
    ///
    /// `account.keysetVersion` is the generation the local header belongs to (bound into the keyset's wrap, so an
    /// edited value opens nothing). A header ahead of the anchor is this device's own step only where the Keychain
    /// named it before the step was committed (`trustedAnchor`, which then moves the anchor to it); otherwise it is
    /// no step of this device's, whoever wrote it into the file and whatever its own branch says, and a change is
    /// pending (review finding Z9). So is one this device's own step left half done.
    func passwordChangePending(_ account: AccountRecord) async -> Bool {
        guard let anchor = await trustedAnchor(account) else { return false }
        if !anchor.pending.isEmpty || anchor.intent != nil || account.keysetVersion > anchor.generation {
            return true
        }
        guard let view = try? await registry(account) else { return false }
        return !view.state.pendingCredentials.isEmpty
    }

    static func registryRow(_ entry: RegistryEntry, account: AccountRecord) -> StoredRecord {
        registryRow(entry.serialized(), accountID: account.accountID, deviceID: account.deviceID)
    }

    /// A registry entry as a row of the local store, under the account's own ID where a vault's would be. The row is
    /// named by the first half of the entry's ID; the entry itself is re-hashed and re-verified whenever it is read.
    static func registryRow(_ bytes: [UInt8], accountID: UUID, deviceID: UUID) -> StoredRecord {
        let id = ObjectDigest(hashing: bytes)
        return StoredRecord(
            recordID: uuid(Array(id.bytes[..<16])), kind: .deviceRegistry, vaultID: accountID, keyID: zeroUUID,
            version: 1, deviceID: deviceID, envelope: bytes)
    }

    static func uuid(_ b: [UInt8]) -> UUID {
        UUID(
            uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
        )
    }

    static func bytes(_ id: UUID) -> [UInt8] {
        let u = id.uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }

    // MARK: - Signing

    /// This device's own signature over `message`.
    func deviceSignature(_ message: [UInt8], domain: SignatureDomain, account: AccountRecord) async throws -> [UInt8] {
        try await deviceKeys.sign(
            DeviceSignatures.signedBytes(domain: domain, deviceID: account.deviceID, message: message),
            accountID: account.accountID, deviceID: account.deviceID)
    }

    /// The account key's signature and this device's over `message`. The account key signs first, before the
    /// suspension, so a `lock()` that lands meanwhile cannot leave it reading a zeroised keyset.
    func dualSignature(_ message: [UInt8], domain: SignatureDomain, keys: UnlockedKeys, account: AccountRecord)
        async throws -> [UInt8]
    {
        // Callers check the lock epoch after their own suspensions; this is the backstop, because reading a zeroised
        // key traps.
        guard !keys.keyset.isZeroised else { throw SyncKeyringError.locked }
        let accountSignature = try keys.keyset.sign(message, domain: domain)
        let device = try await deviceSignature(message, domain: domain, account: account)
        return DualSignature.encode(account: accountSignature, device: device)
    }

    /// Checks a dual signature by `author`, who must be a registered device that has not been revoked.
    static func verifyDual(
        _ signature: [UInt8], over message: [UInt8], domain: SignatureDomain, author: UUID, view: RegistryView
    ) throws {
        guard let device = view.state.devices[author] else { throw SyncKeyringError.untrustedAuthor(author) }
        guard let parts = DualSignature.decode(signature),
            (try? Signatures.verify(
                parts.account, for: message, domain: domain, signingKey: view.state.accountSigningKey)) != nil,
            (try? DeviceSignatures.verify(
                parts.device, for: message, domain: domain, deviceID: author, key: device.key)) != nil
        else { throw SyncKeyringError.authenticationFailed }
    }

    /// A registry entry written by this device (`author` a device) or by the enrolment key, signed and ready to
    /// store.
    func signedRegistryEntry(
        parents: [ObjectDigest], author: RegistryEntry.Author, body: RegistryEntry.Body, account: AccountRecord,
        keyset: Keyset, enrolment: EnrolmentKey? = nil, previousCredential: EnrolmentKey? = nil
    ) async throws -> RegistryEntry {
        guard !keyset.isZeroised else { throw VaultError.locked }
        var entry = RegistryEntry(
            accountID: account.accountID, parents: Array(parents.sorted().prefix(RegistryEntry.maximumParents)),
            author: author, body: body)
        entry.accountSignature = try keyset.sign(entry.accountMessage, domain: .deviceRegistry)
        if let previousCredential {
            entry.previousCredentialSignature = try previousCredential.sign(
                entry.previousCredentialMessage, domain: .deviceRegistry)
        }
        switch author {
        case .device(let id):
            entry.authorSignature = try await deviceKeys.sign(
                DeviceSignatures.signedBytes(domain: .deviceRegistry, deviceID: id, message: entry.deviceMessage),
                accountID: account.accountID, deviceID: id)
        case .enrolment:
            guard let enrolment else { throw VaultError.deviceRegistryUnavailable }
            entry.authorSignature = try enrolment.sign(entry.enrolmentMessage, domain: .deviceRegistry)
        }
        return entry
    }

    // MARK: - Device names

    struct DeviceLabel: Codable {
        var name: String
        var addedAt: Date
    }

    static func labelContext(deviceID: UUID, keyset: Keyset) -> EnvelopeContext {
        EnvelopeContext(
            recordID: deviceID, vaultID: keyset.accountID, schemaVersion: 1, kind: .deviceRegistry,
            keyID: keyset.symmetricKey.keyID)
    }

    /// The device's name sealed under the keyset's symmetric key: private to the account's devices.
    func sealedLabel(name: String, at date: Date, deviceID: UUID, keyset: Keyset) throws -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .secondsSince1970
        let plaintext = try encoder.encode(DeviceLabel(name: String(name.prefix(64)), addedAt: date))
        return try RecordCipher.seal(
            plaintext, context: Self.labelContext(deviceID: deviceID, keyset: keyset), key: keyset.symmetricKey,
            using: &random)
    }

    static func openLabel(_ sealed: [UInt8], deviceID: UUID, keyset: Keyset) -> DeviceLabel? {
        guard
            let plaintext = try? RecordCipher.open(
                sealed, context: labelContext(deviceID: deviceID, keyset: keyset), key: keyset.symmetricKey,
                maximumLength: RegistryDevice.maximumLabelLength)
        else { return nil }
        defer { plaintext.zeroise() }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        // A device's name: the person's metadata, not key material.
        return try? decoder.decode(DeviceLabel.self, from: Data(plaintext.unprotectedCopy()))
    }

    // MARK: - The published account header

    static func headerKey(_ accountID: UUID) -> RecordKey {
        RecordKey(recordID: accountID, kind: .accountHeader)
    }

    /// The account header this device would publish for `account`, bound under `unlockKey` and signed.
    func makeHeader(
        account: AccountRecord, credentialID: ObjectDigest, genesisID: ObjectDigest, unlockKey: EncryptionKey,
        keyset: Keyset
    ) async throws -> AccountHeaderObject {
        guard !keyset.isZeroised, !unlockKey.isZeroised else { throw VaultError.locked }
        var header = AccountHeaderObject(
            accountID: account.accountID, generation: account.credentialGeneration, author: account.deviceID,
            kdf: account.kdf, salt: account.salt, unlockKeyID: account.unlockKeyID,
            keysetVersion: account.keysetVersion, credentialID: credentialID, genesisID: genesisID,
            wrappedKeyset: account.wrappedKeyset)
        try header.bind(personalVaultID: account.personalVaultID, unlockKey: unlockKey, using: &random)
        header.accountSignature = try keyset.sign(header.signedPart, domain: .accountHeader)
        header.deviceSignature = try await deviceSignature(header.signedPart, domain: .accountHeader, account: account)
        return header
    }

    /// The header as the local row that mirrors the account record (`recordID` the account's own) or, under any
    /// other record ID, as a candidate waiting for the person's new password.
    /// The version a row that replaces `existing` is written at: one above it, or 1 where there is none. A row at the
    /// last version there is can only come from an edited file (A8), since nothing writes one: refused with a typed
    /// error, never trapped on (review finding Z23).
    static func version(replacing existing: StoredRecord?) throws -> UInt64 {
        guard let existing else { return 1 }
        guard existing.version < UInt64.max else { throw VaultError.versionOverflow }
        return existing.version + 1
    }

    static func headerRow(_ header: AccountHeaderObject, recordID: UUID, version: UInt64) -> StoredRecord {
        StoredRecord(
            recordID: recordID, kind: .accountHeader, vaultID: header.accountID, keyID: header.unlockKeyID,
            version: version, deviceID: header.author, envelope: header.serialized())
    }

    /// The published header in the local store, if it parses and is this account's.
    func storedHeader(_ account: AccountRecord) async throws -> (header: AccountHeaderObject, row: StoredRecord)? {
        guard let row = try await store.record(Self.headerKey(account.accountID)),
            let header = try? AccountHeaderObject.parse(row.envelope), header.accountID == account.accountID
        else { return nil }
        return (header, row)
    }

    /// Account headers for credentials this device does not follow yet, each checked against the registry: its
    /// credential entry must be one the registry lists as pending or forked, written by the same device, and the
    /// header must carry the account key's signature and that device's. `pending` are password changes made after
    /// the one this device follows; `forked` branch off earlier. **One per authoring device**, its newest, newest
    /// generation first: whoever publishes many changes under one device's name is tried once (Z1). Devices whose
    /// registration the checkpoint this device follows sealed come before the rest (Z13).
    ///
    /// Judged along the chain `passwordChangePending` reads (`trustedAnchor`), and none at all while a step of this
    /// device's own is under way: a change that was pending before it is a fork after it (review finding Z9).
    func candidateHeaders(_ account: AccountRecord) async -> (
        pending: [AccountHeaderObject], forked: [AccountHeaderObject]
    ) {
        guard let anchor = await trustedAnchor(account), anchor.intent == nil,
            let view = try? await registry(account),
            let rows = try? await store.records(in: account.accountID, kind: .accountHeader)
        else { return ([], []) }
        var pending: [UUID: AccountHeaderObject] = [:]
        var forked: [UUID: AccountHeaderObject] = [:]
        let newestFirst: (AccountHeaderObject, AccountHeaderObject) -> Bool = {
            ($0.generation, $0.credentialID) > ($1.generation, $1.credentialID)
        }
        // Authors the followed checkpoint sealed are tried first (Z13), then the rest, newest first.
        let sealed = Self.sealedAuthors(view)
        let order: (AccountHeaderObject, AccountHeaderObject) -> Bool = {
            let (first, second) = (sealed.contains($0.author), sealed.contains($1.author))
            return first != second ? first : newestFirst($0, $1)
        }
        for row in rows where row.recordID != account.accountID {
            guard let header = try? AccountHeaderObject.parse(row.envelope),
                Self.isCandidate(header, account: account, view: view)
            else { continue }
            if view.state.pendingCredentials.contains(where: { $0.id == header.credentialID }) {
                if pending[header.author].map({ newestFirst(header, $0) }) ?? true { pending[header.author] = header }
            } else {
                if forked[header.author].map({ newestFirst(header, $0) }) ?? true { forked[header.author] = header }
            }
        }
        return (pending.values.sorted(by: order), forked.values.sorted(by: order))
    }

    static func isCandidate(_ header: AccountHeaderObject, account: AccountRecord, view: RegistryView) -> Bool {
        guard header.accountID == account.accountID, header.genesisID == view.state.genesis,
            let credential = (view.state.pendingCredentials + view.state.forkedCredentials).first(where: {
                $0.id == header.credentialID
            }), credential.generation == header.generation, credential.author == header.author,
            let key = Self.registeredKey(of: header.author, in: view)
        else { return false }
        return (try? header.verifySignatures(accountSigningKey: view.state.accountSigningKey, deviceKey: key)) != nil
    }

    /// The key `device` is registered under as this device sees the registry, revoked or not.
    static func registeredKey(of device: UUID, in view: RegistryView) -> DevicePublicKey? {
        view.state.devices[device]?.key ?? view.state.revoked[device]?.key
    }

    /// The credential changes this device does not follow, by the device that made them, each device's newest
    /// first. The devices in `sealed` (`sealedAuthors`) come first, then the rest; within each, in the order their
    /// newest change sorts (generation, then entry ID, descending). That last order is no defence, since whoever
    /// makes a change chooses its place in it; `sealed` is (review finding Z13): a device registered after the change
    /// this device follows may have been registered with the password that change retired, by anyone who knew it,
    /// and as many of them as they like, while one the checkpoint sealed was registered before. What bounds an author
    /// is that each gets one attempt, and what reaches a change this order starves is naming its device.
    static func changesByAuthor(_ changes: [DeviceRegistryState.Credential], sealed: Set<UUID> = []) -> [(
        author: UUID, changes: [DeviceRegistryState.Credential]
    )] {
        var grouped: [UUID: [DeviceRegistryState.Credential]] = [:]
        for change in changes { grouped[change.author, default: []].append(change) }
        return grouped.map { author, changes in
            (author, changes.sorted { ($0.generation, $0.id) > ($1.generation, $1.id) })
        }.sorted {
            let (first, second) = (sealed.contains($0.author), sealed.contains($1.author))
            if first != second { return first }
            return ($0.changes[0].generation, $0.changes[0].id) > ($1.changes[0].generation, $1.changes[0].id)
        }
    }

    /// The devices whose registration the credential entry this device follows sealed: it descends from the entry
    /// that registered them (review finding Z13). Bounded by the entries held.
    static func sealedAuthors(_ view: RegistryView) -> Set<UUID> {
        var sealed: Set<ObjectDigest> = []
        var stack = [view.state.credential.id]
        while let id = stack.popLast() {
            guard sealed.insert(id).inserted, let entry = view.entries[id] else { continue }
            stack += entry.parents
        }
        return Set(
            (Array(view.state.devices.values) + Array(view.state.revoked.values))
                .filter { sealed.contains($0.entry) }.map(\.id))
    }

    // MARK: - Account creation and upkeep

    /// The registry's first entry and the account header, for a new account or for one created before the registry
    /// existed: this device, the account's signing key and the first enrolment key.
    func registryGenesis(account: AccountRecord, unlockKey: EncryptionKey, keyset: Keyset, now: Date) async throws
        -> (rows: [StoredRecord], anchor: RegistryAnchor)
    {
        let deviceKey: DevicePublicKey
        if let existing = try await deviceKeys.publicKey(accountID: account.accountID, deviceID: account.deviceID) {
            deviceKey = existing
        } else {
            deviceKey = try await deviceKeys.create(accountID: account.accountID, deviceID: account.deviceID)
        }
        // The session may have locked while the key store was asked.
        guard !keyset.isZeroised, !unlockKey.isZeroised else { throw VaultError.locked }
        let enrolment = EnrolmentKey.derive(from: unlockKey, accountID: account.accountID)
        defer { enrolment.zeroise() }
        let device = RegistryDevice(
            id: account.deviceID, key: deviceKey,
            label: try sealedLabel(
                name: configuration.deviceName, at: now, deviceID: account.deviceID, keyset: keyset))
        let genesis = try await signedRegistryEntry(
            parents: [], author: .device(account.deviceID),
            body: .genesis(
                accountSigningKey: try keyset.publicKeyBundle().signingKey, device: device,
                enrolmentKey: try enrolment.publicKey()),
            account: account, keyset: keyset)
        let header = try await makeHeader(
            account: account, credentialID: genesis.id, genesisID: genesis.id, unlockKey: unlockKey, keyset: keyset)
        return (
            [
                Self.registryRow(genesis, account: account),
                Self.headerRow(header, recordID: account.accountID, version: 1),
            ], RegistryAnchor(genesis: genesis.id, credential: genesis.id, generation: 0, heads: [genesis.id])
        )
    }

    /// After an unlock: makes sure this device has what the registry needs of it, and refuses a header older than
    /// the credentials it already follows. Best effort except for that refusal — a registry that cannot be repaired
    /// here stops sync (`deviceRegistryUnavailable`), not the person's access to their vault.
    ///
    /// The session may lock at any suspension in here (auto-lock, the AutoFill extension finishing): `keys` is then
    /// zeroised, and reading it traps. So the lock epoch is re-checked after every suspension before `keys` is
    /// touched, and a lock ends the reconciliation quietly — it runs again at the next unlock.
    func reconcileAccountObjects(account: AccountRecord, keys: UnlockedKeys) async throws {
        let epoch = lockEpoch
        registryView = nil
        let accountID = account.accountID
        let stored = try await storedHeader(account)
        let anchor = await trustedAnchor(account)
        guard epoch == lockEpoch, !keys.accountUnlockKey.isZeroised else { return }

        // An account from before the registry existed has none of this. Its registry is started at a sync, and only
        // if the transport holds no header for the account (`startRegistryIfAccountPredatesIt`): a database
        // restored without its registry rows must not start a second registry for an account that already syncs.
        if stored == nil, anchor == nil { return }

        // The stored header is this account record's own only if it opens under the key just derived; then what it
        // names is authenticated by the password, and can restore a missing anchor (a Keychain that lost it, a
        // store restored onto other hardware). It never moves an anchor that exists (review finding Z9): this
        // device's own steps move it through the intent they write first (`trustedAnchor`), and a header ahead of
        // the anchor that no intent named is not this device's step, whoever opened it with which password.
        // A device that has an anchor never takes another genesis entry: one registry per account, for good.
        //
        // A stored header that is not this record's own, or whose binding names another Personal vault than the row
        // does, is not a reason to skip this quietly: the row was edited (review finding Z5). The unlock checked the
        // same before installing a key (`requirePersonalVaultBinding`); here it is a hard failure too.
        if let stored {
            guard stored.header.unlockKeyID == account.unlockKeyID,
                (try? stored.header.openBinding(with: keys.accountUnlockKey)) == account.personalVaultID
            else { throw VaultError.personalVaultMismatch }
        }
        if let stored,
            anchor == nil || anchor?.genesis == stored.header.genesisID,
            anchor?.credential != stored.header.credentialID,
            let accountKey = await trustedAccountSigningKey(account)
        {
            let rows = try await store.records(in: accountID, kind: .deviceRegistry)
            if let pinned = anchor,
                let view = try? Self.evaluateRegistry(
                    rows.map(\.envelope), accountID: accountID, accountKey: accountKey, genesis: pinned.genesis,
                    credential: pinned.credential),
                !Self.descends(stored.header.credentialID, from: pinned.credential, in: view)
            {
                // Older than, or beside, what this device follows: the file was rolled back (A8).
                throw VaultError.accountHeaderRolledBack
            }
            if anchor == nil,
                let view = try? Self.evaluateRegistry(
                    rows.map(\.envelope), accountID: accountID, accountKey: accountKey,
                    genesis: stored.header.genesisID, credential: stored.header.credentialID)
            {
                try await pinRegistry(view, accountID: accountID)
                registryView = view
            }
        }

        guard let view = try? await registry(account), epoch == lockEpoch else { return }
        // A store restored onto other hardware arrives without the device key (Keychain items never leave a
        // device): this installation is a new device, and says so. One whose registration no longer counts (it was
        // made with a password since changed) registers again under the same ID.
        guard view.state.pendingCredentials.isEmpty, !(await passwordChangePending(account)), epoch == lockEpoch
        else { return }
        // A move of an earlier ID's sync state that did not finish is made first, so that a registration below starts
        // from a whole state; one that fails again throws, and runs again at the next unlock (Z181).
        try await completeDeviceMigration(account: account)
        let account = (try await loadAccount()) ?? account
        guard epoch == lockEpoch else { return }
        let ownKey = try await deviceKeys.publicKey(accountID: accountID, deviceID: account.deviceID)
        if ownKey == nil {
            try await registerThisDevice(account: account, keys: keys, asNewDevice: true)
        } else if view.state.standing(of: account.deviceID) == .unknown {
            try await registerThisDevice(account: account, keys: keys, asNewDevice: false)
        }
        // Deletions fetched while locked become this device's own now that it can sign.
        try? await adoptVerifiedDeletions(account: (try? await loadAccount()) ?? account)
    }

    /// For an account created before the device registry existed — no registry entries, no published header, no
    /// anchor — and only if the transport holds no account header either: this device starts the registry. If the
    /// transport does hold one, the account already has a registry that this device is not part of, and it must
    /// enrol again rather than start a second one (review finding W6).
    func startRegistryIfAccountPredatesIt(account: AccountRecord, transport: any SyncTransport) async throws {
        let epoch = lockEpoch
        guard keys != nil, try await storedHeader(account) == nil, await readAnchor(account.accountID) == nil,
            try await store.records(in: account.accountID, kind: .deviceRegistry).isEmpty,
            try await transport.list(prefix: AccountObjectLocation.headerPrefix(account.accountID)).isEmpty
        else { return }
        let keys = try requireKeys(since: epoch)
        let genesis = try await registryGenesis(
            account: account, unlockKey: keys.accountUnlockKey, keyset: keys.keyset, now: await clock.now())
        _ = try requireKeys(since: epoch)
        try await store.commit(StoreChange(upserts: genesis.rows))
        try await writeAnchor(genesis.anchor, accountID: account.accountID)
        registryView = nil
    }

    /// Refuses an account header older than the credentials this device already follows: the local file was rolled
    /// back to before a password change (A8), and the password that just opened it is one the person retired. Call
    /// once the keyset has opened, which is what authenticates `keysetVersion` (it is bound into the wrap), and
    /// before any key is installed. Needs nothing from the file but the account record, so deleting registry
    /// entries hides nothing.
    func refuseRolledBackHeader(_ account: AccountRecord) async throws {
        guard let anchor = await trustedAnchor(account) else { return }
        // The two move together with every credential change; apart, one of them was edited.
        guard account.keysetVersion == account.credentialGeneration, account.keysetVersion >= anchor.generation
        else { throw VaultError.accountHeaderRolledBack }
    }

    /// Whether credential entry `candidate` is `ancestor` or follows from it link by link.
    static func descends(_ candidate: ObjectDigest, from ancestor: ObjectDigest, in view: RegistryView) -> Bool {
        var cursor = candidate
        for _ in 0...view.entries.count {
            if cursor == ancestor { return true }
            guard case .credential(_, _, let previous)? = view.entries[cursor]?.body else { return false }
            cursor = previous
        }
        return false
    }

    /// Registers this installation with the enrolment key, which the session can derive because it holds the
    /// Account Unlock Key: the same proof a new device gives (PRD F5.2).
    ///
    /// As a new device (a store restored onto other hardware), what the old device ID wrote and never published is
    /// carried over, or nobody would ever publish it (`SyncEngine` publishes only rows of its own device): each such
    /// row is written again by the new ID, unchanged (`ItemMerge.written`), in the commit that registers it, and that
    /// commit records the move of the old ID's sync state (`AccountRecord.migration`, signed), which
    /// `completeDeviceMigration` then makes: the old ID's pending deletions recorded again as the new ID's (PRD F7.7),
    /// or parked for it (Z167, Z170). A move that fails part way is made again at each unlock, and at each sync, until
    /// it is complete, and until then this device publishes nothing (review of round 10, Z181).
    func registerThisDevice(account: AccountRecord, keys: UnlockedKeys, asNewDevice: Bool) async throws {
        // A new ID over a move that is not complete would replace its record, and the earlier ID's deletions would
        // stay stamped by an ID this installation never publishes again: the move comes first
        // (`reconcileAccountObjects` makes it, and throws if it fails), and registration waits for it (Z181).
        guard !asNewDevice || account.migration == nil else { return }
        let epoch = lockEpoch
        // Before a current key is picked for any row carried over.
        await loadSharedMarkersIfNeeded()
        let view = try await registry(account)
        var updated = account
        // What the old ID left, read before anything is made or committed: one read that fails ends the registration
        // with nothing written and no device key made (review of round 10, I1; Z182), and it runs again at the next
        // unlock (Z177). The move reads the deletions again (`completeDeviceMigration`), and decides what it parks.
        let unpublished = asNewDevice ? try await unpublishedRows(of: account) : (rows: [], deletions: [:])
        if asNewDevice { _ = try await parkedDeletions(of: account) }
        // Then a new device's key, so that its ID can commit to the account under it (review finding Z157).
        let created = asNewDevice ? try await deviceKeys.createDevice(accountID: account.accountID) : nil
        if let created { updated.deviceID = created.id }
        let now = await clock.now()
        let keys = try requireKeys(since: epoch)
        let enrolment = EnrolmentKey.derive(from: keys.accountUnlockKey, accountID: account.accountID)
        defer { enrolment.zeroise() }
        let label = try sealedLabel(
            name: configuration.deviceName, at: now, deviceID: updated.deviceID, keyset: keys.keyset)
        let keyset = keys.keyset
        let deviceKey: DevicePublicKey
        if let created {
            deviceKey = created.key
        } else {
            guard
                let existing = try await deviceKeys.publicKey(
                    accountID: account.accountID, deviceID: updated.deviceID)
            else { throw DeviceKeyError.keyMissing }
            deviceKey = existing
        }
        _ = try requireKeys(since: epoch)
        let entry = try await signedRegistryEntry(
            parents: view.state.heads, author: .enrolment(credential: view.state.credential.id),
            body: .add(RegistryDevice(id: updated.deviceID, key: deviceKey, label: label)), account: updated,
            keyset: keyset, enrolment: enrolment)
        var change = StoreChange(upserts: [Self.registryRow(entry, account: updated)])
        if asNewDevice {
            if syncSettings != nil {
                updated.migration = try signedMigration(from: account.deviceID, to: updated, keyset: keyset)
            }
            change.account = .update(updated, expectedKeysetVersion: account.keysetVersion)
            for row in try carriedOver(unpublished.rows, keys: try requireKeys(since: epoch), as: updated) {
                change.upserts.append(row.row)
                change.expectations[row.row.key] = .version(row.replacing)
            }
        }
        try await store.commit(change)
        if asNewDevice {
            self.account = updated
            for row in change.upserts where row.kind == .item || row.kind == .vaultMetadata {
                highestVersionSeen[row.vaultID] = max(highestVersionSeen[row.vaultID] ?? 0, row.version)
            }
        }
        registryView = nil
        if let refreshed = try? await registry(updated) {
            try? await pinRegistry(refreshed, accountID: account.accountID)
        }
        // After the registry is pinned again, so that the move reads the registry that lists the new ID. A move that
        // fails throws, and is made again at the next unlock or sync (Z181).
        if asNewDevice { try await completeDeviceMigration(account: updated) }
    }

    /// The rows this device wrote that its sync state does not record as published, and its pending deletions
    /// (those that verify), per vault: what a store restored onto other hardware holds that no other device has.
    func unpublishedRows(of account: AccountRecord) async throws -> (
        rows: [StoredRecord], deletions: [UUID: [RecordKey: PendingDeletion]]
    ) {
        guard let syncState else { return ([], [:]) }
        var rows: [StoredRecord] = []
        var deletions: [UUID: [RecordKey: PendingDeletion]] = [:]
        for vaultID in try await vaultDirectory(account).keys {
            // The state this session signed, or none (Z20): a planted `published` must not keep a row from being
            // carried over.
            let state = try await syncState.loadState(vaultID: vaultID)
            let published = state?.published ?? [:]
            // Items merge by what each value's writer had seen, so carrying one over that was published after all
            // changes nothing. A vault's name is last-writer-wins: carried over without knowing it was unpublished,
            // an old name would win over a newer rename, so it is carried only when the state says so.
            let kinds: [EnvelopeKind] = state == nil ? [.item] : [.item, .vaultMetadata]
            for kind in kinds {
                for row in try await store.records(in: vaultID, kind: kind) where row.deviceID == account.deviceID {
                    if let stamp = published[row.key], stamp >= RecordStamp(row) { continue }
                    rows.append(row)
                }
            }
            let pending = try await syncState.pendingDeletions(vaultID: vaultID)
            if !pending.isEmpty { deletions[vaultID] = pending }
        }
        return (rows, deletions)
    }

    /// Each row as the version `updated`'s device writes next: the same content, one version up, sealed under the
    /// vault's current key. A row that does not open is left as it is; it carries nothing this device can read.
    func carriedOver(_ rows: [StoredRecord], keys: UnlockedKeys, as updated: AccountRecord) throws -> [(
        row: StoredRecord, replacing: UInt64
    )] {
        var result: [(row: StoredRecord, replacing: UInt64)] = []
        for row in rows {
            guard let vaultKey = currentVaultKey(row.vaultID, keys: keys, account: updated) else { continue }
            let revision = try nextRevision(in: row.vaultID, above: row, account: updated)
            highestVersionSeen[row.vaultID] = max(highestVersionSeen[row.vaultID] ?? 0, revision.version)
            switch row.kind {
            case .item:
                guard let item = try? openItem(row, keys: keys) else { continue }
                let written = ItemMerge.written(item, as: revision)
                result.append((try sealItem(written, vaultKey: vaultKey, account: updated), row.version))
            case .vaultMetadata:
                guard var metadata = try? openMetadata(row, keys: keys) else { continue }
                metadata.writtenBy = metadata.writtenBy ?? Self.origin(row)
                metadata.version = revision.version
                result.append((try sealMetadata(metadata, vaultKey: vaultKey, account: updated), row.version))
            default:
                continue
            }
        }
        return result
    }

    /// The move of an earlier device ID's sync state to `account`'s (review of round 10, Z181), recorded by
    /// registration with the account record that names the new ID (`AccountRecord.migration`) and made here, again
    /// at each unlock and each sync until it is complete; a failure throws, and the record stays. What the old ID
    /// published and acknowledged is not this device's to continue (its stream, its sequence numbers), so each vault's
    /// state is first saved empty, signed by this session for the new ID through `syncState`: one the session did not
    /// sign is no state (Z20), which reads back as none, so that a second restore before the next sync would carry no
    /// vault's description over (`unpublishedRows`, Z184). Then the old ID's pending deletions are recorded again as this
    /// device's, each stamped above the old one so that it replaces it in one write, so a move made twice finds only
    /// what the first did not do; or, while a shared vault holds an edit nobody received of the old ID or of any
    /// device ID of the registry that does not commit (`vaultsHoldingEditsNobodyReceived`, Z167, Z170), parked for the
    /// new ID (`parkedDeletionDevice`), which the engine neither publishes nor applies. Those the old ID had parked
    /// itself are always parked again (Z170): only `releaseParkedDeletions` lets one go. Last, the record is cleared.
    /// Until then the sync publishes nothing (`AccountSyncReport.deviceMigrationIncomplete`), so a state started over
    /// again by a second attempt loses nothing this device published.
    ///
    /// A record the session did not sign (`DeviceMigration.authenticator` over the account, the new ID and the old,
    /// under `SignatureDomain.deviceMigration`) moves nothing: planted in the database (A8), it would make this
    /// device take another device's genuine pending deletions, copied into its state file, for its own. It is cleared.
    /// Without sync configured there is nothing to move, and the record waits for a session that has it.
    func completeDeviceMigration(account: AccountRecord) async throws {
        guard let migration = account.migration, let base = syncSettings?.state, let syncState else { return }
        let epoch = lockEpoch
        let previous = migration.previousDeviceID
        if try verifiedMigration(migration, to: account, keyset: try requireKeys(since: epoch).keyset) {
            let view = try await registry(account)
            for vaultID in try await vaultDirectory(account).keys {
                _ = try requireKeys(since: epoch)
                try await syncState.saveState(SyncState(vaultID: vaultID))
            }
            let deletions = try await signedPendingDeletions(stampedBy: previous, account: account)
            let parked = try await signedPendingDeletions(
                stampedBy: Self.parkedDeletionDevice(of: previous), account: account)
            // The old ID's deletions wait while a shared vault holds an edit that nobody received, of it or of any
            // device ID of the registry that does not commit: the release's own predicate, so that an ID which commits
            // (a second restore) does not let go of what an earlier one left.
            var parking = false
            if !deletions.isEmpty {
                let nobodyReceived = Self.idsNobodyReceives(account: account, view: view, including: previous)
                parking = !(await vaultsHoldingEditsNobodyReceived(of: nobodyReceived, account: account)).isEmpty
            }
            let carried = deletions.map { (deletion: $0, parks: parking) } + parked.map { ($0, true) }
            for (deletion, parks) in carried where deletion.stamp.version < .max - 1 {
                _ = try requireKeys(since: epoch)
                if parks {
                    try await base.addPendingDeletion(
                        try signedPendingDeletion(
                            Self.restamped(deletion, device: Self.parkedDeletionDevice(of: account.deviceID))))
                } else {
                    try await syncState.addPendingDeletion(Self.restamped(deletion, device: account.deviceID))
                }
            }
        }
        _ = try requireKeys(since: epoch)
        guard let current = try await store.loadAccount(), current.deviceID == account.deviceID,
            current.migration == migration
        else { return }
        var done = current
        done.migration = nil
        try await store.commit(StoreChange(account: .update(done, expectedKeysetVersion: current.keysetVersion)))
        self.account = done
    }

    /// The move from `previous` to `updated`'s device ID, signed by the account key (Z181).
    func signedMigration(from previous: UUID, to updated: AccountRecord, keyset: Keyset) throws -> DeviceMigration {
        DeviceMigration(
            previousDeviceID: previous,
            authenticator: try keyset.sign(
                Self.migrationMessage(from: previous, to: updated), domain: .deviceMigration))
    }

    /// Whether this session signed `migration` for `account`'s current device ID.
    func verifiedMigration(_ migration: DeviceMigration, to account: AccountRecord, keyset: Keyset) throws -> Bool {
        let message = Self.migrationMessage(from: migration.previousDeviceID, to: account)
        let signingKey = try keyset.publicKeyBundle().signingKey
        return
            (try? Signatures.verify(
                migration.authenticator, for: message, domain: .deviceMigration, signingKey: signingKey)) != nil
    }

    static func migrationMessage(from previous: UUID, to account: AccountRecord) -> [UInt8] {
        Array("WW-device-migration-v1".utf8) + bytes(account.accountID) + bytes(account.deviceID) + bytes(previous)
    }

    /// `deletion` stamped by `device`, above the original so that it replaces it in one write.
    static func restamped(_ deletion: PendingDeletion, device: UUID) -> PendingDeletion {
        PendingDeletion(
            stamp: RecordStamp(version: deletion.stamp.version + 1, device: device, deleted: true),
            record: deletion.record)
    }

    /// The device ID a deletion parked for `deviceID` is stamped with (review finding Z167): derived from it, so that
    /// only the installation that is `deviceID` releases it, and naming no device, so that no engine publishes or
    /// applies it (`verifiedPendingDeletions` takes only the current ID's). Never another device's deletion: one that
    /// device's session genuinely signed, copied into this file (A8), is stamped with that device's own ID.
    static func parkedDeletionDevice(of deviceID: UUID) -> UUID {
        var id = Array(ObjectDigest(hashing: Array("WW-parked-deletion-v1".utf8) + bytes(deviceID)).bytes[..<16])
        id[6] = (id[6] & 0x0F) | 0x80
        id[8] = (id[8] & 0x3F) | 0x80
        return uuid(id)
    }

    /// `deletion` signed by the account key, as `authenticatePendingDeletion` signs this device's own.
    func signedPendingDeletion(_ deletion: PendingDeletion) throws -> PendingDeletion {
        let keys = try requireKeys()
        var signed = deletion
        signed.authenticator = try keys.keyset.sign(Self.pendingDeletionMessage(deletion), domain: .pendingDeletion)
        return signed
    }

    /// The deletions parked for `account`'s device (`parkedDeletionDevice`) that the account key signed. Throws what
    /// the state store threw, and `VaultError.locked` while locked: never an empty list for one it could not read.
    func parkedDeletions(of account: AccountRecord) async throws -> [PendingDeletion] {
        try await signedPendingDeletions(stampedBy: Self.parkedDeletionDevice(of: account.deviceID), account: account)
    }

    /// The pending deletions stamped by `device` that the account key signed, in every vault of `account`'s directory.
    /// Throws what the state store threw, and `VaultError.locked` while locked.
    func signedPendingDeletions(stampedBy device: UUID, account: AccountRecord) async throws -> [PendingDeletion] {
        guard let base = syncSettings?.state else { return [] }
        let keys = try requireKeys()
        let signingKey = try keys.keyset.publicKeyBundle().signingKey
        var parked: [PendingDeletion] = []
        for vaultID in try await vaultDirectory(account).keys {
            for (key, deletion) in try await base.pendingDeletions(vaultID: vaultID)
            where deletion.stamp.device == device
                && Self.isSigned(deletion, as: key, in: vaultID, signingKey: signingKey)
            {
                parked.append(deletion)
            }
        }
        return parked
    }

    /// The device IDs whose edits in a shared vault nobody else received (review findings Z157, Z162, Z170): every ID
    /// of `account`'s registry, current or revoked, that does not commit to the account under the key the registry
    /// lists for it, and `deviceID` (an ID this installation wrote under) unless the registry lists it with a key it
    /// commits under. Every member's device counts only devices whose IDs commit, so such an edit reached nobody
    /// whatever the sync state recorded as published, and it keeps its writer's ID in every value it stamped: carried
    /// over to a new ID, or merged into a row of another of this account's devices, it is still held aside everywhere
    /// else.
    static func idsNobodyReceives(account: AccountRecord, view: RegistryView, including deviceID: UUID? = nil)
        -> Set<UUID>
    {
        var ids: Set<UUID> = []
        for device in Array(view.state.devices.values) + Array(view.state.revoked.values)
        where !DeviceIdentifier.commits(device.id, to: account.accountID, key: device.key) {
            ids.insert(device.id)
        }
        if let deviceID {
            let listed = view.state.devices[deviceID] ?? view.state.revoked[deviceID]
            if listed.map({ !DeviceIdentifier.commits(deviceID, to: account.accountID, key: $0.key) }) ?? true {
                ids.insert(deviceID)
            }
        }
        return ids
    }

    /// The items of `vaultID`, if it is shared, whose rows hold an edit of one of `deviceIDs` (`idsNobodyReceives`),
    /// whichever device's row it is (Z170: one this installation carried over under an intermediate ID holds the first
    /// ID's values too); `nil` where the vault's rows cannot be read. An edit is a value that ID stamped
    /// (`holdsValue(ofAny:in:)`), never a clock's claim to have seen one, which another account can write (Z173).
    /// Fails closed: a row that does not open counts, and "shared" is `isMarkedShared`, so a vault counts until the
    /// markers say it is private.
    func itemsHoldingEdits(of deviceIDs: Set<UUID>, in vaultID: UUID, account: AccountRecord) async -> Set<UUID>? {
        guard !deviceIDs.isEmpty, isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) else {
            return []
        }
        guard let rows = try? await store.records(in: vaultID, kind: .item) else { return nil }
        var items: Set<UUID> = []
        for row in rows where holdsValue(ofAny: deviceIDs, in: row) { items.insert(row.recordID) }
        return items
    }

    /// The shared vaults whose rows hold an edit of one of `deviceIDs` (`itemsHoldingEdits`); the Personal vault where
    /// the directory could not be read. The predicate both registration and `releaseParkedDeletions` decide by, and the
    /// one the deletion gate applies (`holdsUnpublishedWork`).
    func vaultsHoldingEditsNobodyReceived(of deviceIDs: Set<UUID>, account: AccountRecord) async -> Set<UUID> {
        guard !deviceIDs.isEmpty else { return [] }
        guard let vaults = try? await vaultDirectory(account).keys else { return [account.personalVaultID] }
        var held: Set<UUID> = []
        for vaultID in vaults {
            let items = await itemsHoldingEdits(of: deviceIDs, in: vaultID, account: account)
            if items?.isEmpty != true { held.insert(vaultID) }
        }
        return held
    }

    /// The pending deletions made under an earlier ID of this installation that registering as a new device parked
    /// (review finding Z167), stamped for this device (`parkedDeletionDevice`), so the engine neither publishes nor
    /// applies them. While a shared vault holds an edit nobody received of a device ID of this account's registry that
    /// does not commit (the earlier ID among them; `vaultsHoldingEditsNobodyReceived`), they stay parked, and this
    /// returns the vaults holding one (the sync reports them in `deletionsHeldBack`, and the deletion gate holds every
    /// other deletion back too, Z170); once none remains (the person moved the copy out, or deleted it),
    /// each is recorded again as this device's, as a device move does (`completeDeviceMigration`), and goes out like
    /// any other. Fails closed: with no registry, or parked deletions that cannot be read, nothing is released.
    func releaseParkedDeletions(account: AccountRecord, view: RegistryView?) async -> Set<UUID> {
        guard let syncState, let parked = try? await parkedDeletions(of: account), !parked.isEmpty else { return [] }
        guard let view else { return [account.personalVaultID] }
        let held = await vaultsHoldingEditsNobodyReceived(
            of: Self.idsNobodyReceives(account: account, view: view), account: account)
        guard held.isEmpty else { return held }
        for deletion in parked {
            try? await syncState.addPendingDeletion(Self.restamped(deletion, device: account.deviceID))
        }
        return []
    }

    // MARK: - Devices (PRD F10.2; review findings D9, Y5, Y6)

    /// This device's standing in the registry. Needs no keys.
    public func deviceStanding() async throws -> DeviceStanding {
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        return try await registry(account).state.standing(of: account.deviceID)
    }

    /// Whether the account password was changed on another device and has not been entered here yet. While it is,
    /// the old password is refused and sync neither merges nor publishes.
    public func isAwaitingNewPassword() async throws -> Bool {
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        // What the Keychain remembers of a change first: a registry that cannot be evaluated hides none of it.
        if await passwordChangePending(account) { return true }
        return !(try await registry(account)).state.pendingCredentials.isEmpty
    }

    /// The password changes other devices have made that this one does not follow, one per device that made any
    /// (its newest), for the person to choose between when the lock screen cannot (`tooManyPasswordChangesPending`),
    /// and to see what following one would do before they type its password. Device names need the vault unlocked.
    ///
    /// To a device that has not been given a new password, two changes made at once are symmetric: both carry the
    /// account key's signature, a registered device's and the previous password's. Which is the person's own is
    /// theirs to say, by the device it was made on; `revokedDevices` is what each would take away.
    ///
    /// **Every** author is listed (review finding Z13): listing needs no replay. Those whose registration the
    /// followed checkpoint sealed come first, so that puppets registered with a retired password cannot push the
    /// genuine change off a screen. What following each would do is worked out for the first
    /// `maximumChangesDescribed`; `describePasswordChange(by:)` works it out for any other.
    public func pendingPasswordChanges() async throws -> [PendingPasswordChange] {
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let view = try await registry(account)
        let rows = try await store.records(in: account.accountID, kind: .deviceRegistry)
        let sealed = Self.sealedAuthors(view)
        let authors = Self.changesByAuthor(
            view.state.pendingCredentials + view.state.forkedCredentials, sealed: sealed)
        return authors.enumerated().map { index, author in
            describe(
                author.changes[0], view: view, rows: rows, account: account, sealed: sealed,
                replaying: index < Self.maximumChangesDescribed)
        }
    }

    /// One row of `pendingPasswordChanges`, worked out in full: the newest change `device` made that this device
    /// does not follow.
    public func describePasswordChange(by device: UUID) async throws -> PendingPasswordChange {
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let view = try await registry(account)
        let rows = try await store.records(in: account.accountID, kind: .deviceRegistry)
        guard
            let change = Self.changesByAuthor(view.state.pendingCredentials + view.state.forkedCredentials)
                .first(where: { $0.author == device })?.changes.first
        else { throw VaultError.noPasswordChangeToFollow(device) }
        return describe(
            change, view: view, rows: rows, account: account, sealed: Self.sealedAuthors(view), replaying: true)
    }

    private func describe(
        _ change: DeviceRegistryState.Credential, view: RegistryView, rows: [StoredRecord], account: AccountRecord,
        sealed: Set<UUID>, replaying: Bool
    ) -> PendingPasswordChange {
        let author = change.author
        // As it would be followed: the registry replayed with the change as its last checkpoint.
        let followed =
            replaying
            ? try? Self.evaluateRegistry(
                rows.map(\.envelope), accountID: account.accountID, accountKey: view.state.accountSigningKey,
                genesis: view.state.genesis, credential: change.id) : nil
        var name = ""
        if let keys, !keys.keyset.isZeroised,
            let label = view.state.devices[author]?.label ?? view.state.revoked[author]?.label
        {
            name = Self.openLabel(label, deviceID: author, keyset: keys.keyset)?.name ?? ""
        }
        let known = Set(view.state.devices.keys).union(view.state.revoked.keys)
        return PendingPasswordChange(
            device: author, deviceName: name, generation: change.generation,
            isFork: !view.state.pendingCredentials.contains { $0.id == change.id }, canBeFollowed: followed != nil,
            revokedDevices: (followed?.state.revoked.keys.filter(known.contains) ?? [])
                .sorted { $0.uuidString < $1.uuidString },
            revokesThisDevice: followed?.state.standing(of: account.deviceID) == .revoked,
            registeredBeforeFollowed: sealed.contains(author), isDescribed: replaying)
    }

    /// Every device of the account, revoked ones included, this device first. Names need the vault unlocked.
    public func devices() async throws -> [DeviceInfo] {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let view = try await registry(account)
        let keys = try requireKeys(since: epoch)
        func info(_ device: DeviceRegistryState.Device, revoked: Bool) -> DeviceInfo {
            let label = Self.openLabel(device.label, deviceID: device.id, keyset: keys.keyset)
            var addedBy: UUID?
            if case .device(let id) = device.addedBy, id != device.id { addedBy = id }
            return DeviceInfo(
                id: device.id, name: label?.name ?? "", addedAt: label?.addedAt,
                isThisDevice: device.id == account.deviceID, isRevoked: revoked, addedBy: addedBy,
                revokedBy: device.revokedBy)
        }
        let all =
            view.state.devices.values.map { info($0, revoked: false) }
            + view.state.revoked.values.map { info($0, revoked: true) }
        return all.sorted {
            if $0.isThisDevice != $1.isThisDevice { return $0.isThisDevice }
            if $0.isRevoked != $1.isRevoked { return !$0.isRevoked }
            return ($0.name, $0.id.uuidString) < ($1.name, $1.id.uuidString)
        }
    }

    /// Registers another device from this one, before it has the Secret Key: the registered, unlocked device vouches
    /// for the new device's key (shown as a QR code, say). The new device still needs the password and the Secret
    /// Key to open the keyset; this only spares it registering itself.
    ///
    /// The ID must commit to the account under the key (`DeviceIdentifier`, review findings Z157 and Z162), as
    /// `prepareDeviceIdentity` makes it: a device whose ID does not would count in no shared vault, and what it wrote
    /// there would reach nobody. An identity from an older build, or an edited one, is refused
    /// (`deviceIDDoesNotCommit`).
    public func approveDevice(id: UUID, key: DevicePublicKey, name: String) async throws {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        guard DeviceIdentifier.commits(id, to: account.accountID, key: key) else {
            throw VaultError.deviceIDDoesNotCommit
        }
        let view = try await registry(account)
        guard view.state.standing(of: account.deviceID) == .active else { throw VaultError.deviceRevoked }
        let now = await clock.now()
        let keys = try requireKeys(since: epoch)
        let label = try sealedLabel(name: name, at: now, deviceID: id, keyset: keys.keyset)
        let entry = try await signedRegistryEntry(
            parents: view.state.heads, author: .device(account.deviceID),
            body: .add(RegistryDevice(id: id, key: key, label: label)), account: account, keyset: keys.keyset)
        _ = try requireKeys(since: epoch)
        try await store.commit(StoreChange(upserts: [Self.registryRow(entry, account: account)]))
        registryView = nil
        try await pinRegistry(try await registry(account), accountID: account.accountID)
    }

    /// Revokes a device (docs/02-architecture.md §7.8). From the moment each other device learns of it, nothing the
    /// revoked device writes is accepted, it is no longer waited for by garbage collection, and neither its ID nor
    /// its key can be registered again.
    ///
    /// What it does not do: take back what the device already holds. A device that was unlocked by someone else
    /// knows the account key and every vault key it had; `.change` stops it registering a new device, but reading
    /// what it can still reach ends only when it loses access to the sync store and the vault keys are rotated.
    public func revokeDevice(_ deviceID: UUID, password: RevocationPasswordChoice) async throws {
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        guard deviceID != account.deviceID else { throw VaultError.cannotRevokeThisDevice }
        _ = try requireKeys()
        guard try await registry(account).state.devices[deviceID] != nil else {
            throw VaultError.unknownDevice(deviceID)
        }
        // A vault deletion the device made, which this device has checked, must outlive the device's standing.
        try await adoptVerifiedDeletions(account: account)
        switch password {
        case .keepPassword(let current):
            try await rotateCredentials(current: current, new: nil, revoking: deviceID)
        case .change(let current, let new):
            try await rotateCredentials(current: current, new: new, revoking: deviceID)
        }
    }

    // MARK: - Enrolment of a new device (PRD F5.2, F10.2)

    /// Joins an existing account from nothing but the sync transport, the account password and the Secret Key
    /// (typed or scanned from the Emergency Kit): fetches the account header, derives the Account Unlock Key, opens
    /// the keyset, learns the device registry and the account's vaults, registers this device, and leaves the vault
    /// unlocked. `secretKey` may be the kit's setup code, which names the account; otherwise pass `accountID`.
    ///
    /// Everything fetched is hostile until authenticated (A1): the header's KDF parameters are bounded on both
    /// sides before any derivation, the header counts only if its binding opens under the derived key, the registry
    /// only from the genesis entry that binding names, and each vault key only if a registered device vouched for it
    /// and it opens under the keyset for the vault and key its name says. A wrong password, a wrong Secret Key and a
    /// tampered header are one error, `CryptoError.authenticationFailed`.
    ///
    /// `identity` is for a device that a registered device has already vouched for (`approveDevice`): it enrols as
    /// that device, with the key `prepareDeviceIdentity` made. Without it the device takes a new ID and key and
    /// registers itself with the enrolment key, which the password and Secret Key yield. An identity whose ID does not
    /// commit to the account under its key is refused (`deviceIDDoesNotCommit`, Z162).
    public func enrol(
        password: String, secretKey: String, accountID: UUID? = nil, as identity: DeviceIdentity? = nil
    ) async throws {
        if let identity {
            guard let accountID = accountID ?? EmergencyKit.parseSetupCode(secretKey)?.accountID else {
                throw VaultError.enrolmentUnavailable
            }
            guard try await deviceKeys.publicKey(accountID: accountID, deviceID: identity.id) == identity.key else {
                throw VaultError.enrolmentUnavailable
            }
            guard DeviceIdentifier.commits(identity.id, to: accountID, key: identity.key) else {
                throw VaultError.deviceIDDoesNotCommit
            }
        }
        try await enrol(
            password: password, secretKey: secretKey, accountID: accountID, assigningDeviceID: identity?.id)
    }

    /// Makes this installation's device key before it has the account, so that a registered device can vouch for it
    /// (`approveDevice`) — the ID and public key are what the new device shows, as a QR code say. Nothing secret
    /// leaves this device, and nothing here gives it access: it still needs the password and the Secret Key.
    public func prepareDeviceIdentity(accountID: UUID) async throws -> DeviceIdentity {
        guard keys == nil, try await loadAccount() == nil else { throw VaultError.enrolmentUnavailable }
        return try await deviceKeys.createDevice(accountID: accountID)
    }

    /// As `enrol`, with the new device's ID chosen by the caller: for tests that need to name the device. An ID with a
    /// key this installation prepared must commit to the account under it, as for `enrol(as:)` (Z162); an ID a test
    /// names with no prepared key is given a key of its own and commits to nothing, so it counts in no shared vault and
    /// writes nothing there (`SharedVaultError.deviceIDDoesNotCommit`). No production path names an ID.
    package func enrol(password: String, secretKey text: String, accountID: UUID?, assigningDeviceID: UUID?)
        async throws
    {
        guard let transport = syncSettings?.transport, keys == nil, try await loadAccount() == nil else {
            throw VaultError.enrolmentUnavailable
        }
        var keyText = text
        var named = accountID
        if let setup = EmergencyKit.parseSetupCode(text) {
            guard accountID == nil || accountID == setup.accountID else {
                throw VaultError.secretKeyForAnotherAccount
            }
            named = setup.accountID
            keyText = setup.secretKey
        }
        guard let accountID = named else { throw VaultError.enrolmentUnavailable }
        let secretKey = try SecretKey(parsing: keyText)
        defer { secretKey.zeroise() }
        let epoch = lockEpoch
        let now = await clock.now()

        // The newest headers first, a bounded number of them: each costs a key derivation.
        var names: [(generation: UInt64, author: UUID, name: String)] = []
        for name in Set(try await transport.list(prefix: AccountObjectLocation.headerPrefix(accountID))) {
            guard case .header(let id, let generation, let author)? = AccountObjectLocation(name: name),
                id == accountID
            else { continue }
            names.append((generation, author, name))
        }
        names.sort { ($0.generation, $0.author.uuidString) > ($1.generation, $1.author.uuidString) }
        guard !names.isEmpty else { throw VaultError.accountNotOnTransport }

        var opened: (header: AccountHeaderObject, unlockKey: EncryptionKey, keyset: Keyset, personal: UUID)?
        var derivations = 0
        // One derivation per authoring device, on its newest header that parses: a device that publishes a chain of
        // password changes (a revoked device that kept the account key can, each under parameters of its choosing)
        // spends one attempt, and the header of the device that really changed the password is still reached (Z1).
        // Nothing here can be checked against the registry yet, so a store that plants headers under device IDs of
        // its own invention still exhausts the budget; it can as easily delete the real one (W5, Y7).
        var triedAuthors: Set<UUID> = []
        for candidate in names.prefix(Self.maximumHeadersConsidered)
        where derivations < Self.maximumHeaderAttempts && !triedAuthors.contains(candidate.author) {
            // A header that is not what its name says, or whose KDF parameters are out of bounds, costs a fetch and
            // nothing more; only one that parses is worth a derivation, and only a few of those are tried.
            guard
                let bytes = try? await transport.fetch(
                    candidate.name, maximumLength: AccountHeaderObject.maximumLength),
                let header = try? AccountHeaderObject.parse(bytes), header.accountID == accountID,
                header.generation == candidate.generation, header.author == candidate.author
            else { continue }
            triedAuthors.insert(candidate.author)
            derivations += 1
            // `accountUnlockKey` validates the KDF parameters again before any work (SEC5, SEC9).
            guard
                let unlockKey = try? TwoSecretKeyDerivation.accountUnlockKey(
                    password: password, secretKey: secretKey, accountID: accountID, parameters: header.kdf,
                    salt: header.salt, keyID: header.unlockKeyID)
            else { continue }
            guard
                let keyset = try? Keyset.unwrap(
                    header.wrappedKeyset, accountID: accountID, with: unlockKey,
                    recordVersion: header.keysetVersion)
            else {
                unlockKey.zeroise()
                continue
            }
            guard let personal = try? header.openBinding(with: unlockKey) else {
                unlockKey.zeroise()
                keyset.zeroise()
                continue
            }
            opened = (header, unlockKey, keyset, personal)
            break
        }
        guard let opened else { throw CryptoError.authenticationFailed }
        let (header, unlockKey, keyset) = (opened.header, opened.unlockKey, opened.keyset)
        var installed = false
        var vaultKeys: [UUID: VaultKey] = [:]
        defer {
            if !installed {
                unlockKey.zeroise()
                keyset.zeroise()
                for key in vaultKeys.values { key.zeroise() }
            }
        }

        // The registry, from the genesis entry and credential the header's binding authenticated.
        let accountKey = try keyset.publicKeyBundle().signingKey
        var discarded = AccountObjectsReport()
        let gathered = try await gatherRegistryEntries(
            transport: transport, accountID: accountID, accountKey: accountKey, held: [:], genesis: header.genesisID,
            credential: header.credentialID, report: &discarded)
        let raw = gathered.fetched.sorted { $0.key < $1.key }.map(\.value)
        guard
            let view = gathered.view,
            view.state.credential.author == header.author,
            let authorKey = view.state.devices[header.author]?.key ?? view.state.revoked[header.author]?.key,
            (try? header.verifySignatures(accountSigningKey: accountKey, deviceKey: authorKey)) != nil
        else { throw VaultError.accountNotOnTransport }
        // The header opened, but the registry already holds a later password change: the store showed an old header,
        // or the person typed an old password.
        guard view.state.pendingCredentials.isEmpty else { throw VaultError.passwordSuperseded }

        // This device: a new ID, a new key, registered with the enrolment key the derived AUK yields.
        // Its ID commits to the account under its key (review finding Z157): made with the key, unless a registered
        // device vouched for one made earlier (`prepareDeviceIdentity`) or a test names it.
        let deviceID: UUID
        let deviceKey: DevicePublicKey
        if let assigningDeviceID {
            deviceID = assigningDeviceID
            if let prepared = try await deviceKeys.publicKey(accountID: accountID, deviceID: deviceID) {
                guard DeviceIdentifier.commits(deviceID, to: accountID, key: prepared) else {
                    throw VaultError.deviceIDDoesNotCommit
                }
                deviceKey = prepared
            } else {
                deviceKey = try await deviceKeys.create(accountID: accountID, deviceID: deviceID)
            }
        } else {
            let created = try await deviceKeys.createDevice(accountID: accountID)
            (deviceID, deviceKey) = (created.id, created.key)
        }
        var account = AccountRecord(
            accountID: accountID, deviceID: deviceID, personalVaultID: opened.personal,
            personalVaultKeyID: Self.zeroUUID, kdf: header.kdf, salt: header.salt, unlockKeyID: header.unlockKeyID,
            wrappedKeyset: header.wrappedKeyset, keysetVersion: header.keysetVersion,
            credentialGeneration: header.generation, createdAt: now, emergencyKitConfirmedAt: now)
        let enrolment = EnrolmentKey.derive(from: unlockKey, accountID: accountID)
        defer { enrolment.zeroise() }
        let registration = try await signedRegistryEntry(
            parents: view.state.heads, author: .enrolment(credential: header.credentialID),
            body: .add(
                RegistryDevice(
                    id: deviceID, key: deviceKey,
                    label: try sealedLabel(name: configuration.deviceName, at: now, deviceID: deviceID, keyset: keyset)
                )),
            account: account, keyset: keyset, enrolment: enrolment)
        let registered = try Self.evaluateRegistry(
            raw + [registration.serialized()], accountID: accountID, accountKey: accountKey,
            genesis: header.genesisID, credential: header.credentialID)
        guard registered.state.standing(of: deviceID) == .active else { throw VaultError.accountNotOnTransport }

        // The account's vaults: every key a registered device vouched for that opens under the keyset.
        let directory = try await fetchDirectory(
            transport: transport, accountID: accountID, view: registered, keyset: keyset, knownKeys: [],
            deletedVaults: [], personalVaultID: opened.personal, report: &discarded)
        for wrap in directory.keys {
            guard
                let key = try? VaultKey.unwrap(
                    wrap.envelope, vaultID: wrap.vaultID, keyID: wrap.recordID, with: keyset)
            else { continue }
            vaultKeys[wrap.recordID] = key
        }
        guard
            let personalKeyID = Self.currentKeyID(
                for: opened.personal, among: Array(vaultKeys.values), personal: nil)
        else { throw VaultError.accountNotOnTransport }
        account.personalVaultKeyID = personalKeyID

        var rows = raw.map { Self.registryRow($0, accountID: accountID, deviceID: deviceID) }
        rows.append(Self.registryRow(registration, account: account))
        rows.append(Self.headerRow(header, recordID: accountID, version: 1))
        rows += directory.keys.filter { vaultKeys[$0.recordID] != nil }
        let vaultIDs = Set(vaultKeys.values.map(\.vaultID)).union(directory.deletions.map(\.recordID))
        let deleted = Dictionary(uniqueKeysWithValues: directory.deletions.map { ($0.recordID, $0) })
        for vaultID in vaultIDs {
            rows.append(
                deleted[vaultID] ?? Self.directoryRow(vaultID: vaultID, accountID: accountID, deviceID: deviceID))
        }
        // Which of those vaults are shared, as the account's other devices marked them: a new device knows from its
        // first moment, and holds them closed until it has their ledgers (review finding Z41).
        rows += directory.markers

        // Keychain first, as in `createAccount`: an orphaned Secret Key is harmless.
        try await keychain.store(
            secretKey.bytes.extracting(0..<SecretKey.byteCount), for: .secretKey(accountID: accountID))
        do {
            try await store.commit(StoreChange(account: .create(account), upserts: rows))
        } catch {
            try? await keychain.delete(.secretKey(accountID: accountID))
            try? await deviceKeys.delete(accountID: accountID)
            throw error
        }
        self.account = account
        try await writeAnchor(
            RegistryAnchor(
                genesis: header.genesisID, credential: header.credentialID, generation: header.generation,
                heads: registered.state.heads),
            accountID: accountID)
        let newKeys = UnlockedKeys(accountUnlockKey: unlockKey, keyset: keyset, vaultKeys: vaultKeys)
        installed = true
        guard epoch == lockEpoch, keys == nil else {
            newKeys.zeroise()
            throw VaultError.lockedDuringUnlock
        }
        registryView = nil
        install(newKeys, at: now, withPassword: true)
        try? await refreshSigningKey(account: account, keys: newKeys)
        await loadSharedMarkersIfNeeded(force: true)
    }

    // MARK: - Account objects on the transport (docs/02-architecture.md §7.7)

    /// Registry entries fetched in one batch, and batches in one gathering: each batch is evaluated together with
    /// what is already held, so no evaluation exceeds `DeviceRegistry.maximumEvaluated`.
    static let registryBatch = DeviceRegistry.maximumEntries / 2
    static let maximumRegistryBatches = 8
    static let maximumSkippedRegistryEntries = 1 << 16

    /// Registry entries on the transport that this device does not hold, fetched in batches and judged together
    /// with `held` from `genesis` along `credential` (docs/02-architecture.md §7.8). Each must be named by the
    /// SHA-256 of its bytes and signed by the account key; of those, only what the evaluation retains
    /// (`DeviceRegistryState.retainedEntries`) is returned. One whose missing parents are listed but not fetched yet
    /// is held while the batches go on, and fetched again by a later sync if they never arrive. Everything else can
    /// never count, is not kept, and is not fetched again by this session until a sync keeps something new
    /// (`skippedRegistryEntries`): a revoked device that kept the account key can put any number of entries on the
    /// transport, but they fill neither this device's registry nor its fetches.
    ///
    /// `view` is the registry evaluated from `held` and what was kept, or `nil` if it could not be evaluated (which
    /// is then reported by the caller as it would be without the transport).
    func gatherRegistryEntries(
        transport: any SyncTransport, accountID: UUID, accountKey: [UInt8], held: [ObjectDigest: [UInt8]],
        genesis: ObjectDigest, credential: ObjectDigest, requiredHeads: [ObjectDigest] = [],
        report: inout AccountObjectsReport
    ) async throws -> (view: RegistryView?, fetched: [ObjectDigest: [UInt8]], listed: Set<ObjectDigest>) {
        var listed: [ObjectDigest: String] = [:]
        for name in Set(try await transport.list(prefix: AccountObjectLocation.registryPrefix(accountID))) {
            guard case .registryEntry(let id, let hex)? = AccountObjectLocation(name: name), id == accountID,
                let digest = ObjectDigest(hex: hex)
            else {
                report.ignoredNames += 1
                continue
            }
            listed[digest] = name
        }
        var pool = held
        var fetched: [ObjectDigest: [UInt8]] = [:]
        var tried: Set<ObjectDigest> = []
        var view: RegistryView?
        var evaluated = false
        for _ in 0..<Self.maximumRegistryBatches {
            let room = DeviceRegistry.maximumEvaluated - pool.count
            let batch = listed.keys.filter {
                pool[$0] == nil && !tried.contains($0) && !skippedRegistryEntries.contains($0)
            }.sorted().prefix(max(0, min(Self.registryBatch, room)))
            if batch.isEmpty, evaluated { break }
            for digest in batch {
                tried.insert(digest)
                do {
                    guard
                        let bytes = try await transport.fetch(
                            listed[digest]!, maximumLength: RegistryEntry.maximumLength)
                    else { continue }
                    guard ObjectDigest(hashing: bytes) == digest,
                        !DeviceRegistry.admit([bytes], accountID: accountID, accountSigningKey: accountKey).isEmpty
                    else {
                        report.rejected.append(listed[digest]!)
                        continue
                    }
                    pool[digest] = bytes
                    fetched[digest] = bytes
                } catch let error as SyncTransportError where error.stopsSync {
                    throw error
                } catch {
                    report.rejected.append(listed[digest]!)
                }
            }
            evaluated = true
            view = try? Self.evaluateRegistry(
                Array(pool.values), accountID: accountID, accountKey: accountKey, genesis: genesis,
                credential: credential, requiredHeads: requiredHeads)
            if let view {
                // Kept: what the registry retains, and what waits only on parents still to be fetched. The rest is
                // worth nothing, now and later.
                var waiting = Set(pool.keys).subtracting(view.state.connectedEntries)
                var changed = true
                while changed {
                    changed = false
                    for digest in waiting {
                        let parents = view.entries[digest]?.parents ?? []
                        let fetchable = parents.allSatisfy { parent in
                            view.state.connectedEntries.contains(parent) || waiting.contains(parent)
                                || (listed[parent] != nil && !tried.contains(parent) && pool[parent] == nil
                                    && !skippedRegistryEntries.contains(parent))
                        }
                        if parents.isEmpty || !fetchable {
                            waiting.remove(digest)
                            changed = true
                        }
                    }
                }
                for digest in Array(pool.keys)
                where !view.state.retainedEntries.contains(digest) && !waiting.contains(digest) {
                    pool[digest] = nil
                    if fetched.removeValue(forKey: digest) != nil,
                        skippedRegistryEntries.count < Self.maximumSkippedRegistryEntries
                    {
                        skippedRegistryEntries.insert(digest)
                    }
                }
            } else if room <= 0 {
                break
            }
            if batch.isEmpty { break }
        }
        if let current = view, current.entries.count != pool.count {
            // Evaluated again from exactly what is kept, which is what the caller stores.
            view = try? Self.evaluateRegistry(
                Array(pool.values), accountID: accountID, accountKey: accountKey, genesis: genesis,
                credential: credential, requiredHeads: requiredHeads)
        }
        return (view, fetched.filter { view?.state.retainedEntries.contains($0.key) ?? true }, Set(listed.keys))
    }

    /// The vault directory on the transport: wraps and deletions this device does not hold, each vouched for by a
    /// registered device (both signatures over the object's name and body), as rows for the local store. With a
    /// keyset, a wrap is kept only if it also opens for the vault and key its name says.
    func fetchDirectory(
        transport: any SyncTransport, accountID: UUID, view: RegistryView, keyset: Keyset?, knownKeys: Set<UUID>,
        deletedVaults: Set<UUID>, markedVaults: Set<UUID> = [], personalVaultID: UUID,
        report: inout AccountObjectsReport
    ) async throws -> (keys: [StoredRecord], deletions: [StoredRecord], markers: [StoredRecord], listed: Set<String>) {
        var keys: [UUID: StoredRecord] = [:]
        var deletions: [UUID: StoredRecord] = [:]
        var markers: [UUID: StoredRecord] = [:]
        let listed = Set(try await transport.list(prefix: AccountObjectLocation.vaultsPrefix(accountID)))
        for name in listed.sorted() {
            guard let location = AccountObjectLocation(name: name), location.accountID == accountID else {
                report.ignoredNames += 1
                continue
            }
            let author: UUID
            switch location {
            case .vaultKey(_, _, let keyID, let device):
                guard !knownKeys.contains(keyID), keys[keyID] == nil else { continue }
                author = device
            case .vaultDeletion(_, let vaultID, let device):
                guard !deletedVaults.contains(vaultID), deletions[vaultID] == nil else { continue }
                // The Personal vault cannot be deleted, whoever says so (PRD F2.1).
                guard vaultID != personalVaultID else {
                    report.rejected.append(name)
                    continue
                }
                author = device
            case .vaultShared(_, let vaultID, let device):
                // A marker this device holds already is not fetched again; the Personal vault is never shared.
                guard !markedVaults.contains(vaultID), markers[vaultID] == nil, vaultID != personalVaultID else {
                    continue
                }
                author = device
            default:
                report.ignoredNames += 1
                continue
            }
            // Vouched for by a device since revoked, or not yet known: another device's copy may follow.
            guard view.state.devices[author] != nil else { continue }
            do {
                guard let bytes = try await transport.fetch(name, maximumLength: Self.directoryObjectMaximumLength)
                else { continue }
                let object = try SignedObject.parse(bytes)
                try Self.verifyDual(
                    object.signature, over: Self.directoryMessage(name: name, body: object.envelope),
                    domain: .vaultDirectory, author: author, view: view)
                switch location {
                case .vaultKey(_, let vaultID, let keyID, _):
                    let header = try EnvelopeHeader.parse(object.envelope, expecting: .vaultKeyWrap).header
                    // Of either class: the account's own key, or one that arrived by grant (`VaultKey`).
                    try VaultKey.checkWrapForm(object.envelope, vaultID: vaultID, keyID: keyID)
                    if let keyset {
                        // The session's keyset may have been zeroised by a `lock()` during the fetch: reading it
                        // would trap. The rest of this sync is then a download.
                        guard !keyset.isZeroised else { throw SyncKeyringError.locked }
                        try VaultKey.unwrap(object.envelope, vaultID: vaultID, keyID: keyID, with: keyset).zeroise()
                    }
                    keys[keyID] = StoredRecord(
                        recordID: keyID, kind: .vaultKeyWrap, vaultID: vaultID, keyID: header.keyID, version: 1,
                        deviceID: author, envelope: object.envelope)
                case .vaultDeletion(_, let vaultID, _):
                    guard object.envelope == Self.deletionMarker else { throw SyncFormatError.malformedEntry }
                    deletions[vaultID] = Self.directoryRow(
                        vaultID: vaultID, accountID: accountID, deviceID: author, deletion: object)
                case .vaultShared(_, let vaultID, _):
                    guard let marker = Self.parseSharedMarkerBody(object.envelope), marker.vaultID == vaultID else {
                        throw SyncFormatError.malformedEntry
                    }
                    markers[vaultID] = Self.sharedMarkerRow(
                        vaultID: vaultID, accountID: accountID, author: author, object: object)
                default:
                    break
                }
            } catch let error as SyncTransportError where error.stopsSync {
                throw error
            } catch SyncKeyringError.locked {
                throw SyncKeyringError.locked
            } catch {
                report.rejected.append(name)
            }
        }
        return (Array(keys.values), Array(deletions.values), Array(markers.values), listed)
    }

    /// What a directory object's signatures cover: its name and its body.
    static func directoryMessage(name: String, body: [UInt8]) -> [UInt8] {
        Array(name.utf8) + [0x00] + body
    }

    /// Downloads and publishes the account's own objects: registry entries, the account header and candidates for a
    /// password changed elsewhere, and the vault directory. Downloading and checking need public keys only;
    /// vouching for vault keys and deletions needs the vault unlocked and this device registered.
    func syncAccountObjects(account: AccountRecord, transport: any SyncTransport) async throws -> AccountObjectsReport {
        var report = AccountObjectsReport()
        let accountID = account.accountID
        guard let accountKey = await trustedAccountSigningKey(account) else { return report }

        // 0. Before the registry moves on (a revocation may arrive with it), every vault deletion this device has
        //    verified becomes its own.
        try? await adoptVerifiedDeletions(account: account)

        // 1. The registry: a grow-only set of entries, merged by union in both directions — of the entries that may
        //    count. One that can never count (its author revoked behind a password change, say) is neither stored,
        //    nor kept if it was, nor published, so it cannot fill the registry (`DeviceRegistry.maximumEntries`).
        //    Without the Keychain's anchor (lost, or a store restored onto other hardware), what to keep is judged
        //    from the local header's genesis and credential: that decides what is stored, not what is trusted,
        //    which waits for the header to open under the password at the next unlock.
        let pin: (genesis: ObjectDigest, credential: ObjectDigest, heads: [ObjectDigest])
        if let anchor = await trustedAnchor(account) {
            pin = (anchor.genesis, anchor.credential, anchor.heads)
        } else if let stored = try await storedHeader(account) {
            pin = (stored.header.genesisID, stored.header.credentialID, [])
        } else {
            return report
        }
        let localRows = try await store.records(in: accountID, kind: .deviceRegistry)
        var held: [ObjectDigest: [UInt8]] = [:]
        for row in localRows { held[ObjectDigest(hashing: row.envelope)] = row.envelope }
        let gathered = try await gatherRegistryEntries(
            transport: transport, accountID: accountID, accountKey: accountKey, held: held, genesis: pin.genesis,
            credential: pin.credential, requiredHeads: pin.heads, report: &report)
        if let judged = gathered.view {
            var change = StoreChange()
            for (_, bytes) in gathered.fetched.sorted(by: { $0.key < $1.key }) {
                let row = Self.registryRow(bytes, accountID: accountID, deviceID: account.deviceID)
                if try await store.record(row.key) == nil { change.upserts.append(row) }
            }
            for row in localRows where !judged.state.retainedEntries.contains(ObjectDigest(hashing: row.envelope)) {
                change.deletions.append(row.key)
            }
            if !change.upserts.isEmpty || !change.deletions.isEmpty {
                try await store.commit(change)
                report.registryEntriesFetched = change.upserts.count
            }
            // Progress: what was skipped as waiting on a parent may be wanted now.
            if !change.upserts.isEmpty { skippedRegistryEntries = [] }
        }
        registryView = nil
        guard let view = try? await registry(account) else { return report }
        try? await pinRegistry(view, accountID: accountID)
        for id in view.state.retainedEntries.subtracting(gathered.listed).sorted() {
            guard let entry = view.entries[id] else { continue }
            if try await create(
                AccountObjectLocation.registryEntry(accountID: accountID, id: id.hex).name,
                contents: entry.serialized(), on: transport)
            {
                report.registryEntriesPublished += 1
            }
        }

        // 2. Account headers: publish this device's, keep candidates for credentials it does not follow yet.
        try await syncHeaders(account: account, view: view, transport: transport, report: &report)

        // 3. The vault directory.
        try await syncDirectory(account: account, view: view, transport: transport, report: &report)
        return report
    }

    /// Creates an object; `false` if it was already there (objects are written once).
    func create(_ name: String, contents: [UInt8], on transport: any SyncTransport) async throws -> Bool {
        do {
            try await transport.create(name, contents: contents)
            return true
        } catch SyncTransportError.objectExists {
            return false
        }
    }

    private func syncHeaders(
        account: AccountRecord, view: RegistryView, transport: any SyncTransport, report: inout AccountObjectsReport
    ) async throws {
        let accountID = account.accountID
        let listed = Set(try await transport.list(prefix: AccountObjectLocation.headerPrefix(accountID)))
        var currentName: String?
        if let stored = try await storedHeader(account) {
            let name = AccountObjectLocation.header(
                accountID: accountID, generation: stored.header.generation, author: stored.header.author
            ).name
            currentName = name
            // Any device puts back a header the store has lost — unless it knows its own to be out of date (the
            // password was changed elsewhere), or is no longer a device of the account.
            if !listed.contains(name), view.state.pendingCredentials.isEmpty,
                stored.header.credentialID == view.state.credential.id,
                view.state.standing(of: account.deviceID) == .active
            {
                report.headerPublished = try await create(name, contents: stored.row.envelope, on: transport)
            }
        }

        // Candidates: only headers whose credential entry the registry lists as pending or forked are fetched at
        // all, so a store full of planted headers costs nothing; and one per authoring device, its newest that the
        // transport holds, so a device that publishes a chain of changes costs one header (Z1).
        let rows = try await store.records(in: accountID, kind: .accountHeader).filter { $0.recordID != accountID }
        var held: [UUID: (header: AccountHeaderObject, key: RecordKey)] = [:]
        var stale: [RecordKey] = []
        for row in rows {
            guard let header = try? AccountHeaderObject.parse(row.envelope),
                Self.isCandidate(header, account: account, view: view)
            else {
                stale.append(row.key)
                continue
            }
            if let other = held[header.author] {
                let newer =
                    (header.generation, header.credentialID) > (other.header.generation, other.header.credentialID)
                stale.append(newer ? other.key : row.key)
                if !newer { continue }
            }
            held[header.author] = (header, row.key)
        }
        if !stale.isEmpty { try await store.commit(StoreChange(deletions: stale)) }
        let wanted = Self.changesByAuthor(
            view.state.pendingCredentials + view.state.forkedCredentials, sealed: Self.sealedAuthors(view))
        for (author, changes) in wanted.prefix(Self.maximumCandidateAuthors) {
            for credential in changes.prefix(Self.maximumHeaderAttempts) {
                if let have = held[author], have.header.generation >= credential.generation { break }
                guard
                    let header = await fetchCandidateHeader(
                        for: credential, account: account, view: view,
                        transport: transport, listed: listed)
                else { continue }
                let row = Self.headerRow(
                    header,
                    recordID: Self.uuid(Array(ObjectDigest(hashing: header.serialized()).bytes[..<16])), version: 1)
                var change = StoreChange()
                if try await store.record(row.key) == nil { change.upserts.append(row) }
                if let replaced = held[author] { change.deletions.append(replaced.key) }
                if !change.upserts.isEmpty || !change.deletions.isEmpty { try await store.commit(change) }
                if !change.upserts.isEmpty { report.candidateHeadersFetched += 1 }
                break
            }
        }

        // This device's own superseded headers are of no use to anyone.
        if let currentName, listed.contains(currentName) || report.headerPublished {
            for name in listed where name != currentName {
                if case .header(_, _, let author)? = AccountObjectLocation(name: name), author == account.deviceID {
                    try? await transport.delete(name)
                }
            }
        }
    }

    /// The header for `credential` from the transport, if it is there under the name its generation and author
    /// give it and is what `isCandidate` requires.
    func fetchCandidateHeader(
        for credential: DeviceRegistryState.Credential, account: AccountRecord, view: RegistryView,
        transport: any SyncTransport, listed: Set<String>? = nil
    ) async -> AccountHeaderObject? {
        let name = AccountObjectLocation.header(
            accountID: account.accountID, generation: credential.generation, author: credential.author
        ).name
        guard listed?.contains(name) ?? true,
            let bytes = try? await transport.fetch(name, maximumLength: AccountHeaderObject.maximumLength),
            let header = try? AccountHeaderObject.parse(bytes), header.credentialID == credential.id,
            Self.isCandidate(header, account: account, view: view)
        else { return nil }
        return header
    }

    private func syncDirectory(
        account: AccountRecord, view: RegistryView, transport: any SyncTransport, report: inout AccountObjectsReport
    ) async throws {
        let accountID = account.accountID
        let directory = try await vaultDirectory(account)
        // While unlocked, a wrap row counts as known only if it opened. One edited in the file (A8) — moved under
        // another vault, corrupted — is replaced by the signed copy on the transport, which `fetchDirectory` opens
        // with the keyset before it is taken. While locked nothing can tell, and only missing rows are fetched.
        let opened = keys.map { Set($0.vaultKeys.keys) }
        var knownKeys: Set<UUID> = []
        for vaultID in directory.keys {
            for row in try await store.records(in: vaultID, kind: .vaultKeyWrap)
            where opened?.contains(row.recordID) ?? true {
                knownKeys.insert(row.recordID)
            }
        }
        let deleted = Set(directory.filter { $0.value.isDeleted }.keys)
        // The markers this device holds, read from the store now: a row removed from the file since (A8) is fetched
        // again here, before any vault's log is touched.
        await loadSharedMarkersIfNeeded(force: true)
        var markedLocally: Set<UUID> = []
        if let signingKey = await trustedAccountSigningKey(account) {
            for row in try await store.records(in: accountID, kind: .vaultDirectory) {
                if let marker = Self.verifiedSharedMarker(row, accountID: accountID, accountSigningKey: signingKey) {
                    markedLocally.insert(marker.vaultID)
                }
            }
        }
        let fetched = try await fetchDirectory(
            transport: transport, accountID: accountID, view: view, keyset: keys?.keyset, knownKeys: knownKeys,
            deletedVaults: deleted, markedVaults: markedLocally, personalVaultID: account.personalVaultID,
            report: &report)
        // Which vaults the account's other devices know of, as far as the listing says: a device that holds nothing of
        // one the listing names accepts no invitation for it naming just anyone (Z59, `knownOwner`).
        sharing.directoryVaults = Set(
            fetched.listed.compactMap { name -> UUID? in
                switch AccountObjectLocation(name: name) {
                case .vaultKey(let owner, let vaultID, _, _)? where owner == accountID: return vaultID
                case .vaultDeletion(let owner, let vaultID, _)? where owner == accountID: return vaultID
                case .vaultShared(let owner, let vaultID, _)? where owner == accountID: return vaultID
                default: return nil
                }
            })

        var change = StoreChange()
        var indexed = Set(directory.keys)
        for var wrap in fetched.keys {
            let local = try await store.record(wrap.key)
            if let local {
                // A row that did not open is replaced, above the version it was at (a store never goes back).
                guard opened?.contains(wrap.recordID) == false, local.version < UInt64.max else { continue }
                wrap.version = local.version + 1
            }
            change.upserts.append(wrap)
            change.expectations[wrap.key] = local.map { .version($0.version) } ?? .absent
            report.vaultKeysFetched += 1
            if indexed.insert(wrap.vaultID).inserted,
                !fetched.deletions.contains(where: { $0.recordID == wrap.vaultID })
            {
                change.upserts.append(
                    Self.directoryRow(vaultID: wrap.vaultID, accountID: accountID, deviceID: account.deviceID))
            }
        }
        for var deletion in fetched.deletions {
            if let existing = try await store.record(deletion.key) {
                // A row at the last version (an edited file, Z23) cannot be replaced: left as it is, like a wrap.
                guard existing.version < UInt64.max else { continue }
                deletion.version = existing.version + 1
            }
            change.upserts.append(deletion)
            report.vaultDeletionsFetched += 1
        }
        for var marker in fetched.markers {
            // Over whatever the row held: only a row that marks nothing can be there (a marker held is not fetched).
            if let existing = try await store.record(marker.key) {
                guard existing.version < UInt64.max else { continue }
                marker.version = existing.version + 1
                change.expectations[marker.key] = .version(existing.version)
            } else {
                change.expectations[marker.key] = .absent
            }
            change.upserts.append(marker)
        }
        if !change.upserts.isEmpty { try await store.commit(change) }
        if !fetched.markers.isEmpty { await loadSharedMarkersIfNeeded(force: true) }
        // Every device's marker for a vault must name the same owner (VaultSession+SharedMarker.swift, Z48).
        await examineSharedMarkers(listed: fetched.listed, view: view, account: account, transport: transport)
        if report.vaultKeysFetched > 0 { try await adoptNewVaultKeys(account: account) }
        if report.vaultDeletionsFetched > 0 { try? await adoptVerifiedDeletions(account: account) }

        // Vouch for what this device holds and has checked: every vault key it has opened, every deletion it has
        // verified. A directory object then never depends on the signature of a device that is later revoked.
        guard let keys, view.state.standing(of: account.deviceID) == .active, view.state.pendingCredentials.isEmpty
        else { return }
        let epoch = lockEpoch
        for key in keys.vaultKeys.values.sorted(by: { $0.key.keyID.uuidString < $1.key.keyID.uuidString }) {
            let name = AccountObjectLocation.vaultKey(
                accountID: accountID, vaultID: key.vaultID, keyID: key.key.keyID, author: account.deviceID
            ).name
            guard !fetched.listed.contains(name),
                let wrap = try await store.record(RecordKey(recordID: key.key.keyID, kind: .vaultKeyWrap)),
                wrap.vaultID == key.vaultID
            else { continue }
            let keys = try requireSyncKeys(since: epoch)
            let signature = try await dualSignature(
                Self.directoryMessage(name: name, body: wrap.envelope), domain: .vaultDirectory, keys: keys,
                account: account)
            if try await create(
                name, contents: SignedObject(signature: signature, envelope: wrap.envelope).serialized(),
                on: transport)
            {
                report.vaultKeysPublished += 1
            }
        }
        // The markers this device holds, each vouched for under its own name, so that one does not rest on the
        // device that first wrote it.
        for (vaultID, owner) in sharing.markers.sorted(by: { $0.key.uuidString < $1.key.uuidString }) {
            let name = AccountObjectLocation.vaultShared(
                accountID: accountID, vaultID: vaultID, author: account.deviceID
            )
            .name
            guard !fetched.listed.contains(name) else { continue }
            let keys = try requireSyncKeys(since: epoch)
            let body = Self.sharedMarkerBody(vaultID: vaultID, owner: owner)
            let signature = try await dualSignature(
                Self.directoryMessage(name: name, body: body), domain: .vaultDirectory, keys: keys, account: account)
            _ = try await create(
                name, contents: SignedObject(signature: signature, envelope: body).serialized(), on: transport)
        }
        for (vaultID, entry) in try await vaultDirectory(account) where entry.isDeleted {
            let name = AccountObjectLocation.vaultDeletion(
                accountID: accountID, vaultID: vaultID, author: account.deviceID
            ).name
            guard !fetched.listed.contains(name) else { continue }
            let keys = try requireSyncKeys(since: epoch)
            let signature = try await dualSignature(
                Self.directoryMessage(name: name, body: Self.deletionMarker), domain: .vaultDirectory, keys: keys,
                account: account)
            if try await create(
                name, contents: SignedObject(signature: signature, envelope: Self.deletionMarker).serialized(),
                on: transport)
            {
                report.vaultDeletionsPublished += 1
            }
        }
    }

    func requireSyncKeys(since epoch: UInt64) throws -> UnlockedKeys {
        guard epoch == lockEpoch, let keys else { throw SyncKeyringError.locked }
        return keys
    }
}
