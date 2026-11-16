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
struct RegistryAnchor: Equatable, Sendable {
    static let magic = Array("WWRA1".utf8)
    static let maximumHeads = 256

    var genesis: ObjectDigest
    var credential: ObjectDigest
    /// The generation of `credential`. The account header in the local file must not be older than this: that is
    /// checked at unlock without needing a single registry entry, so deleting them from the file hides nothing.
    var generation: UInt64
    /// The newest entries applied. The local store must still hold them, and so everything they descend from.
    var heads: [ObjectDigest]

    func encoded() -> [UInt8] {
        let kept = heads.sorted().prefix(Self.maximumHeads)
        var out = Self.magic + genesis.bytes + credential.bytes
        out += (0..<8).map { UInt8(truncatingIfNeeded: generation >> (8 * $0)) }
        out += [UInt8(truncatingIfNeeded: kept.count), UInt8(truncatingIfNeeded: kept.count >> 8)]
        for head in kept { out += head.bytes }
        return out
    }

    init(genesis: ObjectDigest, credential: ObjectDigest, generation: UInt64, heads: [ObjectDigest]) {
        self.genesis = genesis
        self.credential = credential
        self.generation = generation
        self.heads = heads.sorted()
    }

    init?(bytes: [UInt8]) {
        let fixed = Self.magic.count + 2 * ObjectDigest.byteCount + 8 + 2
        guard bytes.count >= fixed, Array(bytes[..<Self.magic.count]) == Self.magic else { return nil }
        var offset = Self.magic.count
        func digest(_ offset: inout Int) -> ObjectDigest? {
            defer { offset += ObjectDigest.byteCount }
            return ObjectDigest(bytes: Array(bytes[offset..<(offset + ObjectDigest.byteCount)]))
        }
        guard let genesis = digest(&offset), let credential = digest(&offset) else { return nil }
        let generation = (0..<8).reduce(UInt64(0)) { $0 | UInt64(bytes[offset + $1]) << (8 * UInt64($1)) }
        offset += 8
        let count = Int(bytes[offset]) | Int(bytes[offset + 1]) << 8
        offset += 2
        guard count <= Self.maximumHeads, bytes.count == fixed + count * ObjectDigest.byteCount else { return nil }
        var heads: [ObjectDigest] = []
        for _ in 0..<count {
            guard let head = digest(&offset) else { return nil }
            heads.append(head)
        }
        self.init(genesis: genesis, credential: credential, generation: generation, heads: heads)
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
    /// header's KDF parameters ask, up to the ceiling (SEC9).
    static let maximumHeaderAttempts = 3
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

    /// The registry as this device sees it: the entries in the local store, replayed from the genesis entry and
    /// along the credentials the Keychain anchor names. Needs public keys only, so it works while locked. Throws
    /// `deviceRegistryUnavailable` when there is no anchor or account key to trust, or when the store no longer
    /// holds the entries the anchor names — a file rolled back to before a revocation (A8) is refused, not believed.
    func registry(_ account: AccountRecord) async throws -> RegistryView {
        if let registryView { return registryView }
        guard let accountKey = await trustedAccountSigningKey(account),
            let anchor = await readAnchor(account.accountID)
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
    /// behind it.
    func pinRegistry(_ view: RegistryView, accountID: UUID) async throws {
        let anchor = RegistryAnchor(
            genesis: view.state.genesis, credential: view.state.credential.id,
            generation: view.state.credential.generation, heads: view.state.heads)
        if await readAnchor(accountID) != anchor {
            try await writeAnchor(anchor, accountID: accountID)
        }
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
    /// credential entry must be one the registry holds as pending or forked, written by the same device, and the
    /// header must carry the account key's signature and that device's. `pending` are password changes made after
    /// the one this device follows; `forked` branch off earlier.
    func candidateHeaders(_ account: AccountRecord) async -> (
        pending: [AccountHeaderObject], forked: [AccountHeaderObject]
    ) {
        guard let view = try? await registry(account),
            let rows = try? await store.records(in: account.accountID, kind: .accountHeader)
        else { return ([], []) }
        var pending: [AccountHeaderObject] = []
        var forked: [AccountHeaderObject] = []
        for row in rows where row.recordID != account.accountID {
            guard let header = try? AccountHeaderObject.parse(row.envelope),
                Self.isCandidate(header, account: account, view: view)
            else { continue }
            if view.state.pendingCredentials.contains(where: { $0.id == header.credentialID }) {
                pending.append(header)
            } else {
                forked.append(header)
            }
        }
        let newestFirst: (AccountHeaderObject, AccountHeaderObject) -> Bool = {
            ($0.generation, $0.credentialID) > ($1.generation, $1.credentialID)
        }
        return (pending.sorted(by: newestFirst), forked.sorted(by: newestFirst))
    }

    static func isCandidate(_ header: AccountHeaderObject, account: AccountRecord, view: RegistryView) -> Bool {
        guard header.accountID == account.accountID, header.genesisID == view.state.genesis,
            let credential = (view.state.pendingCredentials + view.state.forkedCredentials).first(where: {
                $0.id == header.credentialID
            }), credential.generation == header.generation, credential.author == header.author,
            let key = view.state.devices[header.author]?.key ?? view.state.revoked[header.author]?.key
        else { return false }
        return (try? header.verifySignatures(accountSigningKey: view.state.accountSigningKey, deviceKey: key)) != nil
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
        let anchor = await readAnchor(accountID)
        guard epoch == lockEpoch, !keys.accountUnlockKey.isZeroised else { return }

        // An account from before the registry existed has none of this. Its registry is started at a sync, and only
        // if the transport holds no header for the account (`startRegistryIfAccountPredatesIt`): a database
        // restored without its registry rows must not start a second registry for an account that already syncs.
        if stored == nil, anchor == nil { return }

        // The stored header is this account record's own only if it opens under the key just derived; then what it
        // names is authenticated by the password, and can restore a missing anchor (a Keychain that lost it, a
        // store restored onto other hardware) or move it forward (a crash between committing a password change and
        // pinning it).
        // A device that has an anchor never takes another genesis entry: one registry per account, for good.
        if let stored, stored.header.unlockKeyID == account.unlockKeyID,
            (try? stored.header.openBinding(with: keys.accountUnlockKey)) == account.personalVaultID,
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
            if let view = try? Self.evaluateRegistry(
                rows.map(\.envelope), accountID: accountID, accountKey: accountKey,
                genesis: stored.header.genesisID, credential: stored.header.credentialID,
                requiredHeads: anchor?.heads ?? [])
            {
                try await pinRegistry(view, accountID: accountID)
                registryView = view
            }
        }

        guard let view = try? await registry(account), epoch == lockEpoch else { return }
        // A store restored onto other hardware arrives without the device key (Keychain items never leave a
        // device): this installation is a new device, and says so. One whose registration no longer counts (it was
        // made with a password since changed) registers again under the same ID.
        guard view.state.pendingCredentials.isEmpty else { return }
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
        guard let anchor = await readAnchor(account.accountID) else { return }
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
    /// row is written again by the new ID, unchanged (`ItemMerge.written`), in the commit that registers it, and
    /// each of the old ID's pending deletions is recorded again as the new ID's (PRD F7.7).
    func registerThisDevice(account: AccountRecord, keys: UnlockedKeys, asNewDevice: Bool) async throws {
        let epoch = lockEpoch
        let view = try await registry(account)
        var updated = account
        if asNewDevice { updated.deviceID = UUID.random(using: &random) }
        let unpublished = asNewDevice ? try await unpublishedRows(of: account) : (rows: [], deletions: [:])
        let now = await clock.now()
        let keys = try requireKeys(since: epoch)
        let enrolment = EnrolmentKey.derive(from: keys.accountUnlockKey, accountID: account.accountID)
        defer { enrolment.zeroise() }
        let label = try sealedLabel(
            name: configuration.deviceName, at: now, deviceID: updated.deviceID, keyset: keys.keyset)
        let keyset = keys.keyset
        let deviceKey: DevicePublicKey
        if asNewDevice {
            deviceKey = try await deviceKeys.create(accountID: account.accountID, deviceID: updated.deviceID)
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
            try? await startNewDeviceSyncState(carrying: unpublished.deletions, as: updated)
        }
        registryView = nil
        if let refreshed = try? await registry(updated) {
            try? await pinRegistry(refreshed, accountID: account.accountID)
        }
    }

    /// The rows this device wrote that its sync state does not record as published, and its pending deletions
    /// (those that verify), per vault: what a store restored onto other hardware holds that no other device has.
    func unpublishedRows(of account: AccountRecord) async throws -> (
        rows: [StoredRecord], deletions: [UUID: [RecordKey: PendingDeletion]]
    ) {
        guard let base = syncSettings?.state, let syncState else { return ([], [:]) }
        var rows: [StoredRecord] = []
        var deletions: [UUID: [RecordKey: PendingDeletion]] = [:]
        for vaultID in try await vaultDirectory(account).keys {
            let state = try await base.loadState(vaultID: vaultID)
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

    /// The sync state of a new device ID: what the old ID published and acknowledged is not this device's to
    /// continue (its stream, its sequence numbers), so each vault starts over — but the old ID's pending deletions
    /// are recorded again as this device's, each stamped above the old one so that it replaces it in one write.
    func startNewDeviceSyncState(carrying deletions: [UUID: [RecordKey: PendingDeletion]], as updated: AccountRecord)
        async throws
    {
        guard let base = syncSettings?.state, let syncState else { return }
        for pending in deletions.values {
            for deletion in pending.values where deletion.stamp.version < .max {
                try await syncState.addPendingDeletion(
                    PendingDeletion(
                        stamp: RecordStamp(
                            version: deletion.stamp.version + 1, device: updated.deviceID, deleted: true),
                        record: deletion.record))
            }
        }
        for vaultID in try await vaultDirectory(updated).keys {
            try await base.saveState(SyncState(vaultID: vaultID))
        }
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
        return !(try await registry(account)).state.pendingCredentials.isEmpty
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
    public func approveDevice(id: UUID, key: DevicePublicKey, name: String) async throws {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
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
    /// registers itself with the enrolment key, which the password and Secret Key yield.
    public func enrol(
        password: String, secretKey: String, accountID: UUID? = nil, as identity: DeviceIdentity? = nil
    ) async throws {
        if let identity, let accountID = accountID ?? EmergencyKit.parseSetupCode(secretKey)?.accountID {
            guard try await deviceKeys.publicKey(accountID: accountID, deviceID: identity.id) == identity.key else {
                throw VaultError.enrolmentUnavailable
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
        let id = UUID.random(using: &random)
        return DeviceIdentity(id: id, key: try await deviceKeys.create(accountID: accountID, deviceID: id))
    }

    /// As `enrol`, with the new device's ID chosen by the caller: for tests that need to name the device.
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
        for candidate in names.prefix(Self.maximumHeadersConsidered)
        where derivations < Self.maximumHeaderAttempts {
            // A header that is not what its name says, or whose KDF parameters are out of bounds, costs a fetch and
            // nothing more; only one that parses is worth a derivation, and only a few of those are tried.
            guard
                let bytes = try? await transport.fetch(
                    candidate.name, maximumLength: AccountHeaderObject.maximumLength),
                let header = try? AccountHeaderObject.parse(bytes), header.accountID == accountID,
                header.generation == candidate.generation, header.author == candidate.author
            else { continue }
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
        let deviceID: UUID
        if let assigningDeviceID {
            deviceID = assigningDeviceID
        } else {
            deviceID = UUID.random(using: &random)
        }
        var account = AccountRecord(
            accountID: accountID, deviceID: deviceID, personalVaultID: opened.personal,
            personalVaultKeyID: Self.zeroUUID, kdf: header.kdf, salt: header.salt, unlockKeyID: header.unlockKeyID,
            wrappedKeyset: header.wrappedKeyset, keysetVersion: header.keysetVersion,
            credentialGeneration: header.generation, createdAt: now, emergencyKitConfirmedAt: now)
        let deviceKey: DevicePublicKey
        if let prepared = try await deviceKeys.publicKey(accountID: accountID, deviceID: deviceID) {
            deviceKey = prepared
        } else {
            deviceKey = try await deviceKeys.create(accountID: accountID, deviceID: deviceID)
        }
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
        install(newKeys, at: now)
        try? await refreshSigningKey(account: account, keys: newKeys)
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
                } catch SyncTransportError.unavailable {
                    throw SyncTransportError.unavailable
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
        deletedVaults: Set<UUID>, personalVaultID: UUID, report: inout AccountObjectsReport
    ) async throws -> (keys: [StoredRecord], deletions: [StoredRecord], listed: Set<String>) {
        var keys: [UUID: StoredRecord] = [:]
        var deletions: [UUID: StoredRecord] = [:]
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
                    _ = try Envelope.parse(
                        object.envelope,
                        expecting: VaultKey.wrapContext(vaultID: vaultID, keyID: keyID, keysetKeyID: header.keyID),
                        maximumLength: 1024)
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
                default:
                    break
                }
            } catch SyncTransportError.unavailable {
                throw SyncTransportError.unavailable
            } catch SyncKeyringError.locked {
                throw SyncKeyringError.locked
            } catch {
                report.rejected.append(name)
            }
        }
        return (Array(keys.values), Array(deletions.values), listed)
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
        if let anchor = await readAnchor(accountID) {
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
                view.state.standing(of: account.deviceID) == .active
            {
                report.headerPublished = try await create(name, contents: stored.row.envelope, on: transport)
            }
        }

        // Candidates: only headers whose credential entry the registry already holds as pending or forked are
        // fetched at all, so a store full of planted headers costs nothing.
        let wanted = view.state.pendingCredentials + view.state.forkedCredentials
        let rows = try await store.records(in: accountID, kind: .accountHeader).filter { $0.recordID != accountID }
        var held: Set<ObjectDigest> = []
        var stale: [RecordKey] = []
        for row in rows {
            if let header = try? AccountHeaderObject.parse(row.envelope),
                Self.isCandidate(header, account: account, view: view)
            {
                held.insert(header.credentialID)
            } else {
                stale.append(row.key)
            }
        }
        if !stale.isEmpty { try await store.commit(StoreChange(deletions: stale)) }
        for credential in wanted where !held.contains(credential.id) {
            let name = AccountObjectLocation.header(
                accountID: accountID, generation: credential.generation, author: credential.author
            ).name
            guard listed.contains(name),
                let bytes = try? await transport.fetch(name, maximumLength: AccountHeaderObject.maximumLength),
                let header = try? AccountHeaderObject.parse(bytes), header.credentialID == credential.id,
                Self.isCandidate(header, account: account, view: view)
            else { continue }
            let row = Self.headerRow(
                header, recordID: Self.uuid(Array(ObjectDigest(hashing: bytes).bytes[..<16])), version: 1)
            if try await store.record(row.key) == nil {
                try await store.commit(StoreChange(upserts: [row]))
                report.candidateHeadersFetched += 1
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
        let fetched = try await fetchDirectory(
            transport: transport, accountID: accountID, view: view, keyset: keys?.keyset, knownKeys: knownKeys,
            deletedVaults: deleted, personalVaultID: account.personalVaultID, report: &report)

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
            if let existing = try await store.record(deletion.key) { deletion.version = existing.version + 1 }
            change.upserts.append(deletion)
            report.vaultDeletionsFetched += 1
        }
        if !change.upserts.isEmpty { try await store.commit(change) }
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
