import Foundation
import SecureMemory
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordMatching
import WatchwordModel
import WatchwordStore
import WatchwordSync

/// A vault as the person sees it (PRD F2.1).
public struct VaultInfo: Sendable, Hashable, Identifiable {
    public static let defaultPersonalName = "Personal"

    public var id: UUID
    /// Empty if the vault's description has not arrived yet, or cannot be read.
    public var name: String
    public var createdAt: Date?
    /// The vault every account has: it can be neither deleted nor shared.
    public var isPersonal: Bool
    /// Deleted, here or on another device. Listed only on request, for what the deletion left in it.
    public var isDeleted: Bool
    /// The vault is shared (governed by a membership chain) and this device holds no verified ledger for it: its
    /// account's other device shared or joined it, or the saved ledger no longer loads. Held closed here until this
    /// device accepts the vault's invitation itself: readable, but nothing is written, sealed, published or deleted
    /// (docs/02-architecture.md §8.10; review finding Z41).
    public var isSharedUnavailable = false
    /// Accounts other than this one read this vault, and those who may write there can add and change its items: it
    /// is governed by a membership chain, as far as anything this device holds says so (`isMarkedShared`; true of an
    /// unavailable vault too, and of every vault but the Personal one until the account's markers are read). The one
    /// fact AutoFill reads to tell a vault of the person's own from one a member writes (review finding Z60).
    public var isShared = false
}

/// A vault's own description, sealed under the vault key as a `.vaultMetadata` record whose record ID is the vault's
/// (docs/02-architecture.md §5, §7.7). A vault's name is as private as an item's title.
///
/// It merges as a last-writer-wins register on (version, device): a name is one short value, and of two renames made
/// at once one is kept. Nothing else about a vault lives here — which vaults exist, and their keys, are the vault
/// directory's.
public struct VaultMetadata: Codable, Hashable, Sendable {
    public var vaultID: UUID
    public var name: String
    public var createdAt: Date
    public var modifiedAt: Date
    /// Lamport version, bound into the record's authenticated data. Assigned by the vault.
    public var version: UInt64
    /// The write that chose this description, when the row was sealed again rather than written (a rotation's
    /// re-seal, a password change, the merge of two copies at one version); `nil` means the row's own version and
    /// device. A shared vault's judge attributes the description to it (review finding S37).
    public var writtenBy: Revision? = nil
}

public enum VaultMetadataCodec {
    public static let schemaVersion: UInt64 = 1
    public static let maximumPayloadLength = 16 << 10
    public static let maximumNameLength = 256

    public static func encode(_ metadata: VaultMetadata) throws -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .secondsSince1970
        let data = try encoder.encode(metadata)
        guard data.count <= maximumPayloadLength else { throw ItemCodecError.payloadTooLarge(data.count) }
        return Array(data)
    }

    /// Decodes a payload that a holder of the vault key wrote — from milestone 4 any member — so it is still hostile:
    /// a size cap before decoding and a bounded name after.
    public static func decode(_ bytes: [UInt8]) throws -> VaultMetadata {
        guard bytes.count <= maximumPayloadLength else { throw ItemCodecError.payloadTooLarge(bytes.count) }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        guard let metadata = try? decoder.decode(VaultMetadata.self, from: Data(bytes)),
            metadata.name.count <= maximumNameLength
        else { throw ItemCodecError.malformedPayload }
        return metadata
    }
}

/// Search over decrypted items, in memory only (PRD F2.3): nothing here is ever written anywhere.
public enum ItemSearch {
    /// Case, diacritics and width folded, so "Cafe" finds "café" and "ＡＢＣ" finds "abc".
    public static func normalize(_ text: String) -> String {
        text.folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: nil)
    }

    /// The words of a query. Every one of them must be found for an item to match.
    public static func tokens(_ query: String) -> [String] {
        normalize(query).split(whereSeparator: \.isWhitespace).map(String.init)
    }

    /// How well `item` matches, lower being better, or `nil` if some word is found nowhere. A word found in the title
    /// counts 0, in a scope's host or a username or email 1, in a tag 2, in the notes 3. Secret field values are
    /// never searched: a search box is on screen, and what is typed into it should not confirm a password.
    public static func score(_ item: Item, tokens: [String]) -> Int? {
        guard !tokens.isEmpty else { return nil }
        let fields: [(Int, [String])] = [
            (0, [item.title]),
            (1, item.scopes.map(\.host) + item.loginNames),
            (2, Array(item.tags)),
            (3, [item.notes]),
        ]
        let haystacks = fields.map { ($0.0, $0.1.map(normalize)) }
        var total = 0
        for token in tokens {
            guard let best = haystacks.first(where: { $0.1.contains { $0.contains(token) } }) else { return nil }
            total += best.0
        }
        return total
    }
}

// Vaults (PRD F2.1–F2.3; docs/02-architecture.md §7.7).
extension VaultSession {
    /// A vault in the local directory.
    struct DirectoryEntry: Sendable {
        var isDeleted: Bool
    }

    // MARK: - The vault directory

    /// The local index row of a vault, under the account's own ID where a vault's would be: `0x01` for a vault that
    /// exists, or `0x02` and the signed statement that it was deleted. Nothing is ever inferred from a missing row.
    static func directoryRow(vaultID: UUID, accountID: UUID, deviceID: UUID, deletion: SignedObject? = nil)
        -> StoredRecord
    {
        StoredRecord(
            recordID: vaultID, kind: .vaultDirectory, vaultID: accountID, keyID: zeroUUID,
            version: deletion == nil ? 1 : 2, deviceID: deviceID,
            envelope: deletion.map { [0x02] + $0.serialized() } ?? [0x01])
    }

    /// Every vault this device knows of. A vault counts as deleted only if its row carries a deletion signed by the
    /// account key and a registered device for exactly this vault: a row edited in the file (A8) deletes nothing,
    /// and the Personal vault is never deleted, whatever a row says.
    func vaultDirectory(_ account: AccountRecord) async throws -> [UUID: DirectoryEntry] {
        var result: [UUID: DirectoryEntry] = [account.personalVaultID: DirectoryEntry(isDeleted: false)]
        let rows = try await store.records(in: account.accountID, kind: .vaultDirectory)
        guard !rows.isEmpty else { return result }
        let view = try? await registry(account)
        // A shared marker's row is a fact about a vault, not a vault (VaultSession+SharedMarker.swift).
        for row in rows where row.recordID != account.personalVaultID && row.envelope.first != Self.sharedMarkerTag {
            let isDeleted = view.map { Self.isVerifiedDeletion(row, accountID: account.accountID, view: $0) } ?? false
            result[row.recordID] = DirectoryEntry(isDeleted: isDeleted)
        }
        return result
    }

    /// Whether a directory row carries a deletion of its vault signed by the account key and by the row's device,
    /// which the registry holds as registered and not revoked.
    static func isVerifiedDeletion(_ row: StoredRecord, accountID: UUID, view: RegistryView) -> Bool {
        guard row.kind == .vaultDirectory, row.vaultID == accountID, row.envelope.first == 0x02,
            let object = try? SignedObject.parse(Array(row.envelope.dropFirst())),
            object.envelope == Self.deletionMarker
        else { return false }
        let name = AccountObjectLocation.vaultDeletion(
            accountID: accountID, vaultID: row.recordID, author: row.deviceID
        )
        .name
        return
            (try? Self.verifyDual(
                object.signature, over: Self.directoryMessage(name: name, body: object.envelope),
                domain: .vaultDirectory, author: row.deviceID, view: view)) != nil
    }

    /// Makes every vault deletion this device holds and has verified its own: the local row is replaced by the same
    /// deletion signed by the account key and this device (docs/02-architecture.md §7.7). The row a deletion
    /// arrives in names the device that made it, and a deletion counts only while its signer is registered; once
    /// this device has checked it, its standing must not depend on that device any more, or revoking the device
    /// that deleted a vault would bring the vault back here. Needs the vault unlocked and this device registered;
    /// until then a deletion seen only while locked rests on its author's signature, and on the copies other
    /// devices vouched for on the transport.
    func adoptVerifiedDeletions(account: AccountRecord) async throws {
        let epoch = lockEpoch
        guard keys != nil, let view = try? await registry(account),
            view.state.standing(of: account.deviceID) == .active, view.state.pendingCredentials.isEmpty
        else { return }
        var change = StoreChange()
        for row in try await store.records(in: account.accountID, kind: .vaultDirectory)
        where row.recordID != account.personalVaultID && row.deviceID != account.deviceID && row.version < .max
            && Self.isVerifiedDeletion(row, accountID: account.accountID, view: view)
        {
            let name = AccountObjectLocation.vaultDeletion(
                accountID: account.accountID, vaultID: row.recordID, author: account.deviceID
            ).name
            let signature = try await dualSignature(
                Self.directoryMessage(name: name, body: Self.deletionMarker), domain: .vaultDirectory,
                keys: try requireKeys(since: epoch), account: account)
            var own = Self.directoryRow(
                vaultID: row.recordID, accountID: account.accountID, deviceID: account.deviceID,
                deletion: SignedObject(signature: signature, envelope: Self.deletionMarker))
            own.version = row.version + 1
            change.upserts.append(own)
            change.expectations[own.key] = .version(row.version)
        }
        guard !change.upserts.isEmpty else { return }
        _ = try requireKeys(since: epoch)
        try await store.commit(change)
    }

    /// The key new records of a vault are sealed under.
    ///
    /// This is the one place a vault's current key is chosen, and so where key rotation and a key received through a
    /// member's grant plug in (milestone 4): a grant, once opened, is stored wrapped under this account's own keyset
    /// like any other vault key, and the membership record's key ID replaces the rule below. Until then a vault has
    /// one key; if the directory ever holds several, every device picks the same one.
    static func currentKeyID(for vaultID: UUID, among keys: [VaultKey], personal: AccountRecord?) -> UUID? {
        let candidates = keys.filter { $0.vaultID == vaultID }.map(\.key.keyID)
        if let personal, personal.personalVaultID == vaultID, candidates.contains(personal.personalVaultKeyID) {
            return personal.personalVaultKeyID
        }
        return candidates.min { $0.uuidString < $1.uuidString }
    }

    func currentVaultKey(_ vaultID: UUID, keys: UnlockedKeys, account: AccountRecord) -> VaultKey? {
        // A shared vault's key is the one its membership chain names (VaultSession+Sharing.swift).
        // A shared vault with no ledger here has none (Z41).
        if let shared = sharedCurrentKey(vaultID, keys: keys, personalVaultID: account.personalVaultID) {
            return shared
        }
        return Self.currentKeyID(for: vaultID, among: Array(keys.vaultKeys.values), personal: account).flatMap {
            keys.vaultKeys[$0]
        }
    }

    /// The key to seal a new record of `vaultID` under, for a write the person makes: the vault must be one of the
    /// account's, with a key this device holds, and not deleted (unless the write is one a deleted vault still
    /// allows: settling what the deletion left behind).
    func writableVaultKey(_ vaultID: UUID, keys: UnlockedKeys, account: AccountRecord, allowingDeleted: Bool = false)
        async throws -> VaultKey
    {
        // A shared vault adds the member's role to this check (PRD F4.5).
        try await checkSharedWrite(vaultID, account: account)
        if vaultID != account.personalVaultID {
            guard let entry = try await vaultDirectory(account)[vaultID] else {
                throw VaultError.unknownVault(vaultID)
            }
            if entry.isDeleted, !allowingDeleted { throw VaultError.vaultDeleted(vaultID) }
        }
        guard let vaultKey = currentVaultKey(vaultID, keys: keys, account: account) else {
            throw VaultError.unknownVault(vaultID)
        }
        return vaultKey
    }

    /// Opens vault keys that arrived since unlock (a vault created on another device), without disturbing the keys
    /// already resident.
    func adoptNewVaultKeys(account: AccountRecord) async throws {
        guard keys != nil else { return }
        let epoch = lockEpoch
        var wraps: [StoredRecord] = []
        for vaultID in try await vaultDirectory(account).keys {
            wraps += try await store.records(in: vaultID, kind: .vaultKeyWrap)
        }
        guard epoch == lockEpoch, let keys else { return }
        var vaultKeys = keys.vaultKeys
        for row in wraps where vaultKeys[row.recordID] == nil {
            // Identity from the row, never from the wrap (§4); a wrap that does not open is skipped.
            if let key = try? VaultKey.unwrap(
                row.envelope, vaultID: row.vaultID, keyID: row.recordID, with: keys.keyset)
            {
                vaultKeys[row.recordID] = key
            }
        }
        if vaultKeys.count != keys.vaultKeys.count {
            self.keys = UnlockedKeys(
                accountUnlockKey: keys.accountUnlockKey, keyset: keys.keyset, vaultKeys: vaultKeys)
        }
    }

    // MARK: - Vault metadata

    static func metadataContext(_ row: StoredRecord) -> EnvelopeContext {
        EnvelopeContext(
            recordID: row.recordID, vaultID: row.vaultID, schemaVersion: VaultMetadataCodec.schemaVersion,
            kind: .vaultMetadata, keyID: row.keyID, recordVersion: row.version)
    }

    /// Opens a vault's description. As for items, the context comes from the row, and what the plaintext says of
    /// itself must equal the row.
    func openMetadata(_ row: StoredRecord, keys: UnlockedKeys) throws -> VaultMetadata {
        guard row.kind == .vaultMetadata, row.recordID == row.vaultID, let vaultKey = keys.vaultKeys[row.keyID],
            vaultKey.vaultID == row.vaultID
        else { throw VaultError.unknownVault(row.vaultID) }
        let plaintext = try RecordCipher.open(
            row.envelope, context: Self.metadataContext(row), key: vaultKey.key,
            maximumLength: VaultMetadataCodec.maximumPayloadLength + 4096)
        defer { plaintext.zeroise() }
        // A vault's name: private, but not key material.
        let metadata = try VaultMetadataCodec.decode(plaintext.unprotectedCopy())
        guard metadata.vaultID == row.vaultID, metadata.version == row.version else {
            throw VaultError.recordMismatch(row.recordID)
        }
        highestVersionSeen[row.vaultID] = max(highestVersionSeen[row.vaultID] ?? 0, row.version)
        return metadata
    }

    func sealMetadata(_ metadata: VaultMetadata, vaultKey: VaultKey, account: AccountRecord) throws -> StoredRecord {
        var row = StoredRecord(
            recordID: metadata.vaultID, kind: .vaultMetadata, vaultID: metadata.vaultID, keyID: vaultKey.key.keyID,
            version: metadata.version, deviceID: account.deviceID, envelope: [])
        row.envelope = try RecordCipher.seal(
            try VaultMetadataCodec.encode(metadata), context: Self.metadataContext(row), key: vaultKey.key,
            using: &random)
        highestVersionSeen[metadata.vaultID] = max(highestVersionSeen[metadata.vaultID] ?? 0, metadata.version)
        return row
    }

    private static func validatedName(_ name: String) throws -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= VaultMetadataCodec.maximumNameLength else {
            throw VaultError.invalidVaultName
        }
        return trimmed
    }

    // MARK: - Vaults (PRD F2.1)

    /// The account's vaults, the Personal vault first, then by name. A deleted vault is listed only on request.
    public func vaults(includingDeleted: Bool = false) async throws -> [VaultInfo] {
        let epoch = lockEpoch
        _ = try requireKeys()
        await loadSharedVaultsIfNeeded()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let directory = try await vaultDirectory(account)
        var rows: [UUID: StoredRecord] = [:]
        for vaultID in directory.keys {
            rows[vaultID] = try await store.record(RecordKey(recordID: vaultID, kind: .vaultMetadata))
        }
        var leftovers: Set<UUID> = []
        for vaultID in directory.keys where membershipEnded(vaultID, account: account) {
            if !(try await store.records(in: vaultID, kind: .item)).isEmpty { leftovers.insert(vaultID) }
        }
        let keys = try requireKeys(since: epoch)
        var result: [VaultInfo] = []
        for (vaultID, entry) in directory where includingDeleted || !entry.isDeleted {
            // A vault whose key this device does not hold (yet) is not one it can show. A shared vault with no
            // ledger here is shown, as shared and unavailable, if it holds any key for it: never hidden, and never
            // shown as one of the account's own (Z41).
            let unavailable =
                isSharedUnavailable(vaultID, keys: keys, personalVaultID: account.personalVaultID)
                && keys.vaultKeys.values.contains { $0.vaultID == vaultID }
            // A shared vault this account is no longer a member of has no current key here once the key was
            // rotated. It is still listed while this device holds items of it, so that they are shown as what they
            // are (`SharedVaultStatus.role` is `nil`) and can be removed (Z45).
            let ended = membershipEnded(vaultID, account: account) && leftovers.contains(vaultID)
            guard unavailable || ended || currentVaultKey(vaultID, keys: keys, account: account) != nil else {
                continue
            }
            let isPersonal = vaultID == account.personalVaultID
            let metadata = rows[vaultID].flatMap { try? openMetadata($0, keys: keys) }
            result.append(
                VaultInfo(
                    id: vaultID, name: metadata?.name ?? (isPersonal ? VaultInfo.defaultPersonalName : ""),
                    createdAt: metadata?.createdAt ?? (isPersonal ? account.createdAt : nil), isPersonal: isPersonal,
                    isDeleted: entry.isDeleted, isSharedUnavailable: unavailable,
                    isShared: isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID)))
        }
        return result.sorted {
            if $0.isPersonal != $1.isPersonal { return $0.isPersonal }
            let order = $0.name.localizedStandardCompare($1.name)
            return order == .orderedSame ? $0.id.uuidString < $1.id.uuidString : order == .orderedAscending
        }
    }

    /// Creates a vault the account owns: a fresh 256-bit key wrapped under the keyset, the directory row, and the
    /// vault's description, in one commit. Other devices learn of it from the vault directory at their next sync.
    @discardableResult
    public func createVault(name: String) async throws -> VaultInfo {
        let name = try Self.validatedName(name)
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let now = await clock.now()
        let keys = try requireKeys(since: epoch)

        let vaultID = UUID.random(using: &random)
        let vaultKey = VaultKey.generate(vaultID: vaultID, using: &random)
        let wrap = StoredRecord(
            recordID: vaultKey.key.keyID, kind: .vaultKeyWrap, vaultID: vaultID,
            keyID: keys.keyset.symmetricKey.keyID, version: 1, deviceID: account.deviceID,
            envelope: try vaultKey.wrap(for: keys.keyset, using: &random))
        let metadata = try sealMetadata(
            VaultMetadata(vaultID: vaultID, name: name, createdAt: now, modifiedAt: now, version: 1),
            vaultKey: vaultKey, account: account)
        let index = Self.directoryRow(vaultID: vaultID, accountID: account.accountID, deviceID: account.deviceID)
        var change = StoreChange(upserts: [wrap, index, metadata])
        for row in change.upserts { change.expectations[row.key] = .absent }
        do {
            try await store.commit(change)
        } catch {
            vaultKey.zeroise()
            throw error
        }
        guard epoch == lockEpoch, let current = self.keys else {
            vaultKey.zeroise()
            throw VaultError.locked
        }
        var vaultKeys = current.vaultKeys
        vaultKeys[vaultKey.key.keyID] = vaultKey
        self.keys = UnlockedKeys(
            accountUnlockKey: current.accountUnlockKey, keyset: current.keyset, vaultKeys: vaultKeys)
        return VaultInfo(id: vaultID, name: name, createdAt: now, isPersonal: false, isDeleted: false)
    }

    /// Renames a vault. The Personal vault can be renamed too; it cannot be deleted.
    @discardableResult
    public func renameVault(id: UUID, to name: String) async throws -> VaultInfo {
        let name = try Self.validatedName(name)
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let now = await clock.now()
        let existing = try await store.record(RecordKey(recordID: id, kind: .vaultMetadata))
        let keys = try requireKeys(since: epoch)
        let vaultKey = try await writableVaultKey(id, keys: keys, account: account)
        _ = try requireKeys(since: epoch)
        let previous = existing.flatMap { try? openMetadata($0, keys: keys) }
        let revision = try nextRevision(in: id, above: existing, account: account)
        let metadata = VaultMetadata(
            vaultID: id, name: name,
            createdAt: previous?.createdAt ?? (id == account.personalVaultID ? account.createdAt : now),
            modifiedAt: max(now, previous?.modifiedAt ?? now), version: revision.version)
        let row = try sealMetadata(metadata, vaultKey: vaultKey, account: account)
        var change = StoreChange(upserts: [row])
        change.expectations[row.key] = existing.map { .version($0.version) } ?? .absent
        try await store.commit(change)
        return VaultInfo(
            id: id, name: name, createdAt: metadata.createdAt, isPersonal: id == account.personalVaultID,
            isDeleted: false)
    }

    /// The number of items a vault holds, trashed ones included: what the person must be shown, and must confirm,
    /// before the vault is deleted.
    public func itemCount(in vaultID: UUID) async throws -> Int {
        _ = try requireKeys()
        return try await store.records(in: vaultID, kind: .item).count
    }

    /// Deletes a vault and every item in it, which the caller confirms by naming how many items that is
    /// (`itemCount(in:)`, shown to the person): if anything arrived in between, the count is wrong and nothing is
    /// deleted. The Personal vault cannot be deleted.
    ///
    /// As with an item, the deletion is explicit and signed, never inferred from absence: the vault's directory row
    /// becomes a deletion signed by the account key and this device, and every item is deleted through the same path
    /// as a permanent deletion, each tombstone carrying what this device had seen of the item. On another device an
    /// item, or an edit, that this device had not seen is therefore kept (PRD F7.6, F7.7): it stays in the deleted
    /// vault, shown in the trash as kept after a deletion, from where the person can move it to another vault or
    /// delete it. The vault's key is kept, so that what arrives later can still be read.
    public func deleteVault(id: UUID, confirmingItemCount: Int) async throws {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        guard id != account.personalVaultID else { throw VaultError.cannotDeletePersonalVault }
        guard let entry = try await vaultDirectory(account)[id] else { throw VaultError.unknownVault(id) }
        guard !entry.isDeleted else { return }
        let rows = try await store.records(in: id, kind: .item)
        guard rows.count == confirmingItemCount else {
            throw VaultError.vaultDeletionNotConfirmed(itemCount: rows.count)
        }
        // A shared vault is deleted by its owner, in its membership chain too (VaultSession+Sharing.swift).
        try await checkSharedDeletion(id, account: account)
        let name = AccountObjectLocation.vaultDeletion(
            accountID: account.accountID, vaultID: id, author: account.deviceID
        ).name
        let signature = try await dualSignature(
            Self.directoryMessage(name: name, body: Self.deletionMarker), domain: .vaultDirectory,
            keys: try requireKeys(since: epoch), account: account)
        _ = try requireKeys(since: epoch)
        let existing = try await store.record(RecordKey(recordID: id, kind: .vaultDirectory))
        var tombstone = Self.directoryRow(
            vaultID: id, accountID: account.accountID, deviceID: account.deviceID,
            deletion: SignedObject(signature: signature, envelope: Self.deletionMarker))
        tombstone.version = max(tombstone.version, try Self.version(replacing: existing))
        // Conditional on every version just counted, so an edit that lands in between fails the whole deletion.
        // The items' synced scan results go with them (§13.9).
        let scanStatus = try await store.records(in: id, kind: .scanStatus).map(\.key)
        try await writer(for: account).commit(
            StoreChange(
                upserts: [tombstone], deletions: scanStatus,
                conditionalDeletions: Dictionary(uniqueKeysWithValues: rows.map { ($0.key, $0.version) })))
    }

    /// An item as the person sees it. Whatever a vault's deletion left in it — an item, or an edit, its author had
    /// not seen — is in the trash, kept after a deletion: shown that way, never written that way. A write here would
    /// be an edit of this device's own, one per device, which the next deletion or move made elsewhere would not
    /// have seen and so would have to keep (found by the vault simulation). Derived from the directory, it is the
    /// same on every device, and the person's next deletion removes exactly what they were shown.
    static func presented(_ item: Item, inDeletedVault: Bool) -> Item {
        guard inDeletedVault else { return item }
        var item = item
        if item.trashedAt == nil { item.trashedAt = item.modifiedAt }
        item.keptAfterDeletion = true
        return item
    }

    // MARK: - Items across vaults (PRD F2.2, F2.3)

    /// The items of one vault, trashed and archived ones included.
    public func items(in vaultID: UUID) async throws -> ItemListing {
        try await items(inVaults: [vaultID])
    }

    func items(inVaults vaultIDs: [UUID]) async throws -> ItemListing {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let deleted = Set(try await vaultDirectory(account).filter { $0.value.isDeleted }.keys)
        var rows: [StoredRecord] = []
        for vaultID in vaultIDs {
            rows += try await store.records(in: vaultID, kind: .item)
        }
        let keys = try requireKeys(since: epoch)
        var listing = ItemListing(items: [], unreadable: [])
        for row in rows {
            do {
                listing.items.append(
                    Self.presented(try openItem(row, keys: keys), inDeletedVault: deleted.contains(row.vaultID)))
            } catch {
                listing.unreadable.append(row.recordID)
            }
        }
        listing.items.sort {
            let order = $0.title.localizedStandardCompare($1.title)
            return order == .orderedSame ? $0.id.uuidString < $1.id.uuidString : order == .orderedAscending
        }
        return listing
    }

    /// Copies an item into another vault of the account, as a new item with its own ID. The original is untouched.
    @discardableResult
    public func copy(itemID: UUID, to vaultID: UUID) async throws -> Item {
        try await transfer(itemID: itemID, to: vaultID, removingOriginal: false)
    }

    /// Moves an item to another vault of the account (PRD F2.2).
    ///
    /// A move is a copy under a new ID in the destination and the original put in the trash, **in one commit**: an
    /// interruption leaves either nothing changed or the item in its new vault, never neither and never a move that
    /// only seems to have happened. The original is then deleted for good, as `deletePermanently` would; if that
    /// last step does not happen, it is still in the trash of the vault it came from, where the 30-day purge
    /// finds it.
    ///
    /// Other devices see the same thing, because nothing here is special to sync: a new item in one vault, and in
    /// the other an item trashed and then deleted. An edit made elsewhere that this device had not seen is not lost
    /// with the original (PRD F7.6): the deletion removes only what its author had seen, so the edited original
    /// stays, in the trash, for the person to find. The new ID is derived from the version moved, so two devices
    /// that move the same version to the same vault make one item, not two.
    ///
    /// An item holding values kept for the person to choose between is refused (`itemHasUnresolvedValues`): the copy
    /// would not carry them and the deletion would discard them, which only the person may do (F7.7).
    @discardableResult
    public func move(itemID: UUID, to vaultID: UUID) async throws -> Item {
        try await transfer(itemID: itemID, to: vaultID, removingOriginal: true)
    }

    private func transfer(itemID: UUID, to destination: UUID, removingOriginal: Bool) async throws -> Item {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let now = await clock.now()
        guard let originalRow = try await store.record(RecordKey(recordID: itemID, kind: .item)) else {
            throw VaultError.itemNotFound(itemID)
        }
        let directory = try await vaultDirectory(account)
        let keys = try requireKeys(since: epoch)
        let original = try openItem(originalRow, keys: keys)
        if removingOriginal, original.vaultID == destination { return original }
        let destinationKey = try await writableVaultKey(destination, keys: keys, account: account)
        // A move writes in the vault it takes the item out of too: the original is trashed, then deleted. That needs
        // this account's permission to write there as any write does (Z44), before anything is written anywhere. A
        // deleted vault's leftovers can still be moved out: that is how they are restored. A copy writes nothing in
        // the vault it reads from.
        let originalKey =
            removingOriginal
            ? try await writableVaultKey(original.vaultID, keys: keys, account: account, allowingDeleted: true) : nil
        _ = try requireKeys(since: epoch)
        for scope in original.scopes {
            do {
                try ScopePolicy.validate(scope)
            } catch let error as ScopeValidationError {
                throw VaultError.scopeRejected(error)
            }
        }

        var newID = UUID.random(using: &random)
        if removingOriginal {
            guard !original.hasConflicts, original.retainedValues.isEmpty else {
                throw VaultError.itemHasUnresolvedValues(itemID)
            }
            // From the trash only what a vault's deletion left behind can be moved: that is how it is restored.
            guard !original.isTrashed || directory[original.vaultID]?.isDeleted == true else {
                throw VaultError.itemIsTrashed(itemID)
            }
            newID = Self.movedItemID(of: originalRow, to: destination)
        }
        var created = Item(
            id: newID, vaultID: destination, title: original.title, scopes: original.scopes, fields: original.fields,
            tags: original.tags, notes: original.notes, createdAt: removingOriginal ? original.createdAt : now,
            modifiedAt: now, archived: original.archived, history: removingOriginal ? original.history : [],
            excludedFromSuggestions: original.excludedFromSuggestions)
        let revision = try nextRevision(in: destination, above: nil, account: account)
        created.version = revision.version
        created = ItemMerge.stamped(created, previous: nil, previousOrigin: nil, revision: revision)
        let createdRow = try sealItem(created, vaultKey: destinationKey, account: account)
        var change = StoreChange(upserts: [createdRow], expectations: [createdRow.key: .absent])

        var trashedRow: StoredRecord?
        if let originalKey {
            var trashed = original
            if trashed.trashedAt == nil || trashed.keptAfterDeletion { trashed.trashedAt = now }
            trashed.keptAfterDeletion = false
            trashed.modifiedAt = now
            let revision = try nextRevision(in: original.vaultID, above: originalRow, account: account)
            trashed.version = revision.version
            trashed = ItemMerge.stamped(
                trashed, previous: original, previousOrigin: Self.origin(originalRow), revision: revision)
            let row = try sealItem(trashed, vaultKey: originalKey, account: account)
            change.upserts.append(row)
            change.expectations[row.key] = .version(originalRow.version)
            trashedRow = row
        }
        try await writer(for: account).commit(change)
        highestVersionSeen[destination] = max(highestVersionSeen[destination] ?? 0, created.version)
        if let trashedRow {
            highestVersionSeen[trashedRow.vaultID] = max(
                highestVersionSeen[trashedRow.vaultID] ?? 0, trashedRow.version)
            // The move is done and committed. This completes it; if it fails, the original is in the trash.
            let scanStatus = (try? await scanStatusKeys(of: [trashedRow.recordID])) ?? []
            try? await writer(for: account).commit(
                StoreChange(deletions: scanStatus, conditionalDeletions: [trashedRow.key: trashedRow.version]))
        }
        return created
    }

    /// The ID an item takes when one version of it is moved to a vault: a function of the item, the version moved
    /// and the destination, so that devices moving the same version to the same place create the same item.
    static func movedItemID(of row: StoredRecord, to destination: UUID) -> UUID {
        var message = Array("WW-move-v1".utf8) + bytes(row.recordID) + bytes(destination) + bytes(row.deviceID)
        message += (0..<8).map { UInt8(truncatingIfNeeded: row.version >> (8 * $0)) }
        var id = Array(ObjectDigest(hashing: message).bytes[..<16])
        id[6] = (id[6] & 0x0F) | 0x80
        id[8] = (id[8] & 0x3F) | 0x80
        return uuid(id)
    }

    /// Searches titles, scope hosts, usernames and emails, tags and notes of the decrypted items, in memory only:
    /// nothing is indexed on disk (PRD F2.3). Every word of the query must be found; the best matches come first.
    /// Items in a deleted vault are never returned.
    public func search(_ query: String, in vaultID: UUID? = nil, includingTrashed: Bool = false) async throws
        -> [Item]
    {
        let tokens = ItemSearch.tokens(query)
        guard !tokens.isEmpty else { return [] }
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let active = try await vaultDirectory(account).filter { !$0.value.isDeleted }.map(\.key)
        let vaultIDs = vaultID.map { id in active.filter { $0 == id } } ?? active
        // `items(inVaults:)` is sorted by title; equal scores keep that order.
        let scored = try await items(inVaults: vaultIDs).items.enumerated().compactMap {
            position, item -> (score: Int, position: Int, item: Item)? in
            guard includingTrashed || !item.isTrashed, let score = ItemSearch.score(item, tokens: tokens) else {
                return nil
            }
            return (score, position, item)
        }
        return scored.sorted { ($0.score, $0.position) < ($1.score, $1.position) }.map(\.item)
    }
}
