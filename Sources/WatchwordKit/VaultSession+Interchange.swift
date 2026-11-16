import Foundation
import SecureMemory
import WatchwordCrypto
import WatchwordInterchange
import WatchwordMatching
import WatchwordModel
import WatchwordStore
import WatchwordSync

// Import, export and the encrypted Watchword archive through the session (docs/02-architecture.md §14.1, PRD F8.1–F8.5,
// F11.2). The parsers and exporters are `WatchwordInterchange`'s and the archive format is `WatchwordCrypto`'s; this
// file decides who may call them, with what proof, and how their results reach the vault.

/// The file formats an import reads. The CSV variant (1Password 8, 1Password 7, Apple Passwords) is read off the
/// header row and named in `ImportReport.format`.
public enum ImportFileFormat: String, Sendable, Hashable, CaseIterable {
    case passwordCSV
    case onePUX
    /// A CXF 1.0 document: a file, or the payload the OS Credential Exchange import hands the app.
    case credentialExchange
}

/// The plaintext formats an export writes (PRD F8.4).
public enum PlaintextExportFormat: Sendable, Hashable {
    /// Apple Passwords CSV. `.neutralise` (the default to offer) prefixes formula-like cells; `.preserve` is for a
    /// file going straight into another password manager (docs/02-architecture.md §14).
    case applePasswordsCSV(formulaPolicy: CSVWriter.FormulaPolicy)
    /// A `.1pux` archive for 1Password's importer. Every chosen vault's items go into one 1Password vault.
    case onePUX
    /// A CXF 1.0 document, for a file or the OS Credential Exchange export. The format requires the exporting
    /// app's relying-party identifier; the app passes its own (its associated domain).
    case credentialExchange(exporterRelyingPartyID: String)
}

/// Why an import or export through the session refused. Wrong passwords and passphrases are not here: they are
/// `CryptoError.authenticationFailed`, which cannot tell them from tampering.
public enum InterchangeSessionError: Error, Equatable, Sendable {
    /// The preview named is not the one the session holds: it was committed, discarded, replaced by a newer one, or
    /// dropped by `lock()`. Read the file again. From a preview call: `discardImport()` or a newer preview ran while
    /// this one was being read, and its drafts were dropped rather than kept.
    case noPendingImport
    /// An entry that duplicates an existing item has no decision: the person must choose skip, keep both or merge.
    case decisionRequired(importedID: UUID)
    /// A merge into an item the entry was not matched with, or a decision for an entry the preview does not hold.
    case unknownMatch(importedID: UUID)
    /// An archive passphrase shorter than `VaultConfiguration.minimumPasswordLength`.
    case passphraseTooShort(minimum: Int)
    /// The archive names another account. Opening it needs that account's Secret Key, from its Emergency Kit.
    case archiveFromAnotherAccount(UUID)
    case noVaultChosen
    /// `lock()` ran during a commit. The first `saved` entries were written; the rest were not, and the preview is
    /// gone with the lock.
    case importInterrupted(saved: Int)
}

/// What an import would do, for the person to review before anything is written. Holds no secret: the drafts stay
/// inside the session (and are dropped by `lock()`), and the values a merge would add come from `importAdditions`
/// while the duplicate screen shows them.
public struct ImportPreview: Sendable, Equatable {
    public var id: UUID
    public var vaultID: UUID
    /// Everything the file held that was skipped, degraded or kept in another form. Titles and URLs are private:
    /// never logged.
    public var report: ImportReport
    public var entries: [ImportPreviewEntry]
    /// Entries that duplicate items already in `vaultID`; each needs a decision before `commitImport`.
    public var matches: [DuplicateMatch]
    /// For an encrypted Watchword archive, its identifier and when it was made, as sealed: set only once the archive
    /// has opened, so they are the authenticated values (the manifest covers the header). The restore screen shows
    /// the date, so that an older archive put in place of the newest (A1 can replace files in the cloud drive, and
    /// every archive under the same passphrase and Secret Key opens) is seen for what it is. `nil` for other formats.
    public var archiveID: UUID?
    public var archiveCreatedAt: Date?
}

public struct ImportPreviewEntry: Sendable, Hashable, Identifiable {
    /// The draft's ID: the key of its `ImportDecision` and of `DuplicateMatch.importedID`.
    public var id: UUID
    public var title: String
    public var kind: ImportedKind
    public var state: ImportedState
    public var reference: ImportEntryReference
    public var hosts: [String]
    public var loginNames: [String]
}

/// The person's choice for one imported entry. Entries without a decision and without a match are added as new
/// items; an entry with a match must have one.
public struct ImportDecision: Sendable, Hashable {
    public var resolution: DuplicateResolution
    /// The existing item a merge goes into: one of the entry's matches.
    public var existingID: UUID?
    /// For a merge, the hosts and fields the person accepted one by one (`DuplicateMatch.newHosts`,
    /// `MergeAdditions.signInFields` and `urlFields`). Never pre-filled.
    public var choices: MergeChoices

    public static let skip = ImportDecision(resolution: .skip, existingID: nil, choices: .none)
    public static let keepBoth = ImportDecision(resolution: .keepBoth, existingID: nil, choices: .none)

    public static func merge(into existingID: UUID, accepting choices: MergeChoices = .none) -> ImportDecision {
        ImportDecision(resolution: .merge, existingID: existingID, choices: choices)
    }
}

public struct ImportFailure: Sendable, Equatable {
    public enum Reason: Sendable, Equatable {
        case vault(VaultError)
        /// The item as stored would exceed `ItemCodec.maximumPayloadLength`.
        case tooLarge
        /// The store refused the write for another reason (an existing item changed while it was being merged).
        case storeRefused
    }

    public var importedID: UUID
    public var reason: Reason
}

/// What a commit did, entry by entry.
public struct ImportOutcome: Sendable, Equatable {
    /// The IDs of the new items, as stored.
    public var created: [UUID] = []
    /// The existing items that took a merge.
    public var merged: [UUID] = []
    /// Imported entries the person chose to skip.
    public var skipped: [UUID] = []
    public var failed: [ImportFailure] = []

    public var saved: Int { created.count + merged.count }
}

/// A plaintext export: the file's bytes, what the format could not carry, and the items that could not be read.
public struct PlaintextExport: Sendable, Hashable {
    public var bytes: [UInt8]
    public var report: ExportReport
    /// Records in the chosen vaults that would not open, and so are not in the file. Show them with the report.
    public var unreadable: [UUID]
}

public struct ArchiveExport: Sendable, Hashable {
    public var bytes: [UInt8]
    public var itemCount: Int
    public var vaultCount: Int
    /// Records in the chosen vaults that would not open, and so are not in the archive.
    public var unreadable: [UUID]
}

/// The drafts of one import, between preview and commit. Session state; `lock()` drops it.
struct PendingImport: Sendable {
    let id: UUID
    let epoch: UInt64
    let vaultID: UUID
    let result: ImportResult
    let matches: [DuplicateMatch]
}

/// What an archive entry holds: the first byte of its plaintext.
enum ArchivePayload {
    static let vault: UInt8 = 1
    static let item: UInt8 = 2
    static let maximumVaultNameBytes = 1024
}

extension VaultSession {
    /// The standing warning the export screen shows before and while a plaintext export is made (PRD F8.4).
    public nonisolated static var plaintextExportWarning: String { InterchangeGuide.plaintextExportWarning.text }

    // MARK: - Import (PRD F8.1–F8.3)

    /// Reads an import file into drafts for `vaultID` and returns what an import would do. Writes nothing.
    ///
    /// The drafts, which hold every secret in the file, stay in the session until `commitImport`, `discardImport`,
    /// the next preview or `lock()`, whichever comes first; a `discardImport()` or newer preview while this one is
    /// still being read wins, and this one throws `noPendingImport`. The parse runs on the session and is bounded
    /// by `InterchangeLimits`.
    public func previewImport(
        _ bytes: [UInt8], format: ImportFileFormat, into vaultID: UUID, options: ImportOptions = ImportOptions()
    ) async throws -> ImportPreview {
        let epoch = lockEpoch
        let generation = beginImport()
        try await requireWritableVault(vaultID, since: epoch)
        let result: ImportResult
        switch format {
        case .passwordCSV:
            result = try PasswordCSV.importFile(bytes, into: vaultID, options: options, using: &random)
        case .onePUX:
            result = try OnePUX.importArchive(bytes, into: vaultID, options: options, using: &random)
        case .credentialExchange:
            result = try CredentialExchange.importDocument(bytes, into: vaultID, options: options, using: &random)
        }
        return try await stage(result, vaultID: vaultID, since: epoch, generation: generation)
    }

    /// Opens an encrypted Watchword archive and returns what importing its items into `vaultID` would do. Writes
    /// nothing. The archive is parsed and bounded before any key is derived, and its passphrase is combined with
    /// the Secret Key of the account that made it (ADR 0008): this account's own, from the Keychain, or, for an
    /// archive another account made (a restore into a new account), `secretKey` as printed on that account's
    /// Emergency Kit. A wrong passphrase, a wrong Secret Key and a tampered archive are all
    /// `CryptoError.authenticationFailed`. The preview carries the archive's authenticated creation time, for the
    /// restore screen to show.
    ///
    /// The derivation costs what the archive's header says (up to `KDFParameters.maximumIterations`, seconds on a
    /// phone) before anything in the file is authenticated, so it runs off the session's actor, with the decryption
    /// and decoding of the entries: a `lock()` meanwhile takes effect at once, and this call then throws `locked`.
    public func previewArchiveImport(
        _ bytes: [UInt8], passphrase: String, secretKey text: String? = nil, into vaultID: UUID,
        options: ImportOptions = ImportOptions()
    ) async throws -> ImportPreview {
        let epoch = lockEpoch
        let generation = beginImport()
        try await requireWritableVault(vaultID, since: epoch)
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        let archive = try AccountArchive.parse(bytes)
        let secretKey: SecretKey
        if let text {
            var keyText = text
            if let setup = EmergencyKit.parseSetupCode(text) {
                guard setup.accountID == archive.accountID else { throw VaultError.secretKeyForAnotherAccount }
                keyText = setup.secretKey
            }
            secretKey = try SecretKey(parsing: keyText)
        } else {
            guard archive.accountID == record.accountID else {
                throw InterchangeSessionError.archiveFromAnotherAccount(archive.accountID)
            }
            secretKey = try await storedSecretKey(accountID: record.accountID)
        }
        defer { secretKey.zeroise() }
        _ = try requireKeys(since: epoch)
        let entries = try await awayFromSession(since: epoch) {
            try Self.archivedEntries(of: archive, passphrase: passphrase, secretKey: secretKey)
        }
        let result = try ArchivedItems.importEntries(entries, into: vaultID, options: options, using: &random)
        return try await stage(
            result, vaultID: vaultID, since: epoch, generation: generation,
            archive: (archive.archiveID, archive.createdAt))
    }

    /// What merging the imported entry into the existing item would add, with every value in full, for the
    /// duplicate screen to show before the person accepts any of it. Nothing here is pre-selected or added.
    public func importAdditions(preview: UUID, importedID: UUID, existingID: UUID) async throws -> MergeAdditions {
        let pending = try currentImport(preview)
        guard pending.matches.contains(where: { $0.importedID == importedID && $0.existingID == existingID }),
            let imported = pending.result.entries.first(where: { $0.item.id == importedID })?.item
        else { throw InterchangeSessionError.unknownMatch(importedID: importedID) }
        let existing = try await item(id: existingID)
        _ = try requireKeys(since: pending.epoch)
        return DuplicateDetector.additions(of: imported, to: existing)
    }

    /// Drops the preview without writing anything, and any preview still being read: it throws `noPendingImport`
    /// instead of keeping its drafts.
    public func discardImport() {
        importGeneration &+= 1
        pendingImport = nil
    }

    /// Writes the preview's entries as the person decided, each through the vault's own write path: a new item is
    /// stamped by `ItemMerge.stamped` as this device's write, checked against `ScopePolicy` and committed on the
    /// condition that no row has its ID, keeping the history and the creation and modification times the file
    /// gave it and none of its sync metadata; a merge is an edit of the existing item (`DuplicateDetector.merged`
    /// over the item as it is now, with only the hosts and fields in `MergeChoices`). An entry the source had in its
    /// trash is saved and then moved to the trash.
    ///
    /// Every decision is checked before anything is written. The preview is consumed whatever happens.
    public func commitImport(_ preview: UUID, decisions: [UUID: ImportDecision]) async throws -> ImportOutcome {
        let pending = try currentImport(preview)
        var matched: [UUID: Set<UUID>] = [:]
        for match in pending.matches {
            matched[match.importedID, default: []].insert(match.existingID)
        }
        let importedIDs = Set(pending.result.entries.map(\.item.id))
        for (importedID, decision) in decisions {
            guard importedIDs.contains(importedID) else {
                throw InterchangeSessionError.unknownMatch(importedID: importedID)
            }
            if decision.resolution == .merge {
                guard let existingID = decision.existingID, matched[importedID]?.contains(existingID) == true else {
                    throw InterchangeSessionError.unknownMatch(importedID: importedID)
                }
            }
        }
        for importedID in matched.keys where decisions[importedID] == nil {
            throw InterchangeSessionError.decisionRequired(importedID: importedID)
        }
        pendingImport = nil

        var outcome = ImportOutcome()
        for entry in pending.result.entries {
            let importedID = entry.item.id
            let decision = decisions[importedID] ?? .keepBoth
            do {
                switch decision.resolution {
                case .skip:
                    outcome.skipped.append(importedID)
                case .keepBoth:
                    let created = try await createImported(entry.item, in: pending.vaultID, since: pending.epoch)
                    outcome.created.append(created)
                    // Saved even if this fails; the failure is listed beside it.
                    if entry.state == .trashed { try await trash(id: created) }
                case .merge:
                    // Checked above.
                    guard let existingID = decision.existingID else { continue }
                    try await mergeImported(
                        entry.item, into: existingID, accepting: decision.choices, since: pending.epoch)
                    outcome.merged.append(existingID)
                }
            } catch VaultError.locked {
                throw InterchangeSessionError.importInterrupted(saved: outcome.saved)
            } catch let error as VaultError {
                outcome.failed.append(ImportFailure(importedID: importedID, reason: .vault(error)))
            } catch ItemCodecError.payloadTooLarge {
                outcome.failed.append(ImportFailure(importedID: importedID, reason: .tooLarge))
            } catch {
                guard pending.epoch == lockEpoch else {
                    throw InterchangeSessionError.importInterrupted(saved: outcome.saved)
                }
                outcome.failed.append(ImportFailure(importedID: importedID, reason: .storeRefused))
            }
        }
        return outcome
    }

    // MARK: - Export (PRD F8.4)

    /// A plaintext export of the items of `vaults`, refused unless `password` is the account password, checked the
    /// way an unlock checks it (the KDF over the stored header, then the keyset must open), never against anything
    /// held in memory. Refused while locked, and a lock while it runs wins.
    ///
    /// The bytes are every secret in those vaults, unencrypted. The app shows `plaintextExportWarning` before and
    /// while it asks, writes the file only to a place the person chooses, with `FileProtectionType.completeUnlessOpen`
    /// or stronger (on macOS, a location outside any synced folder unless the person picks one), never into the App
    /// Group container, and shows the report before it says the export is complete: the report is what the person
    /// reads before deleting anything from Watchword.
    public func exportPlaintext(_ format: PlaintextExportFormat, vaults: [UUID], password: String) async throws
        -> PlaintextExport
    {
        let epoch = lockEpoch
        _ = try requireKeys()
        let record = try await verifyAccountPassword(password, since: epoch)
        let chosen = try await exportedItems(vaults, account: record, since: epoch)
        let now = await clock.now()
        _ = try requireKeys(since: epoch)
        let result: ExportResult
        switch format {
        case .applePasswordsCSV(let policy):
            result = PasswordCSV.exportApplePasswords(chosen.items, formulaPolicy: policy)
        case .onePUX:
            let vaultName = chosen.vaults.count == 1 ? chosen.vaults[0].name : "Watchword"
            result = try OnePUX.exportArchive(
                chosen.items,
                options: OnePUX.ExportOptions(
                    accountID: record.accountID, vaultName: vaultName.isEmpty ? "Watchword" : vaultName,
                    vaultID: chosen.vaults[0].id, createdAt: now))
        case .credentialExchange(let relyingPartyID):
            result = CredentialExchange.exportDocument(
                chosen.items,
                options: CredentialExchange.ExportOptions(
                    exporterRelyingPartyID: relyingPartyID, accountID: record.accountID, timestamp: now))
        }
        _ = try requireKeys(since: epoch)
        return PlaintextExport(bytes: result.bytes, report: result.report, unreadable: chosen.unreadable)
    }

    /// An encrypted Watchword archive of the items of `vaults` (PRD F8.4; docs/02-architecture.md §14.1): every item
    /// as the vault stores it, history, trash and unresolved values included, and each vault's name, sealed under a
    /// fresh archive key wrapped under `passphrase` combined with this account's Secret Key (ADR 0008). The account
    /// password is required as for a plaintext export: the archive leaves the vault's protection, and someone
    /// holding an unlocked device should not be able to take it under a passphrase of their own.
    ///
    /// The archive is opened with the same passphrase and the Emergency Kit's Secret Key; neither is stored in it.
    /// The bytes are ciphertext, but the app still writes them with `completeUnlessOpen` or stronger.
    public func exportArchive(vaults: [UUID], passphrase: String, password: String) async throws -> ArchiveExport {
        guard passphrase.count >= VaultConfiguration.minimumPasswordLength else {
            throw InterchangeSessionError.passphraseTooShort(minimum: VaultConfiguration.minimumPasswordLength)
        }
        let epoch = lockEpoch
        _ = try requireKeys()
        let record = try await verifyAccountPassword(password, since: epoch)
        let chosen = try await exportedItems(vaults, account: record, since: epoch)
        let now = await clock.now()
        let secretKey = try await storedSecretKey(accountID: record.accountID)
        defer { secretKey.zeroise() }
        _ = try requireKeys(since: epoch)

        // One entry's plaintext in protected storage at a time: `seal` zeroises each as soon as it is sealed.
        let vaults = chosen.vaults
        let items = chosen.items
        let bytes = try AccountArchive.seal(
            entryCount: vaults.count + items.count,
            payload: { index in
                guard index >= vaults.count else {
                    let vault = vaults[index]
                    let name = Array(vault.name.utf8.prefix(ArchivePayload.maximumVaultNameBytes))
                    return SecureBytes(copying: [ArchivePayload.vault] + Self.bytes(vault.id) + name)
                }
                let encoded = try ItemCodec.encode(items[index - vaults.count])
                defer { encoded.zeroise() }
                return SecureBytes.concatenating([SecureBytes(copying: [ArchivePayload.item]), encoded])
            },
            archiveID: UUID.random(using: &random), accountID: record.accountID, createdAt: now,
            passphrase: passphrase, secretKey: secretKey, parameters: try kdfParameters(), using: &random)
        _ = try requireKeys(since: epoch)
        return ArchiveExport(
            bytes: bytes, itemCount: chosen.items.count, vaultCount: chosen.vaults.count,
            unreadable: chosen.unreadable)
    }

    // MARK: - Helpers

    private func requireWritableVault(_ vaultID: UUID, since epoch: UInt64) async throws {
        let keys = try requireKeys(since: epoch)
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        _ = try await writableVaultKey(vaultID, keys: keys, account: record)
        _ = try requireKeys(since: epoch)
    }

    /// Starts a preview: drops the one held, and makes any preview still being read stale.
    private func beginImport() -> UInt64 {
        importGeneration &+= 1
        pendingImport = nil
        return importGeneration
    }

    /// Compares the drafts with the target vault's items and keeps them, inside the session, for the commit, unless
    /// a lock, a `discardImport()` or a newer preview came while they were read: then they are dropped.
    private func stage(
        _ result: ImportResult, vaultID: UUID, since epoch: UInt64, generation: UInt64,
        archive: (id: UUID, createdAt: Date)? = nil
    ) async throws -> ImportPreview {
        _ = try requireKeys(since: epoch)
        guard generation == importGeneration else { throw InterchangeSessionError.noPendingImport }
        let existing = try await items(inVaults: [vaultID]).items
        _ = try requireKeys(since: epoch)
        guard generation == importGeneration else { throw InterchangeSessionError.noPendingImport }
        let matches = DuplicateDetector.matches(imported: result.entries.map(\.item), existing: existing)
        let id = UUID.random(using: &random)
        pendingImport = PendingImport(id: id, epoch: epoch, vaultID: vaultID, result: result, matches: matches)
        return ImportPreview(
            id: id, vaultID: vaultID, report: result.report,
            entries: result.entries.map {
                ImportPreviewEntry(
                    id: $0.item.id, title: $0.item.title, kind: $0.kind, state: $0.state, reference: $0.reference,
                    hosts: $0.item.scopes.map(\.host), loginNames: $0.item.loginNames)
            },
            matches: matches, archiveID: archive?.id, archiveCreatedAt: archive?.createdAt)
    }

    /// Runs `work` off the session's actor, then requires that no `lock()` came meanwhile (CLAUDE.md: `lock()`
    /// always wins). For work whose cost the caller does not control and that touches none of the session's keys:
    /// an archive's derivation, whose iteration count is the file's. On the actor it would hold `lock()`, auto-lock
    /// and sync behind it with the vault keys resident; here a lock zeroises them at once, and what `work` produced
    /// is dropped.
    func awayFromSession<T: Sendable>(since epoch: UInt64, _ work: @escaping @Sendable () throws -> T) async throws
        -> T
    {
        let outcome = await Task.detached(priority: Task.currentPriority) { Result { try work() } }.value
        _ = try requireKeys(since: epoch)
        return try outcome.get()
    }

    private func currentImport(_ preview: UUID) throws -> PendingImport {
        guard let pending = pendingImport, pending.id == preview, pending.epoch == lockEpoch else {
            throw InterchangeSessionError.noPendingImport
        }
        _ = try requireKeys(since: pending.epoch)
        return pending
    }

    /// Saves an imported draft as a new item of `vaultID`: a write of this device's like any other, but keeping the
    /// draft's history and times (which `save` would replace) and none of its sync metadata.
    private func createImported(_ draft: Item, in vaultID: UUID, since epoch: UInt64) async throws -> UUID {
        for scope in draft.scopes {
            do {
                try ScopePolicy.validate(scope)
            } catch let error as ScopeValidationError {
                throw VaultError.scopeRejected(error)
            }
        }
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        let keys = try requireKeys(since: epoch)
        let vaultKey = try await writableVaultKey(vaultID, keys: keys, account: record)
        _ = try requireKeys(since: epoch)
        var item = draft
        item.vaultID = vaultID
        item.trashedAt = nil
        item.keptAfterDeletion = false
        let revision = try nextRevision(in: vaultID, above: nil, account: record)
        item.version = revision.version
        item = ItemMerge.stamped(item, previous: nil, previousOrigin: nil, revision: revision, using: &random)
        try await commitItem(item, replacing: nil, vaultKey: vaultKey, account: record)
        return item.id
    }

    /// Merges an imported draft into an existing item as an edit of it, computed over the item as it is when the
    /// write reads it, so nothing written since the preview is undone.
    private func mergeImported(
        _ imported: Item, into existingID: UUID, accepting choices: MergeChoices, since epoch: UInt64
    ) async throws {
        for scope in imported.scopes where choices.hosts.contains(scope.host) {
            do {
                try ScopePolicy.validate(scope)
            } catch let error as ScopeValidationError {
                throw VaultError.scopeRejected(error)
            }
        }
        _ = try requireKeys(since: epoch)
        try await write(id: existingID) { item, existing, now in
            guard let existing else { return }
            item = DuplicateDetector.merged(imported, into: existing, accepting: choices)
            if existing.fields != item.fields {
                item.history.insert(
                    ItemHistoryEntry(replacedAt: now, version: existing.version, fields: existing.fields), at: 0)
            }
        }
    }

    /// Re-verifies the account password against the stored header, as `deleteAccount` does: the derivation under
    /// the header's own parameters, then the keyset must open. Throws `CryptoError.authenticationFailed` otherwise.
    func verifyAccountPassword(_ password: String, since epoch: UInt64) async throws -> AccountRecord {
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        let secretKey = try await storedSecretKey(accountID: record.accountID)
        defer { secretKey.zeroise() }
        _ = try requireKeys(since: epoch)
        let verified = try deriveUnlockKey(password: password, secretKey: secretKey, account: record)
        defer { verified.zeroise() }
        try Keyset.unwrap(
            record.wrappedKeyset, accountID: record.accountID, with: verified, recordVersion: record.keysetVersion
        ).zeroise()
        _ = try requireKeys(since: epoch)
        return record
    }

    /// The items of the chosen vaults, each a vault of the account that is not deleted.
    private func exportedItems(_ vaultIDs: [UUID], account: AccountRecord, since epoch: UInt64) async throws
        -> (vaults: [VaultInfo], items: [Item], unreadable: [UUID])
    {
        var seen = Set<UUID>()
        let wanted = vaultIDs.filter { seen.insert($0).inserted }
        guard !wanted.isEmpty else { throw InterchangeSessionError.noVaultChosen }
        let known = Dictionary(uniqueKeysWithValues: try await vaults().map { ($0.id, $0) })
        var chosen: [VaultInfo] = []
        for vaultID in wanted {
            guard let vault = known[vaultID] else { throw VaultError.unknownVault(vaultID) }
            chosen.append(vault)
        }
        let listing = try await items(inVaults: wanted)
        _ = try requireKeys(since: epoch)
        return (chosen, listing.items, listing.unreadable)
    }

    /// Opens `archive` and decodes its entries one at a time, each item with its vault's name as its container. Each
    /// plaintext is zeroised as soon as it is decoded (`AccountArchive.open(passphrase:secretKey:each:)`), so memory
    /// grows with the items, not with a page-rounded buffer per entry. An entry that is neither a vault nor an item
    /// that decodes is listed as unreadable.
    static func archivedEntries(of archive: AccountArchive, passphrase: String, secretKey: SecretKey) throws
        -> [ArchivedEntry]
    {
        var names: [UUID: String] = [:]
        var entries: [ArchivedEntry] = []
        try archive.open(passphrase: passphrase, secretKey: secretKey) { payload in
            guard payload.count > 0 else {
                entries.append(ArchivedEntry(.unreadable))
                return
            }
            switch payload[0] {
            case ArchivePayload.vault:
                // A vault's ID and name: metadata, not key material.
                let bytes = payload.unprotectedCopy()
                guard bytes.count >= 17, bytes.count - 17 <= ArchivePayload.maximumVaultNameBytes,
                    let name = String(bytes: bytes[17...], encoding: .utf8)
                else { return }
                names[Self.uuid(Array(bytes[1..<17]))] = name
            case ArchivePayload.item:
                let encoded = payload.extracting(1..<payload.count)
                defer { encoded.zeroise() }
                if let item = try? ItemCodec.decode(encoded) {
                    entries.append(ArchivedEntry(.item(item)))
                } else {
                    entries.append(ArchivedEntry(.unreadable))
                }
            default:
                entries.append(ArchivedEntry(.unreadable))
            }
        }
        for index in entries.indices {
            if case .item(let item) = entries[index].content { entries[index].container = names[item.vaultID] }
        }
        return entries
    }

}
