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
    /// Apple Passwords CSV, every value exactly as stored: the file is for another password manager's importer, not a
    /// spreadsheet, so nothing neutralises formulas (owner decision, 2026-11-16; docs/02-architecture.md §14). The
    /// export screen shows `InterchangeGuide.plaintextExportWarning`.
    case applePasswordsCSV
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
    /// Also an entry the preview raised a concern about (`ImportPreview.concerns`): it would hide a saved account from
    /// AutoFill, stand beside one, or scope a new item to a look-alike host, and is imported only if the person says
    /// so (`keepBoth`) or skipped.
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
    /// A merge accepts hosts that would hide or stand beside an account AutoFill offers, or that resemble a saved
    /// site, and `MergeChoices.confirmedHosts` does not name them (review finding Z75). `concern` says what each would
    /// do; nothing was written and the preview is kept.
    case mergeNeedsConfirmation(importedID: UUID, concern: ImportConcern)
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
    /// Entries that would change what AutoFill offers for a site already saved, in any vault, or that would scope a
    /// new item to a look-alike host; each needs a decision too (review finding Z62).
    public var concerns: [ImportConcern] = []
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
    /// The entry's scopes as the draft holds them: each host with how far it reaches, for the review to show.
    public var scopes: [ServiceScope] = []
    public var loginNames: [String]
    /// The apex hosts the import added as scopes beside a `www` host the file named (`ImportOptions.matchApexOfWWWHosts`,
    /// on by default; owner decision, 2026-11-16), each also in `hosts`: the widening the preview must show. From the
    /// report's `apexScopeAdded` lines, so an entry past `ImportReport.maximumWarnings` lists none here.
    public var apexScopesAdded: [String]
}

/// What importing one entry as a new item would do to AutoFill, where that needs the person's decision (review
/// finding Z62; adversary A7, whoever hands over the file).
///
/// A new entry was taken to hold only the file's own secrets, so only a merge was guarded. But an item is ranked
/// against every other by its scopes: an entry scoped one label below a saved login outranks it, the extension then
/// neither lists nor releases the saved login there, and the next password the person saves on that site is offered
/// to the imported item, whose other scopes are the file's to choose. An entry the file marks archived does the same
/// without ever being listed. So before anything is written the preview says, by the gate's own ranking
/// (`SavedSites`), which saved accounts each entry would hide or stand beside, in every vault, and which of its hosts
/// resemble a saved site without being it. The entry is imported only with an explicit decision.
public struct ImportConcern: Sendable, Hashable, Identifiable {
    public var importedID: UUID
    /// Saved accounts the entry would outrank on a host they are offered on now: the extension would stop offering
    /// them there.
    public var hidden: [AffectedAccount]
    /// Saved accounts it would be offered beside: the person would choose between them on every fill, and a saved
    /// password could be offered to either.
    public var beside: [AffectedAccount]
    /// The entry's scopes cover more saved hosts than were examined: `hidden` and `beside` are not everything.
    public var overlapIsTruncated: Bool
    /// Hosts of the entry that resemble a saved site without being it, or cannot be verified by eye (PRD F11.7).
    public var lookAlikeHosts: [HostConfirmation]
    /// Hosts that were not compared with what is saved, because the import as a whole would have cost too many
    /// comparisons (`VaultSession.maximumImportHostComparisons`). Not known to be ordinary, so they need the decision.
    public var uncheckedHosts: [String]
    /// The file marks the entry archived: it would rank, and hide what it outranks, without ever being offered.
    public var isArchived: Bool
    /// The file (an archive) marks the entry excluded from suggestions: the same as archived, for AutoFill.
    public var isExcludedFromSuggestions: Bool = false
    /// The file has the entry in its trash: it is saved into the trash, where it ranks for nothing until the person
    /// restores it, and a restore asks nothing, so the decision is made here (review finding Z73).
    public var isTrashed: Bool = false

    public var id: UUID { importedID }

    public var isEmpty: Bool {
        hidden.isEmpty && beside.isEmpty && !overlapIsTruncated && lookAlikeHosts.isEmpty && uncheckedHosts.isEmpty
    }
}

/// The person's choice for one imported entry. Entries without a decision, without a match and without a concern
/// are added as new items; an entry with a match or a concern must have one.
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
public struct PlaintextExport: Sendable {
    /// The file, in zeroising memory. The exporter's array was moved here and wiped while it was the only reference
    /// to its buffer (review §Z, Z83); what the exporters build on the way (the CSV or JSON text, the ZIP's parts)
    /// is ordinary memory and is not wiped, like every decoded item's `String`s (SEC4, D5).
    public var bytes: SecureBytes
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
    /// What a restore of this archive would not bring back, if anything (review §Z, Z82): the archive holds it, but
    /// this version's restore would skip it or refuse the file. Checked with the restore's own assembler and limits.
    public var restoreCheck: ArchiveRestoreCheck = ArchiveRestoreCheck()
}

/// The drafts of one import, between preview and commit. Session state; `lock()` drops it.
struct PendingImport: Sendable {
    let id: UUID
    let epoch: UInt64
    let vaultID: UUID
    let result: ImportResult
    let matches: [DuplicateMatch]
    /// Entries with an `ImportConcern`: each needs a decision as a match does.
    let concerned: Set<UUID>
}

/// A draft's scopes and state: what the import's review compares with the saved items, and nothing secret.
struct DraftScopes: Sendable {
    let id: UUID
    let scopes: [ServiceScope]
    let state: ImportedState
    /// Archived by the file's state or by the item itself (an archive restores the flag as it was).
    var isArchived = false
    var isExcludedFromSuggestions = false

    init(id: UUID, scopes: [ServiceScope], state: ImportedState) {
        self.id = id
        self.scopes = scopes
        self.state = state
        isArchived = state == .archived
    }

    init(_ entry: ImportedEntry) {
        self.init(id: entry.item.id, scopes: entry.item.scopes, state: entry.state)
        isArchived = entry.state == .archived || entry.item.archived
        isExcludedFromSuggestions = entry.item.excludedFromSuggestions
    }
}

/// The long steps the session runs off its actor (`awayFromSession`), so that `lock()` never waits for them.
enum AwayWork: Sendable, Hashable {
    /// A plaintext import file's parse into drafts (CSV, 1PUX, CXF).
    case importParse
    /// An archive's parse: bounds, envelopes' places, SHA-256 over up to 256 MiB.
    case archiveParse
    /// An archive's key derivation at the file's iteration count, its decryption and its entries' assembly.
    case archiveDerivation
    /// The account password's derivation before an export.
    case passwordCheck
    /// A new archive's key derivation, under this account's parameters.
    case archiveKeyDerivation
    /// A new archive's items run through the restore's assembler, to report what it would not bring back (Z82).
    case archiveRestoreCheck
    /// An import's drafts compared with what is saved: which accounts each would hide, and which hosts are
    /// look-alikes. Linear in the file for a fixed vault, but the file and the vault are both large.
    case importReview
    /// Another account's device registry replayed along the password changes it publishes (Z10): up to
    /// `maximumMemberBranches` replays a step, of a registry its account fills.
    case memberRegistry
    /// A candidate account header's derivation under its own KDF parameters (up to the ceiling, its author's
    /// choice), at the lock screen or in `followPasswordChange` (Z14).
    case candidateDerivation
}

/// What an archive entry holds: the first byte of its plaintext.
enum ArchivePayload {
    static let vault: UInt8 = 1
    static let item: UInt8 = 2
    static let maximumVaultNameBytes = 1024

    /// `name`'s UTF-8, cut to at most `maximumVaultNameBytes` at a scalar boundary: a cut through a scalar would
    /// leave bytes that do not decode, and the restore would then lose the whole name.
    static func vaultName(_ name: String) -> [UInt8] {
        var bytes: [UInt8] = []
        for scalar in name.unicodeScalars {
            let encoded = Array(String(scalar).utf8)
            guard bytes.count + encoded.count <= maximumVaultNameBytes else { break }
            bytes += encoded
        }
        return bytes
    }
}

extension VaultSession {
    /// The standing warning the export screen shows before and while a plaintext export is made (PRD F8.4).
    public nonisolated static var plaintextExportWarning: String { InterchangeGuide.plaintextExportWarning.text }

    // MARK: - Import (PRD F8.1–F8.3)

    /// Reads an import file into drafts for `vaultID` and returns what an import would do. Writes nothing.
    ///
    /// The drafts, which hold every secret in the file, stay in the session until `commitImport`, `discardImport`,
    /// the next preview or `lock()`, whichever comes first; a `discardImport()` or newer preview while this one is
    /// still being read wins, and this one throws `noPendingImport`. The parse is bounded by `InterchangeLimits` and
    /// runs off the session's actor (`awayFromSession`), on the file's bytes and nothing of the session's, with IDs
    /// from a fork of the session's generator: a `lock()` meanwhile takes effect at once, and this call then throws
    /// `locked`.
    public func previewImport(
        _ bytes: [UInt8], format: ImportFileFormat, into vaultID: UUID, options: ImportOptions = ImportOptions()
    ) async throws -> ImportPreview {
        let epoch = lockEpoch
        let generation = beginImport()
        try await requireWritableVault(vaultID, since: epoch)
        let fork = ForkedGenerator(forkingFrom: &random)
        let result = try await awayFromSession(.importParse, since: epoch) { () -> ImportResult in
            var fork = fork
            switch format {
            case .passwordCSV:
                return try PasswordCSV.importFile(bytes, into: vaultID, options: options, using: &fork)
            case .onePUX:
                return try OnePUX.importArchive(bytes, into: vaultID, options: options, using: &fork)
            case .credentialExchange:
                return try CredentialExchange.importDocument(bytes, into: vaultID, options: options, using: &fork)
            }
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
    /// phone) before anything in the file is authenticated, so it runs off the session's actor, with the parse (up to
    /// 256 MiB, hashed), the decryption and decoding of the entries and their assembly into drafts: a `lock()`
    /// meanwhile takes effect at once, and this call then throws `locked`.
    public func previewArchiveImport(
        _ bytes: [UInt8], passphrase: String, secretKey text: String? = nil, into vaultID: UUID,
        options: ImportOptions = ImportOptions()
    ) async throws -> ImportPreview {
        let epoch = lockEpoch
        let generation = beginImport()
        try await requireWritableVault(vaultID, since: epoch)
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        let archive = try await awayFromSession(.archiveParse, since: epoch) { try AccountArchive.parse(bytes) }
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
        let fork = ForkedGenerator(forkingFrom: &random)
        let result = try await awayFromSession(.archiveDerivation, since: epoch) { () -> ImportResult in
            var fork = fork
            let entries = try Self.archivedEntries(of: archive, passphrase: passphrase, secretKey: secretKey)
            return try ArchivedItems.importEntries(entries, into: vaultID, options: options, using: &fork)
        }
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
    /// trash is saved into the trash, in the one write that creates it (review finding Z73).
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
        // In the file's order, so the same entry is named every time.
        for entry in pending.result.entries
        where pending.concerned.contains(entry.item.id) && decisions[entry.item.id] == nil {
            throw InterchangeSessionError.decisionRequired(importedID: entry.item.id)
        }
        try await checkMergedHosts(pending, decisions: decisions)
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
                    // An entry from the source's trash is created in the trash: never live, not even between two
                    // writes a lock or an error could separate (Z73).
                    let created = try await createImported(
                        entry.item, in: pending.vaultID, trashed: entry.state == .trashed, since: pending.epoch)
                    outcome.created.append(created)
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
        var result: ExportResult
        switch format {
        case .applePasswordsCSV:
            result = PasswordCSV.exportApplePasswords(chosen.items)
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
        // Moved out of the result first, so the array is the buffer's only reference and the wipe reaches it rather
        // than a copy-on-write duplicate (Z83).
        var bytes = result.bytes
        result.bytes = []
        let contents = SecureBytes(wiping: &bytes)
        return PlaintextExport(bytes: contents, report: result.report, unreadable: chosen.unreadable)
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

        // The derivation, under this account's calibrated parameters, runs off the actor like the password check; the
        // archive's ID, salt and keys come from the session's generator, here.
        let parameters = try kdfParameters()
        let archiveID = UUID.random(using: &random)
        let salt = SecureBytes(randomCount: parameters.saltLength, using: &random).unprotectedCopy()
        let wrapKeyID = UUID.random(using: &random)
        let accountID = record.accountID
        let wrappingKey = try await awayFromSession(.archiveKeyDerivation, since: epoch) {
            try ArchiveKeyDerivation.wrappingKey(
                passphrase: passphrase, secretKey: secretKey, archiveID: archiveID, accountID: accountID,
                parameters: parameters, salt: salt, keyID: wrapKeyID)
        }
        defer { wrappingKey.zeroise() }

        // One entry's plaintext in protected storage at a time: `seal` zeroises each as soon as it is sealed.
        let vaults = chosen.vaults
        let items = chosen.items
        let bytes = try AccountArchive.seal(
            entryCount: vaults.count + items.count,
            payload: { index in
                guard index >= vaults.count else {
                    let vault = vaults[index]
                    let name = ArchivePayload.vaultName(vault.name)
                    return SecureBytes(copying: [ArchivePayload.vault] + Self.bytes(vault.id) + name)
                }
                let encoded = try ItemCodec.encode(items[index - vaults.count])
                defer { encoded.zeroise() }
                return SecureBytes.concatenating([SecureBytes(copying: [ArchivePayload.item]), encoded])
            },
            archiveID: archiveID, accountID: accountID, createdAt: now, wrappingKey: wrappingKey, salt: salt,
            parameters: parameters, using: &random)
        _ = try requireKeys(since: epoch)
        let fork = ForkedGenerator(forkingFrom: &random)
        let check = try await awayFromSession(.archiveRestoreCheck, since: epoch) { () -> ArchiveRestoreCheck in
            var fork = fork
            return ArchivedItems.restoreCheck(items, using: &fork)
        }
        return ArchiveExport(
            bytes: bytes, itemCount: chosen.items.count, vaultCount: chosen.vaults.count,
            unreadable: chosen.unreadable, restoreCheck: check)
    }

    // MARK: - Helpers

    /// A host a merge adds makes the existing item offered there, which can hide or stand beside another account as a
    /// new entry's host can (review finding Z75): a duplicate of the Shop login that adds `login.bank.example` takes
    /// the bank's sign-in page from the saved Bank login. The screen asks a second time for a look-alike only, so the
    /// session judges every accepted host like a new entry's, against `SavedSites`, and refuses the first merge whose
    /// host needs a confirmation that `MergeChoices.confirmedHosts` does not give. Before anything is written; the
    /// preview is kept.
    private func checkMergedHosts(_ pending: PendingImport, decisions: [UUID: ImportDecision]) async throws {
        let merging = pending.result.entries.compactMap { entry -> (Item, ImportDecision)? in
            guard let decision = decisions[entry.item.id], decision.resolution == .merge,
                !decision.choices.hosts.isEmpty
            else { return nil }
            return (entry.item, decision)
        }
        guard !merging.isEmpty else { return }
        let existing = Dictionary(
            try await items(inVaults: [pending.vaultID]).items.map { ($0.id, $0) },
            uniquingKeysWith: { first, _ in first })
        let sites = try await savedSites()
        let targetIsShared =
            try await vaults(includingDeleted: true).first { $0.id == pending.vaultID }?.isShared ?? true
        _ = try requireKeys(since: pending.epoch)
        let requests = merging.compactMap { imported, decision -> MergedHosts? in
            guard let existingID = decision.existingID, let item = existing[existingID] else { return nil }
            let held = Set(item.scopes.map(\.host))
            let added = imported.scopes.filter { decision.choices.hosts.contains($0.host) && !held.contains($0.host) }
            guard !added.isEmpty else { return nil }
            return MergedHosts(
                importedID: imported.id, existing: item, added: added, confirmed: decision.choices.confirmedHosts)
        }
        guard !requests.isEmpty else { return }
        let concerns = try await awayFromSession(.importReview, since: pending.epoch) {
            Self.mergeConcerns(requests, among: sites, isOwnVault: !targetIsShared)
        }
        if let first = concerns.first {
            throw InterchangeSessionError.mergeNeedsConfirmation(importedID: first.importedID, concern: first)
        }
    }

    /// The hosts one merge adds to an existing item, and those the person confirmed.
    struct MergedHosts: Sendable {
        let importedID: UUID
        let existing: Item
        let added: [ServiceScope]
        let confirmed: Set<String>
    }

    /// What the unconfirmed hosts of each merge would do, for the merges where that is anything. Pure; run off the
    /// actor. The existing item is among what is saved: it is left out of what a host would hide or stand beside, and
    /// its own scopes are the item's (the person's word in a vault of their own) beside the new host.
    nonisolated static func mergeConcerns(
        _ merges: [MergedHosts], among sites: SavedSites, isOwnVault: Bool
    ) -> [ImportConcern] {
        let prepared = sites.prepared()
        var concerns: [ImportConcern] = []
        for merge in merges {
            var concern = ImportConcern(
                importedID: merge.importedID, hidden: [], beside: [], overlapIsTruncated: false, lookAlikeHosts: [],
                uncheckedHosts: [], isArchived: merge.existing.archived,
                isExcludedFromSuggestions: merge.existing.excludedFromSuggestions)
            for scope in merge.added.filter(ScopePolicy.isAcceptable) where !merge.confirmed.contains(scope.host) {
                let overlap = prepared.overlap(
                    ofAdding: [scope], inVault: merge.existing.vaultID, isOwnVault: isOwnVault)
                concern.hidden += overlap.hidden.filter { $0.itemID != merge.existing.id }
                concern.beside += overlap.beside.filter { $0.itemID != merge.existing.id }
                concern.overlapIsTruncated = concern.overlapIsTruncated || overlap.isTruncated
                if case .needsConfirmation(let resembles) = prepared.standing(
                    ofNewHost: scope.host, beside: merge.existing.scopes, inSharedVault: !isOwnVault,
                    inVault: merge.existing.vaultID)
                {
                    concern.lookAlikeHosts.append(HostConfirmation(host: scope.host, resembles: resembles))
                }
            }
            if !concern.isEmpty { concerns.append(concern) }
        }
        return concerns
    }

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
        // The file's dates are kept (created, modified, history), so none may be later than this clock's now: sync
        // keeps `modifiedAt` monotonic, and one date in the future would stick on every device (Z85).
        let result = result.boundingDates(notAfter: await clock.now())
        let existing = try await items(inVaults: [vaultID]).items
        _ = try requireKeys(since: epoch)
        guard generation == importGeneration else { throw InterchangeSessionError.noPendingImport }
        let matches = DuplicateDetector.matches(imported: result.entries.map(\.item), existing: existing)
        // Against every vault, as the gate ranks: duplicates are a matter of one vault, AutoFill is not.
        let sites = try await savedSites()
        let targetIsShared = try await vaults(includingDeleted: true).first { $0.id == vaultID }?.isShared ?? true
        _ = try requireKeys(since: epoch)
        // Only what the comparison needs leaves the actor: no field of a draft.
        let entries = result.entries.map(DraftScopes.init)
        let concerns = try await awayFromSession(.importReview, since: epoch) {
            Self.importConcerns(entries, among: sites, vaultID: vaultID, isOwnVault: !targetIsShared)
        }
        guard generation == importGeneration else { throw InterchangeSessionError.noPendingImport }
        let id = UUID.random(using: &random)
        pendingImport = PendingImport(
            id: id, epoch: epoch, vaultID: vaultID, result: result, matches: matches,
            concerned: Set(concerns.map(\.importedID)))
        var apexAdded: [ImportEntryReference: [String]] = [:]
        for record in result.report.warnings {
            if case .apexScopeAdded(_, let apex) = record.warning { apexAdded[record.entry, default: []].append(apex) }
        }
        return ImportPreview(
            id: id, vaultID: vaultID, report: result.report,
            entries: result.entries.map {
                ImportPreviewEntry(
                    id: $0.item.id, title: $0.item.title, kind: $0.kind, state: $0.state, reference: $0.reference,
                    hosts: $0.item.scopes.map(\.host), scopes: $0.item.scopes, loginNames: $0.item.loginNames,
                    apexScopesAdded: apexAdded[$0.reference] ?? [])
            },
            matches: matches, concerns: concerns, archiveID: archive?.id, archiveCreatedAt: archive?.createdAt)
    }

    /// The comparisons of a host with a saved scope that one import preview makes at most. A host costs one per
    /// saved scope; past the budget the remaining hosts are reported as unchecked, which needs the person's decision
    /// like a look-alike: an import of tens of thousands of entries into a vault of thousands is then reviewed in
    /// parts rather than waited for.
    public nonisolated static var maximumImportHostComparisons: Int { 20_000_000 }

    /// What each draft would do to AutoFill, by the gate's own view of what is saved. Pure; run off the actor.
    ///
    /// A host is judged against what is saved, and compared with the entry's other scopes for resemblance only
    /// (`standing(ofNewHost:resemblingOnly:)`): those are the file's too and vouch for nothing, but `amaz0n.com`
    /// beside `amazon.com` in one entry is a look-alike of it (review finding Z74). An entry holds at most
    /// `maximumURLsPerItem` (32) scopes, so that is at most 32 × 31 comparisons an entry, linear in the file, and
    /// they are charged to the budget with the rest. An entry the source had in its trash is reviewed like any other
    /// (Z73): a restore from the trash asks nothing.
    nonisolated static func importConcerns(
        _ entries: [DraftScopes], among sites: SavedSites, vaultID: UUID, isOwnVault: Bool,
        budget comparisons: Int = maximumImportHostComparisons
    ) -> [ImportConcern] {
        let prepared = sites.prepared()
        let cost = max(1, prepared.comparisonsPerHost)
        var budget = comparisons
        var concerns: [ImportConcern] = []
        for entry in entries where !entry.scopes.isEmpty {
            let scopes = entry.scopes
            // The overlap is charged to the same budget (review finding Z79): a shared vault's members can put any
            // number of items on one host, and every entry ranks them. Past the budget it is reported truncated,
            // which needs the decision like an unchecked host.
            let overlap = prepared.overlap(
                ofAdding: scopes, inVault: vaultID, isOwnVault: isOwnVault, limit: max(0, budget))
            budget -= overlap.comparisons
            var lookAlikes: [HostConfirmation] = []
            var unchecked: [String] = []
            for scope in scopes {
                let others = scopes.filter { $0.host != scope.host }
                guard budget >= cost + others.count else {
                    unchecked.append(scope.host)
                    continue
                }
                budget -= cost + others.count
                if case .needsConfirmation(let resembles) = prepared.standing(
                    ofNewHost: scope.host, resemblingOnly: others, inSharedVault: !isOwnVault, inVault: vaultID)
                {
                    lookAlikes.append(HostConfirmation(host: scope.host, resembles: resembles))
                }
            }
            let concern = ImportConcern(
                importedID: entry.id, hidden: overlap.hidden, beside: overlap.beside,
                overlapIsTruncated: overlap.isTruncated, lookAlikeHosts: lookAlikes, uncheckedHosts: unchecked,
                isArchived: entry.isArchived, isExcludedFromSuggestions: entry.isExcludedFromSuggestions,
                isTrashed: entry.state == .trashed)
            if !concern.isEmpty { concerns.append(concern) }
        }
        return concerns
    }

    /// Runs `work` off the session's actor, then requires that no `lock()` came meanwhile (CLAUDE.md: `lock()`
    /// always wins). For long work that touches none of the session's keys, on inputs copied for it (`AwayWork` names
    /// each): on the actor it would hold `lock()`, auto-lock and sync behind it with the vault keys resident; here a
    /// lock zeroises them at once, and what `work` produced is dropped. Whatever key-bearing input `work` is given (a
    /// Secret Key read for the call, a password) is the caller's to zeroise once this returns, whatever it returns.
    func awayFromSession<T: Sendable>(
        _ step: AwayWork, since epoch: UInt64, _ work: @escaping @Sendable () throws -> T
    ) async throws -> T {
        let hook = awayWorkHook
        let outcome = await Task.detached(priority: Task.currentPriority) {
            Result {
                hook?(step)
                return try work()
            }
        }.value
        _ = try requireKeys(since: epoch)
        return try outcome.get()
    }

    /// Tests only: see `awayWorkHook`.
    func setAwayWorkHook(_ hook: (@Sendable (AwayWork) -> Void)?) {
        awayWorkHook = hook
    }

    private func currentImport(_ preview: UUID) throws -> PendingImport {
        guard let pending = pendingImport, pending.id == preview, pending.epoch == lockEpoch else {
            throw InterchangeSessionError.noPendingImport
        }
        _ = try requireKeys(since: pending.epoch)
        return pending
    }

    /// Saves an imported draft as a new item of `vaultID`: a write of this device's like any other, but keeping the
    /// draft's history and times (which `save` would replace) and none of its sync metadata. `trashed` puts it in
    /// the trash in the same write, as the person's own trash from now (Z73).
    private func createImported(
        _ draft: Item, in vaultID: UUID, trashed: Bool, since epoch: UInt64
    ) async throws -> UUID {
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
        let now = await clock.now()
        _ = try requireKeys(since: epoch)
        var item = draft
        item.vaultID = vaultID
        item.trashedAt = trashed ? now : nil
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
    ///
    /// The derivation costs what the account's parameters say, with every key resident, so it runs off the actor
    /// (`awayFromSession`) on copies: the password, the Secret Key read for this call, and the stored header. What it
    /// derives and unwraps is zeroised there before it returns, and a `lock()` meanwhile wins (`locked`).
    func verifyAccountPassword(_ password: String, since epoch: UInt64) async throws -> AccountRecord {
        guard let record = try await loadAccount() else { throw VaultError.noAccount }
        let secretKey = try await storedSecretKey(accountID: record.accountID)
        defer { secretKey.zeroise() }
        _ = try requireKeys(since: epoch)
        try await awayFromSession(.passwordCheck, since: epoch) {
            let verified = try TwoSecretKeyDerivation.accountUnlockKey(
                password: password, secretKey: secretKey, accountID: record.accountID, parameters: record.kdf,
                salt: record.salt, keyID: record.unlockKeyID)
            defer { verified.zeroise() }
            try Keyset.unwrap(
                record.wrappedKeyset, accountID: record.accountID, with: verified, recordVersion: record.keysetVersion
            ).zeroise()
        }
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
                // One that does not parse is listed as skipped (§14.1), never dropped in silence.
                guard bytes.count >= 17, bytes.count - 17 <= ArchivePayload.maximumVaultNameBytes,
                    let name = String(bytes: bytes[17...], encoding: .utf8)
                else {
                    entries.append(ArchivedEntry(.unreadable))
                    return
                }
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
