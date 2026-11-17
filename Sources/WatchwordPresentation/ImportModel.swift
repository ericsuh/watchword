import Foundation
import Observation
import WatchwordInterchange
import WatchwordKit
import WatchwordMatching
import WatchwordModel

/// What the person chose for an imported entry that duplicates an existing item.
public enum ImportChoice: Hashable, Sendable {
    case skip
    case keepBoth
    case merge(into: UUID)
}

/// An entry of the file, as the review lists it.
public struct ImportEntryRow: Hashable, Sendable, Identifiable {
    public let id: UUID
    public let title: String
    public let hosts: [String]
    /// Apex hosts the import added beside a `www` host the file named: the widening the review must show.
    public let apexScopesAdded: [String]
    public let loginNames: [String]
    public let isDuplicate: Bool
}

/// An existing item an imported entry may duplicate.
public struct DuplicateOption: Hashable, Sendable, Identifiable {
    public let id: UUID
    public let existingTitle: String
    public let isIdentical: Bool
    /// Hosts a merge would add to the existing item if the person accepts them (`DuplicateMatch.newHosts`).
    public let newHosts: [String]
    public let hasNewSignInFields: Bool
    public let hasNewURLFields: Bool

    /// What the option says before the person opens it.
    public var summary: String {
        if isIdentical { return "Identical to “\(existingTitle)”." }
        var parts = ["Looks like the same account as “\(existingTitle)”."]
        if !newHosts.isEmpty { parts.append("A merge could add " + newHosts.joined(separator: ", ") + ".") }
        if hasNewSignInFields { parts.append("It has sign-in details the existing item lacks.") }
        if hasNewURLFields { parts.append("It has URLs the existing item lacks.") }
        return parts.joined(separator: " ")
    }
}

public struct DuplicateRow: Hashable, Sendable, Identifiable {
    public let id: UUID
    public let title: String
    public let hosts: [String]
    public let loginNames: [String]
    public let options: [DuplicateOption]
}

/// A field a merge would add only if the person accepts it, shown with its value: hidden for secrets until shown.
public struct AdditionField: Hashable, Sendable, Identifiable {
    public let id: UUID
    public let label: String
    public let value: String
    public let isSecret: Bool
}

/// Everything a merge would add, for the duplicate screen to show before anything is accepted (PRD F8.2, F11.2;
/// `MergeAdditions`). Hosts, sign-in fields and URLs are added only one by one; the rest is added by the merge.
public struct MergeReview: Hashable, Sendable {
    public let existingID: UUID
    /// Hosts the existing item would also be offered on, each as the person should read it (`MergeHost`).
    public let hosts: [MergeHost]
    public let signInFields: [AdditionField]
    public let urlFields: [AdditionField]
    /// Labels of the other fields a merge adds as they are.
    public let otherFields: [String]
    public let tags: [String]
    public let addsNotes: Bool

    /// `sites` is what the hosts are compared with for look-alikes: what is saved in every vault, as the gate sees it
    /// (`VaultSession.savedSites()`), the existing item included.
    public init(existingID: UUID, additions: MergeAdditions, sites: SavedSites.Prepared, inSharedVault: Bool = false) {
        self.existingID = existingID
        hosts = additions.scopes.map { MergeHost($0, among: sites, inSharedVault: inSharedVault) }
        func row(_ field: Field) -> AdditionField {
            AdditionField(
                id: field.id, label: field.label.isEmpty ? field.kind.rawValue : field.label, value: field.value,
                isSecret: field.kind.isSecret)
        }
        signInFields = additions.signInFields.map(row)
        urlFields = additions.urlFields.map(row)
        otherFields = additions.otherFields.map { $0.label.isEmpty ? $0.kind.rawValue : $0.label }
        tags = additions.tags.sorted()
        addsNotes = !additions.notes.isEmpty
    }

    public var addsNothingWithoutChoice: Bool { otherFields.isEmpty && tags.isEmpty && !addsNotes }
}

/// What a commit did, in words.
public struct ImportSummary: Hashable, Sendable {
    public let created: Int
    public let merged: Int
    public let skipped: Int
    public let failed: Int

    public init(created: Int, merged: Int, skipped: Int, failed: Int) {
        self.created = created
        self.merged = merged
        self.skipped = skipped
        self.failed = failed
    }

    public var text: String {
        var parts = ["\(created) added", "\(merged) merged", "\(skipped) skipped"]
        if failed > 0 { parts.append("\(failed) could not be saved") }
        return parts.joined(separator: ", ") + "."
    }
}

/// Import from another password manager's file, or restore from an encrypted Watchword archive (PRD F8.1–F8.3, F8.5;
/// docs/02-architecture.md §14.1), as preview, review and commit. The drafts stay inside the session until the commit
/// (and go with a lock); this model holds only what the review shows, and the values a merge would add while the
/// person looks at them. Every duplicate needs a choice, and a merge adds no host, sign-in field or URL the person did
/// not accept by name: there is no "accept all".
@MainActor
@Observable
public final class ImportModel: LockSensitive {
    public enum Stage: Hashable, Sendable {
        case choose
        case review
        case done(ImportSummary)
    }

    public private(set) var stage: Stage = .choose
    /// Vaults the import can go into.
    public private(set) var vaults: [VaultRow] = []
    public var vaultID: UUID?
    public var format: ImportFileFormat = .passwordCSV
    public var archivePassphrase = ""
    /// For an archive another account made: the Secret Key from that account's Emergency Kit.
    public var archiveSecretKey = ""

    public private(set) var formatName = ""
    public private(set) var entries: [ImportEntryRow] = []
    public private(set) var duplicates: [DuplicateRow] = []
    public private(set) var reportLines: [String] = []
    /// When the archive was made, as sealed in it. The restore screen shows it, so that an older archive put in place
    /// of the newest is seen for what it is.
    public private(set) var archiveCreatedAt: Date?
    public private(set) var choices: [UUID: ImportChoice] = [:]
    public private(set) var merges: [UUID: MergeReview] = [:]
    public private(set) var accepted: [UUID: MergeChoices] = [:]
    /// Secret values the person chose to see, by field ID.
    public var revealed: Set<UUID> = []
    /// A host that resembles a saved site, switched on and waiting for the person's second confirmation.
    public private(set) var hostAwaitingConfirmation: (importedID: UUID, host: MergeHost)?
    public private(set) var isWorking = false
    public var errorMessage: String?

    private let context: ScreenContext
    private var previewID: UUID?

    public init(context: ScreenContext) {
        self.context = context
        context.locks?.register(self)
    }

    /// On every lock: the merge values (secrets among them), what was revealed, every choice and the typed
    /// passphrase and Secret Key go, as the session's drafts did (finding 6).
    public func dropOnLock() {
        reset()
        archivePassphrase = ""
        archiveSecretKey = ""
        if stage == .review { stage = .choose }
    }

    public var undecided: [DuplicateRow] { duplicates.filter { choices[$0.id] == nil } }
    public var canCommit: Bool { stage == .review && undecided.isEmpty && !isWorking }

    public func load() async {
        await perform {
            vaults = try await VaultRow.load(from: context.session).filter { !$0.isReadOnly }
            if vaultID == nil || !vaults.contains(where: { $0.id == vaultID }) { vaultID = vaults.first?.id }
        }
    }

    /// Reads a file of another app's into drafts and shows what an import would do. Writes nothing.
    public func read(_ bytes: [UInt8]) async {
        guard let vaultID else {
            errorMessage = "Choose a vault to import into."
            return
        }
        let format = self.format
        await perform {
            let preview = try await context.session.previewImport(bytes, format: format, into: vaultID)
            try await show(preview)
        }
    }

    /// Opens an encrypted Watchword archive and shows what restoring its items would do. Writes nothing.
    public func readArchive(_ bytes: [UInt8]) async {
        guard let vaultID else {
            errorMessage = "Choose a vault to restore into."
            return
        }
        let passphrase = archivePassphrase
        let secretKey = archiveSecretKey.trimmingCharacters(in: .whitespacesAndNewlines)
        await perform {
            let preview = try await context.session.previewArchiveImport(
                bytes, passphrase: passphrase, secretKey: secretKey.isEmpty ? nil : secretKey, into: vaultID)
            archivePassphrase = ""
            archiveSecretKey = ""
            try await show(preview)
        }
    }

    public func choose(_ choice: ImportChoice, for importedID: UUID) async {
        guard let previewID, duplicates.contains(where: { $0.id == importedID }) else { return }
        await perform {
            if case .merge(let existingID) = choice {
                let additions = try await context.session.importAdditions(
                    preview: previewID, importedID: importedID, existingID: existingID)
                let existing = try await context.session.item(id: existingID)
                let sites = try await context.session.savedSites().prepared()
                merges[importedID] = MergeReview(
                    existingID: existingID, additions: additions, sites: sites,
                    inSharedVault: sites.sites.sharedVaults.contains(existing.vaultID))
            } else {
                merges[importedID] = nil
            }
            // A new choice starts from nothing accepted: never pre-filled.
            accepted[importedID] = MergeChoices.none
            choices[importedID] = choice
        }
    }

    public func isAccepted(host: String, for importedID: UUID) -> Bool {
        accepted[importedID]?.hosts.contains(host) ?? false
    }

    public func isAccepted(field: UUID, for importedID: UUID) -> Bool {
        accepted[importedID]?.fieldIDs.contains(field) ?? false
    }

    /// Accepts or drops one host. A host that resembles a saved site is not accepted at once: it waits in
    /// `hostAwaitingConfirmation` for `confirmAwaitingHost()`.
    public func setHost(_ host: String, accepted isAccepted: Bool, for importedID: UUID) {
        context.recordActivity()
        guard let review = merges[importedID], let shown = review.hosts.first(where: { $0.host == host }) else {
            return
        }
        if isAccepted, shown.needsConfirmation {
            hostAwaitingConfirmation = (importedID, shown)
            return
        }
        apply(host, accepted: isAccepted, for: importedID)
    }

    /// The person confirmed the look-alike host a second time, having read its warning.
    public func confirmAwaitingHost() {
        guard let (importedID, host) = hostAwaitingConfirmation else { return }
        hostAwaitingConfirmation = nil
        apply(host.host, accepted: true, for: importedID)
    }

    public func cancelAwaitingHost() {
        hostAwaitingConfirmation = nil
    }

    private func apply(_ host: String, accepted isAccepted: Bool, for importedID: UUID) {
        var current = accepted[importedID] ?? .none
        if isAccepted { current.hosts.insert(host) } else { current.hosts.remove(host) }
        accepted[importedID] = current
    }

    public func setField(_ fieldID: UUID, accepted isAccepted: Bool, for importedID: UUID) {
        context.recordActivity()
        guard let review = merges[importedID],
            (review.signInFields + review.urlFields).contains(where: { $0.id == fieldID })
        else { return }
        var current = accepted[importedID] ?? .none
        if isAccepted { current.fieldIDs.insert(fieldID) } else { current.fieldIDs.remove(fieldID) }
        accepted[importedID] = current
    }

    /// The decisions the session is given: one for every duplicate, none for the rest (added as new items).
    public var decisions: [UUID: ImportDecision] {
        var decisions: [UUID: ImportDecision] = [:]
        for (importedID, choice) in choices {
            switch choice {
            case .skip: decisions[importedID] = .skip
            case .keepBoth: decisions[importedID] = .keepBoth
            case .merge(let existingID):
                decisions[importedID] = .merge(into: existingID, accepting: accepted[importedID] ?? .none)
            }
        }
        return decisions
    }

    public func commit() async {
        guard let previewID, canCommit else {
            if !undecided.isEmpty { errorMessage = "Choose what to do with every duplicate first." }
            return
        }
        let decisions = self.decisions
        await perform {
            let outcome = try await context.session.commitImport(previewID, decisions: decisions)
            reset()
            stage = .done(
                ImportSummary(
                    created: outcome.created.count, merged: outcome.merged.count, skipped: outcome.skipped.count,
                    failed: outcome.failed.count))
        }
    }

    /// Drops the drafts the session holds and everything shown.
    public func cancel() async {
        await context.session.discardImport()
        reset()
        stage = .choose
    }

    private func reset() {
        previewID = nil
        entries = []
        duplicates = []
        reportLines = []
        choices = [:]
        merges = [:]
        accepted = [:]
        revealed = []
        hostAwaitingConfirmation = nil
        archiveCreatedAt = nil
    }

    private func show(_ preview: ImportPreview) async throws {
        reset()
        previewID = preview.id
        archiveCreatedAt = preview.archiveCreatedAt
        formatName = InterchangeWording.name(of: preview.report.format)
        let matched = Dictionary(grouping: preview.matches, by: \.importedID)
        entries = preview.entries.map { entry in
            ImportEntryRow(
                id: entry.id, title: entry.title.isEmpty ? "Untitled" : entry.title, hosts: entry.hosts,
                apexScopesAdded: entry.apexScopesAdded, loginNames: entry.loginNames,
                isDuplicate: matched[entry.id] != nil)
        }
        var existingTitles: [UUID: String] = [:]
        for id in Set(preview.matches.map(\.existingID)) {
            existingTitles[id] = (try? await context.session.item(id: id)).map {
                $0.title.isEmpty ? "Untitled" : $0.title
            }
        }
        duplicates = entries.filter(\.isDuplicate).map { entry in
            DuplicateRow(
                id: entry.id, title: entry.title, hosts: entry.hosts, loginNames: entry.loginNames,
                options: (matched[entry.id] ?? []).map { match in
                    DuplicateOption(
                        id: match.existingID, existingTitle: existingTitles[match.existingID] ?? "an existing item",
                        isIdentical: match.kind == .identical, newHosts: match.newHosts,
                        hasNewSignInFields: match.hasNewSignInFields, hasNewURLFields: match.hasNewURLFields)
                })
        }
        reportLines = Self.lines(preview.report)
        stage = .review
    }

    static func lines(_ report: ImportReport) -> [String] {
        var lines: [String] = []
        let counts = report.countsByKind.filter { $0.value > 0 }.sorted { $0.key.rawValue < $1.key.rawValue }
        if !counts.isEmpty {
            lines.append(
                "Read " + counts.map { "\($0.value) \(Self.kindName($0.key, count: $0.value))" }.joined(separator: ", ")
                    + ".")
        }
        lines += report.skipped.map(InterchangeWording.text(for:))
        lines += report.warnings.map(InterchangeWording.text(for:))
        if report.omittedWarningCount > 0 { lines.append("\(report.omittedWarningCount) more note(s) not shown.") }
        return lines
    }

    static func kindName(_ kind: ImportedKind, count: Int) -> String {
        let one: String
        switch kind {
        case .login: one = "login"
        case .password: one = "password"
        case .secureNote: one = "secure note"
        case .apiCredential: one = "API credential"
        case .bankAccount: one = "bank account"
        case .membership: one = "membership"
        case .passkey: one = "passkey"
        case .oneTimePassword: one = "one-time password"
        case .other: one = "other item"
        }
        return count == 1 ? one : one + "s"
    }

    private func perform(_ body: () async throws -> Void) async {
        isWorking = true
        defer { isWorking = false }
        errorMessage = await ScreenOperation(context: context).run(body)
    }
}
