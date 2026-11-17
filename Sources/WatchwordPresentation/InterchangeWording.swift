import Foundation
import WatchwordInterchange

/// How the import and export screens word what the interchange core reports (PRD F8.1–F8.5). Every line names the
/// entry or item it is about: a report is read before anything is deleted from the app being left.
public enum InterchangeWording {
    public static func name(of format: InterchangeFormat) -> String {
        switch format {
        case .onePassword8CSV: return "1Password 8 CSV"
        case .onePassword7CSV: return "1Password 7 CSV"
        case .applePasswordsCSV: return "Apple Passwords CSV"
        case .onePUX: return "1Password export (.1pux)"
        case .credentialExchange: return "Credential Exchange (CXF)"
        case .watchwordArchive: return "Encrypted Watchword archive"
        }
    }

    static func entry(_ reference: ImportEntryReference) -> String {
        if !reference.title.isEmpty { return "“\(reference.title)”" }
        if let line = reference.line { return "The entry on line \(line)" }
        return "Entry \(reference.index)"
    }

    public static func text(for record: ImportWarningRecord) -> String {
        entry(record.entry) + ": " + text(for: record.warning)
    }

    public static func text(for record: ImportSkipRecord) -> String {
        entry(record.entry) + " was not imported: " + text(for: record.reason)
    }

    static func text(for warning: ImportWarning) -> String {
        switch warning {
        case .scopeRefused(let url, _):
            return "\(url) is not a website AutoFill can use; it was kept as a URL field."
        case .unusableOneTimePassword(let label, _):
            return "\(label) is not a usable one-time password; it was kept as a concealed field."
        case .passkeyRefused: return "its passkey could not be stored and was left out."
        case .passkeyDetailDropped(let detail): return "part of its passkey was left out (\(detail))."
        case .unsupportedCredentialType(let type): return "\(type) was kept as fields."
        case .unsupportedFieldType(let label, _): return "\(label) was kept as text, or left out if it had none."
        case .attachmentNotImported(let name): return "the attachment \(name) was not imported."
        case .linkedItemNotImported(let label): return "the link \(label) to another item was not imported."
        case .unknownState: return "its state was not recognised; it was imported as active."
        case .implausibleDate(let label): return "the date \(label) was implausible and was ignored."
        case .urlsNotConsidered(let count): return "\(count) more URL(s) were kept as fields, not websites."
        case .androidAppsNotImported(let count): return "\(count) Android app(s) were left out."
        case .titleDerived: return "it had no title; one was made from its website or user name."
        case .apexScopeAdded(let wwwHost, let apex):
            return "\(apex) was added beside \(wwwHost), so the item is also offered there."
        case .unresolvedValuesKept(let count):
            return "\(count) unresolved value(s) were kept as concealed fields."
        case .unresolvedValuesOmitted(let count): return "\(count) unresolved value(s) were left out."
        case .restoredFromSyncTrash:
            return "it was in the trash only because of sync, not by choice, and was imported as a live item."
        }
    }

    static func text(for reason: ImportSkipReason) -> String {
        switch reason {
        case .tooLarge: return "it is larger than an item can be."
        case .duplicateIdentifier: return "an earlier entry has the same identifier."
        case .trashedAtSource: return "it was in the other app's trash."
        case .empty: return "it held nothing."
        case .columnCountMismatch(let expected, let found):
            return "it has \(found) columns where \(expected) were expected."
        case .malformed: return "it is not shaped like an entry of this format."
        case .nothingImportable: return "nothing in it could be imported."
        }
    }

    /// One line per export warning, naming the item by `titles` (item ID to title).
    public static func text(for warning: ExportWarning, titles: [UUID: String]) -> String {
        func item(_ id: UUID) -> String { titles[id].map { "“\($0)”" } ?? "An item" }
        switch warning {
        case .passkeyOmitted(let id): return item(id) + ": its passkey was left out; this format has no place for one."
        case .passkeyUnreadable(let id): return item(id) + ": its passkey could not be read and was left out."
        case .fieldsMovedToNotes(let id, let count):
            return item(id) + ": \(count) field(s) were written into the notes."
        case .trashedItemOmitted(let id): return item(id) + " is in the Trash and was left out."
        case .oneTimePasswordUnusable(let id):
            return item(id) + ": its one-time password was written as a concealed field."
        case .unresolvedValuesAdded(let id, let count):
            return item(id) + ": \(count) unresolved value(s) were written as extra fields."
        case .unresolvedValuesOmitted(let id, let count):
            return item(id) + ": \(count) unresolved value(s) were left out; only the one shown was written."
        case .historyOmitted(let id, let entries):
            return item(id) + ": \(entries) earlier version(s) were left out."
        case .scopeRestrictionOmitted(let id, let host):
            return item(id) + ": the file cannot say that \(host) excludes subdomains; it will be offered on them."
        case .websiteNotScoped(let id, let count):
            return item(id) + ": \(count) URL(s) were written as fields, not websites."
        case .archivedStateOmitted(let id): return item(id) + " is archived; the file marks it as active."
        case .tagsOmitted(let id): return item(id) + ": its tags were left out."
        case .fieldDetailOmitted(let id, let label): return item(id) + ": part of \(label) was left out."
        }
    }
}
