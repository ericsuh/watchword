import Foundation
import Observation
import SecureMemory
import WatchwordInterchange
import WatchwordKit

/// The files the export screen makes (PRD F8.4). The CXF file is not offered yet: the format names the exporting
/// app's relying-party identifier, its associated domain, which the app does not have (an owner decision).
public enum ExportKind: String, Hashable, Sendable, CaseIterable, Identifiable {
    /// The encrypted Watchword archive: the backup, and the only export that is not plaintext.
    case archive
    case applePasswordsCSV
    case onePUX

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .archive: return "Encrypted Watchword archive"
        case .applePasswordsCSV: return "Apple Passwords CSV (not encrypted)"
        case .onePUX: return "1Password export, .1pux (not encrypted)"
        }
    }

    public var isPlaintext: Bool { self != .archive }

    /// The uniform type identifier of an encrypted archive, which both apps declare as an exported type
    /// (`Apps/project.yml`, `UTExportedTypeDeclarations`) so that a backup has a name and the restore screen's file
    /// picker offers backups only. The apps deliberately register no document type for it: nothing outside Watchword
    /// can hand it a file to open (owner decision, 2026-11-17; docs/02-architecture.md §14.1).
    public static let archiveTypeIdentifier = "com.ericsuh.watchword.backup"

    /// The archive's file name extension, the one tag of `archiveTypeIdentifier`.
    public static let archiveFileExtension = "watchwordbackup"

    public var fileExtension: String {
        switch self {
        case .archive: return Self.archiveFileExtension
        case .applePasswordsCSV: return "csv"
        case .onePUX: return "1pux"
        }
    }
}

/// A finished export, as the screen shows it. The bytes stay in the model, in zeroising memory, until
/// `ExportModel.stage` writes them where the system's file mover takes them, and go at `discardFile`.
public struct ExportFile: Hashable, Sendable {
    /// One export: a new one is a new file even with the same report.
    public let id: UUID
    public let kind: ExportKind
    public let filename: String
    public let itemCount: Int
    /// The report, one line per warning, naming items by title (`ExportReport`); for the archive, nothing is lost.
    public let lines: [String]
    /// Items in the chosen vaults that would not open and so are not in the file.
    public let unreadableCount: Int
}

/// Export and backup (PRD F8.4, F8.5; docs/02-architecture.md §14.1). The account password is asked for every time
/// and checked by the session in the same call; the plaintext warning stands for as long as the screen is open; and
/// the report is shown before the file is saved, since it is what the person reads before deleting anything. The CSV
/// is every value exactly as stored (owner decision, 2026-11-16: no formula neutralisation, the file is for another
/// password manager's importer).
@MainActor
@Observable
public final class ExportModel: LockSensitive {
    /// The standing warning (`InterchangeGuide.plaintextExportWarning`).
    public static let plaintextWarning = VaultSession.plaintextExportWarning

    public var kind: ExportKind = .archive
    public private(set) var vaults: [VaultRow] = []
    public var selectedVaults: Set<UUID> = []
    public var password = ""
    public var passphrase = ""
    public var passphraseConfirmation = ""
    public private(set) var file: ExportFile?
    public private(set) var isWorking = false
    public var errorMessage: String?

    private let context: ScreenContext
    private let now: @Sendable () -> Date
    /// The file's bytes: plaintext for every format but the archive. Zeroised by `discardFile`.
    private var contents: SecureBytes?
    /// Where `stage` wrote them, until the file mover has taken them or the export is dropped.
    private var stagingDirectory: URL?

    public init(context: ScreenContext, now: @escaping @Sendable () -> Date = { Date() }) {
        self.context = context
        self.now = now
        context.locks?.register(self)
    }

    /// On every lock: the bytes, any staged copy and the typed password and passphrase go (finding 6).
    public func dropOnLock() {
        discardFile()
        password = ""
        passphrase = ""
        passphraseConfirmation = ""
    }

    /// Whether the model still holds a file's bytes (for tests: the bytes themselves never leave but by `stage`).
    public var holdsContents: Bool { contents != nil }

    /// Why the export cannot run yet, or `nil`.
    public var problem: String? {
        if selectedVaults.isEmpty { return "Choose at least one vault." }
        if password.isEmpty { return "Enter your account password." }
        if kind == .archive {
            if passphrase.count < VaultConfiguration.minimumPasswordLength {
                return "Use an archive passphrase of at least \(VaultConfiguration.minimumPasswordLength) characters."
            }
            if passphrase != passphraseConfirmation { return "The passphrases do not match." }
        }
        return nil
    }

    public func load() async {
        await perform {
            vaults = try await VaultRow.load(from: context.session)
            if selectedVaults.isEmpty { selectedVaults = Set(vaults.map(\.id)) }
        }
    }

    public func export() async {
        if let problem {
            errorMessage = problem
            return
        }
        let vaultIDs = vaults.map(\.id).filter(selectedVaults.contains)
        let password = self.password
        let passphrase = self.passphrase
        let kind = self.kind
        // Typed secrets go as soon as they are handed over, whatever the outcome.
        self.password = ""
        self.passphrase = ""
        passphraseConfirmation = ""
        discardFile()
        await perform {
            let session = context.session
            let stamp = Self.stamp(self.now())
            switch kind {
            case .archive:
                let archive = try await session.exportArchive(
                    vaults: vaultIDs, passphrase: passphrase, password: password)
                var bytes = archive.bytes
                contents = SecureBytes(wiping: &bytes)
                file = ExportFile(
                    id: UUID(), kind: kind, filename: "Watchword Backup \(stamp).\(kind.fileExtension)",
                    itemCount: archive.itemCount, lines: [], unreadableCount: archive.unreadable.count)
            case .applePasswordsCSV, .onePUX:
                let format: PlaintextExportFormat = kind == .onePUX ? .onePUX : .applePasswordsCSV
                let export = try await session.exportPlaintext(format, vaults: vaultIDs, password: password)
                let titles = try await Self.titles(session)
                var bytes = export.bytes
                contents = SecureBytes(wiping: &bytes)
                file = ExportFile(
                    id: UUID(), kind: kind, filename: "Watchword Export \(stamp).\(kind.fileExtension)",
                    itemCount: export.report.exportedCount,
                    lines: export.report.warnings.map { InterchangeWording.text(for: $0, titles: titles) },
                    unreadableCount: export.unreadable.count)
            }
        }
    }

    /// Writes the file into a new directory of its own under `directory`, with `options` (on iOS the app passes
    /// `.completeFileProtectionUnlessOpen`, so the file is never readable at rest while the device is locked), for the
    /// system's file mover to take where the person chooses. Returns the file's URL. The staged copy is removed by
    /// `finishSaving` or `discardFile`, whichever comes first (PRD F8.4; review of the account screens, finding 5).
    public func stage(in directory: URL, options: Data.WritingOptions) throws -> URL {
        guard let contents, let file else { throw CocoaError(.fileNoSuchFile) }
        removeStagedCopy()
        let folder = directory.appendingPathComponent("Export-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        stagingDirectory = folder
        let url = folder.appendingPathComponent(file.filename, isDirectory: false)
        try Data(contents.unprotectedCopy()).write(to: url, options: options.union(.withoutOverwriting))
        return url
    }

    /// After the file mover: whatever is left of the staged copy is removed, and once the file was saved its bytes go.
    public func finishSaving(saved: Bool) {
        removeStagedCopy()
        if saved { discardFile() }
    }

    /// The archive's bytes, which are ciphertext, for the UI-test hook that restores the archive just made. `nil` for a
    /// plaintext export, whose bytes never leave the model but through `stage`.
    public var archiveBytes: [UInt8]? {
        guard file?.kind == .archive else { return nil }
        return contents?.unprotectedCopy()
    }

    /// Drops the file: its bytes zeroised, any staged copy removed. Once saved, on cancel, when the screen closes,
    /// and on every lock.
    public func discardFile() {
        removeStagedCopy()
        contents?.zeroise()
        contents = nil
        file = nil
    }

    private func removeStagedCopy() {
        if let stagingDirectory { try? FileManager.default.removeItem(at: stagingDirectory) }
        stagingDirectory = nil
    }

    static func titles(_ session: VaultSession) async throws -> [UUID: String] {
        Dictionary(
            try await session.items().items.map { ($0.id, $0.title.isEmpty ? "Untitled" : $0.title) },
            uniquingKeysWith: { first, _ in first })
    }

    /// `2026-11-16`, in UTC: a file name, so the same everywhere.
    public static func stamp(_ date: Date) -> String {
        let days = Int((date.timeIntervalSince1970 / 86_400).rounded(.down))
        // Civil date from days since 1970 (Howard Hinnant's algorithm), to avoid a locale-dependent formatter.
        let z = days + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let day = doy - (153 * mp + 2) / 5 + 1
        let month = mp < 10 ? mp + 3 : mp - 9
        let year = yoe + era * 400 + (month <= 2 ? 1 : 0)
        func two(_ value: Int) -> String { value < 10 ? "0\(value)" : "\(value)" }
        return "\(year)-\(two(month))-\(two(day))"
    }

    private func perform(_ body: () async throws -> Void) async {
        isWorking = true
        defer { isWorking = false }
        errorMessage = await ScreenOperation(context: context).run(body)
    }
}
