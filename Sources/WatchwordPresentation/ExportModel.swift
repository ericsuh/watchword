import Foundation
import Observation
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

    public var fileExtension: String {
        switch self {
        case .archive: return "wwarchive"
        case .applePasswordsCSV: return "csv"
        case .onePUX: return "1pux"
        }
    }
}

/// A finished export: the bytes for the system's file exporter, and what the screen shows about them.
public struct ExportFile: Hashable, Sendable {
    public let bytes: [UInt8]
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
public final class ExportModel {
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

    public init(context: ScreenContext, now: @escaping @Sendable () -> Date = { Date() }) {
        self.context = context
        self.now = now
    }

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
            vaults = try await context.session.vaults().map { VaultRow($0, sharing: nil) }
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
        file = nil
        await perform {
            let session = context.session
            let stamp = Self.stamp(self.now())
            switch kind {
            case .archive:
                let archive = try await session.exportArchive(
                    vaults: vaultIDs, passphrase: passphrase, password: password)
                file = ExportFile(
                    bytes: archive.bytes, kind: kind, filename: "Watchword Backup \(stamp).\(kind.fileExtension)",
                    itemCount: archive.itemCount, lines: [], unreadableCount: archive.unreadable.count)
            case .applePasswordsCSV, .onePUX:
                let format: PlaintextExportFormat = kind == .onePUX ? .onePUX : .applePasswordsCSV
                let export = try await session.exportPlaintext(format, vaults: vaultIDs, password: password)
                let titles = try await Self.titles(session)
                file = ExportFile(
                    bytes: export.bytes, kind: kind, filename: "Watchword Export \(stamp).\(kind.fileExtension)",
                    itemCount: export.report.exportedCount,
                    lines: export.report.warnings.map { InterchangeWording.text(for: $0, titles: titles) },
                    unreadableCount: export.unreadable.count)
            }
        }
    }

    /// Drops the file's bytes: once saved, or when the screen closes.
    public func discardFile() {
        file = nil
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
