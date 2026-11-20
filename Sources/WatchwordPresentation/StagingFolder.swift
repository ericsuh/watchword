import Foundation

/// The one place the app writes a file of its own for the system's file mover to take: a plaintext export, the
/// encrypted archive, the Emergency Kit PDF (PRD F5.1, F8.4; docs/02-architecture.md §14.1).
///
/// One fixed folder, `<temporary directory>/Watchword Staging/`, excluded from backups, with one sub-folder per staged
/// file. Every removal that depends on the process being alive (the mover's completion, a cancel, the screen closing,
/// a lock) removes that file's sub-folder; and the whole folder is swept independently of any model's state at launch
/// before any UI, at every lock and unlock, and at termination, so a copy left by a process that died while the mover
/// was up (a crash, a force quit, a jetsam kill, a power loss) is gone at the next launch at the latest. What a dead
/// process leaves until then is the file as written: with a protection class on iOS, none on macOS. The sweep also
/// removes the `Export-<UUID>` folders the export staged in directly under the temporary directory before this
/// folder existed (review §Z, Z80).
public struct StagingFolder: Sendable, Hashable {
    /// The folder's name under the temporary directory.
    public static let folderName = "Watchword Staging"
    /// The prefix of the folders an export was staged in before this one existed, directly in the temporary
    /// directory. Swept as well, so an upgrade does not leave one behind.
    static let earlierPrefix = "Export-"

    /// The temporary directory the folder is in.
    public let temporaryDirectory: URL
    /// The folder itself.
    public var url: URL { temporaryDirectory.appendingPathComponent(Self.folderName, isDirectory: true) }

    public init(temporaryDirectory: URL = FileManager.default.temporaryDirectory) {
        self.temporaryDirectory = temporaryDirectory
    }

    /// The process's own temporary directory.
    public static var standard: StagingFolder { StagingFolder() }

    /// Creates a sub-folder of its own for one file named `filename` and calls `write` with the file's URL, which
    /// must create the file there. Returns that URL. If `write` throws, nothing is left behind.
    ///
    /// The folder's own path is not trusted (review finding Z129): if `Watchword Staging` is anything but a real
    /// directory (a symbolic link someone who can write the temporary directory made, a file), it is removed and made
    /// again before anything is written, and nothing is created with intermediate directories. The temporary
    /// directory itself is the system's. A swap between the check and the write is not excluded.
    public func stage(named filename: String, write: (URL) throws -> Void) throws -> URL {
        try prepareFolder()
        let folder = url.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
        excludeFromBackup()
        let file = folder.appendingPathComponent(Self.safeName(filename), isDirectory: false)
        do {
            try write(file)
        } catch {
            try? FileManager.default.removeItem(at: folder)
            throw error
        }
        return file
    }

    /// Makes `url` a real directory of its own: whatever else is at the path (read without following a link) goes.
    private func prepareFolder() throws {
        let manager = FileManager.default
        // The system's own directory (or a test's), trusted as it is; made if it is missing.
        if Self.type(of: temporaryDirectory) == nil {
            try manager.createDirectory(at: temporaryDirectory, withIntermediateDirectories: true)
        }
        if let type = Self.type(of: url) {
            guard type != .typeDirectory else { return }
            try manager.removeItem(at: url)
        }
        try manager.createDirectory(at: url, withIntermediateDirectories: false)
        guard Self.type(of: url) == .typeDirectory else { throw CocoaError(.fileWriteUnknown) }
    }

    /// The type of what is at `url` itself, a link not followed; `nil` if nothing is.
    static func type(of url: URL) -> FileAttributeType? {
        (try? FileManager.default.attributesOfItem(atPath: url.path))?[.type] as? FileAttributeType
    }

    /// Removes one staged file with its sub-folder. A URL not staged here is left alone.
    public func remove(_ file: URL) {
        let folder = file.deletingLastPathComponent().standardizedFileURL
        guard folder.deletingLastPathComponent().standardizedFileURL.path == url.standardizedFileURL.path else {
            return
        }
        try? FileManager.default.removeItem(at: folder)
    }

    /// Removes everything staged, and any folder an earlier version staged in. Safe to call at any time; a file the
    /// mover is still presenting is removed with the rest (every caller drops that file at the same moment).
    public func sweep() {
        let manager = FileManager.default
        try? manager.removeItem(at: url)
        let leftovers = (try? manager.contentsOfDirectory(atPath: temporaryDirectory.path)) ?? []
        for name in leftovers where Self.isEarlierExport(name, in: temporaryDirectory) {
            try? manager.removeItem(at: temporaryDirectory.appendingPathComponent(name, isDirectory: true))
        }
    }

    /// A folder an earlier build staged an export in, and nothing else of that name (review finding Z129): exactly
    /// `Export-` and a UUID, a real directory holding one regular file. In an unsandboxed build the temporary
    /// directory is the user's, and another program's `Export-…` folder there is not ours to remove.
    static func isEarlierExport(_ name: String, in directory: URL) -> Bool {
        guard name.hasPrefix(earlierPrefix), UUID(uuidString: String(name.dropFirst(earlierPrefix.count))) != nil
        else { return false }
        let folder = directory.appendingPathComponent(name, isDirectory: true)
        guard type(of: folder) == .typeDirectory,
            let contents = try? FileManager.default.contentsOfDirectory(atPath: folder.path), contents.count == 1
        else { return false }
        return type(of: folder.appendingPathComponent(contents[0], isDirectory: false)) == .typeRegular
    }

    /// The staged files, for tests and for the launch check: every regular file under the folder.
    public func stagedFiles() -> [URL] {
        let manager = FileManager.default
        let folders = (try? manager.contentsOfDirectory(atPath: url.path)) ?? []
        return folders.flatMap { folder -> [URL] in
            let directory = url.appendingPathComponent(folder, isDirectory: true)
            let names = (try? manager.contentsOfDirectory(atPath: directory.path)) ?? []
            return names.map { directory.appendingPathComponent($0, isDirectory: false) }
        }
    }

    /// A file name with no path separator in it, so a name can never place the file outside its sub-folder.
    static func safeName(_ filename: String) -> String {
        let cleaned = filename.replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: "\\", with: "-")
        return cleaned.isEmpty || cleaned == "." || cleaned == ".." ? "Watchword file" : cleaned
    }

    /// Backups never take the folder: on iOS the temporary directory is not backed up anyway, and on macOS this keeps
    /// Time Machine off it whatever the system's own rules for temporary files become. Best effort.
    private func excludeFromBackup() {
        #if canImport(Darwin)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            var folder = url
            try? folder.setResourceValues(values)
        #endif
    }
}

/// Sweeps the staging folder on every lock of the session, whether or not any screen model that staged a file is
/// still alive (Z80). The app holds one for as long as it runs, registered with its `LockSignal`, and calls
/// `launched()` from its start, `sweep()` at every unlock and at termination.
///
/// The launch sweep is made once per process (review finding Z99): the app's start runs once per window, and a second
/// window opened while the first one's save sheet is up must not delete the file that sheet is presenting. A lock
/// still sweeps, and so loses a save whose sheet is up when it lands (architecture §14.1).
@MainActor
public final class StagingSweeper: LockSensitive {
    public let folder: StagingFolder
    private var hasLaunched = false

    public init(folder: StagingFolder = .standard, locks: LockSignal? = nil) {
        self.folder = folder
        locks?.register(self)
    }

    public func sweep() {
        folder.sweep()
    }

    /// The launch sweep: the first call sweeps, every later one (another window's start) does nothing.
    public func launched() {
        guard !hasLaunched else { return }
        hasLaunched = true
        folder.sweep()
    }

    public func dropOnLock() {
        folder.sweep()
    }
}
