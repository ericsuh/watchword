import Foundation
import WatchwordKit

/// Why the file adapter refused a record. The session reads every failure as "no record" (an empty ledger, a cache
/// miss), which is the safe reading: everything is then due for a check (docs/02-architecture.md §13.8).
public enum DeviceLocalFileError: Error, Equatable, Sendable {
    /// The store's directory is not a directory: a symbolic link, a file or anything else put in its place.
    case directoryReplaced
    /// What is under a record's name is not a regular file (a link, a directory).
    case notARegularFile(UUID)
    /// The record is larger than any record the session writes: refused before it is read.
    case recordTooLarge(UUID)
}

/// The production `DeviceLocalStore` (docs/02-architecture.md §13.8): one file per record in a directory of its own in
/// the App Group container (`AppContainer.deviceLocalStoreURL`), on this device only.
///
/// What it holds is already sealed under the device-local key and named by keyed digests, so the adapter stores opaque
/// bytes under opaque names and decides nothing about them. Its job is the file system's part of "this device only,
/// and never trusted":
///
/// - **Excluded from backup** (`isExcludedFromBackup`, on the directory and on every file written): a backup restored
///   onto other hardware arrives without the device secret, so its records could not open anyway, and nothing in a
///   backup is anyone's business.
/// - **`completeUntilFirstUserAuthentication`** file protection on iOS, on the directory and on every write: hygiene
///   runs only with the vault unlocked, but the device may be locked while it does (a background task). macOS has no
///   per-file protection class for this; FileVault protects it at rest.
/// - **Writes never through a link**: the bytes go to a new temporary file in the directory, created exclusively
///   (`withoutOverwriting`, `O_EXCL`, so not even a link planted under its random name is followed), which is then
///   moved into place; a move renames a directory entry and never follows a link at the destination. Whatever is under
///   the record's name (the old record, or a link A8 planted) is removed first, so a crash between the two leaves no
///   record, which the session reads as none: the safe reading. A link planted again in that moment makes the move
///   fail, and nothing is written.
/// - **Fail-closed reads** (A8, who can write these files while the app is locked): only a regular file is read, never
///   through a link, and never more than `maximumRecordLength` bytes; anything else throws. A planted or damaged file
///   that passes those checks is still only bytes, which the session opens under its key and context or ignores.
/// - **The whole path is checked.** The directory is `components` below a trusted `ancestor` (the App Group container,
///   its own links resolved once at `init`); every component below it must be a real directory or not exist yet, at
///   every operation. A link anywhere on that path is refused for reading and writing, and `deleteAll` removes a link
///   in the store directory's place without touching what it points to. The directory is owner-only (0700), set again
///   before every write in case something widened it.
///
/// A link swapped in between the checks and the read is not caught (Foundation offers no `O_NOFOLLOW` open, as in
/// `FileSyncTransport`); the read is still capped and what it returns is still opened under the key or ignored.
///
/// Portable apart from the backup flag and the protection class, which exist only on Apple platforms, so its logic and
/// its adversarial suite ("device-local store files") also run under `swift test` on Linux.
public struct FileDeviceLocalStore: DeviceLocalStore {
    public static let fileExtension = "wwl"
    /// Above the largest record the session reads (the scan ledger, 48 MiB of plaintext, and its envelope).
    public static let defaultMaximumRecordLength = 49 << 20

    /// The trusted directory the store lives below, its links resolved.
    public let ancestor: URL
    /// The path from `ancestor` to the store's directory, one name per component.
    public let components: [String]
    public let directory: URL
    public let maximumRecordLength: Int

    /// The store in `ancestor/components…`. Every component must be a plain name (not empty, `.` or `..`, no `/`);
    /// one that is not is dropped, so the directory can never be outside `ancestor`.
    public init(
        ancestor: URL, components: [String],
        maximumRecordLength: Int = FileDeviceLocalStore.defaultMaximumRecordLength
    ) {
        self.ancestor = ancestor.resolvingSymlinksInPath()
        let checked = components.filter { !$0.isEmpty && $0 != "." && $0 != ".." && !$0.contains("/") }
        self.components = checked
        directory = checked.reduce(self.ancestor) { $0.appendingPathComponent($1, isDirectory: true) }
        self.maximumRecordLength = maximumRecordLength
    }

    /// The store in `directory`, below its parent as the trusted ancestor.
    public init(directory: URL, maximumRecordLength: Int = FileDeviceLocalStore.defaultMaximumRecordLength) {
        self.init(
            ancestor: directory.deletingLastPathComponent(), components: [directory.lastPathComponent],
            maximumRecordLength: maximumRecordLength)
    }

    /// `<directory>/<UUID>.wwl`. A UUID's canonical string has only hexadecimal digits and dashes, so no name can
    /// leave the directory.
    public func fileURL(for name: UUID) -> URL {
        directory.appendingPathComponent(name.uuidString + "." + Self.fileExtension, isDirectory: false)
    }

    public func read(_ name: UUID) async throws -> [UInt8]? {
        switch try pathState() {
        case .missing: return nil
        case .replaced: throw DeviceLocalFileError.directoryReplaced
        case .present: break
        }
        let url = fileURL(for: name)
        switch try Self.kind(of: url) {
        case .missing: return nil
        case .file: break
        case .directory, .other: throw DeviceLocalFileError.notARegularFile(name)
        }
        let size = (try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.intValue ?? 0
        guard size <= maximumRecordLength else { throw DeviceLocalFileError.recordTooLarge(name) }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        // One byte past the limit, in case the file grew after the size check.
        let data = try handle.read(upToCount: maximumRecordLength + 1) ?? Data()
        guard data.count <= maximumRecordLength else { throw DeviceLocalFileError.recordTooLarge(name) }
        return Array(data)
    }

    public func write(_ bytes: [UInt8], as name: UUID) async throws {
        guard bytes.count <= maximumRecordLength else { throw DeviceLocalFileError.recordTooLarge(name) }
        try prepareDirectory()
        var url = fileURL(for: name)
        // A directory planted under the name would make the move fail anyway; say why.
        if try Self.kind(of: url) == .directory { throw DeviceLocalFileError.notARegularFile(name) }
        let temporary = directory.appendingPathComponent(".tmp-\(UUID().uuidString)", isDirectory: false)
        try Data(bytes).write(to: temporary, options: Self.writingOptions)
        defer { try? FileManager.default.removeItem(at: temporary) }
        if try Self.kind(of: url) != .missing { try FileManager.default.removeItem(at: url) }
        try FileManager.default.moveItem(at: temporary, to: url)
        try Self.excludeFromBackup(&url)
    }

    public func delete(_ names: [UUID]) async throws {
        guard try pathState() == .present else { return }
        for name in names {
            let url = fileURL(for: name)
            // Whatever is under the name goes, a planted link included (the link, never its target).
            if try Self.kind(of: url) != .missing { try FileManager.default.removeItem(at: url) }
        }
    }

    /// Removes the directory and everything in it, whatever was planted there. A link in the directory's place is
    /// removed as a link.
    public func deleteAll() async throws {
        // A link above the directory: nothing of the store's is there to remove, and nothing is removed through it.
        guard try pathState(includingDirectory: false) != .replaced else { return }
        if try Self.kind(of: directory) != .missing { try FileManager.default.removeItem(at: directory) }
    }

    // MARK: - Directory

    enum PathState {
        case missing, present, replaced
    }

    /// Whether every component from `ancestor` to the store's directory is a real directory (`present`), the path
    /// stops at one that does not exist yet (`missing`), or something else stands on it (`replaced`).
    func pathState(includingDirectory: Bool = true) throws -> PathState {
        guard try Self.kind(of: ancestor) == .directory else { return .missing }
        var url = ancestor
        let checked = includingDirectory ? components : Array(components.dropLast())
        for component in checked {
            url.appendPathComponent(component, isDirectory: true)
            switch try Self.kind(of: url) {
            case .directory: continue
            case .missing: return .missing
            case .file, .other: return .replaced
            }
        }
        return .present
    }

    /// Creates whatever of the path is missing, one component at a time with each checked first (the store's own
    /// directory owner-only, protected, excluded from backup), and refuses a path with anything but directories on
    /// it. The permissions and the backup flag are set again each time, in case something changed them. Excluding the
    /// directory from backup excludes what it holds; each record is marked as well.
    private func prepareDirectory() throws {
        // The ancestor is trusted (the App Group container, or a test's temporary directory): created if missing.
        if try Self.kind(of: ancestor) == .missing {
            try FileManager.default.createDirectory(at: ancestor, withIntermediateDirectories: true)
        }
        var url = ancestor
        for (index, component) in components.enumerated() {
            url.appendPathComponent(component, isDirectory: true)
            let isStore = index == components.count - 1
            switch try Self.kind(of: url) {
            case .directory:
                break
            case .missing:
                try FileManager.default.createDirectory(
                    at: url, withIntermediateDirectories: false,
                    attributes: isStore ? Self.directoryAttributes : [:])
                guard try Self.kind(of: url) == .directory else { throw DeviceLocalFileError.directoryReplaced }
            case .file, .other:
                throw DeviceLocalFileError.directoryReplaced
            }
        }
        try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: 0o700)], ofItemAtPath: directory.path)
        var directoryURL = directory
        try Self.excludeFromBackup(&directoryURL)
    }

    private static var directoryAttributes: [FileAttributeKey: Any] {
        var attributes: [FileAttributeKey: Any] = [.posixPermissions: NSNumber(value: 0o700)]
        #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
            attributes[.protectionKey] = FileProtectionType.completeUntilFirstUserAuthentication
        #endif
        return attributes
    }

    static var writingOptions: Data.WritingOptions {
        #if os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
            return [.withoutOverwriting, .completeFileProtectionUntilFirstUserAuthentication]
        #else
            return [.withoutOverwriting]
        #endif
    }

    private static func excludeFromBackup(_ url: inout URL) throws {
        #if canImport(Darwin)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try url.setResourceValues(values)
        #endif
    }

    enum ItemKind {
        case missing, file, directory, other
    }

    /// What is at `url`, without following a symbolic link in its last component (`attributesOfItem` does not
    /// traverse one).
    static func kind(of url: URL) throws -> ItemKind {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path) else {
            return FileManager.default.fileExists(atPath: url.path) ? .other : .missing
        }
        switch attributes[.type] as? FileAttributeType {
        case .typeRegular?: return .file
        case .typeDirectory?: return .directory
        default: return .other
        }
    }
}
