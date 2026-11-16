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
/// - **Atomic writes** (`Data.WritingOptions.atomic`: a temporary file renamed over the record), so a crash leaves the
///   old record or the new one, never half of one. A symbolic link planted under a record's name is removed first, so
///   the write never follows it.
/// - **Fail-closed reads** (A8, who can write these files while the app is locked): only a regular file is read, never
///   through a link, and never more than `maximumRecordLength` bytes; anything else throws. A planted or damaged file
///   that passes those checks is still only bytes, which the session opens under its key and context or ignores.
/// - A store directory replaced by a link is refused for reading and writing, and `deleteAll` removes the link without
///   touching what it points to. The directory is created owner-only (0700).
///
/// A link swapped in between the check and the read is not caught (Foundation offers no `O_NOFOLLOW` open, as in
/// `FileSyncTransport`); the read is still capped and what it returns is still opened under the key or ignored.
///
/// Portable apart from the backup flag and the protection class, which exist only on Apple platforms, so its logic and
/// its adversarial suite ("device-local store files") also run under `swift test` on Linux.
public struct FileDeviceLocalStore: DeviceLocalStore {
    public static let fileExtension = "wwl"
    /// Above the largest record the session reads (the scan ledger, 48 MiB of plaintext, and its envelope).
    public static let defaultMaximumRecordLength = 49 << 20

    public let directory: URL
    public let maximumRecordLength: Int

    public init(directory: URL, maximumRecordLength: Int = FileDeviceLocalStore.defaultMaximumRecordLength) {
        self.directory = directory
        self.maximumRecordLength = maximumRecordLength
    }

    /// `<directory>/<UUID>.wwl`. A UUID's canonical string has only hexadecimal digits and dashes, so no name can
    /// leave the directory.
    public func fileURL(for name: UUID) -> URL {
        directory.appendingPathComponent(name.uuidString + "." + Self.fileExtension, isDirectory: false)
    }

    public func read(_ name: UUID) async throws -> [UInt8]? {
        switch try Self.kind(of: directory) {
        case .missing: return nil
        case .directory: break
        case .file, .other: throw DeviceLocalFileError.directoryReplaced
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
        switch try Self.kind(of: url) {
        case .missing, .file:
            break
        case .directory:
            // A directory planted under the name would make the rename fail anyway; say why.
            throw DeviceLocalFileError.notARegularFile(name)
        case .other:
            // A planted link goes first: an atomic write may resolve a link and replace its target instead.
            try FileManager.default.removeItem(at: url)
        }
        try Data(bytes).write(to: url, options: Self.writingOptions)
        try Self.excludeFromBackup(&url)
    }

    public func delete(_ names: [UUID]) async throws {
        guard try Self.kind(of: directory) == .directory else { return }
        for name in names {
            let url = fileURL(for: name)
            // Whatever is under the name goes, a planted link included (the link, never its target).
            if try Self.kind(of: url) != .missing { try FileManager.default.removeItem(at: url) }
        }
    }

    /// Removes the directory and everything in it, whatever was planted there. A link in the directory's place is
    /// removed as a link.
    public func deleteAll() async throws {
        if try Self.kind(of: directory) != .missing { try FileManager.default.removeItem(at: directory) }
    }

    // MARK: - Directory

    /// Creates the directory if it is missing (owner-only, protected, excluded from backup) and refuses one that is not
    /// a directory. The backup flag is set again each time, in case something cleared it.
    private func prepareDirectory() throws {
        switch try Self.kind(of: directory) {
        case .directory:
            break
        case .missing:
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true, attributes: Self.directoryAttributes)
            guard try Self.kind(of: directory) == .directory else { throw DeviceLocalFileError.directoryReplaced }
        case .file, .other:
            throw DeviceLocalFileError.directoryReplaced
        }
        var url = directory
        try Self.excludeFromBackup(&url)
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
            return [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
        #else
            return [.atomic]
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
