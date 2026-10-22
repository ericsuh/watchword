import Foundation

/// A transport over a directory: each object is one file, `<root>/<name>.wwe` (docs/02-architecture.md §7.3).
///
/// Files are immutable once written. `create` writes a hidden temporary file beside the target and hard-links it into
/// place, which fails if the target exists, so two writers can never interleave into one file and an existing object
/// is never replaced — the property that removes the single-file conflict problem of KeePass-style sync.
///
/// The directory is shared with whatever else can write to it: the file provider, other members of a shared folder
/// (milestone 4), anyone with the cloud account (A1). So names are checked on the way in and the way out (only the
/// layout's own characters, no dot-files, no `..`), no path component may be a symbolic link — a planted link would
/// otherwise redirect a read to an arbitrary local file or a write outside the root — and a file larger than the
/// caller's limit is refused before it is read (SEC9).
///
/// This is the portable core. On iCloud Drive every access must also go through `NSFileCoordinator`, with an
/// `NSFilePresenter` for change notification and a reconciliation pass on wake; on other providers the root comes from
/// a security-scoped bookmark. Those wrappers are Apple-only and belong to milestone 3's Mac half.
public struct FileSyncTransport: SyncTransport {
    public static let fileExtension = "wwe"

    public let root: URL

    public init(root: URL) {
        self.root = root
    }

    public func list(prefix: String) async throws -> [String] {
        // Walk only the deepest directory the prefix names, then filter by the full prefix.
        let directoryComponents = prefix.split(separator: "/", omittingEmptySubsequences: false).dropLast().map(
            String.init)
        guard directoryComponents.allSatisfy(Self.isValidComponent) else {
            throw SyncTransportError.invalidName(prefix)
        }
        let start = directoryComponents.reduce(root) { $0.appendingPathComponent($1, isDirectory: true) }
        guard try Self.kind(of: start) == .directory else { return [] }
        var names: [String] = []
        try walk(start, relative: directoryComponents, into: &names)
        return names.filter { $0.hasPrefix(prefix) }.sorted()
    }

    private func walk(_ directory: URL, relative: [String], into names: inout [String]) throws {
        let entries = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        for entry in entries where Self.isValidComponent(entry) || entry.hasSuffix("." + Self.fileExtension) {
            let url = directory.appendingPathComponent(entry)
            switch try Self.kind(of: url) {
            case .directory where Self.isValidComponent(entry):
                try walk(url, relative: relative + [entry], into: &names)
            case .file where entry.hasSuffix("." + Self.fileExtension):
                let stem = String(entry.dropLast(Self.fileExtension.count + 1))
                if Self.isValidComponent(stem) { names.append((relative + [stem]).joined(separator: "/")) }
            default:
                continue  // Symbolic links, temporaries, anything else: not an object.
            }
        }
    }

    public func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        let url = try fileURL(for: name)
        switch try Self.kind(of: url) {
        case .missing: return nil
        case .file: break
        default: throw SyncTransportError.invalidName(name)
        }
        let size = (try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.intValue ?? 0
        guard size <= maximumLength else { throw SyncTransportError.objectTooLarge(name) }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        // Read at most one byte past the limit, in case the file grew after the size check.
        let data = try handle.read(upToCount: maximumLength + 1) ?? Data()
        guard data.count <= maximumLength else { throw SyncTransportError.objectTooLarge(name) }
        return Array(data)
    }

    public func create(_ name: String, contents: [UInt8]) async throws {
        let url = try fileURL(for: name)
        let directory = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        _ = try fileURL(for: name)  // Re-check: no component became a link while the directories were created.
        let temporary = directory.appendingPathComponent(".tmp-\(UUID().uuidString)")
        try Data(contents).write(to: temporary)
        defer { try? FileManager.default.removeItem(at: temporary) }
        do {
            try FileManager.default.linkItem(at: temporary, to: url)
        } catch {
            if try Self.kind(of: url) != .missing { throw SyncTransportError.objectExists(name) }
            throw error
        }
    }

    public func delete(_ name: String) async throws {
        let url = try fileURL(for: name)
        switch try Self.kind(of: url) {
        case .missing: return
        case .file: try FileManager.default.removeItem(at: url)
        default: throw SyncTransportError.invalidName(name)
        }
    }

    // MARK: - Paths

    /// The file for `name`, after checking every component of the name and that no existing directory on the way is a
    /// symbolic link.
    func fileURL(for name: String) throws -> URL {
        let components = name.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard !components.isEmpty, components.allSatisfy(Self.isValidComponent) else {
            throw SyncTransportError.invalidName(name)
        }
        var url = root
        for component in components.dropLast() {
            url.appendPathComponent(component, isDirectory: true)
            switch try Self.kind(of: url) {
            case .missing, .directory: continue
            default: throw SyncTransportError.invalidName(name)
            }
        }
        return url.appendingPathComponent(components.last! + "." + Self.fileExtension, isDirectory: false)
    }

    /// Letters, digits and `-` only: the characters of the layout's UUIDs and numbers. Rules out `.`, `..`, hidden
    /// files, separators and anything a file system might normalise.
    static func isValidComponent(_ component: String) -> Bool {
        !component.isEmpty && component.utf8.count <= 64
            && component.utf8.allSatisfy { byte in
                (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
                    || byte == 0x2D
            }
    }

    enum ItemKind {
        case missing, file, directory, other
    }

    /// What is at `url`, without following a symbolic link in the last component (`attributesOfItem` does not
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
