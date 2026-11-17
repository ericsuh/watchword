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
/// A link swapped in between the check and the read of a file is not caught (Foundation offers no `O_NOFOLLOW` open);
/// the read is still capped, and what it returns is still checked like anything else from a transport.
///
/// **Renamed duplicates.** A file provider that receives a second file under a name it already holds keeps both and
/// renames one: iCloud Drive calls it `<name> 2.wwe` (then 3, and so on). Such a file is a *copy* of the object
/// `<name>`, never an object of its own (a space is not in the layout's alphabet): `listingNow` counts it,
/// `fetchCopiesNow` reads it after the file itself, and `deleteNow` removes it with the object. Only the numbers 2 to
/// `maximumDuplicateNumber` are attributed, so reading the copies of a name is a bounded number of look-ups, never a
/// scan. Which copy is genuine is not decided here (docs/02-architecture.md §7.5, "Conflict copies").
///
/// This is the portable core. On iCloud Drive every access also goes through `NSFileCoordinator`, with an
/// `NSFilePresenter` for change notification: `WatchwordPlatform.CoordinatedFileSyncTransport`, which runs the
/// synchronous forms below (`listNow`, `fetchNow`, `createNow`, `deleteNow`) inside the coordinator's accessor, so
/// every rule about names, links and sizes stays here, where Linux tests reach it. On other providers the root comes
/// from a security-scoped bookmark (not built).
public struct FileSyncTransport: SyncTransport {
    public static let fileExtension = "wwe"
    /// The suffix of iCloud Drive's legacy placeholder for a file not yet downloaded: `.<name>.icloud` beside where
    /// `<name>` will be (docs/02-architecture.md §7.3).
    public static let placeholderSuffix = "icloud"

    public let root: URL
    /// Whether a not-yet-downloaded iCloud placeholder (`.<stem>.wwe.icloud`) is listed as the object `<stem>`. Only
    /// the listing changes: `fetchNow` still finds no file there, and the coordinated wrapper asks for the download.
    public let listsUbiquityPlaceholders: Bool

    public init(root: URL, listsUbiquityPlaceholders: Bool = false) {
        self.root = root
        self.listsUbiquityPlaceholders = listsUbiquityPlaceholders
    }

    public func list(prefix: String) async throws -> [String] {
        try listNow(prefix: prefix)
    }

    public func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        try fetchNow(name, maximumLength: maximumLength)
    }

    public func create(_ name: String, contents: [UInt8]) async throws {
        try createNow(name, contents: contents)
    }

    public func delete(_ name: String) async throws {
        try deleteNow(name)
    }

    public func listWithCopies(prefix: String) async throws -> SyncListing {
        try listingNow(prefix: prefix)
    }

    public func fetchCopies(_ name: String, maximumLength: Int, maximumCopies: Int) async throws -> SyncObjectCopies {
        try fetchCopiesNow(name, maximumLength: maximumLength, maximumCopies: maximumCopies)
    }

    /// The directory a listing of `prefix` walks: the deepest one the prefix names in full.
    public func listingDirectory(for prefix: String) throws -> URL {
        let directoryComponents = prefix.split(separator: "/", omittingEmptySubsequences: false).dropLast()
        guard directoryComponents.allSatisfy({ Self.isValidComponent(String($0)) }) else {
            throw SyncTransportError.invalidName(prefix)
        }
        return directoryComponents.reduce(root) { $0.appendingPathComponent(String($1), isDirectory: true) }
    }

    // MARK: - Synchronous forms, for a caller that already holds file coordination

    public func listNow(prefix: String) throws -> [String] {
        try listingNow(prefix: prefix).names
    }

    public func listingNow(prefix: String) throws -> SyncListing {
        // Walk only the deepest directory the prefix names, then filter by the full prefix.
        let directoryComponents = prefix.split(separator: "/", omittingEmptySubsequences: false).dropLast().map(
            String.init)
        guard directoryComponents.allSatisfy(Self.isValidComponent) else {
            throw SyncTransportError.invalidName(prefix)
        }
        // Every directory on the way must be a real one: a planted link anywhere would list another folder.
        var start = root
        for component in directoryComponents {
            start.appendPathComponent(component, isDirectory: true)
            guard try Self.kind(of: start) == .directory else { return SyncListing() }
        }
        var names: [String] = []
        var duplicates: [String: Int] = [:]
        try walk(start, relative: directoryComponents, into: &names, duplicates: &duplicates)
        // A placeholder and its downloaded file can both be present for a moment: one object.
        var listed = Set(names.filter { $0.hasPrefix(prefix) })
        var listing = SyncListing()
        for (name, count) in duplicates where name.hasPrefix(prefix) {
            // Listed even when only renamed copies are left under the name: one of them may be the object.
            listing.copied[name] = count + (listed.contains(name) ? 1 : 0)
            listed.insert(name)
        }
        listing.names = listed.sorted()
        return listing
    }

    private func walk(
        _ directory: URL, relative: [String], into names: inout [String], duplicates: inout [String: Int]
    ) throws {
        let entries = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        for entry in entries
        where Self.isValidComponent(entry) || entry.hasSuffix("." + Self.fileExtension)
            || (listsUbiquityPlaceholders && Self.placeholderStem(entry) != nil)
        {
            let url = directory.appendingPathComponent(entry)
            switch try Self.kind(of: url) {
            case .directory where Self.isValidComponent(entry):
                try walk(url, relative: relative + [entry], into: &names, duplicates: &duplicates)
            case .file where entry.hasSuffix("." + Self.fileExtension):
                let stem = String(entry.dropLast(Self.fileExtension.count + 1))
                if Self.isValidComponent(stem) {
                    names.append((relative + [stem]).joined(separator: "/"))
                } else if let original = Self.duplicatedStem(stem) {
                    duplicates[(relative + [original]).joined(separator: "/"), default: 0] += 1
                }
            case .file where listsUbiquityPlaceholders:
                if let stem = Self.placeholderStem(entry) { names.append((relative + [stem]).joined(separator: "/")) }
            default:
                continue  // Symbolic links, temporaries, anything else: not an object.
            }
        }
    }

    public func fetchNow(_ name: String, maximumLength: Int) throws -> [UInt8]? {
        let url = try fileURL(for: name)
        switch try Self.kind(of: url) {
        case .missing: return nil
        case .file: break
        default: throw SyncTransportError.invalidName(name)
        }
        guard let bytes = try Self.read(url, maximumLength: maximumLength) else {
            throw SyncTransportError.objectTooLarge(name)
        }
        return bytes
    }

    /// The bytes of the regular file at `url`, or `nil` if it is larger than `maximumLength` (not read).
    public static func read(_ url: URL, maximumLength: Int) throws -> [UInt8]? {
        let size = (try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.intValue ?? 0
        guard size <= maximumLength else { return nil }
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        // Read at most one byte past the limit, in case the file grew after the size check.
        let data = try handle.read(upToCount: maximumLength + 1) ?? Data()
        return data.count <= maximumLength ? Array(data) : nil
    }

    /// The file of `name` and its renamed duplicates, in that order, as bytes: at most `maximumCopies`, each within
    /// `maximumLength`. Anything else under those names (a link, a directory, a file over the limit or unreadable)
    /// is counted as omitted, so one planted entry cannot hide the copies after it.
    public func fetchCopiesNow(_ name: String, maximumLength: Int, maximumCopies: Int) throws -> SyncObjectCopies {
        var found = SyncObjectCopies()
        for url in [try fileURL(for: name)] + (try duplicateURLs(for: name)) {
            switch try Self.kind(of: url) {
            case .missing: continue
            case .file:
                guard found.copies.count < maximumCopies,
                    let bytes = try? Self.read(url, maximumLength: maximumLength)
                else {
                    found.omitted += 1
                    continue
                }
                found.copies.append(bytes)
            default:
                found.omitted += 1
            }
        }
        return found
    }

    public func createNow(_ name: String, contents: [UInt8]) throws {
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
            // Some providers (exFAT, SMB, some file-provider domains) have no hard links. A move refuses an existing
            // destination too, though not atomically; under the coordinated iCloud Drive wrapper no other coordinated
            // writer on this device can come between the check and the move.
            do {
                try FileManager.default.moveItem(at: temporary, to: url)
            } catch {
                if try Self.kind(of: url) != .missing { throw SyncTransportError.objectExists(name) }
                throw error
            }
        }
    }

    public func deleteNow(_ name: String) throws {
        let url = try fileURL(for: name)
        // The renamed copies go with the object: only its author deletes it, once nobody needs it (§7.5).
        for duplicate in try duplicateURLs(for: name) where try Self.kind(of: duplicate) == .file {
            try FileManager.default.removeItem(at: duplicate)
        }
        switch try Self.kind(of: url) {
        case .missing: return
        case .file: try FileManager.default.removeItem(at: url)
        default: throw SyncTransportError.invalidName(name)
        }
    }

    // MARK: - Paths

    /// The file for `name`, after checking every component of the name and that no existing directory on the way is a
    /// symbolic link.
    public func fileURL(for name: String) throws -> URL {
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

    /// The highest number of a renamed duplicate (`<stem> <n>.wwe`) that is attributed to its object.
    public static let maximumDuplicateNumber = 64

    /// Where a provider's renamed duplicates of `name` would be: `<stem> 2.wwe` to `<stem> 64.wwe`, beside it.
    public func duplicateURLs(for name: String) throws -> [URL] {
        let url = try fileURL(for: name)
        let stem = String(url.lastPathComponent.dropLast(Self.fileExtension.count + 1))
        let directory = url.deletingLastPathComponent()
        return (2...Self.maximumDuplicateNumber).map {
            directory.appendingPathComponent("\(stem) \($0)." + Self.fileExtension, isDirectory: false)
        }
    }

    /// The object stem a renamed duplicate's stem stands for (`<stem> <n>`, `n` from 2 to `maximumDuplicateNumber`
    /// in plain decimal), if it is one. Exact, like every name here: one space, no sign, no leading zero.
    public static func duplicatedStem(_ stem: String) -> String? {
        let parts = stem.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 2, isValidComponent(String(parts[0])),
            parts[1].utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }), let number = Int(parts[1]),
            (2...maximumDuplicateNumber).contains(number), String(number) == parts[1]
        else { return nil }
        return String(parts[0])
    }

    /// Letters, digits and `-` only: the characters of the layout's UUIDs and numbers. Rules out `.`, `..`, hidden
    /// files, separators and anything a file system might normalise.
    public static func isValidComponent(_ component: String) -> Bool {
        !component.isEmpty && component.utf8.count <= 64
            && component.utf8.allSatisfy { byte in
                (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
                    || byte == 0x2D
            }
    }

    /// The object stem an iCloud placeholder file name stands for (`.<stem>.wwe.icloud`), if it is one.
    public static func placeholderStem(_ entry: String) -> String? {
        let suffix = "." + fileExtension + "." + placeholderSuffix
        guard entry.utf8.first == UInt8(ascii: "."), entry.hasSuffix(suffix) else { return nil }
        let stem = String(entry.dropFirst().dropLast(suffix.count))
        return isValidComponent(stem) ? stem : nil
    }

    /// The legacy placeholder iCloud Drive keeps beside `url` while the file itself is not downloaded.
    public static func placeholderURL(for url: URL) -> URL {
        url.deletingLastPathComponent().appendingPathComponent(
            "." + url.lastPathComponent + "." + placeholderSuffix, isDirectory: false)
    }

    public enum ItemKind: Sendable {
        case missing, file, directory, other
    }

    /// What is at `url`, without following a symbolic link in the last component (`attributesOfItem` does not
    /// traverse one).
    public static func kind(of url: URL) throws -> ItemKind {
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
