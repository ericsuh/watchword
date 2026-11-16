#if canImport(Darwin)
    import Foundation
    import WatchwordSync

    /// The iCloud Drive transport (docs/02-architecture.md §7.3): `FileSyncTransport` with every access under file
    /// coordination, and iCloud's not-yet-downloaded files handled.
    ///
    /// Every rule about what may be read or written — the layout's names, no symbolic links, size limits, create-once —
    /// is the portable `FileSyncTransport`'s, run here inside an `NSFileCoordinator` accessor through its synchronous
    /// forms (`listNow`, `fetchNow`, `createNow`, `deleteNow`), so the Linux tests of those rules cover this transport
    /// too. What this wrapper adds is only what iCloud Drive needs:
    ///
    /// - **Coordination.** A listing is a coordinated read of the directory it walks, metadata only
    ///   (`immediatelyAvailableMetadataOnly`), so it neither waits for downloads nor sees a write in progress; a fetch a
    ///   coordinated read of the file, without asking other presenters to save first (`withoutChanges`: objects never
    ///   change); a create a coordinated write of the new file; a delete one with `forDeleting`.
    /// - **Create, never overwrite.** Inside the write, an object iCloud knows but has not downloaded (its legacy
    ///   `.<name>.icloud` placeholder) counts as existing, so `create` fails with `objectExists` rather than make a second
    ///   version; otherwise `createNow`'s hard link (or move) refuses an existing file. Two devices that still write one
    ///   name (a restored device reusing a number before the listing caught up) leave iCloud with a conflict, which the
    ///   next point refuses to resolve.
    /// - **Conflicts are refused, not resolved.** An object with unresolved `NSFileVersion` conflict versions throws
    ///   `conflictingVersions`: an immutable object was written twice and the transport cannot know which copy is
    ///   genuine (only the engine's signature check could say, and it rejects the object as it rejects a damaged one).
    ///   §7.3 asks for the copy that verifies to be kept; doing that needs the engine, and is not built.
    /// - **Downloads.** A file that is not on this device yet — a placeholder, or a dataless file whose
    ///   `ubiquitousItemDownloadingStatus` is `notDownloaded`, which is also what an evicted file becomes — is fetched as
    ///   absent (`nil`) after asking iCloud to download it (`startDownloadingUbiquitousItem`). The engine already treats
    ///   absence safely: a stream waits at the gap (it never skips one) and the next sync fetches it; the folder's
    ///   `SyncFolderPresenter` reports the download's arrival as a remote-change hint. Nothing waits for the network
    ///   inside a coordinated read.
    /// - Coordination itself failing (the provider unavailable, the request cancelled) is `unavailable`.
    ///
    /// Nothing here decides what to trust: everything it returns is checked by the engine like anything else from a
    /// transport. Not built: other file providers with a security-scoped bookmark, and polling them.
    public struct CoordinatedFileSyncTransport: SyncTransport {
        public let base: FileSyncTransport

        public init(root: URL) {
            base = FileSyncTransport(root: root, listsUbiquityPlaceholders: true)
        }

        /// `<ubiquity container>/Watchword/<accountID>`: outside the container's `Documents`, so the Files app does
        /// not show it (§7.3). `nil` when iCloud Drive is off or the app has no container. `url(forUbiquityContainer...)`
        /// can block, so call this off the main thread.
        public static func ubiquityRoot(containerIdentifier: String?, accountID: UUID) -> URL? {
            FileManager.default.url(forUbiquityContainerIdentifier: containerIdentifier)?
                .appendingPathComponent("Watchword", isDirectory: true)
                .appendingPathComponent(accountID.uuidString, isDirectory: true)
        }

        public func list(prefix: String) async throws -> [String] {
            let directory = try base.listingDirectory(for: prefix)
            let base = base
            return try await Self.coordinate(
                .readingIntent(with: directory, options: [.immediatelyAvailableMetadataOnly])
            ) {
                try base.listNow(prefix: prefix)
            }
        }

        public func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
            let url = try base.fileURL(for: name)
            switch try Self.availability(of: url) {
            case .absent:
                return nil
            case .notDownloaded:
                // Asked for, not waited for: absence makes the stream wait, and the presenter says when it arrives.
                try? FileManager.default.startDownloadingUbiquitousItem(at: url)
                return nil
            case .local:
                break
            }
            let base = base
            return try await Self.coordinate(.readingIntent(with: url, options: [.withoutChanges])) {
                if let conflicts = NSFileVersion.unresolvedConflictVersionsOfItem(at: url), !conflicts.isEmpty {
                    throw SyncTransportError.conflictingVersions(name)
                }
                return try base.fetchNow(name, maximumLength: maximumLength)
            }
        }

        public func create(_ name: String, contents: [UInt8]) async throws {
            let url = try base.fileURL(for: name)
            let base = base
            try await Self.coordinate(.writingIntent(with: url, options: [])) {
                // Known to iCloud but not downloaded here: it exists.
                if try FileSyncTransport.kind(of: FileSyncTransport.placeholderURL(for: url)) != .missing {
                    throw SyncTransportError.objectExists(name)
                }
                try base.createNow(name, contents: contents)
            }
        }

        public func delete(_ name: String) async throws {
            let url = try base.fileURL(for: name)
            let base = base
            try await Self.coordinate(.writingIntent(with: url, options: [.forDeleting])) {
                try base.deleteNow(name)
                // An object deleted while only its placeholder is here: the placeholder stands for it.
                let placeholder = FileSyncTransport.placeholderURL(for: url)
                if try FileSyncTransport.kind(of: placeholder) == .file {
                    try FileManager.default.removeItem(at: placeholder)
                }
            }
        }

        // MARK: - Downloads

        enum Availability: Equatable {
            case absent, notDownloaded, local
        }

        /// Whether the object is here to read. Only a regular file's download status is asked; anything else is left
        /// to `fetchNow`, which refuses it.
        static func availability(of url: URL) throws -> Availability {
            switch try FileSyncTransport.kind(of: url) {
            case .missing:
                let placeholder = FileSyncTransport.placeholderURL(for: url)
                return try FileSyncTransport.kind(of: placeholder) == .file ? .notDownloaded : .absent
            case .file:
                let values = try? url.resourceValues(forKeys: [
                    .isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey,
                ])
                if values?.isUbiquitousItem == true, values?.ubiquitousItemDownloadingStatus == .notDownloaded {
                    return .notDownloaded
                }
                return .local
            case .directory, .other:
                return .local
            }
        }

        // MARK: - Coordination

        /// Runs `body` while holding coordination for `intent`, on a queue of its own, and returns what it returns.
        static func coordinate<T: Sendable>(
            _ intent: NSFileAccessIntent, _ body: @escaping @Sendable () throws -> T
        ) async throws -> T {
            let coordinator = NSFileCoordinator(filePresenter: nil)
            let queue = OperationQueue()
            queue.maxConcurrentOperationCount = 1
            return try await withCheckedThrowingContinuation { continuation in
                coordinator.coordinate(with: [intent], queue: queue) { error in
                    if error != nil {
                        continuation.resume(throwing: SyncTransportError.unavailable)
                        return
                    }
                    continuation.resume(with: Result(catching: body))
                }
            }
        }
    }

    /// Change notification for a sync folder (§7.3): an `NSFilePresenter` on the root that calls `onChange` when
    /// anything under it appears, changes or moves — another device's object arriving, a download finishing — so the
    /// app records `AutoSyncEvent.remoteChangeHint` (§7.9). A hint carries nothing and is trusted for nothing: the sync it
    /// triggers lists and checks everything as usual. This process's own coordinated writes notify it too, which costs
    /// one coalesced sync. `start()` registers it with `NSFileCoordinator`, `stop()` removes it; call `stop()` before
    /// releasing it.
    public final class SyncFolderPresenter: NSObject, NSFilePresenter {
        public let presentedItemURL: URL?
        public let presentedItemOperationQueue: OperationQueue
        private let onChange: @Sendable () -> Void

        public init(root: URL, onChange: @escaping @Sendable () -> Void) {
            presentedItemURL = root
            let queue = OperationQueue()
            queue.maxConcurrentOperationCount = 1
            presentedItemOperationQueue = queue
            self.onChange = onChange
            super.init()
        }

        public func start() {
            NSFileCoordinator.addFilePresenter(self)
        }

        public func stop() {
            NSFileCoordinator.removeFilePresenter(self)
        }

        public func presentedItemDidChange() {
            onChange()
        }

        public func presentedSubitemDidAppear(at url: URL) {
            onChange()
        }

        public func presentedSubitemDidChange(at url: URL) {
            onChange()
        }

        public func presentedSubitem(at oldURL: URL, didMoveTo newURL: URL) {
            onChange()
        }
    }
#endif
