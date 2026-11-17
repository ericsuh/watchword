#if canImport(Darwin)
    import Foundation
    import WatchwordSync
    import os

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
    ///   next point hands to the engine.
    /// - **Conflicts are handed over, not resolved** (§7.5, "Conflict copies"). One name can hold several copies: the
    ///   file, each unresolved `NSFileVersion` conflict version of it, and a second create iCloud renamed (`N 2.wwe`,
    ///   which the portable transport attributes to `N`). `listWithCopies` says which names hold more than the file and
    ///   how many copies; `fetchCopies` reads them all under one coordinated read, the file first, each within the
    ///   reader's limit. The transport cannot know which copy is genuine and does not try: it never marks a conflict
    ///   resolved, never replaces the file with a version, and `fetch` reads the current file as it always did. Only
    ///   `delete` removes the copies, with the object, when its author collects it. Drafted and not yet built or run
    ///   on a Mac, like the rest of this file.
    /// - **Downloads.** A file that is not on this device yet — a placeholder, or a dataless file whose
    ///   `ubiquitousItemDownloadingStatus` is `notDownloaded`, which is also what an evicted file becomes — is fetched as
    ///   absent (`nil`) after asking iCloud to download it (`startDownloadingUbiquitousItem`). The engine already treats
    ///   absence safely: a stream waits at the gap (it never skips one) and the next sync fetches it; the folder's
    ///   `SyncFolderPresenter` reports the download's arrival as a remote-change hint. Nothing waits for the network
    ///   inside a coordinated read.
    /// - **Bounded waits.** An access not granted coordination before its deadline (two minutes), or whose task is
    ///   cancelled, is given up and its coordinator cancelled. For a fetch that is `objectUnreadable`, that object's
    ///   failure alone (its stream waits, the sync and this device's publishing go on); for a listing, a create or a
    ///   delete it is `unavailable`. Download status is checked once before the read, so a file known not to be here
    ///   is not waited for, and again inside it, so a file evicted in between is still read as absent.
    ///
    /// Nothing here decides what to trust: everything it returns is checked by the engine like anything else from a
    /// transport. Not built: other file providers with a security-scoped bookmark, and polling them.
    public struct CoordinatedFileSyncTransport: SyncTransport {
        /// Returns when an access that has not been granted coordination yet should be given up. The default waits two
        /// minutes, counted from the request: long enough for the iCloud daemon or a busy device to grant an access to a
        /// file that is here (a file that is not is never waited for), short enough that a holder that never lets go
        /// cannot hold a sync open. Only the wait for the grant counts: once the accessor runs, nothing gives it up, so a
        /// process too busy to schedule this task cannot turn a granted access into a failure. Tests pass their own.
        public typealias Deadline = @Sendable () async -> Void

        public let base: FileSyncTransport
        let deadline: Deadline

        public static let standardDeadline: Deadline = { try? await Task.sleep(for: .seconds(120)) }

        public init(root: URL, coordinationDeadline: @escaping Deadline = CoordinatedFileSyncTransport.standardDeadline)
        {
            base = FileSyncTransport(root: root, listsUbiquityPlaceholders: true)
            deadline = coordinationDeadline
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
            do {
                return try await coordinated(.read([.immediatelyAvailableMetadataOnly]), at: directory) {
                    try base.listNow(prefix: prefix)
                }
            } catch is CoordinationFailure {
                throw SyncTransportError.unavailable  // The folder as a whole.
            }
        }

        public func listWithCopies(prefix: String) async throws -> SyncListing {
            let directory = try base.listingDirectory(for: prefix)
            let base = base
            do {
                return try await coordinated(.read([.immediatelyAvailableMetadataOnly]), at: directory) {
                    var listing = try base.listingNow(prefix: prefix)
                    for name in listing.names {
                        let versions = try Self.conflictVersions(of: base.fileURL(for: name)).count
                        // The file (or its placeholder) counts as one, unless only renamed copies are left.
                        if versions > 0 { listing.copied[name] = (listing.copied[name] ?? 1) + versions }
                    }
                    return listing
                }
            } catch is CoordinationFailure {
                throw SyncTransportError.unavailable  // The folder as a whole.
            }
        }

        public func fetchCopies(_ name: String, maximumLength: Int, maximumCopies: Int) async throws
            -> SyncObjectCopies
        {
            let url = try base.fileURL(for: name)
            // As for `fetch`: a file that is not here is asked for and read as absent, with its copies, for now.
            if try Self.availability(of: url) == .notDownloaded {
                _ = Self.requestDownload(url)
                return SyncObjectCopies()
            }
            let base = base
            do {
                return try await coordinated(.read([.withoutChanges]), at: url) {
                    if try Self.availability(of: url) == .notDownloaded {
                        _ = Self.requestDownload(url)
                        return SyncObjectCopies()
                    }
                    var found = try base.fetchCopiesNow(
                        name, maximumLength: maximumLength, maximumCopies: maximumCopies)
                    for version in Self.conflictVersions(of: url) {
                        // A version iCloud has not downloaded, one over the limit, or one past the count: omitted.
                        guard found.copies.count < maximumCopies, try FileSyncTransport.kind(of: version.url) == .file,
                            let bytes = try? FileSyncTransport.read(version.url, maximumLength: maximumLength)
                        else {
                            found.omitted += 1
                            continue
                        }
                        found.copies.append(bytes)
                    }
                    return found
                }
            } catch is CoordinationFailure {
                // One name whose read was not granted in time: that object alone waits, the sync goes on.
                throw SyncTransportError.objectUnreadable(name)
            }
        }

        /// The unresolved conflict versions iCloud keeps of the file at `url`. Never resolved here.
        static func conflictVersions(of url: URL) -> [NSFileVersion] {
            NSFileVersion.unresolvedConflictVersionsOfItem(at: url) ?? []
        }

        public func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
            let url = try base.fileURL(for: name)
            // A first look, outside coordination, so that a file known not to be here is not waited for: a coordinated
            // read of it would download it first.
            switch try Self.availability(of: url) {
            case .absent: return nil
            case .notDownloaded: return Self.requestDownload(url)
            case .local: break
            }
            let base = base
            do {
                return try await coordinated(.read([.withoutChanges]), at: url) {
                    // Again, inside the read: the file may have been evicted since the first look.
                    switch try Self.availability(of: url) {
                    case .absent: return nil
                    case .notDownloaded: return Self.requestDownload(url)
                    case .local: break
                    }
                    // The current file, whatever versions are kept beside it: `fetchCopies` hands those over.
                    return try base.fetchNow(name, maximumLength: maximumLength)
                }
            } catch is CoordinationFailure {
                // One file whose read was not granted in time: that object alone waits, the sync goes on.
                throw SyncTransportError.objectUnreadable(name)
            }
        }

        public func create(_ name: String, contents: [UInt8]) async throws {
            let url = try base.fileURL(for: name)
            let base = base
            do {
                try await coordinated(.write([]), at: url) {
                    // Known to iCloud but not downloaded here: it exists.
                    if try FileSyncTransport.kind(of: FileSyncTransport.placeholderURL(for: url)) != .missing {
                        throw SyncTransportError.objectExists(name)
                    }
                    try base.createNow(name, contents: contents)
                }
            } catch is CoordinationFailure {
                throw SyncTransportError.unavailable
            }
        }

        public func delete(_ name: String) async throws {
            let url = try base.fileURL(for: name)
            let base = base
            do {
                try await coordinated(.write([.forDeleting]), at: url) {
                    // The conflict versions go with the object (the renamed copies in `deleteNow`): its author is
                    // collecting it, which the engine allows only once nobody needs any copy of it (§7.5).
                    if !Self.conflictVersions(of: url).isEmpty {
                        try NSFileVersion.removeOtherVersionsOfItem(at: url)
                    }
                    try base.deleteNow(name)
                    // An object deleted while only its placeholder is here: the placeholder stands for it.
                    let placeholder = FileSyncTransport.placeholderURL(for: url)
                    if try FileSyncTransport.kind(of: placeholder) == .file {
                        try FileManager.default.removeItem(at: placeholder)
                    }
                }
            } catch is CoordinationFailure {
                throw SyncTransportError.unavailable
            }
        }

        // MARK: - Downloads

        enum Availability: Equatable {
            case absent, notDownloaded, local
        }

        /// Asks iCloud for the file and reads it as absent for now: absence makes the stream wait, and the presenter
        /// says when it arrives.
        static func requestDownload(_ url: URL) -> [UInt8]? {
            try? FileManager.default.startDownloadingUbiquitousItem(at: url)
            return nil
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

        /// Runs `body` while holding coordination for `access` to `url`. Gives up, cancelling the coordinator, when the
        /// deadline passes or the task is cancelled before coordination is granted; once `body` has started it runs to
        /// its end (it is local file work, bounded by `FileSyncTransport`'s limits).
        func coordinated<T: Sendable>(
            _ access: CoordinatedAccess, at url: URL, _ body: @escaping @Sendable () throws -> T
        ) async throws -> T {
            try await CoordinationAttempt<T>().run(access, at: url, deadline: deadline, body)
        }
    }

    /// What a coordinated access is for.
    enum CoordinatedAccess: Sendable {
        case read(NSFileCoordinator.ReadingOptions)
        case write(NSFileCoordinator.WritingOptions)
    }

    /// Coordination was refused, cancelled, or not granted before the deadline.
    struct CoordinationFailure: Error {}

    /// One coordinated access, which the deadline or a cancellation can give up while it waits. The coordinator is the
    /// actor's own, so `cancel()` reaches it without sharing it across threads; the accessor and the deadline settle
    /// who goes first through `phase`.
    actor CoordinationAttempt<T: Sendable> {
        enum Phase: Sendable {
            case waiting, running, abandoned
        }

        private let coordinator = NSFileCoordinator(filePresenter: nil)
        private let phase = OSAllocatedUnfairLock(initialState: Phase.waiting)
        private var continuation: CheckedContinuation<T, any Error>?
        private var timer: Task<Void, Never>?

        func run(
            _ access: CoordinatedAccess, at url: URL, deadline: @escaping CoordinatedFileSyncTransport.Deadline,
            _ body: @escaping @Sendable () throws -> T
        ) async throws -> T {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    self.continuation = continuation
                    let intent: NSFileAccessIntent
                    switch access {
                    case .read(let options): intent = .readingIntent(with: url, options: options)
                    case .write(let options): intent = .writingIntent(with: url, options: options)
                    }
                    let queue = OperationQueue()
                    queue.maxConcurrentOperationCount = 1
                    let phase = phase
                    coordinator.coordinate(with: [intent], queue: queue) { error in
                        let started = phase.withLock { state -> Bool in
                            guard state == .waiting else { return false }
                            state = .running
                            return true
                        }
                        guard started else { return }
                        let result: Result<T, any Error> =
                            error == nil ? Result(catching: body) : .failure(CoordinationFailure())
                        Task { await self.finish(result) }
                    }
                    // Created inside the actor, so the task runs on it: `giveUp()` is a plain call here.
                    timer = Task {
                        await deadline()
                        self.giveUp()
                    }
                }
            } onCancel: {
                Task { await self.giveUp() }
            }
        }

        private func finish(_ result: Result<T, any Error>) {
            timer?.cancel()
            continuation?.resume(with: result)
            continuation = nil
        }

        /// Gives up an access still waiting for coordination; one already running is left to finish.
        private func giveUp() {
            let abandoned = phase.withLock { state -> Bool in
                guard state == .waiting else { return false }
                state = .abandoned
                return true
            }
            guard abandoned else { return }
            coordinator.cancel()
            continuation?.resume(throwing: CoordinationFailure())
            continuation = nil
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
