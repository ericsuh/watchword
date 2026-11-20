import Foundation

/// The downloads a transport has asked its file provider for and not yet seen end (review finding R20). The iCloud
/// Drive transport asks iCloud for each conflict version whose contents are not on this device; before this, every
/// sync asked again for the same versions, each request a coordinator waiting up to its deadline, so a store listing
/// many such versions (A1: 256 names of 16 versions each, every sync) piled up coordinators without bound. A URL
/// already asked for is not asked for again until its request ends, and at most `capacity` wait at once; what is left
/// out is found again by a later sync, whose listing still counts it unread (R11, R17). Portable, so its rules are
/// tested on Linux; `CoordinatedFileSyncTransport` is its one user, and every copy of a transport shares one.
public actor PendingDownloads {
    /// The most requests waiting at once.
    public let capacity: Int
    private var inFlight: Set<URL> = []

    public init(capacity: Int = 16) {
        self.capacity = max(0, capacity)
    }

    /// The URLs of `urls`, in order and each once, that are not already asked for, as long as fewer than `capacity`
    /// are; each is now pending until `finish`.
    public func claim(_ urls: [URL]) -> [URL] {
        var claimed: [URL] = []
        for url in urls where inFlight.count < capacity && !inFlight.contains(url) {
            inFlight.insert(url)
            claimed.append(url)
        }
        return claimed
    }

    /// The request for `url` ended, however it ended: a later sync may ask again.
    public func finish(_ url: URL) {
        inFlight.remove(url)
    }

    /// How many requests are waiting.
    public var count: Int { inFlight.count }
}
