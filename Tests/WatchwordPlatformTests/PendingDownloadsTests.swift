import Foundation
import Testing
import WatchwordPlatform

/// `PendingDownloads` (review finding R20): what the iCloud Drive transport asks iCloud for is asked for once while it
/// waits, and never more than the capacity at once, however many unread versions a listing names at every sync.
@Suite("Pending downloads")
struct PendingDownloadsTests {
    static func urls(_ count: Int) -> [URL] {
        (0..<count).map { URL(fileURLWithPath: "/versions/\($0)") }
    }

    @Test("a URL already asked for is not claimed again until its request ends")
    func claimedOnce() async {
        let pending = PendingDownloads(capacity: 8)
        let urls = Self.urls(3)
        #expect(await pending.claim(urls + [urls[0]]) == urls, "in order, each once")
        #expect(await pending.claim(urls).isEmpty, "the next sync asks for nothing already waiting")
        await pending.finish(urls[1])
        #expect(await pending.claim(urls) == [urls[1]])
        #expect(await pending.count == 3)
    }

    @Test("no more than the capacity wait at once, whatever each sync lists")
    func capacity() async {
        let pending = PendingDownloads(capacity: 4)
        let urls = Self.urls(256)
        for _ in 0..<10 { _ = await pending.claim(urls) }
        #expect(await pending.count == 4)
        for url in urls.prefix(4) { await pending.finish(url) }
        #expect(
            await pending.claim(Array(urls.dropFirst(4))) == Array(urls[4..<8]),
            "what was left out is claimed by a later sync")
        #expect(await PendingDownloads(capacity: -1).claim(urls).isEmpty)
    }
}
