import Foundation
import Testing
import WatchwordSync

@testable import WatchwordKit

@Suite("Vault session: one vault's report over two engine runs")
struct SyncReportCombinationTests {
    @Test("a stop for a newer version, or a replay needed, in either run is reported")
    func flagsFromEitherRun() {
        var first = SyncReport()
        first.requiresNewerVersion = true
        first.replayNeeded = true
        first.snapshotWithheldBy = [UUID(uuidString: "D0000000-0000-4000-8000-0000000000A0")!]
        first.snapshotWithheldForQuarantine = true
        let combined = VaultSession.report(first, followedBy: SyncReport())
        #expect(combined.requiresNewerVersion && combined.replayNeeded)
        #expect(combined.snapshotWithheldForQuarantine, "a replay after the first run hides the stall (Z37)")
        #expect(combined.snapshotWithheldBy == first.snapshotWithheldBy)
        var second = SyncReport()
        second.requiresNewerVersion = true
        #expect(VaultSession.report(SyncReport(), followedBy: second).requiresNewerVersion)
    }
}
