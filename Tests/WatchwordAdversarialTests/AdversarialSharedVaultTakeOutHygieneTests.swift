import Foundation
import Testing
import WatchwordHygiene
import WatchwordModel
import WatchwordSharing
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// Review finding S47 (docs/06-adversarial-review.md §O): the hygiene engine and a shared vault's take-out, in the
/// suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Threat: review finding S47. A former member (A5) whose client still writes, behind a store (A1) that withholds
    /// the record removing them from them and from a remaining member's device, renames an item and sets its password
    /// to one in every breach list. The member's device merges it before it knows, so its hygiene engine analyses the
    /// late version. Shown the record, the device takes the version out and rebuilds the item from what counts, here at
    /// the same version number by another device. The engine remembered only a version number, took the rebuilt row
    /// for one it had seen, and went on reporting and checking the late password until the next unlock, while the
    /// vault's own password went unchecked.
    @Test("the hygiene report follows an item a take-out rebuilt, not the late version")
    func hygieneAfterTakeOut() async throws {
        let household = SharedVaultHousehold()
        let (ownerSettings, _) = await HygieneSessionFixture.settings()
        let (memberSettings, _) = await HygieneSessionFixture.settings()
        let owner = try await household.account(seed: 2_600, hygiene: ownerSettings)
        let (removed, removedView) = try await household.withheldAccount(seed: 2_617)
        let (member, memberView) = try await household.withheldAccount(seed: 2_634, hygiene: memberSettings)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(removed, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        let item = try await owner.session.save(
            HygieneSessionFixture.login(vaultID, title: "Forum", host: "forum.example", password: "Zr8@Wn4&x7#Vq9!"))
        try await Self.syncAll([owner, removed, member])
        #expect(try await member.session.hygieneReport().item(item.id)?.title == "Forum")

        await removedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await memberView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        #expect(try await owner.session.removeMember(removed.accountID, from: vaultID) == .complete)
        var late = try await removed.session.item(id: item.id)
        late.title = "Late title"
        try await removed.session.save(Self.setting(.password, to: "password", in: late))
        try await removed.session.sync()
        try await member.session.sync()
        #expect(try await member.session.hygieneReport().item(item.id)?.title == "Late title")

        await memberView.reveal()
        try await Self.syncAll([member, owner, member])
        let rebuilt = try await member.session.item(id: item.id)
        #expect(rebuilt.title == "Forum")
        #expect(try await member.session.hygieneReport().item(item.id)?.title == "Forum")
        _ = try await HygieneSessionFixture.scanUntilIdle(member.session, clock: member.vault.clock)
        let entry = try await member.session.hygieneReport().item(item.id)
        #expect(entry?.title == "Forum")
        guard case .clear = entry?.breachStatus else {
            Issue.record("expected the vault's own password clear, got \(String(describing: entry?.breachStatus))")
            return
        }
    }
}
