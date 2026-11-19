import Foundation
import Testing
import WatchwordSharing
import WatchwordTestSupport

@testable import WatchwordKit

// The judge's route for a value no stream will ever carry here, and §T's rule for a vault's description
// (docs/06-adversarial-review.md V48).
extension AdversarialSharedVaultTests {
    /// Threat: a current member who may write but is no administrator (A4), whose device was revoked by its own
    /// account (its stream is not read again), so a value stamped by that device is never carried here and the judge
    /// believes it of an account that may write (Z144). For an item that is the rule; for the vault's description it
    /// is not enough: a description counts only as an administrator's work (§T), on this route as on every other.
    @Test("a value no stream will carry here counts for a description only as an administrator's")
    func uncarriedDescriptionNeedsTheRole() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(
            roles: [.readWrite, .administrator], seed: 2_400)
        let (writer, administrator) = (members[0], members[1])
        let ledger = try #require(await owner.session.sharing.vaults[vaultID]?.ledger)
        let keyID = UUID()

        let writerItem = VaultSession.neverCarriedValueCounts(
            [writer.accountID], isDescription: false, sealedUnder: keyID, in: ledger)
        #expect(writerItem, "an item value of a member who may write is not believed")
        let writerName = VaultSession.neverCarriedValueCounts(
            [writer.accountID], isDescription: true, sealedUnder: keyID, in: ledger)
        #expect(!writerName, "a read-write member's description is believed")
        let administratorName = VaultSession.neverCarriedValueCounts(
            [administrator.accountID], isDescription: true, sealedUnder: keyID, in: ledger)
        #expect(administratorName, "an administrator's description is not believed")
        let ownerName = VaultSession.neverCarriedValueCounts(
            [owner.accountID], isDescription: true, sealedUnder: keyID, in: ledger)
        #expect(ownerName, "the owner's description is not believed")
        let shared = VaultSession.neverCarriedValueCounts(
            [administrator.accountID, writer.accountID], isDescription: true, sealedUnder: keyID, in: ledger)
        #expect(!shared, "a description is believed when one account listing the device may not name the vault")
    }
}
