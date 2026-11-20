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

        let writerItem = VaultSession.neverCarriedValueCounts(
            [writer.accountID], isDescription: false, in: ledger)
        #expect(writerItem, "an item value of a member who may write is not believed")
        let writerName = VaultSession.neverCarriedValueCounts(
            [writer.accountID], isDescription: true, in: ledger)
        #expect(!writerName, "a read-write member's description is believed")
        let administratorName = VaultSession.neverCarriedValueCounts(
            [administrator.accountID], isDescription: true, in: ledger)
        #expect(administratorName, "an administrator's description is not believed")
        let ownerName = VaultSession.neverCarriedValueCounts(
            [owner.accountID], isDescription: true, in: ledger)
        #expect(ownerName, "the owner's description is not believed")
        let shared = VaultSession.neverCarriedValueCounts(
            [administrator.accountID, writer.accountID], isDescription: true, in: ledger)
        #expect(!shared, "a description is believed when one account listing the device may not name the vault")
    }

    /// Threat: a former administrator (A4), demoted to read-write by the owner and so still a member who may write,
    /// whose own account revoked one of its devices (its stream is not read again, so a value stamped by it is never
    /// carried here, Z144). The key was rotated after the demotion's cut, so a version sealed under the current key
    /// passes `descriptionMayBeVouched` (sealed at or after the cut that ended the role), which V48's rule asked: the
    /// former administrator could stamp a description as that revoked device's under the current key, and the name
    /// counted on every device. Nothing carried it, so no cut can judge it: only the role now counts (V50).
    @Test("a demoted administrator's uncarried description does not count under a key rotated after the cut")
    func demotedAdministratorsUncarriedDescription() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.administrator], seed: 2_410)
        let former = members[0]
        try await owner.session.changeRole(of: former.accountID, in: vaultID, to: .readWrite)
        try await owner.session.sync()
        try await former.session.sync()
        #expect(try await owner.session.rotateVaultKey(vaultID) == .complete)
        try await owner.session.sync()
        let ledger = try #require(await owner.session.sharing.vaults[vaultID]?.ledger)
        let rotated = ledger.state.vaultKeyID
        #expect(ledger.writeStanding(of: former.accountID) == .mayWrite)
        let vouched = VaultSession.descriptionMayBeVouched(of: former.accountID, sealedUnder: rotated, in: ledger)
        #expect(vouched, "the fixture's key was not rotated after the demotion's cut")

        let item = VaultSession.neverCarriedValueCounts([former.accountID], isDescription: false, in: ledger)
        #expect(item, "an item value of a member who may still write is not believed")
        let name = VaultSession.neverCarriedValueCounts([former.accountID], isDescription: true, in: ledger)
        #expect(!name, "a former administrator's uncarried description counted")
    }
}
