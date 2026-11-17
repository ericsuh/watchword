import Foundation
import WatchwordCrypto

/// What comparing the keys a vault's chain lists for its members with this account's verified contacts found
/// (docs/02-architecture.md §8.4; PRD F4.2, SEC3).
///
/// A pin guards one account's keys wherever they turn up, and the chain is one of those places: an administrator
/// (hostile, or handed a substituted bundle by the key directory and careless with the comparison) can remove a
/// member and add the same account ID back with other keys. The chain's rules allow that, so the ledger accepts it;
/// what must not follow is this device wrapping the next vault key to keys its person never verified, in the belief
/// that the account is still the one they did (review finding S21).
///
/// Only `MembershipLedger.checkMemberKeys` makes one, for one head. `RotationPlanner.plan` and
/// `MembershipLedger.makeGrant` take one and refuse a recipient in `substituted`, so the comparison cannot be left
/// out of anything that wraps a key; the same value tells the UI what to show.
public struct MemberKeyCheck: Sendable, Hashable {
    public let vaultID: UUID
    /// The head the comparison was made on. It is good for that head only.
    public let head: MembershipHash
    /// Members whose keys in the chain differ from the keys pinned for their account (for this account itself: from
    /// its own keys), in account order. Report each as `SharingError.keySubstituted`; nothing is wrapped to them
    /// until the person verifies the new keys (`VerifiedContacts.verify(…, replacingPin: true)`) or they are removed.
    public let substituted: [UUID]
    /// Other members this account has no pin for, in account order: trusted only through the chain (the UI shows
    /// them as unverified; review finding D17).
    public let unverified: [UUID]

    init(vaultID: UUID, head: MembershipHash, substituted: [UUID], unverified: [UUID]) {
        self.vaultID = vaultID
        self.head = head
        self.substituted = substituted
        self.unverified = unverified
    }

    /// A check that compared nothing and found nothing, for `WatchwordTestSupport` only: tests that are not about
    /// pins use it so that they need no contacts store. No production target may call it (it would be the
    /// comparison left out); the name is there to be searched for.
    package static func unchecked(in ledger: MembershipLedger) -> MemberKeyCheck {
        MemberKeyCheck(vaultID: ledger.vaultID, head: ledger.state.hash, substituted: [], unverified: [])
    }

    /// Refuses unless this check was made on `ledger`'s head and none of `members` is listed with substituted keys.
    func requireVerifiedKeys(of members: [Member], in ledger: MembershipLedger) throws {
        guard vaultID == ledger.vaultID, head == ledger.state.hash else { throw SharingError.memberKeysNotChecked }
        if let member = members.first(where: { substituted.contains($0.accountID) }) {
            throw SharingError.keySubstituted(accountID: member.accountID)
        }
    }
}

extension MembershipLedger {
    /// Compares the keys the current state lists for every member with this account's verified contacts.
    ///
    /// Call it whenever the head changes, and before planning a rotation or making a grant. It throws only if the
    /// contacts store cannot be read.
    public func checkMemberKeys(against contacts: VerifiedContacts) async throws -> MemberKeyCheck {
        var substituted: [UUID] = []
        var unverified: [UUID] = []
        for member in state.members {
            do {
                if case .unverified = try await contacts.trust(of: member.bundle) {
                    unverified.append(member.accountID)
                }
            } catch SharingError.keySubstituted {
                substituted.append(member.accountID)
            }
        }
        return MemberKeyCheck(
            vaultID: vaultID, head: state.hash, substituted: substituted, unverified: unverified)
    }
}
