import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// Only a shared vault's owner or an administrator may rename it (owner decision of 2026-11-17;
/// docs/02-architecture.md §8.7, §8.10; docs/06-adversarial-review.md §T). The session refuses its own account, but
/// what binds a client that does not ask is every other device's write judge: a description counts only as the work
/// of an account that holds the role, or held it and wrote the description inside the cut of the record that ended
/// it. In the suite "shared vaults through the session"; the adversaries are those of §2.
extension AdversarialSharedVaultTests {
    static func name(of vaultID: UUID, on account: SharingAccount) async throws -> String? {
        try await account.session.vaults().first { $0.id == vaultID }?.name
    }

    /// How many versions of the vault's description the device holds aside.
    static func descriptionsHeldAside(_ vaultID: UUID, on account: SharingAccount) async throws -> Int {
        try await account.session.quarantinedVersions().filter {
            $0.recordID == vaultID && $0.kind == .vaultMetadata
        }.count
    }

    static func holdsDescriptionAside(_ vaultID: UUID, on account: SharingAccount) async throws -> Bool {
        try await descriptionsHeldAside(vaultID, on: account) > 0
    }

    /// Threat: a current member who may write but is no administrator (A4), with a client that does not keep the
    /// rule: it seals a description of the vault and publishes it in its own stream, where every member's device
    /// reads it under the vault key they all hold. Three times: a plain rename; one made above a rename the owner has
    /// made since (a later version, as if written knowing it); and one labelled, stamp and all, as the owner's
    /// revision. None may count on any device, the owner's, another member's or one invited afterwards; the name
    /// stays the last one an administrator chose; nothing is destroyed (each is held aside for the person); and the
    /// member's items go on counting, because the rule is about the vault's name and nothing else.
    @Test("a read-write member's rename counts on no device, and the vault keeps the name an administrator chose")
    func forgedRenameByAMember() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readWrite], seed: 2_000)
        let (hostile, bystander) = (members[0], members[1])
        try await Self.syncAll([owner, hostile, bystander])

        try await hostile.session.renameAsAModifiedClient(vaultID, to: "Personal")
        try await hostile.session.sync()
        let report = try await owner.session.syncAll()
        #expect(report.vaults[vaultID]?.heldAside.contains(RecordKey(recordID: vaultID, kind: .vaultMetadata)) == true)
        try await Self.syncAll([bystander, owner])
        for account in [owner, bystander] {
            #expect(try await Self.name(of: vaultID, on: account) == "Household")
            #expect(try await Self.holdsDescriptionAside(vaultID, on: account))
        }

        // The owner renames; the member's client writes again, above it.
        try await owner.session.renameVault(id: vaultID, to: "Family")
        try await Self.syncAll([owner, hostile, bystander])
        try await hostile.session.renameAsAModifiedClient(vaultID, to: "Personal")
        try await hostile.session.sync()
        try await Self.syncAll([owner, bystander])
        for account in [owner, bystander] {
            #expect(try await Self.name(of: vaultID, on: account) == "Family")
            #expect(try await Self.descriptionsHeldAside(vaultID, on: account) == 2)
        }

        // And once more, labelled as the owner's own revision: no stream of the owner's device carried those bytes.
        let key = RecordKey(recordID: vaultID, kind: .vaultMetadata)
        let ownersRow = try #require(await owner.session.storedRowForTest(key))
        try await hostile.session.renameAsAModifiedClient(
            vaultID, to: "Personal", writtenBy: Revision(version: ownersRow.version, device: ownersRow.deviceID))
        try await hostile.session.sync()
        try await Self.syncAll([owner, bystander])
        for account in [owner, bystander] {
            #expect(try await Self.name(of: vaultID, on: account) == "Family")
            #expect(try await Self.descriptionsHeldAside(vaultID, on: account) == 3)
        }

        // What the member writes as a member still counts everywhere.
        let item = try await hostile.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([hostile, owner, bystander])
        #expect(try await owner.session.item(id: item.id).field(.password)?.value == "bank-password")
        #expect(try await bystander.session.item(id: item.id).title == item.title)

        let newcomer = try await household.account(seed: 2_051)
        try await owner.invite(newcomer, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([newcomer, owner, newcomer])
        #expect(try await Self.name(of: vaultID, on: newcomer) == "Family")
        #expect(try await newcomer.session.item(id: item.id).title == item.title)
    }

    /// Threat: a former administrator (A5 as to the role, still a member who may write) whose client has not been
    /// shown the record that demoted them to read-write, with a store (A1) that hides it from them and from another
    /// member's device. There is no transport step and no new key for a demotion, and their items go on counting, so
    /// without a cut in that record nothing would say which of their renames were made with the role. The rename they
    /// made as an administrator is inside the cut the owner's device signed and stays the vault's name everywhere;
    /// the late one counts nowhere, including on the device that merged it before it knew and on their own.
    @Test("a demoted administrator's late rename is taken out again, and the name they chose with the role stays")
    func lateRenameOfADemotedAdministrator() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 2_100)
        let (demoted, demotedView) = try await household.withheldAccount(seed: 2_117)
        let (member, memberView) = try await household.withheldAccount(seed: 2_134)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(demoted, to: vaultID, as: .administrator, owner: owner)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([owner, demoted, member])
        try await demoted.session.renameVault(id: vaultID, to: "Family")
        try await Self.syncAll([demoted, owner, member])
        #expect(try await Self.name(of: vaultID, on: member) == "Family")

        await demotedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await memberView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        try await owner.session.changeRole(of: demoted.accountID, in: vaultID, to: .readWrite)
        #expect(
            try await owner.session.sharedVaultStatus(vaultID).membership.member(demoted.accountID)?.role == .readWrite)

        // Their client has not heard, and the store still takes their writes: a rename, and an item.
        try await demoted.session.renameVault(id: vaultID, to: "Late name")
        let item = try await demoted.session.save(Self.bank(in: vaultID))
        try await demoted.session.sync()
        try await member.session.sync()
        #expect(try await Self.name(of: vaultID, on: member) == "Late name")

        // The owner's device never counts the late name; the item is a member's write and counts.
        try await owner.session.sync()
        #expect(try await Self.name(of: vaultID, on: owner) == "Family")
        #expect(try await Self.holdsDescriptionAside(vaultID, on: owner))
        #expect(try await owner.session.item(id: item.id).title == item.title)

        // Shown the record, the member's device takes the late name out and holds it aside.
        await memberView.reveal()
        try await Self.syncAll([member, owner, member])
        #expect(try await Self.name(of: vaultID, on: member) == "Family")
        #expect(try await Self.holdsDescriptionAside(vaultID, on: member))
        #expect(try await member.session.item(id: item.id).title == item.title)

        // So does their own device, which then refuses to rename, and still writes items.
        await demotedView.reveal()
        try await Self.syncAll([demoted, owner, demoted])
        #expect(try await Self.name(of: vaultID, on: demoted) == "Family")
        await #expect(throws: SharedVaultError.renameRefused) {
            try await demoted.session.renameVault(id: vaultID, to: "Once more")
        }
        var edit = try await demoted.session.item(id: item.id)
        edit.notes = "Still a member"
        try await demoted.session.save(edit)
        try await Self.syncAll([demoted, owner])
        #expect(try await owner.session.item(id: item.id).notes == "Still a member")

        let newcomer = try await household.account(seed: 2_151)
        try await owner.invite(newcomer, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([newcomer, owner, newcomer])
        #expect(try await Self.name(of: vaultID, on: newcomer) == "Family")
    }

    /// Threat: the S37 shape under the new rule. A former administrator (A5 as to the role), behind a store (A1) that
    /// withholds their demotion from them and from a read-write member's device, renames the vault at the same
    /// version as a rename the owner makes, from a device that orders later. The member's device, which may not name
    /// the vault itself, then stores the late name again as a version of its own, one above both (the description's
    /// last-writer-wins merge): a row written by a member in good standing, in that member's stream. A judge that
    /// looked at who wrote the row, or only at whether its writer may write, would count it everywhere. The
    /// description is judged by the write that chose it (`VaultMetadata.writtenBy`), in the stream of the device that
    /// names, against the cut that ended its writer's role: it counts nowhere, on the owner's device as on the one
    /// that stored it again, and the owner's name stands.
    @Test("a late rename stored again by an unaware member's device as its own row counts on no device")
    func lateRenameLaunderedThroughAMember() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 2_200)
        let (demoted, demotedView) = try await household.withheldAccount(seed: 2_217)
        let (member, memberView) = try await household.withheldAccount(seed: 2_234)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(demoted, to: vaultID, as: .administrator, owner: owner)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([owner, demoted, member])
        let ownerDevice = try #require(await owner.session.deviceIDForTest())
        let demotedDevice = try #require(await demoted.session.deviceIDForTest())
        let memberDevice = try #require(await member.session.deviceIDForTest())

        await demotedView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await memberView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        try await owner.session.changeRole(of: demoted.accountID, in: vaultID, to: .readWrite)

        try await owner.session.renameVault(id: vaultID, to: "Owner's name")
        try await demoted.session.renameVault(id: vaultID, to: "Late name")
        let key = RecordKey(recordID: vaultID, kind: .vaultMetadata)
        let ownersRow = try #require(await owner.session.storedRowForTest(key))
        let lateRow = try #require(await demoted.session.storedRowForTest(key))
        try #require(ownersRow.version == lateRow.version && ownerDevice.precedes(demotedDevice))
        try await owner.session.sync()
        try await member.session.sync()
        try await demoted.session.sync()
        try await member.session.sync()
        // The member's device holds the late name in a row of its own, and publishes it.
        let stored = try #require(await member.session.storedRowForTest(key))
        #expect(stored.deviceID == memberDevice && stored.version == lateRow.version + 1)
        #expect(try await Self.name(of: vaultID, on: member) == "Late name")
        try await member.session.sync()

        try await owner.session.sync()
        #expect(try await Self.name(of: vaultID, on: owner) == "Owner's name")
        #expect(try await Self.holdsDescriptionAside(vaultID, on: owner))
        await memberView.reveal()
        try await Self.syncAll([member, owner, member, owner])
        #expect(try await Self.name(of: vaultID, on: owner) == "Owner's name")
        #expect(try await Self.name(of: vaultID, on: member) == "Owner's name")
        #expect(try await Self.holdsDescriptionAside(vaultID, on: member))
    }

    /// Threat: review finding S54, found while reviewing this rule. Whoever may write can seal a version of the
    /// description (a re-seal carries the name on, and stays its writer's), so with the merge ordered by the
    /// *carrier's* version, sealing an old description again above the current one chose the vault's name without
    /// writing one: a read-write member (A4) brings back the name the vault was created with, and a former
    /// administrator (A5 as to the role) the one they chose while they held it, inside their cut and genuine to the
    /// byte, over the owner's later rename. The description's own stamp decides, so neither moves the name on any
    /// device; and an administrator's next rename still lands everywhere.
    @Test("an older name sealed again above the current one, by a member or a former administrator, changes nothing")
    func olderNameSealedAgain() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(
            roles: [.administrator, .readWrite, .readWrite], seed: 2_600)
        let (former, member, bystander) = (members[0], members[1], members[2])
        let everyone = [owner, former, member, bystander]
        try await Self.syncAll(everyone)
        let key = RecordKey(recordID: vaultID, kind: .vaultMetadata)
        let created = try #require(await owner.session.storedRowForTest(key))
        try await former.session.renameVault(id: vaultID, to: "Family")
        let chosen = try #require(await former.session.storedRowForTest(key))
        try await Self.syncAll([former] + everyone)
        try await owner.session.changeRole(of: former.accountID, in: vaultID, to: .readWrite)
        try await owner.session.renameVault(id: vaultID, to: "Home")
        try await Self.syncAll(everyone, rounds: 3)
        for account in everyone { #expect(try await Self.name(of: vaultID, on: account) == "Home") }

        // The member seals the first name again, as the owner's own write of it; the former administrator theirs.
        try await member.session.renameAsAModifiedClient(
            vaultID, to: "Household", writtenBy: Revision(version: created.version, device: created.deviceID))
        try await member.session.sync()
        try await Self.syncAll([owner, bystander])
        for account in [owner, bystander] { #expect(try await Self.name(of: vaultID, on: account) == "Home") }
        try await former.session.renameAsAModifiedClient(
            vaultID, to: "Family", writtenBy: Revision(version: chosen.version, device: chosen.deviceID))
        try await former.session.sync()
        try await Self.syncAll([owner, bystander, owner])
        // (The two devices whose clients overwrote their own copies show what they wrote; nobody else does.)
        for account in [owner, bystander] {
            #expect(try await Self.name(of: vaultID, on: account) == "Home")
            #expect(try await account.session.quarantinedVersions().isEmpty, "genuine descriptions, carried on")
        }

        try await owner.session.renameVault(id: vaultID, to: "Our house")
        try await Self.syncAll(everyone, rounds: 3)
        for account in everyone { #expect(try await Self.name(of: vaultID, on: account) == "Our house") }
        let newcomer = try await household.account(seed: 2_690)
        try await owner.invite(newcomer, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([newcomer, owner, newcomer])
        #expect(try await Self.name(of: vaultID, on: newcomer) == "Our house")
    }

    /// Threat: an administrator (A4 with the role) who expects to lose it. Descriptions are ordered by the stamp of
    /// the write that chose them, which the writer picks: dated far above the row that carries it, a name would
    /// outrank every rename made afterwards, by anyone, for good, from inside the cut once the role has ended, while
    /// the row itself stays under the version jump the engine allows (U5). A description dated above its own row is
    /// no version at all: it opens on no device, is held aside, and the owner's next rename stands.
    @Test("a description dated above the row that carries it is refused, so no name outranks later renames for good")
    func descriptionDatedAboveItsRow() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(
            roles: [.administrator, .readWrite], seed: 2_700)
        let (hostile, member) = (members[0], members[1])
        let everyone = [owner, hostile, member]
        try await Self.syncAll(everyone)
        let device = try #require(await hostile.session.deviceIDForTest())
        let key = RecordKey(recordID: vaultID, kind: .vaultMetadata)
        let current = try #require(await hostile.session.storedRowForTest(key))

        try await hostile.session.renameAsAModifiedClient(
            vaultID, to: "Mine for good", writtenBy: Revision(version: current.version + 1_000_000, device: device))
        try await hostile.session.sync()
        try await Self.syncAll([owner, member])
        for account in [owner, member] {
            #expect(try await Self.name(of: vaultID, on: account) == "Household")
            #expect(try await Self.holdsDescriptionAside(vaultID, on: account))
        }
        try await owner.session.renameVault(id: vaultID, to: "Home")
        try await Self.syncAll(everyone, rounds: 3)
        for account in [owner, member] { #expect(try await Self.name(of: vaultID, on: account) == "Home") }
    }

    /// Threat: a former administrator (A5 as to the role, still a member who may write and holds the current key),
    /// against a member who joined after a rotation. The vault's name is one they chose while they held the role,
    /// inside their cut; the newcomer cannot read the segment that first carried it and holds it on the word of the
    /// owner's device, which sealed it again when it rotated. The former administrator publishes the same
    /// description, byte for byte, once more: the only segment of theirs the newcomer can read that carries it is
    /// now a late one, outside the cut. If that undid the owner's word, they could take the vault's name away on
    /// every device that joined since, and on no other. An administrator's version sealed after the role ended still
    /// vouches, so the newcomer keeps the name every other device shows, through a replay too.
    @Test("a name published again late by its former author is not taken from a member who joined after a rotation")
    func ownNamePublishedAgainLate() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(
            roles: [.administrator, .readWrite], seed: 2_800)
        let (former, leaving) = (members[0], members[1])
        try await Self.syncAll([owner, former, leaving])
        try await former.session.renameVault(id: vaultID, to: "Family")
        let key = RecordKey(recordID: vaultID, kind: .vaultMetadata)
        let chosen = try #require(await former.session.storedRowForTest(key))
        try await Self.syncAll([former, owner, leaving])
        try await owner.session.changeRole(of: former.accountID, in: vaultID, to: .readWrite)
        #expect(try await owner.session.removeMember(leaving.accountID, from: vaultID) == .complete)
        try await Self.syncAll([owner, former, owner])
        let newcomer = try await household.account(seed: 2_890)
        try await owner.invite(newcomer, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([newcomer, owner, former, newcomer])
        #expect(try await Self.name(of: vaultID, on: newcomer) == "Family")

        try await former.session.renameAsAModifiedClient(
            vaultID, to: "Family", writtenBy: Revision(version: chosen.version, device: chosen.deviceID))
        try await former.session.sync()
        try await Self.syncAll([newcomer, owner, newcomer])
        // A change of head replays the newcomer's log, which judges the owner's version again.
        let another = try await household.account(seed: 2_891)
        try await owner.invite(another, to: vaultID, as: .readOnly, owner: owner)
        try await Self.syncAll([another, owner, newcomer, another, newcomer])
        for account in [owner, newcomer, another] {
            #expect(try await Self.name(of: vaultID, on: account) == "Family")
        }
    }

    /// Threat: none from a person; the store (A1) only delivers. What a member who joined after a rotation can and
    /// cannot check about a name whose first segment they pass over, when roles change afterwards. Another
    /// administrator's demotion says nothing about the name's author, so the name stays (vouching for a description
    /// is judged for its author alone). The author's own demotion, with no rotation since, leaves the newcomer unable
    /// to tell whether the name is inside the cut: it shows no name rather than one it cannot check, holds the
    /// version aside, and has the name back when the next rotation seals it again (review finding S57, the limit
    /// S42 states for items). Every other device shows the name throughout.
    @Test("a newcomer keeps a name across another member's demotion, and checks its author's at the next rotation")
    func vouchedNameAcrossDemotions() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(
            roles: [.administrator, .administrator, .readWrite], seed: 2_900)
        let (author, other, leaving) = (members[0], members[1], members[2])
        try await Self.syncAll([owner, author, other, leaving])
        try await author.session.renameVault(id: vaultID, to: "Family")
        try await Self.syncAll([author, owner, other, leaving])
        #expect(try await owner.session.removeMember(leaving.accountID, from: vaultID) == .complete)
        try await Self.syncAll([owner, author, other, owner])
        let newcomer = try await household.account(seed: 2_990)
        try await owner.invite(newcomer, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([newcomer, owner, newcomer])
        #expect(try await Self.name(of: vaultID, on: newcomer) == "Family")

        try await owner.session.changeRole(of: other.accountID, in: vaultID, to: .readWrite)
        try await Self.syncAll([owner, newcomer, author, other, newcomer])
        for account in [owner, newcomer, author, other] {
            #expect(try await Self.name(of: vaultID, on: account) == "Family")
        }
        #expect(try await newcomer.session.quarantinedVersions().isEmpty)

        try await owner.session.changeRole(of: author.accountID, in: vaultID, to: .readWrite)
        try await Self.syncAll([owner, newcomer, author, other, newcomer])
        for account in [owner, author, other] { #expect(try await Self.name(of: vaultID, on: account) == "Family") }
        #expect(try await Self.name(of: vaultID, on: newcomer) != "Family")
        #expect(try await Self.holdsDescriptionAside(vaultID, on: newcomer))

        #expect(try await owner.session.rotateVaultKey(vaultID) == .complete)
        try await Self.syncAll([owner, newcomer, author, other, newcomer], rounds: 3)
        for account in [owner, newcomer, author, other] {
            #expect(try await Self.name(of: vaultID, on: account) == "Family")
        }
    }

    /// Threat: none; the property the rule must not break, with the store (A1) only delivering. The owner's and an
    /// administrator's renames reach every device, a read-write member's, a read-only member's and one invited later,
    /// and hold nothing aside; a member promoted to administrator renames like any other; and the session refuses
    /// everyone else before anything is sealed, with the vault's name and stored row untouched.
    @Test("an owner's and an administrator's renames converge on every device; a member's is refused by the session")
    func renamesByAdministratorsConverge() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(
            roles: [.administrator, .readWrite, .readOnly], seed: 2_300)
        let (administrator, writer, reader) = (members[0], members[1], members[2])
        let everyone = [owner, administrator, writer, reader]
        try await Self.syncAll(everyone)

        try await administrator.session.renameVault(id: vaultID, to: "Family")
        try await Self.syncAll([administrator] + everyone)
        for account in everyone {
            #expect(try await Self.name(of: vaultID, on: account) == "Family")
            #expect(try await account.session.quarantinedVersions().isEmpty)
        }
        try await owner.session.renameVault(id: vaultID, to: "Home")
        try await Self.syncAll(everyone)
        for account in everyone { #expect(try await Self.name(of: vaultID, on: account) == "Home") }

        let key = RecordKey(recordID: vaultID, kind: .vaultMetadata)
        let before = try #require(await writer.session.storedRowForTest(key))
        await #expect(throws: SharedVaultError.renameRefused) {
            try await writer.session.renameVault(id: vaultID, to: "Personal")
        }
        await #expect(throws: SharedVaultError.writeRefused(.readOnly)) {
            try await reader.session.renameVault(id: vaultID, to: "Personal")
        }
        #expect(await writer.session.storedRowForTest(key) == before)

        // Promoted, the member renames, and every device follows.
        try await owner.session.changeRole(of: writer.accountID, in: vaultID, to: .administrator)
        try await Self.syncAll(everyone)
        try await writer.session.renameVault(id: vaultID, to: "Our house")
        try await Self.syncAll([writer] + everyone)
        for account in everyone {
            #expect(try await Self.name(of: vaultID, on: account) == "Our house")
            #expect(try await account.session.quarantinedVersions().isEmpty)
        }
        let newcomer = try await household.account(seed: 2_371)
        try await owner.invite(newcomer, to: vaultID, as: .readOnly, owner: owner)
        try await Self.syncAll([newcomer, owner, newcomer])
        #expect(try await Self.name(of: vaultID, on: newcomer) == "Our house")
    }

    /// Threat: a current member (A4) whose modified client renamed the vault while read-write, and who is made an
    /// administrator afterwards. Standing is judged now, never at the time a write claims (§8.7): nothing in a write
    /// says when it was made that its writer could not have chosen, and the account can write the same name again the
    /// moment it holds the role, so holding the old one aside would bind nobody. What must hold is that every device
    /// gives the same answer at every head: held aside by all before the promotion, counted by all after it, and,
    /// when the role is taken away again, counted or not by the cut of that record alone.
    @Test("a rename written before its author was made an administrator is judged alike on every device at each head")
    func renameWrittenBeforeAPromotion() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readWrite], seed: 2_400)
        let (promoted, bystander) = (members[0], members[1])
        let everyone = [owner, promoted, bystander]
        try await Self.syncAll(everyone)

        try await promoted.session.renameAsAModifiedClient(vaultID, to: "Early name")
        try await promoted.session.sync()
        try await Self.syncAll([owner, bystander])
        for account in [owner, bystander] {
            #expect(try await Self.name(of: vaultID, on: account) == "Household")
            #expect(try await Self.holdsDescriptionAside(vaultID, on: account))
        }

        try await owner.session.changeRole(of: promoted.accountID, in: vaultID, to: .administrator)
        try await Self.syncAll(everyone, rounds: 3)
        for account in everyone { #expect(try await Self.name(of: vaultID, on: account) == "Early name") }

        // Demoted again: the name is inside the cut the owner's device signs, and stays; a later one does not count.
        try await owner.session.changeRole(of: promoted.accountID, in: vaultID, to: .readWrite)
        try await Self.syncAll(everyone, rounds: 3)
        for account in everyone { #expect(try await Self.name(of: vaultID, on: account) == "Early name") }
        let before = try await Self.descriptionsHeldAside(vaultID, on: owner)
        try await promoted.session.renameAsAModifiedClient(vaultID, to: "After the role")
        try await promoted.session.sync()
        try await Self.syncAll([owner, bystander])
        for account in [owner, bystander] {
            #expect(try await Self.name(of: vaultID, on: account) == "Early name")
        }
        #expect(try await Self.descriptionsHeldAside(vaultID, on: owner) == before + 1)
    }

    /// Threat: a current read-write member (A4) with a modified client, against a member who joined after a
    /// rotation. That member cannot open the segments sealed under the earlier key, so a description first carried
    /// there reaches them only in a version sealed again, taken on its sealer's word (§8.10, vouching). The hostile
    /// member seals, under the current key, a name of their choosing labelled as the owner's old revision. A device
    /// that holds every key waits for the owner's stream to show those bytes, which it never will; the newcomer must
    /// not take a member's word for a name either: only an administrator's version vouches for a description. The
    /// genuine name, sealed again by the owner's device when it rotated, is what the newcomer shows.
    @Test("a member who joined after a rotation takes an old name on an administrator's word, never a member's")
    func forgedRenameVouchedToANewcomer() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(
            roles: [.administrator, .readWrite, .readWrite], seed: 2_500)
        let (administrator, hostile, leaving) = (members[0], members[1], members[2])
        try await Self.syncAll([owner, administrator, hostile, leaving])
        try await administrator.session.renameVault(id: vaultID, to: "Family")
        try await Self.syncAll([administrator, owner, hostile, leaving])
        let key = RecordKey(recordID: vaultID, kind: .vaultMetadata)
        let named = try #require(await administrator.session.storedRowForTest(key))
        let namedBy = Revision(version: named.version, device: named.deviceID)

        // The rotation: the owner's device seals the administrator's name again under the new key.
        #expect(try await owner.session.removeMember(leaving.accountID, from: vaultID) == .complete)
        try await Self.syncAll([owner, administrator, hostile, owner])
        let newcomer = try await household.account(seed: 2_590)
        try await owner.invite(newcomer, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([newcomer, owner, newcomer])
        #expect(try await Self.name(of: vaultID, on: newcomer) == "Family")
        #expect(try await newcomer.session.quarantinedVersions().isEmpty)

        try await hostile.session.sync()
        try await hostile.session.renameAsAModifiedClient(vaultID, to: "Personal", writtenBy: namedBy)
        try await hostile.session.sync()
        try await Self.syncAll([newcomer, owner, administrator, newcomer])
        for account in [newcomer, owner, administrator] {
            #expect(try await Self.name(of: vaultID, on: account) == "Family")
            #expect(try await Self.holdsDescriptionAside(vaultID, on: account))
        }
    }

    /// Threat: the store (A1) chooses the order of arrival, with a former administrator (A5 as to the role) whose
    /// client goes on renaming. `lateRenameOfADemotedAdministrator` shows a device the stream first and the record
    /// afterwards; here a member's device is shown the record that ended the role first and none of the stream it
    /// bounds, then all of it at once, the name chosen with the role and the late one in the same pass. The rule is
    /// a function of the chain and the logs, so the order must decide nothing: while the stream is withheld the
    /// device shows the last name it can check (a withheld stream delays, never widens), and once shown it the
    /// name inside the cut is the vault's and the one outside it is held aside, as on the owner's device.
    @Test("a device shown a demotion before the stream it bounds ends on the name inside the cut, like every other")
    func demotionHeardBeforeTheNamesItBounds() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 3_000)
        let (former, formerView) = try await household.withheldAccount(seed: 3_017)
        let (late, lateView) = try await household.withheldAccount(seed: 3_034)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(former, to: vaultID, as: .administrator, owner: owner)
        try await owner.invite(late, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([owner, former, late])
        let formerDevice = try #require(await former.session.deviceIDForTest())
        await lateView.withholdNew(under: SyncObjectLocation.vaultPrefix(vaultID) + "log/\(formerDevice.uuidString)/")

        try await former.session.renameVault(id: vaultID, to: "Family")
        try await Self.syncAll([former, owner])
        // Their own device is not shown the record either, or it would take its late name out before publishing it.
        await formerView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        try await owner.session.changeRole(of: former.accountID, in: vaultID, to: .readWrite)
        try await former.session.renameVault(id: vaultID, to: "Late name")
        try await former.session.sync()
        try await owner.session.sync()
        #expect(try await Self.name(of: vaultID, on: owner) == "Family")
        #expect(try await Self.holdsDescriptionAside(vaultID, on: owner))

        // The record, and none of the stream: neither name can be checked yet, and neither is shown.
        try await Self.syncAll([late, owner, late])
        #expect(
            try await late.session.sharedVaultStatus(vaultID).membership.member(former.accountID)?.role == .readWrite)
        #expect(try await Self.name(of: vaultID, on: late) == "Household")

        await lateView.reveal()
        try await Self.syncAll([late, owner, late])
        #expect(try await Self.name(of: vaultID, on: late) == "Family")
        #expect(try await Self.holdsDescriptionAside(vaultID, on: late))
        #expect(try await Self.name(of: vaultID, on: owner) == "Family")
    }

    /// Threat: review finding S59, found in the second review of this rule. A former administrator (A5 as to the
    /// role, still a member who may write) with the store (A1), against an administrator who joined after a rotation
    /// and so takes older names on the word of whoever sealed them again. The store withholds the demotion from that
    /// administrator's device while it merges the former administrator's late rename, and shows it the record only
    /// when the device turns to a rotation of its own: the plan ingests the record, the rotation follows it on the
    /// chain, and the records are sealed again under the new key before anything was judged against the new head. The
    /// late name, sealed by an administrator under a key introduced after the role ended, is exactly what vouching
    /// believes (§8.10): the device would keep it, publish it, and every member who joined since a rotation would
    /// show it, while devices holding every key held it aside. A device seals again only what it has judged against
    /// the head it seals under, so the late name is taken out before the rotation's re-seal and reaches nobody.
    @Test("a late rename is not sealed again by an administrator's device that learns of the demotion as it rotates")
    func lateRenameSealedAgainWhileRotating() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 3_200)
        let (former, formerView) = try await household.withheldAccount(seed: 3_217)
        let leaving = try await household.account(seed: 3_234)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(former, to: vaultID, as: .administrator, owner: owner)
        try await owner.invite(leaving, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([owner, former, leaving])
        // A rotation, then an administrator who joins after it and passes over the first key.
        #expect(try await owner.session.removeMember(leaving.accountID, from: vaultID) == .complete)
        try await Self.syncAll([owner, former, owner])
        let (rotating, rotatingView) = try await household.withheldAccount(seed: 3_251)
        try await owner.invite(rotating, to: vaultID, as: .administrator, owner: owner)
        try await Self.syncAll([rotating, owner, former, rotating])
        #expect(try await Self.name(of: vaultID, on: rotating) == "Household")

        await formerView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        await rotatingView.withholdNew(under: SharingObjectLocation.vaultPrefix(vaultID))
        try await owner.session.changeRole(of: former.accountID, in: vaultID, to: .readWrite)
        try await former.session.renameVault(id: vaultID, to: "Late name")
        try await former.session.sync()
        try await rotating.session.sync()
        #expect(try await Self.name(of: vaultID, on: rotating) == "Late name")

        // The store shows the device the demotion once its sync is over, as it turns to rotating the key.
        await rotatingView.reveal()
        try await rotating.session.planRotation(.routine, in: vaultID)
        _ = try await rotating.session.carryOutRotation(in: vaultID)
        #expect(
            try await rotating.session.sharedVaultStatus(vaultID).membership.member(former.accountID)?.role
                == .readWrite)
        try await Self.syncAll([rotating, owner, rotating, owner], rounds: 3)
        #expect(try await rotating.session.sharedVaultStatus(vaultID).pendingRotation.isEmpty)
        for account in [rotating, owner] { #expect(try await Self.name(of: vaultID, on: account) == "Household") }
        #expect(try await Self.holdsDescriptionAside(vaultID, on: rotating))

        // A member invited now holds the newest key alone, and takes every older name on an administrator's word.
        let newcomer = try await household.account(seed: 3_268)
        try await owner.invite(newcomer, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([newcomer, owner, rotating, newcomer])
        #expect(try await Self.name(of: vaultID, on: newcomer) == "Household")
    }

    /// Threat: none beyond a store (A1) that delays one stream, as any slow provider does; the finding is a report
    /// that never clears (PR review of `resealSharedVault`, S60). Only an administrator's device seals the vault's
    /// description again after a rotation, so a read-write member's device skips it. If it still counted the
    /// description as a record it owes, its status would say `.resealing(remaining: 1)` for as long as no
    /// administrator's re-seal reached it, and for good if none ever did. The member's re-seal must finish with
    /// nothing owed by that device while the description is still under the earlier key there, and the vault must
    /// converge once the owner's re-seal arrives.
    @Test("a read-write member's re-seal after a rotation leaves nothing owed, and the vault converges")
    func readWriteMemberResealsWithoutTheDescription() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 3_300)
        let (member, memberView) = try await household.withheldAccount(seed: 3_317)
        let leaving = try await household.account(seed: 3_334)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(leaving, to: vaultID, as: .readWrite, owner: owner)
        let item = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, member, leaving])
        let ownerDevice = try #require(await owner.session.deviceIDForTest())
        await memberView.withholdNew(under: SyncObjectLocation.vaultPrefix(vaultID) + "log/\(ownerDevice.uuidString)/")

        #expect(try await owner.session.removeMember(leaving.accountID, from: vaultID) == .complete)
        try await Self.syncAll([member])
        let status = try await member.session.sharedVaultStatus(vaultID)
        #expect(!status.mayRename)
        let key = RecordKey(recordID: vaultID, kind: .vaultMetadata)
        let description = try #require(await member.session.storedRowForTest(key))
        #expect(description.keyID != status.membership.vaultKeyID, "the owner's re-seal has not reached the member")
        let resealedItem = try #require(
            await member.session.storedRowForTest(RecordKey(recordID: item.id, kind: .item)))
        #expect(resealedItem.keyID == status.membership.vaultKeyID, "the member sealed the item again")
        #expect(status.pendingRotation.isEmpty)

        await memberView.reveal()
        try await Self.syncAll([member, owner, member])
        let converged = try await member.session.sharedVaultStatus(vaultID)
        #expect(converged.pendingRotation.isEmpty)
        #expect(try await member.session.storedRowForTest(key)?.keyID == converged.membership.vaultKeyID)
        #expect(try await owner.session.sharedVaultStatus(vaultID).pendingRotation.isEmpty)
        for account in [owner, member] {
            #expect(try await Self.name(of: vaultID, on: account) == "Household")
            #expect(try await account.session.item(id: item.id).field(.password)?.value == "bank-password")
        }
    }

    /// Threat: a current member who may write but is no administrator (A4), with a client that does not keep the
    /// rule, trying the other way to change what a vault is called: not a description of its own, which every judge
    /// refuses, but a deletion of the description record, published in its own stream like the deletion of an item.
    /// A vault left without a name is a vault whose name the member chose. A description is never erased by sync
    /// (`VaultMetadataMerger.resolveErasure`), so the name stays on every other device, and an administrator's next
    /// rename lands as usual. That held before the rule; the test is here because the rule leans on it.
    @Test("a member's deletion of the vault's description takes the name from no other device")
    func descriptionDeletedByAMember() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readWrite], seed: 3_100)
        let (hostile, bystander) = (members[0], members[1])
        try await Self.syncAll([owner, hostile, bystander])

        try await hostile.session.deleteDescriptionAsAModifiedClient(vaultID)
        #expect(try await Self.name(of: vaultID, on: hostile) == "")
        let report = try await hostile.session.syncAll()
        #expect((report.vaults[vaultID]?.pushedEntries ?? 0) >= 1, "the deletion was published")
        try await Self.syncAll([owner, bystander, owner])
        for account in [owner, bystander] { #expect(try await Self.name(of: vaultID, on: account) == "Household") }

        try await owner.session.renameVault(id: vaultID, to: "Family")
        try await Self.syncAll([owner, bystander, hostile, owner, bystander])
        for account in [owner, bystander] { #expect(try await Self.name(of: vaultID, on: account) == "Family") }
        let newcomer = try await household.account(seed: 3_151)
        try await owner.invite(newcomer, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([newcomer, owner, newcomer])
        #expect(try await Self.name(of: vaultID, on: newcomer) == "Family")
    }
}

extension VaultSession {
    /// Seals a description over the stored one the way a client that does not keep the rule would: `renameVault`
    /// without its checks, optionally labelled as another write's (`VaultMetadata.writtenBy`).
    func renameAsAModifiedClient(_ vaultID: UUID, to name: String, writtenBy: Revision? = nil) async throws {
        guard let account = try await loadAccount(), let keys,
            let vaultKey = currentVaultKey(vaultID, keys: keys, account: account)
        else { throw VaultError.noAccount }
        let key = RecordKey(recordID: vaultID, kind: .vaultMetadata)
        let existing = try await store.record(key)
        let previous = existing.flatMap { try? openMetadata($0, keys: keys) }
        let revision = try nextRevision(in: vaultID, above: existing, account: account)
        let now = await clock.now()
        var metadata = VaultMetadata(
            vaultID: vaultID, name: name, createdAt: previous?.createdAt ?? now, modifiedAt: now,
            version: revision.version)
        metadata.writtenBy = writtenBy
        let row = try sealMetadata(metadata, vaultKey: vaultKey, account: account)
        try await store.commit(
            StoreChange(upserts: [row], expectations: [key: existing.map { .version($0.version) } ?? .absent]))
    }

    /// Deletes the vault's description the way a client that does not keep the rule would: through the store that
    /// records a deletion to publish, as the permanent deletion of an item goes.
    func deleteDescriptionAsAModifiedClient(_ vaultID: UUID) async throws {
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        try await writer(for: account).commit(
            StoreChange(deletions: [RecordKey(recordID: vaultID, kind: .vaultMetadata)]))
    }
}
