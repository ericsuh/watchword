import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
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

    /// Threat: review finding S61. A current member who may write but is no administrator (A4), with a client that
    /// does not keep the rule, against a member who joined after a rotation. The owner's device sealed the vault's
    /// description again when it rotated, as its own row at some version, and the newcomer indexed that segment. The
    /// member seals a description of their choosing as a row at exactly that version, labelled with the owner's
    /// device and written by nobody else, and delivers it in a snapshot of their own: a snapshot may carry rows of
    /// any device, and a version key binds no bytes, so a judge asking "did the owner's stream carry this version?"
    /// says yes. It must count on no device: the newcomer keeps the owner's name and holds the forged row aside, and
    /// so do the owner and a member holding every key.
    @Test("a description delivered in a member's snapshot as an administrator's row counts on no device")
    func forgedDescriptionInAMembersSnapshot() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(
            roles: [.readWrite, .readWrite, .readWrite], seed: 3_400)
        let (hostile, bystander, leaving) = (members[0], members[1], members[2])
        try await Self.syncAll([owner, hostile, bystander, leaving])
        #expect(try await owner.session.removeMember(leaving.accountID, from: vaultID) == .complete)
        try await Self.syncAll([owner, hostile, bystander, owner])
        let newcomer = try await household.account(seed: 3_480)
        try await owner.invite(newcomer, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([newcomer, owner, newcomer])
        #expect(try await Self.name(of: vaultID, on: newcomer) == "Household")
        let key = RecordKey(recordID: vaultID, kind: .vaultMetadata)
        let ownersRow = try #require(await owner.session.storedRowForTest(key))
        #expect(ownersRow.deviceID == (try #require(await owner.session.deviceIDForTest())), "the rotation's re-seal")

        let forged = try await hostile.session.sealDescriptionAsAModifiedClient(
            vaultID, to: "Personal", version: ownersRow.version, device: ownersRow.deviceID)
        try await hostile.session.publishSnapshotAsAModifiedClient(vaultID, rows: [forged], lamport: 9_000)
        try await Self.syncAll([newcomer, owner, bystander, newcomer])
        for account in [newcomer, owner, bystander] {
            #expect(try await Self.name(of: vaultID, on: account) == "Household")
        }
        #expect(try await Self.holdsDescriptionAside(vaultID, on: newcomer))
        #expect(try await newcomer.session.storedRowForTest(key)?.envelope == ownersRow.envelope)
    }

    /// Threat: review finding S61's second route. A current member who may write but is no administrator (A4) enrols
    /// a device of their own account under the device ID of the owner's device (device IDs are public, and each
    /// account's registry is its own), and from it publishes the next segment of that device's stream: signed as
    /// every object is, so it verifies under the member's registry, and carrying a description row just above the
    /// version of the owner's rotation re-seal, labelled with the owner's device. The newcomer who joined after the rotation finds
    /// a segment of the owner's device's stream carrying those bytes. It must count on no device: the segment's signer
    /// is the member, whose segments count as writes and never as an administrator's. (At the re-seal's own version
    /// the row would be passed over as a stamp already merged; one version above it is the version that matters.)
    @Test("a description in a later segment of the owner's device's stream, signed by a member, counts on no device")
    func forgedDescriptionInALaterSegmentOfTheOwnersStream() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(
            roles: [.readWrite, .readWrite, .readWrite], seed: 3_800)
        let (hostile, bystander, leaving) = (members[0], members[1], members[2])
        try await Self.syncAll([owner, hostile, bystander, leaving])
        #expect(try await owner.session.removeMember(leaving.accountID, from: vaultID) == .complete)
        try await Self.syncAll([owner, hostile, bystander, owner])
        let newcomer = try await household.account(seed: 3_880)
        try await owner.invite(newcomer, to: vaultID, as: .readWrite, owner: owner)
        try await Self.syncAll([newcomer, owner, newcomer])
        let key = RecordKey(recordID: vaultID, kind: .vaultMetadata)
        let ownersRow = try #require(await owner.session.storedRowForTest(key))
        let ownerDevice = try #require(await owner.session.deviceIDForTest())
        #expect(ownersRow.deviceID == ownerDevice, "the rotation's re-seal")

        let impostor = try await hostile.vault.enrolledDevice(deviceID: ownerDevice, over: household.transport)
        await impostor.session.configureSharing(
            SharingSettings(
                state: InMemorySharingStateStore(), contacts: InMemoryVerifiedContactStore(),
                directory: household.directory, shareAccess: RecordingShareAccess()))
        try await impostor.session.unlock(password: TestVault.password)
        // For the vault's current key. Its engine reads the owner's stream as its own, and what it makes of that is not
        // what this test is about.
        _ = try? await impostor.session.syncAll()
        let ownStream = SyncObjectLocation.vaultPrefix(vaultID) + "log/\(ownerDevice.uuidString)/"
        let next = UInt64(await household.transport.list(prefix: ownStream).count) + 1
        let forged = try await impostor.session.sealDescriptionAsAModifiedClient(
            vaultID, to: "Personal", version: ownersRow.version + 1, device: ownerDevice)
        try await impostor.session.publishSegmentAsAModifiedClient(vaultID, rows: [forged], sequence: next)
        try await Self.syncAll([newcomer, owner, bystander, newcomer])
        for account in [newcomer, owner, bystander] {
            #expect(try await Self.name(of: vaultID, on: account) == "Household")
        }
        // Devices holding every key judge it and hold it aside; the newcomer applies none of it.
        for account in [owner, bystander] {
            #expect(try await Self.holdsDescriptionAside(vaultID, on: account))
        }
        #expect(try await newcomer.session.storedRowForTest(key)?.envelope == ownersRow.envelope)
    }

    /// Threat: review finding S62. A current member who may write but is no administrator (A4), with a client that
    /// does not keep the rule, publishes a rename at the very top of what every device's engine accepts above what
    /// it holds (U5's ceiling). Every device holds it aside, as it must; but the judge opened it to judge it, and
    /// opening a version raised the device's write clock, so the next thing each device wrote went one above the
    /// forged version: above the ceiling of every device whose store had not moved. An administrator's next rename,
    /// and anyone's next edit, was then quarantined as implausible on every other device. A version held aside moves
    /// no clock: the administrator's rename lands everywhere and nothing is quarantined as implausible.
    @Test("a forged rename at the version ceiling makes no later write implausible on any device")
    func forgedRenameAtTheCeiling() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(
            roles: [.administrator, .readWrite, .readWrite], seed: 3_500)
        let (administrator, hostile, bystander) = (members[0], members[1], members[2])
        try await Self.syncAll([owner, administrator, hostile, bystander])
        var highWaters: Set<UInt64> = []
        for account in [owner, administrator, bystander] {
            highWaters.insert(try await account.session.storedHighWaterForTest(vaultID))
        }
        let highWater = try #require(highWaters.count == 1 ? highWaters.first : nil)
        let jump = try #require(await owner.session.maximumVersionJumpForTest())

        try await hostile.session.renameAsAModifiedClient(vaultID, to: "Personal", version: highWater + jump)
        try await hostile.session.sync()
        try await Self.syncAll([owner, administrator, bystander])
        for account in [owner, administrator, bystander] {
            #expect(try await Self.name(of: vaultID, on: account) == "Household")
            #expect(try await Self.holdsDescriptionAside(vaultID, on: account))
        }

        try await administrator.session.renameVault(id: vaultID, to: "Family")
        let item = try await bystander.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([administrator, bystander, owner, administrator, bystander])
        for account in [owner, administrator, bystander] {
            #expect(try await Self.name(of: vaultID, on: account) == "Family")
            #expect(try await account.session.item(id: item.id).title == item.title)
            let implausible = try await account.session.quarantine().filter { $0.reason == .implausibleVersion }
            #expect(implausible.isEmpty, "\(implausible)")
        }
    }

    /// Threat: review finding S65, a race any person can start (removing a member, or leaving, ingests membership
    /// outside `syncAll`'s guard) and the store (A1) can time. A replay judges the vault against the head it began
    /// with; if a record arrives while it is suspended, versions admitted before it were judged without it. The run
    /// used to settle `judgedHead` with the head as it *ended*, so the next sync believed everything judged against
    /// the new head and took nothing out: a version the new record no longer counts could stay, and a member who
    /// joined later could take it on this device's word. The marker is the head the run began with, so the next sync
    /// takes out and replays against the new one.
    @Test("a replay that saw the head move settles the head it began with, and the next sync judges again")
    func replaySettlesTheHeadItBeganWith() async throws {
        let household = SharedVaultHousehold()
        let (vaultID, owner, members) = try await household.household(roles: [.readWrite, .readWrite], seed: 3_600)
        let (member, other) = (members[0], members[1])
        try await Self.syncAll([owner, member, other])
        let began = try #require(await member.session.beginReplayForTest(vaultID))

        try await owner.session.changeRole(of: other.accountID, in: vaultID, to: .readOnly)
        try await member.session.ingestMembershipForTest(vaultID)
        let moved = try await member.session.sharedVaultStatus(vaultID).membership.hash.bytes
        #expect(moved != began)
        await member.session.endReplayForTest(vaultID, judgedAgainst: began)
        #expect(await member.session.judgedHeadForTest(vaultID) != moved)

        try await member.session.sync()
        #expect(await member.session.judgedHeadForTest(vaultID) == moved)
    }

    /// Threat: review finding S65 again, as a real race through `syncAll` rather than through hooks, on the branch
    /// the hooks never reached: the head moves after the take-out and before the vault's own run begins, so the run
    /// judges against a head nothing was taken out for (`takenOutAgainst` differs from it). A member made read-only
    /// (A4) whose client is not shown the record keeps writing; the store (A1) hides the record from another member's
    /// device, which merges the late write. That device then replays, and while its sync is suspended in another
    /// vault's listing, a call that ingests membership outside the guard (here `removeMember`, which ingests before it
    /// finds it may not remove) brings the record in. The replay rebuilds nothing it does not count, but takes nothing
    /// out either; marking the vault judged against the new head would keep the late write there for good. It must be
    /// taken out at the next sync.
    @Test("a head that moves between the take-out and the replay leaves the vault to be judged again, through syncAll")
    func headMovedBeforeTheReplayThroughSyncAll() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 3_700)
        let (demoted, demotedView) = try await household.withheldAccount(seed: 3_717)
        let racing = RacingTransport(base: household.transport)
        let member = try await SharingAccount.make(over: racing, directory: household.directory, seed: 3_734)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        try await owner.invite(demoted, to: vaultID, as: .readWrite, owner: owner)
        try await owner.invite(member, to: vaultID, as: .readWrite, owner: owner)
        // A vault of the member's own that its sync reaches before the shared one.
        var earlier = try await member.session.createVault(name: "Earlier").id
        for index in 0..<32 where earlier.uuidString >= vaultID.uuidString {
            earlier = try await member.session.createVault(name: "Earlier \(index)").id
        }
        try #require(earlier.uuidString < vaultID.uuidString)
        let bank = try await owner.session.save(Self.bank(in: vaultID))
        try await Self.syncAll([owner, demoted, member])

        let sharingPrefix = SharingObjectLocation.vaultPrefix(vaultID)
        await demotedView.withholdNew(under: sharingPrefix)
        await racing.withholdNew(under: sharingPrefix)
        try await owner.session.changeRole(of: demoted.accountID, in: vaultID, to: .readOnly)
        try await demoted.session.save(
            Self.setting(.password, to: "late-password", in: try await demoted.session.item(id: bank.id)))
        try await demoted.session.sync()
        try await member.session.sync()
        #expect(try await member.session.item(id: bank.id).field(.password)?.value == "late-password")

        await racing.pause(atListingOf: SyncObjectLocation.vaultPrefix(earlier))
        let replay = Task { try await member.session.syncAll(reconcile: true) }
        await racing.untilPaused()
        await racing.reveal()
        await #expect(throws: SharingError.notPermitted) {
            try await member.session.removeMember(demoted.accountID, from: vaultID)
        }
        let moved = try await member.session.sharedVaultStatus(vaultID).membership.hash.bytes
        #expect(moved == (try await owner.session.sharedVaultStatus(vaultID).membership.hash.bytes))
        await racing.resume()
        _ = try await replay.value
        #expect(await member.session.judgedHeadForTest(vaultID) != moved, "nothing was taken out for this head")

        try await member.session.sync()
        #expect(await member.session.judgedHeadForTest(vaultID) == moved)
        #expect(try await member.session.item(id: bank.id).field(.password)?.value == "bank-password")
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
    func renameAsAModifiedClient(
        _ vaultID: UUID, to name: String, writtenBy: Revision? = nil, version: UInt64? = nil
    ) async throws {
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
            version: version ?? revision.version)
        metadata.writtenBy = writtenBy
        let row = try sealMetadata(metadata, vaultKey: vaultKey, account: account)
        try await store.commit(
            StoreChange(upserts: [row], expectations: [key: existing.map { .version($0.version) } ?? .absent]))
    }

    func maximumVersionJumpForTest() -> UInt64? {
        syncSettings?.configuration.maximumVersionJump
    }

    /// The start of a replay of `vaultID`, as `syncAll` begins one: asked for, what no longer counts taken out, and
    /// the engine's options taken. Returns the head the run judges against.
    func beginReplayForTest(_ vaultID: UUID) async throws -> [UInt8]? {
        guard let account = try await loadAccount(), let syncSettings else { return nil }
        sharing.vaults[vaultID]?.needsReconcile = true
        try await takeOutWhatNoLongerCounts(vaultID)
        return sharedEngineOptions(vaultID, base: syncSettings.configuration, account: account).head
    }

    func ingestMembershipForTest(_ vaultID: UUID) async throws {
        _ = try await ingestMembership(vaultID)
    }

    /// The end of that replay, finished and settled.
    func endReplayForTest(_ vaultID: UUID, judgedAgainst head: [UInt8]?) {
        sharedEngineDidRun(vaultID, reconciled: true, judgedAgainst: head, report: SyncReport())
    }

    func judgedHeadForTest(_ vaultID: UUID) -> [UInt8]? {
        sharing.vaults[vaultID]?.index.judgedHead
    }

    /// The highest version this device's store holds    /// The highest version this device's store holds in `vaultID`: what its engine's ceiling (U5) is measured from.
    func storedHighWaterForTest(_ vaultID: UUID) async throws -> UInt64 {
        var highest: UInt64 = 0
        for kind in [EnvelopeKind.item, .vaultMetadata, .scanStatus] {
            highest = max(highest, try await store.records(in: vaultID, kind: kind).map(\.version).max() ?? 0)
        }
        return highest
    }

    /// Seals a row of the vault's description the way a client that does not keep the rule would: at any version,
    /// labelled with any device, written by nobody else, and not stored.
    func sealDescriptionAsAModifiedClient(_ vaultID: UUID, to name: String, version: UInt64, device: UUID)
        async throws -> StoredRecord
    {
        guard let account = try await loadAccount(), let keys,
            let vaultKey = currentVaultKey(vaultID, keys: keys, account: account)
        else { throw VaultError.noAccount }
        let existing = try await store.record(RecordKey(recordID: vaultID, kind: .vaultMetadata))
        let createdAt =
            existing.flatMap { try? openMetadata($0, keys: keys) }?.createdAt ?? Date(timeIntervalSince1970: 0)
        let metadata = VaultMetadata(
            vaultID: vaultID, name: name, createdAt: createdAt, modifiedAt: createdAt, version: version)
        var row = try sealMetadata(metadata, vaultKey: vaultKey, account: account)
        row.deviceID = device
        return row
    }

    /// Publishes `rows` in a snapshot of this device's own, signed as every object is, the way a client that does not
    /// keep the rules would: an honest device writes no snapshot of a shared vault (§8.10).
    func publishSnapshotAsAModifiedClient(_ vaultID: UUID, rows: [StoredRecord], lamport: UInt64) async throws {
        guard let account = try await loadAccount(), let transport = syncSettings?.transport else {
            throw VaultError.noAccount
        }
        let location = SyncObjectLocation.snapshot(vaultID: vaultID, author: account.deviceID, lamport: lamport)
        let payload = SyncPayload(
            kind: .snapshot, vaultID: vaultID, author: account.deviceID, number: lamport, vector: [:],
            entries: rows.map(SyncEntry.init)
        ).encoded()
        let envelope = try syncSeal(payload, at: location)
        let signature = try await syncSign(envelope, at: location)
        try await transport.create(
            location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
    }

    /// Publishes `rows` as segment `sequence` of this device's own stream, signed as every object is, the way a
    /// client that does not keep the rules would: whatever the stream already holds, and with no acknowledgements.
    func publishSegmentAsAModifiedClient(_ vaultID: UUID, rows: [StoredRecord], sequence: UInt64) async throws {
        guard let account = try await loadAccount(), let transport = syncSettings?.transport else {
            throw VaultError.noAccount
        }
        let location = SyncObjectLocation.segment(vaultID: vaultID, author: account.deviceID, sequence: sequence)
        let payload = SyncPayload(
            kind: .segment, vaultID: vaultID, author: account.deviceID, number: sequence, vector: [:],
            entries: rows.map(SyncEntry.init)
        ).encoded()
        let envelope = try syncSeal(payload, at: location)
        let signature = try await syncSign(envelope, at: location)
        try await transport.create(
            location.name, contents: SignedObject(signature: signature, envelope: envelope).serialized())
    }

    /// Deletes the vault's description the way a client that does not keep the rule would: through the store that
    /// records a deletion to publish, as the permanent deletion of an item goes.
    func deleteDescriptionAsAModifiedClient(_ vaultID: UUID) async throws {
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        try await writer(for: account).commit(
            StoreChange(deletions: [RecordKey(recordID: vaultID, kind: .vaultMetadata)]))
    }
}

/// The household's transport as one device sees it, with the store (A1) in control of two things: it can stop
/// showing objects created under a prefix (as `WithholdingTransport` does), and it can hold one listing of a prefix
/// until released, so a test can act while that device's sync is suspended there. Test code only.
actor RacingTransport: SyncTransport {
    let base: InMemorySyncTransport
    private var frozen: [String: Set<String>] = [:]
    private var pausePrefix: String?
    private var paused = false
    private var reached: CheckedContinuation<Void, Never>?
    private var held: CheckedContinuation<Void, Never>?

    init(base: InMemorySyncTransport) {
        self.base = base
    }

    func withholdNew(under prefix: String) async {
        frozen[prefix] = Set(await base.list(prefix: prefix))
    }

    func reveal() {
        frozen = [:]
    }

    /// The next listing of exactly `prefix` waits for `resume()`.
    func pause(atListingOf prefix: String) {
        pausePrefix = prefix
    }

    /// Returns once a listing is waiting.
    func untilPaused() async {
        guard !paused else { return }
        await withCheckedContinuation { reached = $0 }
    }

    func resume() {
        held?.resume()
        held = nil
    }

    private func holdIfAsked(_ prefix: String) async {
        guard prefix == pausePrefix else { return }
        pausePrefix = nil
        paused = true
        reached?.resume()
        reached = nil
        await withCheckedContinuation { held = $0 }
    }

    private func isWithheld(_ name: String) -> Bool {
        frozen.contains { prefix, shown in name.hasPrefix(prefix) && !shown.contains(name) }
    }

    func list(prefix: String) async throws -> [String] {
        await holdIfAsked(prefix)
        return await base.list(prefix: prefix).filter { !isWithheld($0) }
    }

    func listWithCopies(prefix: String) async throws -> SyncListing {
        await holdIfAsked(prefix)
        var listing = try await base.listWithCopies(prefix: prefix)
        listing.names.removeAll { isWithheld($0) }
        listing.copied = listing.copied.filter { !isWithheld($0.key) }
        return listing
    }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        guard !isWithheld(name) else { return nil }
        return try await base.fetch(name, maximumLength: maximumLength)
    }

    func fetchCopies(_ name: String, maximumLength: Int, maximumCopies: Int) async throws -> SyncObjectCopies {
        guard !isWithheld(name) else { return SyncObjectCopies() }
        return try await base.fetchCopies(name, maximumLength: maximumLength, maximumCopies: maximumCopies)
    }

    func create(_ name: String, contents: [UInt8]) async throws {
        try await base.create(name, contents: contents)
    }

    func delete(_ name: String) async throws {
        await base.delete(name)
    }
}
