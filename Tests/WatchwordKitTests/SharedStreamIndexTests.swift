import Foundation
import Testing
import WatchwordCrypto
import WatchwordSharing
import WatchwordTestSupport

@testable import WatchwordKit

/// What a device remembers of each stream of a shared vault (docs/02-architecture.md §8.10): whose a stream is, what
/// is filed through it, and that both are a function of the segments recorded, whatever order they came in and
/// whether or not each opened (review findings Z46, Z51).
@Suite("Shared vaults: the stream index")
struct SharedStreamIndexTests {
    static let device = UUID()
    static let victim = UUID()
    static let insider = UUID()

    static func version(_ number: UInt64) -> VersionKey {
        VersionKey(
            recordID: UUID(uuid: (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, UInt8(number))), kind: 0, version: number
        )
    }

    static func value(_ number: UInt8) -> SharedStreamIndex.ValueKey {
        SharedStreamIndex.ValueKey(device: device, digest: [UInt8](repeating: number, count: 32))
    }

    static func segment(_ number: UInt8, by account: UUID, opened: Bool = true) -> SharedStreamIndex.Segment {
        SharedStreamIndex.Segment(
            digest: [UInt8](repeating: number, count: 32), account: account,
            entries: opened ? [version(UInt64(number))] : [], values: opened ? [value(number)] : [], opened: opened)
    }

    @Test("a stream belongs to the account that signed its lowest segment, in whatever order the segments came")
    func ownerIsTheLowestSegmentsSigner() {
        let segments: [(UInt64, SharedStreamIndex.Segment)] = [
            (1, Self.segment(1, by: Self.victim)), (2, Self.segment(2, by: Self.victim)),
            (3, Self.segment(3, by: Self.insider)), (4, Self.segment(4, by: Self.victim)),
        ]
        var reference: SharedStreamIndex?
        for order in [[0, 1, 2, 3], [2, 0, 1, 3], [3, 2, 1, 0], [2, 3, 0, 1]] {
            var index = SharedStreamIndex()
            for position in order {
                index.record(device: Self.device, sequence: segments[position].0, segment: segments[position].1)
            }
            #expect(index.account(ofStream: Self.device) == Self.victim)
            #expect(index.isOwnersSegment(device: Self.device, sequence: 2))
            #expect(!index.isOwnersSegment(device: Self.device, sequence: 3))
            // The insider's segment is there for the chain, and nothing is filed through it.
            #expect(index.chain(device: Self.device, through: 4) != nil)
            #expect(index.firstCarrier[Self.device]?[Self.version(3)] == nil)
            #expect(index.valueCarriers[Self.value(3)] == nil)
            #expect(index.firstCarrier[Self.device]?[Self.version(4)] == 4)
            #expect(index.valueCarriers[Self.value(1)]?[Self.device] == 1)
            #expect(index.devices(signedBy: Self.victim) == [Self.device])
            #expect(index.devices(signedBy: Self.insider).isEmpty, "a cut for the insider would cover the stream")
            if let reference { #expect(index == reference) } else { reference = index }
        }
    }

    @Test("what was filed through a stream is filed again when an earlier segment shows it to be another account's")
    func refilingWhenTheOwnerChanges() {
        var index = SharedStreamIndex()
        index.record(device: Self.device, sequence: 3, segment: Self.segment(3, by: Self.insider))
        #expect(index.account(ofStream: Self.device) == Self.insider)
        #expect(index.valueCarriers[Self.value(3)]?[Self.device] == 3)
        #expect(index.firstCarrier[Self.device]?[Self.version(3)] == 3)

        index.record(device: Self.device, sequence: 1, segment: Self.segment(1, by: Self.victim))
        #expect(index.account(ofStream: Self.device) == Self.victim)
        #expect(index.valueCarriers[Self.value(3)] == nil, "still filed through a segment that is not the stream's own")
        #expect(index.firstCarrier[Self.device]?[Self.version(3)] == nil)
        #expect(index.valueCarriers[Self.value(1)]?[Self.device] == 1)
        #expect(index.devices(signedBy: Self.insider).isEmpty)
    }

    @Test("a segment that does not open names the stream's account and is in the chain; it is completed when it opens")
    func unopenedSegments() {
        var index = SharedStreamIndex()
        index.record(device: Self.device, sequence: 1, segment: Self.segment(1, by: Self.victim, opened: false))
        index.record(device: Self.device, sequence: 2, segment: Self.segment(2, by: Self.insider))
        #expect(index.account(ofStream: Self.device) == Self.victim)
        #expect(!index.isOwnersSegment(device: Self.device, sequence: 2))
        #expect(index.valueCarriers[Self.value(2)] == nil)
        #expect(index.contiguous(device: Self.device, upTo: 2) == 2)
        #expect(index.chain(device: Self.device, through: 2) != nil)
        #expect(index.segment(device: Self.device, sequence: 1)?.opened == false)
        #expect(index.firstCarrier[Self.device]?[Self.version(1)] == nil)
        let chain = index.chain(device: Self.device, through: 2)

        // The key arrives and the log is replayed: the same object, opened.
        index.record(device: Self.device, sequence: 1, segment: Self.segment(1, by: Self.victim))
        #expect(index.segment(device: Self.device, sequence: 1)?.opened == true)
        #expect(index.firstCarrier[Self.device]?[Self.version(1)] == 1)
        #expect(index.valueCarriers[Self.value(1)]?[Self.device] == 1)
        #expect(index.chain(device: Self.device, through: 2) == chain)
        // Another object under that name is not taken for it, opened or not.
        var other = Self.segment(9, by: Self.victim)
        other.entries = [Self.version(9)]
        index.record(device: Self.device, sequence: 1, segment: other)
        #expect(index.firstCarrier[Self.device]?[Self.version(9)] == nil)
    }

    @Test("a saved index says the same after it is read back, the stream's account and unopened segments included")
    func savedAndParsed() throws {
        let keyset = Keyset.generate(accountID: UUID())
        let bundle = try keyset.publicKeyBundle()
        let vaultID = UUID()
        var index = SharedStreamIndex()
        index.record(device: Self.device, sequence: 5, segment: Self.segment(5, by: Self.insider))
        index.record(device: Self.device, sequence: 2, segment: Self.segment(2, by: Self.victim, opened: false))
        index.record(device: Self.device, sequence: 3, segment: Self.segment(3, by: Self.victim))
        index.awaiting = [Self.device]
        index.relied = [Self.victim, Self.insider]
        index.collected = [Self.device: 4, Self.victim: 1]
        let saved = try index.signed(account: keyset.accountID, vaultID: vaultID, keyset: keyset)
        let parsed = try #require(SharedStreamIndex.parse(saved, account: bundle, vaultID: vaultID))
        #expect(parsed == index)
        #expect(parsed.account(ofStream: Self.device) == Self.victim)
        #expect(parsed.segment(device: Self.device, sequence: 2)?.opened == false)
        #expect(parsed.valueCarriers[Self.value(5)] == nil && parsed.valueCarriers[Self.value(3)]?[Self.device] == 3)
        // An index of the earlier format, or one altered, is refused whole and rebuilt from the log.
        var earlier = saved
        earlier[4] = 4
        #expect(SharedStreamIndex.parse(earlier, account: bundle, vaultID: vaultID) == nil)
    }

    /// Review finding Z151: a device of the owner's account whose first segments are not here is taken for one whose
    /// segments were collected before the vault was shared only where a snapshot merged here covers them, and only for
    /// what it can have written before what its segments here carried.
    @Test("an owner's stream is taken for collected only where a snapshot covers the missing segments")
    func collectedOwnerStream() throws {
        let keyset = Keyset.generate(accountID: UUID())
        var generator = SeededGenerator(seed: 151)
        let vaultID = UUID()
        let ledger = try MembershipLedger.create(
            vaultKey: VaultKey.generate(vaultID: vaultID, using: &generator), owner: keyset)
        var vault = SharedVault(ledger: ledger)
        vault.index.record(device: Self.device, sequence: 3, segment: Self.segment(3, by: keyset.accountID))
        let owner = [keyset.accountID]
        func believed(_ claimed: UInt64, accounts: [UUID] = owner, retired: Set<UUID> = []) -> Bool {
            VaultSession.neverCarriesHere(
                Self.device, accounts: accounts, claimed: claimed, in: vault, retired: retired)
        }
        #expect(!believed(2), "segments 1 and 2 are merely missing here")
        vault.index.collected[Self.device] = 1
        #expect(!believed(2), "a snapshot covers segment 1 of the two missing")
        vault.index.collected[Self.device] = 2
        #expect(believed(3))
        #expect(!believed(4), "a claim beyond what the stream carried is about edits still to come")
        #expect(!believed(3, accounts: owner + [Self.insider]), "another account lists the device")
        #expect(believed(.max, accounts: [Self.insider], retired: [Self.device]), "a revoked device publishes nothing")
    }

    /// What the take-out held aside is a row of its own, which survives the index being refused or rebuilt (review
    /// finding Z121), and says whether it is complete; the key provenance row is bound to the ledger's owner (Z59).
    @Test("the rows beside the index say the same after they are read back, and refuse another account, vault or owner")
    func rowsBesideTheIndex() throws {
        let keyset = Keyset.generate(accountID: UUID())
        let bundle = try keyset.publicKeyBundle()
        let vaultID = UUID()
        let versions: Set<VersionKey> = [Self.version(7), Self.version(2)]
        for complete in [true, false] {
            let saved = try OwnTakenOutRow.signed(
                versions, complete: complete, account: keyset.accountID, vaultID: vaultID, keyset: keyset)
            let parsed = try #require(OwnTakenOutRow.parse(saved, account: bundle, vaultID: vaultID))
            #expect(parsed.versions == versions && parsed.complete == complete)
            #expect(OwnTakenOutRow.parse(saved, account: bundle, vaultID: UUID()) == nil)
            var altered = saved
            altered[altered.count - 70] ^= 1
            #expect(OwnTakenOutRow.parse(altered, account: bundle, vaultID: vaultID) == nil)
        }
        let other = try Keyset.generate(accountID: UUID()).publicKeyBundle()
        let empty = try OwnTakenOutRow.signed(
            [], complete: true, account: keyset.accountID, vaultID: vaultID, keyset: keyset)
        #expect(OwnTakenOutRow.parse(empty, account: bundle, vaultID: vaultID)?.versions.isEmpty == true)
        #expect(OwnTakenOutRow.parse(empty, account: other, vaultID: vaultID) == nil)

        let owner = UUID()
        let keyIDs: Set<UUID> = [UUID(), UUID()]
        let provenance = try SharedKeyProvenance.signed(
            keyIDs, owner: owner, account: keyset.accountID, vaultID: vaultID, keyset: keyset)
        #expect(SharedKeyProvenance.parse(provenance, owner: owner, account: bundle, vaultID: vaultID) == keyIDs)
        #expect(SharedKeyProvenance.parse(provenance, owner: UUID(), account: bundle, vaultID: vaultID) == nil)
        #expect(SharedKeyProvenance.parse(provenance, owner: owner, account: other, vaultID: vaultID) == nil)
    }
}
