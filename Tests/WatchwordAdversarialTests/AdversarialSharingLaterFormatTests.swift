import Foundation
import Testing
import WatchwordCrypto
import WatchwordTestSupport

@testable import WatchwordSharing

/// A vault that goes on in a format this version cannot read: what ownership transfer will be when it comes
/// (docs/02-architecture.md §8.9). The owner's decision of 2026-11-16 is that a device on an older version must refuse
/// the chain from that record on, fail closed, and never carry on as though it had not happened.
extension AdversarialSharingTests {
    /// The record a later version would write after `state`: format version 3 (or 2 with an operation this version
    /// does not know), this version's prefix, and the signature over everything before it.
    static func laterFormat(
        after state: MembershipState, signer: SharingParty, version: UInt8 = 3, operation: [UInt8] = [7]
    ) throws -> [UInt8] {
        var record = ForgedRecord(after: state, signer: signer.accountID, operation: .rotateKey)
        record.formatVersion = version
        record.operation = operation + ForgedRecord.bytes(UUID())
        return try record.signed(by: signer.keyset)
    }

    /// The owner of a future version transfers the vault, and the former owner, still holding a device on this
    /// version, or an administrator on one, goes on signing records from before the transfer. A device on this
    /// version cannot read the transfer, so if it took it for junk it would follow them and split from every updated
    /// device. Instead, once a record of a later format extends a record it holds and verifies under the owner's key
    /// in the state it follows, the device's chain stops there, in whatever order and batches the records arrive, and
    /// it proposes, plans and writes nothing.
    @Test("a later format signed by the owner stops the chain where it begins, and nothing is written past it")
    func laterFormatStopsTheChain() async throws {
        var household = try await SharingHousehold.make(seed: 91)
        let head = household.state
        let transfer = try Self.laterFormat(after: head, signer: household.owner)
        let carryOnKey = household.newKeyID()
        let carryOn = try household.forgery(.rotateKey, signer: household.administrator, newKeyID: carryOnKey)
            .signed(by: household.administrator.keyset)

        for batches in [[[transfer, carryOn]], [[carryOn], [transfer]], [[transfer], [carryOn]]] {
            var ledger = household.ledger
            for batch in batches {
                ledger.ingest(batch)
            }
            #expect(ledger.continuesInLaterFormat)
            #expect(ledger.state.hash == head.hash, "the chain stops at the record the later one follows")
            #expect(ledger.branches.count == 1, "the administrator's record is held, not accepted")
            // Serving less afterwards rolls nothing back, and neither does a restart (A8 cannot drop it either: the
            // saved ledger is signed).
            ledger.ingest([])
            #expect(ledger.continuesInLaterFormat)
            #expect(ledger.state.hash == head.hash)
            let restored = try Self.restored(ledger, household)
            #expect(restored.continuesInLaterFormat)
            #expect(restored.state.hash == head.hash)
            #expect(restored.laterFormatRecords == [transfer])

            #expect(ledger.writePermission(for: household.writer.accountID) == .refused(.requiresNewerVersion))
            #expect(ledger.writePermission(for: household.owner.accountID) == .refused(.requiresNewerVersion))
            #expect(throws: SharingError.requiresNewerVersion) {
                try ledger.proposeRoleChange(
                    of: household.writer.accountID, to: .readOnly, signedBy: household.owner.keyset)
            }
            #expect(throws: SharingError.requiresNewerVersion) {
                try RotationPlanner.plan(.routine, ledger: ledger, signedBy: household.administrator.keyset)
            }
        }

        // An unknown operation under this version's own format version is a later format too.
        var ledger = household.ledger
        ledger.ingest([try Self.laterFormat(after: head, signer: household.owner, version: 2, operation: [9])])
        #expect(ledger.continuesInLaterFormat)
    }

    /// The sync store (A1), or a member who is not the owner, plants something in a later format's clothing to freeze
    /// the vault for every device on this version. Only the owner as of the record it follows can sign one that
    /// counts; anything else is junk, costs one signature check at most, and changes nothing.
    @Test("a later format not signed by the owner, or not in its place, changes nothing")
    func laterFormatImpostors() async throws {
        var household = try await SharingHousehold.make(seed: 92)
        let head = household.state
        var unsigned = ForgedRecord(after: head, signer: household.owner.accountID, operation: .rotateKey)
        unsigned.formatVersion = 3
        var elsewhere = ForgedRecord(after: head, signer: household.owner.accountID, operation: .rotateKey)
        elsewhere.formatVersion = 3
        elsewhere.vaultID = UUID()
        var skipped = ForgedRecord(after: head, signer: household.owner.accountID, operation: .rotateKey)
        skipped.formatVersion = 3
        skipped.epoch += 1
        let impostors = [
            try Self.laterFormat(after: head, signer: household.administrator),
            try Self.laterFormat(after: head, signer: household.writer),
            unsigned.withSignature([UInt8](repeating: 0x5A, count: 64)),
            try unsigned.signed(by: household.administrator.keyset),
            try elsewhere.signed(by: household.owner.keyset),
            try skipped.signed(by: household.owner.keyset),
        ]
        var ledger = household.ledger
        let report = ledger.ingest(impostors)
        #expect(!ledger.continuesInLaterFormat)
        #expect(ledger.state.hash == head.hash)
        #expect(report.rejected.count == impostors.count)
        #expect(report.signatureChecks <= 4, "one check each at most, and none for what cannot be in place")
        #expect(ledger.writePermission(for: household.writer.accountID) == .allowed)

        // The vault goes on as before.
        let nextKey = household.newKeyID()
        let next = try household.forgery(.rotateKey, signer: household.administrator, newKeyID: nextKey)
            .signed(by: household.administrator.keyset)
        ledger.ingest([next])
        #expect(ledger.state.epoch == head.epoch + 1)
    }
}
