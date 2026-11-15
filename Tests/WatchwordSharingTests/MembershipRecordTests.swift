import Foundation
import Testing
import WatchwordCrypto
import WatchwordTestSupport

@testable import WatchwordSharing

/// The membership record's encoding and its bounded parser (docs/02-architecture.md §8.2, PRD SEC9).
@Suite("Membership record format")
struct MembershipRecordTests {
    /// One record of each operation, taken from a real chain.
    static func samples() async throws -> [MembershipRecord] {
        var household = try await SharingHousehold.make()
        let guest = try SharingParty(seed: 77)
        try await household.add(guest, as: .readWrite, by: household.administrator)
        try household.adopt(
            household.ledger.proposeRoleChange(
                of: guest.accountID, to: .readOnly, signedBy: household.administrator.keyset
            ).encoded())
        let request = try LeaveRequest.make(leaving: household.state, as: guest.keyset)
        try household.rotate(.departure(request), by: household.administrator)
        try household.rotate(.removal(household.reader.accountID), by: household.owner)
        try household.rotate(.routine, by: household.administrator)
        try household.adopt(household.ledger.proposeDeletion(signedBy: household.owner.keyset).encoded())
        return household.ledger.chain.map(\.record)
    }

    @Test("every operation survives encoding and parsing unchanged, and the test encoder agrees byte for byte")
    func roundTrip() async throws {
        let records = try await Self.samples()
        #expect(Set(records.map(\.operation.code)) == Set(0...6))
        for record in records {
            let bytes = record.encoded()
            #expect(bytes.count <= MembershipRecord.maximumLength)
            let parsed = try MembershipRecord.parse(bytes)
            #expect(parsed == record)
            #expect(parsed.encoded() == bytes)
            #expect(parsed.hash == record.hash)
        }
    }

    @Test("an honest record from the tests' own encoder is accepted: two encoders, one format")
    func independentEncoder() async throws {
        var household = try await SharingHousehold.make()
        let forged = household.forgery(.changeRole(household.writer.accountID, to: .readOnly), signer: household.owner)
        let honest = try household.ledger.proposeRoleChange(
            of: household.writer.accountID, to: .readOnly, signedBy: household.owner.keyset)
        #expect(forged.content == honest.signedContent)
        try household.adopt(forged.signed(by: household.owner.keyset))
        #expect(household.state.member(household.writer.accountID)?.role == .readOnly)
    }

    @Test("a record cut short at any length is refused, and so is one with anything after it")
    func truncationAndTrailingBytes() async throws {
        for record in try await Self.samples() {
            let bytes = record.encoded()
            for length in 0..<bytes.count {
                #expect(throws: SharingFormatError.self, "length \(length)") {
                    _ = try MembershipRecord.parse(Array(bytes[0..<length]))
                }
            }
            #expect(throws: SharingFormatError.self) {
                _ = try MembershipRecord.parse(bytes + [0])
            }
        }
    }

    @Test("an oversized record is refused before it is parsed")
    func oversized() {
        let huge = [UInt8](repeating: 0x57, count: MembershipRecord.maximumLength + 1)
        #expect(throws: SharingFormatError.tooLarge(huge.count)) {
            _ = try MembershipRecord.parse(huge)
        }
    }

    @Test("the largest record the format allows is exactly the maximum length")
    func maximumLength() throws {
        let owner = try SharingParty(seed: 1)
        var forged = ForgedRecord(genesisOf: UUID(), owner: owner.bundle, vaultKeyID: UUID())
        forged.epoch = 9
        forged.keyEpoch = 9
        forged.operation = ForgedRecord.bytes(
            of: .memberLeft(UUID(), requestSignature: [UInt8](repeating: 1, count: 64)))
        forged.entries = (0..<MembershipLimits.maximumMembers).map { index in
            var entry = ForgedEntry(bundle: owner.bundle, role: .readWrite, since: 1)
            entry.accountID = UUID(
                uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, UInt8(index >> 8), UInt8(index & 0xFF)))
            return entry
        }
        let bytes = try forged.signed(by: owner.keyset)
        #expect(bytes.count == MembershipRecord.maximumLength)
        #expect(try MembershipRecord.parse(bytes).entries.count == MembershipLimits.maximumMembers)
    }

    @Test("fields out of range are refused with the reason")
    func bounds() async throws {
        let household = try await SharingHousehold.make()
        let owner = household.owner
        func parse(_ mutate: (inout ForgedRecord) -> Void) throws -> MembershipRecord {
            var forged = household.forgery(.rotateKey, signer: owner, newKeyID: UUID())
            mutate(&forged)
            return try MembershipRecord.parse(forged.signed(by: owner.keyset))
        }

        #expect(throws: SharingFormatError.badMagic) { _ = try parse { $0.magic = Array("WWMX".utf8) } }
        #expect(throws: SharingFormatError.unsupportedFormatVersion(2)) { _ = try parse { $0.formatVersion = 2 } }
        #expect(throws: SharingFormatError.unsupportedFormatVersion(0)) { _ = try parse { $0.formatVersion = 0 } }
        #expect(throws: SharingFormatError.unknownOperation(7)) { _ = try parse { $0.operation = [7] } }
        #expect(throws: SharingFormatError.unknownOperation(255)) { _ = try parse { $0.operation = [255] } }
        #expect(throws: SharingFormatError.unknownRole(4)) { _ = try parse { $0.entries[0].role = 4 } }
        #expect(throws: SharingFormatError.unknownRole(9)) {
            _ = try parse { $0.operation = [4] + ForgedRecord.bytes(UUID()) + [9] }
        }
        let beyond = MembershipLimits.maximumEpoch + 1
        #expect(throws: SharingFormatError.epochOutOfRange(beyond)) { _ = try parse { $0.epoch = beyond } }
        #expect(throws: SharingFormatError.epochOutOfRange(.max)) { _ = try parse { $0.epoch = .max } }
        #expect(throws: SharingFormatError.epochOutOfRange(5)) { _ = try parse { $0.keyEpoch = 5 } }
        #expect(throws: SharingFormatError.epochOutOfRange(5)) { _ = try parse { $0.entries[1].since = 5 } }
        #expect(throws: SharingFormatError.memberCountOutOfRange(0)) { _ = try parse { $0.entries = [] } }
        #expect(throws: SharingFormatError.self, "sixty-five members are already more bytes than a record may be") {
            _ = try parse { $0.entries = Array(repeating: $0.entries[0], count: 65) }
        }
        #expect(throws: SharingFormatError.notCanonical) {
            _ = try parse {
                $0.entries.reverse()
                $0.sortsEntries = false
            }
        }
        #expect(throws: SharingFormatError.notCanonical, "the same member twice") {
            _ = try parse {
                $0.entries = [$0.entries[0], $0.entries[0]]
                $0.sortsEntries = false
            }
        }
        #expect(throws: SharingFormatError.self, "a key of the wrong length shifts everything after it") {
            _ = try parse { $0.entries[0].agreementKey.removeLast() }
        }
    }

    @Test("a declared member count must account for exactly the bytes that follow")
    func memberCountMustMatch() async throws {
        let household = try await SharingHousehold.make()
        let bytes = try household.forgery(.rotateKey, signer: household.owner, newKeyID: UUID())
            .signed(by: household.owner.keyset)
        // The count field follows the fixed prefix (no operands for rotateKey): 4+1+16+8+32+16+1+16+8 bytes in.
        let countOffset = 102
        #expect(bytes[countOffset] == 4 && bytes[countOffset + 1] == 0)
        for count: UInt16 in [0, 1, 3, 5, 64, 65, 0xFFFF] {
            var mutated = bytes
            mutated[countOffset] = UInt8(count & 0xFF)
            mutated[countOffset + 1] = UInt8(count >> 8)
            let expected: SharingFormatError =
                count == 0 || count > 64 ? .memberCountOutOfRange(Int(count)) : count < 4 ? .trailingBytes : .truncated
            #expect(throws: expected, "count \(count)") {
                _ = try MembershipRecord.parse(mutated)
            }
        }
    }

    @Test("the hash covers every signed byte and not the signature")
    func hash() async throws {
        let household = try await SharingHousehold.make()
        let record = household.ledger.chain[2].record
        let bytes = record.encoded()
        let contentLength = record.signedContent.count
        #expect(bytes.count == contentLength + 64)

        var resigned = bytes
        resigned[contentLength + 5] ^= 0x01
        #expect(try MembershipRecord.parse(resigned).hash == record.hash)

        for position in stride(from: 5, to: contentLength, by: 7) {
            var mutated = bytes
            mutated[position] ^= 0x01
            if let parsed = try? MembershipRecord.parse(mutated) {
                #expect(parsed.hash != record.hash, "byte \(position)")
            }
        }
        #expect(MembershipHash.none.bytes == [UInt8](repeating: 0, count: 32))
        #expect(throws: SharingFormatError.badFieldLength) { _ = try MembershipHash(bytes: [1, 2, 3]) }
    }

    @Test("object names are exact: one spelling per object, and nothing else parses")
    func objectNames() async throws {
        var household = try await SharingHousehold.make()
        let record = household.ledger.chain[1].record
        let location = SharingObjectLocation.membership(record)
        #expect(SharingObjectLocation(name: location.name) == location)
        #expect(location.name.hasPrefix(SharingObjectLocation.membershipPrefix(household.vaultID)))
        #expect(SharingObject(record).name == location.name)

        let plan = try household.rotate(.routine, by: household.owner)
        for grant in plan.grants {
            #expect(SharingObjectLocation(name: grant.name) == grant.location)
            #expect(grant.name.hasPrefix(SharingObjectLocation.vaultPrefix(household.vaultID) + "grant/"))
        }
        let request = try LeaveRequest.make(leaving: household.state, as: household.writer.keyset)
        let leave = SharingObject(request)
        #expect(leave.location.isName(of: leave.contents) && !leave.location.isName(of: leave.contents + [0]))
        #expect(SharingObjectLocation(name: leave.name) == leave.location)
        #expect(leave.name.hasPrefix(SharingObjectLocation.leavePrefix(household.vaultID)))

        // A record's name carries its epoch, its hash and a digest of the whole object, signature included: a copy
        // with another signature is the same record under another name.
        guard case .membership(let epoch, let hash, let digest) = location.kind else {
            Issue.record("not a membership location")
            return
        }
        #expect(epoch == 1 && hash == record.hash && digest == SharingBytes.sha256(record.encoded()))
        var resigned = record.encoded()
        resigned[resigned.count - 1] ^= 1
        let copy = try MembershipRecord.parse(resigned)
        #expect(copy.hash == record.hash)
        #expect(SharingObject(copy).name != location.name)
        #expect(SharingObject(copy).name.dropLast(64) == location.name.dropLast(64))
        #expect(location.isName(of: record.encoded()) && !location.isName(of: resigned))

        let name = location.name
        let withoutDigest = String(name.dropLast(64))
        let zeros = String(repeating: "0", count: 64)
        let notHex = String(repeating: "g", count: 64)
        let bad: [String] = [
            String(name.dropLast(65)),
            name + "-" + zeros,
            withoutDigest,
            withoutDigest + notHex,
            name.lowercased(),
            name.uppercased(),
            name + "/",
            name + "0",
            String(name.dropLast()),
            name.replacingOccurrences(of: "sharing/", with: "vault/"),
            name.replacingOccurrences(of: "membership", with: "members"),
            name.replacingOccurrences(of: "00000000000000000001-", with: "1-"),
            name.replacingOccurrences(of: "00000000000000000001-", with: "+0000000000000000001-"),
            name.replacingOccurrences(of: "/membership/", with: "//membership/"),
            "sharing/" + name,
            "",
            String(repeating: "a", count: 10_000),
        ]
        for candidate in bad {
            #expect(SharingObjectLocation(name: candidate) == nil, "\(candidate.prefix(80))")
        }
    }
}
