import Foundation
import Testing
import WatchwordCrypto
import WatchwordTestSupport

@testable import WatchwordSharing

/// Known answers from an independent implementation of the formats in docs/02-architecture.md §8.2: a Python script
/// using `cryptography` for Ed25519 and X25519 and `hashlib` for SHA-256 and SHA-512, with its own encoders (never
/// this module's). Inputs: the owner's Ed25519 seed is bytes 0...31 and X25519 private key bytes 32...63; the
/// member's are bytes 64...95 and 96...127; the account, vault and key IDs are the UUIDs visible in the vectors.
/// The chain is a genesis, the owner adding the member as read-write, and the member's departure carried out by the
/// owner with a new key and a write cut. (The script first reproduces the version-1 vectors these replaced, from the
/// same keys, so it is the same encoder with the cut added.)
///
/// These pin the wire format: a change that alters any of these bytes or hashes is a format change, and devices that
/// disagree about a record's hash disagree about the whole chain after it.
@Suite("Sharing formats: known answers")
struct SharingKnownAnswerTests {
    static let vaultID = UUID(uuidString: "11111111-2222-4333-8444-555555555555")!
    static let ownerID = UUID(uuidString: "0F0E0D0C-0B0A-4908-8706-050403020100")!
    static let memberID = UUID(uuidString: "A1A2A3A4-B1B2-4C1C-8D1D-E1E2E3E4E5E6")!

    static let ownerBundle = """
        57574b42010f0e0d0c0b0a49088706050403020100358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0
        d2cd16625403a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b81f31ea110d63c4cfb4460a
        27f70a9f6fa10011e37d313768d40c4b1f2ab658ecc1d640e39ffcbfa7e77125841007de12934f7dc541bb35da4f8c74
        a464639900
        """
    static let memberBundle = """
        57574b4201a1a2a3a4b1b24c1c8d1de1e2e3e4e5e6675dd574ed7789310b3d2e7681f3790b466c773b1521fecf365779
        58371ea52f2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d14cce7d64b6a40fa957868
        fa83f41eac8534161fad26075c76888c822c58e230e5f74c64dc955bcc54c68bbe56410a370e0ab7a446fee4ec4b3fd9
        b575d16c01
        """
    static let genesis = """
        57574d520211111111222243338444555555555555000000000000000000000000000000000000000000000000000000
        000000000000000000000000000f0e0d0c0b0a4908870605040302010000aaaaaaaa0000400080000000000000000000
        000000000000000001000f0e0d0c0b0a49088706050403020100000000000000000000358072d6365880d1aeea329adf
        9121383851ed21a28e3b75e965d0d2cd16625403a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc866412
        5531b81f31ea110d63c4cfb4460a27f70a9f6fa10011e37d313768d40c4b1f2ab658ecc1d640e39ffcbfa7e771258410
        07de12934f7dc541bb35da4f8c74a4646399002fc431db6e0b78a31707c9f50b47270c8b7a44c2e1daac8215e308b4c0
        8dd70be25fcf091fd9e3b313c4b53555596d9d7957de23c7f24295d80d641585a3f508
        """
    static let addition = """
        57574d5202111111112222433384445555555555550100000000000000f147109e4d1eee4730020a96767e1573ef2d12
        1d100f1d76c0ea49591ef5cd840f0e0d0c0b0a4908870605040302010001a1a2a3a4b1b24c1c8d1de1e2e3e4e5e602aa
        aaaaaa0000400080000000000000000000000000000000000002000f0e0d0c0b0a490887060504030201000000000000
        00000000358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd16625403a107bff3ce10be1d70dd18
        e74bc09967e4d6309ba50d5f1ddc8664125531b81f31ea110d63c4cfb4460a27f70a9f6fa10011e37d313768d40c4b1f
        2ab658ecc1d640e39ffcbfa7e77125841007de12934f7dc541bb35da4f8c74a464639900a1a2a3a4b1b24c1c8d1de1e2
        e3e4e5e6020100000000000000675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f2543b9
        2ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d14cce7d64b6a40fa957868fa83f41eac853416
        1fad26075c76888c822c58e230e5f74c64dc955bcc54c68bbe56410a370e0ab7a446fee4ec4b3fd9b575d16c0165288c
        c5da224f830ababb2ca47315c1935d3463a8fe695c7e67c00b2d36832dbafd7def78c69c0c6fd232002accf95030e390
        f4858fbbf30f39071ad3313109
        """
    static let departure = """
        57574d5202111111112222433384445555555555550200000000000000ba8d45015d5c08b4501f45c967bb1bd4dee6cb
        6a5ec4bb078110af3ad1355ffa0f0e0d0c0b0a4908870605040302010003a1a2a3a4b1b24c1c8d1de1e2e3e4e5e62424
        cb0131ab5107beb186d3623be58e4e5114f450e10ccf1c9d813bbf7a14a97215c054ccc9182369655b593ed542872f6f
        bf0771783a7b5d30369e7f685806bbbbbbbb00004000800000000000000202000000000000002400c0ffee00c8c9cacb
        cccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e701000f0e0d0c0b0a490887060504030201000000
        00000000000000358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd16625403a107bff3ce10be1d
        70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b81f31ea110d63c4cfb4460a27f70a9f6fa10011e37d313768d4
        0c4b1f2ab658ecc1d640e39ffcbfa7e77125841007de12934f7dc541bb35da4f8c74a464639900ed8913c265ca5f1c70
        aaa6c5195756c1a456fed56f0eba8e6076d613f9da9a8f8e537399bc928c69e598c5446a15b78dd62723f8c3ed7034b6
        09d8f05809bf09
        """
    static let leaveRequest = """
        57574c520111111111222243338444555555555555a1a2a3a4b1b24c1c8d1de1e2e3e4e5e601000000000000002424cb
        0131ab5107beb186d3623be58e4e5114f450e10ccf1c9d813bbf7a14a97215c054ccc9182369655b593ed542872f6fbf
        0771783a7b5d30369e7f685806
        """
    static let hashes = [
        "f147109e4d1eee4730020a96767e1573ef2d121d100f1d76c0ea49591ef5cd84",
        "ba8d45015d5c08b4501f45c967bb1bd4dee6cb6a5ec4bb078110af3ad1355ffa",
        "087655532d619eb96036aa4c6c924a066d8a7fff58b220b194b6069b7ef5d7d1",
    ]
    /// The departure's write cut: 36 bytes that mean nothing to this module.
    static let writeCut = "c0ffee00c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7"
    static let code =
        "WWFP1-0F0E0D0C0B0A49088706050403020100142BCF252D12860EE2FDE24A5738A33AF746B7E0A7EE1790ACDB8477724B1CC779"
        + "55A146492624871B8BBABF19E69FA16A588B340DFF490BA85B6D45"
    static let safetyNumber = "41677 33885 39011 10112 60204 58379 02049 47207 88633 33944 86697 04293"

    static func owner() throws -> PublicKeyBundle {
        try KeyBundleCodec.parse([UInt8](hex: ownerBundle), expecting: ownerID)
    }

    @Test("a chain written by an independent implementation verifies, with the hashes it computed")
    func chainVerifies() throws {
        let owner = VerifiedContact(bundle: try Self.owner(), method: .comparedByEye, verifiedAt: nil)
        let records = [Self.departure, Self.genesis, Self.addition].map { [UInt8](hex: $0) }
        let (ledger, report) = try MembershipLedger.join(vaultID: Self.vaultID, owner: owner, candidates: records)

        #expect(report.rejected.isEmpty)
        #expect(ledger.chain.map(\.state.hash.hex) == Self.hashes)
        #expect(ledger.state.epoch == 2)
        #expect(ledger.state.members.map(\.accountID) == [Self.ownerID])
        #expect(ledger.state.vaultKeyID == UUID(uuidString: "BBBBBBBB-0000-4000-8000-000000000002"))
        #expect(ledger.state.keyEpoch == 2)
        #expect(ledger.chain[1].state.member(Self.memberID)?.role == .readWrite)
        #expect(ledger.chain[1].state.member(Self.memberID)?.since == 1)
        #expect(ledger.chain[1].state.vaultKeyID == UUID(uuidString: "AAAAAAAA-0000-4000-8000-000000000000"))
        #expect(ledger.chain.map(\.record.writeCut.bytes) == [[], [], [UInt8](hex: Self.writeCut)])
        let member = try #require(ledger.chain[1].state.member(Self.memberID))
        #expect(
            ledger.writeStanding(of: Self.memberID)
                == .ended(cut: try WriteCut([UInt8](hex: Self.writeCut)), author: member, refusal: .notAMember))
    }

    @Test("parsing and re-encoding each record reproduces the independent encoder's bytes")
    func recordsReencode() throws {
        for vector in [Self.genesis, Self.addition, Self.departure] {
            let bytes = [UInt8](hex: vector)
            #expect(try MembershipRecord.parse(bytes).encoded() == bytes)
        }
        let departure = try MembershipRecord.parse([UInt8](hex: Self.departure))
        // The object's name ends in SHA-256 of the whole object (hashlib, over the vector above).
        #expect(
            SharingObjectLocation.membership(departure).name
                == "sharing/11111111-2222-4333-8444-555555555555/membership/00000000000000000002-" + Self.hashes[2]
                + "-06f9afae397cb5c08a4f8233aa659146e6247ba42c4bb14719388078595d0930")
    }

    @Test("a published bundle and a leave request written independently parse, validate and re-encode")
    func bundleAndLeaveRequest() throws {
        let member = try KeyBundleCodec.parse([UInt8](hex: Self.memberBundle), expecting: Self.memberID)
        #expect(KeyBundleCodec.encode(member) == [UInt8](hex: Self.memberBundle))
        #expect(KeyBundleCodec.encode(try Self.owner()) == [UInt8](hex: Self.ownerBundle))

        let request = try LeaveRequest.parse([UInt8](hex: Self.leaveRequest))
        #expect(request.encoded() == [UInt8](hex: Self.leaveRequest))
        #expect(request.vaultID == Self.vaultID)
        #expect(request.accountID == Self.memberID)
        #expect(request.memberSince == 1)

        let owner = VerifiedContact(bundle: try Self.owner(), method: .comparedByEye, verifiedAt: nil)
        let ledger = try MembershipLedger.join(
            vaultID: Self.vaultID, owner: owner,
            candidates: [Self.genesis, Self.addition].map { [UInt8](hex: $0) }
        ).ledger
        try request.validate(against: ledger.state)
    }

    @Test("the fingerprint code and the safety number are the independently computed ones")
    func fingerprintCode() throws {
        let owner = try Self.owner()
        #expect(FingerprintCode(bundle: owner).payload == Self.code)
        #expect(Self.code.utf8.count == FingerprintCode.payloadLength)
        #expect(try FingerprintCode(scanned: Self.code).matches(owner))
        #expect(owner.fingerprint.safetyNumber == Self.safetyNumber)
        #expect(owner.fingerprint.matches(safetyNumber: Self.safetyNumber))
    }
}
