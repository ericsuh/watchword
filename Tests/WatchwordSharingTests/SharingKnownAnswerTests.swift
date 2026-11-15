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
/// owner with a new key.
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
        57574d520111111111222243338444555555555555000000000000000000000000000000000000000000000000000000
        000000000000000000000000000f0e0d0c0b0a4908870605040302010000aaaaaaaa0000400080000000000000000000
        00000000000001000f0e0d0c0b0a49088706050403020100000000000000000000358072d6365880d1aeea329adf9121
        383851ed21a28e3b75e965d0d2cd16625403a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531
        b81f31ea110d63c4cfb4460a27f70a9f6fa10011e37d313768d40c4b1f2ab658ecc1d640e39ffcbfa7e77125841007de
        12934f7dc541bb35da4f8c74a4646399003ac0e5b5e0d789112282c52a85c6c92eeaec56fa99d4a7bbf6fb5e2f6349ca
        ec7b9569345c66f8ba7aadca9ca4239db3f89ceb63d50cad697fd37830624ed70d
        """
    static let addition = """
        57574d5201111111112222433384445555555555550100000000000000cc223b7579fe6c465ddda019811756daf93815
        8c4b8e7e1b9306e319171290640f0e0d0c0b0a4908870605040302010001a1a2a3a4b1b24c1c8d1de1e2e3e4e5e602aa
        aaaaaa000040008000000000000000000000000000000002000f0e0d0c0b0a4908870605040302010000000000000000
        0000358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd16625403a107bff3ce10be1d70dd18e74b
        c09967e4d6309ba50d5f1ddc8664125531b81f31ea110d63c4cfb4460a27f70a9f6fa10011e37d313768d40c4b1f2ab6
        58ecc1d640e39ffcbfa7e77125841007de12934f7dc541bb35da4f8c74a464639900a1a2a3a4b1b24c1c8d1de1e2e3e4
        e5e6020100000000000000675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f2543b92ff1
        095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d14cce7d64b6a40fa957868fa83f41eac8534161fad
        26075c76888c822c58e230e5f74c64dc955bcc54c68bbe56410a370e0ab7a446fee4ec4b3fd9b575d16c01c494f964f9
        c9218dfc8458829eb050cd20f622e3813cf92f8ab97464e7bbdbd9252ba31b0003039ee98cae9c45e1df2376f484808d
        a8240a862bdafcbbd07a0f
        """
    static let departure = """
        57574d5201111111112222433384445555555555550200000000000000706658b8cc6b6ebad06355409fa2c1086cd770
        ea426dfa30e8a2277c81c972b70f0e0d0c0b0a4908870605040302010003a1a2a3a4b1b24c1c8d1de1e2e3e4e5e62424
        cb0131ab5107beb186d3623be58e4e5114f450e10ccf1c9d813bbf7a14a97215c054ccc9182369655b593ed542872f6f
        bf0771783a7b5d30369e7f685806bbbbbbbb000040008000000000000002020000000000000001000f0e0d0c0b0a4908
        8706050403020100000000000000000000358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662
        5403a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b81f31ea110d63c4cfb4460a27f70a9f
        6fa10011e37d313768d40c4b1f2ab658ecc1d640e39ffcbfa7e77125841007de12934f7dc541bb35da4f8c74a4646399
        00208c75bbe4e7b1d1d4a26b45eca3fcccdf09067298c30f31ef7ba35b7d7b6342c12db6d5e2d5d602e7cf861cc6d512
        29f1f47451f880abf92f0c5c12fc01ed0e
        """
    static let leaveRequest = """
        57574c520111111111222243338444555555555555a1a2a3a4b1b24c1c8d1de1e2e3e4e5e601000000000000002424cb
        0131ab5107beb186d3623be58e4e5114f450e10ccf1c9d813bbf7a14a97215c054ccc9182369655b593ed542872f6fbf
        0771783a7b5d30369e7f685806
        """
    static let hashes = [
        "cc223b7579fe6c465ddda019811756daf938158c4b8e7e1b9306e31917129064",
        "706658b8cc6b6ebad06355409fa2c1086cd770ea426dfa30e8a2277c81c972b7",
        "0df120b6223cc138f232762e6ddd14d5ee4f14811b308af256a1e899637ab1da",
    ]
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
                + "-11ce53bb0384baf8c1fe63f00ef3304d1f28e730e689492dc04c00418b64055d")
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
