import Foundation
import SecureMemory
import Testing
import WatchwordEnvelope
import WatchwordTestSupport

@testable import WatchwordCrypto

@Suite("Device keys and signatures")
struct DeviceKeyTests {
    static let deviceID = UUID(uuidString: "D0000000-0000-4000-8000-0000000000B0")!
    /// `"vault/7A00…0001/log/x" ‖ 0x00 ‖ "envelope-bytes"`: the shape of a sync object's signed message.
    static let message = [UInt8](
        hex: """
            7661756c742f37413030303030302d303030302d343030302d383030302d3030303030303030303030312f6c6f672f78
            00656e76656c6f70652d6279746573
            """)

    // Vectors from Python `cryptography` 50 (OpenSSL), over the bytes `DeviceSignatures.signedBytes` is specified to
    // produce — built independently there as "WW-devsig-v1" ‖ 0x00 ‖ domain ‖ deviceID ‖ message — never from this
    // code's own output.
    static let p256PublicKey = [UInt8](
        hex: """
            04945bafbfe49bbffe5c33d49cd083da75ce805aaf1f2a82cfb010e0968163582a40f7f692a325069e22cc0fe04c0e68322f4459
            e45106d54325ee23b8c66bd184
            """)
    static let p256LowS = [UInt8](
        hex: """
            c09371ee5cf24eeb5de84a3023575ceaaf082c04ee5035180b6613ab197724bb021fcf01f68df481702c4c2eecc9a3b301c639a6
            6f3fdd55ae0bfaec317ab9e9
            """)
    static let p256HighS = [UInt8](
        hex: """
            c09371ee5cf24eeb5de84a3023575ceaaf082c04ee5035180b6613ab197724bbfde030fd09720b7f8fd3b3d113365c4cbb20c107
            37d7c12f45adcfd6cae86b68
            """)
    static let ed25519PublicKey = [UInt8](hex: "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
    static let ed25519Signature = [UInt8](
        hex: """
            ab4370615fd3d2a7356f8cedba786efb45eb01697a47777a83b8635372ea72a94efc369bb1bb9dd301929708dafd0f1ce05e2348
            692a7dfee54e0a531796880d
            """)

    @Test("an Ed25519 device signature made elsewhere verifies, and only for its device and domain")
    func ed25519KnownAnswer() throws {
        let key = try DevicePublicKey(algorithm: .ed25519, rawRepresentation: Self.ed25519PublicKey)
        try DeviceSignatures.verify(
            Self.ed25519Signature, for: Self.message, domain: .logSegment, deviceID: Self.deviceID, key: key)
        #expect(throws: CryptoError.signatureInvalid) {
            try DeviceSignatures.verify(
                Self.ed25519Signature, for: Self.message, domain: .deviceRegistry, deviceID: Self.deviceID, key: key)
        }
        #expect(throws: CryptoError.signatureInvalid) {
            try DeviceSignatures.verify(
                Self.ed25519Signature, for: Self.message, domain: .logSegment, deviceID: UUID(), key: key)
        }
        // The software key signs the same bytes to the same signature (Ed25519 is deterministic).
        let software = try SoftwareDeviceKey(seed: SecureBytes(copying: (0..<32).map { UInt8($0) }))
        #expect(try software.publicKey() == key)
        #expect(
            try software.sign(
                prepared: DeviceSignatures.signedBytes(
                    domain: .logSegment, deviceID: Self.deviceID, message: Self.message)) == Self.ed25519Signature)
    }

    @Test("a P-256 signature as a Secure Enclave key makes verifies; its high-S twin is refused")
    func p256KnownAnswer() throws {
        let key = try DevicePublicKey(algorithm: .p256ECDSA, rawRepresentation: Self.p256PublicKey)
        try DeviceSignatures.verify(
            Self.p256LowS, for: Self.message, domain: .logSegment, deviceID: Self.deviceID, key: key)
        // (r, n − s) is as valid an ECDSA signature as (r, s); accepting both would give every entry two names.
        #expect(throws: CryptoError.signatureInvalid) {
            try DeviceSignatures.verify(
                Self.p256HighS, for: Self.message, domain: .logSegment, deviceID: Self.deviceID, key: key)
        }
        var tampered = Self.message
        tampered[0] ^= 1
        #expect(throws: CryptoError.signatureInvalid) {
            try DeviceSignatures.verify(
                Self.p256LowS, for: tampered, domain: .logSegment, deviceID: Self.deviceID, key: key)
        }
    }

    @Test("a device public key is validated when it is made")
    func publicKeyValidation() {
        #expect(throws: CryptoError.self) {
            try DevicePublicKey(algorithm: .ed25519, rawRepresentation: [UInt8](repeating: 0, count: 32))
        }
        #expect(throws: CryptoError.self) {
            try DevicePublicKey(algorithm: .ed25519, rawRepresentation: [1, 2, 3])
        }
        var offCurve = Self.p256PublicKey
        offCurve[64] ^= 1
        #expect(throws: CryptoError.invalidPublicKey) {
            try DevicePublicKey(algorithm: .p256ECDSA, rawRepresentation: offCurve)
        }
        #expect(throws: CryptoError.invalidPublicKey) {
            try DevicePublicKey(algorithm: .p256ECDSA, rawRepresentation: Array(Self.p256PublicKey.dropFirst()))
        }
    }

    @Test("the enrolment key is HKDF-SHA256 of the AUK, as an independent implementation derives it")
    func enrolmentKeyKnownAnswer() throws {
        // Python: HKDF(SHA256, salt = accountID, info = "WW-enrol-v1").derive(bytes(0x40…0x5f)) as an Ed25519 seed.
        let accountID = UUID(uuidString: "AC000000-0000-4000-8000-0000000000AC")!
        let unlockKey = try EncryptionKey(
            keyID: UUID(), material: SecureBytes(copying: (0x40..<0x60).map { UInt8($0) }))
        let enrolment = EnrolmentKey.derive(from: unlockKey, accountID: accountID)
        #expect(
            try enrolment.publicKey()
                == [UInt8](hex: "874c5b64c92374c3560c407e9bd1b679f439b75d41b1d6716ffb0c3b4ccce73d"))
        let signature = try enrolment.sign([0x02] + Array("entry".utf8), domain: .deviceRegistry)
        #expect(
            signature
                == [UInt8](
                    hex: """
                        c29d05909768b00c1b19d8e57d018b3b8ec9e51793ef4042971e05acf3851bdd7001fe00c7a5af537f967bc2d020
                        d86bd9bc8b1e00987e0008d4ba3c0070260a
                        """))
        // Another account, or another AUK, is another key.
        #expect(try EnrolmentKey.derive(from: unlockKey, accountID: UUID()).publicKey() != enrolment.publicKey())
    }

    @Test("an object digest is SHA-256, and parses only from 64 lower-case hexadecimal digits")
    func digests() {
        let digest = ObjectDigest(hashing: Array("abc".utf8))
        #expect(digest.hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(ObjectDigest(hex: digest.hex) == digest)
        #expect(ObjectDigest(hex: digest.hex.uppercased()) == nil)
        #expect(ObjectDigest(hex: String(digest.hex.dropLast())) == nil)
        #expect(ObjectDigest(hex: digest.hex + "00") == nil)
        #expect(ObjectDigest(bytes: [1, 2, 3]) == nil)
    }
}

@Suite("Device registry")
struct DeviceRegistryTests {
    static let a = RegistryFixture.deviceID(0xA0)
    static let b = RegistryFixture.deviceID(0xB0)
    static let c = RegistryFixture.deviceID(0xC0)
    static let d = RegistryFixture.deviceID(0xD0)

    @Test("an entry round-trips to exactly the bytes it was parsed from")
    func codec() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        let add = f.add(Self.b, by: Self.a, parents: [genesis])
        let enrolled = f.enrol(Self.c, credential: genesis, generation: 0, parents: [genesis, add])
        let revoke = f.revoke(Self.b, by: Self.a, parents: [add])
        _ = f.nextUnlockKey()
        let credential = f.credential(generation: 1, previous: genesis, by: Self.a, parents: [revoke])
        for entry in [genesis, add, enrolled, revoke, credential] {
            let bytes = entry.serialized()
            let parsed = try RegistryEntry.parse(bytes)
            #expect(parsed == entry)
            #expect(parsed.serialized() == bytes)
            #expect(parsed.id == ObjectDigest(hashing: bytes))
        }
    }

    @Test("every truncation and every trailing byte is refused with a typed error")
    func parserIsExact() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        _ = f.nextUnlockKey()
        let credential = f.credential(generation: 1, previous: genesis, by: Self.a, parents: [genesis])
        for bytes in [genesis.serialized(), credential.serialized()] {
            for length in 0..<bytes.count {
                #expect(throws: AccountFormatError.self) { try RegistryEntry.parse(Array(bytes.prefix(length))) }
            }
            #expect(throws: AccountFormatError.trailingBytes) { try RegistryEntry.parse(bytes + [0]) }
        }
        #expect(throws: AccountFormatError.tooLong(RegistryEntry.maximumLength + 1)) {
            try RegistryEntry.parse([UInt8](repeating: 0, count: RegistryEntry.maximumLength + 1))
        }
        var wrongMagic = genesis.serialized()
        wrongMagic[0] ^= 0xFF
        #expect(throws: AccountFormatError.badMagic) { try RegistryEntry.parse(wrongMagic) }
        var wrongVersion = genesis.serialized()
        wrongVersion[4] = 9
        #expect(throws: AccountFormatError.unsupportedVersion(9)) { try RegistryEntry.parse(wrongVersion) }
    }

    @Test("parents out of order, or repeated, are not a canonical entry")
    func parentsAreCanonical() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        let one = f.add(Self.b, by: Self.a, parents: [genesis])
        let two = f.add(Self.c, by: Self.a, parents: [genesis])
        let merged = f.revoke(Self.b, by: Self.a, parents: [one, two])
        var bytes = merged.serialized()
        // The two parents sit after magic(4) version(1) type(1) account(16) count(1); swap them.
        let first = 23..<55
        let second = 55..<87
        let swapped = Array(bytes[second]) + Array(bytes[first])
        bytes.replaceSubrange(23..<87, with: swapped)
        #expect(throws: AccountFormatError.notCanonical) { try RegistryEntry.parse(bytes) }
        var repeated = merged.serialized()
        repeated.replaceSubrange(second, with: Array(repeated[first]))
        #expect(throws: AccountFormatError.notCanonical) { try RegistryEntry.parse(repeated) }
    }

    @Test("a device added by a registered device, and one that registers itself, may write; others may not")
    func addingDevices() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        let add = f.add(Self.b, by: Self.a, parents: [genesis])
        let enrolled = f.enrol(Self.c, credential: genesis, generation: 0, parents: [add])
        let state = try f.evaluate([genesis, add, enrolled], genesis: genesis)
        #expect(Set(state.devices.keys) == [Self.a, Self.b, Self.c])
        #expect(state.standing(of: Self.d) == .unknown)
        #expect(state.devices[Self.b]?.addedBy == .device(Self.a))
        #expect(state.devices[Self.c]?.addedBy == .enrolment(credential: genesis.id))
        #expect(state.heads == [enrolled.id])
        #expect(state.credential.generation == 0)

        // Added by a device the registry does not hold: nothing.
        let stranger = f.add(Self.d, by: RegistryFixture.deviceID(0x99), parents: [genesis])
        #expect(try f.evaluate([genesis, stranger], genesis: genesis).standing(of: Self.d) == .unknown)
    }

    @Test("every device computes the same registry from the same entries, whatever order they arrived in")
    func deterministic() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        let addB = f.add(Self.b, by: Self.a, parents: [genesis])
        let addC = f.enrol(Self.c, credential: genesis, generation: 0, parents: [genesis])
        let revokeC = f.revoke(Self.c, by: Self.b, parents: [addB, addC])
        let addD = f.add(Self.d, by: Self.c, parents: [addC])
        var entries = [genesis, addB, addC, revokeC, addD]
        let reference = try f.evaluate(entries, genesis: genesis)
        var generator = SeededGenerator(seed: 3)
        for _ in 0..<20 {
            entries.shuffle(using: &generator)
            #expect(try f.evaluate(entries, genesis: genesis) == reference)
        }
        // D was added by C at the same time as C was revoked: the revocation is replayed first, so C's word no
        // longer counts.
        #expect(reference.standing(of: Self.c) == .revoked)
        #expect(reference.standing(of: Self.d) == .unknown)
        #expect(reference.revoked[Self.c]?.revokedBy == Self.b)
    }

    @Test("a subset that is missing a parent leaves the orphan out until the parent arrives")
    func causalClosure() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        let addB = f.add(Self.b, by: Self.a, parents: [genesis])
        let addC = f.add(Self.c, by: Self.b, parents: [addB])
        let partial = try f.evaluate([genesis, addC], genesis: genesis)
        #expect(Set(partial.devices.keys) == [Self.a])
        #expect(!partial.connectedEntries.contains(addC.id))
        #expect(Set(try f.evaluate([genesis, addB, addC], genesis: genesis).devices.keys) == [Self.a, Self.b, Self.c])
    }

    @Test("a revoked device never returns: not under its ID, not under its key, not by its own hand")
    func revocationIsFinal() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        let addB = f.add(Self.b, by: Self.a, parents: [genesis])
        let revoke = f.revoke(Self.b, by: Self.a, parents: [addB])

        // Added again by a registered device, and enrolling again with the password: the same ID stays out.
        let again = f.add(Self.b, by: Self.a, parents: [revoke])
        let enrolAgain = f.enrol(Self.b, credential: genesis, generation: 0, parents: [revoke])
        var state = try f.evaluate([genesis, addB, revoke, again, enrolAgain], genesis: genesis)
        #expect(state.standing(of: Self.b) == .revoked)
        #expect(!state.validEntries.contains(again.id) && !state.validEntries.contains(enrolAgain.id))

        // The same key under a new device ID.
        let key = try f.key(for: Self.b).publicKey()
        let renamed = f.signed(
            RegistryEntry(
                accountID: f.accountID, parents: [revoke.id], author: .device(Self.a),
                body: .add(RegistryDevice(id: Self.d, key: key, label: []))))
        state = try f.evaluate([genesis, addB, revoke, renamed], genesis: genesis)
        #expect(state.standing(of: Self.d) == .unknown)

        // The revoked device signing for itself, or for a friend.
        let selfAdd = f.add(Self.b, by: Self.b, parents: [revoke])
        let friend = f.add(Self.c, by: Self.b, parents: [revoke])
        state = try f.evaluate([genesis, addB, revoke, selfAdd, friend], genesis: genesis)
        #expect(state.standing(of: Self.b) == .revoked)
        #expect(state.standing(of: Self.c) == .unknown)
        #expect(Set(state.devices.keys) == [Self.a])
    }

    @Test("a registered device's key cannot be replaced, and one key cannot serve two devices")
    func keysAreFixed() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        let addB = f.add(Self.b, by: Self.a, parents: [genesis])
        var other = RegistryFixture(seed: 77)
        let replaced = f.signed(
            RegistryEntry(
                accountID: f.accountID, parents: [addB.id], author: .device(Self.a),
                body: .add(other.certificate(Self.b))))
        var state = try f.evaluate([genesis, addB, replaced], genesis: genesis)
        #expect(try state.devices[Self.b]?.key == f.key(for: Self.b).publicKey())
        #expect(!state.validEntries.contains(replaced.id))

        let shared = f.signed(
            RegistryEntry(
                accountID: f.accountID, parents: [addB.id], author: .device(Self.a),
                body: .add(RegistryDevice(id: Self.c, key: try f.key(for: Self.b).publicKey(), label: []))))
        state = try f.evaluate([genesis, addB, shared], genesis: genesis)
        #expect(state.standing(of: Self.c) == .unknown)
    }

    @Test("a password change is a new generation; only the newest enrolment key registers a device")
    func credentialChain() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        let before = f.enrol(Self.b, credential: genesis, generation: 0, parents: [genesis])
        _ = f.nextUnlockKey()
        let change = f.credential(generation: 1, previous: genesis, by: Self.a, parents: [before])
        // With the old password after the change, and with the new one.
        let late = f.enrol(Self.c, credential: genesis, generation: 0, parents: [change])
        let current = f.enrol(Self.d, credential: change, generation: 1, parents: [change])
        let entries = [genesis, before, change, late, current]

        let followed = try f.evaluate(entries, genesis: genesis, credential: change)
        #expect(followed.credential.generation == 1)
        #expect(followed.credentialChain.map(\.id) == [genesis.id, change.id])
        #expect(Set(followed.devices.keys) == [Self.a, Self.b, Self.d])
        #expect(followed.pendingCredentials.isEmpty)

        // A device that has not been given the new password yet: the change is pending, and a device enrolled with
        // the new password does not count for it yet.
        let behind = try f.evaluate(entries, genesis: genesis)
        #expect(behind.credential.generation == 0)
        #expect(behind.pendingCredentials.map(\.id) == [change.id])
        #expect(behind.standing(of: Self.d) == .unknown)
    }

    @Test("a credential change needs the previous generation's enrolment key and a registered device")
    func credentialChangeNeedsThePassword() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        let addB = f.add(Self.b, by: Self.a, parents: [genesis])
        _ = f.nextUnlockKey()
        let honest = f.credential(generation: 1, previous: genesis, by: Self.a, parents: [addB])

        // B holds the keyset and a registered device key, but not the password: it signs the "previous" slot with
        // the key it is announcing.
        var forged = honest
        forged.author = .device(Self.b)
        forged = f.signed(forged, previousGeneration: 1)
        let state = try f.evaluate([genesis, addB, forged], genesis: genesis)
        #expect(state.pendingCredentials.isEmpty)
        #expect(throws: DeviceRegistryError.brokenCredentialChain) {
            try f.evaluate([genesis, addB, forged], genesis: genesis, credential: forged)
        }

        // The wrong generation number, and a device nobody registered.
        var skipped = honest
        skipped.body = .credential(
            generation: 5, enrolmentKey: try f.enrolmentKey(generation: 1).publicKey(), previous: genesis.id)
        skipped = f.signed(skipped, previousGeneration: 0)
        #expect(try f.evaluate([genesis, addB, skipped], genesis: genesis).pendingCredentials.isEmpty)
        var stranger = honest
        stranger.author = .device(Self.d)
        stranger = f.signed(stranger, previousGeneration: 0)
        #expect(try f.evaluate([genesis, addB, stranger], genesis: genesis).pendingCredentials.isEmpty)
    }

    @Test("entries a revoked device back-dates count for nothing once a password change has sealed its revocation")
    func checkpointsAreFinal() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        let addB = f.add(Self.b, by: Self.a, parents: [genesis])
        let addX = f.add(Self.c, by: Self.a, parents: [addB])
        let revokeX = f.revoke(Self.c, by: Self.a, parents: [addX])
        _ = f.nextUnlockKey()
        let change = f.credential(generation: 1, previous: genesis, by: Self.a, parents: [revokeX])

        // X kept the account key and its own device key. It writes entries that name only old parents, as if made
        // before its revocation: revoking A and B, adding a device of its own, enrolling one with the old password.
        let backdated = [
            f.revoke(Self.a, by: Self.c, parents: [addX]),
            f.revoke(Self.b, by: Self.c, parents: [addX]),
            f.add(Self.d, by: Self.c, parents: [addX]),
            f.enrol(RegistryFixture.deviceID(0xE0), credential: genesis, generation: 0, parents: [addX]),
        ]
        let entries = [genesis, addB, addX, revokeX, change] + backdated
        let state = try f.evaluate(entries, genesis: genesis, credential: change)
        #expect(Set(state.devices.keys) == [Self.a, Self.b])
        #expect(state.standing(of: Self.c) == .revoked)
        #expect(backdated.allSatisfy { !state.validEntries.contains($0.id) })

        // Even if an honest device later names X's entries as parents (it saw them), they stay void: they belong to
        // the next checkpoint's layer, where X is already revoked.
        _ = f.nextUnlockKey()
        let later = f.credential(generation: 2, previous: change, by: Self.a, parents: [change] + backdated)
        let sealed = try f.evaluate(entries + [later], genesis: genesis, credential: later)
        #expect(Set(sealed.devices.keys) == [Self.a, Self.b])
        #expect(sealed.credential.generation == 2)
    }

    /// Found by the adversarial suite: a device that has not been given the new password replays the password
    /// change among entries no checkpoint has sealed, where a back-dated revocation of the device that made the
    /// change can sort in front of it. The change must be seen all the same, or that device could never follow it.
    @Test("a back-dated revocation of the device that changed the password cannot hide the change")
    func pendingChangeSurvivesBackdating() throws {
        var exercised = false
        for seed in UInt64(1)...12 {
            var f = RegistryFixture(seed: seed)
            let genesis = f.genesis(device: Self.a)
            let addB = f.add(Self.b, by: Self.a, parents: [genesis])
            let addX = f.add(Self.c, by: Self.a, parents: [addB])
            let revokeX = f.revoke(Self.c, by: Self.a, parents: [addX])
            _ = f.nextUnlockKey()
            let change = f.credential(generation: 1, previous: genesis, by: Self.a, parents: [revokeX])
            let backdated = [
                f.revoke(Self.a, by: Self.c, parents: [addX]),
                f.revoke(Self.a, by: Self.c, parents: [addX, addB]),
                f.revoke(Self.a, by: Self.c, parents: [addX, genesis]),
            ]
            let entries = [genesis, addB, addX, revokeX, change] + backdated
            exercised = exercised || backdated.contains { $0.id < revokeX.id }

            // A device still on the old password: whatever it makes of the unsealed entries, it sees the change.
            let behind = try f.evaluate(entries, genesis: genesis)
            #expect(behind.pendingCredentials.map(\.id) == [change.id], "seed \(seed)")
            // And following it settles everything: the revoked device is revoked, the others are not.
            let followed = try f.evaluate(entries, genesis: genesis, credential: change)
            #expect(Set(followed.devices.keys) == [Self.a, Self.b], "seed \(seed)")
            #expect(followed.standing(of: Self.c) == .revoked)
        }
        #expect(exercised, "no seed put a back-dated revocation in front of the genuine one")
    }

    @Test("two password changes at once are two branches; a device follows the one the person's password opens")
    func forks() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        let addB = f.add(Self.b, by: Self.a, parents: [genesis])
        _ = f.nextUnlockKey()
        let byA = f.credential(generation: 1, previous: genesis, by: Self.a, parents: [addB])
        var g = f
        _ = g.nextUnlockKey()
        // B's change is generation 1 too, made with another password and so another key.
        let otherKey = g.unlockKeys[2]
        let byBEnrolment = EnrolmentKey.derive(from: otherKey, accountID: f.accountID)
        var byB = RegistryEntry(
            accountID: f.accountID, parents: [addB.id], author: .device(Self.b),
            body: .credential(generation: 1, enrolmentKey: try byBEnrolment.publicKey(), previous: genesis.id))
        byB = f.signed(byB, previousGeneration: 0)
        let entries = [genesis, addB, byA, byB]

        // A device on neither: both are pending. A device that followed A's: B's is a fork, and the reverse.
        #expect(Set(try f.evaluate(entries, genesis: genesis).pendingCredentials.map(\.id)) == [byA.id, byB.id])
        let onA = try f.evaluate(entries, genesis: genesis, credential: byA)
        #expect(onA.pendingCredentials.isEmpty && onA.forkedCredentials.map(\.id) == [byB.id])
        let onB = try f.evaluate(entries, genesis: genesis, credential: byB)
        #expect(onB.pendingCredentials.isEmpty && onB.forkedCredentials.map(\.id) == [byA.id])
        #expect(onA.devices.keys.sorted { $0.uuidString < $1.uuidString } == [Self.a, Self.b])
    }

    @Test("only the genesis entry the device trusts counts, and it must name the trusted account key")
    func genesis() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        // A second genesis entry, validly signed by the account key (a revoked device that kept it could make one).
        let second = f.genesis(device: Self.c)
        let state = try f.evaluate([genesis, second], genesis: genesis)
        #expect(Set(state.devices.keys) == [Self.a])
        #expect(!state.connectedEntries.contains(second.id))

        #expect(throws: DeviceRegistryError.genesisUnavailable) { try f.evaluate([second], genesis: genesis) }
        let other = RegistryFixture(seed: 9)
        #expect(throws: DeviceRegistryError.genesisUnavailable) {
            try DeviceRegistry.evaluate(
                [genesis.id: genesis], accountID: f.accountID, accountSigningKey: other.accountSigningKey,
                genesis: genesis.id, credential: genesis.id)
        }
    }

    @Test("entries that are not signed by the account key, or belong to another account, are never admitted")
    func admission() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        var unsigned = f.add(Self.b, by: Self.a, parents: [genesis])
        unsigned.accountSignature = [UInt8](repeating: 7, count: 64)
        var other = RegistryFixture(seed: 9, accountID: UUID(uuidString: "AC000000-0000-4000-8000-0000000000FF")!)
        let foreign = other.genesis(device: Self.a)
        let admitted = DeviceRegistry.admit(
            [genesis.serialized(), unsigned.serialized(), foreign.serialized(), [1, 2, 3]], accountID: f.accountID,
            accountSigningKey: f.accountSigningKey)
        #expect(Array(admitted.keys) == [genesis.id])
    }

    @Test("more entries than are ever evaluated at once are refused, not evaluated")
    func evaluationLimit() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        var entries: [ObjectDigest: RegistryEntry] = [genesis.id: genesis]
        for index in 0..<DeviceRegistry.maximumEvaluated {
            // Distinct keys are enough for the count; the entries are never evaluated.
            entries[ObjectDigest(hashing: [UInt8(index & 0xFF), UInt8(index >> 8)])] = genesis
        }
        #expect(throws: DeviceRegistryError.tooManyEntries(DeviceRegistry.maximumEvaluated + 1)) {
            try DeviceRegistry.evaluate(
                entries, accountID: f.accountID, accountSigningKey: f.accountSigningKey, genesis: genesis.id,
                credential: genesis.id)
        }
    }

    @Test("a registry with more entries worth keeping than any household's is refused")
    func sizeLimit() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        // Revocations of devices that never existed: they change nothing, but a registered device signed them and
        // nothing rules out that they might count, so they are kept, and counted.
        var entries = [genesis]
        for index in 0..<DeviceRegistry.maximumEntries {
            let nobody = UUID(
                uuid: (0x4E, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, UInt8(index >> 8), UInt8(index & 0xFF)))
            entries.append(f.revoke(nobody, by: Self.a, parents: [entries[entries.count - 1]]))
        }
        #expect(throws: DeviceRegistryError.tooManyEntries(DeviceRegistry.maximumEntries + 1)) {
            try f.evaluate(entries, genesis: genesis)
        }
        #expect(try f.evaluate(Array(entries.dropLast()), genesis: genesis).retainedEntries.count == 4096)
    }

    /// Review of the device registry ("flood"): a revoked device that kept the account key signs any number of
    /// entries. Those that can never count are not retained — not stored, not published, not counted — whatever
    /// arrives later; and evaluating only what is retained gives the same registry.
    @Test("entries that can never count are not retained, and what is retained evaluates to the same registry")
    func retention() throws {
        var f = RegistryFixture()
        let genesis = f.genesis(device: Self.a)
        let addB = f.add(Self.b, by: Self.a, parents: [genesis])
        let addX = f.add(Self.c, by: Self.a, parents: [addB])
        let revokeX = f.revoke(Self.c, by: Self.a, parents: [addX])
        _ = f.nextUnlockKey()
        let change = f.credential(generation: 1, previous: genesis, by: Self.a, parents: [revokeX])

        // Signed by its own key after the checkpoint sealed its revocation, back-dated or not.
        let byRevoked = [
            f.revoke(Self.a, by: Self.c, parents: [addX]),
            f.add(Self.d, by: Self.c, parents: [change]),
        ]
        // Registered with the enrolment key the password change replaced.
        let superseded = f.enrol(RegistryFixture.deviceID(0xE0), credential: genesis, generation: 0, parents: [change])
        // In B's name without B's key; and by B, but not descending from B's registration.
        var forged = f.add(Self.d, by: Self.b, parents: [change])
        forged.authorSignature = [UInt8](repeating: 7, count: 64)
        let unregistered = f.add(RegistryFixture.deviceID(0xE1), by: Self.b, parents: [genesis])
        // Disconnected: no parents at all.
        var orphan = RegistryEntry(accountID: f.accountID, parents: [], author: .device(Self.c), body: .revoke(Self.b))
        orphan = f.signed(orphan)
        let worthless = byRevoked + [superseded, forged, unregistered, orphan]

        // What may still count: B adding a device, and an enrolment with the current password.
        let honest = f.add(Self.d, by: Self.b, parents: [change])
        let enrolled = f.enrol(RegistryFixture.deviceID(0xE2), credential: change, generation: 1, parents: [honest])
        let entries = [genesis, addB, addX, revokeX, change, honest, enrolled] + worthless
        let state = try f.evaluate(entries, genesis: genesis, credential: change)
        #expect(state.retainedEntries == Set([genesis, addB, addX, revokeX, change, honest, enrolled].map(\.id)))
        #expect(Set(state.devices.keys) == [Self.a, Self.b, Self.d, RegistryFixture.deviceID(0xE2)])
        #expect(!state.validEntries.contains(unregistered.id), "B's entries descend from B's registration")

        let kept = entries.filter { state.retainedEntries.contains($0.id) }
        #expect(
            try f.evaluate(kept, genesis: genesis, credential: change)
                == {
                    var expected = state
                    expected.connectedEntries = state.retainedEntries
                    return expected
                }())

        // A device still on the old password keeps what the change it has not confirmed needs, and the change.
        let behind = try f.evaluate(entries, genesis: genesis)
        #expect(behind.pendingCredentials.map(\.id) == [change.id])
        #expect(behind.retainedEntries.isSuperset(of: [change.id, honest.id, enrolled.id]))

        // An honest entry that names a worthless one as a parent (it saw it) keeps it: nothing it descends from is
        // ever dropped.
        let naming = f.add(RegistryFixture.deviceID(0xE3), by: Self.a, parents: [enrolled, byRevoked[1]])
        let named = try f.evaluate(entries + [naming], genesis: genesis, credential: change)
        #expect(named.retainedEntries.isSuperset(of: [naming.id, byRevoked[1].id]))
    }

    /// Review of the device registry ("puppets"): the revoked device registers a device of its own in an entry that
    /// can never count, then signs any number of entries in that puppet's name with a key it made. Each verifies
    /// against the dead registration, and the puppet was never revoked; none may count, so none is kept. The same
    /// holds when the puppet registers a second puppet (a valid signature, a dead registration), when the dead
    /// registration is one a checkpoint sealed as void, and when the puppet enrols with a key the revoked device
    /// published in a credential change of its own.
    @Test("a device registered by an entry that can never count writes nothing that is kept, however deep the chain")
    func puppets() throws {
        var f = RegistryFixture()
        let x = Self.c
        let genesis = f.genesis(device: Self.a)
        let addB = f.add(Self.b, by: Self.a, parents: [genesis])
        let addX = f.add(x, by: Self.a, parents: [addB])
        // X adds a device of its own at the same time as its revocation; A's password change, which saw both, seals
        // it as void.
        let sealedPuppet = f.add(RegistryFixture.deviceID(0xF3), by: x, parents: [addX])
        let revokeX = f.revoke(x, by: Self.a, parents: [addX])
        _ = f.nextUnlockKey()
        let change = f.credential(generation: 1, previous: genesis, by: Self.a, parents: [revokeX, sealedPuppet])
        let honest = [genesis, addB, addX, sealedPuppet, revokeX, change]

        func junk(_ index: Int, _ tag: UInt8) -> UUID {
            UUID(uuid: (0x4A, tag, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, UInt8(index >> 8), UInt8(index & 0xFF)))
        }
        func flood(by puppet: UUID, from registration: RegistryEntry, tag: UInt8, count: Int = 64) -> [RegistryEntry] {
            (0..<count).map { f.revoke(junk($0, tag), by: puppet, parents: [registration]) }
        }

        // As the verifier found it: a registration with a garbage author signature, after the checkpoint.
        let y = RegistryFixture.deviceID(0xF1)
        var forgedAdd = f.add(y, by: x, parents: [change])
        forgedAdd.authorSignature = [UInt8](repeating: 0, count: 64)
        // Signed properly by X, after its revocation was sealed.
        let w = RegistryFixture.deviceID(0xF4)
        let signedAdd = f.add(w, by: x, parents: [change])
        // A chain: Y, registered only by the forged entry, registers Z with a signature that verifies.
        let z = RegistryFixture.deviceID(0xF2)
        let addZ = f.add(z, by: y, parents: [forgedAdd])
        // An enrolment with a key X published in a password change of its own.
        _ = f.nextUnlockKey()
        let ownChange = f.credential(generation: 2, previous: change, by: x, parents: [change])
        let enrolled = RegistryFixture.deviceID(0xF5)
        let enrolment = f.enrol(enrolled, credential: ownChange, generation: 2, parents: [ownChange])

        let planted =
            [forgedAdd, signedAdd, addZ, ownChange, enrolment]
            + flood(by: y, from: forgedAdd, tag: 1) + flood(by: z, from: addZ, tag: 2)
            + flood(by: RegistryFixture.deviceID(0xF3), from: sealedPuppet, tag: 3)
            + flood(by: w, from: signedAdd, tag: 4) + flood(by: enrolled, from: enrolment, tag: 5)
        let entries = honest + planted
        let state = try f.evaluate(entries, genesis: genesis, credential: change)
        #expect(state.retainedEntries == Set(honest.map(\.id)))
        #expect(Set(state.devices.keys) == [Self.a, Self.b])
        #expect(state.pendingCredentials.isEmpty)
        for puppet in [y, z, w, enrolled, RegistryFixture.deviceID(0xF3)] {
            #expect(state.standing(of: puppet) == .unknown)
        }
        // A device still on the old password sees the change. Until it follows it, X's revocation is not final
        // there, so what X signs itself may yet count and is kept (as X's own entries are); but nothing that relies
        // on the forged registration ever counts, on any credential, and none of it is kept.
        let behind = try f.evaluate(entries, genesis: genesis)
        #expect(behind.pendingCredentials.map(\.id) == [change.id])
        let forgedChain =
            [forgedAdd, addZ]
            + planted.filter { entry in
                if case .device(let author) = entry.author { return author == y || author == z }
                return false
            }
        #expect(behind.retainedEntries.isDisjoint(with: forgedChain.map(\.id)))

        // At the registry's size limit, the flood is still not counted: the registry is not refused.
        let full = try f.evaluate(
            honest + [forgedAdd] + flood(by: y, from: forgedAdd, tag: 6, count: DeviceRegistry.maximumEntries),
            genesis: genesis, credential: change)
        #expect(full.retainedEntries == Set(honest.map(\.id)))

        // Honest histories are untouched: B registers a device after the change, and that device writes.
        let d = Self.d
        let addD = f.add(d, by: Self.b, parents: [change])
        let byD = f.add(RegistryFixture.deviceID(0xE6), by: d, parents: [addD])
        let fine = try f.evaluate(entries + [addD, byD], genesis: genesis, credential: change)
        #expect(fine.retainedEntries == Set((honest + [addD, byD]).map(\.id)))
        #expect(fine.standing(of: RegistryFixture.deviceID(0xE6)) == .active)
    }
}

@Suite("Published account header")
struct AccountHeaderObjectTests {
    struct Fixture {
        var registry = RegistryFixture()
        let personalVault = UUID(uuidString: "7A000000-0000-4000-8000-000000000001")!
        let author = RegistryFixture.deviceID(0xA0)
        var header: AccountHeaderObject
        let unlockKey: EncryptionKey

        init() throws {
            var generator = SeededGenerator(seed: 5)
            unlockKey = registry.unlockKeys[0]
            let genesis = registry.genesis(device: author)
            header = AccountHeaderObject(
                accountID: registry.accountID, generation: 0, author: author, kdf: .baseline,
                salt: (0..<32).map { UInt8($0) }, unlockKeyID: unlockKey.keyID, keysetVersion: 0,
                credentialID: genesis.id, genesisID: genesis.id,
                wrappedKeyset: try registry.keyset.wrap(with: unlockKey, recordVersion: 0, using: &generator))
            try header.bind(personalVaultID: personalVault, unlockKey: unlockKey, using: &generator)
            header.accountSignature = try registry.keyset.sign(header.signedPart, domain: .accountHeader)
            header.deviceSignature = try registry.key(for: author).sign(
                prepared: DeviceSignatures.signedBytes(
                    domain: .accountHeader, deviceID: author, message: header.signedPart))
        }
    }

    @Test("a header round-trips, opens its binding under the AUK, and carries both signatures")
    func roundTrip() throws {
        var f = try Fixture()
        let bytes = f.header.serialized()
        let parsed = try AccountHeaderObject.parse(bytes)
        #expect(parsed == f.header)
        #expect(parsed.serialized() == bytes)
        #expect(try parsed.openBinding(with: f.unlockKey) == f.personalVault)
        try parsed.verifySignatures(
            accountSigningKey: f.registry.accountSigningKey, deviceKey: try f.registry.key(for: f.author).publicKey())
    }

    @Test("every truncation, and anything after the end, is refused")
    func parserIsExact() throws {
        let bytes = try Fixture().header.serialized()
        for length in 0..<bytes.count {
            #expect(throws: AccountFormatError.self) { try AccountHeaderObject.parse(Array(bytes.prefix(length))) }
        }
        #expect(throws: AccountFormatError.trailingBytes) { try AccountHeaderObject.parse(bytes + [0]) }
        #expect(throws: AccountFormatError.tooLong(AccountHeaderObject.maximumLength + 1)) {
            try AccountHeaderObject.parse([UInt8](repeating: 0, count: AccountHeaderObject.maximumLength + 1))
        }
    }

    @Test("the binding opens only for the header it was sealed for")
    func bindingCoversEveryField() throws {
        let f = try Fixture()
        var edits: [(String, (inout AccountHeaderObject) -> Void)] = [
            ("generation", { $0.generation = 1 }),
            ("author", { $0.author = UUID() }),
            ("iterations", { $0.kdf.iterations += 1 }),
            ("salt", { $0.salt[0] ^= 1 }),
            ("keysetVersion", { $0.keysetVersion = 9 }),
            ("credential", { $0.credentialID = ObjectDigest(hashing: [1]) }),
            ("genesis", { $0.genesisID = ObjectDigest(hashing: [2]) }),
            ("keyset", { $0.wrappedKeyset[$0.wrappedKeyset.count - 1] ^= 1 }),
            ("account", { $0.accountID = UUID() }),
        ]
        edits.append(("binding", { $0.binding[$0.binding.count - 1] ^= 1 }))
        for (name, edit) in edits {
            var header = f.header
            edit(&header)
            #expect(throws: CryptoError.authenticationFailed, "\(name)") { try header.openBinding(with: f.unlockKey) }
        }
        // And not under another key, even one carrying the right ID.
        var generator = SeededGenerator(seed: 8)
        let wrong = try EncryptionKey(
            keyID: f.unlockKey.keyID, material: SecureBytes(randomCount: 32, using: &generator))
        #expect(throws: CryptoError.authenticationFailed) { try f.header.openBinding(with: wrong) }
    }

    @Test("the binding and the keyset wrap, under the same key, never open as each other")
    func bindingIsNotAKeyset() throws {
        let f = try Fixture()
        #expect(throws: (any Error).self) {
            try Keyset.unwrap(f.header.binding, accountID: f.registry.accountID, with: f.unlockKey, recordVersion: 0)
        }
        var swapped = f.header
        swapped.binding = f.header.wrappedKeyset
        #expect(throws: CryptoError.authenticationFailed) { try swapped.openBinding(with: f.unlockKey) }
    }
}
