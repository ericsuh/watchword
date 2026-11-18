import Foundation
import Testing
import WatchwordCrypto
import WatchwordTestSupport

/// Review finding Z157: a device's ID commits to its account under its key, so that in a shared vault no account can
/// list, sign as or revoke another account's device (docs/02-architecture.md §7.8, §8.10).
@Suite("Device IDs that commit to their account")
struct DeviceIdentifierTests {
    /// The public key of RFC 8032 §7.1, test 1.
    static let rfcKey = try! DevicePublicKey(
        algorithm: .ed25519,
        rawRepresentation: [UInt8](hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))

    /// Known answers from Python's `hashlib`: `sha256(b"WW-device-id-v1\x00" + account + bytes([1, 32]) + key)`,
    /// its first 16 bytes with byte 6 set to version 8 and byte 8 to the RFC 9562 variant.
    @Test(
        "an ID is the digest of the account and the device key, as a version-8 UUID",
        arguments: zip(
            ["00010203-0405-0607-0809-0A0B0C0D0E0F", "01020304-0506-0708-090A-0B0C0D0E0F10"],
            ["EC39E937-C5EF-876C-A356-40EEEAF3FA3D", "C11CCDB4-CC6D-80E4-B7D4-67F9D3772D62"]))
    func knownAnswers(account: String, expected: String) throws {
        let accountID = try #require(UUID(uuidString: account))
        let id = DeviceIdentifier.derive(accountID: accountID, key: Self.rfcKey)
        #expect(id.uuidString == expected)
        #expect(DeviceIdentifier.commits(id, to: accountID, key: Self.rfcKey))
        #expect(!DeviceIdentifier.commits(id, to: UUID(), key: Self.rfcKey), "the same key commits to one account")
    }

    @Test("a registry counts in a shared vault only the devices whose IDs commit to its account")
    func committedDevicesOnly() throws {
        var f = RegistryFixture(seed: 157)
        let legacy = RegistryFixture.deviceID(0xA0)
        let kept = f.committedDevice()
        let revoked = f.committedDevice()
        let genesis = f.genesis(device: legacy)
        let addKept = f.add(kept, by: legacy, parents: [genesis])
        let addRevoked = f.add(revoked, by: legacy, parents: [addKept])
        let revocation = f.revoke(revoked, by: kept, parents: [addRevoked])
        let state = try f.evaluate([genesis, addKept, addRevoked, revocation], genesis: genesis)
        #expect(Set(state.devices.keys) == [legacy, kept] && Set(state.revoked.keys) == [revoked])
        let counted = state.committedDevicesOnly
        #expect(Set(counted.devices.keys) == [kept])
        #expect(Set(counted.revoked.keys) == [revoked])

        // Another account lists the device's ID, with a key of its own or with the device's own public key, and
        // revokes it: no listing of it counts, so nothing it signs as that device verifies, and its revocation is
        // nobody's.
        var other = RegistryFixture(seed: 158, accountID: UUID(uuidString: "AC000000-0000-4000-8000-0000000000BD")!)
        let author = other.committedDevice()
        let otherGenesis = other.genesis(device: author)
        let squat = other.add(kept, by: author, parents: [otherGenesis])
        let copied = other.add(
            revoked, key: try f.key(for: revoked).publicKey(), by: author, parents: [squat])
        let revokeSquat = other.revoke(kept, by: author, parents: [copied])
        let otherState = try other.evaluate([otherGenesis, squat, copied, revokeSquat], genesis: otherGenesis)
        #expect(otherState.revoked[kept] != nil && otherState.devices[revoked] != nil, "the plant did not take")
        #expect(Set(otherState.committedDevicesOnly.devices.keys) == [author])
        #expect(otherState.committedDevicesOnly.revoked.isEmpty)
    }
}
