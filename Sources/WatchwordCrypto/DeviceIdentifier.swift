import Foundation

/// A device ID that commits to its account (docs/02-architecture.md §7.8, §8.10; review finding Z157).
///
/// A device's ID is the first 128 bits of `SHA-256("WW-device-id-v1" ‖ 0x00 ‖ accountID ‖ algorithm u8 ‖ keyLength u8 ‖
/// key)`, its device key's public half, with the bits of an RFC 9562 version-8 UUID set (122 bits of the digest
/// remain). So an ID names one account: for another account to list it, that account would have to find a key whose
/// digest under its own account ID is the same 122 bits, a second preimage.
///
/// This is what makes "whose stream is this?" a question of identity in a shared vault. A stream is named by a device
/// ID, a value by a stamp that names a device, a revocation by a device ID; and any account can put any device ID it
/// likes in its own registry, so before this the account of a stream was inferred (from its lowest segment, from who
/// could write when its key was current), and each inference was attacked in turn (review findings Z46, Z137, Z146,
/// Z150, Z152, and round 5's M1 and M2). A shared vault now counts a registry's device only if its ID commits to that
/// registry's account (`DeviceRegistryState.committedDevicesOnly`), so no account can list, sign as, or revoke a device
/// of another's.
///
/// The ID is derived once, when the device's key is made, and never again: a registered device's key never changes
/// (`DeviceRegistry`), so the commitment holds for as long as the device does.
public enum DeviceIdentifier {
    static let domain = Array("WW-device-id-v1".utf8) + [0]

    /// The ID of the device of `accountID` whose public key is `key`.
    public static func derive(accountID: UUID, key: DevicePublicKey) -> UUID {
        let header = [key.algorithm.rawValue, UInt8(truncatingIfNeeded: key.rawRepresentation.count)]
        let input = domain + accountID.byteArray + header + key.rawRepresentation
        var bytes = Array(AccountBytes.sha256(input).prefix(16))
        bytes[6] = (bytes[6] & 0x0F) | 0x80
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return UUID(byteArray: bytes)
    }

    /// Whether `id` is the ID that `key` gives a device of `accountID`.
    public static func commits(_ id: UUID, to accountID: UUID, key: DevicePublicKey) -> Bool {
        derive(accountID: accountID, key: key) == id
    }
}

extension RegistryDevice {
    /// Whether this device's ID commits to `accountID` under its key (`DeviceIdentifier`).
    public func commits(to accountID: UUID) -> Bool {
        DeviceIdentifier.commits(id, to: accountID, key: key)
    }
}

extension DeviceRegistryState {
    /// The registry with only the devices, registered and revoked, whose IDs commit to its account
    /// (`DeviceIdentifier`). What a shared vault asks of every registry, this account's own included, so that every
    /// device holding the same registries counts the same devices: another account's device ID listed here (S33)
    /// is no device of this account's, can sign nothing that verifies as it, and is revoked by nobody here. A private
    /// vault, which only this account's devices write, has no other account to tell apart and asks the registry as
    /// it is.
    public var committedDevicesOnly: DeviceRegistryState {
        var state = self
        state.devices = devices.filter { DeviceIdentifier.commits($0.key, to: accountID, key: $0.value.key) }
        state.revoked = revoked.filter { DeviceIdentifier.commits($0.key, to: accountID, key: $0.value.key) }
        return state
    }

    /// The device IDs, registered or revoked, that more than one of `states` lists (round 6's L3). Committed
    /// registries of two accounts list one ID only if the two found keys whose IDs under their own accounts collide:
    /// 122 bits, so about 2^61 work for two accounts acting together (a birthday search), never one account against
    /// another's existing device (a second preimage). Such an ID is either account's by arrival order alone, so a
    /// shared vault counts it as neither's (`removingDevices`): it decides the same on every device whatever arrived
    /// first, and costs only the two accounts that made it.
    public static func listedMoreThanOnce(_ states: [DeviceRegistryState]) -> Set<UUID> {
        var listings: [UUID: Int] = [:]
        for state in states {
            for id in Set(state.devices.keys).union(state.revoked.keys) { listings[id, default: 0] += 1 }
        }
        return Set(listings.filter { $0.value > 1 }.keys)
    }

    /// The registry without `ids`, registered or revoked.
    public func removingDevices(_ ids: Set<UUID>) -> DeviceRegistryState {
        guard !ids.isEmpty else { return self }
        var state = self
        state.devices = devices.filter { !ids.contains($0.key) }
        state.revoked = revoked.filter { !ids.contains($0.key) }
        return state
    }
}
