import Foundation
import SecureMemory
import WatchwordCrypto

/// The Keychain items Watchword keeps per account (docs/02-architecture.md §6). All are device-only
/// (`WhenPasscodeSetThisDeviceOnly`, never synchronisable; ADR 0004) and in the access group shared with the AutoFill
/// extension.
public enum KeychainItem: Hashable, Sendable {
    /// The 16-byte Secret Key. No access-control prompt: unlocking already requires the password.
    case secretKey(accountID: UUID)
    /// The 32-byte Local Unlock Key that wraps the Account Unlock Key for quick unlock. Released by the OS only after
    /// biometric authentication against the *current* enrolment (`biometryCurrentSet`), so re-enrolment destroys it
    /// (PRD F5.3).
    case quickUnlockKey(accountID: UUID)
    /// `QuickUnlockState`: the wrapped AUK and the policy inputs of F5.4. Not secret on its own (it is useless without
    /// the Local Unlock Key) but kept in the Keychain so the failure counter cannot be reset by editing a file.
    case quickUnlockState(accountID: UUID)
    /// The account's 32-byte Ed25519 public key, copied from the keyset at every unlock, so sync can check signatures
    /// on downloads while the vault is locked (docs/02-architecture.md §7.4). Not secret; kept in the Keychain rather
    /// than the database so an attacker with the file (A8) cannot substitute a key of their own.
    case accountSigningKey(accountID: UUID)
    /// This installation's device signing key when it is held in software (`KeychainDeviceKeyStore`): the device ID
    /// it belongs to and a 32-byte Ed25519 seed. Device-only like every item here, so a store restored onto other
    /// hardware arrives without it and registers as a new device (docs/02-architecture.md §7.8).
    case deviceSigningKey(accountID: UUID)
    /// What this device trusts of the device registry: the genesis entry, the credential entry it follows and the
    /// newest entries it has applied. Not secret; in the Keychain rather than the database so that an attacker with
    /// the file (A8) can neither substitute a registry of their own nor roll this one back to before a revocation.
    case deviceRegistryAnchor(accountID: UUID)
    /// 32 random bytes this device made for itself, mixed with the keyset into the key that seals its local records
    /// (`DeviceLocalKeys.deviceLocalKey`; docs/02-architecture.md §13.8). Device-only and never synced: it is what
    /// another device of the account, which holds the same keyset, does not have, so it can neither read this
    /// device's scan ledger and prefix cache nor plant its own.
    case deviceLocalSecret(accountID: UUID)

    public var accountID: UUID {
        switch self {
        case .secretKey(let id), .quickUnlockKey(let id), .quickUnlockState(let id), .accountSigningKey(let id),
            .deviceSigningKey(let id), .deviceRegistryAnchor(let id), .deviceLocalSecret(let id):
            return id
        }
    }

    /// Every item an account may have, for erasing them all.
    public static func all(accountID: UUID) -> [KeychainItem] {
        [
            .secretKey(accountID: accountID), .quickUnlockKey(accountID: accountID),
            .quickUnlockState(accountID: accountID), .accountSigningKey(accountID: accountID),
            .deviceSigningKey(accountID: accountID), .deviceRegistryAnchor(accountID: accountID),
            .deviceLocalSecret(accountID: accountID),
        ]
    }
}

public enum KeychainError: Error, Equatable, Sendable {
    /// The person dismissed the biometric prompt. Not counted as a failed attempt.
    case userCancelled
    /// Biometric authentication failed. Counted towards the F5.4 limit.
    case authenticationFailed
    /// Biometrics are locked out, unavailable or not enrolled.
    case biometryUnavailable
    /// The device is locked, so the item's accessibility class does not allow access right now.
    case interactionNotAllowed
    /// Anything else, with the raw status for diagnostics. Never carries item contents.
    case unexpectedStatus(Int32)
}

/// Keychain port (docs/02-architecture.md §15). Production: `WatchwordPlatform.SystemKeychainStore`.
///
/// Reading `.quickUnlockKey` is the biometric check. There is deliberately no separate "did biometrics succeed"
/// boolean anywhere in the unlock path (§1 principle 4): the only thing that unlocks is key material the OS released.
public protocol KeychainStore: Sendable {
    /// Stores `value`, replacing any existing item.
    func store(_ value: SecureBytes, for item: KeychainItem) async throws
    /// The item's bytes, or `nil` if there is none (including an item the OS invalidated after re-enrolment).
    /// `prompt` is the reason shown by a biometric prompt for `.quickUnlockKey`; it is ignored for other items.
    func read(_ item: KeychainItem, prompt: String) async throws -> SecureBytes?
    /// Deletes the item; succeeds if it does not exist.
    func delete(_ item: KeychainItem) async throws
}

/// What the device's biometric enrolment looks like right now.
public enum BiometricEnrolment: Sendable, Hashable {
    /// Biometrics (or, on the Mac, a paired Watch) can authenticate. `domainState` changes whenever the enrolled set
    /// changes (`LAContext.evaluatedPolicyDomainState`).
    case enrolled(domainState: [UInt8])
    case unavailable
}

/// Biometric capability port. Production: `WatchwordPlatform.LocalAuthenticationGate`.
///
/// It reports enrolment only; it cannot authorise anything. Authentication happens inside the Keychain read of the
/// Local Unlock Key, which is what makes the "boolean bypass" impossible to express (docs/04-test-plan.md §6.2).
public protocol BiometricGate: Sendable {
    func enrolment() async -> BiometricEnrolment
}

/// Wall-clock port, for the policy decisions measured in days (F5.4) and minutes (F5.5). Tests advance a fake.
public protocol WallClock: Sendable {
    func now() async -> Date
}

public struct SystemWallClock: WallClock {
    public init() {}

    public func now() -> Date {
        Date()
    }
}

public enum DeviceKeyError: Error, Equatable, Sendable {
    /// This installation holds no signing key for the device (a store restored onto other hardware, or a Keychain
    /// that lost the item). The device registers again, as a new device.
    case keyMissing
}

/// This installation's device signing key (docs/02-architecture.md §6 `deviceSigningKey`, §7.8). Every sync object and
/// registry entry a device writes carries its signature beside the account key's, so holding the keyset alone is not
/// enough to write as a device, and a device can be revoked.
///
/// A port because the key should never leave the Secure Enclave where there is one: that adapter (P-256, Apple-only)
/// arrives with the platform work and signs `DeviceSignatureAlgorithm.p256ECDSA`. `KeychainDeviceKeyStore` is the
/// software implementation; `WatchwordTestSupport.FakeDeviceKeyStore` is the fake.
public protocol DeviceKeyStore: Sendable {
    /// Creates this installation's key for a new device of `accountID`, replacing any it held for the account, and
    /// returns the device's ID with the key's public half. The ID is derived from the account and that key
    /// (`DeviceIdentifier`), so it names no other account's device (review finding Z157): the one way production makes
    /// a device.
    func createDevice(accountID: UUID) async throws -> DeviceIdentity
    /// Creates this installation's key for `deviceID`, replacing any it held for the account, and returns its public
    /// half. For a device whose ID is already chosen: an account made before IDs committed to their account, and tests
    /// that must name a device. Such an ID counts for nothing in a shared vault unless it happens to commit.
    func create(accountID: UUID, deviceID: UUID) async throws -> DevicePublicKey
    /// The public half of the key held for `deviceID`, or `nil` if this installation has none for that device.
    func publicKey(accountID: UUID, deviceID: UUID) async throws -> DevicePublicKey?
    /// Signs bytes prepared by `DeviceSignatures.signedBytes`. Throws `DeviceKeyError.keyMissing` without a key.
    func sign(_ prepared: [UInt8], accountID: UUID, deviceID: UUID) async throws -> [UInt8]
    /// Destroys the key; succeeds if there is none.
    func delete(accountID: UUID) async throws
}

/// The software `DeviceKeyStore`: an Ed25519 seed in the Keychain item `deviceSigningKey`, device-only like the
/// Secret Key. It is not hardware-bound: someone who can read this device's Keychain has the key, though not the
/// account key that every object must also be signed with.
public actor KeychainDeviceKeyStore: DeviceKeyStore {
    private let keychain: any KeychainStore
    private var random: InjectedGenerator

    /// Production passes `SystemRandomNumberGenerator()`; only tests inject anything else (CLAUDE.md).
    public init(
        keychain: any KeychainStore,
        random: any RandomNumberGenerator & Sendable = SystemRandomNumberGenerator()
    ) {
        self.keychain = keychain
        self.random = InjectedGenerator(base: random)
    }

    public func createDevice(accountID: UUID) async throws -> DeviceIdentity {
        let key = SoftwareDeviceKey.generate(using: &random)
        defer { key.zeroise() }
        let publicKey = try key.publicKey()
        let deviceID = DeviceIdentifier.derive(accountID: accountID, key: publicKey)
        try await store(key, deviceID: deviceID, accountID: accountID)
        return DeviceIdentity(id: deviceID, key: publicKey)
    }

    public func create(accountID: UUID, deviceID: UUID) async throws -> DevicePublicKey {
        let key = SoftwareDeviceKey.generate(using: &random)
        defer { key.zeroise() }
        let publicKey = try key.publicKey()
        try await store(key, deviceID: deviceID, accountID: accountID)
        return publicKey
    }

    private func store(_ key: SoftwareDeviceKey, deviceID: UUID, accountID: UUID) async throws {
        let stored = SecureBytes.concatenating([SecureBytes(copying: Self.bytes(deviceID)), key.seedCopy()])
        try await keychain.store(stored, for: .deviceSigningKey(accountID: accountID))
    }

    public func publicKey(accountID: UUID, deviceID: UUID) async throws -> DevicePublicKey? {
        guard let key = try await key(accountID: accountID, deviceID: deviceID) else { return nil }
        defer { key.zeroise() }
        return try key.publicKey()
    }

    public func sign(_ prepared: [UInt8], accountID: UUID, deviceID: UUID) async throws -> [UInt8] {
        guard let key = try await key(accountID: accountID, deviceID: deviceID) else {
            throw DeviceKeyError.keyMissing
        }
        defer { key.zeroise() }
        return try key.sign(prepared: prepared)
    }

    public func delete(accountID: UUID) async throws {
        try await keychain.delete(.deviceSigningKey(accountID: accountID))
    }

    /// The stored key, if it is for `deviceID`. A key stored for another device ID is not this device's.
    private func key(accountID: UUID, deviceID: UUID) async throws -> SoftwareDeviceKey? {
        guard let stored = try await keychain.read(.deviceSigningKey(accountID: accountID), prompt: "") else {
            return nil
        }
        defer { stored.zeroise() }
        guard stored.count == 16 + SoftwareDeviceKey.seedLength,
            stored.extracting(0..<16).unprotectedCopy() == Self.bytes(deviceID)
        else { return nil }
        return try SoftwareDeviceKey(seed: stored.extracting(16..<stored.count))
    }

    private static func bytes(_ id: UUID) -> [UInt8] {
        let u = id.uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }
}
