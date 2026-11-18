import Foundation
import SecureMemory
import WatchwordCrypto

/// An account's signing material, for tests that build device-registry entries by hand: the keyset, a software key
/// per device, and an Account Unlock Key per credential generation (docs/02-architecture.md §7.8). Every entry it
/// makes is really signed, so what a test then alters or withholds fails for the reason the registry gives, not
/// because the fixture cut a corner.
public struct RegistryFixture: Sendable {
    public let accountID: UUID
    public let keyset: Keyset
    public private(set) var deviceKeys: [UUID: SoftwareDeviceKey] = [:]
    public private(set) var unlockKeys: [EncryptionKey] = []
    private var generator: SeededGenerator

    public init(seed: UInt64 = 42, accountID: UUID = UUID(uuidString: "AC000000-0000-4000-8000-0000000000AC")!) {
        self.accountID = accountID
        generator = SeededGenerator(seed: seed)
        keyset = Keyset.generate(accountID: accountID, using: &generator)
        unlockKeys = [EncryptionKey.generate(using: &generator)]
    }

    public static func deviceID(_ number: UInt8) -> UUID {
        UUID(uuid: (0xD0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, number))
    }

    public var accountSigningKey: [UInt8] {
        // Cannot fail for a generated keyset.
        try! keyset.publicKeyBundle().signingKey
    }

    /// The device's software key, made on first use.
    public mutating func key(for device: UUID) -> SoftwareDeviceKey {
        if let key = deviceKeys[device] { return key }
        let key = SoftwareDeviceKey.generate(using: &generator)
        deviceKeys[device] = key
        return key
    }

    /// A device whose ID commits to this account under a key made for it here (`DeviceIdentifier`, Z157).
    public mutating func committedDevice() -> UUID {
        let key = SoftwareDeviceKey.generate(using: &generator)
        // Cannot fail for a generated key.
        let id = DeviceIdentifier.derive(accountID: accountID, key: try! key.publicKey())
        deviceKeys[id] = key
        return id
    }

    /// `device` registered under `key` (another device's, say) by a registered device.
    public mutating func add(_ device: UUID, key: DevicePublicKey, by author: UUID, parents: [RegistryEntry])
        -> RegistryEntry
    {
        signed(
            RegistryEntry(
                accountID: accountID, parents: parents.map(\.id), author: .device(author),
                body: .add(RegistryDevice(id: device, key: key, label: []))))
    }

    /// A new Account Unlock Key: the next credential generation's.
    public mutating func nextUnlockKey() -> EncryptionKey {
        let key = EncryptionKey.generate(using: &generator)
        unlockKeys.append(key)
        return key
    }

    public func enrolmentKey(generation: Int) -> EnrolmentKey {
        EnrolmentKey.derive(from: unlockKeys[generation], accountID: accountID)
    }

    public mutating func certificate(_ device: UUID, label: [UInt8] = []) -> RegistryDevice {
        // Cannot fail for a generated key.
        RegistryDevice(id: device, key: try! key(for: device).publicKey(), label: label)
    }

    /// Signs `entry` with the account key and as its author: the named device, or the enrolment key of
    /// `enrolmentGeneration`. A credential entry is also signed by the enrolment key of `previousGeneration`.
    public mutating func signed(
        _ entry: RegistryEntry, enrolmentGeneration: Int? = nil, previousGeneration: Int? = nil
    ) -> RegistryEntry {
        var entry = entry
        entry.accountSignature = try! keyset.sign(entry.accountMessage, domain: .deviceRegistry)
        switch entry.author {
        case .device(let device):
            entry.authorSignature = try! key(for: device).sign(
                prepared: DeviceSignatures.signedBytes(
                    domain: .deviceRegistry, deviceID: device, message: entry.deviceMessage))
        case .enrolment:
            entry.authorSignature = try! enrolmentKey(generation: enrolmentGeneration ?? 0).sign(
                entry.enrolmentMessage, domain: .deviceRegistry)
        }
        if let previousGeneration {
            entry.previousCredentialSignature = try! enrolmentKey(generation: previousGeneration).sign(
                entry.previousCredentialMessage, domain: .deviceRegistry)
        }
        return entry
    }

    public mutating func genesis(device: UUID) -> RegistryEntry {
        let body = RegistryEntry.Body.genesis(
            accountSigningKey: accountSigningKey, device: certificate(device),
            enrolmentKey: try! enrolmentKey(generation: 0).publicKey())
        return signed(RegistryEntry(accountID: accountID, parents: [], author: .device(device), body: body))
    }

    /// `device` registered by a registered device.
    public mutating func add(_ device: UUID, by author: UUID, parents: [RegistryEntry]) -> RegistryEntry {
        signed(
            RegistryEntry(
                accountID: accountID, parents: parents.map(\.id), author: .device(author),
                body: .add(certificate(device))))
    }

    /// `device` registering itself with the enrolment key of `generation`, published by `credential`.
    public mutating func enrol(
        _ device: UUID, credential: RegistryEntry, generation: Int, parents: [RegistryEntry]
    ) -> RegistryEntry {
        signed(
            RegistryEntry(
                accountID: accountID, parents: parents.map(\.id), author: .enrolment(credential: credential.id),
                body: .add(certificate(device))),
            enrolmentGeneration: generation)
    }

    public mutating func revoke(_ device: UUID, by author: UUID, parents: [RegistryEntry]) -> RegistryEntry {
        signed(
            RegistryEntry(
                accountID: accountID, parents: parents.map(\.id), author: .device(author), body: .revoke(device)))
    }

    /// A credential change to `generation` (whose unlock key must exist), following `previous`.
    public mutating func credential(
        generation: Int, previous: RegistryEntry, by author: UUID, parents: [RegistryEntry]
    ) -> RegistryEntry {
        signed(
            RegistryEntry(
                accountID: accountID, parents: parents.map(\.id), author: .device(author),
                body: .credential(
                    generation: UInt64(generation), enrolmentKey: try! enrolmentKey(generation: generation).publicKey(),
                    previous: previous.id)),
            previousGeneration: generation - 1)
    }

    /// Evaluates `entries` as a device that trusts `genesis` and follows `credential` (the genesis entry by default).
    public func evaluate(_ entries: [RegistryEntry], genesis: RegistryEntry, credential: RegistryEntry? = nil) throws
        -> DeviceRegistryState
    {
        let admitted = DeviceRegistry.admit(
            entries.map { $0.serialized() }, accountID: accountID, accountSigningKey: accountSigningKey)
        return try DeviceRegistry.evaluate(
            admitted, accountID: accountID, accountSigningKey: accountSigningKey, genesis: genesis.id,
            credential: (credential ?? genesis).id)
    }
}
