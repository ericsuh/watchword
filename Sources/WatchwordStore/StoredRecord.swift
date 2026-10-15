import Foundation
import WatchwordEnvelope

/// One ciphertext row of the local store (docs/02-architecture.md §6, table `records`).
///
/// Every column besides `envelope` is the record's *storage location*: a reader builds the `EnvelopeContext` it expects
/// from these columns, never from the envelope, and `Envelope.parse` refuses a record whose embedded context differs.
/// So a row edited to point at another vault, record or version fails closed before decryption (SEC2).
public struct StoredRecord: Sendable, Hashable {
    public var recordID: UUID
    public var kind: EnvelopeKind
    public var vaultID: UUID
    /// The key the envelope is sealed under.
    public var keyID: UUID
    /// Lamport version; bound into the envelope's authenticated data as `recordVersion`.
    public var version: UInt64
    /// The device that wrote this version.
    public var deviceID: UUID
    public var envelope: [UInt8]

    public init(
        recordID: UUID,
        kind: EnvelopeKind,
        vaultID: UUID,
        keyID: UUID,
        version: UInt64,
        deviceID: UUID,
        envelope: [UInt8]
    ) {
        self.recordID = recordID
        self.kind = kind
        self.vaultID = vaultID
        self.keyID = keyID
        self.version = version
        self.deviceID = deviceID
        self.envelope = envelope
    }

    public var key: RecordKey {
        RecordKey(recordID: recordID, kind: kind)
    }
}

/// A record's identity in the store. The kind is part of it, so an item and a key wrap can never overwrite each other.
public struct RecordKey: Sendable, Hashable {
    public var recordID: UUID
    public var kind: EnvelopeKind

    public init(recordID: UUID, kind: EnvelopeKind) {
        self.recordID = recordID
        self.kind = kind
    }
}

/// The local account header (docs/02-architecture.md §4, §6): everything needed to derive the Account Unlock Key and
/// unwrap the keyset on this device.
///
/// None of it is secret. The KDF parameters and salt are inputs to 2SKD, and changing them only changes the key that is
/// derived, which then fails to open `wrappedKeyset`; `KDFParameters.validate()` runs before derivation, so a tampered
/// header can neither weaken nor stall it (SEC5, SEC9).
public struct AccountRecord: Sendable, Hashable {
    public var accountID: UUID
    /// This installation's identity, recorded on every row it writes.
    public var deviceID: UUID
    public var personalVaultID: UUID
    public var personalVaultKeyID: UUID
    public var kdf: KDFParameters
    public var salt: [UInt8]
    /// ID of the Account Unlock Key the keyset is wrapped under; changes with every password change.
    public var unlockKeyID: UUID
    /// The keyset sealed under AUK as an `.accountHeader` envelope.
    public var wrappedKeyset: [UInt8]
    /// `recordVersion` of `wrappedKeyset`; increases with each rewrap.
    public var keysetVersion: UInt64
    /// Increases whenever the password or Secret Key changes, so quick unlock enrolled before the change is refused
    /// (PRD F5.4).
    public var credentialGeneration: UInt64
    public var createdAt: Date
    /// When the person confirmed they saved the Emergency Kit (PRD F5.1); `nil` until then.
    public var emergencyKitConfirmedAt: Date?

    public init(
        accountID: UUID,
        deviceID: UUID,
        personalVaultID: UUID,
        personalVaultKeyID: UUID,
        kdf: KDFParameters,
        salt: [UInt8],
        unlockKeyID: UUID,
        wrappedKeyset: [UInt8],
        keysetVersion: UInt64,
        credentialGeneration: UInt64,
        createdAt: Date,
        emergencyKitConfirmedAt: Date? = nil
    ) {
        self.accountID = accountID
        self.deviceID = deviceID
        self.personalVaultID = personalVaultID
        self.personalVaultKeyID = personalVaultKeyID
        self.kdf = kdf
        self.salt = salt
        self.unlockKeyID = unlockKeyID
        self.wrappedKeyset = wrappedKeyset
        self.keysetVersion = keysetVersion
        self.credentialGeneration = credentialGeneration
        self.createdAt = createdAt
        self.emergencyKitConfirmedAt = emergencyKitConfirmedAt
    }
}
