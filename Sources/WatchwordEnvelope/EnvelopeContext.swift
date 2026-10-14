import Foundation

/// Where a record lives and what it claims to be: the fields every envelope's authenticated data binds
/// (docs/02-architecture.md §5, PRD SEC2).
///
/// A reader never trusts the context embedded in an envelope. It builds the context it *expects* from the storage
/// location (which vault's table, which record ID, which version the sync layer says this is) and `Envelope.parse`
/// compares the two encodings byte for byte before any decryption. A record copied into another vault, relabelled as
/// another record, presented as a newer version than it is, or claiming a different schema fails closed.
///
/// `recordVersion` is the record's Lamport version. Binding it means a sync store cannot present an old ciphertext as
/// a newer version; presenting it as its true, older version is then caught by the caller's monotonic version check
/// (replay of an *older* version is a sync-layer decision, milestone 3).
public struct EnvelopeContext: Sendable, Hashable {
    public var recordID: UUID
    /// The vault the record belongs to. Account-level records (the wrapped keyset) use the account ID.
    public var vaultID: UUID
    public var schemaVersion: UInt64
    public var kind: EnvelopeKind
    /// The key the record is encrypted under.
    public var keyID: UUID
    public var recordVersion: UInt64

    public init(
        recordID: UUID,
        vaultID: UUID,
        schemaVersion: UInt64,
        kind: EnvelopeKind,
        keyID: UUID,
        recordVersion: UInt64 = 0
    ) {
        self.recordID = recordID
        self.vaultID = vaultID
        self.schemaVersion = schemaVersion
        self.kind = kind
        self.keyID = keyID
        self.recordVersion = recordVersion
    }

    /// Canonical CBOR map `{1: recordID, 2: vaultID, 3: schemaVersion, 4: kind, 5: keyID, 6: recordVersion}`.
    /// The integer keys are part of the format; never renumber them.
    public func canonicalAAD() -> [UInt8] {
        CBORValue.map([
            1: .uuid(recordID),
            2: .uuid(vaultID),
            3: .unsigned(schemaVersion),
            4: .unsigned(UInt64(kind.rawValue)),
            5: .uuid(keyID),
            6: .unsigned(recordVersion),
        ]).encoded()
    }
}
