import Foundation
import WatchwordCrypto

extension PublicKeyBundle {
    /// The same account with the same two keys: exactly what a fingerprint covers.
    ///
    /// The self-signature is deliberately not compared. Ed25519 signing may be randomised (CryptoKit's is), so a
    /// bundle built twice from one keyset can be two different, equally valid values; comparing with `==` would then
    /// report a key substitution where there is none.
    public func hasSameKeys(as other: PublicKeyBundle) -> Bool {
        accountID == other.accountID && agreementKey == other.agreementKey && signingKey == other.signingKey
    }

    /// SHA-256 of the account ID and the two keys.
    var keyDigest: [UInt8] {
        SharingBytes.sha256(accountID.sharingBytes, agreementKey, signingKey)
    }
}

/// The stored form of a `VaultKeyGrant` (docs/02-architecture.md §8.5, PRD SEC3).
///
/// ```
/// magic "WWKG"  formatVersion u8 = 1  vaultID 16  keyID 16  sender 16  recipient 16
/// recipient's X25519 key 32  HPKE encapsulated key 32  ciphertext 48 (a 32-byte key and its tag)  signature 64
/// ```
///
/// Every field has one length, so the whole grant has one length and the parser's bound is equality. Nothing parsed
/// is trusted: `MembershipLedger.openGrant` decides who may have sent it, and `VaultKeyGrant.open` checks the rest.
public enum KeyGrantCodec {
    static let magic: [UInt8] = Array("WWKG".utf8)
    static let formatVersion: UInt8 = 1
    static let ciphertextLength = 32 + 16
    public static let encodedLength = 4 + 1 + 16 * 4 + 32 + 32 + ciphertextLength + 64

    public static func encode(_ grant: VaultKeyGrant) throws -> [UInt8] {
        guard grant.recipientAgreementKey.count == 32, grant.encapsulatedKey.count == 32,
            grant.ciphertext.count == ciphertextLength, grant.signature.count == 64
        else { throw SharingFormatError.badFieldLength }
        return magic + [formatVersion] + grant.vaultID.sharingBytes + grant.keyID.sharingBytes
            + grant.senderAccountID.sharingBytes + grant.recipientAccountID.sharingBytes
            + grant.recipientAgreementKey + grant.encapsulatedKey + grant.ciphertext + grant.signature
    }

    public static func parse(_ bytes: [UInt8]) throws -> VaultKeyGrant {
        guard bytes.count <= encodedLength else { throw SharingFormatError.tooLarge(bytes.count) }
        var reader = SharingReader(bytes)
        try reader.header(magic: magic, version: formatVersion)
        let grant = VaultKeyGrant(
            vaultID: try reader.uuid(), keyID: try reader.uuid(), senderAccountID: try reader.uuid(),
            recipientAccountID: try reader.uuid(), recipientAgreementKey: try reader.read(32),
            encapsulatedKey: try reader.read(32), ciphertext: try reader.read(ciphertextLength),
            signature: try reader.read(64))
        try reader.finish()
        return grant
    }
}

/// A grant with its stored bytes and the name it is published under.
public struct VaultKeyGrantRecord: Sendable, Hashable {
    public let grant: VaultKeyGrant
    public let encoded: [UInt8]
    public let location: SharingObjectLocation

    init(_ grant: VaultKeyGrant) throws {
        self.grant = grant
        encoded = try KeyGrantCodec.encode(grant)
        location = .grant(
            vaultID: grant.vaultID, keyID: grant.keyID, recipient: grant.recipientAccountID, contents: encoded)
    }
}

extension MembershipLedger {
    /// The epoch of the record that introduced `keyID`, if the accepted chain ever did.
    public func keyEpoch(of keyID: UUID) -> UInt64? {
        chain.first { $0.state.vaultKeyID == keyID }?.state.keyEpoch
    }

    /// The one account entitled to grant `keyID` to `recipient`, with the key bundle the chain lists for it
    /// (docs/02-architecture.md §8.5).
    ///
    /// It is the signer of the record through which the recipient came to be entitled to the key: the record that
    /// introduced the key, if the recipient was a member then (the genesis, a rotation, a removal), or else the record
    /// that added the recipient while the key was current. That signer was an administrator in the verified chain at
    /// that epoch, by the chain's own rules. Nobody else's grant is accepted, in particular not one from:
    /// - a former member or former administrator, whatever old signatures they can produce;
    /// - someone who is an administrator of another vault, or became one of this vault later;
    /// - an administrator who was demoted after introducing the key, for a member added since (a demotion does not
    ///   rotate the key, so "an administrator when the key was introduced" alone would still let them in).
    ///
    /// A removal ends a key's life, so within it a member is added at most once and the answer is unique.
    public func grantSender(forKey keyID: UUID, to recipient: UUID) throws -> Member {
        guard let introduced = keyEpoch(of: keyID) else { throw SharingError.unknownKey(keyID) }
        var epoch = Int(introduced)
        while epoch < chain.count, chain[epoch].state.vaultKeyID == keyID {
            if chain[epoch].state.member(recipient) != nil {
                let signer = chain[epoch].record.signer
                // The signer of an accepted record is a member of the state before it; the genesis is the owner's.
                let before = epoch == 0 ? chain[0].state : chain[epoch - 1].state
                guard let member = before.member(signer) else { throw SharingError.notEntitledToKey(recipient) }
                return member
            }
            epoch += 1
        }
        throw SharingError.notEntitledToKey(recipient)
    }

    /// Wraps `vaultKey` to a member, as the account entitled to (`grantSender`). The recipient's key is the one the
    /// verified chain lists, which an administrator put there only after confirming its fingerprint; `memberKeys`
    /// (`checkMemberKeys`, on the current head) is this device's own comparison of that key with its verified
    /// contacts, and a recipient whose listed keys are not the pinned ones is refused (`keySubstituted`).
    public func makeGrant(
        of vaultKey: VaultKey, to recipient: UUID, memberKeys: MemberKeyCheck, from keyset: Keyset
    ) throws -> VaultKeyGrantRecord {
        guard vaultKey.vaultID == vaultID else { throw SharingError.grantMisfiled }
        guard memberKeys.vaultID == vaultID, memberKeys.head == state.hash else {
            throw SharingError.memberKeysNotChecked
        }
        guard !memberKeys.substituted.contains(recipient) else {
            throw SharingError.keySubstituted(accountID: recipient)
        }
        let sender = try grantSender(forKey: vaultKey.key.keyID, to: recipient)
        guard sender.accountID == keyset.accountID else { throw SharingError.notPermitted }
        guard
            let member = chain.last(where: {
                $0.state.vaultKeyID == vaultKey.key.keyID && $0.state.member(recipient) != nil
            })?.state.member(recipient)
        else { throw SharingError.notEntitledToKey(recipient) }
        return try VaultKeyGrantRecord(VaultKeyGrant.seal(vaultKey, to: member.bundle, from: keyset))
    }

    /// Opens a grant found at `location`, as its recipient.
    ///
    /// The vault, the key ID and the recipient come from the location (and the vault must be this ledger's); the
    /// sender must be the one account the verified chain entitles (`grantSender`), under the key the chain lists for
    /// it. Only then does `VaultKeyGrant.open` check the signature, the addressing and the HPKE ciphertext. A grant
    /// replayed from an earlier key, filed under another vault or key, addressed to another member, or signed by
    /// anyone else fails closed.
    public func openGrant(_ bytes: [UInt8], at location: SharingObjectLocation, as keyset: Keyset) throws
        -> VaultKey
    {
        guard location.vaultID == vaultID, case .grant(let keyID, let recipient, let digest) = location.kind,
            recipient == keyset.accountID, digest == SharingBytes.sha256(bytes)
        else { throw SharingError.grantMisfiled }
        let grant = try KeyGrantCodec.parse(bytes)
        let sender = try grantSender(forKey: keyID, to: recipient)
        return try grant.open(as: keyset, from: sender.bundle, vaultID: vaultID, keyID: keyID)
    }

    /// Opens the first acceptable grant of `keyID` among objects listed under
    /// `SharingObjectLocation.grantPrefix(vaultID:keyID:recipient:)`. Objects that are not acceptable are skipped:
    /// anyone with write access to the store can put junk under that prefix, and it must not hide the real grant.
    /// So every object is looked at, names first, and there is no bound on how many: one filed for this key and this
    /// member under its own digest costs a signature check, and anything else costs nothing (S10, S24).
    public func openGrant(of keyID: UUID, from objects: [(name: String, contents: [UInt8])], as keyset: Keyset)
        throws -> VaultKey
    {
        // Establishes that someone is entitled at all, so the caller learns why nothing can match.
        _ = try grantSender(forKey: keyID, to: keyset.accountID)
        for object in objects {
            guard let location = SharingObjectLocation(name: object.name), location.vaultID == vaultID,
                case .grant(let found, let recipient, _) = location.kind, found == keyID,
                recipient == keyset.accountID, object.contents.count == KeyGrantCodec.encodedLength
            else { continue }
            if let key = try? openGrant(object.contents, at: location, as: keyset) { return key }
        }
        throw SharingError.grantNotFound
    }
}
