import Foundation
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordSharing
import WatchwordStore
import WatchwordSync

// "Shared" as a fact a device cannot lose (docs/02-architecture.md §8.10; review finding Z41).
//
// Whether a vault is governed by a membership chain used to be answered by the ledger a device had loaded, which is
// per-device state: another device of the account, or this one after its sharing state was lost or edited (A8), ran
// the vault as one of the account's own. Three things answer it now, none of which goes with the ledger:
//
// - a **marker** beside the vault's directory entry, signed by the account key and a device, published in the
//   account's vault directory and kept as a row of the record store. It names the chain's owner;
// - a vault key that **arrived by grant** (`VaultKey.arrivedByGrant`), which the key's own wrap authenticates, so it
//   reaches every device of the account with the key and cannot be taken off it;
// - the sharing state itself naming the vault while its ledger does not load (`SharingRuntime.unloadable`).
//
// A vault any of them names, with no verified ledger loaded, is **unavailable** on this device: readable, and
// otherwise held closed. `sharedCurrentKey` gives it no current key, so nothing is sealed, signed or published and its
// engine only downloads (no snapshots, no collection); `checkSharedWrite` and `checkSharedDeletion` refuse every write
// and the vault's deletion (`SharedVaultError.ledgerUnavailable`). The way out is this device accepting the vault's
// invitation itself (`acceptInvitation`), which the marker's owner makes possible on a second device.
extension VaultSession {
    static let sharedMarker = Array("WWVS1-shared".utf8)
    /// The first byte of a marker's row, beside `0x01` (a vault that exists) and `0x02` (a deleted one).
    static let sharedMarkerTag: UInt8 = 0x03

    /// What a marker says: `"WWVS1-shared" ‖ vault ID ‖ the chain owner's account ID`. The vault is in the object's
    /// name too, which the signatures cover; it is repeated here so that a local row can be read on its own.
    static func sharedMarkerBody(vaultID: UUID, owner: UUID) -> [UInt8] {
        sharedMarker + bytes(vaultID) + bytes(owner)
    }

    static func parseSharedMarkerBody(_ body: [UInt8]) -> (vaultID: UUID, owner: UUID)? {
        guard body.count == sharedMarker.count + 32, Array(body.prefix(sharedMarker.count)) == sharedMarker else {
            return nil
        }
        let rest = Array(body.dropFirst(sharedMarker.count))
        return (uuid(Array(rest[..<16])), uuid(Array(rest[16...])))
    }

    /// The record ID of a marker's row: derived from the vault and the owner it names, since the vault's own ID is
    /// its directory row's and a store keeps one row per record ID and kind. One row for each owner the account's
    /// markers name for a vault: there should be one, and a second is kept so that the disagreement is not forgotten
    /// with the session (`markerConflicts`, Z48).
    static func sharedMarkerRecordID(_ vaultID: UUID, owner: UUID) -> UUID {
        let seed = Array("WW-shared-marker-v2".utf8) + bytes(vaultID) + bytes(owner)
        var id = Array(ObjectDigest(hashing: seed).bytes[..<16])
        id[6] = (id[6] & 0x0F) | 0x80
        id[8] = (id[8] & 0x3F) | 0x80
        return uuid(id)
    }

    /// The row for a marker object. `object`'s body says which owner it names; a body that is no marker's gives a
    /// row that marks nothing (`verifiedSharedMarker`).
    static func sharedMarkerRow(vaultID: UUID, accountID: UUID, author: UUID, object: SignedObject) -> StoredRecord {
        let owner = parseSharedMarkerBody(object.envelope)?.owner ?? zeroUUID
        return StoredRecord(
            recordID: sharedMarkerRecordID(vaultID, owner: owner), kind: .vaultDirectory, vaultID: accountID,
            keyID: zeroUUID, version: 1, deviceID: author, envelope: [sharedMarkerTag] + object.serialized())
    }

    /// The vault and owner a marker row names, if the account key signed it for the device the row names. Only the
    /// account key's half of the dual signature is asked here: the device's half is checked when the object is
    /// fetched, and a marker this device has taken must not stop counting when the device that wrote it is revoked,
    /// or revoking a device would open the vaults it had marked. A row planted in the file (A8) carries no such
    /// signature and marks nothing; one removed is put back by the next sync, and a key that arrived by grant says
    /// the same without it.
    static func verifiedSharedMarker(_ row: StoredRecord, accountID: UUID, accountSigningKey: [UInt8]) -> (
        vaultID: UUID, owner: UUID
    )? {
        guard row.kind == .vaultDirectory, row.vaultID == accountID, row.envelope.first == sharedMarkerTag,
            let object = try? SignedObject.parse(Array(row.envelope.dropFirst())),
            let marker = parseSharedMarkerBody(object.envelope),
            row.recordID == sharedMarkerRecordID(marker.vaultID, owner: marker.owner),
            let parts = DualSignature.decode(object.signature)
        else { return nil }
        let name = AccountObjectLocation.vaultShared(
            accountID: accountID, vaultID: marker.vaultID, author: row.deviceID
        ).name
        guard
            (try? Signatures.verify(
                parts.account, for: directoryMessage(name: name, body: object.envelope), domain: .vaultDirectory,
                signingKey: accountSigningKey)) != nil
        else { return nil }
        return marker
    }

    /// Reads the markers the record store holds, once per session and again after anything that adds one. Until it
    /// has, every vault but the Personal one is treated as possibly shared (`sharedCurrentKey`), so a read that
    /// fails closes vaults rather than opening them.
    func loadSharedMarkersIfNeeded(force: Bool = false) async {
        guard force || !sharing.markersLoaded else { return }
        guard let account = try? await loadAccount(), let signingKey = await trustedAccountSigningKey(account),
            let rows = try? await store.records(in: account.accountID, kind: .vaultDirectory)
        else { return }
        // In row order, so that which owner is listed first does not depend on the store.
        for row in rows.sorted(by: { $0.recordID.uuidString < $1.recordID.uuidString }) {
            guard
                let marker = Self.verifiedSharedMarker(
                    row, accountID: account.accountID, accountSigningKey: signingKey),
                marker.vaultID != account.personalVaultID
            else { continue }
            // Markers are only ever added: one this session has seen is not forgotten because a later read lacks
            // it. A second owner for a vault is a disagreement between the account's devices, and is kept as one.
            if let held = sharing.markers[marker.vaultID], held != marker.owner {
                sharing.markerConflicts.insert(marker.vaultID)
            } else {
                sharing.markers[marker.vaultID] = marker.owner
            }
        }
        sharing.markersLoaded = true
    }

    /// Compares every marker in the account's vault directory with the one this device holds for its vault: each
    /// device vouches for the markers it holds under its own name, so the directory may hold several for one vault,
    /// and they must agree. One that names another owner is kept beside the first (a row of its own) and the vault
    /// is in `markerConflicts` from then on, on this device and after a restart. `listed` is the directory's listing
    /// this sync already made; each object is fetched once a session, and must carry the signatures of the account
    /// and of a device registered now.
    func examineSharedMarkers(
        listed: Set<String>, view: RegistryView, account: AccountRecord, transport: any SyncTransport
    ) async {
        for name in listed.sorted() where !sharing.examinedMarkers.contains(name) {
            guard case .vaultShared(let accountID, let vaultID, let author)? = AccountObjectLocation(name: name),
                accountID == account.accountID, vaultID != account.personalVaultID,
                view.state.devices[author] != nil
            else { continue }
            guard
                let bytes = try? await transport.fetch(name, maximumLength: Self.directoryObjectMaximumLength),
                let object = try? SignedObject.parse(bytes),
                (try? Self.verifyDual(
                    object.signature, over: Self.directoryMessage(name: name, body: object.envelope),
                    domain: .vaultDirectory, author: author, view: view)) != nil,
                let marker = Self.parseSharedMarkerBody(object.envelope), marker.vaultID == vaultID
            else { continue }
            sharing.examinedMarkers.insert(name)
            guard let held = sharing.markers[vaultID], held != marker.owner else { continue }
            let row = Self.sharedMarkerRow(
                vaultID: vaultID, accountID: account.accountID, author: author, object: object)
            if (try? await store.record(row.key)) == nil {
                try? await store.commit(StoreChange(upserts: [row], expectations: [row.key: .absent]))
            }
            sharing.markerConflicts.insert(vaultID)
        }
    }

    /// Records, signed by the account key and this device, that `vaultID` is governed by a membership chain owned
    /// by `owner`, and publishes it in the account's vault directory if the transport can be reached now (the next
    /// sync publishes it otherwise). Does nothing if this device already holds a marker for the vault.
    func markShared(_ vaultID: UUID, owner: UUID, account: AccountRecord, epoch: UInt64) async throws {
        await loadSharedMarkersIfNeeded()
        guard vaultID != account.personalVaultID else { return }
        // Never a second owner for a vault under this account's signature.
        if let held = sharing.markers[vaultID], held != owner {
            throw SharingError.vaultOwnerConflict(vaultID: vaultID)
        }
        let key = RecordKey(recordID: Self.sharedMarkerRecordID(vaultID, owner: owner), kind: .vaultDirectory)
        if sharing.markers[vaultID] != nil, try await store.record(key) != nil { return }
        let location = AccountObjectLocation.vaultShared(
            accountID: account.accountID, vaultID: vaultID, author: account.deviceID)
        let body = Self.sharedMarkerBody(vaultID: vaultID, owner: owner)
        let signature = try await dualSignature(
            Self.directoryMessage(name: location.name, body: body), domain: .vaultDirectory,
            keys: try requireKeys(since: epoch), account: account)
        _ = try requireKeys(since: epoch)
        let object = SignedObject(signature: signature, envelope: body)
        let row = Self.sharedMarkerRow(
            vaultID: vaultID, accountID: account.accountID, author: account.deviceID, object: object)
        if let existing = try await store.record(key) {
            // A row that is there and marks nothing (edited in the file) is replaced, above its version.
            var replacement = row
            replacement.version = existing.version < .max ? existing.version + 1 : existing.version
            try await store.commit(
                StoreChange(upserts: [replacement], expectations: [key: .version(existing.version)]))
        } else {
            try await store.commit(StoreChange(upserts: [row], expectations: [key: .absent]))
        }
        sharing.markers[vaultID] = sharing.markers[vaultID] ?? owner
        if let transport = syncSettings?.transport {
            _ = try? await create(location.name, contents: object.serialized(), on: transport)
        }
    }

    /// Whether `vaultID` is governed by a membership chain, as far as anything this device holds says so. With the
    /// markers not read yet the answer for any vault but the Personal one is yes: nothing is run as a private vault
    /// on a fact that has not been looked up.
    func isMarkedShared(_ vaultID: UUID, keys: UnlockedKeys?, personalVaultID: UUID?) -> Bool {
        if vaultID == personalVaultID { return false }
        if sharing.vaults[vaultID] != nil || sharing.markers[vaultID] != nil || sharing.unloadable.contains(vaultID) {
            return true
        }
        if keys?.vaultKeys.values.contains(where: { $0.vaultID == vaultID && $0.arrivedByGrant }) == true {
            return true
        }
        return !sharing.markersLoaded
    }

    /// Shared, and no verified ledger loaded for it: held closed on this device.
    func isSharedUnavailable(_ vaultID: UUID, keys: UnlockedKeys?, personalVaultID: UUID?) -> Bool {
        sharing.vaults[vaultID] == nil && isMarkedShared(vaultID, keys: keys, personalVaultID: personalVaultID)
    }

    /// The invitation this device would accept to set up a shared vault its account already takes part in: the
    /// vault and the owner its account's marker names. `nil` for a vault that is not marked, or whose owner this
    /// device does not know (it holds a granted key and no marker yet): the person then needs the invitation they
    /// were sent. An invitation is not a secret and proves nothing; accepting it verifies the owner and the chain.
    public func sharedVaultInvitation(_ vaultID: UUID) async throws -> Invitation? {
        _ = try requireKeys()
        await loadSharedMarkersIfNeeded()
        await loadSharedVaultsIfNeeded()
        if let owner = sharing.vaults[vaultID]?.ledger.owner.accountID {
            return Invitation(vaultID: vaultID, ownerAccountID: owner)
        }
        // Not where the account's markers disagree about the owner (Z48).
        guard !sharing.markerConflicts.contains(vaultID), let owner = sharing.markers[vaultID] else { return nil }
        return Invitation(vaultID: vaultID, ownerAccountID: owner)
    }
}
