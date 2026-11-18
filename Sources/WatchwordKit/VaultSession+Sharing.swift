import Foundation
import SecureMemory
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync

/// One shared vault as this device holds it (docs/02-architecture.md §8.8): the verified ledger, at most one rotation
/// plan, the records this device proposed and has not seen adopted, and what it has seen of each device's stream.
struct SharedVault: Sendable {
    var ledger: MembershipLedger
    var proposals: [MembershipRecord] = []
    /// `RotationPlan.encoded()`, parsed as this account's on every use (S23).
    var plan: [UInt8]?
    var index = SharedStreamIndex()
    /// Membership objects refused for good (`malformed`, `invalid`), so a flood is paid for once per session.
    var refusedNames: Set<String> = []
    var keyCheck: MemberKeyCheck?
    /// Something this pass learnt changes which writes count: replay the vault's log with the judge. In memory; what
    /// must outlast a restart is also written down by clearing `index.judgedHead` (review finding S41).
    var needsReconcile = false
    var indexChanged = false
    /// The saved index was refused or missing, so it is being rebuilt from the log: what no longer counts is taken
    /// out only once the replay has rebuilt it, never judged against an empty index.
    var indexRebuilding = false
    /// The head the store was last taken out against in this session (`takeOutWhatNoLongerCounts`), so that a replay
    /// settles a head only if the take-out before it used the same one (review finding S65). In memory.
    var takenOutAgainst: [UInt8]?
}

/// An account's device registry as one vault's chain anchors it: the account, and the signing key that chain lists
/// for it (review finding S39). Two vaults may list different keys under one account ID; each judges by its own.
struct MemberRegistryAnchor: Hashable, Sendable {
    var accountID: UUID
    var signingKey: [UInt8]
}

/// The session's sharing state: the settings, the shared vaults once loaded, and the other members' device
/// registries as last fetched (public data, kept across a lock).
struct SharingRuntime: Sendable {
    var settings: SharingSettings?
    var vaults: [UUID: SharedVault] = [:]
    var loaded = false
    /// Vaults the sharing state lists as shared whose saved ledger could not be restored at the last load (the owner's
    /// pin gone or replaced, the ledger or owner row damaged: A8). Such a vault is shared whatever this device can
    /// verify, so it is never treated as one of the account's own: nothing is written, synced, sealed under a
    /// fallback key, shared again or accepted into it until a load restores it (`sharedVaultUnavailable`;
    /// docs/06-adversarial-review.md, V19). Kept across a lock, as `loaded` is, and recomputed by every load.
    var unanchored: Set<UUID> = []
    /// Other accounts' registries, evaluated from the transport, by the anchor a vault's chain gives them.
    var registries: [MemberRegistryAnchor: DeviceRegistryState] = [:]
}

/// A contact as the key directory gives it, with what this device knows of it: the fingerprint to compare out of
/// band and whether it is already pinned (PRD F4.2, docs/02-architecture.md §8.4).
public struct ContactCandidate: Sendable {
    public let accountID: UUID
    public let fingerprint: Fingerprint
    public let trust: ContactTrust
}

/// What the UI shows of a shared vault (PRD F4.3, F4.5; review finding D17).
public struct SharedVaultStatus: Sendable, Hashable {
    public let vaultID: UUID
    public let membership: MembershipState
    /// This account's role, `nil` once it was removed or left.
    public let role: MemberRole?
    public let writePermission: WritePermission
    /// Whether this account may rename the vault: its owner or an administrator, while it may write (§8.7). For the
    /// screens; `renameVault` checks again, and so does every other device's judge.
    public let mayRename: Bool
    /// Members whose keys in the chain differ from this device's pins (shown as a warning), and members trusted
    /// through the chain only (shown as unverified).
    public let substitutedMembers: [UUID]
    public let unverifiedMembers: [UUID]
    /// Members other than this account whose keys in the chain are the ones this device pinned, from a comparison made
    /// on the current head; `nil` when no such comparison could be made (the vault is locked, or the contacts could not
    /// be read). Only these are shown as verified: an empty `unverifiedMembers` is not evidence of anything.
    public let verifiedMembers: [UUID]?
    /// "Pending rotation" (F4.3).
    public let pendingRotation: [PendingRotation]
    /// Writes held aside because they do not count (docs/02-architecture.md §8.7), for the person to look at.
    public let heldAside: Int
    /// The vault has gone on in a format this version cannot read (`MembershipLedger.continuesInLaterFormat`,
    /// docs/02-architecture.md §8.9): it is read-only on this device, which proposes, plans, publishes and seals
    /// nothing there, and the person is told to update the app.
    public let requiresNewerVersion: Bool
}

/// What the sharing half of one sync did for one vault.
public struct SharedVaultSyncReport: Sendable, Equatable {
    public var membershipChanged = false
    public var recordsRejected = 0
    public var keyReceived = false
    public var rotation: RotationStatus?
    public var resealed = 0
    /// The vault's chain stopped at a later format (§8.9): only membership was ingested and the log downloaded and
    /// merged; nothing was proposed, planned, published or sealed again.
    public var requiresNewerVersion = false
    /// Why a step stopped, for diagnostics; the next sync tries again.
    public var failure: String?
    /// The transport stopped the pass (`SyncTransportError.stopsSync`: offline, throttled with the wait it asked,
    /// signed out). The rest of the sync asks the transport no more (`AutoSyncOutcome` reads it).
    public var transportFailure: SyncTransportError?

    public init() {}
}

extension VaultSession {
    // MARK: - Configuration and contacts

    /// Turns sharing on for this session. Sharing travels over the sync transport, so sync must be configured too.
    public func configureSharing(_ settings: SharingSettings) {
        sharing.settings = settings
        sharing.loaded = false
    }

    /// This account's public key bundle: what the key directory publishes, and whose fingerprint the person reads
    /// out to someone inviting them (PRD F4.2).
    public func publicKeyBundle() throws -> PublicKeyBundle {
        try requireKeys().keyset.publicKeyBundle()
    }

    /// Looks an account up in the key directory, for the person to compare its fingerprint out of band.
    public func contactCandidate(_ accountID: UUID) async throws -> ContactCandidate {
        let settings = try sharingSettings()
        let contacts = try verifiedContacts(settings)
        let bundle = try await settings.directory.candidateBundle(for: accountID)
        return ContactCandidate(
            accountID: accountID, fingerprint: bundle.fingerprint, trust: try await contacts.trust(of: bundle))
    }

    /// Confirms an account's fingerprint (typed safety number, scanned code, or the person's own comparison) and
    /// pins its bundle (docs/02-architecture.md §8.4). A different bundle already pinned is refused
    /// (`SharingError.keySubstituted`) unless `replacingPin`, which the person chooses explicitly.
    @discardableResult
    public func verifyContact(_ accountID: UUID, evidence: VerificationEvidence, replacingPin: Bool = false)
        async throws -> VerifiedContact
    {
        let settings = try sharingSettings()
        let epoch = lockEpoch
        let contacts = try verifiedContacts(settings)
        let bundle = try await settings.directory.candidateBundle(for: accountID)
        let now = await clock.now()
        let keys = try requireKeys(since: epoch)
        let pinned = try await contacts.verify(
            bundle, evidence: evidence, signedBy: keys.keyset, at: now, replacingPin: replacingPin)
        retryUnanchoredVaults()
        return pinned
    }

    func sharingSettings() throws -> SharingSettings {
        guard let settings = sharing.settings else { throw SharedVaultError.sharingNotConfigured }
        guard syncSettings != nil else { throw SharedVaultError.syncNotConfigured }
        return settings
    }

    func verifiedContacts(_ settings: SharingSettings) throws -> VerifiedContacts {
        VerifiedContacts(store: settings.contacts, account: try requireKeys().keyset.publicKeyBundle())
    }

    func sharedVault(_ vaultID: UUID) throws -> SharedVault {
        guard let vault = sharing.vaults[vaultID] else { throw SharedVaultError.notShared(vaultID) }
        return vault
    }

    // MARK: - Loading and saving

    /// Reads every saved ledger, plan, proposal list and stream index, each verified again (docs/02-architecture.md
    /// §8.3, §8.6). Needs the keyset (the account's own bundle anchors the checks); a ledger whose owner's pin is
    /// gone is not loaded, which puts the vault back in front of the person.
    func loadSharedVaultsIfNeeded() async {
        guard !sharing.loaded, let settings = sharing.settings, keys != nil else { return }
        let epoch = lockEpoch
        guard let ids = try? await settings.state.sharedVaultIDs() else { return }
        var loaded: [UUID: SharedVault] = [:]
        for vaultID in ids {
            guard let ownerBytes = try? await settings.state.value(.owner, vaultID: vaultID), ownerBytes.count == 16,
                let saved = try? await settings.state.value(.ledger, vaultID: vaultID),
                let keys = try? requireKeys(since: epoch), let bundle = try? keys.keyset.publicKeyBundle()
            else { continue }
            let ownerID = Self.uuid(ownerBytes)
            let contacts = VerifiedContacts(store: settings.contacts, account: bundle)
            guard let owner = ownerID == bundle.accountID ? contacts.myself : try? await contacts.pinned(ownerID),
                let ledger = try? MembershipLedger.restore(saved, vaultID: vaultID, owner: owner, account: bundle)
            else { continue }
            var vault = SharedVault(ledger: ledger)
            if let bytes = try? await settings.state.value(.proposals, vaultID: vaultID) {
                vault.proposals = SharedBytes.decodeRecords(bytes).filter {
                    $0.vaultID == vaultID && $0.signer == bundle.accountID
                }
            }
            if let plan = try? await settings.state.value(.plan, vaultID: vaultID),
                (try? RotationPlan.parse(plan, account: bundle)) != nil
            {
                vault.plan = plan
            }
            if let bytes = try? await settings.state.value(.streamIndex, vaultID: vaultID) {
                if let index = SharedStreamIndex.parse(bytes, account: bundle, vaultID: vaultID) {
                    vault.index = index
                } else {
                    // Refused whole (A8, or damage): rebuilt from the log.
                    vault.needsReconcile = true
                    vault.indexRebuilding = true
                }
            } else {
                vault.needsReconcile = true
                vault.indexRebuilding = true
            }
            // The comparison of the chain's member keys with the pins is made again for the restored head, not left
            // to the next sync: until it is, nothing would be reported as substituted, here (D17, SEC3) or to the
            // sync keyring (S39).
            vault.keyCheck = try? await ledger.checkMemberKeys(against: contacts)
            loaded[vaultID] = vault
        }
        guard epoch == lockEpoch, !sharing.loaded else { return }
        for (vaultID, vault) in loaded where sharing.vaults[vaultID] == nil {
            sharing.vaults[vaultID] = vault
        }
        // Listed as shared and not restored: unavailable, never "not shared" (V19).
        sharing.unanchored = Set(ids).filter { sharing.vaults[$0] == nil }
        sharing.loaded = true
    }

    /// Whether `vaultID` is a shared vault this device could not restore (`SharingRuntime.unanchored`): shared, and
    /// unavailable here until the owner is checked again.
    func isUnanchoredSharedVault(_ vaultID: UUID) -> Bool {
        sharing.vaults[vaultID] == nil && sharing.unanchored.contains(vaultID)
    }

    /// Refuses anything that would treat an unrestored shared vault as one of the account's own (V19).
    func refuseUnanchored(_ vaultID: UUID) throws {
        if isUnanchoredSharedVault(vaultID) { throw SharedVaultError.sharedVaultUnavailable(vaultID) }
    }

    /// After a pin was made: a vault left unrestored because its owner was not pinned may restore now, so the next use
    /// loads the saved ledgers again (what is already loaded is kept).
    func retryUnanchoredVaults() {
        if !sharing.unanchored.isEmpty { sharing.loaded = false }
    }

    /// Saves one vault's ledger, proposals, plan and index, each signed by the account (or verified again on load).
    func saveSharedVault(_ vaultID: UUID) async throws {
        let settings = try sharingSettings()
        guard let account = try await loadAccount() else { return }
        // Read after the suspension: a lock that landed meanwhile has zeroised the keyset, and reading it traps.
        let keys = try requireKeys()
        guard let vault = sharing.vaults[vaultID] else { return }
        let ledger = try vault.ledger.persisted(signedBy: keys.keyset)
        let index = try vault.index.signed(account: account.accountID, vaultID: vaultID, keyset: keys.keyset)
        try await settings.state.setValue(
            SharedBytes.bytes(vault.ledger.owner.accountID), for: .owner, vaultID: vaultID)
        try await settings.state.setValue(ledger, for: .ledger, vaultID: vaultID)
        try await settings.state.setValue(
            SharedBytes.encodeRecords(vault.proposals), for: .proposals, vaultID: vaultID)
        try await settings.state.setValue(vault.plan, for: .plan, vaultID: vaultID)
        try await settings.state.setValue(index, for: .streamIndex, vaultID: vaultID)
        sharing.vaults[vaultID]?.indexChanged = false
    }

    // MARK: - Objects on the transport

    func sharingTransport() throws -> any SyncTransport {
        guard let syncSettings else { throw SharedVaultError.syncNotConfigured }
        return syncSettings.transport
    }

    /// Every object under `prefix`, fetched. No bound on how many: a bound is something junk filed in the right place
    /// can fill (S10, S24); each object is bounded in size.
    func listSharingObjects(prefix: String, maximumLength: Int, skipping skip: (String) -> Bool = { _ in false })
        async throws -> [(name: String, contents: [UInt8])]
    {
        let transport = try sharingTransport()
        var objects: [(name: String, contents: [UInt8])] = []
        for name in Set(try await transport.list(prefix: prefix)).sorted() where !skip(name) {
            guard let contents = try? await transport.fetch(name, maximumLength: maximumLength) else { continue }
            objects.append((name, contents))
        }
        return objects
    }

    /// Creates an object. Its name ends in a digest of its contents, so one already there is this object.
    func publishSharingObject(_ object: SharingObject) async throws {
        do {
            try await sharingTransport().create(object.name, contents: object.contents)
        } catch SyncTransportError.objectExists {
        }
    }

    // MARK: - Membership (§8.8 steps 1–3)

    /// Lists the vault's membership objects and offers the ledger every one it does not hold. Names first: one that
    /// is not a membership object's, that the ledger holds, or that was refused for good before, is not fetched; and
    /// contents that are not what the name commits to are not offered.
    @discardableResult
    func ingestMembership(_ vaultID: UUID) async throws -> MembershipLedger.IngestReport {
        guard let before = sharing.vaults[vaultID] else { throw SharedVaultError.notShared(vaultID) }
        let objects = try await listSharingObjects(
            prefix: SharingObjectLocation.membershipPrefix(vaultID), maximumLength: MembershipRecord.maximumLength
        ) { name in
            guard let location = SharingObjectLocation(name: name), location.vaultID == vaultID else { return true }
            return before.ledger.holds(location) || before.refusedNames.contains(name)
        }
        let offered = objects.filter { SharingObjectLocation(name: $0.name)?.isName(of: $0.contents) == true }
        guard var vault = sharing.vaults[vaultID] else { throw SharedVaultError.notShared(vaultID) }
        let report = vault.ledger.ingest(offered.map(\.contents))
        for rejection in report.rejected {
            switch rejection.reason {
            case .malformed(.unsupportedFormatVersion), .malformed(.unknownOperation):
                // Perhaps a later format (§8.8 step 1, §8.9): offered again until the ledger holds it, since one that
                // arrives before the record it follows stops the chain only once that record is here.
                let contents = offered[rejection.index].contents
                if vault.ledger.laterFormatRecords.contains(contents) {
                    vault.refusedNames.insert(offered[rejection.index].name)
                }
            case .malformed, .invalid: vault.refusedNames.insert(offered[rejection.index].name)
            case .unconnected: break
            }
        }
        let me = account?.accountID
        // A record of this account's displaced from the chain is a proposal again (S27).
        for record in report.superseded where record.signer == me && !vault.proposals.contains(record) {
            vault.proposals.append(record)
        }
        sharing.vaults[vaultID] = vault
        if let settings = sharing.settings, let contacts = try? verifiedContacts(settings) {
            let check = try? await vault.ledger.checkMemberKeys(against: contacts)
            sharing.vaults[vaultID]?.keyCheck = check
        }
        return report
    }

    /// Publishes a record this device signed, if it can still be adopted, and remembers it until it is.
    func propose(_ record: MembershipRecord, in vaultID: UUID) async throws {
        try await ingestMembership(vaultID)
        guard try sharedVault(vaultID).ledger.status(of: record) == .awaitingPublication else {
            throw SharingError.nothingToDo
        }
        sharing.vaults[vaultID]?.proposals.append(record)
        try await saveSharedVault(vaultID)
        try await publishSharingObject(SharingObject(record))
        try await ingestMembership(vaultID)
        try await saveSharedVault(vaultID)
    }

    /// Every proposal of this device's: adopted ones forgotten, waiting ones published again, superseded ones
    /// proposed again on the new head if still wanted and possible (§8.3, S27). Returns whether anything was published.
    func settleProposals(in vaultID: UUID) async throws -> Bool {
        _ = try requireKeys()
        // A chain stopped at a later format (§8.9) takes nothing from this version: proposals are kept, unpublished,
        // for the updated app to judge.
        guard !(try sharedVault(vaultID).ledger.continuesInLaterFormat) else { return false }
        var published = false
        var remaining: [MembershipRecord] = []
        for record in try sharedVault(vaultID).proposals {
            let ledger = try sharedVault(vaultID).ledger
            switch ledger.status(of: record) {
            case .adopted:
                continue
            case .awaitingPublication:
                try await publishSharingObject(SharingObject(record))
                remaining.append(record)
                published = true
            case .superseded:
                guard let again = try await proposeAgain(record.operation, ledger: ledger, in: vaultID) else {
                    continue
                }
                try await publishSharingObject(SharingObject(again))
                remaining.append(again)
                published = true
            }
        }
        sharing.vaults[vaultID]?.proposals = remaining
        return published
    }

    /// The record that does on the current head what a superseded record of this device's did; `nil` if it has
    /// happened by other means, is no longer allowed, or is a rotation (which has a plan of its own).
    /// Every signature is made with the keyset as it is after the last suspension (`requireKeys()`), never one read
    /// before it.
    private func proposeAgain(_ operation: MembershipRecord.Operation, ledger: MembershipLedger, in vaultID: UUID)
        async throws -> MembershipRecord?
    {
        switch operation {
        case .changeRole(let accountID, let role):
            let cut =
                ledger.requiresWriteCut(changingRoleOf: accountID, to: role)
                ? try await takeWriteCut(of: accountID, in: vaultID) : nil
            return try? ledger.proposeRoleChange(
                of: accountID, to: role, writeCut: cut, signedBy: try requireKeys().keyset)
        case .addMember(let accountID, let role):
            // The invitation over again, from the pin: the key may have changed on the winning branch.
            guard let settings = sharing.settings, let contacts = try? verifiedContacts(settings),
                var invitation = try? await OutgoingInvitation.begin(
                    vaultID: vaultID, inviting: accountID, as: role, directory: settings.directory, contacts: contacts),
                let account = try await loadAccount(),
                let key = currentVaultKey(vaultID, keys: try requireKeys(), account: account),
                let package = try? invitation.issue(ledger: ledger, vaultKey: key, signedBy: try requireKeys().keyset)
            else { return nil }
            try await publishSharingObject(package.grant)
            return package.proposal
        case .deleteVault:
            return try? ledger.proposeDeletion(signedBy: try requireKeys().keyset)
        case .createVault, .removeMember, .memberLeft, .rotateKey:
            return nil
        }
    }

    // MARK: - Keys (§8.8 step 4)

    /// Opens the grant of the vault's current key if this device does not hold it and the chain entitles this
    /// account to it, and stores the key wrapped under the keyset like any other vault key. Identity (vault, key,
    /// recipient) from where the grant is filed; the sender must be the one the chain names (§8.5).
    @discardableResult
    func fetchCurrentKey(_ vaultID: UUID) async throws -> Bool {
        let epoch = lockEpoch
        let keys = try requireKeys()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let ledger = try sharedVault(vaultID).ledger
        let state = ledger.state
        // Held for this vault, not merely under this ID: another vault's key with the same ID is no key of this one
        // (S38), and `adoptVaultKey` refuses the grant's.
        guard !state.isDeleted, state.member(account.accountID) != nil,
            keys.vaultKeys[state.vaultKeyID]?.vaultID != vaultID
        else { return false }
        let grants = try await listSharingObjects(
            prefix: SharingObjectLocation.grantPrefix(
                vaultID: vaultID, keyID: state.vaultKeyID, recipient: account.accountID),
            maximumLength: KeyGrantCodec.encodedLength)
        let current = try requireKeys(since: epoch)
        guard let key = try? ledger.openGrant(of: state.vaultKeyID, from: grants, as: current.keyset) else {
            return false
        }
        try await adoptVaultKey(key, account: account, epoch: epoch)
        // Records sealed under this key, held aside while it was missing, can be judged now; written down in the
        // index too, so that a restart before the replay still replays (S41).
        requestReplay(vaultID)
        return true
    }

    /// Asks for the vault's log to be replayed with the judge: in this sync, and, through the saved index, in the
    /// next one if this one does not get that far (review finding S41).
    func requestReplay(_ vaultID: UUID) {
        guard sharing.vaults[vaultID] != nil else { return }
        sharing.vaults[vaultID]?.needsReconcile = true
        sharing.vaults[vaultID]?.index.judgedHead = nil
        sharing.vaults[vaultID]?.indexChanged = true
    }

    /// Refuses a vault key whose ID this device already holds, resident or stored, for another vault (S38).
    func checkKeyIDFree(_ keyID: UUID, for vaultID: UUID) async throws {
        if let resident = keys?.vaultKeys[keyID], resident.vaultID != vaultID {
            throw SharedVaultError.keyIDInUse(keyID)
        }
        if let stored = try await store.record(RecordKey(recordID: keyID, kind: .vaultKeyWrap)),
            stored.vaultID != vaultID
        {
            throw SharedVaultError.keyIDInUse(keyID)
        }
    }

    /// Stores a vault key received through a grant as this account's own (a `vaultKeyWrap` row, and a directory row
    /// if the vault is new here), and makes it resident.
    func adoptVaultKey(_ vaultKey: VaultKey, account: AccountRecord, epoch: UInt64) async throws {
        let vaultID = vaultKey.vaultID
        do {
            try await checkKeyIDFree(vaultKey.key.keyID, for: vaultID)
        } catch {
            vaultKey.zeroise()
            throw error
        }
        let keys = try requireKeys(since: epoch)
        var change = StoreChange()
        if try await store.record(RecordKey(recordID: vaultKey.key.keyID, kind: .vaultKeyWrap)) == nil {
            let wrap = StoredRecord(
                recordID: vaultKey.key.keyID, kind: .vaultKeyWrap, vaultID: vaultID,
                keyID: keys.keyset.symmetricKey.keyID, version: 1, deviceID: account.deviceID,
                envelope: try vaultKey.wrap(for: keys.keyset, using: &random))
            change.upserts.append(wrap)
            change.expectations[wrap.key] = .absent
        }
        if try await store.record(RecordKey(recordID: vaultID, kind: .vaultDirectory)) == nil {
            let row = Self.directoryRow(vaultID: vaultID, accountID: account.accountID, deviceID: account.deviceID)
            change.upserts.append(row)
            change.expectations[row.key] = .absent
        }
        if !change.upserts.isEmpty { try await store.commit(change) }
        guard epoch == lockEpoch, let current = self.keys else {
            vaultKey.zeroise()
            throw VaultError.locked
        }
        var vaultKeys = current.vaultKeys
        vaultKeys[vaultKey.key.keyID] = vaultKey
        self.keys = UnlockedKeys(
            accountUnlockKey: current.accountUnlockKey, keyset: current.keyset, vaultKeys: vaultKeys)
    }

    // MARK: - Creating, inviting, accepting, leaving (PRD F4.1, F4.2, F4.4)

    /// Makes one of the account's own vaults shareable: signs and publishes the genesis record of its membership
    /// chain, with this account as its owner and the vault's current key. Nobody else is a member yet.
    public func shareVault(_ vaultID: UUID) async throws {
        let settings = try sharingSettings()
        let epoch = lockEpoch
        _ = try requireKeys()
        await loadSharedVaultsIfNeeded()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        guard vaultID != account.personalVaultID else { throw SharedVaultError.personalVaultCannotBeShared }
        guard sharing.vaults[vaultID] == nil else { return }
        // A vault this device holds sharing state for is shared already, restored or not: a new genesis would replace
        // its owner and ledger for good (V19).
        try refuseUnanchored(vaultID)
        if try await settings.state.value(.owner, vaultID: vaultID) != nil {
            throw SharedVaultError.sharedVaultUnavailable(vaultID)
        }
        let keys = try requireKeys(since: epoch)
        let vaultKey = try await writableVaultKey(vaultID, keys: keys, account: account)
        let current = try requireKeys(since: epoch)
        let ledger = try MembershipLedger.create(vaultKey: vaultKey, owner: current.keyset)
        sharing.vaults[vaultID] = SharedVault(ledger: ledger)
        try await saveSharedVault(vaultID)
        try await publishSharingObject(SharingObject(ledger.chain[0].record))
    }

    /// Invites a verified contact (`verifyContact` first; PRD F4.1): wraps the current key to the bundle that was
    /// verified and proposes the record that adds them. The returned invitation goes to the invitee out of band; it
    /// names only the vault and its owner.
    public func invite(_ accountID: UUID, to vaultID: UUID, as role: MemberRole) async throws -> Invitation {
        let settings = try sharingSettings()
        let epoch = lockEpoch
        let contacts = try verifiedContacts(settings)
        await loadSharedVaultsIfNeeded()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        var invitation = try await OutgoingInvitation.begin(
            vaultID: vaultID, inviting: accountID, as: role, directory: settings.directory, contacts: contacts)
        guard invitation.fingerprintToConfirm == nil else { throw SharingError.fingerprintNotVerified }
        // On the newest head this device can see.
        try await ingestMembership(vaultID)
        let keys = try requireKeys(since: epoch)
        let ledger = try sharedVault(vaultID).ledger
        guard let vaultKey = currentVaultKey(vaultID, keys: keys, account: account) else {
            throw SharedVaultError.awaitingKey(ledger.state.vaultKeyID)
        }
        let package = try invitation.issue(ledger: ledger, vaultKey: vaultKey, signedBy: keys.keyset)
        try await publishSharingObject(package.grant)
        try await propose(package.proposal, in: vaultID)
        return package.invitation
    }

    /// Accepts an invitation. The owner's fingerprint must have been confirmed (`ownerEvidence`, unless the owner is
    /// already pinned; PRD F4.2). The chain is verified back to that owner before anything is held, this account
    /// must be a member with its own keys, and the grant must come from the account the chain entitles. A vault this
    /// device ever held continues its ledger (S26); one it holds under another owner, its own vaults included, is
    /// refused (`vaultOwnerConflict`, S6).
    @discardableResult
    public func acceptInvitation(_ invitation: Invitation, ownerEvidence: VerificationEvidence? = nil)
        async throws -> UUID
    {
        let settings = try sharingSettings()
        let epoch = lockEpoch
        let contacts = try verifiedContacts(settings)
        await loadSharedVaultsIfNeeded()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let vaultID = invitation.vaultID
        // A vault this device held and cannot restore is never rebuilt from the store (S26, V19).
        try refuseUnanchored(vaultID)
        var knownOwner = sharing.vaults[vaultID]?.ledger.owner.accountID
        if knownOwner == nil, let saved = try await settings.state.value(.owner, vaultID: vaultID),
            saved.count == 16
        {
            knownOwner = Self.uuid(saved)
        }
        if knownOwner == nil {
            let held = try await vaultDirectory(account)[vaultID] != nil
            if held || vaultID == account.personalVaultID { knownOwner = account.accountID }
        }
        var incoming = try await IncomingInvitation.begin(
            invitation, knownOwner: knownOwner, directory: settings.directory, contacts: contacts)
        if incoming.fingerprintToConfirm != nil {
            guard let ownerEvidence else { throw SharingError.fingerprintNotVerified }
            let now = await clock.now()
            try await incoming.confirm(
                ownerEvidence, contacts: contacts, signedBy: try requireKeys(since: epoch).keyset, at: now)
        }
        let records = try await listSharingObjects(
            prefix: SharingObjectLocation.membershipPrefix(vaultID), maximumLength: MembershipRecord.maximumLength
        ).filter { SharingObjectLocation(name: $0.name)?.isName(of: $0.contents) == true }
        let grants = try await listSharingObjects(
            prefix: SharingObjectLocation.vaultPrefix(vaultID) + "grant/", maximumLength: KeyGrantCodec.encodedLength)
        let keys = try requireKeys(since: epoch)
        let joined = try incoming.accept(
            membership: records.map(\.contents), grants: grants, as: keys.keyset,
            continuing: sharing.vaults[vaultID]?.ledger)
        // Before anything is held: a chain whose key ID is another vault's here would displace that vault's key
        // (S38). Its owner chose the ID, and key IDs are public.
        do {
            try await checkKeyIDFree(joined.vaultKey.key.keyID, for: vaultID)
            _ = try requireKeys(since: epoch)
        } catch {
            joined.vaultKey.zeroise()
            throw error
        }
        var vault = sharing.vaults[vaultID] ?? SharedVault(ledger: joined.ledger)
        vault.ledger = joined.ledger
        vault.needsReconcile = true
        vault.index.judgedHead = nil
        sharing.vaults[vaultID] = vault
        try await adoptVaultKey(joined.vaultKey, account: account, epoch: epoch)
        try await saveSharedVault(vaultID)
        return vaultID
    }

    /// Asks to leave a shared vault (PRD F4.4): publishes a signed leave request. An administrator's device turns it
    /// into a rotation; until then this account is still a member. The ledger is kept (S26).
    public func leaveSharedVault(_ vaultID: UUID) async throws {
        _ = try sharingSettings()
        let keys = try requireKeys()
        await loadSharedVaultsIfNeeded()
        try await ingestMembership(vaultID)
        let state = try sharedVault(vaultID).ledger.state
        guard state.owner.accountID != keys.keyset.accountID else { throw SharingError.ownerCannotLeave }
        // Read-only past a later format (§8.9): nothing is published for the vault until the app is updated.
        guard !(try sharedVault(vaultID).ledger.continuesInLaterFormat) else { throw SharingError.requiresNewerVersion }
        let request = try LeaveRequest.make(leaving: state, as: try requireKeys().keyset)
        try await publishSharingObject(SharingObject(request))
    }

    /// Changes a member's role (PRD F4.5). A sync first, so the record is built on the newest head and what the
    /// member wrote has been merged; then, if the change takes away their permission to write, the cut that says
    /// which of their writes count (§8.7); then the record.
    public func changeRole(of accountID: UUID, in vaultID: UUID, to role: MemberRole) async throws {
        _ = try sharingSettings()
        _ = try requireKeys()
        await loadSharedVaultsIfNeeded()
        _ = try sharedVault(vaultID)
        try await syncAll()
        let ledger = try sharedVault(vaultID).ledger
        let cut =
            ledger.requiresWriteCut(changingRoleOf: accountID, to: role)
            ? try await takeWriteCut(of: accountID, in: vaultID) : nil
        let record = try ledger.proposeRoleChange(
            of: accountID, to: role, writeCut: cut, signedBy: try requireKeys().keyset)
        try await propose(record, in: vaultID)
        try await syncAll()
    }

    /// Removes a member (PRD F4.3), in the order F4.3 gives: off the transport's share at once (if this account may
    /// remove them at all), a sync so everything they wrote that this device can have is merged, the cut, then the
    /// signed plan, saved, and carried out by the syncs that follow: grants of a new key to everyone who stays, the
    /// record, and every record sealed again under the new key.
    @discardableResult
    public func removeMember(_ accountID: UUID, from vaultID: UUID) async throws -> RotationStatus {
        let settings = try sharingSettings()
        let keys = try requireKeys()
        await loadSharedVaultsIfNeeded()
        try await ingestMembership(vaultID)
        guard try sharedVault(vaultID).ledger.mayRemove(accountID, signer: keys.keyset.accountID) else {
            throw SharingError.notPermitted
        }
        try await settings.shareAccess?.revokeAccess(of: accountID, to: vaultID)
        try await syncAll()
        try await planRotation(.removal(accountID), in: vaultID)
        return try await carryOutRotation(in: vaultID)
    }

    /// A routine rotation: a new key for everyone who stays, and every record sealed again under it.
    @discardableResult
    public func rotateVaultKey(_ vaultID: UUID) async throws -> RotationStatus {
        _ = try sharingSettings()
        _ = try requireKeys()
        await loadSharedVaultsIfNeeded()
        try await syncAll()
        try await planRotation(.routine, in: vaultID)
        return try await carryOutRotation(in: vaultID)
    }

    /// Plans a rotation and saves the plan before anything is published, so an interruption (a lock, a crash, the
    /// network) leaves a plan the next sync resumes (§8.6).
    func planRotation(_ reason: RotationReason, in vaultID: UUID) async throws {
        let settings = try sharingSettings()
        let epoch = lockEpoch
        let contacts = try verifiedContacts(settings)
        try await ingestMembership(vaultID)
        let ledger = try sharedVault(vaultID).ledger
        var cut: WriteCut?
        if let departing = reason.departingAccount, ledger.requiresWriteCut(removing: departing) {
            cut = try await takeWriteCut(of: departing, in: vaultID)
        }
        let memberKeys = try await ledger.checkMemberKeys(against: contacts)
        let keys = try requireKeys(since: epoch)
        let plan = try RotationPlanner.plan(
            reason, ledger: ledger, memberKeys: memberKeys, writeCut: cut, signedBy: keys.keyset, using: &random)
        sharing.vaults[vaultID]?.plan = plan.encoded()
        try await saveSharedVault(vaultID)
    }

    /// Carries the saved plan forward from wherever it stands and syncs, so what it sealed again reaches the others.
    func carryOutRotation(in vaultID: UUID) async throws -> RotationStatus {
        let status = try await resumeRotation(in: vaultID)
        try await syncAll()
        return status
    }

    /// Continues a saved plan (`RotationPlan.steps(in:)`); each step is safe to repeat. A superseded removal or
    /// departure is planned again, once per call.
    func resumeRotation(in vaultID: UUID) async throws -> RotationStatus {
        // A saved plan is not carried on past a later format (§8.9): it would publish and seal on a chain this
        // version no longer follows.
        guard !(try sharedVault(vaultID).ledger.continuesInLaterFormat) else { throw SharingError.requiresNewerVersion }
        var status = RotationStatus.complete
        for _ in 0..<2 {
            let keys = try requireKeys()
            guard let saved = try sharedVault(vaultID).plan else { return status }
            let plan = try RotationPlan.parse(saved, account: try keys.keyset.publicKeyBundle())
            status = try await carryOut(plan, in: vaultID)
            switch status {
            case .complete:
                sharing.vaults[vaultID]?.plan = nil
                try await saveSharedVault(vaultID)
            case .superseded:
                sharing.vaults[vaultID]?.plan = nil
                try await saveSharedVault(vaultID)
                // The intent outlives the plan: a removal or departure that lost a fork is planned again.
                if plan.reason.departingAccount != nil, (try? await planRotation(plan.reason, in: vaultID)) != nil {
                    continue
                }
            case .awaitingPublication, .resealing:
                break
            }
            return status
        }
        return status
    }

    private func carryOut(_ plan: RotationPlan, in vaultID: UUID) async throws -> RotationStatus {
        let settings = try sharingSettings()
        steps: for step in try sharedVault(vaultID).ledger.steps(of: plan) {
            _ = try requireKeys()
            switch step {
            case .revokeTransportAccess(let accountID):
                try await settings.shareAccess?.revokeAccess(of: accountID, to: vaultID)
            case .publish(let object):
                if object == plan.record {
                    // Never publish a record that can no longer be adopted: one more look at the store first.
                    try await ingestMembership(vaultID)
                    guard try sharedVault(vaultID).ledger.status(of: plan.proposal) == .awaitingPublication else {
                        break steps
                    }
                }
                try await publishSharingObject(object)
            case .resealRecords:
                try await ingestMembership(vaultID)
                guard try sharedVault(vaultID).ledger.status(of: plan.proposal) == .adopted else { break steps }
                try await fetchCurrentKey(vaultID)
                _ = try await resealSharedVault(vaultID)
            }
        }
        try await ingestMembership(vaultID)
        try await fetchCurrentKey(vaultID)
        try await saveSharedVault(vaultID)
        return plan.status(in: try sharedVault(vaultID).ledger, inventory: try await sharedInventory(vaultID))
    }

    /// The vault's live records as rotation sees them: only what counts, since what does not was taken out.
    ///
    /// With `account`, only what that account's device seals again: the vault's description is left out unless the
    /// account may name the vault (`mayRenameSharedVault`), because only an administrator's device seals it again
    /// (§8.7, review finding S55). So a read-write member's `pendingRotation` does not report as owed, for ever, a
    /// record it never seals (PR review of `resealSharedVault`; docs/06-adversarial-review.md §T, S60). Without it,
    /// everything, as the planning device (an administrator's) counts its plan.
    func sharedInventory(_ vaultID: UUID, resealableBy account: UUID? = nil) async throws -> [SealedRecordReference] {
        var kinds = [EnvelopeKind.item, .vaultMetadata, .scanStatus]
        if let account, !mayRenameSharedVault(try sharedVault(vaultID), account: account) {
            kinds.removeAll { $0 == .vaultMetadata }
        }
        var inventory: [SealedRecordReference] = []
        for kind in kinds {
            for row in try await store.records(in: vaultID, kind: kind) {
                inventory.append(
                    SealedRecordReference(recordID: row.recordID, kind: kind, keyID: row.keyID, version: row.version))
            }
        }
        return inventory
    }

    /// Seals again, under the current key, every record `recordsToReseal` lists: the same state at a higher version
    /// (`ItemMerge.written`), not an edit, so two devices doing it at once converge and every value keeps its own
    /// author (§8.6, §8.8 step 6). Only by a member who may write and holds the current key. Returns how many.
    ///
    /// **Only what has been judged against the head it is sealed under** (review finding S59). A version sealed
    /// under a key introduced at or after the record that ended an account's standing is believed, by a member who
    /// joined after a rotation, to have been judged with that record in hand (§8.10, vouching). A rotation ingests
    /// membership on its way here, so the head may have moved past the one this device last judged its records
    /// against, by another account's record as well as its own: what no longer counts is taken out first, and while
    /// that cannot be done (the stream index is being rebuilt) nothing is sealed again; the next sync does both.
    func resealSharedVault(_ vaultID: UUID) async throws -> Int {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        guard try sharedVault(vaultID).ledger.writePermission(for: account.accountID).isAllowed else { return 0 }
        try await takeOutWhatNoLongerCounts(vaultID)
        guard try !sharedVault(vaultID).indexRebuilding else { return 0 }
        _ = try requireKeys(since: epoch)
        let ledger = try sharedVault(vaultID).ledger
        guard ledger.writePermission(for: account.accountID).isAllowed else { return 0 }
        let stale = ledger.recordsToReseal(in: try await sharedInventory(vaultID, resealableBy: account.accountID))
        var count = 0
        for reference in stale {
            let keys = try requireKeys(since: epoch)
            guard let vaultKey = currentVaultKey(vaultID, keys: keys, account: account),
                let row = try await store.record(RecordKey(recordID: reference.recordID, kind: reference.kind)),
                row.vaultID == vaultID, row.version == reference.version
            else { continue }
            let current = try requireKeys(since: epoch)
            let revision = try nextRevision(in: vaultID, above: row, account: account)
            switch reference.kind {
            case .item:
                guard let item = try? openItem(row, keys: current) else { continue }
                let canonical = ItemMerge.canonical(item, origin: Self.origin(row))
                try await commitItem(
                    ItemMerge.written(canonical, as: revision), replacing: row, vaultKey: vaultKey, account: account)
            case .vaultMetadata:
                // Only an administrator seals the description again. It stays the work of whoever chose it (S37),
                // but a member who joined after this rotation cannot read the segment that first carried it, and
                // takes it on the word of the version that carries it on: an administrator's word, never a member's,
                // who may not name the vault (§8.10). The device that planned the rotation is an administrator's.
                guard ledger.administratorStanding(of: account.accountID) == .holdsRole else { continue }
                guard var metadata = try? openMetadata(row, keys: current) else { continue }
                // Sealed again, not written: the description stays the work of whoever chose it (S37).
                metadata.writtenBy = metadata.writtenBy ?? Self.origin(row)
                metadata.version = revision.version
                let sealed = try sealMetadata(metadata, vaultKey: vaultKey, account: account)
                try await writer(for: account).commit(
                    StoreChange(upserts: [sealed], expectations: [sealed.key: .version(row.version)]))
                highestVersionSeen[vaultID] = max(highestVersionSeen[vaultID] ?? 0, revision.version)
            case .scanStatus:
                // Sealed again, not written: every observation keeps its device, revision and the key its bindings
                // are under, which this device still holds (§13.9).
                guard var record = try? openScanStatus(row, keys: current) else { continue }
                record.version = revision.version
                let sealed = try sealScanStatus(record, vaultKey: vaultKey, account: account)
                try await writer(for: account).commit(
                    StoreChange(upserts: [sealed], expectations: [sealed.key: .version(row.version)]))
            default:
                continue
            }
            count += 1
        }
        return count
    }

    // MARK: - Status

    public func sharedVaultIDs() async throws -> [UUID] {
        _ = try sharingSettings()
        await loadSharedVaultsIfNeeded()
        return sharing.vaults.keys.sorted { $0.uuidString < $1.uuidString }
    }

    /// Shared vaults this device could not restore (the owner's pin is gone or no longer the chain's, or the saved
    /// ledger is damaged): shared and unavailable here, never one of the account's own, until the owner is checked
    /// again (V19). Not in `sharedVaultIDs()`, which lists what this device can show.
    public func sharedVaultsAwaitingOwnerCheck() async throws -> [UUID] {
        _ = try sharingSettings()
        await loadSharedVaultsIfNeeded()
        return sharing.unanchored.filter { sharing.vaults[$0] == nil }.sorted { $0.uuidString < $1.uuidString }
    }

    public func sharedVaultStatus(_ vaultID: UUID) async throws -> SharedVaultStatus {
        _ = try sharingSettings()
        await loadSharedVaultsIfNeeded()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let vault = try sharedVault(vaultID)
        let leaveRequests = try await listSharingObjects(
            prefix: SharingObjectLocation.leavePrefix(vaultID), maximumLength: LeaveRequest.encodedLength)
        // A plan is parsed as this account's, which needs the keyset; while locked it is not shown.
        let plan = keys == nil ? nil : try vault.plan.map { try RotationPlan.parse($0, account: try publicKeyBundle()) }
        let held = Set(
            (keys.map { Array($0.vaultKeys.values) } ?? []).filter { $0.vaultID == vaultID }.map(\.key.keyID))
        let pending = vault.ledger.pendingRotation(
            plan: plan, leaveRequests: leaveRequests,
            inventory: try await sharedInventory(vaultID, resealableBy: account.accountID), heldKeyIDs: held)
        let heldAside = try await syncSettings?.state.quarantined(vaultID: vaultID).count ?? 0
        // Only a comparison made on the current head says anything; one is made now if the keys allow.
        if vault.keyCheck?.head != vault.ledger.state.hash, let settings = sharing.settings,
            let contacts = try? verifiedContacts(settings)
        {
            sharing.vaults[vaultID]?.keyCheck = try? await vault.ledger.checkMemberKeys(against: contacts)
        }
        let check = sharing.vaults[vaultID]?.keyCheck.flatMap { $0.head == vault.ledger.state.hash ? $0 : nil }
        return SharedVaultStatus(
            vaultID: vaultID, membership: vault.ledger.state, role: vault.ledger.state.member(account.accountID)?.role,
            writePermission: vault.ledger.writePermission(for: account.accountID),
            mayRename: mayRenameSharedVault(vault, account: account.accountID),
            substitutedMembers: check?.substituted ?? [], unverifiedMembers: check?.unverified ?? [],
            verifiedMembers: check.map { check in
                vault.ledger.state.members.map(\.accountID).filter {
                    $0 != account.accountID && !check.substituted.contains($0) && !check.unverified.contains($0)
                }
            },
            pendingRotation: pending, heldAside: heldAside,
            requiresNewerVersion: vault.ledger.continuesInLaterFormat)
    }

    // MARK: - Hooks the rest of the session calls

    /// The key new records of a shared vault are sealed under: the one the membership chain names, if this device
    /// holds it (docs/02-architecture.md §7.7, the seam left for this). `nil` for a vault that is not shared.
    func sharedCurrentKey(_ vaultID: UUID, keys: UnlockedKeys) -> VaultKey?? {
        // Unrestored: shared, with no key this device may seal under; never the smallest key ID held (V19).
        if isUnanchoredSharedVault(vaultID) { return .some(nil) }
        guard let vault = sharing.vaults[vaultID] else { return nil }
        let key = keys.vaultKeys[vault.ledger.state.vaultKeyID]
        return .some(key?.vaultID == vaultID ? key : nil)
    }

    /// The client's half of F4.5: a write the person makes to a shared vault needs `writePermission`.
    func checkSharedWrite(_ vaultID: UUID, account: AccountRecord) async throws {
        await loadSharedVaultsIfNeeded()
        try refuseUnanchored(vaultID)
        guard let vault = sharing.vaults[vaultID] else { return }
        if case .refused(let refusal) = vault.ledger.writePermission(for: account.accountID) {
            throw SharedVaultError.writeRefused(refusal)
        }
    }

    /// Whether this account may rename `vaultID` now: any vault that is not shared, and a shared one as its owner or
    /// an administrator on the head this device knows, while it may write at all (docs/02-architecture.md §8.7).
    func mayRenameSharedVault(_ vault: SharedVault, account: UUID) -> Bool {
        vault.ledger.writePermission(for: account).isAllowed
            && vault.ledger.administratorStanding(of: account) == .holdsRole
    }

    /// The client's half of "only the owner or an administrator renames a shared vault": asked after
    /// `checkSharedWrite`, which has loaded the shared vaults and refused an account that may not write at all.
    func checkSharedRename(_ vaultID: UUID, account: AccountRecord) throws {
        try refuseUnanchored(vaultID)
        guard let vault = sharing.vaults[vaultID] else { return }
        guard mayRenameSharedVault(vault, account: account.accountID) else { throw SharedVaultError.renameRefused }
    }

    /// A shared vault is deleted through its chain, by its owner (§8.1); a member leaves instead.
    func checkSharedDeletion(_ vaultID: UUID, account: AccountRecord) async throws {
        await loadSharedVaultsIfNeeded()
        try refuseUnanchored(vaultID)
        guard let vault = sharing.vaults[vaultID] else { return }
        guard vault.ledger.owner.accountID == account.accountID else { throw SharedVaultError.notOwner }
        if !vault.ledger.state.isDeleted {
            let record = try vault.ledger.proposeDeletion(signedBy: try requireKeys().keyset)
            try await propose(record, in: vaultID)
        }
    }
}

extension MembershipLedger {
    /// `RotationPlan.steps(in:)`, from the ledger's side.
    func steps(of plan: RotationPlan) -> [RotationStep] {
        plan.steps(in: self)
    }
}
