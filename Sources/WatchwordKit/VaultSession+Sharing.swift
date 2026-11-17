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
}

/// An account's device registry as one vault's chain anchors it: the account, and the signing key that chain lists
/// for it (review finding S39). Two vaults may list different keys under one account ID; each judges by its own.
struct MemberRegistryAnchor: Hashable, Sendable {
    var accountID: UUID
    var signingKey: [UInt8]
}

/// What this device has anchored of another account's device registry (review finding Z6): the one genesis entry it
/// took, and the credential entry (password change) it follows. From there the registry moves only forward, along
/// credential entries that descend from `credential` one after another; it never crosses to a branch that leaves the
/// chain at or before it, whatever generation that branch reaches.
struct MemberRegistryPin: Hashable, Sendable {
    var genesis: ObjectDigest
    var credential: ObjectDigest
    /// A digest of the disagreeing entries the person last settled (`verifyMemberDevices`): they are not reported
    /// again, and anything new is.
    var settled: ObjectDigest?
}

/// One vault's saved pins. `"WWMD" ‖ version u8 = 1 ‖ own account 16 ‖ vault 16 ‖ count u16 ‖ { account 16 ‖
/// signing key 32 ‖ genesis 32 ‖ credential 32 ‖ settled flag u8 ‖ settled 32? } ‖ signature 64`, in the order of
/// account then signing key. Local state like the saved ledger and the stream index: signed by this account's own key
/// under `SignatureDomain.membership` with its own magic, and refused whole if it does not verify, so a file edited on
/// the device (A8) can make this device anchor again from what the transport shows, and never choose its anchor.
enum MemberRegistryPins {
    static let magic: [UInt8] = Array("WWMD".utf8)
    static let formatVersion: UInt8 = 1
    static let maximumPins = 4096

    static func signed(
        _ pins: [MemberRegistryAnchor: MemberRegistryPin], account: UUID, vaultID: UUID, keyset: Keyset
    ) throws -> [UInt8] {
        let ordered = pins.filter { $0.key.signingKey.count == 32 }.sorted {
            ($0.key.accountID.uuidString, $0.key.signingKey.map { String($0, radix: 16) }.joined())
                < ($1.key.accountID.uuidString, $1.key.signingKey.map { String($0, radix: 16) }.joined())
        }.prefix(maximumPins)
        var out = magic + [formatVersion] + SharedBytes.bytes(account) + SharedBytes.bytes(vaultID)
        out += SharedBytes.littleEndian16(UInt16(ordered.count))
        for (anchor, pin) in ordered {
            out += SharedBytes.bytes(anchor.accountID) + anchor.signingKey + pin.genesis.bytes + pin.credential.bytes
            if let settled = pin.settled {
                out += [1] + settled.bytes
            } else {
                out += [0]
            }
        }
        return out + (try keyset.sign(out, domain: .membership))
    }

    static func parse(_ bytes: [UInt8], account: PublicKeyBundle, vaultID: UUID)
        -> [MemberRegistryAnchor: MemberRegistryPin]?
    {
        guard bytes.count > 64 else { return nil }
        let body = Array(bytes[..<(bytes.count - 64)])
        guard
            (try? Signatures.verify(
                Array(bytes[(bytes.count - 64)...]), for: body, domain: .membership, signingKey: account.signingKey))
                != nil
        else { return nil }
        var reader = SharedReader(body)
        guard reader.read(4) == magic, reader.read(1) == [formatVersion], reader.uuid() == account.accountID,
            reader.uuid() == vaultID, let count = reader.uint16(), Int(count) <= maximumPins
        else { return nil }
        var pins: [MemberRegistryAnchor: MemberRegistryPin] = [:]
        for _ in 0..<count {
            guard let member = reader.uuid(), let signingKey = reader.read(32),
                let genesis = reader.read(32).flatMap(ObjectDigest.init(bytes:)),
                let credential = reader.read(32).flatMap(ObjectDigest.init(bytes:)), let flag = reader.read(1)
            else { return nil }
            var settled: ObjectDigest?
            switch flag {
            case [0]: break
            case [1]:
                guard let digest = reader.read(32).flatMap(ObjectDigest.init(bytes:)) else { return nil }
                settled = digest
            default: return nil
            }
            pins[MemberRegistryAnchor(accountID: member, signingKey: signingKey)] = MemberRegistryPin(
                genesis: genesis, credential: credential, settled: settled)
        }
        guard reader.remaining == 0 else { return nil }
        return pins
    }
}

/// The session's sharing state: the settings, the shared vaults once loaded, and the other members' device
/// registries as last fetched (public data, kept across a lock).
struct SharingRuntime: Sendable {
    var settings: SharingSettings?
    var vaults: [UUID: SharedVault] = [:]
    var loaded = false
    /// Other accounts' registries, evaluated from the transport, by the anchor a vault's chain gives them.
    var registries: [MemberRegistryAnchor: DeviceRegistryState] = [:]
    /// What this device has anchored of each of them (Z6); saved with every vault whose chain lists the anchor.
    var registryPins: [MemberRegistryAnchor: MemberRegistryPin] = [:]
    /// The anchors whose registry holds entries that disagree about whose devices the account's are, and that the
    /// person has not settled: a second genesis entry, or a password change beside the ones followed.
    var registryDisagreements: Set<MemberRegistryAnchor> = []
    /// The vaults the account's own markers say are shared, each with its chain's owner (the record store's
    /// account-signed rows, VaultSession+SharedMarker.swift), and whether they have been read this session.
    var markers: [UUID: UUID] = [:]
    var markersLoaded = false
    /// Vaults the sharing state names whose ledger did not load (no owner row, no pin for the owner, a ledger that
    /// does not restore): shared, and unavailable until this device accepts their invitation again (Z41).
    var unloadable: Set<UUID> = []
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
    /// Members whose own devices disagree about which of them are the account's (review finding Z6): the member's
    /// device registry holds a second first entry, or a password change beside the one this device follows. Whoever
    /// made it holds that member's account key. Nothing a contested device signs counts here meanwhile, and nothing
    /// is followed until the person has verified with the member again (`verifyMemberDevices`).
    public let membersWithDisagreeingDevices: [UUID]
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
        return try await contacts.verify(
            bundle, evidence: evidence, signedBy: keys.keyset, at: now, replacingPin: replacingPin)
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
    /// §8.3, §8.6). Needs the keyset (the account's own bundle anchors the checks). A vault the sharing state names
    /// whose ledger does not load (its owner row or the owner's pin is gone, or the ledger does not restore) is not
    /// run as a private vault: it is `unloadable`, held closed until this device accepts its invitation again
    /// (review finding Z41). A read that fails is not an answer either: the vault is held closed for now and the
    /// load is tried again by the next caller.
    func loadSharedVaultsIfNeeded() async {
        await loadSharedMarkersIfNeeded()
        guard !sharing.loaded, let settings = sharing.settings, keys != nil else { return }
        let epoch = lockEpoch
        guard let ids = try? await settings.state.sharedVaultIDs() else { return }
        var loaded: [UUID: SharedVault] = [:]
        var pins: [MemberRegistryAnchor: MemberRegistryPin] = [:]
        var unloadable: Set<UUID> = []
        var complete = true
        for vaultID in ids {
            guard let keys = try? requireKeys(since: epoch), let bundle = try? keys.keyset.publicKeyBundle() else {
                return
            }
            let ownerBytes: [UInt8]?
            let saved: [UInt8]?
            do {
                ownerBytes = try await settings.state.value(.owner, vaultID: vaultID)
                saved = try await settings.state.value(.ledger, vaultID: vaultID)
            } catch {
                unloadable.insert(vaultID)
                complete = false
                continue
            }
            guard let ownerBytes, ownerBytes.count == 16, let saved else {
                unloadable.insert(vaultID)
                continue
            }
            let ownerID = Self.uuid(ownerBytes)
            let contacts = VerifiedContacts(store: settings.contacts, account: bundle)
            let owner: VerifiedContact?
            if ownerID == bundle.accountID {
                owner = contacts.myself
            } else {
                do {
                    owner = try await contacts.pinned(ownerID)
                } catch {
                    unloadable.insert(vaultID)
                    complete = false
                    continue
                }
            }
            guard let owner,
                let ledger = try? MembershipLedger.restore(saved, vaultID: vaultID, owner: owner, account: bundle)
            else {
                unloadable.insert(vaultID)
                continue
            }
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
            // What this device anchored of the other members' device registries (Z6). A blob that does not verify
            // is as good as none: the device anchors again from what the transport shows.
            if let bytes = try? await settings.state.value(.memberDevices, vaultID: vaultID),
                let saved = MemberRegistryPins.parse(bytes, account: bundle, vaultID: vaultID)
            {
                for (anchor, pin) in saved where pins[anchor] == nil { pins[anchor] = pin }
            }
        }
        guard epoch == lockEpoch, !sharing.loaded else { return }
        for (anchor, pin) in pins where sharing.registryPins[anchor] == nil { sharing.registryPins[anchor] = pin }
        for (vaultID, vault) in loaded where sharing.vaults[vaultID] == nil {
            sharing.vaults[vaultID] = vault
        }
        sharing.unloadable = unloadable.subtracting(sharing.vaults.keys)
        sharing.loaded = complete
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
        // The pins of the accounts this vault's chain lists (Z6). Signed here, with the rest, before anything
        // suspends: a lock during the writes below must not leave the keyset read after it was zeroised.
        var pins: [MemberRegistryAnchor: MemberRegistryPin] = [:]
        for (member, signingKey) in Self.memberAnchors(of: vault.ledger, excluding: account.accountID) {
            let anchor = MemberRegistryAnchor(accountID: member, signingKey: signingKey)
            pins[anchor] = sharing.registryPins[anchor]
        }
        let memberDevices = try MemberRegistryPins.signed(
            pins, account: account.accountID, vaultID: vaultID, keyset: keys.keyset)
        try await settings.state.setValue(
            SharedBytes.bytes(vault.ledger.owner.accountID), for: .owner, vaultID: vaultID)
        try await settings.state.setValue(ledger, for: .ledger, vaultID: vaultID)
        try await settings.state.setValue(
            SharedBytes.encodeRecords(vault.proposals), for: .proposals, vaultID: vaultID)
        try await settings.state.setValue(vault.plan, for: .plan, vaultID: vaultID)
        try await settings.state.setValue(index, for: .streamIndex, vaultID: vaultID)
        try await settings.state.setValue(memberDevices, for: .memberDevices, vaultID: vaultID)
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
                // An addition its own branch went on to undo is not replayed: the pair lost together, and what it
                // meant is that the member is out (Z43). The key they were given is the ledger's to report
                // (`exposedKeyHolders`) and an administrator's device's to rotate.
                if ledger.wasUndoneOnItsBranch(record) { continue }
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
        try await adoptVaultKey(key, owner: ledger.owner.accountID, account: account, epoch: epoch)
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
    /// if the vault is new here), and makes it resident. The wrap says the key arrived by grant
    /// (`VaultKey.arrivedByGrant`), so every device of the account that receives it knows the vault is shared; a key
    /// this device already holds under that ID must be the same key, or the grant is refused (the ID is public, and
    /// whoever introduced the key chose it). Then the account's marker for the vault, naming the chain's owner.
    func adoptVaultKey(_ vaultKey: VaultKey, owner: UUID, account: AccountRecord, epoch: UInt64) async throws {
        let vaultID = vaultKey.vaultID
        do {
            try await checkKeyIDFree(vaultKey.key.keyID, for: vaultID)
            if let resident = self.keys?.vaultKeys[vaultKey.key.keyID], !resident.hasSameMaterial(as: vaultKey) {
                throw SharedVaultError.keyIDInUse(vaultKey.key.keyID)
            }
        } catch {
            vaultKey.zeroise()
            throw error
        }
        // Both reads first, then the keys: the wrap reads the keyset, which a `lock()` during either read would
        // have zeroised, and reading a zeroised key traps (review finding Z4). Nothing suspends between
        // `requireKeys(since:)` and the wrap.
        let wrapHeld: Bool
        let directoryHeld: Bool
        let keys: UnlockedKeys
        do {
            wrapHeld = try await store.record(RecordKey(recordID: vaultKey.key.keyID, kind: .vaultKeyWrap)) != nil
            directoryHeld = try await store.record(RecordKey(recordID: vaultID, kind: .vaultDirectory)) != nil
            keys = try requireKeys(since: epoch)
        } catch {
            vaultKey.zeroise()
            throw error
        }
        var change = StoreChange()
        if !wrapHeld {
            let wrap = StoredRecord(
                recordID: vaultKey.key.keyID, kind: .vaultKeyWrap, vaultID: vaultID,
                keyID: keys.keyset.symmetricKey.keyID, version: 1, deviceID: account.deviceID,
                envelope: try vaultKey.wrap(for: keys.keyset, using: &random))
            change.upserts.append(wrap)
            change.expectations[wrap.key] = .absent
        }
        if !directoryHeld {
            let row = Self.directoryRow(vaultID: vaultID, accountID: account.accountID, deviceID: account.deviceID)
            change.upserts.append(row)
            change.expectations[row.key] = .absent
        }
        if !change.upserts.isEmpty { try await store.commit(change) }
        guard epoch == lockEpoch, let current = self.keys else {
            vaultKey.zeroise()
            throw VaultError.locked
        }
        // A key already resident is kept: it is the same key (checked above), with the nonces sealed under it so far.
        // A second copy of its bytes, opened from a grant, is not left behind.
        if let resident = current.vaultKeys[vaultKey.key.keyID] {
            if resident.key.material !== vaultKey.key.material { vaultKey.zeroise() }
        } else {
            var vaultKeys = current.vaultKeys
            vaultKeys[vaultKey.key.keyID] = vaultKey
            self.keys = UnlockedKeys(
                accountUnlockKey: current.accountUnlockKey, keyset: current.keyset, vaultKeys: vaultKeys)
        }
        // Best effort: a granted key already says the vault is shared; the marker adds whose it is, for the
        // account's other devices. The next sync writes it if this cannot (`ensureSharedMarkers`).
        try? await markShared(vaultID, owner: owner, account: account, epoch: epoch)
    }

    /// The account's marker for every shared vault this device holds a ledger for, written if it is missing: a vault
    /// joined before markers existed, or one whose marker could not be signed when its key was adopted.
    func ensureSharedMarkers(account: AccountRecord) async {
        guard keys != nil else { return }
        let epoch = lockEpoch
        for (vaultID, vault) in sharing.vaults where sharing.markers[vaultID] == nil {
            try? await markShared(vaultID, owner: vault.ledger.owner.accountID, account: account, epoch: epoch)
        }
    }

    // MARK: - Creating, inviting, accepting, leaving (PRD F4.1, F4.2, F4.4)

    /// Makes one of the account's own vaults shareable: signs and publishes the genesis record of its membership
    /// chain, with this account as its owner and the vault's current key. Nobody else is a member yet.
    public func shareVault(_ vaultID: UUID) async throws {
        _ = try sharingSettings()
        let epoch = lockEpoch
        _ = try requireKeys()
        await loadSharedVaultsIfNeeded()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        guard vaultID != account.personalVaultID else { throw SharedVaultError.personalVaultCannotBeShared }
        guard sharing.vaults[vaultID] == nil else { return }
        let keys = try requireKeys(since: epoch)
        // Refused for a vault that is already shared and has no ledger here (`ledgerUnavailable`): a second genesis
        // from the account's other device, or from a member's, is never signed (Z41).
        let vaultKey = try await writableVaultKey(vaultID, keys: keys, account: account)
        try await requireWholeLog(vaultID)
        let current = try requireKeys(since: epoch)
        let ledger = try MembershipLedger.create(vaultKey: vaultKey, owner: current.keyset)
        // The marker first: from here on every device of the account that syncs learns the vault is shared, whether
        // or not it ever sees the chain. If it cannot be signed and stored, the vault is not shared.
        try await markShared(vaultID, owner: account.accountID, account: account, epoch: epoch)
        // The vault may hold work already, this device's and the account's other devices'. Its stream index is
        // empty, and a row judged against it would be taken out for every value another device wrote (Z42): the
        // index is built from the log first, by a replay, as for an index refused on load.
        var vault = SharedVault(ledger: ledger)
        vault.needsReconcile = true
        vault.indexRebuilding = true
        sharing.vaults[vaultID] = vault
        try await saveSharedVault(vaultID)
        try await publishSharingObject(SharingObject(ledger.chain[0].record))
    }

    /// Refuses a vault whose sync log has been compacted (`historyCompacted`, review finding Z42). A shared vault
    /// attributes every value through the segment of its writer's stream that carried it. Once segments have been
    /// collected, what they carried survives only in a snapshot, which attributes nothing: an invitee would hold those
    /// items aside for good, and so would any device that replays the log. Asked of the transport (a snapshot listed
    /// there) and of this device's own sync state (a stream it merged through one).
    private func requireWholeLog(_ vaultID: UUID) async throws {
        let names = try await sharingTransport().list(prefix: SyncObjectLocation.vaultPrefix(vaultID))
        let state = try await syncSettings?.state.loadState(vaultID: vaultID)
        guard !names.contains(where: { SyncObjectLocation(name: $0)?.kind == .snapshot }),
            state?.snapshots.isEmpty ?? true, state?.snapshotCoverage.isEmpty ?? true
        else { throw SharedVaultError.historyCompacted(vaultID) }
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
    ///
    /// This is also how another device of an account sets up a shared vault its account already takes part in
    /// (review findings S35, Z41): the owner it must name is the one the account's own marker gives
    /// (`sharedVaultInvitation`), the owner's fingerprint is compared on this device too (pins are per device) unless
    /// the owner is this account, and the key is the one the account's vault directory already gave this device when
    /// no grant is addressed to it (the owner's own genesis key).
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
        let knownOwner = try await knownOwner(of: vaultID, account: account, settings: settings)
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
        // Keys of this vault the account's own vault directory gave this device: signed by the account and a
        // registered device, and opened under the keyset.
        let held = keys.vaultKeys.values.filter { $0.vaultID == vaultID }
        let joined = try incoming.accept(
            membership: records.map(\.contents), grants: grants, as: keys.keyset,
            continuing: sharing.vaults[vaultID]?.ledger, holding: held)
        let adopted = held.contains { $0.key.material === joined.vaultKey.key.material }
        // Before anything is held: a chain whose key ID is another vault's here would displace that vault's key
        // (S38), and one whose key ID is this vault's with other bytes would displace this vault's. Its owner chose
        // the ID, and key IDs are public.
        do {
            try await checkKeyIDFree(joined.vaultKey.key.keyID, for: vaultID)
            if let resident = try requireKeys(since: epoch).vaultKeys[joined.vaultKey.key.keyID],
                !resident.hasSameMaterial(as: joined.vaultKey)
            {
                throw SharedVaultError.keyIDInUse(joined.vaultKey.key.keyID)
            }
        } catch {
            if !adopted { joined.vaultKey.zeroise() }
            throw error
        }
        var vault = sharing.vaults[vaultID] ?? SharedVault(ledger: joined.ledger)
        vault.ledger = joined.ledger
        vault.needsReconcile = true
        vault.index.judgedHead = nil
        if sharing.vaults[vaultID] == nil {
            // A vault this device held without a ledger (its account's other device joined or shared it) may hold
            // rows of its own: the index is built from the log before any of them is judged (Z42).
            vault.indexRebuilding = true
        }
        sharing.vaults[vaultID] = vault
        sharing.unloadable.remove(vaultID)
        try await adoptVaultKey(
            joined.vaultKey, owner: joined.ledger.owner.accountID, account: account, epoch: epoch)
        try await saveSharedVault(vaultID)
        return vaultID
    }

    /// The owner of the vault this device already holds under `vaultID`, or `nil` if it holds none: what an
    /// invitation's owner must equal (S6). From what is authenticated first: the loaded ledger; the account's own
    /// marker for the vault; then, for a vault in the account's directory none of whose keys arrived by grant, the
    /// account itself, since it made the vault (a directory row made by a key that came by grant says nothing of the
    /// kind, which is what refused a member's second device before, Z41). Last, the owner the sharing state names
    /// for a vault whose ledger did not load.
    private func knownOwner(of vaultID: UUID, account: AccountRecord, settings: SharingSettings) async throws
        -> UUID?
    {
        if let ledger = sharing.vaults[vaultID]?.ledger { return ledger.owner.accountID }
        if vaultID == account.personalVaultID { return account.accountID }
        if let marked = sharing.markers[vaultID] { return marked }
        let granted = keys?.vaultKeys.values.contains { $0.vaultID == vaultID && $0.arrivedByGrant } ?? false
        if !granted, try await vaultDirectory(account)[vaultID] != nil { return account.accountID }
        if let saved = try await settings.state.value(.owner, vaultID: vaultID), saved.count == 16 {
            return Self.uuid(saved)
        }
        return nil
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
    func sharedInventory(_ vaultID: UUID) async throws -> [SealedRecordReference] {
        var inventory: [SealedRecordReference] = []
        for kind in [EnvelopeKind.item, .vaultMetadata, .scanStatus] {
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
    func resealSharedVault(_ vaultID: UUID) async throws -> Int {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let ledger = try sharedVault(vaultID).ledger
        guard ledger.writePermission(for: account.accountID).isAllowed else { return 0 }
        let stale = ledger.recordsToReseal(in: try await sharedInventory(vaultID))
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
            plan: plan, leaveRequests: leaveRequests, inventory: try await sharedInventory(vaultID), heldKeyIDs: held)
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
            substitutedMembers: check?.substituted ?? [], unverifiedMembers: check?.unverified ?? [],
            verifiedMembers: check.map { check in
                vault.ledger.state.members.map(\.accountID).filter {
                    $0 != account.accountID && !check.substituted.contains($0) && !check.unverified.contains($0)
                }
            },
            pendingRotation: pending, heldAside: heldAside,
            membersWithDisagreeingDevices: Self.memberAnchors(of: vault.ledger, excluding: account.accountID)
                .filter {
                    sharing.registryDisagreements.contains(
                        MemberRegistryAnchor(accountID: $0.key, signingKey: $0.value))
                }.keys.sorted { $0.uuidString < $1.uuidString },
            requiresNewerVersion: vault.ledger.continuesInLaterFormat)
    }

    // MARK: - A vault this account is no longer in (PRD F4.3, F4.4; review finding Z45)

    /// Whether this account's membership of a shared vault has ended in the chain this device accepts: it left, or
    /// was removed. Nothing takes the vault's records off the device when that happens: they stay, readable under
    /// the keys it held, until the person removes them (`removeLocalCopies`). `false` without a loaded ledger.
    func membershipEnded(_ vaultID: UUID, account: AccountRecord) -> Bool {
        guard let vault = sharing.vaults[vaultID] else { return false }
        return vault.ledger.state.member(account.accountID) == nil
    }

    /// The vaults whose items AutoFill is not given: a shared vault this account is no longer a member of, and one
    /// that is shared with no verified ledger on this device, where membership cannot be told (a device that left a
    /// vault and then lost its sharing state must not start offering it again).
    func vaultsWithheldFromAutoFill() async throws -> Set<UUID> {
        await loadSharedVaultsIfNeeded()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        var withheld: Set<UUID> = []
        for vaultID in try await vaultDirectory(account).keys where vaultID != account.personalVaultID {
            if membershipEnded(vaultID, account: account)
                || isSharedUnavailable(vaultID, keys: keys, personalVaultID: account.personalVaultID)
            {
                withheld.insert(vaultID)
            }
        }
        return withheld
    }

    /// Removes from this device what it holds of a shared vault this account is no longer a member of: every item,
    /// its synced scan results, and the versions held aside from it. The person's choice, made on the vault's
    /// screen; nothing does it for them, and until they do the copies stay (which the screens say). Not a deletion:
    /// nothing is recorded to publish, no other member's copy is touched, and the ledger is kept (S26). Refused while
    /// this account is still a member (it leaves first) and for a vault with no ledger here. Returns how many items
    /// went.
    @discardableResult
    public func removeLocalCopies(ofSharedVault vaultID: UUID) async throws -> Int {
        _ = try sharingSettings()
        _ = try requireKeys()
        await loadSharedVaultsIfNeeded()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        guard sharing.vaults[vaultID] != nil else {
            throw isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID)
                ? SharedVaultError.ledgerUnavailable(vaultID) : SharedVaultError.notShared(vaultID)
        }
        guard membershipEnded(vaultID, account: account) else { throw SharedVaultError.stillAMember(vaultID) }
        let items = try await store.records(in: vaultID, kind: .item)
        let scans = try await store.records(in: vaultID, kind: .scanStatus)
        _ = try requireKeys()
        // The engine's store, not the session's writer: these are not deletions to publish.
        try await store.commit(
            StoreChange(
                deletions: scans.map(\.key),
                conditionalDeletions: Dictionary(uniqueKeysWithValues: items.map { ($0.key, $0.version) })))
        if let state = syncSettings?.state {
            try await state.discardQuarantined(try await state.quarantined(vaultID: vaultID), vaultID: vaultID)
        }
        try? await reconcileHygiene()
        return items.count
    }

    // MARK: - Hooks the rest of the session calls

    /// The key new records of a shared vault are sealed under: the one the membership chain names, if this device
    /// holds it (docs/02-architecture.md §7.7, the seam left for this). `nil` for a vault that is not shared.
    ///
    /// A vault that is shared with no verified ledger loaded here has no current key at all (`.some(nil)`): never
    /// the lowest key ID this device holds, which after a rotation may be the key a removed member kept (Z41). With
    /// no current key nothing is sealed, signed or published for it, and its engine only downloads.
    func sharedCurrentKey(_ vaultID: UUID, keys: UnlockedKeys, personalVaultID: UUID?) -> VaultKey?? {
        guard let vault = sharing.vaults[vaultID] else {
            return isMarkedShared(vaultID, keys: keys, personalVaultID: personalVaultID) ? .some(nil) : nil
        }
        let key = keys.vaultKeys[vault.ledger.state.vaultKeyID]
        return .some(key?.vaultID == vaultID ? key : nil)
    }

    /// The client's half of F4.5: a write the person makes to a shared vault needs `writePermission`. A shared vault
    /// with no ledger loaded here takes no write at all (`ledgerUnavailable`).
    func checkSharedWrite(_ vaultID: UUID, account: AccountRecord) async throws {
        await loadSharedVaultsIfNeeded()
        guard let vault = sharing.vaults[vaultID] else {
            if isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) {
                throw SharedVaultError.ledgerUnavailable(vaultID)
            }
            return
        }
        if case .refused(let refusal) = vault.ledger.writePermission(for: account.accountID) {
            throw SharedVaultError.writeRefused(refusal)
        }
    }

    /// A shared vault is deleted through its chain, by its owner (§8.1); a member leaves instead. One with no ledger
    /// loaded here is not deleted from this device at all: it cannot tell whose the vault is, and the "delete vault"
    /// of a member's other device would otherwise publish tombstones for every item in it (Z41).
    func checkSharedDeletion(_ vaultID: UUID, account: AccountRecord) async throws {
        await loadSharedVaultsIfNeeded()
        guard let vault = sharing.vaults[vaultID] else {
            if isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) {
                throw SharedVaultError.ledgerUnavailable(vaultID)
            }
            return
        }
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
