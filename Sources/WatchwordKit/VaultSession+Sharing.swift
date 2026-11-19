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
    /// The keys of the vault that arrived by grant and that this device has seen the ledger hand to this account
    /// (`SharedKeyProvenance`, saved signed): the only ones of that class made resident for the vault (Z59).
    var verifiedKeys: Set<UUID> = []
    /// How many replays were asked for (`requestReplay`): a pass settles the head it judged against only if none was
    /// asked for while it ran (review finding Z120).
    var replayRequests: UInt64 = 0
    /// What this device's own take-out held aside before it was published (`OwnTakenOutRow`, saved signed in a row of
    /// its own, Z54 and Z121), and whether that is all of it: not when the row did not load, until the quarantine
    /// shows that nothing of this device's can be missing from it.
    var ownTakenOut: Set<VersionKey> = []
    var ownTakenOutComplete = true
}

/// An account's device registry as one vault's chain anchors it: the account, and the signing key that chain lists
/// for it (review finding S39). Two vaults may list different keys under one account ID; each judges by its own.
struct MemberRegistryAnchor: Hashable, Sendable {
    var accountID: UUID
    var signingKey: [UInt8]
}

/// What this device has anchored of another account's device registry (review finding Z6): the one genesis entry it
/// took, the credential entry (password change) it first anchored, and the one it follows now. From there the
/// registry moves only forward, along credential entries that descend from `credential` one after another; it never
/// crosses to a branch that leaves the chain before `base`, whatever generation that branch reaches, and a branch that
/// leaves it at `base` or after competes with the one followed (Z12).
struct MemberRegistryPin: Hashable, Sendable {
    var genesis: ObjectDigest
    /// The credential entry this device first anchored: a walk forward never moves it (Z12).
    var base: ObjectDigest
    var credential: ObjectDigest
    /// A digest of the disagreeing entries the person last settled: they are not reported again, and anything new is.
    /// Read from pins saved by an earlier version, which settled with a code (removed, review finding Z11); nothing
    /// in this version sets it.
    var settled: ObjectDigest?

    init(genesis: ObjectDigest, base: ObjectDigest? = nil, credential: ObjectDigest, settled: ObjectDigest?) {
        self.genesis = genesis
        self.base = base ?? credential
        self.credential = credential
        self.settled = settled
    }
}

/// One vault's saved pins. `"WWMD" ‖ version u8 = 2 ‖ own account 16 ‖ vault 16 ‖ count u16 ‖ { account 16 ‖
/// signing key 32 ‖ genesis 32 ‖ base 32 ‖ credential 32 ‖ settled flag u8 ‖ settled 32? } ‖ signature 64`, in the
/// order of account then signing key. Version 1, written before `base` existed, has no base and is read with the base
/// at the credential followed (Z12). Local state like the saved ledger and the stream index: signed by this account's own key
/// under `SignatureDomain.membership` with its own magic, and refused whole if it does not verify, so a file edited on
/// the device (A8) can make this device anchor again from what the transport shows, and never choose its anchor.
enum MemberRegistryPins {
    static let magic: [UInt8] = Array("WWMD".utf8)
    static let formatVersion: UInt8 = 2
    static let firstFormatVersion: UInt8 = 1
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
            out += SharedBytes.bytes(anchor.accountID) + anchor.signingKey + pin.genesis.bytes + pin.base.bytes
            out += pin.credential.bytes
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
        guard reader.read(4) == magic, let version = reader.read(1)?.first,
            version == formatVersion || version == firstFormatVersion, reader.uuid() == account.accountID,
            reader.uuid() == vaultID, let count = reader.uint16(), Int(count) <= maximumPins
        else { return nil }
        var pins: [MemberRegistryAnchor: MemberRegistryPin] = [:]
        for _ in 0..<count {
            guard let member = reader.uuid(), let signingKey = reader.read(32),
                let genesis = reader.read(32).flatMap(ObjectDigest.init(bytes:))
            else { return nil }
            var base: ObjectDigest?
            if version == formatVersion {
                guard let read = reader.read(32).flatMap(ObjectDigest.init(bytes:)) else { return nil }
                base = read
            }
            guard let credential = reader.read(32).flatMap(ObjectDigest.init(bytes:)), let flag = reader.read(1)
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
                genesis: genesis, base: base, credential: credential, settled: settled)
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
    /// Vaults for which the account's markers name more than one owner: its devices disagree about whose the vault
    /// is. A device with no ledger for such a vault accepts no invitation to it and offers none (Z48).
    var markerConflicts: Set<UUID> = []
    /// The marker objects of the account's vault directory this session has fetched and compared, by name.
    var examinedMarkers: Set<String> = []
    /// The vaults the account's vault directory named, as this session last listed it (any object under a vault's
    /// prefix, fetched or not); `nil` until it has been listed (Z59).
    var directoryVaults: Set<UUID>?
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
    /// made it holds that member's account key. Nothing a contested device signs counts here meanwhile. Nothing in
    /// this version settles it (review finding Z11): that is for the vault sharing code session of ADR 0010.
    public let membersWithDisagreeingDevices: [UUID]
    /// The vault has gone on in a format this version cannot read (`MembershipLedger.continuesInLaterFormat`,
    /// docs/02-architecture.md §8.9): it is read-only on this device, which proposes, plans, publishes and seals
    /// nothing there, and the person is told to update the app.
    public let requiresNewerVersion: Bool
    /// The account's own devices disagree about whose this vault is (review finding Z59): another of its devices
    /// joined a chain with another owner, or this one did. The vault is held closed on every device of the account,
    /// this one included, and nothing in this version ends that: the person is told, can read and copy the items,
    /// and shares a new vault.
    public let ownerDisputed: Bool
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
    /// This device's ID does not commit to its account (review finding Z162): nothing of this device's is published in
    /// the vault, where no other device would receive it, and nothing is written there until the device is enrolled
    /// again as a new device (`SharedVaultError.deviceIDDoesNotCommit`).
    public var deviceIDDoesNotCommit = false
    /// This device's key could not be read this sync (a Keychain error, not a key that is missing or does not
    /// commit): nothing of this device's was published in the vault, and the next sync tries again
    /// (`SharedVaultError.deviceKeyUnreadable`).
    public var deviceKeyUnreadable = false
    /// The account whose keys signed the object that holds this device's next number in the vault's log, where the
    /// engine reported `ownStreamConflict` (round 6's L2): a member who listed a device under this device's ID in
    /// their own registry (S33) signed it. It verifies nowhere (Z157) and costs nothing but this stream, which waits
    /// there until the object is removed; while it waits, this device publishes no vault's deletions (Z44). Named so
    /// that the person knows whom to ask, or to remove. `nil` for junk, or an object no listed account signed.
    public var ownStreamSquattedBy: UUID?

    public init() {}
}

extension VaultSession {
    // MARK: - Configuration and contacts

    /// Turns sharing on for this session. Sharing travels over the sync transport, so sync must be configured too.
    ///
    /// On an unlocked session, the chain rows of a restore's earlier device IDs are then filled in from the vaults'
    /// states (`backfillRestoredChains`, review of round 17, Z222): a move made before sharing was configured wrote
    /// none, and the hold for what it left would end with the next damage to a state. Locked, the next unlock does it.
    /// First a restore's move that waited for sharing is made (`moveAwaitsSharing`, review of round 18, Z229), so
    /// that it reads the chain rows it needs, and the backfill reads the state it saves; one that fails is made again
    /// at the next unlock or sync, as any move is (Z181).
    public func configureSharing(_ settings: SharingSettings) async {
        let epoch = lockEpoch
        sharing.settings = settings
        sharing.loaded = false
        guard keys != nil, var account = try? await loadAccount() else { return }
        if account.migration != nil, epoch == lockEpoch {
            // As at the unlock: the markers first, or every vault but the Personal one is held closed (Z190).
            await loadSharedMarkersIfNeeded()
            try? await completeDeviceMigration(account: account)
            guard epoch == lockEpoch, let moved = try? await loadAccount() else { return }
            account = moved
        }
        await backfillRestoredChains(account: account, since: epoch)
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
    /// §8.3, §8.6). Needs the keyset (the account's own bundle anchors the checks). A ledger that does not load (its
    /// owner row or the owner's pin is gone, it does not restore, or the read fails) leaves no entry here; whether
    /// the vault is then held closed is not this file's to say but the marker's and the key's
    /// (`isMarkedShared`, review finding Z41), which nothing in the sharing state can add to or take from: rows
    /// planted there close no private vault (Z50). After a read that failed the load is tried again by the next
    /// caller.
    func loadSharedVaultsIfNeeded() async {
        await loadSharedMarkersIfNeeded()
        guard !sharing.loaded, let settings = sharing.settings, keys != nil else { return }
        let epoch = lockEpoch
        guard let ids = try? await settings.state.sharedVaultIDs() else { return }
        var loaded: [UUID: SharedVault] = [:]
        var pins: [MemberRegistryAnchor: MemberRegistryPin] = [:]
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
                complete = false
                continue
            }
            guard let ownerBytes, ownerBytes.count == 16, let saved else {
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
                    complete = false
                    continue
                }
            }
            guard let owner,
                let ledger = try? MembershipLedger.restore(saved, vaultID: vaultID, owner: owner, account: bundle)
            else {
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
            // The keys this device saw the ledger hand to this account (Z59). None, if the row does not verify: the
            // next sync shows each again from its grant.
            // What this device's own take-out held aside (Z121): a row that is missing or does not verify is not "none",
            // and the deletion gate falls back to the rule before Z54 until the quarantine says otherwise.
            if let bytes = try? await settings.state.value(.ownTakenOut, vaultID: vaultID),
                let saved = OwnTakenOutRow.parse(bytes, account: bundle, vaultID: vaultID)
            {
                vault.ownTakenOut = saved.versions
                vault.ownTakenOutComplete = saved.complete
            } else {
                vault.ownTakenOutComplete = false
            }
            if let bytes = try? await settings.state.value(.vaultKeys, vaultID: vaultID),
                let verified = SharedKeyProvenance.parse(
                    bytes, owner: ledger.owner.accountID, account: bundle, vaultID: vaultID)
            {
                vault.verifiedKeys = verified
            }
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
        sharing.loaded = complete
        // A vault with a ledger uses only the keys that ledger hands this account (Z59).
        withholdUnvouchedKeys()
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
        let vaultKeys = try SharedKeyProvenance.signed(
            vault.verifiedKeys, owner: vault.ledger.owner.accountID, account: account.accountID, vaultID: vaultID,
            keyset: keys.keyset)
        let ownTakenOut = try OwnTakenOutRow.signed(
            vault.ownTakenOut, complete: vault.ownTakenOutComplete, account: account.accountID, vaultID: vaultID,
            keyset: keys.keyset)
        try await settings.state.setValue(
            SharedBytes.bytes(vault.ledger.owner.accountID), for: .owner, vaultID: vaultID)
        try await settings.state.setValue(ledger, for: .ledger, vaultID: vaultID)
        try await settings.state.setValue(
            SharedBytes.encodeRecords(vault.proposals), for: .proposals, vaultID: vaultID)
        try await settings.state.setValue(vault.plan, for: .plan, vaultID: vaultID)
        try await settings.state.setValue(index, for: .streamIndex, vaultID: vaultID)
        try await settings.state.setValue(memberDevices, for: .memberDevices, vaultID: vaultID)
        try await settings.state.setValue(vaultKeys, for: .vaultKeys, vaultID: vaultID)
        try await settings.state.setValue(ownTakenOut, for: .ownTakenOut, vaultID: vaultID)
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
        try await listSharingObjectsAndNames(prefix: prefix, maximumLength: maximumLength, skipping: skip).objects
    }

    /// `listSharingObjects`, with every name the store listed under the prefix, fetched or not.
    func listSharingObjectsAndNames(
        prefix: String, maximumLength: Int, skipping skip: (String) -> Bool = { _ in false }
    ) async throws -> (objects: [(name: String, contents: [UInt8])], names: Set<String>) {
        let transport = try sharingTransport()
        let names = Set(try await transport.list(prefix: prefix))
        var objects: [(name: String, contents: [UInt8])] = []
        for name in names.sorted() where !skip(name) {
            guard let contents = try? await transport.fetch(name, maximumLength: maximumLength) else { continue }
            objects.append((name, contents))
        }
        return (objects, names)
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
        let listing = try await listSharingObjectsAndNames(
            prefix: SharingObjectLocation.membershipPrefix(vaultID), maximumLength: MembershipRecord.maximumLength
        ) { name in
            guard let location = SharingObjectLocation(name: name), location.vaultID == vaultID else { return true }
            return before.ledger.holds(location) || before.refusedNames.contains(name)
        }
        let objects = listing.objects
        let offered = objects.filter { SharingObjectLocation(name: $0.name)?.isName(of: $0.contents) == true }
        guard var vault = sharing.vaults[vaultID] else { throw SharedVaultError.notShared(vaultID) }
        // The owner's device puts its genesis record back while the store does not list it: the one call that
        // published it may have failed, or been cut short, and nobody can join a chain with no first record (Z50).
        let genesis = SharingObject(vault.ledger.chain[0].record)
        if keys != nil, vault.ledger.owner.accountID == account?.accountID, !listing.names.contains(genesis.name) {
            try await publishSharingObject(genesis)
        }
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
        try requireOwnerUndisputed(vaultID)
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
        // Opened from a grant this ledger entitles this account to: the ledger's key (Z59). Listed before it is made
        // resident, and not at all if it is refused.
        let keyID = key.key.keyID
        let listed = sharing.vaults[vaultID]?.verifiedKeys.insert(keyID).inserted ?? false
        do {
            try await adoptVaultKey(key, owner: ledger.owner.accountID, account: account, epoch: epoch)
        } catch {
            if listed { sharing.vaults[vaultID]?.verifiedKeys.remove(keyID) }
            throw error
        }
        // Records sealed under this key, held aside while it was missing, can be judged now; written down in the
        // index too, so that a restart before the replay still replays (S41).
        requestReplay(vaultID)
        return true
    }

    /// Asks for the vault's log to be replayed with the judge: in this sync, and, through the saved index, in the
    /// next one if this one does not get that far (review finding S41).
    func requestReplay(_ vaultID: UUID) {
        guard sharing.vaults[vaultID] != nil else { return }
        // Counted, so that a pass that was running when this was asked does not settle it away (Z120).
        sharing.vaults[vaultID]?.replayRequests &+= 1
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
            let heldWrap = try await store.record(RecordKey(recordID: vaultKey.key.keyID, kind: .vaultKeyWrap))
            wrapHeld = heldWrap != nil
            directoryHeld = try await store.record(RecordKey(recordID: vaultID, kind: .vaultDirectory)) != nil
            keys = try requireKeys(since: epoch)
            // A wrap of that ID held and not resident (the account's directory brought it, and no ledger here has
            // vouched for it, Z59) must hold the same bytes too: a grant's key never stands in for another key that
            // the store keeps under the ID, and the wrap is what the next unlock reads.
            if let heldWrap,
                let stored = try? VaultKey.unwrap(
                    heldWrap.envelope, vaultID: vaultID, keyID: vaultKey.key.keyID, with: keys.keyset)
            {
                let same = stored.hasSameMaterial(as: vaultKey)
                stored.zeroise()
                if !same { throw SharedVaultError.keyIDInUse(vaultKey.key.keyID) }
            }
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
        // Its items' values would be stamped by a device no member counts, and held aside everywhere (Z162).
        try await requireCommittingDevice(account)
        if let shared = sharing.vaults[vaultID] {
            try requireOwnerUndisputed(vaultID)
            // Shared already. What an interruption may have left undone is done again: the state saved, and the
            // owner's genesis record put where the others look for it (Z50).
            try await saveSharedVault(vaultID)
            if shared.ledger.owner.accountID == account.accountID {
                try await publishSharedMarker(vaultID, owner: account.accountID, account: account, epoch: epoch)
                try await publishSharingObject(SharingObject(shared.ledger.chain[0].record))
            }
            return
        }
        let keys = try requireKeys(since: epoch)
        let vaultKey: VaultKey
        var listed: [[UInt8]] = []
        if isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) {
            // Marked, with no ledger here. If the only thing that says so is this account's own marker naming this
            // account, and no key of the vault came by grant, the vault is this account's and its sharing was cut
            // short after the marker (a lock, the process ending) or happened on another of its devices: it is
            // finished from here (Z50), and the chain already on the transport is taken up if there is one (Z122).
            // Anything else is a vault somebody else's chain governs, and no second genesis is signed for it (Z41).
            guard sharing.markers[vaultID] == account.accountID, !sharing.markerConflicts.contains(vaultID),
                !keys.vaultKeys.values.contains(where: { $0.vaultID == vaultID && $0.arrivedByGrant })
            else { throw SharedVaultError.ledgerUnavailable(vaultID) }
            guard let entry = try await vaultDirectory(account)[vaultID] else {
                throw VaultError.unknownVault(vaultID)
            }
            if entry.isDeleted { throw VaultError.vaultDeleted(vaultID) }
            guard
                let keyID = Self.currentKeyID(
                    for: vaultID, among: Array(try requireKeys(since: epoch).vaultKeys.values), personal: account),
                let own = try requireKeys(since: epoch).vaultKeys[keyID]
            else { throw VaultError.unknownVault(vaultID) }
            vaultKey = own
            listed = try await listSharingObjects(
                prefix: SharingObjectLocation.membershipPrefix(vaultID), maximumLength: MembershipRecord.maximumLength
            ).filter { SharingObjectLocation(name: $0.name)?.isName(of: $0.contents) == true }.map(\.contents)
        } else {
            vaultKey = try await writableVaultKey(vaultID, keys: keys, account: account)
            // Before anything says the vault is shared: a refusal here leaves it exactly as it was.
            try await requireWholeLog(vaultID)
        }
        let current = try requireKeys(since: epoch)
        // A genesis record of this account's for the vault already on the transport (another of its devices shared it,
        // or this one did and lost its ledger) is the chain's first record, with whatever was built on it: taken up,
        // verified back to this account's own bundle, never signed again. A second one is a second root wherever
        // signing is randomised (CryptoKit's Ed25519), and the fork rule then sets an invitee's addition on one of
        // them aside (review finding Z122).
        let ledger: MembershipLedger
        if !listed.isEmpty,
            let joined = try? MembershipLedger.join(
                vaultID: vaultID, owner: try verifiedContacts(try sharingSettings()).myself, candidates: listed
            ).ledger
        {
            ledger = joined
        } else {
            ledger = try MembershipLedger.create(vaultKey: vaultKey, owner: current.keyset)
        }
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
        // On the transport before the chain is: the account's other devices stop compacting the vault's log when
        // they see it (Z56). A failure here leaves a share that `shareVault` finishes (Z50).
        try await publishSharedMarker(vaultID, owner: account.accountID, account: account, epoch: epoch)
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
        try requireOwnerUndisputed(vaultID)
        let keys = try requireKeys(since: epoch)
        let ledger = try sharedVault(vaultID).ledger
        guard let vaultKey = currentVaultKey(vaultID, keys: keys, account: account) else {
            throw SharedVaultError.awaitingKey(ledger.state.vaultKeyID)
        }
        if ledger.isOwnersAlone {
            // The first person let in. The check `shareVault` made is made again here, because it was made before
            // any other device of the account could have seen the marker: one that had not went on running the
            // vault as its own and may have compacted the log since (Z56). The marker is on the transport first, so
            // that from here on none does.
            if ledger.owner.accountID == account.accountID {
                try await publishSharedMarker(vaultID, owner: account.accountID, account: account, epoch: epoch)
            }
            try await requireWholeLog(vaultID)
        }
        // A lock during those requests wins: nothing is wrapped with keys that have been wiped.
        let current = try requireKeys(since: epoch)
        let package = try invitation.issue(ledger: ledger, vaultKey: vaultKey, signedBy: current.keyset)
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
        // A device no member counts takes no part (Z162) until it is enrolled again as a new device, whose ID commits.
        try await requireCommittingDevice(account)
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
        // The key the chain was joined with is the ledger's: from a grant it entitles this account to, or this
        // account's own genesis key (Z59). Other keys of the vault this device holds are not used under this ledger
        // until a grant shows each to be its own.
        vault.verifiedKeys.insert(joined.vaultKey.key.keyID)
        sharing.vaults[vaultID] = vault
        withholdUnvouchedKeys()
        try await adoptVaultKey(
            joined.vaultKey, owner: joined.ledger.owner.accountID, account: account, epoch: epoch)
        _ = try? await admitVaultKeys(vaultID)
        try await saveSharedVault(vaultID)
        return vaultID
    }

    /// The owner of the vault this device already holds under `vaultID`, or `nil` if it holds none: what an
    /// invitation's owner must equal (S6). From what is authenticated: the loaded ledger; then the account's own
    /// marker for the vault; then, for a vault in the account's directory none of whose keys arrived by grant, the
    /// account itself, since it made the vault (a directory row made by a key that came by grant says nothing of the
    /// kind, which is what refused a member's second device before, Z41).
    ///
    /// A vault this device holds a **granted** key of has an owner whether or not this device can name them. With no
    /// ledger and no marker it cannot, and then no invitation is accepted, whoever it names (`ownerUnknown`): the
    /// store withholding the marker would otherwise let anyone the person has reason to verify stand in as the
    /// vault's owner with a chain and a key of their own (review finding Z48). Two markers of the account naming
    /// different owners (`markerConflicts`) say that its devices disagree, and nothing is accepted on either. The
    /// owner the sharing state names is asked last, only for a vault this device holds no key of: that row is not
    /// signed.
    ///
    /// `nil`, which lets an invitation name anyone, is answered only once this session has listed the account's vault
    /// directory and found nothing of the vault there (review finding Z59): a device that has not synced yet, or one
    /// whose listing names the vault while its keys and marker have not reached it, does not know that nobody owns
    /// it. A store that withholds the vault's whole directory (A1) still gets `nil`; what then keeps the account's
    /// real items from the chain the device joins is `withholdUnvouchedKeys` and the dispute (`isOwnerDisputed`).
    private func knownOwner(of vaultID: UUID, account: AccountRecord, settings: SharingSettings) async throws
        -> UUID?
    {
        if let ledger = sharing.vaults[vaultID]?.ledger {
            try requireOwnerUndisputed(vaultID)
            return ledger.owner.accountID
        }
        if vaultID == account.personalVaultID { return account.accountID }
        guard !sharing.markerConflicts.contains(vaultID) else {
            throw SharingError.vaultOwnerConflict(vaultID: vaultID)
        }
        if let marked = sharing.markers[vaultID] { return marked }
        let held = keys?.vaultKeys.values.filter { $0.vaultID == vaultID } ?? []
        if held.contains(where: \.arrivedByGrant) { throw SharedVaultError.ownerUnknown(vaultID) }
        if try await vaultDirectory(account)[vaultID] != nil { return account.accountID }
        if held.isEmpty, let saved = try await settings.state.value(.owner, vaultID: vaultID), saved.count == 16 {
            return Self.uuid(saved)
        }
        guard let listed = sharing.directoryVaults, !listed.contains(vaultID) else {
            throw SharedVaultError.ownerUnknown(vaultID)
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
        try requireOwnerUndisputed(vaultID)
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
        // Nor while the account's devices disagree about whose the vault is (Z59).
        try requireOwnerUndisputed(vaultID)
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
        guard ledger.writePermission(for: account.accountID).isAllowed, !isOwnerDisputed(vaultID) else { return 0 }
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
            requiresNewerVersion: vault.ledger.continuesInLaterFormat, ownerDisputed: isOwnerDisputed(vaultID))
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
                || isOwnerDisputed(vaultID)
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
    ///
    /// Not everything here is a copy. A change made on this device that never reached the others (written and not
    /// published, or put aside when the account's permission ended) exists nowhere else, and removing it is a discard
    /// only the person can make (PRD F7.6; review finding Z57): the call is refused (`unsharedWork`) unless
    /// `acknowledged` is at least the number of such changes, which is the number the person was shown
    /// (`unsharedWork(inSharedVault:)`). A removal that later loses a fork gives the membership back, and those
    /// changes would have gone out then.
    @discardableResult
    public func removeLocalCopies(ofSharedVault vaultID: UUID, discardingUnshared acknowledged: Int = 0)
        async throws -> Int
    {
        _ = try sharingSettings()
        _ = try requireKeys()
        await loadSharedVaultsIfNeeded()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        guard sharing.vaults[vaultID] != nil else {
            throw isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID)
                ? SharedVaultError.ledgerUnavailable(vaultID) : SharedVaultError.notShared(vaultID)
        }
        guard membershipEnded(vaultID, account: account) else { throw SharedVaultError.stillAMember(vaultID) }
        let unshared = await unsharedWorkCount(vaultID, account: account)
        guard unshared <= acknowledged else { throw SharedVaultError.unsharedWork(vaultID, unshared) }
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

    /// How many changes this device made in a shared vault that nobody else has: items whose latest version it
    /// wrote and has not published, and versions of its own that were put aside before they were (review finding
    /// Z57). What `removeLocalCopies` would discard for good, for the screen that offers it to say.
    public func unsharedWork(inSharedVault vaultID: UUID) async throws -> Int {
        _ = try requireKeys()
        await loadSharedVaultsIfNeeded()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        return await unsharedWorkCount(vaultID, account: account)
    }

    func unsharedWorkCount(_ vaultID: UUID, account: AccountRecord) async -> Int {
        guard let syncState, let base = syncSettings?.state else { return 0 }
        // What was published, as this device's signed sync state has it (Z20), and what the sync layer knows of.
        let state = try? await syncState.loadState(vaultID: vaultID)
        let published = state?.published ?? [:]
        let known = state?.known ?? [:]
        var count = 0
        for row in (try? await store.records(in: vaultID, kind: .item)) ?? [] where row.deviceID == account.deviceID {
            // A change of this device's that nobody else has is an edit it made and never published: the latest of
            // its own edits the item contains (its clock's entry for this device) above every version of the record
            // it published. Not merely a row it sealed: the result of a merge is its row too, in a vault it only
            // read, and holds nothing the others lack (review finding Z123). One that does not open here is counted.
            let own: UInt64
            if let keys, let item = try? openItem(row, keys: keys) {
                own = ItemMerge.effectiveClock(item, origin: Self.origin(row)).entries[account.deviceID] ?? 0
            } else {
                own = .max
            }
            if own > (published[row.key]?.version ?? 0) { count += 1 }
        }
        // What this device's own take-out put aside (Z54), never an entry's own word for whose it is; while that set's
        // row has not loaded, every held-aside entry naming this device that the sync state does not know (Z121).
        let vault = sharing.vaults[vaultID]
        let takenOut = vault?.ownTakenOut ?? []
        let complete = vault?.ownTakenOutComplete ?? true
        for entry in (try? await base.quarantined(vaultID: vaultID)) ?? []
        where entry.kind == .item && !entry.isDeletion && entry.device == account.deviceID {
            let version = VersionKey(recordID: entry.recordID, kind: entry.kind.rawValue, version: entry.version)
            if takenOut.contains(version) || (!complete && known[entry.key] == nil) { count += 1 }
        }
        return count
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
        // Held closed while the account's devices disagree about whose it is, ledger or not (Z59).
        if isOwnerDisputed(vaultID) { return .some(nil) }
        let key = keys.vaultKeys[vault.ledger.state.vaultKeyID]
        return .some(key?.vaultID == vaultID ? key : nil)
    }

    /// Whether this device's ID commits to its account under the key this installation holds for it
    /// (`DeviceIdentifier`, review findings Z157 and Z162). Every device of a shared vault counts only the devices whose
    /// IDs commit, so a device whose ID does not (an account made before IDs committed, a device an older build
    /// approved) writes nothing there that anyone receives. `false` with no key held: such a device registers again,
    /// as a new device, at its next unlock. Throws what the key store threw (a Keychain that could not be read just
    /// now, review of round 7): that says nothing about the ID, and every caller fails closed on it without calling the
    /// device one whose ID does not commit (`SharedVaultError.deviceKeyUnreadable`).
    func thisDeviceCommits(_ account: AccountRecord) async throws -> Bool {
        if playsModifiedClient { return true }
        guard let key = try await deviceKeys.publicKey(accountID: account.accountID, deviceID: account.deviceID)
        else { return false }
        return DeviceIdentifier.commits(account.deviceID, to: account.accountID, key: key)
    }

    /// Refuses what a device whose ID does not commit would do in a shared vault (`deviceIDDoesNotCommit`, Z162): write,
    /// share a vault, accept an invitation. Nothing it published there would be received, and its rows would count as
    /// published, so the original of a move into such a vault would be deleted with the copy on this device alone
    /// (PRD F7.6). A device of an account from before IDs committed takes part once it is enrolled again as a new device
    /// (an owner decision, docs/06-adversarial-review.md Z162).
    func requireCommittingDevice(_ account: AccountRecord) async throws {
        let commits: Bool
        do {
            commits = try await thisDeviceCommits(account)
        } catch {
            throw SharedVaultError.deviceKeyUnreadable
        }
        guard commits else { throw SharedVaultError.deviceIDDoesNotCommit }
    }

    /// For `playsModifiedClient`; `false` makes it the honest client again (a build that refuses, after one that did
    /// not).
    package func playModifiedClient(_ playing: Bool = true) {
        playsModifiedClient = playing
    }

    /// The client's half of F4.5: a write the person makes to a shared vault needs `writePermission`. A shared vault
    /// with no ledger loaded here takes no write at all (`ledgerUnavailable`), and none from a device whose ID does
    /// not commit to its account (`deviceIDDoesNotCommit`, Z162).
    func checkSharedWrite(_ vaultID: UUID, account: AccountRecord) async throws {
        await loadSharedVaultsIfNeeded()
        guard let vault = sharing.vaults[vaultID] else {
            if isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) {
                throw SharedVaultError.ledgerUnavailable(vaultID)
            }
            return
        }
        try requireOwnerUndisputed(vaultID)
        try await requireCommittingDevice(account)
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
        try requireOwnerUndisputed(vaultID)
        try await requireCommittingDevice(account)
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
