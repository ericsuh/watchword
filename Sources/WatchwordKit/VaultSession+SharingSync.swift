import Foundation
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync

// The sync pass of a shared vault (docs/02-architecture.md §8.8) and the write cut over sync's own objects (§8.7,
// review finding S28). `syncAll` calls the three hooks at the top of this file around each shared vault's log; the
// sync adapter calls the judge below from inside `SyncEngine`.
extension VaultSession {
    // MARK: - Around the logs

    /// Steps 1 to 4 of §8.8 for every shared vault, before any vault's log is merged: membership, member keys,
    /// this device's proposals, the current key; then the other members' device registries, and, if the head
    /// changed since the vault's items were last judged, every local version that no longer counts taken out and
    /// held aside, and the log replayed. While locked only the membership is ingested.
    func syncSharedVaultsBeforeLogs(account: AccountRecord) async -> [UUID: SharedVaultSyncReport] {
        guard sharing.settings != nil, syncSettings != nil else { return [:] }
        await loadSharedVaultsIfNeeded()
        var reports: [UUID: SharedVaultSyncReport] = [:]
        for vaultID in sharing.vaults.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            var report = SharedVaultSyncReport()
            do {
                let before = try sharedVault(vaultID).ledger.state.hash
                report.recordsRejected = try await ingestMembership(vaultID).rejected.count
                if keys != nil {
                    if try await settleProposals(in: vaultID) { try await ingestMembership(vaultID) }
                    report.keyReceived = try await fetchCurrentKey(vaultID)
                }
                report.membershipChanged = try sharedVault(vaultID).ledger.state.hash != before
            } catch {
                report.failure = String(describing: error)
            }
            reports[vaultID] = report
        }
        await refreshMemberRegistries(account: account)
        guard keys != nil else { return reports }
        for vaultID in sharing.vaults.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            do {
                try await takeOutWhatNoLongerCounts(vaultID)
                try await saveSharedVault(vaultID)
            } catch {
                reports[vaultID, default: SharedVaultSyncReport()].failure = String(describing: error)
            }
        }
        return reports
    }

    /// How the engine of `vaultID` runs: a shared vault gets the judge and keeps its whole log (no snapshots, no
    /// collection: the departing account's segments are what a cut is judged against, §8.8 "a departed account's
    /// log"), publishes only while this account may write, and replays its log when what counts has changed.
    func sharedEngineOptions(_ vaultID: UUID, base: SyncConfiguration, account: AccountRecord)
        -> (configuration: SyncConfiguration, judge: (any WriteJudge)?, publishing: Bool, reconcile: Bool)
    {
        guard let vault = sharing.vaults[vaultID] else { return (base, nil, true, false) }
        var configuration = base
        configuration.maintainsLog = false
        return (
            configuration, VaultSyncAdapter(session: self),
            vault.ledger.writePermission(for: account.accountID).isAllowed, vault.needsReconcile
        )
    }

    /// After a shared vault's engine ran: a replay that finished settles the head it judged against.
    func sharedEngineDidRun(_ vaultID: UUID, reconciled: Bool, report: SyncReport) {
        guard var vault = sharing.vaults[vaultID] else { return }
        if reconciled, !report.deferredUntilUnlock, !report.transportUnavailable {
            vault.needsReconcile = false
            vault.index.judgedHead = vault.ledger.state.hash.bytes
            vault.indexChanged = true
            sharing.vaults[vaultID] = vault
        }
    }

    /// Shared vaults whose log must be replayed again in this sync: something learnt while merging (a key, a
    /// segment inside a cut) changes what counts.
    func sharedVaultsNeedingReplay() -> [UUID] {
        sharing.vaults.filter(\.value.needsReconcile).keys.sorted { $0.uuidString < $1.uuidString }
    }

    /// Step 6 of §8.8, after the logs, unlocked: continue a saved plan, plan the removals that are owed and this
    /// account may sign, turn leave requests into rotations as an administrator, and seal again what the ledger
    /// lists. Then save.
    func syncSharedVaultsAfterLogs(account: AccountRecord, reports: inout [UUID: SharedVaultSyncReport]) async {
        guard keys != nil, sharing.settings != nil else { return }
        for vaultID in sharing.vaults.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            var report = reports[vaultID] ?? SharedVaultSyncReport()
            do {
                if try sharedVault(vaultID).plan != nil {
                    report.rotation = try await resumeRotation(in: vaultID)
                }
                let ledger = try sharedVault(vaultID).ledger
                for owed in ledger.owedRemovals
                where try sharedVault(vaultID).plan == nil
                    && ledger.mayRemove(owed.accountID, signer: account.accountID)
                {
                    guard (try? await planRotation(owed.reason, in: vaultID)) != nil else { continue }
                    report.rotation = try await resumeRotation(in: vaultID)
                }
                if ledger.state.member(account.accountID)?.role.isAdministrator == true {
                    let objects = try await listSharingObjects(
                        prefix: SharingObjectLocation.leavePrefix(vaultID), maximumLength: LeaveRequest.encodedLength)
                    for request in try sharedVault(vaultID).ledger.pendingLeaveRequests(among: objects)
                    where try sharedVault(vaultID).plan == nil {
                        guard (try? await planRotation(.departure(request), in: vaultID)) != nil else { continue }
                        report.rotation = try await resumeRotation(in: vaultID)
                    }
                }
                report.resealed = try await resealSharedVault(vaultID)
                try await saveSharedVault(vaultID)
            } catch {
                report.failure = String(describing: error)
            }
            reports[vaultID] = report
        }
    }

    // MARK: - Other members' device registries

    /// Fetches and evaluates the device registry of every account whose work may count in a shared vault: every
    /// account the chains list or listed, with the signing key the ledger gives for it (the current member's, or
    /// the one the record that ended their permission listed). Their devices are what a value's `GroupStamp`
    /// names, and their keys what a segment's device signature is checked against (§8.8, D9).
    func refreshMemberRegistries(account: AccountRecord) async {
        guard let transport = syncSettings?.transport else { return }
        var signingKeys: [UUID: [UInt8]] = [:]
        for vault in sharing.vaults.values {
            let ledger = vault.ledger
            let accounts = Set(ledger.chain.flatMap { $0.state.members.map(\.accountID) })
            for accountID in accounts where accountID != account.accountID && signingKeys[accountID] == nil {
                switch ledger.writeStanding(of: accountID) {
                case .mayWrite:
                    if let member = ledger.state.member(accountID) { signingKeys[accountID] = member.bundle.signingKey }
                case .ended(_, let author, _):
                    signingKeys[accountID] = author.bundle.signingKey
                case .nothingCounts:
                    // A read-only member's work does not count, but their devices are listed, so that a version
                    // naming one is judged as theirs.
                    if let member = ledger.state.member(accountID) { signingKeys[accountID] = member.bundle.signingKey }
                }
            }
        }
        var registries: [UUID: DeviceRegistryState] = [:]
        for (accountID, signingKey) in signingKeys {
            guard
                let names = try? await transport.list(prefix: AccountObjectLocation.registryPrefix(accountID))
            else {
                if let known = sharing.registries[accountID] { registries[accountID] = known }
                continue
            }
            var raw: [[UInt8]] = []
            for name in Set(names).sorted() {
                guard case .registryEntry(let owner, _)? = AccountObjectLocation(name: name), owner == accountID,
                    let bytes = try? await transport.fetch(name, maximumLength: RegistryEntry.maximumLength)
                else { continue }
                raw.append(bytes)
            }
            if let state = Self.evaluateMemberRegistry(raw, accountID: accountID, signingKey: signingKey) {
                registries[accountID] = state
            } else if let known = sharing.registries[accountID] {
                registries[accountID] = known
            }
        }
        sharing.registries = registries
    }

    /// Another account's registry, anchored on the signing key the membership chain lists for it: the one genesis
    /// entry that key signed, following that account's newest password change (a registry is the account's own
    /// business, and every entry needs its account key's signature). `nil` if there is not exactly one genesis.
    static func evaluateMemberRegistry(_ raw: [[UInt8]], accountID: UUID, signingKey: [UInt8])
        -> DeviceRegistryState?
    {
        let entries = DeviceRegistry.admit(raw, accountID: accountID, accountSigningKey: signingKey)
        let geneses = entries.filter {
            if case .genesis = $0.value.body { return true }
            return false
        }
        guard geneses.count == 1, let genesis = geneses.first?.key else { return nil }
        var credential = genesis
        var state: DeviceRegistryState?
        for _ in 0..<8 {
            guard
                let evaluated = try? DeviceRegistry.evaluate(
                    entries, accountID: accountID, accountSigningKey: signingKey, genesis: genesis,
                    credential: credential)
            else { return state }
            state = evaluated
            guard let next = evaluated.pendingCredentials.last else { return evaluated }
            credential = next.id
        }
        return state
    }

    /// The accounts whose registries list `device`, this account's own first; revoked devices included, since what
    /// a device wrote before its revocation is still its account's work.
    func accountsListing(_ device: UUID, ownView: RegistryView?, account: AccountRecord) -> [UUID] {
        var accounts: [UUID] = []
        if let ownView, ownView.state.devices[device] != nil || ownView.state.revoked[device] != nil {
            accounts.append(account.accountID)
        }
        for (accountID, state) in sharing.registries.sorted(by: { $0.key.uuidString < $1.key.uuidString })
        where state.devices[device] != nil || state.revoked[device] != nil {
            accounts.append(accountID)
        }
        return accounts
    }

    /// The account whose keys signed a sync object: its account key and its device's key in that account's
    /// registry. A device ID listed by more than one registry is answered by whichever signature verifies, which
    /// only one account's keys can make.
    func signingAccount(
        _ signature: [UInt8], over envelope: [UInt8], at location: SyncObjectLocation,
        ownView: RegistryView?, account: AccountRecord
    ) -> UUID? {
        let message = Self.syncSignedMessage(envelope, at: location)
        if let ownView,
            (try? Self.verifyDual(
                signature, over: message, domain: .logSegment, author: location.author, view: ownView)) != nil
        {
            return account.accountID
        }
        guard let parts = DualSignature.decode(signature) else { return nil }
        for (accountID, state) in sharing.registries.sorted(by: { $0.key.uuidString < $1.key.uuidString }) {
            guard let device = state.devices[location.author],
                (try? Signatures.verify(
                    parts.account, for: message, domain: .logSegment, signingKey: state.accountSigningKey)) != nil,
                (try? DeviceSignatures.verify(
                    parts.device, for: message, domain: .logSegment, deviceID: location.author, key: device.key))
                    != nil
            else { continue }
            return accountID
        }
        return nil
    }

    // MARK: - Verifying a shared vault's objects (`SyncKeyring.verify`)

    /// `syncVerify` for a shared vault: the object must carry the dual signature of a device registered to an
    /// account the chain lists, under that account's key in the chain, and that account's writes must be able to
    /// count (`writeStanding` is not `nothingCounts`). A snapshot needs an account that may write now. Whether a
    /// segment of an account whose permission ended is inside its cut is the judge's question, at merge.
    func sharedVerify(
        _ signature: [UInt8], over envelope: [UInt8], at location: SyncObjectLocation, ownView: RegistryView?,
        account: AccountRecord
    ) throws {
        guard let vault = sharing.vaults[location.vaultID] else {
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
        guard !accountsListing(location.author, ownView: ownView, account: account).isEmpty else {
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
        guard
            let signer = signingAccount(signature, over: envelope, at: location, ownView: ownView, account: account)
        else { throw SyncKeyringError.authenticationFailed }
        switch vault.ledger.writeStanding(of: signer) {
        case .mayWrite:
            return
        case .ended:
            guard location.kind == .segment else { throw SyncKeyringError.untrustedAuthor(location.author) }
        case .nothingCounts:
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
    }

    /// The devices whose streams a shared vault no longer reads: revoked from their own account.
    func sharedRetiredAuthors(_ vaultID: UUID) -> Set<UUID> {
        guard sharing.vaults[vaultID] != nil else { return [] }
        return Set(sharing.registries.values.flatMap(\.revoked.keys))
    }

    // MARK: - The judge (`WriteJudge`)

    func judgeRecord(
        segment location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8], entries: [SyncEntry]
    ) async {
        guard location.kind == .segment, sharing.vaults[location.vaultID] != nil,
            let account = try? await loadAccount()
        else { return }
        let ownView = try? await registry(account)
        guard
            let signer = signingAccount(signature, over: envelope, at: location, ownView: ownView, account: account),
            var vault = sharing.vaults[location.vaultID],
            vault.index.segment(device: location.author, sequence: location.number) == nil
        else { return }
        vault.index.record(
            device: location.author, sequence: location.number,
            segment: SharedStreamIndex.Segment(
                digest: SharedStreamIndex.digest(name: location.name, envelope: envelope), account: signer,
                entries: entries.map { VersionKey(recordID: $0.recordID, kind: $0.kind.rawValue, version: $0.version) })
        )
        vault.indexChanged = true
        // A segment inside a cut that this device was waiting for can make versions held aside count: judge again.
        if case .ended(let cut, _, _) = vault.ledger.writeStanding(of: signer),
            let position = SyncWriteCut(cut).positions[location.author], location.number <= position.sequence
        {
            vault.needsReconcile = true
        }
        sharing.vaults[location.vaultID] = vault
    }

    func judgeAdmitsSegment(_ location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8]) async
        -> SegmentAdmission
    {
        guard let vault = sharing.vaults[location.vaultID] else { return .apply }
        guard let account = try? await loadAccount() else { return .holdAside }
        let ownView = try? await registry(account)
        guard let current = sharing.vaults[location.vaultID],
            let signer = signingAccount(signature, over: envelope, at: location, ownView: ownView, account: account)
        else { return .holdAside }
        _ = vault
        switch current.ledger.writeStanding(of: signer) {
        case .mayWrite:
            return .apply
        case .nothingCounts:
            return .holdAside
        case .ended(let cut, _, _):
            switch SyncWriteCut(cut).contains(device: location.author, sequence: location.number, index: current.index)
            {
            case true?: return .apply
            case false?: return .holdAside
            case nil: return .wait
            }
        }
    }

    /// Whether every value of a version counts: the version's own revision and each value's (`GroupStamp`, kept and
    /// retained values, note lines), each judged for the account whose work it is (§8.8 step 5). A version that does
    /// not open here cannot be judged and is held aside; receiving its key replays the log.
    func judgeAdmits(_ record: StoredRecord) async throws -> Bool {
        guard sharing.vaults[record.vaultID] != nil else { return true }
        guard let account = try await loadAccount() else { return false }
        let ownView = try? await registry(account)
        guard let keys else { throw SyncKeyringError.locked }
        let origin = Revision(version: record.version, device: record.deviceID)
        var revisions = [origin]
        if record.kind == .item {
            guard let item = try? openItem(record, keys: keys) else { return false }
            let canonical = ItemMerge.canonical(item, origin: Self.origin(record))
            revisions += canonical.revisions.values.map(\.revision)
            revisions += canonical.conflicts.values.joined().map(\.stamp.revision)
            revisions += canonical.retainedValues.map(\.stamp.revision)
            revisions += canonical.noteLines.map(\.id.revision)
        }
        guard let vault = sharing.vaults[record.vaultID] else { return true }
        let listing = { (device: UUID) in self.accountsListing(device, ownView: ownView, account: account) }
        let kind = record.kind.rawValue
        let originKey = VersionKey(recordID: record.recordID, kind: kind, version: record.version)
        // Sealed under a key the chain introduced at or after the record that ended an account's permission, by a
        // writer whose work counts: that writer held the record (no grant of the key opens without it) and judged
        // what it carried against it. This is how a member who joined after a rotation, and holds none of the keys
        // the departed member's own segments are sealed under, counts what the cut held (§8.6: re-sealed versions
        // still say whose work they carry).
        let sealedAfter = vault.ledger.keyEpoch(of: record.keyID)
        let writerCounts = Self.counts(originKey, device: record.deviceID, in: vault, listing: listing)
        guard writerCounts else { return false }
        for revision in Set(revisions) where revision != origin {
            let key = VersionKey(recordID: record.recordID, kind: kind, version: revision.version)
            guard
                Self.counts(
                    key, device: revision.device, in: vault, listing: listing,
                    vouchedForFrom: sealedAfter)
            else { return false }
        }
        return true
    }

    /// Whether the value written as `key` by `device` counts. Its account is the signer of the segment of
    /// `device`'s own stream that first carried that version, when this device holds it; then that account's
    /// standing decides, and for one whose permission ended, whether that segment is inside the cut. A version this
    /// device never saw in its writer's stream counts only if every account whose registry lists the device may
    /// write now, or (`vouchedForFrom`) if it is carried in a version sealed under a key introduced at or after the
    /// record that ended that account's permission: a former member cannot make a write count by keeping it out of
    /// their own stream, and holds no such key.
    static func counts(
        _ key: VersionKey, device: UUID, in vault: SharedVault, listing: (UUID) -> [UUID],
        vouchedForFrom keyEpoch: UInt64? = nil
    ) -> Bool {
        if let sequence = vault.index.firstCarrier[device]?[key],
            let segment = vault.index.segment(device: device, sequence: sequence)
        {
            switch vault.ledger.writeStanding(of: segment.account) {
            case .mayWrite:
                return true
            case .ended(let cut, _, _):
                return SyncWriteCut(cut).contains(device: device, sequence: sequence, index: vault.index) == true
            case .nothingCounts:
                return false
            }
        }
        let accounts = listing(device)
        guard !accounts.isEmpty else { return false }
        return accounts.allSatisfy { account in
            switch vault.ledger.writeStanding(of: account) {
            case .mayWrite:
                return true
            case .ended:
                guard let keyEpoch, let ended = endingEpoch(of: account, in: vault.ledger) else { return false }
                return keyEpoch >= ended
            case .nothingCounts:
                return false
            }
        }
    }

    /// The epoch of the latest record of the accepted chain that ended `account`'s permission to write: its removal,
    /// departure, or change of role.
    static func endingEpoch(of account: UUID, in ledger: MembershipLedger) -> UInt64? {
        for link in ledger.chain.reversed() {
            switch link.record.operation {
            case .removeMember(let removed) where removed == account:
                return link.state.epoch
            case .memberLeft(let departed, _) where departed == account:
                return link.state.epoch
            case .changeRole(let changed, let role) where changed == account && !role.mayWrite:
                return link.state.epoch
            default:
                continue
            }
        }
        return nil
    }

    /// A key the chain introduced and never entitled this account to: segments sealed under it never open here.
    func judgePassesOver(keyID: UUID, vaultID: UUID) async -> Bool {
        guard let vault = sharing.vaults[vaultID], let account = try? await loadAccount(),
            vault.ledger.keyEpoch(of: keyID) != nil
        else { return false }
        if case SharingError.notEntitledToKey? = Self.error(of: {
            try vault.ledger.grantSender(forKey: keyID, to: account.accountID)
        }) {
            return true
        }
        return false
    }

    private static func error(of body: () throws -> Any) -> (any Error)? {
        do {
            _ = try body()
            return nil
        } catch {
            return error
        }
    }

    // MARK: - Taking out what no longer counts

    /// After a change of head: every local version of the vault that no longer counts is taken out of the store and
    /// held aside (kept in the quarantine, never published on), and the log is replayed with the judge, so that each
    /// record is rebuilt from the versions that count (§8.7: "taken out, not only kept out").
    func takeOutWhatNoLongerCounts(_ vaultID: UUID) async throws {
        guard let vault = sharing.vaults[vaultID], let syncSettings else { return }
        let head = vault.ledger.state.hash.bytes
        guard vault.index.judgedHead != head else { return }
        for kind in [EnvelopeKind.item, .vaultMetadata] {
            for row in try await store.records(in: vaultID, kind: kind) where !(try await judgeAdmits(row)) {
                try await syncSettings.state.quarantine(SyncEntry(row), vaultID: vaultID)
                // The engine's store, not the session's writer: this is not a deletion to publish.
                try await store.commit(StoreChange(conditionalDeletions: [row.key: row.version]))
            }
        }
        sharing.vaults[vaultID]?.needsReconcile = true
    }

    // MARK: - Taking a write cut

    /// The cut for `accountID`, taken now from what this device has merged of each of that account's devices'
    /// streams: the furthest sequence through which it holds every segment, and the chain of their digests (§8.8:
    /// bound to objects, not positions). Take it after a sync, so it holds as much of their work as this device can.
    func takeWriteCut(of accountID: UUID, in vaultID: UUID) async throws -> WriteCut {
        guard let syncSettings else { throw SharedVaultError.syncNotConfigured }
        let state = try await syncSettings.state.loadState(vaultID: vaultID) ?? SyncState(vaultID: vaultID)
        let vault = try sharedVault(vaultID)
        var positions: [UUID: SyncWriteCut.Position] = [:]
        for device in vault.index.devices(signedBy: accountID) {
            let sequence = vault.index.contiguous(device: device, upTo: state.merged[device] ?? 0)
            guard sequence > 0, let chain = vault.index.chain(device: device, through: sequence) else { continue }
            positions[device] = SyncWriteCut.Position(sequence: sequence, chain: chain)
        }
        return try SyncWriteCut(positions: positions).encoded()
    }
}

extension VaultSyncAdapter: WriteJudge {
    func record(
        segment location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8], entries: [SyncEntry]
    ) async throws {
        await session.judgeRecord(segment: location, signature: signature, envelope: envelope, entries: entries)
    }

    func admitsSegment(_ location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8]) async throws
        -> SegmentAdmission
    {
        await session.judgeAdmitsSegment(location, signature: signature, envelope: envelope)
    }

    func admits(_ record: StoredRecord) async throws -> Bool {
        try await session.judgeAdmits(record)
    }

    func passesOverSegment(sealedUnder keyID: UUID, vaultID: UUID) async -> Bool {
        await session.judgePassesOver(keyID: keyID, vaultID: vaultID)
    }
}
