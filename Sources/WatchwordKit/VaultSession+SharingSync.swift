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
        // A replay judges every version again, and notes again which devices' streams it is waiting on.
        if vault.needsReconcile { sharing.vaults[vaultID]?.index.awaiting = [] }
        return (
            configuration, VaultSyncAdapter(session: self),
            vault.ledger.writePermission(for: account.accountID).isAllowed, vault.needsReconcile
        )
    }

    /// After a shared vault's engine ran: a replay that finished settles the head it judged against.
    func sharedEngineDidRun(_ vaultID: UUID, reconciled: Bool, report: SyncReport) {
        guard var vault = sharing.vaults[vaultID] else { return }
        if reconciled, !report.deferredUntilUnlock, !report.transportUnavailable {
            if vault.indexRebuilding {
                // The index is whole again: now take out what no longer counts, and replay once more (S41).
                vault.indexRebuilding = false
                vault.needsReconcile = true
                vault.index.judgedHead = nil
            } else {
                vault.needsReconcile = false
                vault.index.judgedHead = vault.ledger.state.hash.bytes
            }
            vault.indexChanged = true
            sharing.vaults[vaultID] = vault
        }
    }

    /// Before a replay that this sync asks for: what no longer counts, taken out if the vault's items were last
    /// judged against another head (or the index says it must be done again).
    func prepareSharedReplay(_ vaultID: UUID) async {
        try? await takeOutWhatNoLongerCounts(vaultID)
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
    /// account the chains list or listed, once for each signing key a chain gives it (the current member's, or the
    /// one the record that ended their permission listed). Their devices are what a value's `GroupStamp` names, and
    /// their keys what a segment's device signature is checked against (§8.8, D9). Anchored per vault (review finding
    /// S39): an administrator of one vault who lists another account's ID with keys of their own makes a registry
    /// that vault judges by, and no other.
    func refreshMemberRegistries(account: AccountRecord) async {
        guard let transport = syncSettings?.transport else { return }
        var anchors: [UUID: Set<[UInt8]>] = [:]
        for vault in sharing.vaults.values {
            for (accountID, signingKey) in Self.memberAnchors(of: vault.ledger, excluding: account.accountID) {
                anchors[accountID, default: []].insert(signingKey)
            }
        }
        var registries: [MemberRegistryAnchor: DeviceRegistryState] = [:]
        for (accountID, signingKeys) in anchors.sorted(by: { $0.key.uuidString < $1.key.uuidString }) {
            let anchorsOfAccount = signingKeys.map { MemberRegistryAnchor(accountID: accountID, signingKey: $0) }
            guard
                let names = try? await transport.list(prefix: AccountObjectLocation.registryPrefix(accountID))
            else {
                for anchor in anchorsOfAccount { registries[anchor] = sharing.registries[anchor] }
                continue
            }
            var raw: [[UInt8]] = []
            for name in Set(names).sorted() {
                guard case .registryEntry(let owner, _)? = AccountObjectLocation(name: name), owner == accountID,
                    let bytes = try? await transport.fetch(name, maximumLength: RegistryEntry.maximumLength)
                else { continue }
                raw.append(bytes)
            }
            for anchor in anchorsOfAccount {
                registries[anchor] =
                    Self.evaluateMemberRegistry(raw, accountID: accountID, signingKey: anchor.signingKey)
                    ?? sharing.registries[anchor]
            }
        }
        sharing.registries = registries
    }

    /// The signing key `ledger`'s chain gives each account it lists or listed, other than `me`: the current member's,
    /// or the one the record that ended their permission listed.
    static func memberAnchors(of ledger: MembershipLedger, excluding me: UUID) -> [UUID: [UInt8]] {
        var anchors: [UUID: [UInt8]] = [:]
        for accountID in Set(ledger.chain.flatMap { $0.state.members.map(\.accountID) }) where accountID != me {
            switch ledger.writeStanding(of: accountID) {
            case .mayWrite:
                if let member = ledger.state.member(accountID) { anchors[accountID] = member.bundle.signingKey }
            case .ended(_, let author, _):
                anchors[accountID] = author.bundle.signingKey
            case .nothingCounts:
                // A read-only member's work does not count, but their devices are listed, so that a version naming
                // one is judged as theirs.
                if let member = ledger.state.member(accountID) { anchors[accountID] = member.bundle.signingKey }
            }
        }
        return anchors
    }

    /// The other accounts' registries as `vaultID`'s chain anchors them, by account in a fixed order.
    func memberRegistries(_ vaultID: UUID, account: UUID) -> [(accountID: UUID, state: DeviceRegistryState)] {
        guard let vault = sharing.vaults[vaultID] else { return [] }
        return Self.memberAnchors(of: vault.ledger, excluding: account)
            .sorted { $0.key.uuidString < $1.key.uuidString }
            .compactMap { accountID, signingKey in
                sharing.registries[MemberRegistryAnchor(accountID: accountID, signingKey: signingKey)].map {
                    (accountID, $0)
                }
            }
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

    /// The accounts whose registries, as `vaultID`'s chain anchors them, list `device`, this account's own first;
    /// revoked devices included, since what a device wrote before its revocation is still its account's work.
    func accountsListing(_ device: UUID, in vaultID: UUID, ownView: RegistryView?, account: AccountRecord) -> [UUID] {
        var accounts: [UUID] = []
        if let ownView, ownView.state.devices[device] != nil || ownView.state.revoked[device] != nil {
            accounts.append(account.accountID)
        }
        for (accountID, state) in memberRegistries(vaultID, account: account.accountID)
        where state.devices[device] != nil || state.revoked[device] != nil {
            accounts.append(accountID)
        }
        return accounts
    }

    /// The account whose keys signed a sync object: its account key and its device's key in that account's
    /// registry, as the object's own vault's chain anchors it. A device ID listed by more than one registry is
    /// answered by whichever signature verifies, which only one account's keys can make.
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
        for (accountID, state) in memberRegistries(location.vaultID, account: account.accountID) {
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
        guard !accountsListing(location.author, in: location.vaultID, ownView: ownView, account: account).isEmpty
        else { throw SyncKeyringError.untrustedAuthor(location.author) }
        guard
            let signer = signingAccount(signature, over: envelope, at: location, ownView: ownView, account: account)
        else { throw SyncKeyringError.authenticationFailed }
        // Keys in the chain that differ from this device's pin: the person has been warned, and nothing they sign
        // counts here until that is settled (S39).
        if vault.keyCheck?.substituted.contains(signer) == true {
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
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
        guard sharing.vaults[vaultID] != nil, let me = account?.accountID else { return [] }
        return Set(memberRegistries(vaultID, account: me).flatMap(\.state.revoked.keys))
    }

    // MARK: - The judge (`WriteJudge`)

    func judgeRecord(
        segment location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8], entries: [SyncEntry]
    ) async {
        guard location.kind == .segment, sharing.vaults[location.vaultID] != nil,
            let account = try? await loadAccount()
        else { return }
        let ownView = try? await registry(account)
        // Not recorded while locked: a segment is recorded once, so it must be recorded with its values. A lock that
        // landed during the suspensions above stops the merge too, and the next sync records it.
        guard let keys,
            let signer = signingAccount(signature, over: envelope, at: location, ownView: ownView, account: account),
            var vault = sharing.vaults[location.vaultID],
            vault.index.segment(device: location.author, sequence: location.number) == nil
        else { return }
        // The values this segment carried that its stream had not carried before, for the work of the device their
        // stamp names: what a value is checked against, rather than the stamp it chose (S36). Only this stream's own
        // device's values are filed, and the writes a tombstone of its makes where it is applied.
        var values: [SharedStreamIndex.ValueKey] = []
        var seen: Set<SharedStreamIndex.ValueKey> = []
        for entry in entries {
            for value in carriedValues(entry, vaultID: location.vaultID, author: location.author, keys: keys)
            where seen.insert(value).inserted
                && !vault.index.carries(value, device: location.author, atOrBefore: location.number)
            {
                values.append(value)
            }
        }
        vault.index.record(
            device: location.author, sequence: location.number,
            segment: SharedStreamIndex.Segment(
                digest: SharedStreamIndex.digest(name: location.name, envelope: envelope), account: signer,
                entries: entries.map { VersionKey(recordID: $0.recordID, kind: $0.kind.rawValue, version: $0.version) },
                values: values))
        vault.indexChanged = true
        sharing.vaults[location.vaultID] = vault
        // A segment inside a cut that this device was waiting for, or a new segment of a device a version was held
        // aside for, can make versions held aside count: judge again (written down, S41).
        if case .ended(let cut, _, _) = vault.ledger.writeStanding(of: signer),
            let position = SyncWriteCut(cut).positions[location.author], location.number <= position.sequence
        {
            requestReplay(location.vaultID)
        }
        if vault.index.awaiting.contains(location.author) { requestReplay(location.vaultID) }
    }

    /// The values `entry` carries that are its author's own work: of a version, those whose stamp names the author;
    /// of an item's tombstone, what applying it writes (`ItemMerge.attributedSettlement`).
    private func carriedValues(_ entry: SyncEntry, vaultID: UUID, author: UUID, keys: UnlockedKeys)
        -> [SharedStreamIndex.ValueKey]
    {
        if let row = entry.record(in: vaultID) {
            return (attributedValues(of: row, keys: keys) ?? []).map(\.value).filter { $0.device == author }
        }
        guard entry.kind == .item else { return [] }
        return ItemMerge.attributedSettlement(ofErasureSummary: entry.erasure).map {
            SharedStreamIndex.ValueKey(device: $0.revision.device, digest: Self.valueDigest($0.bytes))
        }
    }

    func judgeAdmitsSegment(_ location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8]) async
        -> SegmentAdmission
    {
        guard sharing.vaults[location.vaultID] != nil else { return .apply }
        guard let account = try? await loadAccount() else { return .holdAside }
        // What `record` learnt is written down before anything it lets count is merged (S41).
        if sharing.vaults[location.vaultID]?.indexChanged == true {
            try? await saveSharedVault(location.vaultID)
        }
        let ownView = try? await registry(account)
        guard let current = sharing.vaults[location.vaultID],
            let signer = signingAccount(signature, over: envelope, at: location, ownView: ownView, account: account)
        else { return .holdAside }
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

    /// Whether every value of a version counts (§8.8 step 5, review findings S36 and S37). The version's own revision
    /// must be its writer's in a segment that counts; then each value it holds (`GroupStamp`, kept and retained
    /// values, field order, note lines; the description of a vault) is judged by its *bytes*, stamp included:
    ///
    /// - carried by a segment of the stream of the device its stamp names: it counts if one of those segments does,
    ///   for the account that signed it (inside the cut, for one whose permission ended);
    /// - naming this device and carried by none of its segments: it counts only if this device's own copy of the
    ///   record holds it — a device knows what it wrote, so a value labelled with its revision that it never wrote
    ///   is refused at once, whoever's version carries it;
    /// - carried nowhere here: for a member who joined after a rotation, who cannot open the segments that carried
    ///   older values, it counts if the version is sealed under a key introduced at or after the latest record that
    ///   ended anyone's permission to write (whoever sealed it held that record, and judged the value with every
    ///   segment in hand) and the accounts listing the device may have written it; otherwise it is held aside until
    ///   that device's stream shows it (`SharedStreamIndex.awaiting`).
    ///
    /// A version that does not open here cannot be judged and is held aside; receiving its key replays the log.
    func judgeAdmits(_ record: StoredRecord) async throws -> Bool {
        guard sharing.vaults[record.vaultID] != nil else { return true }
        guard let account = try await loadAccount() else { return false }
        let ownView = try? await registry(account)
        let local = try await store.record(record.key)
        guard let keys else { throw SyncKeyringError.locked }
        guard let vault = sharing.vaults[record.vaultID] else { return true }
        let listing = { (device: UUID) in
            self.accountsListing(device, in: record.vaultID, ownView: ownView, account: account)
        }
        let originKey = VersionKey(recordID: record.recordID, kind: record.kind.rawValue, version: record.version)
        guard Self.counts(originKey, device: record.deviceID, in: vault, listing: listing) else { return false }
        guard let values = attributedValues(of: record, keys: keys) else { return false }
        var ownCopy: Set<SharedStreamIndex.ValueKey>?
        let vouched = Self.vouchesForUncarriedValues(record, in: vault, account: account.accountID)
        var awaited: Set<UUID> = []
        var admitted = true
        // Every value is filed under the device its stamp names (`attributedValues`).
        for value in Set(values.map(\.value)) {
            if let carriers = vault.index.valueCarriers[value] {
                guard carriers.contains(where: { Self.segmentCounts($0.key, sequence: $0.value, in: vault) }) else {
                    return false
                }
                continue
            }
            if value.device == account.deviceID {
                if ownCopy == nil {
                    ownCopy = Set(
                        (local.flatMap { attributedValues(of: $0, keys: keys) } ?? []).map(\.value).filter {
                            $0.device == account.deviceID
                        })
                }
                guard ownCopy?.contains(value) == true else { return false }
                continue
            }
            let accounts = listing(value.device)
            if vouched, !accounts.isEmpty, accounts.allSatisfy({ Self.mayHaveWritten($0, in: vault.ledger) }) {
                continue
            }
            if !accounts.isEmpty { awaited.insert(value.device) }
            admitted = false
        }
        if let known = sharing.vaults[record.vaultID]?.index.awaiting, !awaited.isSubset(of: known) {
            sharing.vaults[record.vaultID]?.index.awaiting.formUnion(awaited)
            sharing.vaults[record.vaultID]?.indexChanged = true
        }
        return admitted
    }

    /// Whether some of the account's work can count here: it may write, or could once.
    static func mayHaveWritten(_ accountID: UUID, in ledger: MembershipLedger) -> Bool {
        if case .nothingCounts = ledger.writeStanding(of: accountID) { return false }
        return true
    }

    /// The attributable values of a stored version, as the index files them: an item's (`ItemMerge.attributedValues`),
    /// or a vault's description as one value, attributed to the write that chose it (`VaultMetadata.writtenBy`, kept
    /// through every re-seal). `nil` if the version does not open here.
    func attributedValues(of row: StoredRecord, keys: UnlockedKeys)
        -> [(revision: Revision, value: SharedStreamIndex.ValueKey)]?
    {
        switch row.kind {
        case .item:
            guard let item = try? openItem(row, keys: keys) else { return nil }
            return ItemMerge.attributedValues(item, origin: Self.origin(row)).map {
                (
                    $0.revision,
                    SharedStreamIndex.ValueKey(device: $0.revision.device, digest: Self.valueDigest($0.bytes))
                )
            }
        case .vaultMetadata:
            guard let metadata = try? openMetadata(row, keys: keys) else { return nil }
            let author = metadata.writtenBy ?? Self.origin(row)
            var bytes: [UInt8] = [6] + SharedBytes.bytes(metadata.vaultID)
            bytes += SharedBytes.littleEndian(UInt64(metadata.name.utf8.count)) + Array(metadata.name.utf8)
            bytes += SharedBytes.littleEndian(metadata.createdAt.timeIntervalSince1970.bitPattern)
            bytes += SharedBytes.littleEndian(author.version) + SharedBytes.bytes(author.device)
            return [(author, SharedStreamIndex.ValueKey(device: author.device, digest: Self.valueDigest(bytes)))]
        default:
            return []
        }
    }

    static func valueDigest(_ bytes: [UInt8]) -> [UInt8] {
        ObjectDigest(hashing: Array("WW-value-v1".utf8) + bytes).bytes
    }

    /// Whether the segment of `device`'s stream at `sequence` counts: its signer may write, or it is inside the cut
    /// of the record that ended the signer's permission.
    static func segmentCounts(_ device: UUID, sequence: UInt64, in vault: SharedVault) -> Bool {
        guard let segment = vault.index.segment(device: device, sequence: sequence) else { return false }
        switch vault.ledger.writeStanding(of: segment.account) {
        case .mayWrite:
            return true
        case .ended(let cut, _, _):
            return SyncWriteCut(cut).contains(device: device, sequence: sequence, index: vault.index) == true
        case .nothingCounts:
            return false
        }
    }

    /// Whether the version vouches for values no segment held here carried: only for an account the chain never
    /// entitled to some key (one who joined after a rotation, and passes over what was sealed under it), and only
    /// for a version sealed under a key introduced at or after the latest record that ended anyone's permission to
    /// write. Its sealer held that record and every earlier segment. A device that holds every key never vouches:
    /// what it has not seen in its writer's stream waits for it (S36; S42 for what this leaves).
    static func vouchesForUncarriedValues(_ record: StoredRecord, in vault: SharedVault, account: UUID) -> Bool {
        let ledger = vault.ledger
        guard let sealed = ledger.keyEpoch(of: record.keyID) else { return false }
        let keyIDs = Set(ledger.chain.map(\.state.vaultKeyID))
        let passesOverSome = keyIDs.contains { keyID in
            if case SharingError.notEntitledToKey? = error(of: { try ledger.grantSender(forKey: keyID, to: account) }) {
                return true
            }
            return false
        }
        guard passesOverSome else { return false }
        return sealed >= (latestEndingEpoch(in: ledger) ?? 0)
    }

    /// Whether the version written as `key` by `device` counts: the segment of `device`'s own stream that first
    /// carried it, for the account that signed it. A version this device never saw in its writer's stream (its own,
    /// not yet published, or one in a stream it passes over) counts only if every account whose registry lists the
    /// device may write now.
    static func counts(_ key: VersionKey, device: UUID, in vault: SharedVault, listing: (UUID) -> [UUID]) -> Bool {
        if let sequence = vault.index.firstCarrier[device]?[key] {
            return segmentCounts(device, sequence: sequence, in: vault)
        }
        let accounts = listing(device)
        guard !accounts.isEmpty else { return false }
        return accounts.allSatisfy { vault.ledger.writeStanding(of: $0) == .mayWrite }
    }

    /// The epoch of the latest record of the accepted chain that ended any account's permission to write.
    static func latestEndingEpoch(in ledger: MembershipLedger) -> UInt64? {
        for link in ledger.chain.reversed() {
            switch link.record.operation {
            case .removeMember, .memberLeft:
                return link.state.epoch
            case .changeRole(_, let role) where !role.mayWrite:
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
        guard !vault.indexRebuilding else {
            // Never judged against an index being rebuilt: the replay rebuilds it first.
            sharing.vaults[vaultID]?.needsReconcile = true
            return
        }
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
