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
        // The markers whether or not sharing is configured: they are what holds a shared vault closed without it.
        await loadSharedMarkersIfNeeded()
        guard sharing.settings != nil, syncSettings != nil else { return [:] }
        await loadSharedVaultsIfNeeded()
        await ensureSharedMarkers(account: account)
        var reports: [UUID: SharedVaultSyncReport] = [:]
        for vaultID in sharing.vaults.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            var report = SharedVaultSyncReport()
            // A transport that stopped for one vault has stopped for all: the rest are not asked again.
            if let stopped = reports.values.lazy.compactMap(\.transportFailure).first {
                report.transportFailure = stopped
                reports[vaultID] = report
                continue
            }
            do {
                let before = try sharedVault(vaultID).ledger.state.hash
                report.recordsRejected = try await ingestMembership(vaultID).rejected.count
                if keys != nil {
                    if try await settleProposals(in: vaultID) { try await ingestMembership(vaultID) }
                    report.keyReceived = try await fetchCurrentKey(vaultID)
                }
                report.membershipChanged = try sharedVault(vaultID).ledger.state.hash != before
                report.requiresNewerVersion = try sharedVault(vaultID).ledger.continuesInLaterFormat
            } catch {
                report.failure = String(describing: error)
                report.transportFailure = Self.stoppingTransportFailure(error)
            }
            reports[vaultID] = report
        }
        guard !reports.values.contains(where: { $0.transportFailure != nil }) else { return reports }
        await refreshMemberRegistries(account: account)
        guard keys != nil else { return reports }
        for vaultID in sharing.vaults.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            do {
                try await takeOutWhatNoLongerCounts(vaultID)
                try await saveSharedVault(vaultID)
            } catch {
                reports[vaultID, default: SharedVaultSyncReport()].failure = String(describing: error)
                if let stopped = Self.stoppingTransportFailure(error) {
                    reports[vaultID, default: SharedVaultSyncReport()].transportFailure = stopped
                    break
                }
            }
        }
        return reports
    }

    /// `error` if it is a transport error that stops a sync.
    static func stoppingTransportFailure(_ error: any Error) -> SyncTransportError? {
        guard let error = error as? SyncTransportError, error.stopsSync else { return nil }
        return error
    }

    /// How the engine of `vaultID` runs: a shared vault gets the judge and keeps its whole log (no snapshots, no
    /// collection: the departing account's segments are what a cut is judged against, §8.8 "a departed account's
    /// log"), publishes only while this account may write, and replays its log when what counts has changed.
    func sharedEngineOptions(_ vaultID: UUID, base: SyncConfiguration, account: AccountRecord)
        -> (configuration: SyncConfiguration, judge: (any WriteJudge)?, publishing: Bool, reconcile: Bool)
    {
        guard let vault = sharing.vaults[vaultID] else {
            // Shared, with no ledger here (Z41): there is no judge to give it, so it is never published to and its
            // log is left whole. `syncAll` only downloads for it anyway, having no current key.
            if isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) {
                var configuration = base
                configuration.maintainsLog = false
                return (configuration, nil, false, false)
            }
            return (base, nil, true, false)
        }
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
                // What the replay did not rebuild is held aside whole: gone from the vault, for the hygiene engine too.
                hygieneRuntime?.takenOut = []
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
                // Read-only past a later format (§8.9): no plan carried on or made, nothing sealed again.
                if try sharedVault(vaultID).ledger.continuesInLaterFormat {
                    report.requiresNewerVersion = true
                    try await saveSharedVault(vaultID)
                    reports[vaultID] = report
                    continue
                }
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
                // Someone outside the vault holds its current key (an addition and its removal lost a fork
                // together, Z43): a routine rotation, by any device whose account administers the vault.
                if !(try sharedVault(vaultID).ledger.exposedKeyHolders.isEmpty), try sharedVault(vaultID).plan == nil,
                    ledger.state.member(account.accountID)?.role.isAdministrator == true,
                    (try? await planRotation(.routine, in: vaultID)) != nil
                {
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
                report.transportFailure = Self.stoppingTransportFailure(error)
            }
            reports[vaultID] = report
            if report.transportFailure != nil { break }
        }
    }

    // MARK: - Other members' device registries

    /// Fetches and evaluates the device registry of every account whose work may count in a shared vault: every
    /// account the chains list or listed, once for each signing key a chain gives it (the current member's, or the
    /// one the record that ended their permission listed). Their devices are what a value's `GroupStamp` names, and
    /// their keys what a segment's device signature is checked against (§8.8, D9). Anchored per vault (review finding
    /// S39): an administrator of one vault who lists another account's ID with keys of their own makes a registry
    /// that vault judges by, and no other. And anchored on this device (Z6, `evaluateMemberRegistry`): what was
    /// taken once moves only forward.
    func refreshMemberRegistries(account: AccountRecord) async {
        guard let transport = syncSettings?.transport else { return }
        var anchors: [UUID: Set<[UInt8]>] = [:]
        for vault in sharing.vaults.values {
            for (accountID, signingKey) in Self.memberAnchors(of: vault.ledger, excluding: account.accountID) {
                anchors[accountID, default: []].insert(signingKey)
            }
        }
        var registries: [MemberRegistryAnchor: DeviceRegistryState] = [:]
        var disagreements: Set<MemberRegistryAnchor> = []
        for (accountID, signingKeys) in anchors.sorted(by: { $0.key.uuidString < $1.key.uuidString }) {
            let anchorsOfAccount = signingKeys.map { MemberRegistryAnchor(accountID: accountID, signingKey: $0) }
            guard let raw = await fetchMemberRegistry(accountID, transport: transport) else {
                for anchor in anchorsOfAccount {
                    registries[anchor] = sharing.registries[anchor]
                    if sharing.registryDisagreements.contains(anchor) { disagreements.insert(anchor) }
                }
                continue
            }
            for anchor in anchorsOfAccount {
                let evaluated = Self.evaluateMemberRegistry(
                    raw, accountID: accountID, signingKey: anchor.signingKey, pin: sharing.registryPins[anchor])
                guard evaluated.complete else {
                    // What was anchored is not all there now (withheld, or lost): nothing new is believed, and
                    // nothing held is forgotten.
                    registries[anchor] = sharing.registries[anchor]
                    if sharing.registryDisagreements.contains(anchor) { disagreements.insert(anchor) }
                    continue
                }
                registries[anchor] = evaluated.state
                if let pin = evaluated.pin { sharing.registryPins[anchor] = pin }
                if evaluated.unsettled { disagreements.insert(anchor) }
            }
        }
        sharing.registries = registries
        sharing.registryDisagreements = disagreements
    }

    /// Every entry under an account's registry prefix on the transport, or `nil` if it cannot be listed.
    func fetchMemberRegistry(_ accountID: UUID, transport: any SyncTransport) async -> [[UInt8]]? {
        guard let names = try? await transport.list(prefix: AccountObjectLocation.registryPrefix(accountID)) else {
            return nil
        }
        var raw: [[UInt8]] = []
        for name in Set(names).sorted() {
            guard case .registryEntry(let owner, _)? = AccountObjectLocation(name: name), owner == accountID,
                let bytes = try? await transport.fetch(name, maximumLength: RegistryEntry.maximumLength)
            else { continue }
            raw.append(bytes)
        }
        return raw
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

    /// Password changes replayed side by side when another account's registry forks at the one followed; more than
    /// this many competing changes are not replayed at all, and every device of the account is held in question.
    static let maximumMemberBranches = 8

    /// What `evaluateMemberRegistry` made of another account's registry.
    struct MemberRegistryEvaluation {
        /// Whose signatures count now: `nil` if nothing is anchored.
        var state: DeviceRegistryState?
        /// What this device anchors from now on; `nil` while it anchors nothing.
        var pin: MemberRegistryPin?
        /// The entries that disagree about whose devices the account's are: genesis entries other than the one
        /// anchored (all of them, with none anchored), competing password changes at the one followed, and password
        /// changes that leave the chain at or before it.
        var disagreement: Set<ObjectDigest> = []
        /// Whether `disagreement` holds anything the person has not settled.
        var unsettled = false
        /// `false` when the anchored entries were not all among those given: the caller keeps what it had.
        var complete = true
    }

    /// Another account's registry, as this device follows it (review finding Z6; docs/02-architecture.md §8.10).
    ///
    /// An account's own devices know which password change is theirs: the person typed its password. Another
    /// member's device knows nothing of the kind, and to it two password changes made from the same generation are
    /// symmetric: each carries the account key's signature, a registered device's, and the previous generation's
    /// enrolment key's. A device that was revoked *with* a password change still holds all three for the generation
    /// before its revocation, so it can publish a competing change there, sealing a back-dated revocation of the
    /// device that revoked it, and extend it to any generation. Following the highest generation therefore followed
    /// whoever published most, and un-revoked that device in every other member's eyes.
    ///
    /// So no rule here picks between two branches. What this device took once (`pin`: the genesis entry and the
    /// credential entry it follows) moves **only forward**, one credential entry at a time, and only where exactly
    /// one change follows that replays as a chain. A change that leaves the chain at or before the anchored entry
    /// is never followed, whatever its generation. Where two or more follow the anchored entry, neither is taken:
    /// the registry stays at the entry before them, and a device counts only if it is registered there **and in
    /// every one of the competing branches** — each side's revocations are honoured, so neither the device a branch
    /// revokes nor the one it keeps signs anything that counts here, while a device nobody contests carries on.
    /// With nothing anchored, more than one genesis entry anchors none.
    ///
    /// Every such sight is returned as a disagreement, for the screens to say that this person's devices disagree
    /// and to verify with them again; `verifyMemberDevices` is that step, and the only thing that moves the anchor
    /// to a branch of the person's choosing. What this does not stop: the key holder can keep the member's
    /// contested devices in question for as long as they like, and a device that anchors while only the forged
    /// branch is visible follows it until the person verifies. The cure for both is the account re-key (F10.1).
    static func evaluateMemberRegistry(
        _ raw: [[UInt8]], accountID: UUID, signingKey: [UInt8], pin: MemberRegistryPin?
    ) -> MemberRegistryEvaluation {
        let entries = DeviceRegistry.admit(raw, accountID: accountID, accountSigningKey: signingKey)
        func evaluate(_ genesis: ObjectDigest, _ credential: ObjectDigest) -> DeviceRegistryState? {
            try? DeviceRegistry.evaluate(
                entries, accountID: accountID, accountSigningKey: signingKey, genesis: genesis,
                credential: credential)
        }
        let geneses = entries.filter {
            if case .genesis = $0.value.body { return true }
            return false
        }.keys.sorted()
        var result = MemberRegistryEvaluation()
        let genesis: ObjectDigest
        if let pin {
            genesis = pin.genesis
            result.disagreement.formUnion(geneses.filter { $0 != genesis })
        } else {
            guard geneses.count == 1 else {
                // None to anchor, or more than one: nothing is anchored on a choice this device cannot make.
                result.disagreement = Set(geneses)
                result.unsettled = !geneses.isEmpty
                return result
            }
            genesis = geneses[0]
        }
        guard var state = evaluate(genesis, pin?.credential ?? genesis) else {
            result.pin = pin
            result.complete = false
            return result
        }

        // Forward, while exactly one change follows the one followed and replays as a chain.
        var branches: [DeviceRegistryState] = []
        var everyDeviceInQuestion = false
        for _ in 0..<DeviceRegistry.maximumEntries {
            let next = state.pendingCredentials.filter { $0.previous == state.credential.id }
            guard !next.isEmpty else { break }
            guard next.count <= maximumMemberBranches else {
                everyDeviceInQuestion = true
                result.disagreement.formUnion(next.map(\.id))
                break
            }
            let followable = next.compactMap { evaluate(genesis, $0.id) }
            if followable.count == 1 {
                state = followable[0]
                continue
            }
            if followable.count > 1 {
                branches = followable
                result.disagreement.formUnion(followable.map(\.credential.id))
            }
            break
        }

        // Changes that leave the chain at or before the entry followed: listed ones, and ones that can never count
        // on this chain (their author revoked behind one of its checkpoints) yet were made with the password of the
        // generation they replace. Never followed; seen, and said.
        result.disagreement.formUnion(state.forkedCredentials.map(\.id))
        let followed = Set(state.credentialChain.map(\.id))
        let ahead = Set(state.pendingCredentials.map(\.id))
        for (id, entry) in entries where !followed.contains(id) && !ahead.contains(id) {
            guard case .credential(_, _, let previous) = entry.body, state.connectedEntries.contains(id) else {
                continue
            }
            let replaced: [UInt8]?
            switch entries[previous]?.body {
            case .genesis(_, _, let key)?, .credential(_, let key, _)?: replaced = key
            default: replaced = nil
            }
            guard let replaced,
                (try? Signatures.verify(
                    entry.previousCredentialSignature, for: entry.previousCredentialMessage, domain: .deviceRegistry,
                    signingKey: replaced)) != nil
            else { continue }
            result.disagreement.insert(id)
        }

        // Competing changes at the one followed: only what every branch agrees is a device of the account counts.
        if everyDeviceInQuestion || !branches.isEmpty {
            for (id, device) in state.devices
            where everyDeviceInQuestion || !branches.allSatisfy({ $0.devices[id]?.key == device.key }) {
                state.devices[id] = nil
                // Still listed, as a revoked device is: what it wrote before stays its account's work, and its
                // stream is not read from here on.
                state.revoked[id] = device
            }
        }
        result.state = state
        result.pin = MemberRegistryPin(genesis: genesis, credential: state.credential.id, settled: pin?.settled)
        result.unsettled =
            !result.disagreement.isEmpty && pin?.settled != Self.disagreementDigest(result.disagreement)
        return result
    }

    static func disagreementDigest(_ entries: Set<ObjectDigest>) -> ObjectDigest {
        ObjectDigest(hashing: Array("WW-devices-settled-v1".utf8) + entries.sorted().flatMap(\.bytes))
    }

    /// The code that names a credential entry of an account's registry: twelve digits from SHA-256 of a label, the
    /// account and the entry's ID. A member reads theirs off their own device (`memberDevicesCode`); whoever shares a
    /// vault with them types it to say which of that account's password changes is the member's own.
    static func devicesCode(accountID: UUID, credential: ObjectDigest) -> String {
        let digest = ObjectDigest(
            hashing: Array("WW-devices-code-v1".utf8) + SharedBytes.bytes(accountID) + credential.bytes
        ).bytes
        let value = digest.prefix(5).reduce(UInt64(0)) { $0 << 8 | UInt64($1) } % 1_000_000_000_000
        let digits = String(repeating: "0", count: 12 - String(value).count) + String(value)
        return stride(from: 0, to: 12, by: 4).map { offset in
            String(digits.dropFirst(offset).prefix(4))
        }.joined(separator: " ")
    }

    /// This account's own code: the password change this device follows, for another member to type on theirs when
    /// their device reports that this account's devices disagree. Read it to them in person or over a call you
    /// trust, as with a safety number.
    public func memberDevicesCode() async throws -> String {
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        let view = try await registry(account)
        return Self.devicesCode(accountID: account.accountID, credential: view.state.credential.id)
    }

    /// The person has verified with a member again, and typed the code that member's own device shows
    /// (`memberDevicesCode`): this device anchors that member's registry on the credential entry the code names,
    /// whichever branch it is on, and takes what it has seen disagree as settled. The one step that moves an anchor
    /// anywhere but forward, and it is the person's.
    ///
    /// The code must name exactly one credential (or genesis) entry of the account's registry that replays as a
    /// chain; otherwise nothing changes (`memberDevicesCodeUnknown`).
    public func verifyMemberDevices(of member: UUID, code: String) async throws {
        _ = try sharingSettings()
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let account = try await loadAccount() else { throw VaultError.noAccount }
        await loadSharedVaultsIfNeeded()
        let transport = try sharingTransport()
        var signingKeys: Set<[UInt8]> = []
        for vault in sharing.vaults.values {
            if let key = Self.memberAnchors(of: vault.ledger, excluding: account.accountID)[member] {
                signingKeys.insert(key)
            }
        }
        guard !signingKeys.isEmpty, let raw = await fetchMemberRegistry(member, transport: transport) else {
            throw SharedVaultError.memberDevicesCodeUnknown(member)
        }
        _ = try requireKeys(since: epoch)
        let wanted = code.filter(\.isNumber)
        var settled: [MemberRegistryAnchor: MemberRegistryEvaluation] = [:]
        for signingKey in signingKeys {
            let anchor = MemberRegistryAnchor(accountID: member, signingKey: signingKey)
            let entries = DeviceRegistry.admit(raw, accountID: member, accountSigningKey: signingKey)
            let named = entries.filter { id, entry in
                switch entry.body {
                case .genesis, .credential:
                    return Self.devicesCode(accountID: member, credential: id).filter(\.isNumber) == wanted
                default:
                    return false
                }
            }.keys.sorted()
            let geneses = entries.filter {
                if case .genesis = $0.value.body { return true }
                return false
            }.keys.sorted()
            guard named.count == 1 else { continue }
            // The genesis entry the named one descends from: the anchored one, or the one it replays from.
            let candidates =
                sharing.registryPins[anchor].map { [$0.genesis] } ?? Array(geneses.prefix(Self.maximumMemberBranches))
            let genesis = candidates.first { candidate in
                (try? DeviceRegistry.evaluate(
                    entries, accountID: member, accountSigningKey: signingKey, genesis: candidate,
                    credential: named[0])) != nil
            }
            guard let genesis else { continue }
            var evaluated = Self.evaluateMemberRegistry(
                raw, accountID: member, signingKey: signingKey,
                pin: MemberRegistryPin(genesis: genesis, credential: named[0], settled: nil))
            guard evaluated.complete, var pin = evaluated.pin else { continue }
            pin.settled = evaluated.disagreement.isEmpty ? nil : Self.disagreementDigest(evaluated.disagreement)
            evaluated.pin = pin
            evaluated.unsettled = false
            settled[anchor] = evaluated
        }
        guard !settled.isEmpty else { throw SharedVaultError.memberDevicesCodeUnknown(member) }
        for (anchor, evaluated) in settled {
            sharing.registries[anchor] = evaluated.state
            sharing.registryPins[anchor] = evaluated.pin
            sharing.registryDisagreements.remove(anchor)
        }
        // Whose devices count has changed: the vaults that list the member are judged again, and the pins saved.
        for (vaultID, vault) in sharing.vaults
        where Self.memberAnchors(of: vault.ledger, excluding: account.accountID)[member] != nil {
            requestReplay(vaultID)
            _ = try requireKeys(since: epoch)
            try await saveSharedVault(vaultID)
        }
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
    /// count (`writeStanding` is not `nothingCounts`). A snapshot needs the owner's account: no device writes one in
    /// a shared vault (`maintainsLog` is off), so the only honest ones are from before the vault was shared, when its
    /// owner's devices were its only writers, and a member's would have its coverage believed unjudged (review
    /// finding Z21). Whether a segment of an account whose permission ended is inside its cut is the judge's
    /// question, at merge.
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
        // A snapshot named as this device's that this account's keys did not sign is nobody's this device knows: it
        // knows what it wrote (Z46). A segment in that position is taken in and held aside by the judge instead
        // (`judgeAdmitsSegment`), so that the stream is not left waiting at it.
        if location.kind == .snapshot, location.author == account.deviceID, signer != account.accountID {
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
        // Keys in the chain that differ from this device's pin: the person has been warned, and nothing they sign
        // counts here until that is settled (S39).
        if vault.keyCheck?.substituted.contains(signer) == true {
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
        guard location.kind == .segment || signer == vault.ledger.owner.accountID else {
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

    /// Whether a segment at `location` signed by `signer`'s keys is that stream's own (review finding Z46). A stream is
    /// named by its device alone, and a member can list another member's device ID in their own registry and sign
    /// objects into "its" stream; every device, the victim's included, used to merge those as that device's versions,
    /// which no rule keyed by device ID survives (a claim to have seen the device's unpublished edits is not asked
    /// of the device itself, S46). So: this device's own stream is this account's and no other's, since a device
    /// knows what it wrote; and any other stream is the account's that signed its lowest-numbered segment
    /// (`SharedStreamIndex.account(ofStream:)`). A segment that is not the stream's own is held aside, never merged,
    /// and the stream carries on past it.
    static func streamAdmits(
        _ signer: UUID, at location: SyncObjectLocation, in vault: SharedVault, account: AccountRecord
    ) -> Bool {
        if location.author == account.deviceID { return signer == account.accountID }
        if let owner = vault.index.account(ofStream: location.author) { return owner == signer }
        return true
    }

    /// The devices whose streams a shared vault no longer reads: revoked from their own account.
    func sharedRetiredAuthors(_ vaultID: UUID) -> Set<UUID> {
        guard sharing.vaults[vaultID] != nil, let me = account?.accountID else { return [] }
        return Set(memberRegistries(vaultID, account: me).flatMap(\.state.revoked.keys))
    }

    // MARK: - The judge (`WriteJudge`)

    func judgeRecord(
        segment location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8], entries: [SyncEntry],
        opened: Bool = true
    ) async {
        guard location.kind == .segment, sharing.vaults[location.vaultID] != nil,
            let account = try? await loadAccount()
        else { return }
        let ownView = try? await registry(account)
        // Not recorded while locked: a segment is recorded once, so it must be recorded with its values. A lock that
        // landed during the suspensions above stops the merge too, and the next sync records it. One recorded
        // unopened (it was sealed under a key not held then) is recorded again when it opens.
        guard let keys,
            let signer = signingAccount(signature, over: envelope, at: location, ownView: ownView, account: account),
            var vault = sharing.vaults[location.vaultID],
            vault.index.segment(device: location.author, sequence: location.number).map({ !$0.opened && opened })
                ?? true,
            // Another account's object in this device's own stream is no part of what it wrote. It is recorded,
            // unfiled, for the cut's chain that runs over it, as in anyone's stream, but only behind a segment of this
            // device's own: the stream's lowest segment names its account, and here that is never anyone else's (Z46).
            location.author != account.deviceID || signer == account.accountID
                || (vault.index.account(ofStream: location.author) == account.accountID
                    && (vault.index.firstSequence(ofStream: location.author) ?? .max) < location.number)
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
        let streamWas = vault.index.account(ofStream: location.author)
        vault.index.record(
            device: location.author, sequence: location.number,
            segment: SharedStreamIndex.Segment(
                digest: SharedStreamIndex.digest(name: location.name, envelope: envelope), account: signer,
                entries: entries.map { VersionKey(recordID: $0.recordID, kind: $0.kind.rawValue, version: $0.version) },
                values: values, opened: opened))
        vault.indexChanged = true
        sharing.vaults[location.vaultID] = vault
        // An earlier segment of the stream arrived after a later one, and another account signed it: the stream is
        // that account's, and whatever was judged while it looked like someone else's is judged again (Z51).
        if let streamWas, streamWas != vault.index.account(ofStream: location.author) {
            requestReplay(location.vaultID)
        }
        // A segment inside a cut that this device was waiting for, or a new segment of a device a version was held
        // aside for, can make versions held aside count: judge again (written down, S41).
        if case .ended(let cut, _, _) = vault.ledger.writeStanding(of: signer),
            let position = SyncWriteCut(cut).positions[location.author], location.number <= position.sequence
        {
            requestReplay(location.vaultID)
        }
        if vault.index.awaiting.contains(location.author) { requestReplay(location.vaultID) }
        // This device's own deletion, made on a copy that held a late write before it was shown the record that ended
        // the writer's permission, and published since: it erased here what the summary claimed, and a replay, which
        // holds it aside (S45), puts back what it should not have erased.
        if location.author == account.deviceID,
            let header = try? EnvelopeHeader.parse(envelope, expecting: location.envelopeKind)
        {
            for entry in entries where entry.isDeletion {
                guard
                    (try? await judgeAdmitsErasure(entry, in: location, sealedUnder: header.header.keyID)) == false
                else { continue }
                requestReplay(location.vaultID)
                break
            }
        }
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
            let signer = signingAccount(signature, over: envelope, at: location, ownView: ownView, account: account),
            Self.streamAdmits(signer, at: location, in: current, account: account)
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
    /// Note-line removals, discards and history entries are values like the rest, each naming its writer (S32, S43).
    /// Last, every edit the version's clock says it contains must count (`knowledgeCounts`, S44).
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
        if admitted, record.kind == .item, let item = try? openItem(record, keys: keys) {
            // A version's writer is not asked about its own edits only where the version is known to be that
            // device's: its own stream carried it (a stream is one account's, Z46), or it is this device's own. One
            // that merely names a device, in a snapshot say, is held to that device's stream like anyone's claim.
            let writersOwn =
                record.deviceID == account.deviceID || vault.index.firstCarrier[record.deviceID]?[originKey] != nil
            admitted = Self.knowledgeCounts(
                ItemMerge.effectiveClock(item, origin: Self.origin(record)),
                of: VersionKey(recordID: record.recordID, kind: record.kind.rawValue, version: record.version),
                author: writersOwn ? record.deviceID : nil, judgedBy: account.deviceID, in: vault, vouched: vouched,
                listing: listing, awaited: &awaited)
        }
        if let known = sharing.vaults[record.vaultID]?.index.awaiting, !awaited.isSubset(of: known) {
            sharing.vaults[record.vaultID]?.index.awaiting.formUnion(awaited)
            sharing.vaults[record.vaultID]?.indexChanged = true
        }
        return admitted
    }

    /// Whether every edit a version's clock says it contains counts (review findings S44 and S46): a version built on
    /// a write that does not count holds what that write had seen, and an edit made on it supersedes values its writer
    /// was shown only through that write. So for each device in the clock (`ItemMerge.effectiveClock`, which covers
    /// every stamp's `seen`) other than the version's own author, a segment of that device's stream that counts must
    /// have carried a version of the record at or above the clock's count: the edits claimed were published, inside
    /// the cut for an account whose permission to write ended (S44).
    ///
    /// That holds for a current member's edits too (S46): a claim to have seen edits their device has not published
    /// yet is a claim about edits that do not exist, and it would supersede them when they are made, concurrent as
    /// they are. Until that device's stream carries them the version waits (`awaited`); a claim about this device's
    /// own edits beyond what it published is refused at once, since it knows what it wrote. A device whose stream this
    /// device cannot read from its first segment (collected before the vault was shared, or sealed under keys this
    /// account was never given) cannot be checked, and a current member's edits there are believed as before; a
    /// version that vouches (S42) vouches for these as for its values. A device no account lists names nobody's work
    /// and is passed over.
    ///
    /// `author` is the device whose own edits are not asked about: the version's writer, where the version is known
    /// to be its work (`judgeAdmits`), or the device whose stream carried a tombstone. `nil` exempts nobody.
    static func knowledgeCounts(
        _ clock: VersionVector, of record: VersionKey, author: UUID?, judgedBy me: UUID, in vault: SharedVault,
        vouched: Bool, listing: (UUID) -> [UUID], awaited: inout Set<UUID>
    ) -> Bool {
        for (device, count) in clock.entries where device != author {
            let accounts = listing(device)
            guard !accounts.isEmpty else { continue }
            let carriers = (vault.index.firstCarrier[device] ?? [:]).filter {
                $0.key.recordID == record.recordID && $0.key.kind == record.kind && $0.key.version >= count
            }
            if carriers.contains(where: { Self.segmentCounts(device, sequence: $0.value, in: vault) }) { continue }
            if accounts.allSatisfy({ vault.ledger.writeStanding(of: $0) == .mayWrite }) {
                // "Cannot read from its first segment": not here at all, or here and sealed under a key not held.
                if vouched || vault.index.segment(device: device, sequence: 1)?.opened != true { continue }
                if device != me { awaited.insert(device) }
                return false
            }
            if carriers.isEmpty {
                if vouched, accounts.allSatisfy({ Self.mayHaveWritten($0, in: vault.ledger) }) { continue }
                awaited.insert(device)
            }
            return false
        }
        return true
    }

    /// Whether a permanent deletion's erasure summary counts (review finding S45): every edit its author says it had
    /// seen is judged as a version's clock is (`knowledgeCounts`). A device that merged a late write and then deleted
    /// the item claims what the late writer had seen, and would erase an honest version it was shown only through that
    /// write; a deletion built on a late write is held aside like a version built on one, and the item it would have
    /// erased stays. Only items' tombstones carry such a summary.
    func judgeAdmitsErasure(_ entry: SyncEntry, in location: SyncObjectLocation, sealedUnder keyID: UUID) async throws
        -> Bool
    {
        guard entry.kind == .item, sharing.vaults[location.vaultID] != nil else { return true }
        guard let account = try await loadAccount() else { return false }
        let ownView = try? await registry(account)
        guard let vault = sharing.vaults[location.vaultID] else { return true }
        let listing = { (device: UUID) in
            self.accountsListing(device, in: location.vaultID, ownView: ownView, account: account)
        }
        let vouched = Self.vouchesForUncarriedValues(sealedUnder: keyID, in: vault, account: account.accountID)
        var awaited: Set<UUID> = []
        var admitted = true
        let key = VersionKey(recordID: entry.recordID, kind: entry.kind.rawValue, version: entry.version)
        for erasure in ItemErasures(summary: entry.erasure).elements where erasure != .void {
            guard
                Self.knowledgeCounts(
                    erasure.seen, of: key, author: entry.device, judgedBy: account.deviceID, in: vault,
                    vouched: vouched, listing: listing, awaited: &awaited)
            else {
                admitted = false
                break
            }
        }
        if let known = sharing.vaults[location.vaultID]?.index.awaiting, !awaited.isSubset(of: known) {
            sharing.vaults[location.vaultID]?.index.awaiting.formUnion(awaited)
            sharing.vaults[location.vaultID]?.indexChanged = true
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
        case .scanStatus:
            // One value per device's observation, attributed to the device and revision it carries (§13.9): a removed
            // member's observation counts only inside its cut, whoever's version carries it on.
            guard let record = try? openScanStatus(row, keys: keys) else { return nil }
            return record.attributedObservations.map { observation in
                let revision = Revision(version: observation.revision, device: observation.device)
                let bytes = [EnvelopeKind.scanStatus.rawValue] + observation.bytes
                return (
                    revision,
                    SharedStreamIndex.ValueKey(device: observation.device, digest: Self.valueDigest(bytes))
                )
            }
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
        // Only a segment of the account the stream belongs to: another account's object there counts for nothing.
        guard let segment = vault.index.segment(device: device, sequence: sequence),
            vault.index.isOwnersSegment(device: device, sequence: sequence)
        else { return false }
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
        vouchesForUncarriedValues(sealedUnder: record.keyID, in: vault, account: account)
    }

    /// `vouchesForUncarriedValues(_:in:account:)` for whatever was sealed under `keyID`: a version, or the segment
    /// carrying a tombstone.
    static func vouchesForUncarriedValues(sealedUnder keyID: UUID, in vault: SharedVault, account: UUID) -> Bool {
        let ledger = vault.ledger
        guard let sealed = ledger.keyEpoch(of: keyID) else { return false }
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
    ///
    /// So is a key that only a branch which lost a fork introduced (a rotation signed on a stale head, Z43): the
    /// accepted chain never names it, so no grant of it is ever fetched here, and the stream of whoever sealed under
    /// it while they saw that branch would wait at that segment for good, their later writes with it. What the segment
    /// carried reaches this device sealed again under the vault's key, as after any rotation; and if that branch
    /// comes to win after all, receiving its key replays the log (`fetchCurrentKey`), the segment included. A key no
    /// record held here introduced is not passed over: its record may yet arrive.
    func judgePassesOver(keyID: UUID, vaultID: UUID) async -> Bool {
        guard let vault = sharing.vaults[vaultID], let account = try? await loadAccount() else { return false }
        guard vault.ledger.keyEpoch(of: keyID) != nil else {
            return vault.ledger.branches.contains { $0.state.vaultKeyID == keyID }
        }
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
        // What this device wrote and has not published, as its signed sync state has it (Z20).
        let ownDevice = account?.deviceID
        let published = (try? await syncState?.loadState(vaultID: vaultID))?.published ?? [:]
        for kind in [EnvelopeKind.item, .vaultMetadata, .scanStatus] {
            for row in try await store.records(in: vaultID, kind: kind) where !(try await judgeAdmits(row)) {
                // An item of this device's own that nobody else has is remembered as such, under the index's
                // signature: a deletion in another vault may be waiting for it (Z44, Z54).
                if kind == .item, row.deviceID == ownDevice,
                    !(published[row.key].map { $0 >= RecordStamp(row) } ?? false)
                {
                    sharing.vaults[vaultID]?.index.ownTakenOut.insert(
                        VersionKey(recordID: row.recordID, kind: kind.rawValue, version: row.version))
                    sharing.vaults[vaultID]?.indexChanged = true
                }
                try await syncSettings.state.quarantine(SyncEntry(row), vaultID: vaultID)
                // The engine's store, not the session's writer: this is not a deletion to publish.
                try await store.commit(StoreChange(conditionalDeletions: [row.key: row.version]))
                // Not deleted, to be rebuilt by the replay: the hygiene engine keeps what it knows of it (S47).
                if kind == .item { hygieneRuntime?.takenOut.insert(row.recordID) }
            }
        }
        sharing.vaults[vaultID]?.needsReconcile = true
    }

    // MARK: - Taking a write cut

    /// The cut for `accountID`, taken now from what this device has merged of each of that account's devices'
    /// streams: the furthest sequence through which it holds every segment, and the chain of their digests (§8.8:
    /// bound to objects, not positions). Take it after a sync, so it holds as much of their work as this device can.
    func takeWriteCut(of accountID: UUID, in vaultID: UUID) async throws -> WriteCut {
        // The state this session signed (Z20): the cut is signed, so a planted `merged` must not widen it.
        guard let syncState else { throw SharedVaultError.syncNotConfigured }
        let state = try await syncState.loadState(vaultID: vaultID) ?? SyncState(vaultID: vaultID)
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

    func recordUnopened(segment location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8]) async throws {
        await session.judgeRecord(
            segment: location, signature: signature, envelope: envelope, entries: [], opened: false)
    }

    func admitsSegment(_ location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8]) async throws
        -> SegmentAdmission
    {
        await session.judgeAdmitsSegment(location, signature: signature, envelope: envelope)
    }

    func admits(_ record: StoredRecord) async throws -> Bool {
        try await session.judgeAdmits(record)
    }

    func admitsErasure(_ entry: SyncEntry, in location: SyncObjectLocation, sealedUnder keyID: UUID) async throws
        -> Bool
    {
        try await session.judgeAdmitsErasure(entry, in: location, sealedUnder: keyID)
    }

    func passesOverSegment(sealedUnder keyID: UUID, vaultID: UUID) async -> Bool {
        await session.judgePassesOver(keyID: keyID, vaultID: vaultID)
    }
}
