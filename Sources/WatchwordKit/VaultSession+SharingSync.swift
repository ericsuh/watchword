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
    ///
    /// The take-out only for a sync that is `writing` (its `mayWrite`, review of round 22, Z253), not wherever the
    /// keys are here now: an unlock that lands during a sync begun locked installs them, and with a restore's move
    /// pending the take-out read `restoredUnpublished` from a state verified for the new ID, found none of the earlier
    /// ID's, and could take an uncarried row of that ID out into the quarantine, where the move no longer finds it.
    /// The take-out of a sync that may not write waits for the next that may: the judged head is left as it was.
    func syncSharedVaultsBeforeLogs(account: AccountRecord, writing: Bool) async -> [UUID: SharedVaultSyncReport] {
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
                // Held closed while the account's devices disagree about whose it is (Z59): membership is read, and
                // nothing is proposed or taken up.
                if keys != nil, !isOwnerDisputed(vaultID) {
                    if try await settleProposals(in: vaultID) { try await ingestMembership(vaultID) }
                    // Keys of the vault the account's directory brought, each taken up once a grant this ledger
                    // entitles the account to shows it is the ledger's (Z59).
                    if try await admitVaultKeys(vaultID) { report.keyReceived = true }
                    if try await fetchCurrentKey(vaultID) { report.keyReceived = true }
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
        for vaultID in sharing.vaults.keys.sorted(by: { $0.uuidString < $1.uuidString })
        where !isOwnerDisputed(vaultID) {
            do {
                await forgetStreamsListedTwice(vaultID, account: account)
                if writing { try await takeOutWhatNoLongerCounts(vaultID) }
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
    /// log"), publishes only while this account may write, and replays its log when what counts has changed. `head`
    /// is the membership head as the run begins, for `sharedEngineDidRun` (S65).
    /// `ownDevices` are this account's registered devices: in a vault whose log is kept whole, the only devices whose
    /// word about this device's own stream moves its numbering (`SyncConfiguration.ownStreamWitnesses`, L-M2).
    /// `ownIDCommits` is `thisDeviceCommits`: a device whose ID does not commit to its account publishes nothing in a
    /// shared vault, where nobody would receive it (review finding Z162).
    func sharedEngineOptions(
        _ vaultID: UUID, base: SyncConfiguration, account: AccountRecord, ownDevices: Set<UUID>, ownIDCommits: Bool
    ) -> (
        configuration: SyncConfiguration, judge: (any WriteJudge)?, publishing: Bool, reconcile: Bool, head: [UInt8]?
    ) {
        guard let vault = sharing.vaults[vaultID] else {
            // Shared, with no ledger here (Z41, V19): there is no judge to give it, so it is never published to and its
            // log is left whole. `syncAll` only downloads for it anyway, having no current key, and `syncVerify`
            // refuses its objects.
            if isMarkedShared(vaultID, keys: keys, personalVaultID: account.personalVaultID) {
                var configuration = base
                configuration.maintainsLog = false
                return (configuration, nil, false, false, nil)
            }
            return (base, nil, true, false, nil)
        }
        var configuration = base
        configuration.maintainsLog = false
        configuration.ownStreamWitnesses = ownDevices
        // Disputed (Z59): downloaded only, like a vault with no ledger here.
        if isOwnerDisputed(vaultID) { return (configuration, nil, false, false, nil) }
        // A replay judges every version again, and notes again which devices' streams it is waiting on and whose
        // revocations it asks about.
        if vault.needsReconcile {
            sharing.vaults[vaultID]?.index.awaiting = []
            sharing.vaults[vaultID]?.index.relied = []
        }
        return (
            configuration, VaultSyncAdapter(session: self),
            ownIDCommits && vault.ledger.writePermission(for: account.accountID).isAllowed, vault.needsReconcile,
            vault.ledger.state.hash.bytes
        )
    }

    /// How many replays of `vaultID` have been asked for so far: what a pass reads before it starts and hands to
    /// `sharedEngineDidRun` (Z120).
    func sharedReplayRequests(_ vaultID: UUID) -> UInt64 {
        sharing.vaults[vaultID]?.replayRequests ?? 0
    }

    /// After a shared vault's engine ran: a replay that finished settles the head it judged against, unless a replay
    /// was asked for while it ran (`requestsBefore` is the count when it started). What the pass learnt then (a
    /// stream's account changed when an earlier segment arrived, a key, a segment inside a cut) can make a version
    /// that the pass's own take-out judged against the old index stop counting, and only a take-out removes it: the
    /// request stays, and the next replay, in this sync or the next, takes out and replays again (review finding
    /// Z120). Settled regardless, it was lost, and the device kept what every other device holds aside. What is settled
    /// is the judged basis (`judgedBasis`): the head, and the revocations what was judged rests on (Z153).
    ///
    /// And only where the take-out before the run, the run's start (`judgedAgainst`, from `sharedEngineOptions`) and
    /// its end saw one head. Membership can be ingested while a run is suspended (`removeMember` and
    /// `leaveSharedVault` ingest before `syncAll`'s guard), and versions admitted earlier in the run were judged against
    /// the earlier head; marking them judged against the new one would keep the next sync from taking out what the new
    /// head no longer counts (review finding S65). A head that moved leaves nothing settled, so the next sync's take-out
    /// runs.
    func sharedEngineDidRun(
        _ vaultID: UUID, reconciled: Bool, judgedAgainst head: [UInt8]?, report: SyncReport, requestsBefore: UInt64
    ) async {
        let basis = reconciled ? await judgedBasis(vaultID) : nil
        guard var vault = sharing.vaults[vaultID] else { return }
        if reconciled, !report.deferredUntilUnlock, !report.transportUnavailable {
            if vault.replayRequests != requestsBefore {
                vault.needsReconcile = true
                vault.index.judgedHead = nil
            } else if takeOutsOwed.contains(vaultID) {
                // A take-out begun for this basis did not finish: the basis is not settled, and the replay stays asked
                // for, so that the next take-out, in this sync or the next, acts on it (review of round 23, Z262).
                vault.needsReconcile = true
            } else if vault.indexRebuilding {
                // The index is whole again: now take out what no longer counts, and replay once more (S41).
                vault.indexRebuilding = false
                vault.needsReconcile = true
                vault.index.judgedHead = nil
            } else {
                vault.needsReconcile = false
                // A basis that cannot be worked out now settles nothing: what was owed stays owed (`judgedHead`
                // unchanged), and the next take-out that can tell decides. One worked out on a head the take-out
                // before the run, or the run's start, did not see settles nothing either (S65).
                if let basis {
                    let current = vault.ledger.state.hash.bytes
                    let unmoved = head != nil && head == vault.takenOutAgainst && head == current
                    vault.index.judgedHead = unmoved ? basis : nil
                }
                // What the replay did not rebuild is held aside whole: gone from the vault, for the hygiene engine too.
                hygieneRuntime?.takenOut = []
            }
            vault.indexChanged = true
            sharing.vaults[vaultID] = vault
        }
    }

    /// Before a replay that this sync asks for: what no longer counts, taken out if the vault's items were last
    /// judged against another head (or the index says it must be done again). A take-out that throws throws here, and
    /// the replay waits for the next sync (review of round 23, Z262): read with `try?`, it was followed at once by the
    /// replay, which settled the basis the take-out had not acted on.
    func prepareSharedReplay(_ vaultID: UUID) async throws {
        try await takeOutWhatNoLongerCounts(vaultID)
    }

    /// Shared vaults whose log must be replayed again in this sync: something learnt while merging (a key, a
    /// segment inside a cut) changes what counts.
    func sharedVaultsNeedingReplay() -> [UUID] {
        sharing.vaults.filter(\.value.needsReconcile).keys.sorted { $0.uuidString < $1.uuidString }
    }

    /// Step 6 of §8.8, after the logs, unlocked: continue a saved plan, plan the removals that are owed and this
    /// account may sign, turn leave requests into rotations as an administrator, and seal again what the ledger
    /// lists. Then save.
    ///
    /// Nothing is sealed again in a vault whose take-out did not finish in this sync's passes (`takeOutsOwed` as the
    /// loop reaches it: the vaults of `AccountSyncReport.takeOutUnfinished`, and an owed vault whose carry did not
    /// finish or whose device ID does not commit, Z262, Z268, Z270), neither by the catch-up reseal nor by a plan's
    /// reseal step (`resumeRotation(resealing: false)`). The reseal's own take-out (S59) would take out what no longer
    /// counts with no replay after it in this sync, so the vault's items stood missing until the next, and the sync
    /// said the take-out had not finished (merged so at round 25, found by `replayLoopTakeOutThatFailsHoldsDeletions`;
    /// the plan's step since the review of PR #22's eighth merge, V71). A plan still revokes the transport's share and
    /// publishes its record, and is kept at `.resealing`, so another owed removal waits for the next sync to be
    /// planned. The next sync's take-out and its replay act together, then the reseal. What waits was already on the
    /// transport under the old key, and the vault publishes nothing while its take-out is owed (Z270), so the wait
    /// exposes nothing to a removed member that sealing again now would not.
    func syncSharedVaultsAfterLogs(account: AccountRecord, reports: inout [UUID: SharedVaultSyncReport]) async {
        guard keys != nil, sharing.settings != nil else { return }
        // Asked as each step is reached: only a take-out that finishes ends it.
        func resealing(_ vaultID: UUID) -> Bool { !takeOutsOwed.contains(vaultID) }
        for vaultID in sharing.vaults.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            var report = reports[vaultID] ?? SharedVaultSyncReport()
            do {
                // Held closed while the account's devices disagree about whose it is (Z59): no plan carried on or
                // made, nothing sealed again.
                if isOwnerDisputed(vaultID) {
                    try await saveSharedVault(vaultID)
                    reports[vaultID] = report
                    continue
                }
                // Read-only past a later format (§8.9): no plan carried on or made, nothing sealed again.
                if try sharedVault(vaultID).ledger.continuesInLaterFormat {
                    report.requiresNewerVersion = true
                    try await saveSharedVault(vaultID)
                    reports[vaultID] = report
                    continue
                }
                if try sharedVault(vaultID).plan != nil {
                    report.rotation = try await resumeRotation(in: vaultID, resealing: resealing(vaultID))
                }
                let ledger = try sharedVault(vaultID).ledger
                for owed in ledger.owedRemovals
                where try sharedVault(vaultID).plan == nil
                    && ledger.mayRemove(owed.accountID, signer: account.accountID)
                {
                    guard (try? await planRotation(owed.reason, in: vaultID)) != nil else { continue }
                    report.rotation = try await resumeRotation(in: vaultID, resealing: resealing(vaultID))
                }
                // Someone outside the vault holds its current key (an addition and its removal lost a fork
                // together, Z43): a routine rotation, by any device whose account administers the vault.
                let current = try sharedVault(vaultID).ledger
                if !current.exposedKeyHolders.isEmpty,
                    try sharedVault(vaultID).plan == nil,
                    ledger.state.member(account.accountID)?.role.isAdministrator == true,
                    (try? await planRotation(.routine, in: vaultID)) != nil
                {
                    report.rotation = try await resumeRotation(in: vaultID, resealing: resealing(vaultID))
                }
                if ledger.state.member(account.accountID)?.role.isAdministrator == true {
                    let objects = try await listSharingObjects(
                        prefix: SharingObjectLocation.leavePrefix(vaultID), maximumLength: LeaveRequest.encodedLength)
                    for request in try sharedVault(vaultID).ledger.pendingLeaveRequests(among: objects)
                    where try sharedVault(vaultID).plan == nil {
                        guard (try? await planRotation(.departure(request), in: vaultID)) != nil else { continue }
                        report.rotation = try await resumeRotation(in: vaultID, resealing: resealing(vaultID))
                    }
                }
                if resealing(vaultID) { report.resealed = try await resealSharedVault(vaultID) }
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
        let epoch = lockEpoch
        var registries: [MemberRegistryAnchor: DeviceRegistryState] = [:]
        var disagreements: Set<MemberRegistryAnchor> = []
        func keep(_ anchor: MemberRegistryAnchor) {
            registries[anchor] = sharing.registries[anchor]
            if sharing.registryDisagreements.contains(anchor) { disagreements.insert(anchor) }
        }
        for (accountID, signingKeys) in anchors.sorted(by: { $0.key.uuidString < $1.key.uuidString }) {
            let anchorsOfAccount = signingKeys.sorted { $0.lexicographicallyPrecedes($1) }.map {
                MemberRegistryAnchor(accountID: accountID, signingKey: $0)
            }
            guard let raw = await fetchMemberRegistry(accountID, transport: transport) else {
                anchorsOfAccount.forEach(keep)
                continue
            }
            // Replays of another account's registry are long work of that account's choosing (Z10): off the actor,
            // on copied inputs, and dropped if a `lock()` came meanwhile, so `lock()` never waits for them.
            let pins = anchorsOfAccount.map { sharing.registryPins[$0] }
            guard
                let evaluations = await awayFromSession(
                    .memberRegistry, unlessLockedSince: epoch,
                    {
                        zip(anchorsOfAccount, pins).map { anchor, pin in
                            Self.evaluateMemberRegistry(
                                raw, accountID: accountID, signingKey: anchor.signingKey, pin: pin)
                        }
                    })
            else { return }
            for (anchor, (pin, evaluated)) in zip(anchorsOfAccount, zip(pins, evaluations)) {
                // What was anchored is not all there now (withheld, or lost), or another refresh moved the pin while
                // this one was away: nothing new is believed, and nothing held is forgotten.
                guard evaluated.complete, sharing.registryPins[anchor] == pin else {
                    keep(anchor)
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

    /// As `awayFromSession`, for work on public data that may run while the session is locked (another member's
    /// registry is refreshed by a locked sync too): `work` runs off the actor, and its result is `nil` if a `lock()`
    /// came meanwhile.
    /// `discarding` is given what `work` produced when it is dropped, to zeroise any key in it.
    func awayFromSession<T: Sendable>(
        _ step: AwayWork, unlessLockedSince epoch: UInt64, discarding: (T) -> Void = { _ in },
        _ work: @escaping @Sendable () -> T
    ) async -> T? {
        let hook = awayWorkHook
        let value = await Task.detached(priority: Task.currentPriority) {
            hook?(step)
            return work()
        }.value
        guard epoch == lockEpoch else {
            discarding(value)
            return nil
        }
        return value
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

    /// The other accounts' registries as `vaultID`'s chain anchors them, by account in a fixed order, each with only
    /// the devices whose IDs commit to that account (`DeviceRegistryState.committedDevicesOnly`, review finding Z157):
    /// a device ID another account's registry lists is no device of this one, so no two registries here list the same
    /// device, and a stream, a value's stamp and a revocation each name one account by identity.
    func memberRegistries(_ vaultID: UUID, account: UUID) -> [(accountID: UUID, state: DeviceRegistryState)] {
        guard let vault = sharing.vaults[vaultID] else { return [] }
        return Self.memberAnchors(of: vault.ledger, excluding: account)
            .sorted { $0.key.uuidString < $1.key.uuidString }
            .compactMap { accountID, signingKey in
                sharing.registries[MemberRegistryAnchor(accountID: accountID, signingKey: signingKey)].map {
                    (accountID, $0.committedDevicesOnly)
                }
            }
    }

    /// This account's own registry as a shared vault counts it: only the devices whose IDs commit to the account
    /// (Z157), as every other member's device counts it.
    static func committedOwnState(_ ownView: RegistryView?) -> DeviceRegistryState? {
        ownView?.state.committedDevicesOnly
    }

    /// The registries `vaultID` counts: this account's own (`committedOwnState`) and the members' (`memberRegistries`),
    /// each less every device ID two of them list (`DeviceRegistryState.listedMoreThanOnce`, round 6's L3). Two
    /// accounts acting together can find colliding committed IDs (a birthday search); kept by whichever registry
    /// arrived first, the stream's account and cut chain differed between devices. Counted as neither's, the same
    /// everywhere. What the judge and `sharedVerify` read, never the two halves alone.
    func countedRegistries(_ vaultID: UUID, ownView: RegistryView?, account: UUID) -> (
        own: DeviceRegistryState?, members: [(accountID: UUID, state: DeviceRegistryState)]
    ) {
        let own = Self.committedOwnState(ownView)
        let members = memberRegistries(vaultID, account: account)
        let twice = DeviceRegistryState.listedMoreThanOnce((own.map { [$0] } ?? []) + members.map(\.state))
        guard !twice.isEmpty else { return (own, members) }
        return (own?.removingDevices(twice), members.map { ($0.accountID, $0.state.removingDevices(twice)) })
    }

    /// The device IDs two of the registries `vaultID` counts list (`countedRegistries`).
    func devicesListedTwice(_ vaultID: UUID, ownView: RegistryView?, account: UUID) -> Set<UUID> {
        let own = Self.committedOwnState(ownView)
        let members = memberRegistries(vaultID, account: account)
        return DeviceRegistryState.listedMoreThanOnce((own.map { [$0] } ?? []) + members.map(\.state))
    }

    /// Forgets what the index recorded of a stream whose device ID two counted registries now list (round 6's L3):
    /// recorded while only one registry listing it was here, under whichever account's arrived first. Nothing of it
    /// verifies now, so a device that saw both registries first never recorded it; forgetting it and asking for a
    /// replay (which takes out what counted through it) leaves this device as that one.
    func forgetStreamsListedTwice(_ vaultID: UUID, account: AccountRecord) async {
        let ownView = try? await registry(account)
        guard let vault = sharing.vaults[vaultID] else { return }
        let recorded = devicesListedTwice(vaultID, ownView: ownView, account: account.accountID).filter {
            vault.index.firstSequence(ofStream: $0) != nil
        }
        guard !recorded.isEmpty else { return }
        for device in recorded { sharing.vaults[vaultID]?.index.forget(stream: device) }
        requestReplay(vaultID)
    }

    /// Password changes replayed side by side when another account's registry forks at the one followed; more than
    /// this many competing changes are not replayed at all, and every device of the account is held in question.
    static let maximumMemberBranches = 8
    /// Password changes one refresh follows forward along another account's registry (review finding Z10). Each
    /// step costs up to `maximumMemberBranches` replays of the registry, and the account chooses how many changes
    /// it publishes; the pin carries what was followed to the next refresh.
    static let memberRegistryStepsPerRefresh = 8

    /// What `evaluateMemberRegistry` made of another account's registry.
    struct MemberRegistryEvaluation: Sendable {
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
        /// The walk stopped at `memberRegistryStepsPerRefresh` with changes still to follow: the next refresh goes on
        /// from `pin`. Until then the account's devices are those registered as of the change reached.
        var moreToFollow = false
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
    /// So no rule here picks between two branches. What this device took once (`pin`: the genesis entry, the
    /// credential entry it first anchored, `base`, and the one it follows now) moves **only forward**, one credential
    /// entry at a time, and only where exactly one change follows that replays as a chain. A change that leaves the
    /// chain before the base is never followed, whatever its generation. One that leaves it at the base or after,
    /// beside a change this device has since followed forward, competes with it (review finding Z12): being published
    /// first earns a branch nothing. Where two or more compete, neither is taken: the registry stays at the entry
    /// they leave, and a device counts only if it is registered there **and in every one of the competing
    /// branches** — each side's revocations are honoured, so neither the device a branch revokes nor the one it keeps
    /// signs anything that counts here, while a device nobody contests carries on. With nothing anchored, more than
    /// one genesis entry anchors none.
    ///
    /// Every such sight is returned as a disagreement, for the screens to say that this person's devices disagree.
    /// Nothing in this version settles one (review finding Z11): the twelve-digit code that once moved an anchor to
    /// the branch the person named was about 40 bits of a value the key holder can grind, the weakness ADR 0010
    /// rejects, and was removed. Re-verifying a member's devices after a fork belongs to the vault sharing code
    /// session of ADR 0010; until that exists a contested registry stays contested, and is reported. What this does
    /// not stop: the key holder can keep the member's contested devices in question for as long as they like, and a
    /// device that anchors while only the forged branch is visible follows it. The cure for both is the account
    /// re-key (F10.1).
    ///
    /// At most `maximumSteps` changes are followed in one call (Z10): the rest are followed by the next, from the pin.
    static func evaluateMemberRegistry(
        _ raw: [[UInt8]], accountID: UUID, signingKey: [UInt8], pin: MemberRegistryPin?,
        maximumSteps: Int = memberRegistryStepsPerRefresh
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
        let tip = pin?.credential ?? genesis
        guard var state = evaluate(genesis, tip) else {
            result.pin = pin
            result.complete = false
            return result
        }
        // Whether `entry` was signed by the enrolment key of the generation it replaces: made with that password.
        func madeWithPassword(_ entry: RegistryEntry, replacing key: [UInt8]) -> Bool {
            (try? Signatures.verify(
                entry.previousCredentialSignature, for: entry.previousCredentialMessage, domain: .deviceRegistry,
                signingKey: key)) != nil
        }

        // The base (review finding Z12): the entry first anchored, which a walk forward never moves. A change beside
        // any followed entry from the base on is a competing branch, however long this device has followed the
        // other: whichever branch was published first is not thereby the account's. Found earliest first; the
        // registry then stands at the entry they leave, and only devices every branch keeps count.
        let path = state.credentialChain
        let baseIndex = pin.map { pin in path.firstIndex { $0.id == pin.base } ?? 0 } ?? path.count - 1
        var branches: [DeviceRegistryState] = []
        var everyDeviceInQuestion = false
        var forkIndex: Int?
        if baseIndex < path.count - 1 {
            let position = Dictionary(uniqueKeysWithValues: path.enumerated().map { ($1.id, $0) })
            var siblings: [Int: [ObjectDigest]] = [:]
            for (id, entry) in entries where position[id] == nil {
                guard case .credential(let generation, _, let previous) = entry.body, let at = position[previous],
                    at >= baseIndex, at < path.count - 1, path[at].generation < .max,
                    generation == path[at].generation + 1, madeWithPassword(entry, replacing: path[at].enrolmentKey)
                else { continue }
                siblings[at, default: []].append(id)
            }
            var budget = maximumMemberBranches
            for at in siblings.keys.sorted() {
                let here = siblings[at, default: []].sorted()
                guard here.count <= budget else {
                    everyDeviceInQuestion = true
                    forkIndex = at
                    result.disagreement.formUnion(here)
                    break
                }
                budget -= here.count
                let followable = here.compactMap { evaluate(genesis, $0) }
                guard !followable.isEmpty, let kept = evaluate(genesis, path[at + 1].id) else { continue }
                forkIndex = at
                branches = followable + [kept]
                result.disagreement.formUnion(followable.map(\.credential.id) + [path[at + 1].id])
                break
            }
            if let forkIndex {
                guard let atFork = evaluate(genesis, path[forkIndex].id) else {
                    result.pin = pin
                    result.complete = false
                    return result
                }
                state = atFork
            }
        }

        // Forward, while exactly one change follows the one followed and replays as a chain.
        for step in 0...maximumSteps where forkIndex == nil {
            let next = state.pendingCredentials.filter { $0.previous == state.credential.id }
            guard !next.isEmpty else { break }
            guard step < maximumSteps else {
                result.moreToFollow = true
                break
            }
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
            guard let replaced, madeWithPassword(entry, replacing: replaced) else { continue }
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
        // At a fork beyond the base the tip followed is kept, so that a branch withheld again is not taken for gone;
        // on first sight the base is where this device lands.
        result.pin = MemberRegistryPin(
            genesis: genesis, base: pin == nil ? state.credential.id : path[baseIndex].id,
            credential: forkIndex == nil ? state.credential.id : tip, settled: pin?.settled)
        result.unsettled =
            !result.disagreement.isEmpty && pin?.settled != Self.disagreementDigest(result.disagreement)
        return result
    }

    static func disagreementDigest(_ entries: Set<ObjectDigest>) -> ObjectDigest {
        ObjectDigest(hashing: Array("WW-devices-settled-v1".utf8) + entries.sorted().flatMap(\.bytes))
    }

    /// The account whose registry, as `vaultID`'s chain anchors it, lists `device`, revoked devices included, since
    /// what a device wrote before its revocation is still its account's work. At most one: a registry counts only the
    /// devices whose IDs commit to its account (Z157), so the list is empty or names the one account the device is.
    func accountsListing(_ device: UUID, in vaultID: UUID, ownView: RegistryView?, account: AccountRecord) -> [UUID] {
        var accounts: [UUID] = []
        let counted = countedRegistries(vaultID, ownView: ownView, account: account.accountID)
        if let own = counted.own, own.devices[device] != nil || own.revoked[device] != nil {
            accounts.append(account.accountID)
        }
        for (accountID, state) in counted.members where state.devices[device] != nil || state.revoked[device] != nil {
            accounts.append(accountID)
        }
        return accounts
    }

    /// The account whose keys signed a sync object: its account key and its device's key in that account's
    /// registry, as the object's own vault's chain anchors it. Only the account the device's ID commits to (Z157):
    /// another account that lists the ID, with a key of its own, signs nothing that verifies here, so every object
    /// that verifies in a device's stream is that device's account's.
    func signingAccount(
        _ signature: [UInt8], over envelope: [UInt8], at location: SyncObjectLocation,
        ownView: RegistryView?, account: AccountRecord
    ) -> UUID? {
        let message = Self.syncSignedMessage(envelope, at: location)
        let counted = countedRegistries(location.vaultID, ownView: ownView, account: account.accountID)
        if let ownView, counted.own?.devices[location.author] != nil,
            (try? Self.verifyDual(
                signature, over: message, domain: .logSegment, author: location.author, view: ownView)) != nil
        {
            return account.accountID
        }
        guard let parts = DualSignature.decode(signature) else { return nil }
        for (accountID, state) in counted.members {
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

    /// The account that signed the object at `sequence` of this device's own stream in `vaultID`, when it is another
    /// member's (round 6's L2, `SharedVaultSyncReport.ownStreamSquattedBy`): its account key's signature and the
    /// signature of a device that account's registry, as the vault's chain anchors it, lists under this device's ID.
    /// The registries as they are, uncommitted: this attributes an object that counts nowhere and decides nothing, so it
    /// is the one place shared-vault code reads a member's listing of a device whose ID does not commit to it. `nil`
    /// for junk, for an object nobody the chain lists signed, and for a vault with no ledger here.
    func ownStreamSigner(at sequence: UInt64, in vaultID: UUID, account: AccountRecord) async -> UUID? {
        guard sharing.vaults[vaultID] != nil, let syncSettings else { return nil }
        let location = SyncObjectLocation.segment(vaultID: vaultID, author: account.deviceID, sequence: sequence)
        guard
            let bytes = try? await syncSettings.transport.fetch(
                location.name, maximumLength: syncSettings.configuration.maximumObjectLength),
            let object = try? SignedObject.parse(bytes), let parts = DualSignature.decode(object.signature),
            let vault = sharing.vaults[vaultID]
        else { return nil }
        let message = Self.syncSignedMessage(object.envelope, at: location)
        let anchors = Self.memberAnchors(of: vault.ledger, excluding: account.accountID)
        for (accountID, signingKey) in anchors.sorted(by: { $0.key.uuidString < $1.key.uuidString }) {
            guard
                let state = sharing.registries[MemberRegistryAnchor(accountID: accountID, signingKey: signingKey)],
                let device = state.devices[location.author] ?? state.revoked[location.author],
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
    /// account the chain lists, under that account's key in the chain. A segment of an account whose writes cannot
    /// count (`nothingCounts`) verifies too, and the judge passes over it in sequence (Z137). A snapshot needs the
    /// owner's account: no device writes one in
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
        // Keys in the chain that differ from this device's pin: the person has been warned, and nothing they sign
        // counts here until that is settled (S39). With no comparison made on the current head (the pins could not be
        // read, or the head moved while locked), nobody's substitution is known, so nothing verifies until one is
        // made; refused objects are fetched again at the next sync (V29).
        guard let check = vault.keyCheck, check.head == vault.ledger.state.hash else {
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
        if check.substituted.contains(signer) {
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
        guard location.kind == .segment || signer == vault.ledger.owner.accountID else {
            throw SyncKeyringError.untrustedAuthor(location.author)
        }
        // A segment of an account whose work cannot count here at all is taken in too, and the judge passes over it in
        // sequence (review finding Z137): refused here, it was never staged anywhere, so every device waited at its
        // own device's stream for good. It can be in no other device's stream: the signer is the account the device
        // ID commits to (Z157).
        switch vault.ledger.writeStanding(of: signer) {
        case .mayWrite:
            return
        case .ended, .nothingCounts:
            guard location.kind == .segment else { throw SyncKeyringError.untrustedAuthor(location.author) }
        }
    }

    /// The devices whose streams a shared vault no longer reads: revoked from their own account (`revokedDevices`, the
    /// same set the judge believes). Never this device by another account's word: no other account lists it (Z157).
    func sharedRetiredAuthors(_ vaultID: UUID, ownView: RegistryView?, account: AccountRecord) -> Set<UUID> {
        guard sharing.vaults[vaultID] != nil else { return [] }
        return revokedDevices(in: vaultID, ownView: ownView, account: account)
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
        //
        // Every segment that verifies in a device's stream is signed by the account the device's ID commits to (Z157),
        // so a stream holds one account's segments and nobody else's. A segment of an account whose work cannot count
        // at all (a member never let write) is not recorded: nothing of it can count, no write cut can run over it
        // (a cut is taken only of an account that could write), and a change of head that lets that account write
        // replays the log, which records it then. Such a member can therefore grow no other device's index (Z146,
        // Z155), and needs no rule about where in a stream it may be recorded.
        guard let keys,
            let signer = signingAccount(signature, over: envelope, at: location, ownView: ownView, account: account),
            var vault = sharing.vaults[location.vaultID],
            Self.mayHaveWritten(signer, in: vault.ledger),
            vault.index.segment(device: location.author, sequence: location.number).map({ !$0.opened && opened })
                ?? true
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
        let firstWas = vault.index.firstSequence(ofStream: location.author)
        vault.index.record(
            device: location.author, sequence: location.number,
            segment: SharedStreamIndex.Segment(
                digest: SharedStreamIndex.digest(name: location.name, envelope: envelope), account: signer,
                entries: entries.map { VersionKey(recordID: $0.recordID, kind: $0.kind.rawValue, version: $0.version) },
                values: values, opened: opened,
                descriptions: entries.compactMap {
                    $0.kind == .vaultMetadata ? $0.envelope.map(SharedStreamIndex.descriptionDigest) : nil
                }))
        vault.indexChanged = true
        sharing.vaults[location.vaultID] = vault
        if let firstWas, let first = vault.index.firstSequence(ofStream: location.author), first < firstWas {
            // An earlier segment of the stream arrived after later ones (a lagging listing, a store that withheld
            // it): a stream whose first segments were missing may have been taken for one collected before sharing
            // (Z144), and what was believed of it is judged again (review finding Z151).
            requestReplay(location.vaultID)
        }
        // A segment inside a cut that this device was waiting for, or a new segment of a device a version was held
        // aside for, can make versions held aside count: judge again (written down, S41).
        if case .ended(let cut, _, _) = vault.ledger.writeStanding(of: signer),
            let position = SyncWriteCut(cut).positions[location.author], location.number <= position.sequence
        {
            requestReplay(location.vaultID)
        }
        // The same for a former administrator who may still write: a segment inside the cut that bounds their
        // descriptions of the vault can make one that was held aside count.
        if case .ended(let cut, _) = vault.ledger.administratorStanding(of: signer),
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

    /// Notes what a snapshot of the vault covers (`SharedStreamIndex.collected`, review finding Z151). Only the owner's
    /// account's snapshots verify in a shared vault (`sharedVerify`), so these are from before it was shared. Coverage
    /// that grows for a device a version waits for asks for a replay: what was missing may be accounted for now.
    func judgeRecordSnapshot(_ location: SyncObjectLocation, covering vector: [UUID: UInt64]) {
        guard location.kind == .snapshot, var vault = sharing.vaults[location.vaultID] else { return }
        var grewForAwaited = false
        for (device, sequence) in vector where sequence > (vault.index.collected[device] ?? 0) {
            vault.index.collected[device] = sequence
            if vault.index.awaiting.contains(device) { grewForAwaited = true }
            vault.indexChanged = true
        }
        sharing.vaults[location.vaultID] = vault
        if grewForAwaited { requestReplay(location.vaultID) }
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
        // Nobody but the owner has ever been listed, on the owner's own device: every object that verifies is the
        // owner's account's, and the vault is judged as that account's other vaults are, which is not at all (Z56).
        if Self.isOwnersAloneHere(current.ledger, account: account.accountID) { return .apply }
        // The signer is the account the stream's device ID commits to (`signingAccount`, Z157): the stream is its, and
        // its standing decides. An account whose work cannot count here at all (a member never let write) has its
        // segments passed over in sequence and nothing of them kept (review finding Z137): refused at download as
        // before, such a segment stopped its own device's stream on every device for good.
        switch current.ledger.writeStanding(of: signer) {
        case .mayWrite:
            return .apply
        case .nothingCounts:
            return .passOver
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
    /// **A vault's description is its administrators' to write** (§8.7; owner decision of 2026-11-17). Its one value
    /// must count as above *and* be an administrator's work: the segment that carried it must be one of an account
    /// that is the owner or an administrator now, or inside the cut of the record that ended its role
    /// (`administratorSegmentCounts`); this device's own, not yet published, counts only while its account holds the
    /// role; and one that no segment held here shows to count is vouched for only by a version that an administrator
    /// wrote, sealed since the record that ended its author's role if one did (`vouchesForDescriptions`). So a
    /// read-write member's rename counts on no device, whoever's row carries it on, and a former administrator's
    /// late one is taken out again.
    ///
    /// A version that does not open here cannot be judged and is held aside; receiving its key replays the log.
    func judgeAdmits(_ record: StoredRecord) async throws -> Bool {
        guard sharing.vaults[record.vaultID] != nil else { return true }
        guard let account = try await loadAccount() else { return false }
        let ownView = try? await registry(account)
        let local = try await store.record(record.key)
        guard let keys else { throw SyncKeyringError.locked }
        guard let vault = sharing.vaults[record.vaultID] else { return true }
        // A chain that has never listed anyone but its owner has one account's devices for writers, and nothing
        // they wrote is held against anything (Z56): what follows weighs one account's work against another's
        // standing. The first record that lists someone else changes the head, and everything is judged then.
        if Self.isOwnersAloneHere(vault.ledger, account: account.accountID) { return true }
        let listing = { (device: UUID) in
            self.accountsListing(device, in: record.vaultID, ownView: ownView, account: account)
        }
        let originKey = VersionKey(recordID: record.recordID, kind: record.kind.rawValue, version: record.version)
        // A vault's description counts only as an administrator's work, on top of everything asked of a value.
        let isDescription = record.kind == .vaultMetadata
        guard
            isDescription
                ? Self.descriptionRowCounts(originKey, of: record, in: vault, listing: listing)
                : Self.counts(originKey, device: record.deviceID, in: vault, listing: listing)
        else { return false }
        guard let values = attributedValues(of: record, keys: keys) else { return false }
        var ownCopy: Set<SharedStreamIndex.ValueKey>?
        let vouched =
            isDescription
            ? Self.vouchesForDescriptions(originKey, of: record, in: vault, account: account)
            : Self.vouchesForUncarriedValues(record, in: vault, account: account.accountID)
        let retired = revokedDevices(in: record.vaultID, ownView: ownView, account: account)
        var awaited: Set<UUID> = []
        var relied: Set<UUID> = []
        var admitted = true
        // Whether this version vouches for a value of a device these accounts list that no segment held here shows to
        // count: the version vouches at all, and every such account could have written the value.
        let vouchesFor = { (accounts: [UUID]) in
            vouched && !accounts.isEmpty
                && accounts.allSatisfy({
                    isDescription
                        ? Self.descriptionMayBeVouched(of: $0, sealedUnder: record.keyID, in: vault.ledger)
                        : Self.mayHaveWritten($0, in: vault.ledger)
                })
        }
        let revisions = Dictionary(values.map { ($0.value, $0.revision.version) }, uniquingKeysWith: max)
        // Every value is filed under the device its stamp names (`attributedValues`).
        for value in Set(values.map(\.value)) {
            if let carriers = vault.index.valueCarriers[value] {
                if carriers.contains(where: {
                    Self.segmentCounts($0.key, sequence: $0.value, in: vault)
                        && (!isDescription || Self.administratorSegmentCounts($0.key, sequence: $0.value, in: vault))
                }) {
                    continue
                }
                // A description whose only carrier *here* does not count may still be one its writer made with the
                // role, in a segment this device passes over: its former author, who holds the current key, can
                // publish the same bytes again late. For a member who joined after a rotation an administrator's
                // version sealed since the role ended vouches for it all the same, as it does for one carried
                // nowhere here; otherwise that author could take the vault's name from every such member (S56).
                guard isDescription, vouchesFor(listing(value.device)) else { return false }
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
                // A name this device wrote and has not published is inside no cut: it counts only while this account
                // holds the role, so one written before this device heard that the role had ended is taken out.
                if isDescription, vault.ledger.administratorStanding(of: account.accountID) != .holdsRole {
                    return false
                }
                continue
            }
            let accounts = listing(value.device)
            if vouchesFor(accounts) { continue }
            if !accounts.isEmpty { relied.insert(value.device) }
            // A stream that will never carry it here: a revoked device's, which is not read again, or one whose first
            // segments were collected before the vault was shared (review finding Z144). Believed of an account that
            // may write, and for a description one that holds the role now (§T, V48, V50), in a version that
            // otherwise counts, and never waited for.
            if !accounts.isEmpty,
                Self.neverCarriesHere(
                    value.device, accounts: accounts, claimed: revisions[value] ?? .max, of: originKey, in: vault,
                    retired: retired)
            {
                if Self.neverCarriedValueCounts(accounts, isDescription: isDescription, in: vault.ledger) { continue }
                admitted = false
                continue
            }
            if !accounts.isEmpty { awaited.insert(value.device) }
            admitted = false
        }
        if admitted, record.kind == .item,
            let item = withoutRaisingWriteClock(record.vaultID, { try? openItem(record, keys: keys) })
        {
            // A version's writer is not asked about its own edits only where the version is known to be that
            // device's: its own stream carried it (a stream is one account's, Z157), or it is this device's own. One
            // that merely names a device, in a snapshot say, is held to that device's stream like anyone's claim.
            let writersOwn =
                record.deviceID == account.deviceID || vault.index.firstCarrier[record.deviceID]?[originKey] != nil
            admitted = Self.knowledgeCounts(
                ItemMerge.effectiveClock(item, origin: Self.origin(record)),
                of: VersionKey(recordID: record.recordID, kind: record.kind.rawValue, version: record.version),
                author: writersOwn ? record.deviceID : nil, judgedBy: account.deviceID,
                ownUnreceived: ownUnreceived(in: local, account: account, view: ownView, listing: listing), in: vault,
                vouched: vouched, retired: retired, listing: listing, awaited: &awaited, relied: &relied)
        }
        noteJudgement(record.vaultID, awaited: awaited, relied: relied, counted: retired)
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
    /// own edits beyond what it published is refused at once, before anything else, since it knows what it wrote
    /// (Z136). A device whose first segment is here and sealed under keys this account was never given cannot be
    /// checked, and a current member's edits there are believed as before; one whose first segment is not here has not
    /// published it yet (a shared vault keeps its whole log), and the claim waits for it (Z136). A version that vouches
    /// (S42) vouches for others' edits as for its values. A device no account lists names nobody's work and is passed
    /// over, unless it is one of this account's own that nobody receives and whose values this device's row holds
    /// (`ownUnreceived`), which is refused unless carried, like this device's own (Z179).
    ///
    /// `author` is the device whose own edits are not asked about: the version's writer, where the version is known
    /// to be its work (`judgeAdmits`), or the device whose stream carried a tombstone. `nil` exempts nobody.
    static func knowledgeCounts(
        _ clock: VersionVector, of record: VersionKey, author: UUID?, judgedBy me: UUID,
        ownUnreceived: (UUID) -> Bool, in vault: SharedVault, vouched: Bool, retired: Set<UUID>,
        listing: (UUID) -> [UUID], awaited: inout Set<UUID>, relied: inout Set<UUID>
    ) -> Bool {
        for (device, count) in clock.entries where device != author {
            let carriers = (vault.index.firstCarrier[device] ?? [:]).filter {
                $0.key.recordID == record.recordID && $0.key.kind == record.kind && $0.key.version >= count
            }
            if carriers.contains(where: { Self.segmentCounts(device, sequence: $0.value, in: vault) }) { continue }
            // A claim about this device's own edits beyond what it published is refused, whatever else is known: it
            // knows what it wrote, and no version vouches for that, nor does a stream it has not published in yet
            // (review finding Z136). So is one about an ID of this account's that no member counts, whose values this
            // device's row holds (`ownUnreceived`; an earlier ID of this installation among them): that work reached
            // nobody, and a claim to have seen it would supersede or erase a copy that is here alone. Both are asked
            // before an ID no account lists is passed over, which every such ID is (Z179).
            if device == me || ownUnreceived(device) { return false }
            let accounts = listing(device)
            guard !accounts.isEmpty else { continue }
            relied.insert(device)
            // A stream that will never show the edits here (review finding Z144): a revoked device's, never read again,
            // so a device that recorded none of it (enrolled, joined or rebuilt its index since) waited for it for
            // good; or the owner's, whose first segments were collected before the vault was shared. Believed of an
            // account that may write, as such a device's own versions are (`counts`): a revoked device publishes
            // nothing any device reads, so a claim about its edits supersedes none yet to come. Never waited for.
            if neverCarriesHere(device, accounts: accounts, claimed: count, of: record, in: vault, retired: retired) {
                if allMayWrite(accounts, in: vault.ledger) { continue }
                if vouched, accounts.allSatisfy({ Self.mayHaveWritten($0, in: vault.ledger) }) { continue }
                return false
            }
            if allMayWrite(accounts, in: vault.ledger) {
                // "Cannot read from its first segment": here and sealed under a key not held. A stream with no first
                // segment here has not published it yet (a shared vault keeps its whole log, Z42), and a claim about
                // it waits for it (Z136): taken for unreadable, a claim about a member who had never published was
                // believed everywhere. The first segment recorded of the stream (`firstSequence(ofStream:)`).
                if vouched || firstSegmentUnopened(device, in: vault) { continue }
                awaited.insert(device)
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

    /// The device IDs of this account whose edits nobody else received (`idsNobodyReceives`, review of round 10, Z179)
    /// and whose values `local`, this device's row of the record, holds, as a test for `knowledgeCounts`: a claim
    /// about one is judged as a claim about this device's own work, refused unless a segment that counts carried it.
    /// Such a value is this account's own work that reached nobody (a copy carried over from an earlier ID), here
    /// alone, and a version or deletion claiming to have seen it would supersede or erase it, and with it release the
    /// deletions parked behind it (`releaseParkedDeletions`). Where this device's row holds none, there is nothing of
    /// that ID's here to supersede, and the claim is passed over as before: so the person's own edit of such a copy,
    /// once it holds no value of the ID, does not hold every member's later edit aside. Fails closed: a row that does
    /// not open counts as holding a value of every such ID, and with this account's registry unreadable every ID no
    /// counted registry lists may be one.
    func ownUnreceived(
        in local: StoredRecord?, account: AccountRecord, view: RegistryView?, listing: @escaping (UUID) -> [UUID]
    ) -> (UUID) -> Bool {
        guard let view else { return { listing($0).isEmpty } }
        let ids = Self.idsNobodyReceives(account: account, view: view, including: account.deviceID)
        guard !ids.isEmpty, let local, local.kind == .item else { return { _ in false } }
        guard let keys, let item = try? openItem(local, keys: keys) else { return { ids.contains($0) } }
        let held = Set(ItemMerge.attributedValues(item, origin: Self.origin(local)).map(\.revision.device))
            .intersection(ids)
        return { held.contains($0) }
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
        if Self.isOwnersAloneHere(vault.ledger, account: account.accountID) { return true }
        let listing = { (device: UUID) in
            self.accountsListing(device, in: location.vaultID, ownView: ownView, account: account)
        }
        let vouched = Self.vouchesForUncarriedValues(sealedUnder: keyID, in: vault, account: account.accountID)
        let retired = revokedDevices(in: location.vaultID, ownView: ownView, account: account)
        var awaited: Set<UUID> = []
        var relied: Set<UUID> = []
        var admitted = true
        let key = VersionKey(recordID: entry.recordID, kind: entry.kind.rawValue, version: entry.version)
        // A segment's tombstone is its author's own (`validate` holds every entry of a segment to the stream's device),
        // so its claims about that device's own edits are not asked about, as for a version its stream carried. A
        // snapshot's entry names whichever device its signer chose: nobody is exempt, the named device included, and
        // a claim about this device's own edits beyond what it published is refused (review finding Z34).
        let author = location.kind == .segment ? entry.device : nil
        let local = try await store.record(RecordKey(recordID: entry.recordID, kind: entry.kind))
        let ownUnreceived = ownUnreceived(in: local, account: account, view: ownView, listing: listing)
        for erasure in ItemErasures(summary: entry.erasure).elements where erasure != .void {
            guard
                Self.knowledgeCounts(
                    erasure.seen, of: key, author: author, judgedBy: account.deviceID, ownUnreceived: ownUnreceived,
                    in: vault, vouched: vouched, retired: retired, listing: listing, awaited: &awaited,
                    relied: &relied)
            else {
                admitted = false
                break
            }
        }
        noteJudgement(location.vaultID, awaited: awaited, relied: relied, counted: retired)
        return admitted
    }

    /// Whether a shared vault is exempt from judging on this device (Z56): its accepted chain has never listed anyone
    /// but its owner, **and this account is that owner** (review finding Z124). Only then is every object that
    /// verifies the owner's account's. On another account's device (a member whose addition lost a fork to records
    /// of the owner's, so that the chain it accepts lists only the owner) this device's own account's signatures
    /// verify first, and its writes, which count nowhere now, would stay; there the vault is judged as any other.
    /// A function of the accepted chain and the device's own account, so it changes only with the head.
    static func isOwnersAloneHere(_ ledger: MembershipLedger, account: UUID) -> Bool {
        ledger.isOwnersAlone && ledger.owner.accountID == account
    }

    /// Whether some of the account's work can count here: it may write, or could once.
    static func mayHaveWritten(_ accountID: UUID, in ledger: MembershipLedger) -> Bool {
        if case .nothingCounts = ledger.writeStanding(of: accountID) { return false }
        return true
    }

    /// Whether a version sealed under `keyID` can vouch for a description as `accountID`'s work: the account is the
    /// owner or an administrator now (every description it signed counts), or it was one and the key was introduced
    /// at or after the record that ended its role or its permission to write, whichever came last, so that whoever
    /// sealed the version held that record and judged the description by its cut. Never while the account's removal
    /// is owed: the record that says what counts is on a branch no key's epoch speaks for.
    static func descriptionMayBeVouched(of accountID: UUID, sealedUnder keyID: UUID, in ledger: MembershipLedger)
        -> Bool
    {
        guard mayHaveWritten(accountID, in: ledger) else { return false }
        switch ledger.administratorStanding(of: accountID) {
        case .holdsRole:
            return true
        case .neverHeld:
            return false
        case .ended:
            guard !ledger.owedRemovals.contains(where: { $0.accountID == accountID }),
                let sealed = ledger.keyEpoch(of: keyID), let ended = ledger.latestCutEpoch(of: accountID)
            else { return false }
            return sealed >= ended
        }
    }

    /// Whether the segment of `device`'s stream at `sequence` counts as an administrator's: its signer is the owner
    /// or an administrator now, or was one and the segment is inside the cut of the record that ended the role
    /// (`MembershipLedger.administratorStanding`). Asked of the segment that carried a vault's description, beside
    /// `segmentCounts`; a segment of a member who was never an administrator carries no description that counts.
    static func administratorSegmentCounts(_ device: UUID, sequence: UInt64, in vault: SharedVault) -> Bool {
        guard let segment = vault.index.segment(device: device, sequence: sequence) else { return false }
        switch vault.ledger.administratorStanding(of: segment.account) {
        case .holdsRole:
            return true
        case .ended(let cut, _):
            return SyncWriteCut(cut).contains(device: device, sequence: sequence, index: vault.index) == true
        case .neverHeld:
            return false
        }
    }

    /// Whether a version of the vault's description vouches for a description that no segment held here shows to
    /// count. As for other values, only for an account the chain never entitled to some key, which passes over the
    /// segments sealed under it (`passesOverSomeKey`). Such a member takes the name on the word of whoever sealed the
    /// version that carries it on, so that must be an administrator's word: the version's own writer is one (its
    /// segment counts as an administrator's; or it is this device's own, unpublished, and this account holds the
    /// role). A member who may not name the vault cannot vouch for a name. When the version was sealed matters
    /// account by account, for the description's author alone (`descriptionMayBeVouched`), not vault-wide as for
    /// items: another member's demotion says nothing about this name.
    static func vouchesForDescriptions(
        _ key: VersionKey, of record: StoredRecord, in vault: SharedVault, account: AccountRecord
    ) -> Bool {
        let ledger = vault.ledger
        guard ledger.keyEpoch(of: record.keyID) != nil, passesOverSomeKey(in: ledger, account: account.accountID)
        else { return false }
        switch descriptionCarriage(key, of: record, in: vault) {
        case .carried(let sequence):
            return administratorSegmentCounts(record.deviceID, sequence: sequence, in: vault)
        case .otherBytes:
            return false
        case .notCarried:
            return record.deviceID == account.deviceID
                && ledger.administratorStanding(of: account.accountID) == .holdsRole
        }
    }

    /// Where the stream of the device a row of the vault's description names carried that exact row.
    enum DescriptionCarriage: Equatable {
        /// Its first segment that carried these bytes.
        case carried(UInt64)
        /// A segment of that stream carried the version, with other bytes: the row is not that device's.
        case otherBytes
        /// No segment of that stream held here carried the version.
        case notCarried
    }

    /// Where `record.deviceID`'s stream carried `record` byte for byte (review finding S61). A version key binds no
    /// bytes, and a row's device is whatever the entry that delivered it says: segments make it their author, but a
    /// snapshot can carry rows of any device. So a member could seal a name of their choosing at a version an
    /// administrator's segment carried, label the row with that administrator's device and deliver it in a snapshot,
    /// and every device that judged the row by its version would take it as the administrator's. A description is
    /// the one record whose row vouches for a value to a newcomer as its writer's word (`vouchesForDescriptions`), so
    /// it is judged by its bytes.
    static func descriptionCarriage(_ key: VersionKey, of record: StoredRecord, in vault: SharedVault)
        -> DescriptionCarriage
    {
        let digest = SharedStreamIndex.descriptionDigest(record.envelope)
        if let sequence = vault.index.descriptionCarriers[record.deviceID]?[digest] { return .carried(sequence) }
        return vault.index.firstCarrier[record.deviceID]?[key] == nil ? .notCarried : .otherBytes
    }

    /// `counts` for a row of the vault's description, by its bytes (`descriptionCarriage`, S61): the segment that
    /// carried these bytes must count; a row whose version that stream carried with other bytes does not count; one
    /// carried nowhere here is judged by who may write, as for any version.
    static func descriptionRowCounts(
        _ key: VersionKey, of record: StoredRecord, in vault: SharedVault, listing: (UUID) -> [UUID]
    ) -> Bool {
        switch descriptionCarriage(key, of: record, in: vault) {
        case .carried(let sequence): return segmentCounts(record.deviceID, sequence: sequence, in: vault)
        case .otherBytes: return false
        case .notCarried: return counts(key, device: record.deviceID, in: vault, listing: listing)
        }
    }

    /// Notes what one judgement waited for and whose revocations it asked about (`awaiting`, `relied`). A judgement made
    /// while the settled basis is current used the revocations as they stand, so the basis moves with it; otherwise
    /// the replay that is due settles it (Z153).
    func noteJudgement(_ vaultID: UUID, awaited: Set<UUID>, relied: Set<UUID>, counted: Set<UUID>) {
        guard let vault = sharing.vaults[vaultID],
            !awaited.isSubset(of: vault.index.awaiting) || !relied.isSubset(of: vault.index.relied)
        else { return }
        let head = vault.ledger.state.hash.bytes
        var index = vault.index
        let before = Self.judgedBasis(head: head, index: index, counted: counted)
        index.awaiting.formUnion(awaited)
        index.relied.formUnion(relied)
        if index.judgedHead == before {
            index.judgedHead = Self.judgedBasis(head: head, index: index, counted: counted)
        }
        sharing.vaults[vaultID]?.index = index
        sharing.vaults[vaultID]?.indexChanged = true
    }

    /// What a replay settles and a change of which takes out and replays (review finding Z153): the head, and the
    /// devices whose revocation counts among those a judgement since the last replay waited for or asked about. A
    /// device's revocation can start counting after a version naming it was held aside waiting for its stream, which
    /// is then never read, and stop counting when a registry lists it again; either changes what counts, and no change
    /// of head follows. Only those devices: every registry change replaying the log would let any member replay it at
    /// will. The head's own hash when none counts, as before.
    static func judgedBasis(head: [UInt8], index: SharedStreamIndex, counted: Set<UUID>) -> [UInt8] {
        let bound = index.relied.union(index.awaiting).intersection(counted).sorted { $0.precedes($1) }
        guard !bound.isEmpty else { return head }
        return ObjectDigest(hashing: Array("WW-judged-v1".utf8) + head + bound.flatMap(SharedBytes.bytes)).bytes
    }

    /// `judgedBasis` for `vaultID` as this device stands now; `nil` for a vault with no ledger here, and when this
    /// account's own registry cannot be read: its revocations are part of the basis, and a basis worked out without
    /// them took out and replayed for nothing (round 5's Lows). Nothing is taken out, nor settled, on a `nil` basis.
    func judgedBasis(_ vaultID: UUID) async -> [UInt8]? {
        guard sharing.vaults[vaultID] != nil, let account = try? await loadAccount(),
            let ownView = try? await registry(account)
        else { return nil }
        guard let vault = sharing.vaults[vaultID] else { return nil }
        return Self.judgedBasis(
            head: vault.ledger.state.hash.bytes, index: vault.index,
            counted: revokedDevices(in: vaultID, ownView: ownView, account: account))
    }

    /// Whether every one of `accounts` may write now.
    static func allMayWrite(_ accounts: [UUID], in ledger: MembershipLedger) -> Bool {
        accounts.allSatisfy { ledger.writeStanding(of: $0) == .mayWrite }
    }

    /// Whether a value of a device whose stream will never carry it here (`neverCarriesHere`) is believed: every one of
    /// `accounts` may write now, and for a vault's description every one also holds the owner's or an administrator's
    /// role now (§T; review of the first merge, I2; V48). Not `descriptionMayBeVouched`, which believes a former
    /// administrator's description in a version sealed under a key introduced at or after the cut that ended the role:
    /// there the version is judged against that cut, and here nothing carried it, so a former administrator who may
    /// still write could stamp a name as one of their own revoked devices' with the current key, and it counted (V50).
    static func neverCarriedValueCounts(
        _ accounts: [UUID], isDescription: Bool, in ledger: MembershipLedger
    ) -> Bool {
        guard allMayWrite(accounts, in: ledger) else { return false }
        return !isDescription || accounts.allSatisfy { ledger.administratorStanding(of: $0) == .holdsRole }
    }

    /// The devices revoked from their own account, in this account's registry or in a member's as `vaultID`'s chain
    /// anchors it. Their streams are not read (`syncRetiredAuthors`), and a shared vault writes no snapshot to hand
    /// their work on, so nothing of theirs is ever waited for (review finding Z144).
    ///
    /// A registry counts only the devices whose IDs commit to its account (`memberRegistries`, Z157), so each
    /// revocation here is one account's of its own device, and no member can revoke another member's device by
    /// listing its ID and revoking it (S33, Z150, round 5's M2): the union is the answer, the same on every device that
    /// holds the same registries. This device is revoked by its own registry, whatever its ID.
    func revokedDevices(in vaultID: UUID, ownView: RegistryView?, account: AccountRecord) -> Set<UUID> {
        var devices: Set<UUID> = []
        if ownView?.state.revoked[account.deviceID] != nil { devices.insert(account.deviceID) }
        guard sharing.vaults[vaultID] != nil else {
            return devices.union(ownView.map { Set($0.state.revoked.keys) } ?? [])
        }
        let counted = countedRegistries(vaultID, ownView: ownView, account: account.accountID)
        if let own = counted.own { devices.formUnion(own.revoked.keys) }
        for (_, state) in counted.members { devices.formUnion(state.revoked.keys) }
        return devices
    }

    /// Whether `device`'s stream will never carry here what was not recorded of it already (review finding Z144): it
    /// is revoked, so its stream is never read again; or it is a device of the owner's account whose first segments
    /// are not here, which in a vault that keeps its whole log only collection before the vault was shared explains
    /// (a stream of another account never lost its first segments, and one that shows none at all has not published
    /// yet, Z136).
    ///
    /// "Collected" only where a snapshot merged here covers the missing segments (`SharedStreamIndex.collected`,
    /// review finding Z151): requireWholeLog (Z42) refuses to share a compacted vault, so a stream whose first segments
    /// are not here has, nearly always, not shown them here yet, and believing claims about it then let any current
    /// writer claim to have seen the owner's device's future edits. And only for what that device can have written
    /// before what its own segments here show (`claimed`, a revision's or clock's version of `record` no higher than
    /// the highest version of that record its stream carried, round 5's L-M3: a version of another record says nothing
    /// about this one's): its later edits are still to come, and a claim beyond them waits for its stream as any other
    /// (S46).
    static func neverCarriesHere(
        _ device: UUID, accounts: [UUID], claimed: UInt64, of record: VersionKey, in vault: SharedVault,
        retired: Set<UUID>
    ) -> Bool {
        if retired.contains(device) { return true }
        guard let first = vault.index.firstSequence(ofStream: device), first > 1,
            (vault.index.collected[device] ?? 0) >= first - 1,
            claimed <= vault.index.highestVersionCarried(by: device, of: record.recordID, kind: record.kind)
        else { return false }
        return accounts.allSatisfy { $0 == vault.ledger.owner.accountID }
    }

    /// Whether the stream's own first segment is segment 1, here, and sealed under a key this device does not hold:
    /// what it carried cannot be checked (S42).
    static func firstSegmentUnopened(_ device: UUID, in vault: SharedVault) -> Bool {
        guard vault.index.firstSequence(ofStream: device) == 1 else { return false }
        return vault.index.segment(device: device, sequence: 1)?.opened == false
    }

    /// The attributable values of a stored version, as the index files them: an item's (`ItemMerge.attributedValues`),
    /// or a vault's description as one value, attributed to the write that chose it (`VaultMetadata.writtenBy`, kept
    /// through every re-seal, so that a description is judged as its writer's and never as its sealer's). `nil` if the
    /// version does not open here.
    func attributedValues(of row: StoredRecord, keys: UnlockedKeys)
        -> [(revision: Revision, value: SharedStreamIndex.ValueKey)]?
    {
        withoutRaisingWriteClock(row.vaultID) { attributedValuesOpening(row, keys: keys) }
    }

    /// Runs `body`, whose opens would raise this device's write clock for `vaultID` (`highestVersionSeen`), and puts
    /// the clock back (review finding S62). The judge opens a version to judge it, and a version it holds aside is
    /// never stored, so no other device's high water moves with it: a member who published a version at the very
    /// top of what the engine accepts (U5) would otherwise lift every device's next write above every other
    /// device's ceiling, and an administrator's next rename, or anyone's next edit, would be quarantined there as
    /// implausible. What is stored raises the clock where it is stored or sealed. Synchronous, so no `lock()` or
    /// merge can land in between.
    func withoutRaisingWriteClock<T>(_ vaultID: UUID, _ body: () -> T) -> T {
        let clock = highestVersionSeen[vaultID]
        defer { highestVersionSeen[vaultID] = clock }
        return body()
    }

    private func attributedValuesOpening(_ row: StoredRecord, keys: UnlockedKeys)
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
            let author = metadata.descriptionStamp(carriedBy: row)
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
        vouchesForUncarriedValues(sealedUnder: record.keyID, in: vault, account: account)
    }

    /// `vouchesForUncarriedValues(_:in:account:)` for whatever was sealed under `keyID`: a version, or the segment
    /// carrying a tombstone.
    static func vouchesForUncarriedValues(sealedUnder keyID: UUID, in vault: SharedVault, account: UUID) -> Bool {
        let ledger = vault.ledger
        guard let sealed = ledger.keyEpoch(of: keyID), passesOverSomeKey(in: ledger, account: account) else {
            return false
        }
        return sealed >= (latestEndingEpoch(in: ledger) ?? 0)
    }

    /// Whether the chain introduced a key it never entitled `account` to: the account joined after a rotation, and
    /// passes over what was sealed under the earlier key.
    static func passesOverSomeKey(in ledger: MembershipLedger, account: UUID) -> Bool {
        Set(ledger.chain.map(\.state.vaultKeyID)).contains { keyID in
            if case SharingError.notEntitledToKey? = error(of: { try ledger.grantSender(forKey: keyID, to: account) }) {
                return true
            }
            return false
        }
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

    /// After a change of head, or of the revocations what was judged rests on (`judgedBasis`, Z153): every local
    /// version of the vault that no longer counts is taken out of the store and held aside (kept in the quarantine,
    /// never published on), and the log is replayed with the judge, so that each record is rebuilt from the versions
    /// that count (§8.7: "taken out, not only kept out").
    func takeOutWhatNoLongerCounts(_ vaultID: UUID) async throws {
        guard sharing.vaults[vaultID] != nil, let syncSettings, let basis = await judgedBasis(vaultID),
            let vault = sharing.vaults[vaultID]
        else { return }
        let head = vault.ledger.state.hash.bytes
        guard vault.index.judgedHead != basis else {
            sharing.vaults[vaultID]?.takenOutAgainst = head
            // An owed take-out may have taken rows out before it threw, and the basis has since come back to the one
            // judged: a replay rebuilds what of them counts, or they stay out of the vault, in the quarantine, until
            // some later replay (review of round 24, Z269).
            if takeOutsOwed.remove(vaultID) != nil { sharing.vaults[vaultID]?.needsReconcile = true }
            return
        }
        guard !vault.indexRebuilding else {
            // Never judged against an index being rebuilt: the replay rebuilds it first.
            sharing.vaults[vaultID]?.needsReconcile = true
            takeOutsOwed.remove(vaultID)
            return
        }
        // Owed until this take-out ends normally: one that throws below leaves the basis for a replay not to settle
        // (`sharedEngineDidRun`, review of round 23, Z262).
        takeOutsOwed.insert(vaultID)
        // What this device wrote and has not published, as its signed sync state has it (Z20). A state that cannot be
        // read throws, and the take-out is left to the next sync, the judged head unmoved (review of PR #22's seventh
        // merge, Z258) and unsettled by any replay until a take-out has run (`takeOutsOwed`, Z262): read as none, it
        // judged a restore's uncarried rows, which no segment carried, and took them out into the quarantine, where
        // nothing carries them.
        let ownDevice = account?.deviceID
        let state = try await syncState?.loadState(vaultID: vaultID)
        let published = state?.published ?? [:]
        // What a restore left under an earlier device ID of this installation and has still to carry over
        // (`SyncState.restoredUnpublished`): this installation's own work, which no segment carried because nobody
        // published it yet, and which the carry writes as this device's (review of round 13, M2). Taken out, it would
        // sit in the quarantine where nothing carries it.
        let restored = state?.restoredUnpublished ?? [:]
        // Unsettled, and saved so, before the first row is taken out (review of round 25, Z274): a take-out that throws
        // after that leaves rows out of the vault that only a replay rebuilds, and `takeOutsOwed`, which asks for one,
        // is in memory. With the judged head kept, a relaunch after the basis came back to it found nothing to take
        // out and asked for no replay (Z269's case, across a relaunch); an unsettled head is taken out and replayed
        // after any relaunch, as `requestReplay` writes its request down (S41). The replay after a take-out that
        // finishes settles it again (`sharedEngineDidRun`). So before a withdrawal of pending deletions, which only the
        // replay makes good too (review of round 26, Z279). The save's immediacy matters only where the process ends
        // before the sync does: the sync's after-logs pass saves the vault too, so it is argued by reading.
        var unsettled = false
        for kind in [EnvelopeKind.item, .vaultMetadata, .scanStatus] {
            for row in try await store.records(in: vaultID, kind: kind) where restored[row.key]?.device != row.deviceID
            {
                guard !(try await judgeAdmits(row)) else { continue }
                // An item of this device's own that nobody else has is remembered as such, signed, in a row that
                // outlives the index: a deletion in another vault may be waiting for it (Z44, Z54, Z121).
                if kind == .item, row.deviceID == ownDevice,
                    !(published[row.key].map { $0 >= RecordStamp(row) } ?? false)
                {
                    sharing.vaults[vaultID]?.ownTakenOut.insert(
                        VersionKey(recordID: row.recordID, kind: kind.rawValue, version: row.version))
                    sharing.vaults[vaultID]?.indexChanged = true
                }
                if !unsettled {
                    try await saveJudgementUnsettled(vaultID)
                    unsettled = true
                }
                try await syncSettings.state.quarantine(SyncEntry(row), vaultID: vaultID)
                // The engine's store, not the session's writer: this is not a deletion to publish.
                try await store.commit(StoreChange(conditionalDeletions: [row.key: row.version]))
                // Not deleted, to be rebuilt by the replay: the hygiene engine keeps what it knows of it (S47).
                if kind == .item { hygieneRuntime?.takenOut.insert(row.recordID) }
            }
        }
        // A deletion this device queued and had not published when its account's permission to write ended is
        // outside the cut, as an edit of that moment is, and does not count either. Left queued it erased the
        // record in every merge here and went out, signed, on the day the account was let write again, with
        // nothing asking (Z57). It is withdrawn, the judged head saved unsettled first (Z279), so that a relaunch
        // replays too; the replay puts back what the log holds of the record.
        if let me = account?.accountID {
            if case .mayWrite = vault.ledger.writeStanding(of: me) {
            } else {
                let pending = try await syncSettings.state.pendingDeletions(vaultID: vaultID)
                if !pending.isEmpty {
                    if !unsettled { try await saveJudgementUnsettled(vaultID) }
                    try await syncSettings.state.removePendingDeletions(pending.mapValues(\.stamp), vaultID: vaultID)
                }
            }
        }
        sharing.vaults[vaultID]?.needsReconcile = true
        // Only if the head did not move while the rows were judged (each judgement suspends).
        let unmoved = sharing.vaults[vaultID]?.ledger.state.hash.bytes == head
        sharing.vaults[vaultID]?.takenOutAgainst = unmoved ? head : nil
        takeOutsOwed.remove(vaultID)
    }

    /// The vault's judged head set to `nil` and the vault saved (review of round 25, Z274): a take-out about to change
    /// what the vault holds writes down first that a replay is owed, as `requestReplay` does (S41).
    private func saveJudgementUnsettled(_ vaultID: UUID) async throws {
        sharing.vaults[vaultID]?.index.judgedHead = nil
        sharing.vaults[vaultID]?.indexChanged = true
        try await saveSharedVault(vaultID)
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

    func recordSnapshot(_ location: SyncObjectLocation, covering vector: [UUID: UInt64]) async throws {
        await session.judgeRecordSnapshot(location, covering: vector)
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
