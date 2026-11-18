import Foundation
import WatchwordCrypto
import WatchwordSharing
import WatchwordStore

/// Which invitation `VaultSession.issuedSharingInvitations` keeps: one per vault and invitee.
struct IssuedInvitationKey: Hashable, Sendable {
    let vaultID: UUID
    let invitee: UUID
}

/// A board object a session made, kept so that a retry puts the same bytes there again (signing is randomised).
struct SharingBoardObject: Sendable, Hashable {
    let name: String
    let contents: [UInt8]
}

/// One vault sharing code session as this device runs it (ADR 0010): in memory only, so a lock (`lock()` drops it),
/// a restart, or ten minutes without progress abandons it, and a new one draws everything fresh.
struct SharingCodeRun: Sendable {
    enum Side: Sendable {
        case starter(SharingCodeStarter)
        case joiner(SharingCodeJoiner)
    }

    var side: Side
    /// Bumped by every change of run, so a step that suspended and finds another run in place drops its result.
    let generation: UInt64
    /// A step is running: the next waits for none and is refused (`SharingCodeError.busy`). Two steps at once could
    /// hold two replies, and reveal for the second (ADR 0010, "The reveal is made once").
    var busy = false
    /// The other account's bundle was pinned from this run's evidence.
    var pinned = false
    /// The evidence names keys that differ from the ones pinned for that account (`SharingError.keySubstituted`):
    /// nothing was pinned, and the person decides (`replacePinFromSharingCode`).
    var pinConflict = false
    /// The starter sent its invitation in this run.
    var invitationSent = false
    /// The starter's invitation, once `invite` has issued it (the grant published and the record that adds the joiner
    /// proposed), and the board object that carries it, once signed: a retry delivers these again and never invites a
    /// second time (V22).
    var issued: Invitation?
    var invitationObject: SharingBoardObject?
    /// Joiner: the person said yes to the account a scan named (`confirmScannedSharingPartner`). A scan is pinned
    /// only then, and only once the starter's reveal has made it evidence (ADR 0010, Scans: "the device names what it
    /// is about to pin"; docs/06-adversarial-review.md, V18).
    var scanConfirmed = false

    /// Whether the run's evidence may be pinned now: always for a typed code or a starter's scan, which authenticate
    /// the account the screen already named; for a joiner's scan, only on the person's yes.
    var mayPin: Bool {
        if case .joiner(let joiner) = side, joiner.scanned { return scanConfirmed }
        return true
    }

    var evidence: SharingCodeEvidence? {
        switch side {
        case .starter(let starter): return starter.evidence
        case .joiner(let joiner): return joiner.evidence
        }
    }
}

/// What a vault sharing code session shows (ADR 0010), for the screens. The session decides; this only reports.
public struct SharingCodeStatus: Sendable, Hashable {
    public enum Role: Sendable, Hashable {
        /// Shows the vault sharing code: the inviter.
        case starter
        /// Types or scans it: the invitee.
        case joiner
    }

    public enum Step: Sendable, Hashable {
        /// Starter: show the vault sharing code and its QR code until the other device answers.
        case showNumber
        /// Starter: answered. Type the six digits on the other person's screen, or scan their code.
        case typeTheirCode
        /// Joiner: answered; waiting for the starter's device.
        case waiting
        /// Joiner: show this device's six digits, and type the six on the starter's screen.
        case showCodeAndTypeTheirs
        /// Joiner: the scanned code is evidence (the starter's reveal opened its commitment), and the screen names the
        /// account it is about to pin (`partner`); nothing is pinned until the person says yes
        /// (`confirmScannedSharingPartner`). This device's own code is shown meanwhile, for a starter that types.
        case confirmScannedAccount
        /// The other account was authenticated by this device (typed or scanned) and the person's yes, where one is
        /// asked, was given. The starter now shows its own code; a joiner that scanned still shows its own, for a
        /// starter that types.
        case verified
        case failed(SharingCodeError)
    }

    public let role: Role
    public let step: Step
    /// Which session this is (its generation): a screen passes it back with every step it takes (`run:`), and a step
    /// for a session that has since been replaced, by another window or screen on this device, is refused
    /// (`SharingCodeError.notReady`) rather than taken in whichever session is running (V25).
    public let runID: UInt64
    /// This device's own account, for the screens to show ("You are …"), so each person can compare it with the
    /// account the other screen names.
    public let ownAccount: UUID
    /// This device's own fingerprint (its account ID and keys), which every step of either side shows as the account
    /// check, so that a person whose camera read a code can compare what the scan names with the other screen
    /// (review finding V34: an 8-hex prefix of an account ID, which anyone may choose, can be ground; this cannot
    /// without breaking SHA-512).
    public let ownFingerprint: Fingerprint
    /// The other account's fingerprint as this device holds its bundle, once it knows which it is: a joiner's from
    /// the scanned code or the directory, a starter's from the reply.
    public let partnerFingerprint: Fingerprint?
    /// Starter: the vault sharing code, "1234 5678".
    public let number: String?
    /// What this device shows as a QR code: the starter's `ScannedSharingCode`, or the joiner's `FingerprintCode`.
    public let scanPayload: String?
    /// This device's six digits, "123 456", once they may be shown.
    public let ownCode: String?
    public let attemptsLeft: Int
    /// The other account, once this device knows which it is.
    public let partner: UUID?
    /// The other account was pinned from this session.
    public let pinned: Bool
    /// The session authenticated keys that differ from the ones this device pinned for that account before.
    public let keysDifferFromPin: Bool
    /// Joiner: the starter was authenticated by a scan, so there is nothing to type.
    public let scanned: Bool
}

extension VaultSession {
    // MARK: - Starting and joining

    /// Starts a vault sharing code session as the starter: draws the number, the session and the nonce, and puts the
    /// commitment on the board, drawing a new number while one is taken (at most `SharingCodeLimits.numberDraws`).
    /// Ends any session already running.
    public func startSharingCodeSession() async throws -> SharingCodeStatus {
        let (board, _) = try sharingCodeSettings()
        let epoch = lockEpoch
        let bundle = try requireKeys().keyset.publicKeyBundle()
        // The session this replaces is ended now, not once the new one is on the board: a step of the old one that
        // resumes meanwhile finds another generation and publishes nothing (review finding V20).
        endSharingCodeSession()
        let generation = sharingCodeGeneration
        for _ in 0..<SharingCodeLimits.numberDraws {
            let now = await clock.now()
            try requireSharingCodeUnchanged(epoch: epoch, generation: generation)
            var starter = SharingCodeStarter.draw(as: bundle, using: &random, at: now)
            do {
                try await starter.publish(on: board, at: now)
            } catch SharingCodeError.sessionTaken {
                continue
            }
            // An end, a lock or another start while the board answered wins: this session is not installed.
            try requireSharingCodeUnchanged(epoch: epoch, generation: generation)
            sharingCodeRun = SharingCodeRun(side: .starter(starter), generation: generation)
            return try sharingCodeStatusOrThrow()
        }
        throw SharingCodeError.numbersExhausted
    }

    /// Joins the session whose vault sharing code the person typed. Ends any session already running.
    public func joinSharingCodeSession(number typed: String) async throws -> SharingCodeStatus {
        guard let number = SharingSessionNumber(typed: typed) else { throw SharingCodeError.malformedCode }
        return try await join(number, scanned: nil)
    }

    /// Joins the session of a QR code the camera read from the starter's screen (`ScannedSharingCode`): the number,
    /// and the starter's bundle authenticated by its whole fingerprint, so nothing is typed in that direction. Only
    /// the scanner calls this; a code pasted from anywhere is not a scan (ADR 0010, Scanning).
    public func joinSharingCodeSession(scanned payload: String) async throws -> SharingCodeStatus {
        guard let scanned = try? ScannedSharingCode(scanned: payload) else { throw SharingCodeError.malformedCode }
        return try await join(scanned.number, scanned: scanned)
    }

    private func join(_ number: SharingSessionNumber, scanned: ScannedSharingCode?) async throws -> SharingCodeStatus {
        let (board, directory) = try sharingCodeSettings()
        let epoch = lockEpoch
        let bundle = try requireKeys().keyset.publicKeyBundle()
        // As for a start: the session this replaces ends now, and an end, a lock or another start or join while this
        // one waits on the board or the directory wins (V20).
        endSharingCodeSession()
        let generation = sharingCodeGeneration
        let nonce = SharingNonce.draw(using: &random)
        let now = await clock.now()
        try requireSharingCodeUnchanged(epoch: epoch, generation: generation)
        // One answer per number: a starter session meets one joiner session from this device (V23).
        answeredSharingNumbers = answeredSharingNumbers.filter {
            now.timeIntervalSince($0.value) <= SharingCodeLimits.answeredMemory
        }
        guard answeredSharingNumbers[number.digits] == nil else { throw SharingCodeError.numberAlreadyAnswered }
        let joiner = try await SharingCodeJoiner.join(
            number, scanned: scanned, as: bundle, board: board, directory: directory, nonce: nonce, at: now
        ) {
            try await self.requireSharingCodeUnchanged(epoch: epoch, generation: generation)
            // Remembered before the reply goes out, whatever its create answers.
            await self.rememberAnswered(number, at: now)
        }
        try requireSharingCodeUnchanged(epoch: epoch, generation: generation)
        sharingCodeRun = SharingCodeRun(side: .joiner(joiner), generation: generation)
        try await pinSharingCodeEvidence(epoch: epoch)
        return try sharingCodeStatusOrThrow()
    }

    // MARK: - Steps

    /// Looks at the board for the session's next message: the reply (starter, which then reveals) or the reveal
    /// (joiner, which checks it opens the commitment).
    @discardableResult
    public func refreshSharingCodeSession(run: UInt64? = nil) async throws -> SharingCodeStatus {
        let (board, directory) = try sharingCodeSettings()
        let epoch = lockEpoch
        let generation = sharingCodeGeneration
        try await sharingCodeStep(run: run) { side, now in
            switch side {
            case .starter(var starter):
                defer { side = .starter(starter) }
                try await starter.poll(board: board, directory: directory, at: now) {
                    try await self.requireSharingCodeUnchanged(epoch: epoch, generation: generation)
                }
            case .joiner(var joiner):
                defer { side = .joiner(joiner) }
                try await joiner.poll(board: board, at: now)
            }
        }
        return try sharingCodeStatusOrThrow()
    }

    /// The six digits the person typed from the other device's screen. A match authenticates the other account,
    /// which is pinned; a wrong code uses one of three attempts, and the last ends the session.
    public func enterSharingCode(_ typed: String, run: UInt64? = nil) async throws -> SharingCodeStatus {
        _ = try sharingCodeSettings()
        try await sharingCodeStep(run: run) { side, now in
            switch side {
            case .starter(var starter):
                defer { side = .starter(starter) }
                _ = try starter.enterJoinerCode(typed, at: now)
            case .joiner(var joiner):
                defer { side = .joiner(joiner) }
                _ = try joiner.enterStarterCode(typed, at: now)
            }
        }
        return try sharingCodeStatusOrThrow()
    }

    /// The starter's camera read the joiner's fingerprint code from their screen, in place of typing their six
    /// digits. Only the scanner calls this.
    public func scanSharingPartnerCode(_ payload: String, run: UInt64? = nil) async throws -> SharingCodeStatus {
        _ = try sharingCodeSettings()
        try await sharingCodeStep(run: run) { side, now in
            guard case .starter(var starter) = side else { throw SharingCodeError.notReady }
            defer { side = .starter(starter) }
            _ = try starter.scanJoinerCode(payload, at: now)
        }
        return try sharingCodeStatusOrThrow()
    }

    /// The session as it stands, or `nil` if none is running.
    public func sharingCodeStatus() -> SharingCodeStatus? {
        guard let run = sharingCodeRun else { return nil }
        return Self.status(of: run)
    }

    /// Joiner: the person said yes to pinning the account a scan named (`SharingCodeStatus.Step.confirmScannedAccount`,
    /// whose `partner` must be `account`). Pins it, or records that it conflicts with the pin already there.
    public func confirmScannedSharingPartner(_ account: UUID, run runID: UInt64? = nil) async throws
        -> SharingCodeStatus
    {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let run = sharingCodeRun, runID == nil || runID == run.generation, !run.busy,
            case .joiner(let joiner) = run.side, joiner.scanned,
            case .verified = joiner.phase, joiner.evidence != nil, joiner.starter.accountID == account
        else { throw SharingCodeError.notReady }
        sharingCodeRun?.scanConfirmed = true
        try await pinSharingCodeEvidence(epoch: epoch)
        return try sharingCodeStatusOrThrow()
    }

    /// Ends the session, wherever it is. Nothing it pinned is undone; evidence it had not pinned (a scan the person
    /// had not said yes to) goes with it.
    public func endSharingCodeSession() {
        sharingCodeRun = nil
        sharingCodeGeneration &+= 1
    }

    /// Ends the session `run` names, if it is still the one running; another (a second window's) is left alone.
    public func endSharingCodeSession(run: UInt64) {
        guard sharingCodeRun?.generation == run else { return }
        endSharingCodeSession()
    }

    // MARK: - After the session

    /// Invites the account this session authenticated (the starter's side of ADR 0010, After the session): the usual
    /// invitation (`invite`: the grant to the pinned bundle and the record that adds them), and the invitation itself
    /// as a board object of the session, signed by this account, so nothing is pasted. One invitation per session.
    ///
    /// Resumable (V22): once `invite` has issued the invitation the run keeps it and its signed object, so a retry
    /// after a failed delivery delivers the same bytes again and never invites a second time. A slot already holding
    /// those bytes (a create whose answer was lost) counts as delivered; one holding anything else (someone who heard
    /// the number took it) throws `SharedVaultError.invitationNotDelivered` with the invitation, for the screen to hand
    /// over as text.
    ///
    /// `checked` is the status the screen showed when the person chose to send: the invitation goes to its partner,
    /// in its session, or nowhere. Another session that replaced it (a second window's) is never the one invited
    /// (V25).
    public func inviteThroughSharingCode(to vaultID: UUID, as role: MemberRole, checked: SharingCodeStatus)
        async throws -> Invitation
    {
        let (board, _) = try sharingCodeSettings()
        let epoch = lockEpoch
        guard let run = sharingCodeRun, run.generation == checked.runID, case .starter(let starter) = run.side,
            case .verified = starter.phase, let partner = starter.joiner?.accountID, partner == checked.partner
        else { throw SharingCodeError.notReady }
        guard run.pinned else { throw SharingError.fingerprintNotVerified }
        guard !run.invitationSent else { throw SharingError.invitationAlreadyCompleted }
        let generation = run.generation
        let kept = IssuedInvitationKey(vaultID: vaultID, invitee: partner)
        let invitation: Invitation
        if let issued = run.issued {
            guard issued.vaultID == vaultID else { throw SharingError.invitationAlreadyCompleted }
            invitation = issued
        } else if let issued = issuedSharingInvitations[kept] {
            // Issued by an earlier run that ended before delivering it (V35): delivered now, never issued again.
            invitation = issued
            sharingCodeRun?.issued = issued
        } else {
            invitation = try await invite(partner, to: vaultID, as: role)
            // The chain has changed: remember what was issued before anything else can fail, outside the run too.
            issuedSharingInvitations[kept] = invitation
            // A run replaced meanwhile cannot deliver it, and the screen is told so with the invitation (V35).
            guard sharingCodeRun?.generation == generation else {
                throw SharedVaultError.invitationNotDelivered(invitation)
            }
            sharingCodeRun?.issued = invitation
        }
        let keys = try requireKeys(since: epoch)
        guard sharingCodeRun?.generation == generation else {
            throw SharedVaultError.invitationNotDelivered(invitation)
        }
        let object: SharingBoardObject
        if let signed = sharingCodeRun?.invitationObject {
            object = signed
        } else {
            let made = try starter.invitationObject(invitation, signedBy: keys.keyset)
            object = SharingBoardObject(name: made.name, contents: made.contents)
            sharingCodeRun?.invitationObject = object
        }
        do {
            try await board.create(object.name, contents: object.contents)
        } catch SharingBoardError.taken {
            let there = try await board.fetch(object.name, maximumLength: SharingCodeJoiner.invitationLength)
            guard there == object.contents else { throw SharedVaultError.invitationNotDelivered(invitation) }
        }
        if sharingCodeRun?.generation == generation { sharingCodeRun?.invitationSent = true }
        issuedSharingInvitations[kept] = nil
        return invitation
    }

    /// An invitation `inviteThroughSharingCode` issued to `invitee` for `vaultID` and could not deliver (V35), for a
    /// screen to hand over as text (`SharingCodes.text(for:)`): the invitee is added and holds a grant, and inviting
    /// them again is refused. `nil` when there is none.
    public func undeliveredInvitation(to vaultID: UUID, for invitee: UUID) -> Invitation? {
        issuedSharingInvitations[IssuedInvitationKey(vaultID: vaultID, invitee: invitee)]
    }

    /// The joiner's side: the invitation the starter sent in this session, verified under the bundle the session
    /// authenticated and bound to this session and account; `nil` while it has not arrived. Accept it with
    /// `acceptInvitation`, which needs the vault's owner pinned: by this session if the starter is the owner, by one
    /// of the person's own with the owner otherwise. Nobody vouches for an owner (ADR 0010, "No vouching").
    public func sharingCodeInvitation(run runID: UInt64? = nil) async throws -> Invitation? {
        let (board, _) = try sharingCodeSettings()
        guard let run = sharingCodeRun, runID == nil || runID == run.generation, case .joiner(let joiner) = run.side
        else { throw SharingCodeError.notReady }
        guard run.pinned else { throw SharingError.fingerprintNotVerified }
        guard
            let bytes = try await board.fetch(
                joiner.invitationName, maximumLength: SharingCodeJoiner.invitationLength)
        else { return nil }
        return try joiner.openInvitation(bytes)
    }

    /// Replaces the pin of the account this session authenticated when the session's keys differ from the pinned
    /// ones: the person's explicit decision after a "keys changed" warning, settled by a session rather than by the
    /// directory's word. Allowed only where nothing this device holds says otherwise: with `vaultID`, the session's
    /// keys must be the ones that vault's chain lists for the account (the warning the person is resolving); without
    /// one, no shared vault here may list the account with other keys. Every vault's member check is made again.
    public func replacePinFromSharingCode(listedIn vaultID: UUID? = nil, run runID: UInt64? = nil) async throws {
        let settings = try sharingSettings()
        let epoch = lockEpoch
        guard let run = sharingCodeRun, runID == nil || runID == run.generation, let evidence = run.evidence,
            run.pinConflict
        else {
            throw SharingCodeError.notReady
        }
        let contact = evidence.contact
        // Every shared vault this device holds, loaded first: one not loaded yet, or unavailable here, could list the
        // account with other keys, and this device cannot tell (V28).
        await loadSharedVaultsIfNeeded()
        try requirePinReplaceable(contact, listedIn: vaultID)
        let contacts = try verifiedContacts(settings)
        let now = await clock.now()
        let keys = try requireKeys(since: epoch)
        // Again after the last suspension: a load or an ingest may have landed meanwhile.
        try requirePinReplaceable(contact, listedIn: vaultID)
        guard sharingCodeRun?.generation == run.generation else { throw SharingCodeError.notReady }
        _ = try await contacts.verify(evidence, signedBy: keys.keyset, at: now, replacingPin: true)
        if sharingCodeRun?.generation == run.generation {
            sharingCodeRun?.pinned = true
            sharingCodeRun?.pinConflict = false
        }
        retryUnrestoredVaults()
        await refreshMemberKeyChecks()
    }

    // MARK: - Internals

    /// Whether nothing this device holds says otherwise about replacing the pin of `contact.accountID` with `contact`:
    /// with `vaultID`, that vault's chain must list these keys for the account; without, no loaded shared vault may
    /// list the account with other keys. Either way the shared vaults must have been loaded, and no shared vault that
    /// is unavailable here may be owned by the account (V28): its chain is one this device cannot read, and a pin of
    /// its owner replaced on a session's word would be what an invitation for it is accepted on. Scoped to that
    /// owner (V33): one damaged or planted row does not stop every other pin being replaced. A vault whose owner this
    /// device cannot name (no marker: a saved owner row is not signed, V42) still refuses every replacement.
    func requirePinReplaceable(_ contact: PublicKeyBundle, listedIn vaultID: UUID?) throws {
        guard sharing.loaded, sharing.markersLoaded, let account else {
            throw SharedVaultError.sharingCodeKeysNotListed
        }
        for owner in unavailableVaultOwners(account: account) where owner == nil || owner == contact.accountID {
            throw SharedVaultError.sharingCodeKeysNotListed
        }
        if let vaultID {
            guard let member = try sharedVault(vaultID).ledger.state.member(contact.accountID),
                member.bundle.hasSameKeys(as: contact)
            else { throw SharedVaultError.sharingCodeKeysNotListed }
        } else {
            for vault in sharing.vaults.values {
                if let member = vault.ledger.state.member(contact.accountID), !member.bundle.hasSameKeys(as: contact) {
                    throw SharedVaultError.sharingCodeKeysNotListed
                }
            }
        }
    }

    /// The owner of each shared vault that is unavailable here, as far as this device can name them: the account's
    /// marker; `nil` where there is none, or where the account's markers disagree. Never the saved `.owner` row, which
    /// is not signed: A8 rewriting it to another contact would have scoped the guard to that contact and left the real
    /// owner's pin replaceable on a session's word (review of V31 to V37, L2; docs/06-adversarial-review.md V42). The
    /// row still words a vault that lacks only its owner's pin (`unavailableSharedVaults`), which decides nothing.
    func unavailableVaultOwners(account: AccountRecord) -> [UUID?] {
        let granted = keys?.vaultKeys.values.filter(\.arrivedByGrant).map(\.vaultID) ?? []
        let candidates = Set(sharing.markers.keys).union(sharing.unrestored.keys).union(granted)
        return candidates.sorted { $0.uuidString < $1.uuidString }.compactMap { vaultID -> UUID?? in
            guard isSharedUnavailable(vaultID, keys: keys, personalVaultID: account.personalVaultID) else {
                return nil
            }
            if sharing.markerConflicts.contains(vaultID) { return .some(nil) }
            return .some(sharing.markers[vaultID])
        }
    }

    func rememberAnswered(_ number: SharingSessionNumber, at now: Date) {
        answeredSharingNumbers[number.digits] = now
    }

    /// Throws if the vault locked, or the session changed, since `epoch` and `generation`: what a step checks before it
    /// puts anything on the board.
    func requireSharingCodeUnchanged(epoch: UInt64, generation: UInt64) throws {
        _ = try requireKeys(since: epoch)
        guard sharingCodeGeneration == generation else { throw SharingCodeError.notReady }
    }

    func sharingCodeSettings() throws -> (board: any SharingBoard, directory: any KeyBundleDirectory) {
        let settings = try sharingSettings()
        guard let board = settings.board else { throw SharedVaultError.sharingBoardNotConfigured }
        return (board, settings.directory)
    }

    /// Runs one step of the session on a copy, one at a time, and keeps its result only if the run is still the one
    /// it began on and the vault has not locked since; then pins what the step evidenced. A step that ends the session
    /// leaves the failed run in place, so the screen shows why.
    private func sharingCodeStep(
        run runID: UInt64?, _ body: (inout SharingCodeRun.Side, Date) async throws -> Void
    ) async throws {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard var run = sharingCodeRun, runID == nil || runID == run.generation else {
            throw SharingCodeError.notReady
        }
        guard !run.busy else { throw SharingCodeError.busy }
        let generation = run.generation
        sharingCodeRun?.busy = true
        let now = await clock.now()
        var side = run.side
        var thrown: (any Error)?
        do {
            try await body(&side, now)
        } catch {
            thrown = error
        }
        // A lock dropped the run (and the keys): `lock()` wins.
        _ = try requireKeys(since: epoch)
        guard sharingCodeRun?.generation == generation, let current = sharingCodeRun else {
            throw SharingCodeError.notReady
        }
        run.side = side
        run.busy = false
        run.pinned = current.pinned
        run.pinConflict = current.pinConflict
        run.invitationSent = current.invitationSent
        run.issued = current.issued
        run.invitationObject = current.invitationObject
        run.scanConfirmed = current.scanConfirmed
        sharingCodeRun = run
        if let thrown { throw thrown }
        try await pinSharingCodeEvidence(epoch: epoch)
    }

    /// Pins the other account from the run's evidence, once. A different pin already there is not replaced: the run
    /// records the conflict for the person (`keysDifferFromPin`). The pin is signed with the keyset as it is after
    /// the last suspension, so `lock()` wins.
    private func pinSharingCodeEvidence(epoch: UInt64) async throws {
        guard let run = sharingCodeRun, !run.pinned, !run.pinConflict, run.mayPin, let evidence = run.evidence else {
            return
        }
        let settings = try sharingSettings()
        let contacts = try verifiedContacts(settings)
        let now = await clock.now()
        let keys = try requireKeys(since: epoch)
        var pinned = false
        var conflict = false
        do {
            _ = try await contacts.verify(evidence, signedBy: keys.keyset, at: now)
            pinned = true
        } catch SharingError.keySubstituted {
            conflict = true
        }
        _ = try requireKeys(since: epoch)
        guard sharingCodeRun?.generation == run.generation else { return }
        sharingCodeRun?.pinned = pinned
        sharingCodeRun?.pinConflict = conflict
        if pinned {
            retryUnrestoredVaults()
            await refreshMemberKeyChecks()
        }
    }

    /// Makes every shared vault's member check again, after a pin changed, so a member just verified is listed as
    /// such and one whose pin was replaced is checked against it.
    func refreshMemberKeyChecks() async {
        guard let settings = sharing.settings, let contacts = try? verifiedContacts(settings) else { return }
        for (vaultID, vault) in sharing.vaults {
            guard let check = try? await vault.ledger.checkMemberKeys(against: contacts) else { continue }
            storeMemberKeyCheck(check, for: vaultID)
        }
    }

    /// Keeps a member-key check only if it was made on the head the vault has now (V29): the actor is re-entrant, and
    /// an ingest that moved the head while the check awaited the pin store has stored the check of the new head. A
    /// check is never replaced by none; `sharedVerify` refuses while the kept one is not for the current head.
    func storeMemberKeyCheck(_ check: MemberKeyCheck, for vaultID: UUID) {
        guard sharing.vaults[vaultID]?.ledger.state.hash == check.head else { return }
        sharing.vaults[vaultID]?.keyCheck = check
    }

    private func sharingCodeStatusOrThrow() throws -> SharingCodeStatus {
        guard let run = sharingCodeRun else { throw SharingCodeError.notReady }
        return Self.status(of: run)
    }

    static func status(of run: SharingCodeRun) -> SharingCodeStatus {
        switch run.side {
        case .starter(let starter):
            let step: SharingCodeStatus.Step
            switch starter.phase {
            case .drawn, .awaitingReply: step = .showNumber
            case .awaitingJoinerCode: step = .typeTheirCode
            case .verified: step = .verified
            case .failed(let error): step = .failed(error)
            }
            return SharingCodeStatus(
                role: .starter, step: step, runID: run.generation, ownAccount: starter.account.accountID,
                ownFingerprint: starter.account.fingerprint, partnerFingerprint: starter.joiner?.fingerprint,
                number: starter.number.grouped,
                scanPayload: starter.scanPayload,
                ownCode: starter.code, attemptsLeft: starter.attemptsLeft, partner: starter.joiner?.accountID,
                pinned: run.pinned, keysDifferFromPin: run.pinConflict, scanned: false)
        case .joiner(let joiner):
            let step: SharingCodeStatus.Step
            switch joiner.phase {
            // A scan is never "verified" before the starter's reveal made it evidence and the person said yes (V18).
            case .awaitingReveal: step = .waiting
            case .awaitingStarterCode: step = .showCodeAndTypeTheirs
            case .verified:
                step = joiner.scanned && !run.pinned && !run.pinConflict ? .confirmScannedAccount : .verified
            case .failed(let error): step = .failed(error)
            }
            return SharingCodeStatus(
                role: .joiner, step: step, runID: run.generation, ownAccount: joiner.account.accountID,
                ownFingerprint: joiner.account.fingerprint, partnerFingerprint: joiner.starter.fingerprint, number: nil,
                scanPayload: joiner.scanPayload, ownCode: joiner.code,
                attemptsLeft: joiner.attemptsLeft, partner: joiner.starter.accountID, pinned: run.pinned,
                keysDifferFromPin: run.pinConflict, scanned: joiner.scanned)
        }
    }
}
