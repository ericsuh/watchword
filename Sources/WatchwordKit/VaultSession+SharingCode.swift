import Foundation
import WatchwordCrypto
import WatchwordSharing

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
    /// This device's own account, for the screens to show ("You are …"), so each person can compare it with the
    /// account the other screen names.
    public let ownAccount: UUID
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
        sharingCodeRun = nil
        for _ in 0..<SharingCodeLimits.numberDraws {
            let now = await clock.now()
            _ = try requireKeys(since: epoch)
            var starter = SharingCodeStarter.draw(as: bundle, using: &random, at: now)
            do {
                try await starter.publish(on: board, at: now)
            } catch SharingCodeError.sessionTaken {
                continue
            }
            _ = try requireKeys(since: epoch)
            sharingCodeGeneration &+= 1
            sharingCodeRun = SharingCodeRun(side: .starter(starter), generation: sharingCodeGeneration)
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
        sharingCodeRun = nil
        let nonce = SharingNonce.draw(using: &random)
        let now = await clock.now()
        let generation = sharingCodeGeneration
        let joiner = try await SharingCodeJoiner.join(
            number, scanned: scanned, as: bundle, board: board, directory: directory, nonce: nonce, at: now
        ) { try await self.requireSharingCodeUnchanged(epoch: epoch, generation: generation) }
        _ = try requireKeys(since: epoch)
        sharingCodeGeneration &+= 1
        sharingCodeRun = SharingCodeRun(side: .joiner(joiner), generation: sharingCodeGeneration)
        try await pinSharingCodeEvidence(epoch: epoch)
        return try sharingCodeStatusOrThrow()
    }

    // MARK: - Steps

    /// Looks at the board for the session's next message: the reply (starter, which then reveals) or the reveal
    /// (joiner, which checks it opens the commitment).
    @discardableResult
    public func refreshSharingCodeSession() async throws -> SharingCodeStatus {
        let (board, directory) = try sharingCodeSettings()
        let epoch = lockEpoch
        let generation = sharingCodeGeneration
        try await sharingCodeStep { side, now in
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
    public func enterSharingCode(_ typed: String) async throws -> SharingCodeStatus {
        _ = try sharingCodeSettings()
        try await sharingCodeStep { side, now in
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
    public func scanSharingPartnerCode(_ payload: String) async throws -> SharingCodeStatus {
        _ = try sharingCodeSettings()
        try await sharingCodeStep { side, now in
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
    public func confirmScannedSharingPartner(_ account: UUID) async throws -> SharingCodeStatus {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard let run = sharingCodeRun, !run.busy, case .joiner(let joiner) = run.side, joiner.scanned,
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

    // MARK: - After the session

    /// Invites the account this session authenticated (the starter's side of ADR 0010, After the session): the usual
    /// invitation (`invite`: the grant to the pinned bundle and the record that adds them), and the invitation itself
    /// as a board object of the session, signed by this account, so nothing is pasted. One invitation per session.
    public func inviteThroughSharingCode(to vaultID: UUID, as role: MemberRole) async throws -> Invitation {
        let (board, _) = try sharingCodeSettings()
        let epoch = lockEpoch
        guard let run = sharingCodeRun, case .starter(let starter) = run.side, case .verified = starter.phase,
            let partner = starter.joiner?.accountID
        else { throw SharingCodeError.notReady }
        guard run.pinned else { throw SharingError.fingerprintNotVerified }
        guard !run.invitationSent else { throw SharingError.invitationAlreadyCompleted }
        let generation = run.generation
        let invitation = try await invite(partner, to: vaultID, as: role)
        let keys = try requireKeys(since: epoch)
        guard sharingCodeRun?.generation == generation else { throw SharingCodeError.notReady }
        let object = try starter.invitationObject(invitation, signedBy: keys.keyset)
        try await board.create(object.name, contents: object.contents)
        if sharingCodeRun?.generation == generation { sharingCodeRun?.invitationSent = true }
        return invitation
    }

    /// The joiner's side: the invitation the starter sent in this session, verified under the bundle the session
    /// authenticated and bound to this session and account; `nil` while it has not arrived. Accept it with
    /// `acceptInvitation`, which needs the vault's owner pinned: by this session if the starter is the owner, by one
    /// of the person's own with the owner otherwise. Nobody vouches for an owner (ADR 0010, "No vouching").
    public func sharingCodeInvitation() async throws -> Invitation? {
        let (board, _) = try sharingCodeSettings()
        guard let run = sharingCodeRun, case .joiner(let joiner) = run.side else { throw SharingCodeError.notReady }
        guard run.pinned else { throw SharingError.fingerprintNotVerified }
        guard
            let bytes = try await board.fetch(
                SharingBoardName.invitation(joiner.number), maximumLength: SharingCodeJoiner.invitationLength)
        else { return nil }
        return try joiner.openInvitation(bytes)
    }

    /// Replaces the pin of the account this session authenticated when the session's keys differ from the pinned
    /// ones: the person's explicit decision after a "keys changed" warning, settled by a session rather than by the
    /// directory's word. Allowed only where nothing this device holds says otherwise: with `vaultID`, the session's
    /// keys must be the ones that vault's chain lists for the account (the warning the person is resolving); without
    /// one, no shared vault here may list the account with other keys. Every vault's member check is made again.
    public func replacePinFromSharingCode(listedIn vaultID: UUID? = nil) async throws {
        let settings = try sharingSettings()
        let epoch = lockEpoch
        guard let run = sharingCodeRun, let evidence = run.evidence, run.pinConflict else {
            throw SharingCodeError.notReady
        }
        let contact = evidence.contact
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
        let contacts = try verifiedContacts(settings)
        let now = await clock.now()
        let keys = try requireKeys(since: epoch)
        _ = try await contacts.verify(evidence, signedBy: keys.keyset, at: now, replacingPin: true)
        if sharingCodeRun?.generation == run.generation {
            sharingCodeRun?.pinned = true
            sharingCodeRun?.pinConflict = false
        }
        retryUnanchoredVaults()
        await refreshMemberKeyChecks()
    }

    // MARK: - Internals

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
        _ body: (inout SharingCodeRun.Side, Date) async throws -> Void
    ) async throws {
        let epoch = lockEpoch
        _ = try requireKeys()
        guard var run = sharingCodeRun else { throw SharingCodeError.notReady }
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
            retryUnanchoredVaults()
            await refreshMemberKeyChecks()
        }
    }

    /// Makes every shared vault's member check again, after a pin changed, so a member just verified is listed as
    /// such and one whose pin was replaced is checked against it.
    func refreshMemberKeyChecks() async {
        guard let settings = sharing.settings, let contacts = try? verifiedContacts(settings) else { return }
        for (vaultID, vault) in sharing.vaults {
            let check = try? await vault.ledger.checkMemberKeys(against: contacts)
            sharing.vaults[vaultID]?.keyCheck = check
        }
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
                role: .starter, step: step, ownAccount: starter.account.accountID, number: starter.number.grouped,
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
                role: .joiner, step: step, ownAccount: joiner.account.accountID, number: nil,
                scanPayload: joiner.scanPayload, ownCode: joiner.code,
                attemptsLeft: joiner.attemptsLeft, partner: joiner.starter.accountID, pinned: run.pinned,
                keysDifferFromPin: run.pinConflict, scanned: joiner.scanned)
        }
    }
}
