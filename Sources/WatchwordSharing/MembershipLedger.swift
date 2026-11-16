import Foundation
import WatchwordCrypto

/// One device's verified copy of a vault's membership records, and the only source of `MembershipState`
/// (docs/02-architecture.md §8.3).
///
/// **Trust anchor.** Two things, both local: the owner's key bundle, pinned when the vault was created or when the
/// person accepting an invitation confirmed the owner's fingerprint out of band (a `VerifiedContact`); and every
/// valid record this device has already seen, which the ledger holds: the accepted chain and the records on branches
/// that lost a fork. Everything a sync store offers is a candidate, checked against those two.
///
/// **A grow-only set of records, and a function of it.** The ledger only ever *adds* valid records to what it holds,
/// and the accepted chain is a pure function of that set (the fork rule below). So devices that have seen the same
/// records agree, in whatever order and in however many calls the records arrived; a record that loses a fork is
/// kept, so a record built on it later still connects and can change the outcome (review finding S17).
///
/// **What the store can and cannot do** (A1):
/// - *Forge*: no. Every record is signed by an account that the state before it lists as an administrator, back to
///   the owner's pinned key.
/// - *Serve less*: a subset of what the ledger holds changes nothing, so an old listing rolls nothing back.
/// - *Withhold*: yes, as everywhere in sync. The ledger then stays where it is. And by withholding the newest head
///   from an administrator's device it can have that device sign on a stale one, which makes a fork between two
///   honest records. The rule below settles that the same way on every device; what the losing record did is done
///   again by its author (`status(of:)`), and a removal that lost is done again by any device that may
///   (`owedRemovals`). The store chooses *when* a fork becomes visible, never which record wins it.
///
/// **The fork rule.** Among all the paths from the genesis through the valid records held, the accepted chain is the
/// one with
/// 1. the most records signed by the owner; then
/// 2. the most records; then
/// 3. at the first record where two such paths part, the lower hash.
///
/// Why: the accounts that may sign change only in owner-signed records (`MembershipRules`). A former administrator,
/// whose removal or demotion the owner signed, can go back to an epoch at which they still were one and publish
/// a branch of any length, with hashes ground as low as they like; but that branch lacks the owner's record that
/// ended their authority, so it holds fewer owner-signed records and loses on every device, however it is timed
/// (review finding S1). Between paths the owner signed equally often and that part *after* the owner's last record,
/// every signer is an administrator on both: the choice is between equals, and the longer path is the one more
/// devices have built on, so a single record signed on a stale head and released late displaces nothing that has
/// been built on since (S18). A stale device of the owner's own is no different (S19). Because the owner is never
/// removed and may always sign, no outcome leaves a vault without someone able to administer it.
///
/// **Removal wins.** A reorganisation can still drop a record that removed a member (two paths of equal standing, or
/// an isolated device of the owner's). The ledger keeps that record, and while its signer may still remove that
/// member in the accepted state the removal is *owed*: `owedRemovals` lists it, `writePermission` refuses the
/// member's writes and `writeStanding` counts only those the losing record's cut holds, `recordsToReseal` re-seals
/// nothing towards a key the member holds, and the next device that may sign the removal plans it again. A former
/// administrator's records on dead branches owe nothing: their signer has no standing in the accepted state. Nor
/// does a removal that its own branch went on to take back by adding the member again.
public struct MembershipLedger: Sendable {
    /// One valid record with the state it produced.
    public struct Link: Sendable, Hashable {
        public let record: MembershipRecord
        public let state: MembershipState
        /// The record as it is stored and published.
        public let encoded: [UInt8]
    }

    /// A removal on a branch that lost a fork, which still has to happen (the type's documentation, "removal wins").
    public struct OwedRemoval: Sendable, Hashable {
        public let accountID: UUID
        /// What to plan: `.removal`, or `.departure` with the member's own request when they asked to leave.
        public let reason: RotationReason
        /// The record that carried it out on the losing branch.
        public let record: MembershipRecord
        /// Which of the member's writes count while the removal is owed, if they may write in the accepted state:
        /// as that record's own branch left it, its cut included, so that a device which learns of the removal this
        /// way treats what the member wrote after it exactly as a device that saw it adopted would (§8.7).
        /// `.mayWrite` when the record, or the one that holds the cut, was signed by an account that could not sign
        /// it on the accepted head (a former administrator carrying out a departure on a dead branch): the removal
        /// is still owed, and its cut is the one in the record that carries it out again.
        public let standing: WriteStanding
    }

    public let vaultID: UUID
    /// The owner's key bundle this ledger is anchored to.
    public let owner: PublicKeyBundle
    /// The accepted chain; never empty, and `chain[n]` is the record of epoch `n`.
    public private(set) var chain: [Link]
    /// The valid records held that are not in the accepted chain, in order of epoch and then hash. Each one's
    /// predecessor is in `chain` or earlier in this list. At most `MembershipLimits.maximumRetainedBranchRecords`.
    public private(set) var branches: [Link]
    /// Removals carried out on a branch that lost, by a signer who may still remove that member: one per member, in
    /// account order. Plan each again (`RotationPlanner.plan` with `reason`) on a device whose account may.
    public private(set) var owedRemovals: [OwedRemoval]
    /// Records of a format this version cannot read, each signed by the owner as of the record it follows, which
    /// extend a record this ledger holds (docs/02-architecture.md §8.9). Held, and saved with the ledger, so that a
    /// later call that is not offered them again still stops where this one did. At most
    /// `MembershipLimits.maximumLaterFormatRecords`.
    public private(set) var laterFormatRecords: [[UInt8]]

    /// Whether the vault has gone on in a format this version cannot read: a later version's operation (ownership
    /// transfer) signed by the owner. Fail closed: the accepted chain stops at the last record this version
    /// understands on that path, whatever else is offered; this device proposes nothing, plans no rotation and may
    /// not write (`WriteRefusal.requiresNewerVersion`). Updating the app is the way on.
    public var continuesInLaterFormat: Bool {
        !laterFormatRecords.isEmpty
    }

    init(
        vaultID: UUID, owner: PublicKeyBundle, chain: [Link], branches: [Link], owedRemovals: [OwedRemoval],
        laterFormatRecords: [[UInt8]] = []
    ) {
        precondition(!chain.isEmpty)
        self.vaultID = vaultID
        self.owner = owner
        self.chain = chain
        self.branches = branches
        self.owedRemovals = owedRemovals
        self.laterFormatRecords = laterFormatRecords
    }

    /// The current verified state.
    public var state: MembershipState {
        chain[chain.count - 1].state
    }

    public func state(atEpoch epoch: UInt64) -> MembershipState? {
        epoch < UInt64(chain.count) ? chain[Int(epoch)].state : nil
    }

    /// Whether the record with this hash is in the accepted chain.
    public func contains(_ hash: MembershipHash) -> Bool {
        chain.contains { $0.state.hash == hash }
    }

    /// Whether the ledger already holds the record with this hash, in the accepted chain or on a losing branch.
    public func holds(_ hash: MembershipHash) -> Bool {
        contains(hash) || branches.contains { $0.state.hash == hash }
    }

    /// Whether the ledger already holds the record a membership object's name says it is. An integrator listing a
    /// store skips fetching such an object: every copy of a record has the one hash, whatever its signature bytes.
    /// The name is only a hint (a store can file anything under it), which is safe here: a name that lies costs a
    /// fetch, or hides a record its author also published under its true name.
    public func holds(_ location: SharingObjectLocation) -> Bool {
        guard location.vaultID == vaultID, case .membership(let epoch, let hash, _) = location.kind else {
            return false
        }
        if let accepted = state(atEpoch: epoch), accepted.hash == hash { return true }
        return branches.contains { $0.state.epoch == epoch && $0.state.hash == hash }
    }

    /// Whether `accountID` may write to the vault now (PRD F4.5): the question to ask before this device's own
    /// writes. `MembershipState.writePermission` for the current state, except that a member whose removal is owed is
    /// refused (`WriteRefusal.removalPending`). For what another account wrote, ask `writeStanding(of:)`, which says
    /// what counts of the work of an account that may no longer write. Not cryptographic; see
    /// `MembershipState.writePermission(for:)`.
    public func writePermission(for accountID: UUID) -> WritePermission {
        let permission = state.writePermission(for: accountID)
        if permission.isAllowed, continuesInLaterFormat { return .refused(.requiresNewerVersion) }
        guard permission.isAllowed, owedRemovals.contains(where: { $0.accountID == accountID }) else {
            return permission
        }
        return .refused(.removalPending)
    }

    /// Which of `accountID`'s writes count in this vault, as far as this device knows (PRD F4.5; §8.7): the question
    /// to ask before merging anything another account wrote, and again about everything already merged whenever
    /// the head has changed.
    ///
    /// - An account that may write now: everything it signed. This is asked about *now*, not about the time a write
    ///   claims: a former member holds the keys of their time and can date a write as they please.
    /// - An account that could write once and may not now: exactly what is inside the `WriteCut` of the record that
    ///   ended it (the latest such record of the accepted chain; while a removal is owed, `OwedRemoval.standing`).
    ///   The administrator's device that signed that record put there what it had merged of the account's work, so
    ///   the answer is the same on every device and does not depend on when a device heard of the record. A device
    ///   that merged a write outside the cut, because it had not yet seen the record, takes it out again and keeps
    ///   it aside; it never publishes it again, alone or inside a version of its own (review finding S28).
    /// - An account that never could write here, and everyone in a deleted vault: nothing.
    ///
    /// The author of a write is the account whose work it is, not only the account that signed the object it
    /// arrived in: a member's version of a record that carries another account's edits is judged for both (§8.8).
    public func writeStanding(of accountID: UUID) -> WriteStanding {
        let state = self.state
        guard !state.isDeleted else { return .nothingCounts(.vaultDeleted) }
        switch state.writePermission(for: accountID) {
        case .allowed:
            return owedRemovals.first { $0.accountID == accountID }?.standing ?? .mayWrite
        case .refused(let refusal):
            for epoch in chain.indices.dropFirst().reversed() {
                let before = chain[epoch - 1].state
                let record = chain[epoch].record
                if MembershipRules.accountLosingWritePermission(by: record.operation, in: before) == accountID,
                    let author = before.member(accountID)
                {
                    return .ended(cut: record.writeCut, author: author, refusal: refusal)
                }
            }
            return .nothingCounts(refusal)
        }
    }

    /// Whether `accountID` could write to the vault as of `epoch` of the accepted chain: for showing history, never
    /// for deciding whether to merge a write (`writeStanding(of:)`). The current epoch gives `writePermission(for:)`.
    public func writePermission(for accountID: UUID, atEpoch epoch: UInt64) -> WritePermission {
        guard let state = state(atEpoch: epoch) else { return .refused(.unknownEpoch) }
        return epoch == self.state.epoch ? writePermission(for: accountID) : state.writePermission(for: accountID)
    }

    // MARK: - Creating and joining

    /// Creates a vault's chain as its owner: signs the genesis record naming `vaultKey` as the first key.
    public static func create(vaultKey: VaultKey, owner keyset: Keyset) throws -> MembershipLedger {
        let bundle = try keyset.publicKeyBundle()
        let record = try MembershipRecord.signed(
            vaultID: vaultKey.vaultID, epoch: 0, previousHash: .none, operation: .createVault,
            vaultKeyID: vaultKey.key.keyID, keyEpoch: 0,
            entries: [MembershipRecord.Entry(bundle: bundle, role: .owner, since: 0)], by: keyset)
        let state = try MembershipRules.genesisState(
            record, hash: record.hash, vaultID: vaultKey.vaultID, owner: bundle)
        return MembershipLedger(
            vaultID: vaultKey.vaultID, owner: bundle,
            chain: [Link(record: record, state: state, encoded: record.encoded())], branches: [], owedRemovals: [])
    }

    /// Builds a ledger from records a store offers, anchored to an owner whose fingerprint has been verified.
    /// Throws `LedgerError.noGenesis` if none of them is that owner's genesis for `vaultID`.
    ///
    /// For a vault this device has never held. A device that holds, or ever held, a ledger for the vault ingests
    /// into that one instead, so that what it had accepted still counts (`IncomingInvitation.accept`).
    public static func join(vaultID: UUID, owner: VerifiedContact, candidates: [[UInt8]]) throws
        -> (ledger: MembershipLedger, report: IngestReport)
    {
        let resolution = resolve(vaultID: vaultID, owner: owner.bundle, chain: [], branches: [], candidates: candidates)
        guard !resolution.chain.isEmpty else { throw LedgerError.noGenesis }
        return (
            MembershipLedger(
                vaultID: vaultID, owner: owner.bundle, chain: resolution.chain, branches: resolution.branches,
                owedRemovals: resolution.owed, laterFormatRecords: resolution.later),
            resolution.report
        )
    }

    // MARK: - Ingesting

    /// What one `ingest` did.
    public struct IngestReport: Sendable, Hashable {
        public struct Rejection: Sendable, Hashable {
            public enum Reason: Sendable, Hashable {
                /// Not a membership record. Permanent: the same bytes are never one.
                case malformed(SharingFormatError)
                /// Refused by the state before it. Permanent: a record names its predecessor by hash, so the state
                /// it is checked against never changes.
                case invalid(MembershipError)
                /// Its predecessor is not among the valid records held or offered. Not permanent: offer it again
                /// when more has arrived.
                case unconnected
            }
            /// Position in the candidates passed to `ingest`.
            public let index: Int
            public let reason: Reason
        }

        /// Records newly in the accepted chain, in epoch order.
        public var adopted: [MembershipRecord] = []
        /// Records that were in the accepted chain and lost a fork to `adopted`. Their effects are undone, and they
        /// are still held. A removal among them is planned again (`owedRemovals`); a vault key one of them
        /// introduced is no longer the vault's (keep it until nothing is sealed under it).
        public var superseded: [MembershipRecord] = []
        /// Valid candidates on a branch that lost. Not an attack by itself: two administrators acted at once. A
        /// device's own record can land here on its first ingest; ask `status(of:)` about what it proposed.
        public var outranked: [MembershipRecord] = []
        public var rejected: [Rejection] = []
        /// How many valid records on losing branches were let go because the ledger holds
        /// `MembershipLimits.maximumRetainedBranchRecords`. Zero unless someone who is or was an administrator has
        /// signed that many competing records. Nothing is wrong with the accepted chain; but until this is zero
        /// again, offer the store's whole listing in each call rather than only what is new.
        public var forgotten = 0
        /// Signature checks made on candidates: at most one each.
        public var signatureChecks = 0
        /// Steps taken through branches' key histories: at most one per rotation on a candidate's own path.
        public var keyHistorySteps = 0

        public var changedHead: Bool {
            !adopted.isEmpty
        }
    }

    /// Offers records from a store to the ledger. A bad record is reported in `IngestReport.rejected` and changes
    /// nothing; any number of candidates is examined, each at the cost of parsing it and at most one signature check,
    /// so a flood costs time in proportion to itself and hides nothing (review finding S17).
    ///
    /// The result depends only on the valid records held and offered, not on their order or on how they are split
    /// across calls. Offer whatever the store lists under the vault's membership prefix that the ledger does not
    /// hold (`holds`), and offer a record reported `unconnected` again later; offering everything every time is
    /// always right.
    @discardableResult
    public mutating func ingest(_ candidates: [[UInt8]]) -> IngestReport {
        let resolution = MembershipLedger.resolve(
            vaultID: vaultID, owner: owner, chain: chain, branches: branches, candidates: candidates,
            later: laterFormatRecords)
        chain = resolution.chain
        branches = resolution.branches
        owedRemovals = resolution.owed
        laterFormatRecords = resolution.later
        return resolution.report
    }

    private struct Node {
        let link: Link
        let parent: Int?
        /// Owner-signed records on the path from the genesis to this record, itself included.
        let ownerRecords: Int
        /// The nearest record on that path, this one included, that introduced a vault key.
        let introducer: Int
        /// Offered in this call rather than held before it.
        let isNew: Bool
        var children: [Int] = []
        /// The best path through this record: its count of owner-signed records, then its last epoch.
        var bestOwnerRecords = 0
        var bestEpoch: UInt64 = 0
        var isOnChain = false
        /// The epoch at which this record's path leaves the accepted chain; `nil` if they share no record.
        var forkEpoch: UInt64?
        /// This record, or one built on it, is an owed removal.
        var isProtected = false
    }

    /// A record on a losing branch that is an owed removal, before it is known which one stands for its member.
    private struct Carrier {
        let accountID: UUID
        let reason: RotationReason
        let record: MembershipRecord
    }

    private struct Pending {
        let index: Int
        let record: MembershipRecord
        let hash: MembershipHash
        let encoded: [UInt8]
    }

    private struct Resolution {
        var chain: [Link]
        var branches: [Link]
        var owed: [OwedRemoval]
        var later: [[UInt8]] = []
        var report: IngestReport
    }

    /// Adds the valid candidates to the tree of records held and applies the fork rule to the result (the type's
    /// documentation says what the rule is and why). `chain` and `branches` were verified when they were first held
    /// and are not verified again.
    private static func resolve(
        vaultID: UUID, owner: PublicKeyBundle, chain accepted: [Link], branches held: [Link], candidates: [[UInt8]],
        later heldLater: [[UInt8]] = []
    ) -> Resolution {
        var report = IngestReport()
        var nodes: [Node] = []
        var indexByHash: [MembershipHash: Int] = [:]
        // A record is always appended after its predecessor, so a parent's index is below its children's.
        func append(_ link: Link, parent: Int?, isNew: Bool) -> Int {
            let index = nodes.count
            let signedByOwner = link.record.signer == owner.accountID ? 1 : 0
            let introducer: Int
            if let parent, link.state.keyEpoch != link.state.epoch {
                introducer = nodes[parent].introducer
            } else {
                introducer = index
            }
            nodes.append(
                Node(
                    link: link, parent: parent,
                    ownerRecords: (parent.map { nodes[$0].ownerRecords } ?? 0) + signedByOwner,
                    introducer: introducer, isNew: isNew))
            indexByHash[link.state.hash] = index
            if let parent { nodes[parent].children.append(index) }
            return index
        }
        for (position, link) in accepted.enumerated() {
            _ = append(link, parent: position == 0 ? nil : position - 1, isNew: false)
        }
        for link in held {
            // `branches` is in epoch order, so a held record's predecessor is already here; one whose predecessor
            // is not (a second genesis apart) has no place in the tree and is let go.
            if link.record.previousHash == .none {
                _ = append(link, parent: nil, isNew: false)
            } else if let parent = indexByHash[link.record.previousHash] {
                _ = append(link, parent: parent, isNew: false)
            }
        }

        // Parse. Nothing here costs a signature check. Exact copies are dropped; two candidates with one hash but
        // different signature bytes are both kept, so that a copy with a spoilt signature, served first, cannot stand
        // in for the genuine record (review finding S4).
        var pendingByParent: [MembershipHash: [Pending]] = [:]
        var seen: Set<[UInt8]> = []
        // Records of a format this version cannot read: still rejected as malformed, and kept aside to be checked
        // once every record that can be verified has been (§8.9).
        var laterCandidates = heldLater.compactMap(MembershipRecord.laterFormat)
        for (index, bytes) in candidates.enumerated() {
            let record: MembershipRecord
            do {
                record = try MembershipRecord.parse(bytes)
            } catch let error as SharingFormatError {
                report.rejected.append(.init(index: index, reason: .malformed(error)))
                if let later = MembershipRecord.laterFormat(bytes), later.vaultID == vaultID {
                    laterCandidates.append(later)
                }
                continue
            } catch {
                report.rejected.append(.init(index: index, reason: .malformed(.truncated)))
                continue
            }
            guard record.vaultID == vaultID else {
                report.rejected.append(
                    .init(index: index, reason: .invalid(.wrongVault(expected: vaultID, actual: record.vaultID))))
                continue
            }
            let hash = record.hash
            // A copy of a record already held, whatever its signature bytes say, is the record already held.
            guard indexByHash[hash] == nil, seen.insert(bytes).inserted else { continue }
            pendingByParent[record.previousHash, default: []].append(
                Pending(index: index, record: record, hash: hash, encoded: bytes))
        }

        // Whether the path to `node` has used `keyID`: a walk over that path's rotations only, however many records
        // elsewhere in the tree introduced the same ID (review finding S22).
        var keyHistorySteps = 0
        func keyUsed(_ keyID: UUID, onPathTo node: Int) -> Bool {
            var cursor: Int? = nodes[node].introducer
            while let index = cursor {
                keyHistorySteps += 1
                if nodes[index].link.state.vaultKeyID == keyID { return true }
                cursor = nodes[index].parent.map { nodes[$0].introducer }
            }
            return false
        }

        // Verify, outwards from what is already verified.
        var signatureChecks = 0
        var worklist = Array(nodes.indices)
        for pending in pendingByParent.removeValue(forKey: .none) ?? [] where indexByHash[pending.hash] == nil {
            do {
                let state = try MembershipRules.genesisState(
                    pending.record, hash: pending.hash, vaultID: vaultID, owner: owner,
                    signatureChecks: &signatureChecks)
                let link = Link(record: pending.record, state: state, encoded: pending.encoded)
                worklist.append(append(link, parent: nil, isNew: true))
            } catch let error as MembershipError {
                report.rejected.append(.init(index: pending.index, reason: .invalid(error)))
            } catch {
                report.rejected.append(.init(index: pending.index, reason: .invalid(.signatureInvalid)))
            }
        }
        while let parent = worklist.popLast() {
            for pending in pendingByParent.removeValue(forKey: nodes[parent].link.state.hash) ?? []
            where indexByHash[pending.hash] == nil {
                do {
                    let state = try MembershipRules.nextState(
                        pending.record, hash: pending.hash, after: nodes[parent].link.state,
                        keyUsedBefore: { keyUsed($0, onPathTo: parent) }, signatureChecks: &signatureChecks)
                    let link = Link(record: pending.record, state: state, encoded: pending.encoded)
                    worklist.append(append(link, parent: parent, isNew: true))
                } catch let error as MembershipError {
                    report.rejected.append(.init(index: pending.index, reason: .invalid(error)))
                } catch {
                    report.rejected.append(.init(index: pending.index, reason: .invalid(.signatureInvalid)))
                }
            }
        }
        for pending in pendingByParent.values.joined() {
            report.rejected.append(.init(index: pending.index, reason: .unconnected))
        }

        // Fail closed on a later format (§8.9): a record this version cannot read, extending a record held, signed
        // by the account that is the owner in the state it follows. Cheap checks first, then one signature check
        // each; junk in a later format's clothing costs what unsigned junk costs. Where such a record is found, the
        // accepted chain is the path to the record it follows, and stops there.
        var stops: [Int] = []
        var laterKept: [[UInt8]] = []
        var laterSeen: Set<[UInt8]> = []
        for later in laterCandidates where laterSeen.insert(later.encoded).inserted {
            guard laterKept.count < MembershipLimits.maximumLaterFormatRecords,
                let parent = indexByHash[later.previousHash]
            else { continue }
            let before = nodes[parent].link.state
            guard !before.isDeleted, later.vaultID == vaultID, later.epoch == before.epoch + 1,
                let signer = before.member(later.signer), signer.role == .owner
            else { continue }
            signatureChecks += 1
            guard
                (try? Signatures.verify(
                    later.signature, for: later.signedContent, domain: .membership,
                    signingKey: signer.bundle.signingKey)) != nil
            else { continue }
            stops.append(parent)
            laterKept.append(later.encoded)
        }
        laterKept.sort { $0.lexicographicallyPrecedes($1) }

        report.rejected.sort { $0.index < $1.index }
        report.signatureChecks = signatureChecks
        report.keyHistorySteps = keyHistorySteps
        guard !nodes.isEmpty else { return Resolution(chain: [], branches: [], owed: [], report: report) }

        // Rank: children before parents, which is descending index.
        for index in nodes.indices.reversed() {
            var best = (nodes[index].ownerRecords, nodes[index].link.state.epoch)
            for child in nodes[index].children {
                let through = (nodes[child].bestOwnerRecords, nodes[child].bestEpoch)
                if through > best { best = through }
            }
            nodes[index].bestOwnerRecords = best.0
            nodes[index].bestEpoch = best.1
        }
        func preferred(_ a: Int, _ b: Int) -> Bool {
            let left = (nodes[a].bestOwnerRecords, nodes[a].bestEpoch)
            let right = (nodes[b].bestOwnerRecords, nodes[b].bestEpoch)
            return left == right ? nodes[a].link.state.hash < nodes[b].link.state.hash : left > right
        }

        // Walk: the fork rule, unless the vault went on in a later format, when the chain is the path to the earliest
        // record a later one follows (by epoch, then hash) and nothing after it.
        var path: [Int] = []
        let stop = stops.min {
            (nodes[$0].link.state.epoch, nodes[$0].link.state.hash) < (
                nodes[$1].link.state.epoch, nodes[$1].link.state.hash
            )
        }
        if let stop {
            var cursor: Int? = stop
            while let index = cursor {
                path.append(index)
                cursor = nodes[index].parent
            }
            path.reverse()
            for index in path { nodes[index].isOnChain = true }
        } else {
            var next = nodes.indices.filter { nodes[$0].parent == nil }.min(by: preferred)
            while let index = next {
                path.append(index)
                nodes[index].isOnChain = true
                next = nodes[index].children.min(by: preferred)
            }
        }
        let chain = path.map { nodes[$0].link }
        // `path` is never empty here, and its last element is the head.
        let head = nodes[path[path.count - 1]].link.state
        for index in nodes.indices {
            nodes[index].forkEpoch =
                nodes[index].isOnChain
                ? nodes[index].link.state.epoch : nodes[index].parent.flatMap { nodes[$0].forkEpoch }
        }

        // Removal wins: which records on losing branches still have to happen. Not one that its own branch went
        // on to take back by adding the member again: what that branch last meant is that they are a member.
        var carriers: [Int: Carrier] = [:]
        for index in nodes.indices where !nodes[index].isOnChain {
            guard let owed = owedRemoval(of: nodes[index], parent: nodes[index].parent.map { nodes[$0] }, in: head)
            else { continue }
            var takenBack = false
            var cursor = nodes[index].children.min(by: preferred)
            while let below = cursor, !takenBack {
                if case .addMember(let added, _) = nodes[below].link.record.operation, added == owed.accountID {
                    takenBack = true
                }
                cursor = nodes[below].children.min(by: preferred)
            }
            if !takenBack { carriers[index] = owed }
        }
        for index in nodes.indices.reversed() {
            nodes[index].isProtected =
                carriers[index] != nil || nodes[index].children.contains { nodes[$0].isProtected }
        }

        // Keep the losing branches, best-ranked first when there are too many. The order puts every record after
        // its predecessor, so what is kept is still a tree.
        var side = nodes.indices.filter { !nodes[$0].isOnChain }
        if side.count > MembershipLimits.maximumRetainedBranchRecords {
            side.sort { a, b in
                let left = nodes[a]
                let right = nodes[b]
                if left.isProtected != right.isProtected { return left.isProtected }
                if left.bestOwnerRecords != right.bestOwnerRecords {
                    return left.bestOwnerRecords > right.bestOwnerRecords
                }
                if left.link.state.epoch != right.link.state.epoch {
                    return left.link.state.epoch < right.link.state.epoch
                }
                return left.link.state.hash < right.link.state.hash
            }
            report.forgotten = side.count - MembershipLimits.maximumRetainedBranchRecords
            side.removeLast(report.forgotten)
        }
        let branches = side.map { nodes[$0].link }.sorted {
            ($0.state.epoch, $0.state.hash) < ($1.state.epoch, $1.state.hash)
        }
        var owedByAccount: [UUID: (carrier: Carrier, index: Int)] = [:]
        for index in side.sorted(by: {
            (nodes[$0].link.state.epoch, nodes[$0].link.state.hash)
                < (nodes[$1].link.state.epoch, nodes[$1].link.state.hash)
        }) {
            guard let owed = carriers[index] else { continue }
            if let existing = owedByAccount[owed.accountID] {
                // The member's own request says more than an administrator's removal.
                if case .removal = existing.carrier.reason, case .departure = owed.reason {
                    owedByAccount[owed.accountID] = (owed, index)
                }
            } else {
                owedByAccount[owed.accountID] = (owed, index)
            }
        }
        // What counts of the member's writes meanwhile is what the owed record's own path says: the cut of the
        // nearest record on it that ended their permission to write, which is the owed record itself unless that
        // branch had made them read-only first. One walk per member owed, over that record's path only.
        //
        // But the branch is believed only as far as accounts with standing signed it: the owed record itself, and
        // the record that holds the cut, must each be in the accepted chain or signed by an account that could sign
        // the same thing on the accepted head. A departure is owed whoever carried it out, because the member's own
        // signature asked for it, so a former administrator can sign one on a dead branch from any pending leave
        // request; if what their branch says counted, they could have every device set the leaving member's work
        // aside. Without a branch to believe, the member's writes go on counting until the removal is carried out
        // again, with a cut, by an account that may.
        func hasStanding(_ index: Int) -> Bool {
            if nodes[index].isOnChain { return true }
            let record = nodes[index].link.record
            guard let signer = head.member(record.signer), signer.role.isAdministrator else { return false }
            return (try? MembershipRules.authorise(record.operation, by: signer, in: head)) != nil
        }
        func standing(of accountID: UUID, onPathTo index: Int) -> WriteStanding {
            guard hasStanding(index) else { return .mayWrite }
            var cursor = index
            while let parent = nodes[cursor].parent {
                let before = nodes[parent].link.state
                let record = nodes[cursor].link.record
                if MembershipRules.accountLosingWritePermission(by: record.operation, in: before) == accountID,
                    let author = before.member(accountID)
                {
                    guard hasStanding(cursor) else { return .mayWrite }
                    return .ended(cut: record.writeCut, author: author, refusal: .removalPending)
                }
                cursor = parent
            }
            return .nothingCounts(.removalPending)
        }
        let owed = owedByAccount.values.map { entry in
            OwedRemoval(
                accountID: entry.carrier.accountID, reason: entry.carrier.reason, record: entry.carrier.record,
                standing: standing(of: entry.carrier.accountID, onPathTo: entry.index))
        }.sorted { $0.accountID.sharingPrecedes($1.accountID) }

        var shared = 0
        while shared < accepted.count, shared < chain.count, accepted[shared].state.hash == chain[shared].state.hash {
            shared += 1
        }
        report.adopted = chain[shared...].map(\.record)
        report.superseded = accepted[shared...].map(\.record)
        report.outranked = nodes.filter { $0.isNew && !$0.isOnChain }.map(\.link.record)
            .sorted { ($0.epoch, $0.hash) < ($1.epoch, $1.hash) }
        return Resolution(chain: chain, branches: branches, owed: owed, later: laterKept, report: report)
    }

    /// Whether `node`, a record on a losing branch, is a removal that still has to happen in `head`: it removes a
    /// member who is still in `head` in the same stint of membership (added by a record both paths share), and for a
    /// removal by an administrator, its signer may still remove that member in `head`. A departure needs no such
    /// standing: the member's own signature asked for it.
    private static func owedRemoval(of node: Node, parent: Node?, in head: MembershipState) -> Carrier? {
        guard !head.isDeleted, let parent, let forkEpoch = node.forkEpoch else { return nil }
        let record = node.link.record
        func sameStint(_ accountID: UUID) -> Member? {
            guard let now = head.member(accountID), let then = parent.link.state.member(accountID),
                now.since == then.since, now.since <= forkEpoch
            else { return nil }
            return now
        }
        switch record.operation {
        case .removeMember(let accountID):
            guard sameStint(accountID) != nil, let signer = head.member(record.signer),
                signer.role.isAdministrator,
                (try? MembershipRules.authorise(record.operation, by: signer, in: head)) != nil
            else { return nil }
            return Carrier(accountID: accountID, reason: .removal(accountID), record: record)
        case .memberLeft(let accountID, let requestSignature):
            guard let member = sameStint(accountID) else { return nil }
            let request = LeaveRequest(
                vaultID: head.vaultID, accountID: accountID, memberSince: member.since,
                signature: requestSignature)
            return Carrier(accountID: accountID, reason: .departure(request), record: record)
        case .createVault, .addMember, .changeRole, .rotateKey, .deleteVault:
            return nil
        }
    }

    // MARK: - Persistence

    static let checkpointMagic: [UInt8] = Array("WWML".utf8)
    static let checkpointVersion: UInt8 = 2

    private static func checkpointContent(
        account: UUID, vaultID: UUID, owner: PublicKeyBundle, epoch: UInt64, hash: MembershipHash
    ) -> [UInt8] {
        checkpointMagic + [checkpointVersion] + account.sharingBytes + vaultID.sharingBytes
            + owner.keyDigest + SharingBytes.littleEndian(epoch) + hash.bytes
    }

    /// The ledger as one blob for local storage: a checkpoint (this account, the vault, the owner's bundle, the head)
    /// signed by this account's key, then the accepted records, then the records held on losing branches.
    ///
    /// ```
    /// magic "WWML"  formatVersion u8 = 2  account 16  vaultID 16  SHA-256(owner's account ID and keys) 32
    /// headEpoch u64  headHash 32  signature 64
    /// recordCount u32, then per record: length u16, record        (the accepted chain)
    /// branchCount u32, then per record: length u16, record        (losing branches, then `laterFormatRecords`)
    /// ```
    ///
    /// Save it after every `ingest` that adopted, outranked or forgot anything.
    public func persisted(signedBy keyset: Keyset) throws -> [UInt8] {
        let content = MembershipLedger.checkpointContent(
            account: keyset.accountID, vaultID: vaultID, owner: owner, epoch: state.epoch, hash: state.hash)
        var out = content + (try keyset.sign(content, domain: .membership))
        for records in [chain.map(\.encoded), branches.map(\.encoded) + laterFormatRecords] {
            out += SharingBytes.littleEndian(UInt32(records.count))
            for record in records {
                out += SharingBytes.littleEndian(UInt16(record.count)) + record
            }
        }
        return out
    }

    /// Restores a ledger saved by `persisted(signedBy:)`.
    ///
    /// Local storage is not trusted either (A8, with the file): the checkpoint must carry this account's signature
    /// and name this vault and this owner, every record is verified again from the genesis exactly as if a store had
    /// offered it, every record must be valid, and the fork rule applied to them must reach the head the checkpoint
    /// names. A blob that was truncated, had records replaced or added, or was planted whole fails closed
    /// (`LedgerError`). What the signature cannot detect is an older blob of this device's own put back in place of a
    /// newer one; the next `ingest` from the transport moves it forward again.
    public static func restore(
        _ bytes: [UInt8], vaultID: UUID, owner: VerifiedContact, account: PublicKeyBundle
    ) throws -> MembershipLedger {
        var reader = SharingReader(bytes)
        try reader.header(magic: checkpointMagic, version: checkpointVersion)
        let savedAccount = try reader.uuid()
        let savedVault = try reader.uuid()
        let ownerDigest = try reader.read(32)
        let epoch = try reader.uint64()
        guard epoch <= MembershipLimits.maximumEpoch else { throw SharingFormatError.epochOutOfRange(epoch) }
        let hash = MembershipHash(unchecked: try reader.read(MembershipHash.byteCount))
        let signature = try reader.read(64)

        let content = checkpointContent(
            account: account.accountID, vaultID: vaultID, owner: owner.bundle, epoch: epoch, hash: hash)
        guard savedAccount == account.accountID, savedVault == vaultID,
            ownerDigest == owner.bundle.keyDigest,
            (try? Signatures.verify(signature, for: content, domain: .membership, signingKey: account.signingKey))
                != nil
        else { throw LedgerError.checkpointInvalid }

        var records: [[UInt8]] = []
        for limit in [
            Int(MembershipLimits.maximumEpoch) + 1,
            MembershipLimits.maximumRetainedBranchRecords + MembershipLimits.maximumLaterFormatRecords,
        ] {
            let count = Int(try reader.uint32())
            guard count <= limit, count <= reader.remaining / 2 else { throw SharingFormatError.countTooLarge }
            records.reserveCapacity(records.count + count)
            for _ in 0..<count {
                let length = Int(try reader.uint16())
                guard length <= MembershipRecord.maximumLength else { throw SharingFormatError.tooLarge(length) }
                records.append(try reader.read(length))
            }
        }
        try reader.finish()

        let resolution = resolve(vaultID: vaultID, owner: owner.bundle, chain: [], branches: [], candidates: records)
        // Every saved record must be valid, but for the later-format records the ledger held, which this version
        // reports as malformed and holds again (§8.9).
        let later = Set(resolution.later)
        guard resolution.report.rejected.allSatisfy({ later.contains(records[$0.index]) }) else {
            throw LedgerError.savedRecordInvalid
        }
        guard UInt64(resolution.chain.count) == epoch + 1, resolution.chain[Int(epoch)].state.hash == hash else {
            throw LedgerError.rolledBack(expectedEpoch: epoch)
        }
        return MembershipLedger(
            vaultID: vaultID, owner: owner.bundle, chain: resolution.chain, branches: resolution.branches,
            owedRemovals: resolution.owed, laterFormatRecords: resolution.later)
    }
}
