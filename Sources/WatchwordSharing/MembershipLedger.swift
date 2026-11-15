import Foundation
import WatchwordCrypto

/// One device's verified copy of a vault's membership chain, and the only source of `MembershipState`
/// (docs/02-architecture.md §8.3).
///
/// **Trust anchor.** Two things, both local: the owner's key bundle, pinned when the vault was created or when the
/// person accepting an invitation confirmed the owner's fingerprint out of band (a `VerifiedContact`); and the chain
/// this device has already accepted, which the ledger holds. Everything a sync store offers is a candidate, checked
/// against those two.
///
/// **What the store cannot do** (A1), because candidates are only ever added to the accepted chain's tree:
/// - *Forge*: every record is signed by an account that the state before it lists as an administrator, back to the
///   owner's pinned key.
/// - *Roll back*: a shorter chain is a subset of what the ledger holds, so it changes nothing.
/// - *Fork at will*: a second record at an epoch needs a genuine administrator's signature, and which branch wins
///   is the rule below, not the store's choice or the order of arrival.
/// - *Withhold* is all that is left to it, as everywhere in sync: the ledger then simply stays where it is.
///
/// **Concurrent administrators.** Records are named by their hash, so two administrators acting on the same epoch
/// produce two objects, and every device chooses between them the same way (`MembershipLedger.ingest`): at each fork
/// the branch whose first owner-signed record comes earliest wins, and between branches with none (or the same
/// epoch) the lower hash of the fork-point record. A device that had accepted the losing record reorganises, and the
/// loser's author proposes again on the new head (`RotationStatus.superseded`).
///
/// Why this rule: the accounts that may sign change only in owner-signed records (`MembershipRules`). So between
/// branches without an owner-signed record every signer is an administrator on both, and the choice is between
/// equals. And a former administrator, whose removal or demotion the owner signed, can publish a competing record
/// at an earlier epoch, but its branch holds no owner-signed record at or before that removal, so it loses on every
/// device, however it is timed (review finding S1). Because the owner is never removed and may always sign, no
/// outcome leaves a vault without someone able to administer it.
public struct MembershipLedger: Sendable {
    /// One accepted record with the state it produced.
    public struct Link: Sendable, Hashable {
        public let record: MembershipRecord
        public let state: MembershipState
        /// The record as it is stored and published.
        public let encoded: [UInt8]
    }

    public let vaultID: UUID
    /// The owner's key bundle this ledger is anchored to.
    public let owner: PublicKeyBundle
    /// The accepted chain; never empty, and `chain[n]` is the record of epoch `n`.
    public private(set) var chain: [Link]

    init(vaultID: UUID, owner: PublicKeyBundle, chain: [Link]) {
        precondition(!chain.isEmpty)
        self.vaultID = vaultID
        self.owner = owner
        self.chain = chain
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

    /// Whether `accountID` may write to the vault as of `epoch` (PRD F4.5): `MembershipState.writePermission`, for a
    /// state this ledger verified. Ask about the ledger's current epoch when deciding whether to merge someone
    /// else's write: a former member can date a write as they please, so the membership that counts is the newest
    /// one this device knows. Not cryptographic; see `MembershipState.writePermission(for:)`.
    public func writePermission(for accountID: UUID, atEpoch epoch: UInt64) -> WritePermission {
        guard let state = state(atEpoch: epoch) else { return .refused(.unknownEpoch) }
        return state.writePermission(for: accountID)
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
            chain: [Link(record: record, state: state, encoded: record.encoded())])
    }

    /// Builds a ledger from records a store offers, anchored to an owner whose fingerprint has been verified.
    /// Throws `LedgerError.noGenesis` if none of them is that owner's genesis for `vaultID`.
    public static func join(vaultID: UUID, owner: VerifiedContact, candidates: [[UInt8]]) throws
        -> (ledger: MembershipLedger, report: IngestReport)
    {
        let resolution = try resolve(
            vaultID: vaultID, owner: owner.bundle, accepted: [], candidates: candidates,
            limit: MembershipLimits.maximumJoinCandidates)
        guard !resolution.chain.isEmpty else { throw LedgerError.noGenesis }
        return (MembershipLedger(vaultID: vaultID, owner: owner.bundle, chain: resolution.chain), resolution.report)
    }

    // MARK: - Ingesting

    /// What one `ingest` did.
    public struct IngestReport: Sendable, Hashable {
        public struct Rejection: Sendable, Hashable {
            public enum Reason: Sendable, Hashable {
                case malformed(SharingFormatError)
                case invalid(MembershipError)
                /// Its predecessor is neither in the accepted chain nor among the valid candidates. Offer it again
                /// once the records before it have arrived.
                case unconnected
            }
            /// Position in the candidates passed to `ingest`.
            public let index: Int
            public let reason: Reason
        }

        /// Records newly in the accepted chain, in epoch order.
        public var adopted: [MembershipRecord] = []
        /// Records that were in the accepted chain and lost a fork to `adopted`. Their effects are undone: whoever
        /// wrote them proposes again, and a vault key one of them introduced is no longer the vault's (keep it
        /// until nothing is sealed under it).
        public var superseded: [MembershipRecord] = []
        /// Valid candidates on a branch that lost. Not an attack by itself: two administrators acted at once.
        public var outranked: [MembershipRecord] = []
        public var rejected: [Rejection] = []

        public var changedHead: Bool {
            !adopted.isEmpty
        }
    }

    /// Offers records from a store to the ledger. Throws only when there are too many to examine; a bad record is
    /// reported in `IngestReport.rejected` and changes nothing.
    ///
    /// Pass every record under the vault's membership prefix that is not already known, in name order (names sort
    /// by epoch); a chain longer than `MembershipLimits.maximumCandidates` is fed in batches.
    public mutating func ingest(_ candidates: [[UInt8]]) throws -> IngestReport {
        let resolution = try MembershipLedger.resolve(
            vaultID: vaultID, owner: owner, accepted: chain, candidates: candidates,
            limit: MembershipLimits.maximumCandidates)
        chain = resolution.chain
        return resolution.report
    }

    private struct Node {
        let record: MembershipRecord
        let state: MembershipState
        let encoded: [UInt8]
        let parent: Int?
        var children: [Int] = []
        /// The epoch of the first owner-signed record on the best path from here; `UInt64.max` if there is none.
        var ownerEpoch = UInt64.max
    }

    private struct Pending {
        let index: Int
        let record: MembershipRecord
        let hash: MembershipHash
        let encoded: [UInt8]
    }

    /// The fork rule (the type's documentation says why): builds the tree of valid records from the accepted chain
    /// and the candidates, and walks it from the genesis choosing, at each fork, the child with the earliest
    /// owner-signed record below it, then the lowest hash.
    private static func resolve(
        vaultID: UUID, owner: PublicKeyBundle, accepted: [Link], candidates: [[UInt8]], limit: Int
    ) throws -> (chain: [Link], report: IngestReport) {
        guard candidates.count <= limit else { throw LedgerError.tooManyCandidates(candidates.count) }
        var report = IngestReport()

        var nodes: [Node] = []
        var indexByHash: [MembershipHash: Int] = [:]
        for (position, link) in accepted.enumerated() {
            nodes.append(
                Node(
                    record: link.record, state: link.state, encoded: link.encoded,
                    parent: position == 0 ? nil : position - 1))
            indexByHash[link.state.hash] = position
            if position > 0 { nodes[position - 1].children.append(position) }
        }

        // Parse. Nothing here costs a signature check. Exact copies are dropped; two candidates with one hash but
        // different signature bytes are both kept, so that a copy with a spoilt signature, served first, cannot stand
        // in for the genuine record (review finding S4).
        var pendingByParent: [MembershipHash: [Pending]] = [:]
        var seen: Set<[UInt8]> = []
        for (index, bytes) in candidates.enumerated() {
            let record: MembershipRecord
            do {
                record = try MembershipRecord.parse(bytes)
            } catch let error as SharingFormatError {
                report.rejected.append(.init(index: index, reason: .malformed(error)))
                continue
            }
            guard record.vaultID == vaultID else {
                report.rejected.append(
                    .init(index: index, reason: .invalid(.wrongVault(expected: vaultID, actual: record.vaultID))))
                continue
            }
            let hash = record.hash
            // A copy of a record already accepted, whatever its signature bytes say, is the record already accepted.
            guard indexByHash[hash] == nil, seen.insert(bytes).inserted else { continue }
            pendingByParent[record.previousHash, default: []].append(
                Pending(index: index, record: record, hash: hash, encoded: bytes))
        }

        // Which nodes introduced each vault key, so that "has this branch used the key before" is a dictionary miss
        // for every honest record and costs a walk only for an actual attempt at reuse.
        var introducers: [UUID: [Int]] = [:]
        for (position, link) in accepted.enumerated() where link.state.keyEpoch == link.state.epoch {
            introducers[link.state.vaultKeyID, default: []].append(position)
        }
        func isAncestor(_ ancestor: Int, of node: Int) -> Bool {
            let target = nodes[ancestor].state.epoch
            var cursor: Int? = node
            while let index = cursor, nodes[index].state.epoch > target {
                // An accepted node's ancestors are the accepted chain, where position is epoch.
                cursor = index < accepted.count ? Int(target) : nodes[index].parent
            }
            return cursor == ancestor
        }
        func keyUsed(_ keyID: UUID, upTo node: Int) -> Bool {
            (introducers[keyID] ?? []).contains { isAncestor($0, of: node) }
        }
        func append(_ pending: Pending, state: MembershipState, parent: Int?) -> Int {
            nodes.append(Node(record: pending.record, state: state, encoded: pending.encoded, parent: parent))
            let index = nodes.count - 1
            indexByHash[pending.hash] = index
            if state.keyEpoch == state.epoch { introducers[state.vaultKeyID, default: []].append(index) }
            if let parent { nodes[parent].children.append(index) }
            return index
        }

        // Verify, outwards from what is already verified.
        var worklist = Array(nodes.indices)
        for pending in pendingByParent.removeValue(forKey: .none) ?? [] where indexByHash[pending.hash] == nil {
            do {
                let state = try MembershipRules.genesisState(
                    pending.record, hash: pending.hash, vaultID: vaultID, owner: owner)
                worklist.append(append(pending, state: state, parent: nil))
            } catch let error as MembershipError {
                report.rejected.append(.init(index: pending.index, reason: .invalid(error)))
            }
        }
        while let parent = worklist.popLast() {
            for pending in pendingByParent.removeValue(forKey: nodes[parent].state.hash) ?? []
            where indexByHash[pending.hash] == nil {
                do {
                    let state = try MembershipRules.nextState(
                        pending.record, hash: pending.hash, after: nodes[parent].state,
                        keyUsedBefore: { keyUsed($0, upTo: parent) })
                    worklist.append(append(pending, state: state, parent: parent))
                } catch let error as MembershipError {
                    report.rejected.append(.init(index: pending.index, reason: .invalid(error)))
                }
            }
        }
        for pending in pendingByParent.values.joined() {
            report.rejected.append(.init(index: pending.index, reason: .unconnected))
        }
        report.rejected.sort { $0.index < $1.index }

        // Rank: children before parents.
        for index in nodes.indices.sorted(by: { nodes[$0].state.epoch > nodes[$1].state.epoch }) {
            if nodes[index].record.signer == owner.accountID {
                nodes[index].ownerEpoch = nodes[index].state.epoch
            } else {
                nodes[index].ownerEpoch = nodes[index].children.map { nodes[$0].ownerEpoch }.min() ?? .max
            }
        }
        func best(of indices: [Int]) -> Int? {
            indices.min { a, b in
                (nodes[a].ownerEpoch, nodes[a].state.hash) < (nodes[b].ownerEpoch, nodes[b].state.hash)
            }
        }

        // Walk.
        var path: [Int] = []
        var next = best(of: nodes.indices.filter { nodes[$0].parent == nil })
        while let index = next {
            path.append(index)
            next = best(of: nodes[index].children)
        }
        let chain = path.map { Link(record: nodes[$0].record, state: nodes[$0].state, encoded: nodes[$0].encoded) }

        let chosen = Set(path)
        var shared = 0
        while shared < accepted.count, shared < chain.count, accepted[shared].state.hash == chain[shared].state.hash {
            shared += 1
        }
        report.adopted = chain[shared...].map(\.record)
        report.superseded = accepted[shared...].map(\.record)
        report.outranked = nodes.indices
            .filter { $0 >= accepted.count && !chosen.contains($0) }
            .map { nodes[$0].record }
            .sorted { ($0.epoch, $0.hash) < ($1.epoch, $1.hash) }
        return (chain, report)
    }

    // MARK: - Persistence

    static let checkpointMagic: [UInt8] = Array("WWML".utf8)
    static let checkpointVersion: UInt8 = 1

    private static func checkpointContent(
        account: UUID, vaultID: UUID, owner: PublicKeyBundle, epoch: UInt64, hash: MembershipHash
    ) -> [UInt8] {
        checkpointMagic + [checkpointVersion] + account.sharingBytes + vaultID.sharingBytes
            + owner.keyDigest + SharingBytes.littleEndian(epoch) + hash.bytes
    }

    /// The ledger as one blob for local storage: a checkpoint (this account, the vault, the owner's bundle, the head)
    /// signed by this account's key, then the accepted records.
    ///
    /// ```
    /// magic "WWML"  formatVersion u8 = 1  account 16  vaultID 16  SHA-256(owner's account ID and keys) 32
    /// headEpoch u64  headHash 32  signature 64
    /// recordCount u32, then per record: length u16, record
    /// ```
    ///
    /// Save it after every `ingest` that changed the head.
    public func persisted(signedBy keyset: Keyset) throws -> [UInt8] {
        let content = MembershipLedger.checkpointContent(
            account: keyset.accountID, vaultID: vaultID, owner: owner, epoch: state.epoch, hash: state.hash)
        var out = content + (try keyset.sign(content, domain: .membership))
        out += SharingBytes.littleEndian(UInt32(chain.count))
        for link in chain {
            out += SharingBytes.littleEndian(UInt16(link.encoded.count)) + link.encoded
        }
        return out
    }

    /// Restores a ledger saved by `persisted(signedBy:)`.
    ///
    /// Local storage is not trusted either (A8, with the file): the checkpoint must carry this account's signature
    /// and name this vault and this owner, every record is verified again from the genesis exactly as if a store had
    /// offered it, and the result must reach the head the checkpoint names. A blob that was truncated, had records
    /// replaced, or was planted whole fails closed (`LedgerError`). What the signature cannot detect is an older blob
    /// of this device's own put back in place of a newer one; the next `ingest` from the transport moves it forward
    /// again.
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

        let count = Int(try reader.uint32())
        guard count <= Int(MembershipLimits.maximumEpoch) + 1, count <= reader.remaining / 2 else {
            throw SharingFormatError.countTooLarge
        }
        var records: [[UInt8]] = []
        records.reserveCapacity(count)
        for _ in 0..<count {
            let length = Int(try reader.uint16())
            guard length <= MembershipRecord.maximumLength else { throw SharingFormatError.tooLarge(length) }
            records.append(try reader.read(length))
        }
        try reader.finish()

        let resolution = try resolve(
            vaultID: vaultID, owner: owner.bundle, accepted: [], candidates: records, limit: records.count)
        guard epoch < UInt64(resolution.chain.count), resolution.chain[Int(epoch)].state.hash == hash else {
            throw LedgerError.rolledBack(expectedEpoch: epoch)
        }
        return MembershipLedger(vaultID: vaultID, owner: owner.bundle, chain: resolution.chain)
    }
}
