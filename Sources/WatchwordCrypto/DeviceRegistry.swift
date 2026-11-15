import Crypto
import Foundation
import WatchwordEnvelope

/// A device as the registry records it: its ID, its public signing key and its name.
public struct RegistryDevice: Sendable, Hashable {
    public static let maximumLabelLength = 1024

    public var id: UUID
    public var key: DevicePublicKey
    /// The device's name, sealed under the keyset's symmetric key (a device name is the person's metadata, and the
    /// registry is readable by the sync store). Opaque here, covered by the entry's signatures, and opened only for
    /// display; nothing about a device's standing depends on it.
    public var label: [UInt8]

    public init(id: UUID, key: DevicePublicKey, label: [UInt8]) {
        self.id = id
        self.key = key
        self.label = label
    }
}

/// One signed statement in the account's device registry (docs/02-architecture.md §7.8, review findings D9, Y5, Y6).
///
/// Entries form a hash-linked graph: each names the entries its author had seen (`parents`), and an entry's ID is the
/// SHA-256 of its bytes, so the sync store can neither alter an entry nor claim one was written knowing less than it
/// did. Binary, little-endian, one canonical encoding:
///
/// ```
/// magic "WWDR"  formatVersion u8 = 1  type u8 (0 genesis, 1 add, 2 revoke, 3 credential)
/// accountID 16
/// parentCount u8 (≤ 16), parents 32 each (strictly ascending)
/// authorKind u8: 0 = a registered device, then deviceID 16; 1 = the enrolment key, then the credential entry's ID 32
/// body:
///   genesis     accountSigningKey 32, device, enrolmentKey 32
///   add         device
///   revoke      deviceID 16
///   credential  generation u64, enrolmentKey 32, previous credential entry 32
/// device := deviceID 16, algorithm u8, keyLength u8, key, labelLength u16, label
/// ── everything above is signed ──
/// accountSignature (u8 length, 64), authorSignature (u8 length), and for a credential entry the signature of the
/// previous generation's enrolment key (u8 length, 64)
/// ```
///
/// Every entry carries two signatures over the signed part: the account's Ed25519 key (so a device key alone, taken
/// from a Keychain without the account password, changes nothing) and its author's — a registered device's own key
/// (so the keyset alone changes nothing either), or, for a device registering itself, the enrolment key that only
/// the current password and Secret Key yield. A credential entry is signed a third time, by the enrolment key of the
/// generation it replaces: changing the password needs the password.
public struct RegistryEntry: Sendable, Hashable {
    public static let maximumLength = 2048
    public static let maximumParents = 16
    static let magic = Array("WWDR".utf8)
    static let formatVersion: UInt8 = 1

    public enum Author: Sendable, Hashable {
        case device(UUID)
        /// The enrolment key published by this credential entry (the genesis entry for generation 0).
        case enrolment(credential: ObjectDigest)
    }

    public enum Body: Sendable, Hashable {
        /// The account's first device, the account's public signing key and the first enrolment key. Exactly one per
        /// account; every other entry descends from it.
        case genesis(accountSigningKey: [UInt8], device: RegistryDevice, enrolmentKey: [UInt8])
        case add(RegistryDevice)
        case revoke(UUID)
        /// The account's credentials changed: `enrolmentKey` replaces the one published by `previous`.
        case credential(generation: UInt64, enrolmentKey: [UInt8], previous: ObjectDigest)
    }

    public var accountID: UUID
    public var parents: [ObjectDigest]
    public var author: Author
    public var body: Body
    public var accountSignature: [UInt8]
    public var authorSignature: [UInt8]
    /// Credential entries only: the previous generation's enrolment key over the signed part.
    public var previousCredentialSignature: [UInt8]

    public init(
        accountID: UUID, parents: [ObjectDigest], author: Author, body: Body, accountSignature: [UInt8] = [],
        authorSignature: [UInt8] = [], previousCredentialSignature: [UInt8] = []
    ) {
        self.accountID = accountID
        self.parents = Array(Set(parents)).sorted()
        self.author = author
        self.body = body
        self.accountSignature = accountSignature
        self.authorSignature = authorSignature
        self.previousCredentialSignature = previousCredentialSignature
    }

    /// The entry's name: the SHA-256 of all of its bytes, signatures included.
    public var id: ObjectDigest {
        ObjectDigest(hashing: serialized())
    }

    var isCredential: Bool {
        if case .credential = body { return true }
        return false
    }

    var isRevocation: Bool {
        if case .revoke = body { return true }
        return false
    }

    // MARK: - What each signature covers

    /// What the account key signs (`Signatures`, domain `.deviceRegistry`).
    public var accountMessage: [UInt8] { [0x01] + signedPart }
    /// What the enrolment key signs for an entry it authors.
    public var enrolmentMessage: [UInt8] { [0x02] + signedPart }
    /// What the previous generation's enrolment key signs on a credential entry.
    public var previousCredentialMessage: [UInt8] { [0x03] + signedPart }
    /// What a device author signs (`DeviceSignatures`, domain `.deviceRegistry`, as that device).
    public var deviceMessage: [UInt8] { signedPart }

    // MARK: - Encoding

    public var signedPart: [UInt8] {
        var out = Self.magic
        out.append(Self.formatVersion)
        switch body {
        case .genesis: out.append(0)
        case .add: out.append(1)
        case .revoke: out.append(2)
        case .credential: out.append(3)
        }
        out += accountID.byteArray
        out.append(UInt8(truncatingIfNeeded: parents.count))
        for parent in parents { out += parent.bytes }
        switch author {
        case .device(let id): out += [0] + id.byteArray
        case .enrolment(let credential): out += [1] + credential.bytes
        }
        switch body {
        case .genesis(let accountSigningKey, let device, let enrolmentKey):
            out += accountSigningKey + Self.encoded(device) + enrolmentKey
        case .add(let device):
            out += Self.encoded(device)
        case .revoke(let deviceID):
            out += deviceID.byteArray
        case .credential(let generation, let enrolmentKey, let previous):
            out += AccountBytes.littleEndian(generation) + enrolmentKey + previous.bytes
        }
        return out
    }

    public func serialized() -> [UInt8] {
        var out = signedPart + AccountBytes.shortField(accountSignature) + AccountBytes.shortField(authorSignature)
        if isCredential { out += AccountBytes.shortField(previousCredentialSignature) }
        return out
    }

    static func encoded(_ device: RegistryDevice) -> [UInt8] {
        device.id.byteArray + [device.key.algorithm.rawValue]
            + AccountBytes.shortField(device.key.rawRepresentation) + AccountBytes.field(device.label)
    }

    // MARK: - Parsing

    /// Parses an entry exactly: anything that would not re-encode to the same bytes is refused.
    public static func parse(_ bytes: [UInt8]) throws -> RegistryEntry {
        guard bytes.count <= maximumLength else { throw AccountFormatError.tooLong(bytes.count) }
        var reader = AccountByteReader(bytes)
        guard try reader.read(4) == magic else { throw AccountFormatError.badMagic }
        let version = try reader.byte()
        guard version == formatVersion else { throw AccountFormatError.unsupportedVersion(version) }
        let type = try reader.byte()
        let accountID = try reader.uuid()
        let parentCount = Int(try reader.byte())
        guard parentCount <= maximumParents else { throw AccountFormatError.notCanonical }
        var parents: [ObjectDigest] = []
        for _ in 0..<parentCount {
            let parent = try digest(&reader)
            if let last = parents.last, !(last < parent) { throw AccountFormatError.notCanonical }
            parents.append(parent)
        }
        let author: Author
        switch try reader.byte() {
        case 0: author = .device(try reader.uuid())
        case 1: author = .enrolment(credential: try digest(&reader))
        case let other: throw AccountFormatError.unknownType(other)
        }
        let body: Body
        switch type {
        case 0:
            let accountSigningKey = try reader.read(32)
            let device = try self.device(&reader)
            body = .genesis(accountSigningKey: accountSigningKey, device: device, enrolmentKey: try reader.read(32))
        case 1:
            body = .add(try device(&reader))
        case 2:
            body = .revoke(try reader.uuid())
        case 3:
            let generation = try reader.uint64()
            let enrolmentKey = try reader.read(32)
            body = .credential(generation: generation, enrolmentKey: enrolmentKey, previous: try digest(&reader))
        default:
            throw AccountFormatError.unknownType(type)
        }
        var entry = RegistryEntry(accountID: accountID, parents: parents, author: author, body: body)
        entry.accountSignature = try reader.shortField(maximum: 64)
        entry.authorSignature = try reader.shortField(maximum: 128)
        if entry.isCredential { entry.previousCredentialSignature = try reader.shortField(maximum: 64) }
        guard reader.remaining == 0 else { throw AccountFormatError.trailingBytes }
        return entry
    }

    private static func digest(_ reader: inout AccountByteReader) throws -> ObjectDigest {
        // Cannot fail: the length is right by construction.
        ObjectDigest(bytes: try reader.read(ObjectDigest.byteCount))!
    }

    private static func device(_ reader: inout AccountByteReader) throws -> RegistryDevice {
        let id = try reader.uuid()
        guard let algorithm = DeviceSignatureAlgorithm(rawValue: try reader.byte()) else {
            throw AccountFormatError.invalidPublicKey
        }
        let raw = try reader.shortField(maximum: DevicePublicKey.maximumLength)
        guard let key = try? DevicePublicKey(algorithm: algorithm, rawRepresentation: raw) else {
            throw AccountFormatError.invalidPublicKey
        }
        return RegistryDevice(id: id, key: key, label: try reader.field(maximum: RegistryDevice.maximumLabelLength))
    }
}

public enum DeviceRegistryError: Error, Equatable, Sendable {
    /// The genesis entry this device trusts is not among the entries, or is not what it must be: self-signed by its
    /// device, signed by the account key, and naming that account key.
    case genesisUnavailable
    /// The credential entry this device follows is missing, or does not lead back to the genesis entry link by
    /// link, each signed by the enrolment key of the one before.
    case brokenCredentialChain
    /// More entries than any household's devices produce: refused rather than evaluated (PRD SEC9).
    case tooManyEntries(Int)
}

/// A device's standing in the registry.
public enum DeviceStanding: Sendable, Hashable {
    case active
    /// Revoked; never active again under this ID or this key.
    case revoked
    /// Not in the registry as this device sees it.
    case unknown
}

/// The registry as one device sees it: who may write, who was revoked, and which credentials are current
/// (docs/02-architecture.md §7.8).
public struct DeviceRegistryState: Sendable, Hashable {
    public struct Device: Sendable, Hashable {
        public var id: UUID
        public var key: DevicePublicKey
        public var label: [UInt8]
        public var addedBy: RegistryEntry.Author
        /// The entry that registered the device.
        public var entry: ObjectDigest
        /// For a revoked device, the device that revoked it.
        public var revokedBy: UUID?
    }

    public struct Credential: Sendable, Hashable {
        public var id: ObjectDigest
        public var generation: UInt64
        public var enrolmentKey: [UInt8]
        /// The device that changed the credentials (the genesis device for generation 0).
        public var author: UUID
        public var previous: ObjectDigest?
    }

    public var accountID: UUID
    public var accountSigningKey: [UInt8]
    public var genesis: ObjectDigest
    public var devices: [UUID: Device] = [:]
    public var revoked: [UUID: Device] = [:]
    /// The credential generations this device follows, from the genesis entry to the current one.
    public var credentialChain: [Credential]
    /// Credential changes that follow the current one and that this device has not confirmed: someone changed the
    /// account password elsewhere. Until the person enters that password here, this device neither merges nor
    /// publishes (§7.8).
    public var pendingCredentials: [Credential] = []
    /// Credential changes that branch off an earlier generation of the chain this device follows: the password was
    /// changed on two devices at once, or by someone who knew an older password. They count for nothing here unless
    /// the person unlocks this device with the password of one of them, which is what makes it follow that branch.
    public var forkedCredentials: [Credential] = []
    /// The newest valid entries, which the next entry written names as its parents.
    public var heads: [ObjectDigest] = []
    public var validEntries: Set<ObjectDigest> = []
    /// Every entry that descends from the genesis entry, valid or not.
    public var connectedEntries: Set<ObjectDigest> = []

    public var credential: Credential {
        credentialChain[credentialChain.count - 1]
    }

    public func standing(of device: UUID) -> DeviceStanding {
        if devices[device] != nil { return .active }
        return revoked[device] != nil ? .revoked : .unknown
    }
}

/// The device registry's rules (docs/02-architecture.md §7.8): a deterministic function from a set of entries, the
/// genesis entry a device trusts and the credential generation it follows, to who may write.
///
/// The entries are a grow-only set, and every device that holds the same entries and follows the same credentials
/// computes the same state — the registry is a state-based CRDT whose merge is set union. What needs care is
/// concurrency: a revoked device that kept the account key can sign entries that *claim* to have been written
/// before its revocation, by naming old parents. So the entries are replayed in one order, fixed by two rules:
///
/// 1. **Credential changes are checkpoints.** Everything a credential change had seen (its ancestors) is replayed
///    before anything it had not, generation by generation. An entry that turns up later, however old the parents
///    it names, is judged against the state the checkpoint left — in which its author, if revoked by then, is
///    revoked. A revocation followed by a password change is therefore final, and only the person, who knows the
///    new password, can make one.
/// 2. Between checkpoints, entries are replayed in causal order, each revocation as early as that allows (what it
///    had seen, then the revocation, then what it had not seen), ties by entry ID. What a device wrote at the same
///    time as it was being revoked therefore counts for nothing.
///
/// An entry is applied only if, at its place in that order, its author is a registered device that has not been
/// revoked (or the current enrolment key, for a device registering itself) and its signatures verify. A revoked
/// device's ID and key are never accepted again.
public enum DeviceRegistry {
    /// Far more than any household's devices produce; a registry beyond it is refused, not evaluated.
    public static let maximumEntries = 4096

    /// Parses and admits entries: an entry that does not parse, belongs to another account, or is not signed by the
    /// account key is dropped here, before it can count for anything. Needs public keys only.
    public static func admit(_ candidates: [[UInt8]], accountID: UUID, accountSigningKey: [UInt8])
        -> [ObjectDigest: RegistryEntry]
    {
        var admitted: [ObjectDigest: RegistryEntry] = [:]
        for bytes in candidates {
            guard let entry = try? RegistryEntry.parse(bytes), entry.accountID == accountID,
                (try? Signatures.verify(
                    entry.accountSignature, for: entry.accountMessage, domain: .deviceRegistry,
                    signingKey: accountSigningKey)) != nil
            else { continue }
            admitted[ObjectDigest(hashing: bytes)] = entry
        }
        return admitted
    }

    /// Replays `entries` (as `admit` returned them). `genesis` and `credential` are what this device pinned: the
    /// genesis entry named by the account header it opened with the password, and the credential entry that header
    /// belongs to.
    public static func evaluate(
        _ entries: [ObjectDigest: RegistryEntry],
        accountID: UUID,
        accountSigningKey: [UInt8],
        genesis: ObjectDigest,
        credential: ObjectDigest
    ) throws -> DeviceRegistryState {
        guard entries.count <= maximumEntries else { throw DeviceRegistryError.tooManyEntries(entries.count) }
        guard let root = entries[genesis],
            case .genesis(let rootKey, let rootDevice, let rootEnrolmentKey) = root.body,
            root.parents.isEmpty, root.author == .device(rootDevice.id), root.accountID == accountID,
            rootKey == accountSigningKey, rootDevice.label.count <= RegistryDevice.maximumLabelLength,
            (try? Signatures.validateSigningKey(rootEnrolmentKey)) != nil,
            (try? Signatures.verify(
                root.accountSignature, for: root.accountMessage, domain: .deviceRegistry,
                signingKey: accountSigningKey)) != nil,
            (try? DeviceSignatures.verify(
                root.authorSignature, for: root.deviceMessage, domain: .deviceRegistry, deviceID: rootDevice.id,
                key: rootDevice.key)) != nil
        else { throw DeviceRegistryError.genesisUnavailable }

        // Entries that descend from the genesis entry, in a causal order, each with a bitset of its ancestors.
        let graph = Graph(entries, genesis: genesis)

        // The credential chain, from the one this device follows back to the genesis entry.
        var chain: [DeviceRegistryState.Credential] = []
        var cursor = credential
        while cursor != genesis {
            guard let entry = entries[cursor], graph.index[cursor] != nil, case .device(let author) = entry.author,
                case .credential(let generation, let enrolmentKey, let previous) = entry.body,
                graph.isAncestor(previous, of: cursor), chain.count < maximumEntries
            else { throw DeviceRegistryError.brokenCredentialChain }
            chain.append(
                .init(
                    id: cursor, generation: generation, enrolmentKey: enrolmentKey, author: author,
                    previous: previous))
            cursor = previous
        }
        chain.append(
            .init(id: genesis, generation: 0, enrolmentKey: rootEnrolmentKey, author: rootDevice.id, previous: nil))
        chain.reverse()
        for (position, link) in chain.enumerated() where link.generation != UInt64(position) {
            throw DeviceRegistryError.brokenCredentialChain
        }

        var state = DeviceRegistryState(
            accountID: accountID, accountSigningKey: accountSigningKey, genesis: genesis, credentialChain: [chain[0]])
        state.connectedEntries = Set(graph.ids)
        var revokedKeys: Set<[UInt8]> = []
        var offChain: [ObjectDigest: DeviceRegistryState.Credential] = [:]

        for id in graph.replayOrder(checkpoints: chain.map(\.id)) {
            let entry = entries[id]!
            switch entry.body {
            case .genesis(_, let device, _):
                // Only the trusted one is in the graph, and it was checked above.
                state.devices[device.id] = .init(
                    id: device.id, key: device.key, label: device.label, addedBy: entry.author, entry: id)

            case .add(let device):
                let current = state.credential
                switch entry.author {
                case .device(let author):
                    guard deviceSigned(entry, by: author, in: state) else { continue }
                case .enrolment(let cited):
                    // Only the generation that is current here, and only an entry written knowing of it.
                    guard cited == current.id, graph.isAncestor(cited, of: id),
                        (try? Signatures.verify(
                            entry.authorSignature, for: entry.enrolmentMessage, domain: .deviceRegistry,
                            signingKey: current.enrolmentKey)) != nil
                    else { continue }
                }
                // A revoked device never returns, under its ID or its key; a registered device's key never changes,
                // and no key serves two devices.
                guard state.revoked[device.id] == nil, !revokedKeys.contains(device.key.rawRepresentation) else {
                    continue
                }
                if let existing = state.devices[device.id] {
                    guard existing.key == device.key else { continue }
                } else {
                    guard !state.devices.values.contains(where: { $0.key == device.key }) else { continue }
                    state.devices[device.id] = .init(
                        id: device.id, key: device.key, label: device.label, addedBy: entry.author, entry: id)
                }

            case .revoke(let target):
                guard case .device(let author) = entry.author, deviceSigned(entry, by: author, in: state) else {
                    continue
                }
                if var device = state.devices.removeValue(forKey: target) {
                    device.revokedBy = author
                    state.revoked[target] = device
                    revokedKeys.insert(device.key.rawRepresentation)
                } else if state.revoked[target] == nil {
                    continue
                }

            case .credential(let generation, let enrolmentKey, let previous):
                let next = state.credentialChain.count
                if next < chain.count, chain[next].id == id {
                    // A link of the chain this device follows: it must be what the rules allow, or the chain is not
                    // one to follow.
                    guard case .device(let author) = entry.author, deviceSigned(entry, by: author, in: state),
                        previous == state.credential.id, credentialSigned(entry, by: state.credential)
                    else { throw DeviceRegistryError.brokenCredentialChain }
                    state.credentialChain.append(chain[next])
                    state.validEntries.insert(id)
                    continue
                }
                // Not on the chain: a change this device has not confirmed (it follows the last link), or a branch
                // off an earlier link. Either counts for nothing until the person's password says otherwise; it is
                // recorded only if it is what the rules allow where it stands.
                guard case .device(let author) = entry.author, deviceSigned(entry, by: author, in: state),
                    graph.isAncestor(previous, of: id),
                    let base = state.credentialChain.first(where: { $0.id == previous }) ?? offChain[previous],
                    generation == base.generation + 1, credentialSigned(entry, by: base),
                    (try? Signatures.validateSigningKey(enrolmentKey)) != nil
                else { continue }
                offChain[id] = .init(
                    id: id, generation: generation, enrolmentKey: enrolmentKey, author: author, previous: previous)
            }
            state.validEntries.insert(id)
        }
        guard state.credentialChain.count == chain.count else { throw DeviceRegistryError.brokenCredentialChain }

        // Pending: descends from the last link. Forked: branches off an earlier one.
        let head = state.credential.id
        for candidate in offChain.values.sorted(by: { ($0.generation, $0.id) < ($1.generation, $1.id) }) {
            var cursor = candidate
            while let previous = cursor.previous, let parent = offChain[previous] { cursor = parent }
            if cursor.previous == head {
                state.pendingCredentials.append(candidate)
            } else {
                state.forkedCredentials.append(candidate)
            }
        }
        var hasValidChild: Set<ObjectDigest> = []
        for id in state.validEntries {
            for parent in entries[id]!.parents { hasValidChild.insert(parent) }
        }
        state.heads = state.validEntries.filter { !hasValidChild.contains($0) }.sorted()
        return state
    }

    private static func deviceSigned(_ entry: RegistryEntry, by author: UUID, in state: DeviceRegistryState) -> Bool {
        guard let device = state.devices[author] else { return false }
        return
            (try? DeviceSignatures.verify(
                entry.authorSignature, for: entry.deviceMessage, domain: .deviceRegistry, deviceID: author,
                key: device.key)) != nil
    }

    private static func credentialSigned(_ entry: RegistryEntry, by previous: DeviceRegistryState.Credential) -> Bool {
        (try? Signatures.verify(
            entry.previousCredentialSignature, for: entry.previousCredentialMessage, domain: .deviceRegistry,
            signingKey: previous.enrolmentKey)) != nil
    }

    /// The entries that descend from the genesis entry, with each one's ancestors.
    struct Graph {
        var ids: [ObjectDigest] = []
        var index: [ObjectDigest: Int] = [:]
        var parents: [[Int]] = []
        var isRevocation: [Bool] = []
        /// `ancestors[i]` has bit `j` set when entry `j` is an ancestor of entry `i`.
        var ancestors: [[UInt64]] = []

        init(_ entries: [ObjectDigest: RegistryEntry], genesis: ObjectDigest) {
            // Connected: the genesis entry, and any other entry whose parents are all connected. An entry with a
            // parent this device has not seen waits; a second genesis entry is never connected.
            var waitingFor: [ObjectDigest: Int] = [:]
            var childrenOf: [ObjectDigest: [ObjectDigest]] = [:]
            for (id, entry) in entries where id != genesis && !entry.parents.isEmpty {
                if case .genesis = entry.body { continue }
                guard entry.parents.allSatisfy({ entries[$0] != nil }) else { continue }
                waitingFor[id] = entry.parents.count
                for parent in entry.parents { childrenOf[parent, default: []].append(id) }
            }
            var order = [genesis]
            var next = 0
            while next < order.count {
                for child in (childrenOf[order[next]] ?? []).sorted() {
                    waitingFor[child]! -= 1
                    if waitingFor[child] == 0 { order.append(child) }
                }
                next += 1
            }
            ids = order
            index = Dictionary(uniqueKeysWithValues: order.enumerated().map { ($0.element, $0.offset) })
            let words = (order.count + 63) / 64
            for id in order {
                let entry = entries[id]!
                let parentIndexes = entry.parents.map { index[$0]! }
                var bits = [UInt64](repeating: 0, count: words)
                for parent in parentIndexes {
                    bits[parent / 64] |= 1 << UInt64(parent % 64)
                    for word in 0..<words { bits[word] |= ancestors[parent][word] }
                }
                parents.append(parentIndexes)
                isRevocation.append(entry.isRevocation)
                ancestors.append(bits)
            }
        }

        func isAncestor(_ ancestor: ObjectDigest, of entry: ObjectDigest) -> Bool {
            guard let a = index[ancestor], let e = index[entry] else { return false }
            return ancestors[e][a / 64] & (1 << UInt64(a % 64)) != 0
        }

        /// The one order every device replays the entries in: checkpoint by checkpoint (an entry belongs to the
        /// first checkpoint that is it or descends from it, or to none), and within that causally, each revocation
        /// as early as causality allows — what a revocation had seen first, then the revocation, then everything it
        /// had not seen — with ties broken by ID. So an entry a device wrote at the same time as it was being
        /// revoked comes after its revocation, and counts for nothing.
        func replayOrder(checkpoints: [ObjectDigest]) -> [ObjectDigest] {
            let unsealed = checkpoints.count
            var layer = [Int](repeating: unsealed, count: ids.count)
            for (position, checkpoint) in checkpoints.enumerated().reversed() {
                guard let c = index[checkpoint] else { continue }
                layer[c] = position
                for other in 0..<ids.count where ancestors[c][other / 64] & (1 << UInt64(other % 64)) != 0 {
                    layer[other] = position
                }
            }
            // Entries a revocation depends on: the revocations themselves and everything they had seen.
            var leadsToRevocation = isRevocation
            for revocation in 0..<ids.count where isRevocation[revocation] {
                for other in 0..<ids.count
                where ancestors[revocation][other / 64] & (1 << UInt64(other % 64)) != 0 {
                    leadsToRevocation[other] = true
                }
            }
            var unprocessedParents = parents.map(\.count)
            var children = [[Int]](repeating: [], count: ids.count)
            for (child, list) in parents.enumerated() {
                for parent in list { children[parent].append(child) }
            }
            var ready = (0..<ids.count).filter { unprocessedParents[$0] == 0 }
            var order: [ObjectDigest] = []
            order.reserveCapacity(ids.count)
            while !ready.isEmpty {
                var best = 0
                for candidate in 1..<ready.count
                where precedes(ready[candidate], ready[best], layer: layer, first: leadsToRevocation) {
                    best = candidate
                }
                let next = ready.remove(at: best)
                order.append(ids[next])
                for child in children[next] {
                    unprocessedParents[child] -= 1
                    if unprocessedParents[child] == 0 { ready.append(child) }
                }
            }
            return order
        }

        private func precedes(_ a: Int, _ b: Int, layer: [Int], first: [Bool]) -> Bool {
            if layer[a] != layer[b] { return layer[a] < layer[b] }
            if first[a] != first[b] { return first[a] }
            if isRevocation[a] != isRevocation[b] { return isRevocation[a] }
            return ids[a] < ids[b]
        }
    }
}
