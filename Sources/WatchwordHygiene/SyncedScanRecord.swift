import Foundation
import WatchwordModel

public enum SyncedScanRecordError: Error, Equatable, Sendable {
    /// The bytes are not one canonical encoding of a record within its bounds.
    case malformed
    /// More observations or results than a record may hold.
    case tooLarge
}

/// The breach-check results a vault shares about one item (docs/02-architecture.md §13.9; ADR 0005, amendment of
/// 2026-11-16): for each device that checked the item's passwords, its latest check, with when it ran and, per
/// password, whether the password was found and how often. Sealed under the vault's key as a record of kind
/// `scanStatus` beside the item (same record ID, its own kind), synced through the vault's log like every record, and
/// never an item version: a check writes no history and makes no conflict.
///
/// **A state-based CRDT.** Each device writes only its own observation; the record is a map from device to that
/// device's latest observation, and `joined` keeps, per device, the observation with the higher revision (the
/// record version at which its device wrote it), then the one whose encoding sorts later. Beyond
/// `maximumObservations` devices, the observations with the lowest (revision, device) go. Per-device maximum and then
/// the top of one total order: commutative, associative and idempotent, so every device that has merged the same
/// observations holds the same state, whatever order they arrived in.
///
/// **What it is not trusted for.** A record says what a vault member reports. A remote "not found" only postpones this
/// device's own check of that password, by at most the scheduling caps; it never hides a breach this device saw,
/// which stays in this device's own sealed ledger, out of any other writer's reach. A remote "found" is shown, and
/// remembered by this device the same way, until this device's own later check says otherwise. The record holds no
/// hash of a password: each result is under a `ScanBinding`, keyed by a key derived from the vault key the
/// observation names, so a result is about one password of one item and says nothing without the key.
public struct SyncedScanRecord: Hashable, Sendable {
    public static let maximumObservations = 32
    /// As many as one item has checked passwords (`ItemAnalyzer.maximumPasswordsPerItem`).
    public static let maximumResultsPerObservation = ItemAnalyzer.maximumPasswordsPerItem
    static let magic = Array("WWSR".utf8)
    static let format: UInt8 = 1
    static let headerLength = 4 + 1 + 16 + 16 + 8 + 1
    static let observationHeaderLength = 16 + 8 + 16 + 8 + 1
    static let resultLength = ScanBinding.length + 4
    public static let maximumEncodedLength =
        headerLength + maximumObservations * (observationHeaderLength + maximumResultsPerObservation * resultLength)
    static let secondsLimit: Int64 = 1 << 40

    /// One device's latest completed check of the item's passwords.
    public struct Observation: Hashable, Sendable {
        public var device: UUID
        /// The record version at which `device` wrote this observation. Its writer's own write carries it at exactly
        /// this version; a merge or a re-seal by another device keeps it.
        public var revision: UInt64
        /// The vault key whose binding key the results are under (`HygieneKeys.scanBindingKey`).
        public var keyID: UUID
        /// When the check ran, by its device's clock, in whole seconds.
        public var scannedAt: Date
        /// Per password, by binding: zero occurrences is "not found".
        public var results: [ScanBinding: UInt32]

        public init(device: UUID, revision: UInt64, keyID: UUID, scannedAt: Date, results: [ScanBinding: UInt32]) {
            self.device = device
            self.revision = revision
            self.keyID = keyID
            self.scannedAt = Date(timeIntervalSince1970: Double(SyncedScanRecord.seconds(scannedAt)))
            self.results = results
        }

        func encoded() -> [UInt8] {
            var out = device.scanBindingBytes + SyncedScanRecord.bigEndian(revision) + keyID.scanBindingBytes
            out += SyncedScanRecord.bigEndian(UInt64(SyncedScanRecord.seconds(scannedAt)))
            out.append(UInt8(results.count))
            for (binding, occurrences) in results.sorted(by: { $0.key < $1.key }) {
                out += binding.bytes
                out += (0..<4).map { UInt8(truncatingIfNeeded: occurrences >> (8 * (3 - $0))) }
            }
            return out
        }

        /// The order `joined` keeps by: revision, then the encoding.
        func supersedes(_ other: Observation) -> Bool {
            if revision != other.revision { return revision > other.revision }
            return other.encoded().lexicographicallyPrecedes(encoded())
        }
    }

    public var itemID: UUID
    public var vaultID: UUID
    /// The record version; equal to the row's, as for every record the session opens.
    public var version: UInt64
    /// At most one per device, keyed by it.
    public private(set) var observations: [UUID: Observation]

    public init(itemID: UUID, vaultID: UUID, version: UInt64, observations: [Observation] = []) {
        self.itemID = itemID
        self.vaultID = vaultID
        self.version = version
        self.observations = [:]
        var map: [UUID: Observation] = [:]
        for observation in observations { map = Self.kept(map, adding: observation) }
        self.observations = Self.bounded(map)
    }

    /// Sets `device`'s observation, replacing whatever that device had here, and keeps the bound.
    public mutating func record(_ observation: Observation) {
        var map = observations
        map[observation.device] = nil
        observations = Self.bounded(Self.kept(map, adding: observation))
    }

    /// Both records' observations taken together (see the type's documentation). The identity and version are this
    /// record's: the caller decides which version the result is written at.
    public func joined(_ other: SyncedScanRecord) -> SyncedScanRecord {
        var map = observations
        for observation in other.observations.values { map = Self.kept(map, adding: observation) }
        var result = self
        result.observations = Self.bounded(map)
        return result
    }

    /// Whether the two hold the same observations, whatever their versions.
    public func sameState(_ other: SyncedScanRecord) -> Bool {
        observations == other.observations
    }

    /// What is left of this record once it has been erased with the stamp `tombstone`: the observations written
    /// after it, which its author cannot have seen. `nil` if there are none.
    public func settled(afterErasureAt tombstone: UInt64) -> SyncedScanRecord? {
        var result = self
        result.observations = observations.filter { $0.value.revision > tombstone }
        return result.observations.isEmpty ? nil : result
    }

    /// Every observation with the canonical bytes that stand for it, for attributing each to its device
    /// (a shared vault's write judge, docs/02-architecture.md §8.10).
    public var attributedObservations: [(device: UUID, revision: UInt64, bytes: [UInt8])] {
        observations.values.sorted { $0.device.uuidString < $1.device.uuidString }.map {
            ($0.device, $0.revision, itemID.scanBindingBytes + $0.encoded())
        }
    }

    private static func kept(_ map: [UUID: Observation], adding observation: Observation) -> [UUID: Observation] {
        var map = map
        if let existing = map[observation.device], !observation.supersedes(existing) { return map }
        map[observation.device] = observation
        return map
    }

    private static func bounded(_ map: [UUID: Observation]) -> [UUID: Observation] {
        guard map.count > maximumObservations else { return map }
        let kept = map.values.sorted { lhs, rhs in
            if lhs.revision != rhs.revision { return lhs.revision > rhs.revision }
            return rhs.device.scanBindingBytes.lexicographicallyPrecedes(lhs.device.scanBindingBytes)
        }.prefix(maximumObservations)
        return Dictionary(uniqueKeysWithValues: kept.map { ($0.device, $0) })
    }

    // MARK: Encoding

    /// `"WWSR"`, format 1, item ID, vault ID, version, a count, then each observation in device order: device,
    /// revision, key ID, the scan time in seconds, a count, and each result in binding order (binding, occurrences).
    /// Big-endian throughout. One canonical encoding per record.
    public func encoded() throws -> [UInt8] {
        guard observations.count <= Self.maximumObservations,
            observations.values.allSatisfy({ $0.results.count <= Self.maximumResultsPerObservation })
        else { throw SyncedScanRecordError.tooLarge }
        var out = Self.magic + [Self.format] + itemID.scanBindingBytes + vaultID.scanBindingBytes
        out += Self.bigEndian(version)
        out.append(UInt8(observations.count))
        for observation in observations.values.sorted(by: {
            $0.device.scanBindingBytes.lexicographicallyPrecedes($1.device.scanBindingBytes)
        }) {
            out += observation.encoded()
        }
        return out
    }

    /// Exact: every length checked before it is used, devices and bindings strictly ascending (so listed once), no
    /// observation from after the record's own version, and nothing after the last.
    public init(decoding bytes: [UInt8]) throws {
        guard bytes.count >= Self.headerLength, bytes.count <= Self.maximumEncodedLength,
            Array(bytes[0..<4]) == Self.magic, bytes[4] == Self.format
        else { throw SyncedScanRecordError.malformed }
        itemID = UUID(scanBindingBytes: bytes[5..<21])
        vaultID = UUID(scanBindingBytes: bytes[21..<37])
        version = Self.read(bytes, 37, 8)
        let count = Int(bytes[45])
        guard count <= Self.maximumObservations else { throw SyncedScanRecordError.malformed }
        var offset = Self.headerLength
        var map: [UUID: Observation] = [:]
        var previousDevice: [UInt8]?
        for _ in 0..<count {
            guard bytes.count - offset >= Self.observationHeaderLength else { throw SyncedScanRecordError.malformed }
            let deviceBytes = Array(bytes[offset..<(offset + 16)])
            if let previousDevice, !previousDevice.lexicographicallyPrecedes(deviceBytes) {
                throw SyncedScanRecordError.malformed
            }
            previousDevice = deviceBytes
            let revision = Self.read(bytes, offset + 16, 8)
            let keyID = UUID(scanBindingBytes: bytes[(offset + 24)..<(offset + 40)])
            let seconds = Self.read(bytes, offset + 40, 8)
            let results = Int(bytes[offset + 48])
            offset += Self.observationHeaderLength
            guard revision >= 1, revision <= version, seconds < UInt64(Self.secondsLimit),
                results <= Self.maximumResultsPerObservation, bytes.count - offset >= results * Self.resultLength
            else { throw SyncedScanRecordError.malformed }
            var values: [ScanBinding: UInt32] = [:]
            var previousBinding: ScanBinding?
            for _ in 0..<results {
                let binding = ScanBinding(bytes: Array(bytes[offset..<(offset + ScanBinding.length)]))!
                if let previousBinding, !(previousBinding < binding) { throw SyncedScanRecordError.malformed }
                previousBinding = binding
                values[binding] = UInt32(Self.read(bytes, offset + ScanBinding.length, 4))
                offset += Self.resultLength
            }
            let device = UUID(scanBindingBytes: deviceBytes[...])
            map[device] = Observation(
                device: device, revision: revision, keyID: keyID,
                scannedAt: Date(timeIntervalSince1970: Double(seconds)), results: values)
        }
        guard offset == bytes.count else { throw SyncedScanRecordError.malformed }
        observations = map
    }

    static func seconds(_ date: Date) -> Int64 {
        let seconds = date.timeIntervalSince1970.rounded(.down)
        guard seconds.isFinite else { return 0 }
        return Int64(min(max(seconds, 0), Double(secondsLimit - 1)))
    }

    static func bigEndian(_ value: UInt64) -> [UInt8] {
        (0..<8).map { UInt8(truncatingIfNeeded: value >> (8 * (7 - $0))) }
    }

    static func read(_ bytes: [UInt8], _ offset: Int, _ count: Int) -> UInt64 {
        bytes[offset..<(offset + count)].reduce(0) { $0 << 8 | UInt64($1) }
    }
}

/// Results all but name passwords (a count is a rank), so a record prints as its identity and size only.
extension SyncedScanRecord: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String {
        "SyncedScanRecord(item: \(itemID), version \(version), \(observations.count) observations, results withheld)"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: ["itemID": itemID, "version": version], displayStyle: .struct)
    }
}

extension SyncedScanRecord.Observation: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "Observation(device: \(device), revision \(revision), results withheld)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: ["device": device, "revision": revision], displayStyle: .struct)
    }
}

/// What other devices reported about the passwords of one item, matched by the session against the item's current
/// passwords (`SyncedScanRecord` opened, each observation's bindings compared with the bindings of the passwords the
/// item holds now). In memory only, handed to `HygieneEngine.updateSynced`, and dropped with everything else at lock:
/// which of the item's passwords another device found breached is derived from them.
///
/// It is for one item version: an engine that knows the item at another version ignores it.
public struct SyncedScanEvidence: Hashable, Sendable {
    public struct Observation: Hashable, Sendable {
        public let device: UUID
        public let scannedAt: Date
        public let result: PwnedPasswordResult

        public init(device: UUID, scannedAt: Date, result: PwnedPasswordResult) {
            self.device = device
            self.scannedAt = scannedAt
            self.result = result
        }
    }

    public let itemID: UUID
    public let itemVersion: UInt64
    /// Per password field of the item at `itemVersion`: what other devices reported about that field's password.
    public let fields: [UUID: [Observation]]

    public init(itemID: UUID, itemVersion: UInt64, fields: [UUID: [Observation]]) {
        self.itemID = itemID
        self.itemVersion = itemVersion
        self.fields = fields.filter { !$0.value.isEmpty }
    }

    /// The evidence in `record` about `item`'s passwords: for each observation by another device than `ownDevice`,
    /// under a key `bindingKey` gives, each password field whose binding the observation holds. Observations whose
    /// key `bindingKey` does not give (it is not this vault's, or not held) say nothing. The keys stay the caller's,
    /// which zeroises them.
    public static func matching(
        _ record: SyncedScanRecord, item: Item, ownDevice: UUID, bindingKey: (UUID) -> ScanBindingKey?
    ) -> SyncedScanEvidence {
        var fields: [UUID: [Observation]] = [:]
        var bindings: [UUID: [(field: UUID, binding: ScanBinding)]] = [:]
        let passwordFields = ItemAnalyzer.passwordFields(of: item)
        for observation in record.observations.values.sorted(by: { $0.device.uuidString < $1.device.uuidString })
        where observation.device != ownDevice {
            if bindings[observation.keyID] == nil {
                guard let key = bindingKey(observation.keyID) else { continue }
                bindings[observation.keyID] = passwordFields.map {
                    ($0.id, key.binding(item: item.id, utf8Of: $0.value))
                }
            }
            for (field, binding) in bindings[observation.keyID] ?? [] {
                guard let occurrences = observation.results[binding] else { continue }
                fields[field, default: []].append(
                    Observation(
                        device: observation.device, scannedAt: observation.scannedAt,
                        result: occurrences == 0 ? .notFound : .found(occurrences: occurrences)))
            }
        }
        return SyncedScanEvidence(itemID: item.id, itemVersion: item.version, fields: fields)
    }
}

extension SyncedScanEvidence: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String {
        "SyncedScanEvidence(item: \(itemID), version \(itemVersion), \(fields.count) fields, results withheld)"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: ["itemID": itemID, "itemVersion": itemVersion], displayStyle: .struct)
    }
}
