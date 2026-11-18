import Foundation
import WatchwordStore

/// How much one vault's quarantine holds, by the device each kept version names as its writer
/// (`SyncStateStore.quarantineUsage`). The engine holds the quarantine to `SyncConfiguration`'s caps with it, and
/// writes no ordinary snapshot while a trusted device's version is in it (review findings Z26 and Z27).
public struct QuarantineUsage: Sendable, Hashable {
    public struct Share: Sendable, Hashable {
        public var entries = 0
        public var bytes = 0

        public init(entries: Int = 0, bytes: Int = 0) {
            self.entries = entries
            self.bytes = bytes
        }
    }

    public var devices: [UUID: Share] = [:]

    public init(devices: [UUID: Share] = [:]) {
        self.devices = devices
    }

    /// Sums saturate: the counts come from a local file (A8), and a total that would overflow reads as full rather
    /// than trapping (review finding Z39).
    public var entries: Int {
        devices.values.reduce(0) { Self.adding($0, $1.entries) }
    }

    public var bytes: Int {
        devices.values.reduce(0) { Self.adding($0, $1.bytes) }
    }

    public mutating func add(_ entry: SyncEntry) {
        var share = devices[entry.device] ?? Share()
        share.entries = Self.adding(share.entries, 1)
        share.bytes = Self.adding(share.bytes, entry.storedLength)
        devices[entry.device] = share
    }

    static func adding(_ a: Int, _ b: Int) -> Int {
        let (sum, overflow) = a.addingReportingOverflow(b)
        return overflow ? .max : sum
    }
}

extension SyncEntry {
    /// What keeping the entry costs: its envelope, or a deletion's erasure summary.
    public var storedLength: Int {
        (envelope?.count ?? 0) + erasure.count
    }

    /// A 64-bit FNV-1a digest of every field, for the indexed column a persistent quarantine finds a duplicate by
    /// (review finding Z27). Not cryptography and not trusted: two entries with one digest are told apart by comparing
    /// them, so a collision costs a comparison and nothing else.
    public var quarantineDigest: UInt64 {
        var hash: UInt64 = 0xCBF2_9CE4_8422_2325
        func mix(_ bytes: some Sequence<UInt8>) {
            for byte in bytes { hash = (hash ^ UInt64(byte)) &* 0x0000_0100_0000_01B3 }
        }
        mix(recordID.byteArray)
        mix([kind.rawValue])
        mix(keyID.byteArray)
        mix((0..<8).map { UInt8(truncatingIfNeeded: version >> (8 * $0)) })
        mix(device.byteArray)
        mix([envelope == nil ? 0 : 1])
        mix(envelope ?? [])
        mix(erasure)
        return hash
    }
}
