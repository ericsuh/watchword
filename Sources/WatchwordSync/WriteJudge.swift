import Foundation
import WatchwordEnvelope
import WatchwordStore

/// What a `WriteJudge` makes of one segment of a stream (docs/02-architecture.md §8.7, §8.8).
public enum SegmentAdmission: Sendable, Hashable {
    /// Its entries are merged, as for any vault.
    case apply
    /// It does not count: its entries are kept for the person (`SyncStateStore.quarantine`), never merged and never
    /// published on, and the stream carries on past it.
    case holdAside
    /// Whether it counts cannot be told yet (the segments that bind a write cut are not all here): the stream waits
    /// at it, as at a gap, and the next sync asks again.
    case wait
}

/// Which writes count in a vault several accounts write to: the integration side of a shared vault's write cut
/// (docs/02-architecture.md §8.7, review finding S28). Production: `VaultSession`'s sync adapter, which answers from
/// the vault's membership ledger, the members' device registries and an index of what each device's stream carried;
/// a vault of one account has no judge, and everything signed by its devices counts.
///
/// The engine asks before it applies anything: `admitsSegment` for each segment in stream order, and `admits` for
/// every record version a segment or snapshot carries, whoever signed it, because a member who merged a write before
/// it stopped counting publishes that write on inside versions of their own. A version that is not admitted is held
/// aside like a quarantined one (kept, not merged, not published on) and the stream continues.
///
/// Portable: the judge does the cryptography (digests, signatures) and the engine passes bytes, so this module
/// stays free of CryptoKit.
public protocol WriteJudge: Sendable {
    /// Called with every segment of a stream that is about to be merged, and with each segment this device
    /// publishes, before anything in it is judged: what the judge needs to bind a write cut to objects (the
    /// segment's name and bytes) and to attribute each record version to the stream that first carried it.
    func record(
        segment location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8], entries: [SyncEntry]
    ) async throws

    /// Whether the entries of this segment count. Asked in stream order, after `record` has seen every segment of
    /// the pass.
    func admitsSegment(_ location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8]) async throws
        -> SegmentAdmission

    /// Whether a remote record version may be stored or merged: every value it holds was written by an account
    /// whose work counts here (`MembershipLedger.writeStanding`), judged value by value through each value's own
    /// revision, not by who sealed the version.
    func admits(_ record: StoredRecord) async throws -> Bool

    /// Whether a segment sealed under `keyID`, which this device does not hold, can be passed over for good: the
    /// vault's membership never entitled this account to that key (it joined after the key was rotated away), so the
    /// segment will never open here, and what it carried reaches this device sealed again under a later key. Any
    /// other key it does not hold makes the stream wait, as before.
    func passesOverSegment(sealedUnder keyID: UUID, vaultID: UUID) async -> Bool
}
