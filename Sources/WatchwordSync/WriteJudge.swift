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
    /// Its signer's work cannot count here at all (a member the vault never let write): the stream carries on past it
    /// as past a held-aside one, and nothing it carries is kept, so that such a signer cannot fill the quarantine or
    /// squat at a number in another device's stream (review finding Z137). The log still holds it, and a replay judges
    /// it again if the signer's standing changes.
    case passOver
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
/// it stopped counting publishes that write on inside versions of their own, and `admitsErasure` for every tombstone
/// of a segment or a snapshot it applies, whose erasure summary is a claim about what its author had seen. A version
/// or tombstone that is not admitted is held aside like a quarantined one (kept, not merged, not published on) and
/// the stream continues.
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

    /// Called instead of `record` with a segment of the pass that carries its signatures and does not open here,
    /// because it is sealed under a key this device does not hold: its name, its bytes and its signer are known
    /// without the key. A judge that names a stream's account by its first segment, or binds a write cut to the
    /// run of a stream's objects, needs them from every device alike, whichever keys each holds (review finding
    /// Z51). The same segment may be given to `record` later, once it opens.
    func recordUnopened(segment location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8]) async throws

    /// Called with each snapshot of the pass that opened and validated, before any of its entries is judged: its
    /// coverage vector, the segments of each stream it says it merged. A judge that keeps a whole log reads snapshots
    /// only from before it began (a shared vault's owner's, for the segments collected then), and needs to know which
    /// of a stream's missing first segments such a snapshot accounts for (review finding Z151).
    func recordSnapshot(_ location: SyncObjectLocation, covering vector: [UUID: UInt64]) async throws

    /// Whether the entries of this segment count. Asked in stream order, after `record` has seen every segment of
    /// the pass.
    func admitsSegment(_ location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8]) async throws
        -> SegmentAdmission

    /// Whether a remote record version may be stored or merged: every value it holds was written by an account
    /// whose work counts here (`MembershipLedger.writeStanding`), judged value by value through each value's own
    /// revision, not by who sealed the version.
    func admits(_ record: StoredRecord) async throws -> Bool

    /// Whether a permanent deletion a segment carries may be applied and remembered: what its erasure summary says its
    /// author had seen must be work that counts here, as a version's clock must (review finding S45). A device that
    /// merged a late write and then deleted the item claims, in its summary, what the late writer had seen, and would
    /// erase an honest version it was shown only through that write. Asked for each tombstone of a segment or a
    /// snapshot that is applied, before anything else is done with it; one that is not admitted is held aside like a
    /// version, and a replay asks again. `location` is the object that carried it and `keyID` the key that object
    /// was sealed under.
    func admitsErasure(_ entry: SyncEntry, in location: SyncObjectLocation, sealedUnder keyID: UUID) async throws
        -> Bool

    /// Whether a segment sealed under `keyID`, which this device does not hold, can be passed over for good: the
    /// vault's membership never entitled this account to that key (it joined after the key was rotated away), so the
    /// segment will never open here, and what it carried reaches this device sealed again under a later key. Any
    /// other key it does not hold makes the stream wait, as before.
    func passesOverSegment(sealedUnder keyID: UUID, vaultID: UUID) async -> Bool
}

extension WriteJudge {
    /// A judge that keeps nothing by stream has nothing to note of a segment it cannot open.
    public func recordUnopened(segment location: SyncObjectLocation, signature: [UInt8], envelope: [UInt8])
        async throws
    {
    }

    /// A judge that keeps nothing by stream has nothing to note of a snapshot.
    public func recordSnapshot(_ location: SyncObjectLocation, covering vector: [UUID: UInt64]) async throws {}

    /// A judge that has nothing to say about erasures admits every one.
    public func admitsErasure(_ entry: SyncEntry, in location: SyncObjectLocation, sealedUnder keyID: UUID)
        async throws -> Bool
    {
        true
    }
}
