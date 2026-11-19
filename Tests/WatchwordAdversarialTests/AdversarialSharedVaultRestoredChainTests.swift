import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

// The review of round 17 (docs/06-adversarial-review.md Z223, Z224): the chain row of a restore's earlier device IDs
// (`RestoredChainRow`, Z216), when it is written and what it refuses. In the suite "shared vaults through the session".
extension AdversarialSharedVaultTests {
    /// Threat: A8, an attacker with the device's files, who copies into this device's sharing store a chain row that
    /// the account genuinely signed for another device of the account (a sibling restored once itself), for the
    /// earlier ID (kept from before this restore, about that ID's own earlier IDs), or for another vault; or a row of
    /// another account; or one unsigned, edited, or signed in another form (review of round 17, Z223). Each would name
    /// as earlier IDs of this installation devices that are not, whose published work the carry would write again as
    /// this device's, which every member then holds twice (Z216's attack with genuine bytes). Only the row this
    /// account signed for this device's ID, in this vault, in its one form names anything.
    @Test("a chain row signed for another device, vault or account, or not in its one form, names nothing")
    func restoredChainRowRefusesEveryOtherBinding() throws {
        let keyset = Keyset.generate(accountID: UUID())
        let signingKey = try keyset.publicKeyBundle().signingKey
        let account = keyset.accountID
        let device = UUID()
        let earlier = UUID()
        let sibling = UUID()
        let vaultID = UUID()
        let named: Set<UUID> = [earlier, UUID()]
        func parsed(_ bytes: [UInt8]) -> Set<UUID>? {
            RestoredChainRow.parse(bytes, device: device, account: account, signingKey: signingKey, vaultID: vaultID)
        }

        let genuine = try RestoredChainRow.signed(
            named, device: device, account: account, vaultID: vaultID, keyset: keyset)
        #expect(parsed(genuine) == named, "the genuine row names nothing: nothing is tested")

        let siblings = try RestoredChainRow.signed(
            named, device: sibling, account: account, vaultID: vaultID, keyset: keyset)
        #expect(parsed(siblings) == nil, "a sibling device's row named IDs for this device")
        let earliers = try RestoredChainRow.signed(
            [UUID()], device: earlier, account: account, vaultID: vaultID, keyset: keyset)
        #expect(parsed(earliers) == nil, "the earlier ID's own row named IDs for this device")
        let elsewhere = try RestoredChainRow.signed(
            named, device: device, account: account, vaultID: UUID(), keyset: keyset)
        #expect(parsed(elsewhere) == nil, "another vault's row named IDs here")

        let stranger = Keyset.generate(accountID: UUID())
        let foreign = try RestoredChainRow.signed(
            named, device: device, account: stranger.accountID, vaultID: vaultID, keyset: stranger)
        #expect(parsed(foreign) == nil, "another account's row named IDs here")
        let impostor = try RestoredChainRow.signed(
            named, device: device, account: account, vaultID: vaultID, keyset: stranger)
        #expect(parsed(impostor) == nil, "a row another account signed in this account's name named IDs here")

        var unsigned = genuine
        unsigned.replaceSubrange((unsigned.count - 64)..., with: [UInt8](repeating: 0, count: 64))
        #expect(parsed(unsigned) == nil, "an unsigned row named IDs")
        #expect(parsed(Array(genuine.dropLast(64))) == nil, "a row with no signature named IDs")
        var edited = genuine
        edited[edited.count - 65] ^= 1
        #expect(parsed(edited) == nil, "an edited row named IDs")
        #expect(parsed([]) == nil)

        // The same binding under another row's magic (the key provenance row, bound to an owner's ID).
        let provenance = try SharedKeyProvenance.signed(
            named, owner: device, account: account, vaultID: vaultID, keyset: keyset)
        #expect(parsed(provenance) == nil, "a key provenance row parsed as a chain row")

        // Signed by the account, but not in the row's one form: items out of order, repeated, or miscounted.
        func signedBody(_ items: [UUID], count: Int) throws -> [UInt8] {
            var body: [UInt8] = RestoredChainRow.magic + [SignedLocalSet.formatVersion]
            body += SharedBytes.bytes(account)
            body += SharedBytes.bytes(vaultID)
            body += SharedBytes.bytes(device)
            body += SharedBytes.littleEndian32(UInt32(count))
            for item in items { body += SharedBytes.bytes(item) }
            return body + (try keyset.sign(body, domain: .membership))
        }
        let ordered = named.sorted { SharedBytes.bytes($0).lexicographicallyPrecedes(SharedBytes.bytes($1)) }
        let handBuilt = try signedBody(ordered, count: 2)
        #expect(parsed(handBuilt) == named, "the hand-built row is not the row's form")
        let reversed: [UUID] = ordered.reversed()
        let outOfOrder = try signedBody(reversed, count: 2)
        #expect(parsed(outOfOrder) == nil, "a row with items out of order named IDs")
        let repeated: [UUID] = [ordered[0], ordered[0]]
        let twice = try signedBody(repeated, count: 2)
        #expect(parsed(twice) == nil, "a row with a repeated item named IDs")
        let overCounted = try signedBody(ordered, count: 3)
        #expect(parsed(overCounted) == nil, "a miscounted row named IDs")
        let underCounted = try signedBody(ordered, count: 1)
        #expect(parsed(underCounted) == nil, "a miscounted row named IDs")
    }

    /// Threat: none needed but a crash, or a sharing store that cannot be written, between the save of a vault's state
    /// that `recordRestoredWorkLeft` starts over and that vault's chain row (review of round 17, Z224), then the state
    /// damaged again (A8, or the disk). The earlier ID that state names came from another vault's chain, and the
    /// other vault's carry has since removed it there; the row of the vault started over is then all that names it.
    /// The row is written before the state, with the IDs the state is about to name (Z216): written only after, it
    /// was never written, the chain was empty once the state was damaged, and the hold failed open on rows the
    /// earlier ID left. Here those rows are ones that ID published, in a vault held closed, whose stream this device
    /// cannot read: they count, as Z200 accepts.
    @Test("a crash between a started-over state and its chain row leaves the chain naming the state's earlier IDs")
    func restoredChainRowWrittenBeforeTheState() async throws {
        let household = SharedVaultHousehold()
        let (open, owner, members) = try await household.household(roles: [.readWrite], seed: 31_100)
        let member = members[0]
        let closer = try await household.account(seed: 31_150)
        let closed = try await closer.session.createVault(name: "Second").id
        try await closer.session.shareVault(closed)
        try await closer.invite(member, to: closed, as: .readWrite, owner: closer)
        try await Self.syncAll([closer, member])
        let published = try await member.session.save(Self.bank(in: closed))
        try await Self.syncAll([member, owner, closer])
        let pending = try await member.session.save(Self.bank(in: open))

        // Restored without the second owner's pin: that vault is held closed here, and the first one opens.
        await member.session.lock()
        await member.contacts.removePin(for: closer.accountID)
        await member.vault.forgetDeviceKey(accountID: member.accountID)
        let raw = try #require(member.vault.sync?.state as? InMemorySyncStateStore)
        let sharingState = ChainRowFailingSharingStore(base: member.state, syncState: raw, vaultID: closed)
        let restored = member.vault.relaunched(seed: 31_101)
        await restored.session.configureSharing(
            SharingSettings(state: sharingState, contacts: member.contacts, directory: household.directory))
        try await restored.session.unlock(password: TestVault.password)
        #expect(try await restored.store.loadAccount()?.migration == nil, "the move did not finish at the unlock")
        let earlier = try #require(await raw.loadState(vaultID: open)?.restoredUnpublished.values.first?.device)
        #expect(await raw.loadState(vaultID: closed)?.restoredUnpublished.isEmpty == true)
        #expect(await member.state.value(.restoredChain, vaultID: closed) == nil)

        func damage(_ vaultID: UUID) async throws {
            var state = try #require(await raw.loadState(vaultID: vaultID))
            state.authenticator = Array(repeating: 0, count: state.authenticator.count)
            await raw.tamper(state)
        }
        // The closed vault's state damaged: the sync starts it over, naming the rows the earlier ID left there, and
        // every write of its row after that save fails.
        try await damage(closed)
        await sharingState.failWritesAfterTheSave()
        let first = try await restored.session.syncAll()
        #expect(first.deletionsHeldBack.contains(closed))
        #expect(await sharingState.refused > 0, "no write of the row failed after the save: nothing is tested")
        let started = try #require(await raw.loadState(vaultID: closed))
        #expect(started.restoredUnpublished[RecordKey(recordID: published.id, kind: .item)]?.device == earlier)
        // The open vault's carry removes the earlier ID from its own state and row.
        for _ in 0..<3 {
            let left = await raw.loadState(vaultID: open)?.restoredUnpublished ?? [:]
            if left.isEmpty { break }
            _ = try await restored.session.syncAll()
        }
        #expect(await raw.loadState(vaultID: open)?.restoredUnpublished.isEmpty == true, "the carry did not finish")
        #expect(await member.state.value(.restoredChain, vaultID: open) == nil)
        _ = pending

        try await damage(closed)
        let report = try await restored.session.syncAll()
        #expect(report.deletionsHeldBack.contains(closed), "the hold failed open: the chain lost the earlier ID")
        #expect(report.restoredWorkWaiting[closed] == [published.id])
    }
}

/// A sharing state store over `base` that, once armed, refuses every write of one vault's chain row
/// (`SharingStateKey.restoredChain`) made after that vault's sync state has been saved since it was last damaged
/// (its authenticator zeroed): a crash, or a store that cannot be written, between the save and the row.
actor ChainRowFailingSharingStore: SharingStateStore {
    struct WriteFailed: Error {}

    let base: InMemorySharingStateStore
    let syncState: InMemorySyncStateStore
    let vaultID: UUID
    private var armed = false
    private(set) var refused = 0

    init(base: InMemorySharingStateStore, syncState: InMemorySyncStateStore, vaultID: UUID) {
        self.base = base
        self.syncState = syncState
        self.vaultID = vaultID
    }

    func failWritesAfterTheSave() {
        armed = true
    }

    func sharedVaultIDs() async throws -> [UUID] { await base.sharedVaultIDs() }

    func value(_ key: SharingStateKey, vaultID: UUID) async throws -> [UInt8]? {
        await base.value(key, vaultID: vaultID)
    }

    func setValue(_ value: [UInt8]?, for key: SharingStateKey, vaultID: UUID) async throws {
        if armed, key == .restoredChain, vaultID == self.vaultID,
            let saved = await syncState.loadState(vaultID: vaultID), saved.authenticator.contains(where: { $0 != 0 })
        {
            refused += 1
            throw WriteFailed()
        }
        await base.setValue(value, for: key, vaultID: vaultID)
    }
}
