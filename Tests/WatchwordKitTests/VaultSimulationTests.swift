import Foundation
import Testing
import WatchwordCrypto
import WatchwordModel
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

/// The multi-device simulation again, one level up (docs/04-test-plan.md §3.3): every device is a real `VaultSession`
/// — AES-GCM, Ed25519, the device registry, enrolment from the transport — over an eventually consistent server that
/// delays, reorders and duplicates. A random schedule of saves, edits, trashes, deletions and conflict resolutions
/// across several vaults; vaults created, renamed and deleted; items copied and moved between vaults; devices locking
/// and going offline; a device enrolling half-way; a device lost and revoked (with or without a password change)
/// while the others keep working; and a device restored from an older backup onto other hardware, while the device
/// it was backed up from keeps working under its old ID (review of round 13). Afterwards every device still in the
/// account holds the same vaults and the same items, a device that enrols then sees the same, and nothing anyone
/// typed was lost unless a person discarded it (PRD F7.6, F7.7).
///
/// Named `LongRunning…` so the nightly `test:long` run widens it (`WATCHWORD_LONG_TESTS=1`) and varies it
/// (`WATCHWORD_TEST_SEED`); a failing nightly is replayed with its seed.
@Suite("Multi-device vault simulation")
struct LongRunningVaultSimulationTests {
    /// One device in the run.
    final class Device {
        let index: Int
        let vault: TestVault
        var password: String
        var isLocked = false
        /// Lost and revoked: never driven again, and not expected to agree with anyone.
        var isLost = false

        init(index: Int, vault: TestVault, password: String) {
            self.index = index
            self.vault = vault
            self.password = password
        }

        var session: VaultSession { vault.session }
    }

    static let tokenPrefix = "tok-"

    static func uuid(using generator: inout SeededGenerator) -> UUID {
        var bytes = (0..<2).flatMap { _ in
            let word = generator.next()
            return (0..<8).map { UInt8(truncatingIfNeeded: word >> (8 * $0)) }
        }
        bytes[6] = (bytes[6] & 0x0F) | 0x40
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return UUID(
            uuid: (
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
                bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
            ))
    }

    /// Every token (a value some device typed) an item holds, wherever it holds it.
    static func tokens(in item: Item) -> Set<String> {
        var found = Set(item.fields.map(\.value))
        found.formUnion(item.history.flatMap(\.fields).map(\.value))
        for conflict in Array(item.conflicts.values.joined()) + item.retainedValues {
            if case .field(let field?) = conflict.value { found.insert(field.value) }
        }
        return found.filter { $0.hasPrefix(tokenPrefix) }
    }

    static func tokens(on device: Device) async throws -> Set<String> {
        try await device.session.items().items.reduce(into: Set<String>()) { $0.formUnion(tokens(in: $1)) }
    }

    @Test(
        "devices converge, and lose nothing, across vaults, moves, enrolment and a revocation",
        arguments: [1, 2, 3] as [UInt64])
    func convergence(_ run: UInt64) async throws {
        let seed = TestEnvironment.seed(fallback: 0xACC0_0000) &+ run
        var generator = SeededGenerator(seed: seed)
        let steps = TestEnvironment.iterations(standard: 160, long: 700)
        let initialDevices = TestEnvironment.iterations(standard: 3, long: 4)
        let server = SimulatedServer(seed: seed, maximumVisibilityDelay: 3, duplicateListings: true)
        var settings = SyncConfiguration(schemaVersions: [
            .item: ItemCodec.schemaVersion, .vaultMetadata: VaultMetadataCodec.schemaVersion,
        ])
        settings.snapshotThreshold = 6
        let configuration = settings

        func makeVault(_ index: Int) async -> TestVault {
            TestVault(
                sync: SyncSettings(
                    state: InMemorySyncStateStore(), transport: await server.transport(for: Fleet.deviceID(index)),
                    configuration: configuration),
                // Never the run's own seed: device 0's session drew the same UUIDs as `generator`, and a copy's new ID
                // landed on an item the run had created (a collision of the harness, not of the session).
                seed: seed &+ UInt64(index + 1) &* 7_919, deviceName: "Device \(index)")
        }

        var passwords = [TestVault.password]
        let first = Device(index: 0, vault: await makeVault(0), password: passwords[0])
        let kit = try await first.vault.createAccount()
        var devices = [first]
        // Tokens a person discarded (a permanent deletion, a deleted vault, a conflict settled), which may be gone;
        // and tokens a lost device had typed that the device revoking it had not received, which are refused.
        var typed: Set<String> = []
        var discardable: Set<String> = []
        var secrets: [String] = []
        var counter = 0
        var enrolments = 0
        var revocations = 0
        // A backup of one device's store and sync state, taken a sixth of the way in and restored onto other hardware
        // a quarter of the way in (before any revocation, so with the password it was taken under), while the device
        // it came from goes on under its old ID: old hardware still running. The restored device registers a new ID
        // and carries over what the backup held that its state did not record as published.
        var backup: (source: Device, password: String, store: InMemoryRecordStore, state: InMemorySyncStateStore)?
        var restores = 0
        // What each device did, item by item: the failure message for a divergence is the history of the items
        // concerned, which with the seed is what it takes to reproduce it.
        var journal: [String] = []

        func note(_ step: Int, _ device: Device, _ text: String) {
            journal.append("\(step) d\(device.index) \(text)")
        }

        func history(of ids: Set<UUID>) -> String {
            journal.filter { line in
                line.contains("REVOKE") || line.contains("BACKUP") || line.contains("RESTORED")
                    || ids.contains { line.contains($0.uuidString) }
            }
            .joined(separator: "\n")
        }

        func enrol(_ index: Int) async -> Bool {
            let vault = await makeVault(index)
            do {
                try await vault.session.enrol(
                    password: passwords[passwords.count - 1], secretKey: kit.secretKey, accountID: kit.accountID,
                    assigningDeviceID: Fleet.deviceID(index))
                devices.append(Device(index: index, vault: vault, password: passwords[passwords.count - 1]))
                return true
            } catch {
                // The header, the registry or the personal vault's key is not visible to it yet: later.
                return false
            }
        }

        /// Unlocks with the newest password the device accepts, as the person would try.
        func unlock(_ device: Device) async {
            for password in passwords.reversed() {
                do {
                    try await device.session.unlock(password: password)
                    device.password = password
                    device.isLocked = false
                    return
                } catch {
                    continue
                }
            }
        }

        func nextToken() -> String {
            counter += 1
            let token = "\(Self.tokenPrefix)\(seed)-\(counter)"
            typed.insert(token)
            if secrets.count < 40 { secrets.append(token) }
            return token
        }

        func pick<T>(_ values: [T]) -> T? {
            values.isEmpty ? nil : values[Int.random(in: 0..<values.count, using: &generator)]
        }

        for step in 0..<steps {
            await server.advance()
            // Enrolments at fixed points of the run, retried now and then until the transport shows enough: a new
            // device can only join once the header, the registry and the personal vault's key are visible to it.
            if step % 4 == 0, devices.count < initialDevices || (step > steps / 2 && enrolments < 1) {
                if await enrol(devices.count) {
                    if devices.count > initialDevices { enrolments += 1 }
                } else if devices.count == 1 {
                    // Nothing is on the transport until the first device has synced once.
                    _ = try? await devices[0].session.sync()
                }
            }
            if step >= steps / 6, backup == nil, let source = pick(devices.filter { !$0.isLost }),
                let saved = await source.vault.backup()
            {
                backup = (source, source.password, saved.store, saved.state)
                note(step, source, "BACKUP")
            }
            if step >= steps / 4, restores == 0, let saved = backup {
                let index = devices.count
                let vault = TestVault(
                    store: saved.store,
                    sync: SyncSettings(
                        state: saved.state, transport: await server.transport(for: Fleet.deviceID(index)),
                        configuration: configuration),
                    seed: seed &+ UInt64(index + 1) &* 7_919, deviceName: "Device \(index)")
                do {
                    // A new Keychain: the Secret Key off the Emergency Kit, and no device key.
                    try await vault.session.unlock(password: saved.password, secretKey: kit.secretKey)
                    devices.append(Device(index: index, vault: vault, password: saved.password))
                    restores += 1
                    note(step, saved.source, "RESTORED from its backup as d\(index)")
                } catch {
                    // The transport did not show enough yet: tried again at the next step.
                }
            }
            let active = devices.filter { !$0.isLost }
            guard let device = pick(active) else { continue }
            let roll = Int.random(in: 0..<100, using: &generator)

            if device.isLocked {
                // A locked device downloads, or the person comes back to it.
                if roll < 50 { await unlock(device) } else { _ = try? await device.session.sync() }
                continue
            }
            let session = device.session
            do {
                switch roll {
                case 0..<12:
                    guard let vault = pick(try await session.vaults()) else { break }
                    var draft = login(
                        vault.id, title: "Title-\(step)", host: "site\(step % 7).example", password: nextToken())
                    // IDs from the run's own generator, so a seed replays the same run.
                    draft.id = Self.uuid(using: &generator)
                    for index in draft.fields.indices { draft.fields[index].id = Self.uuid(using: &generator) }
                    // The simulation's hosts differ by one digit, which is a near miss to the look-alike check.
                    let made = try await session.save(draft, confirmingHosts: Set(draft.scopes.map(\.host)))
                    note(step, device, "create \(made.id) in \(vault.id)")
                case 12..<40:
                    guard var item = pick(try await session.items().items.filter { !$0.isTrashed }) else { break }
                    switch Int.random(in: 0..<4, using: &generator) {
                    case 0: item.title = "Renamed-\(step)"
                    case 1: item.notes += "line \(step)\n"
                    case 2: item.tags.insert("tag\(step % 5)")
                    default:
                        if let index = item.fields.firstIndex(where: { $0.kind == .password }) {
                            item.fields[index].value = nextToken()
                        }
                    }
                    try await session.save(item)
                    note(step, device, "edit \(item.id)")
                case 40..<44:
                    guard let item = pick(try await session.items().items.filter { !$0.isTrashed }) else { break }
                    try await session.trash(id: item.id)
                    note(step, device, "trash \(item.id)")
                case 44..<46:
                    let deleted = Set(try await session.vaults(includingDeleted: true).filter(\.isDeleted).map(\.id))
                    guard
                        let item = pick(
                            try await session.items().items.filter { $0.isTrashed && !deleted.contains($0.vaultID) })
                    else { break }
                    try await session.restore(id: item.id)
                    note(step, device, "restore \(item.id)")
                case 46..<49:
                    guard let item = pick(try await session.items().items.filter(\.isTrashed)) else { break }
                    discardable.formUnion(Self.tokens(in: item))
                    try await session.deletePermanently(id: item.id)
                    note(step, device, "delete \(item.id)")
                case 49..<52:
                    guard try await session.vaults().count < 4 else { break }
                    try await session.createVault(name: "Vault-\(step)")
                case 52..<54:
                    guard let vault = pick(try await session.vaults()) else { break }
                    try await session.renameVault(id: vault.id, to: "Renamed-vault-\(step)")
                case 54..<56:
                    guard let vault = pick(try await session.vaults().filter { !$0.isPersonal }) else { break }
                    let items = try await session.items(in: vault.id).items
                    for item in items {
                        discardable.formUnion(Self.tokens(in: item))
                        note(step, device, "delete vault \(vault.id) holding \(item.id)")
                    }
                    try await session.deleteVault(
                        id: vault.id, confirmingItemCount: try await session.itemCount(in: vault.id))
                case 56..<63:
                    guard let item = pick(try await session.items().items),
                        let destination = pick(try await session.vaults().filter { $0.id != item.vaultID })
                    else { break }
                    do {
                        if roll < 61 {
                            let moved = try await session.move(itemID: item.id, to: destination.id)
                            note(step, device, "move \(item.id) to \(moved.id) in \(destination.id)")
                        } else {
                            let copied = try await session.copy(itemID: item.id, to: destination.id)
                            note(step, device, "copy \(item.id) to \(copied.id)")
                        }
                    } catch VaultError.itemHasUnresolvedValues, VaultError.itemIsTrashed {
                        // The person is told why; nothing moved.
                    }
                case 63..<67:
                    guard let item = pick(try await session.items().items.filter(\.hasConflicts)),
                        let (group, alternatives) = item.conflicts.first(where: { !$0.value.isEmpty }),
                        let chosen = pick(alternatives)
                    else { break }
                    // Choosing discards what is not chosen: the person's decision, and theirs alone.
                    discardable.formUnion(Self.tokens(in: item))
                    try await session.resolveConflict(itemID: item.id, group: group, choosing: chosen.value)
                    note(step, device, "resolve \(item.id)")
                case 67..<73:
                    let target = pick(active) ?? device
                    await server.setOffline(
                        Fleet.deviceID(target.index), Int.random(in: 0..<3, using: &generator) == 0)
                case 73..<75:
                    await session.lock()
                    device.isLocked = true
                case 75..<77 where step > steps / 3 && revocations < 1 && active.count >= 3:
                    // A device is lost. Another, still in the person's hands, revokes it; sometimes the password
                    // changes with it.
                    guard let lost = pick(active.filter { $0.index != device.index && $0.index != 0 }) else { break }
                    let known = try await session.devices()
                    guard known.contains(where: { $0.id == Fleet.deviceID(lost.index) && !$0.isRevoked }) else {
                        break
                    }
                    let lostTokens = try await Self.tokens(on: lost)
                    if Bool.random(using: &generator) {
                        let new = "password-after-revocation-\(seed)"
                        try await session.revokeDevice(
                            Fleet.deviceID(lost.index), password: .change(current: device.password, new: new))
                        passwords.append(new)
                        device.password = new
                    } else {
                        try await session.revokeDevice(
                            Fleet.deviceID(lost.index), password: .keepPassword(current: device.password))
                    }
                    // What the lost device had typed and this one had not received is refused from now on.
                    discardable.formUnion(lostTokens.subtracting(try await Self.tokens(on: device)))
                    lost.isLost = true
                    note(step, device, "REVOKE d\(lost.index), passwords now \(passwords.count)")
                    revocations += 1
                    await server.setOffline(Fleet.deviceID(lost.index), true)
                default:
                    let report = try await session.syncAll()
                    note(step, device, "sync")
                    #expect(report.combined.quarantined.isEmpty, "seed \(seed)")
                    if report.awaitingNewPassword {
                        // The person enters the new password on this device.
                        await session.lock()
                        device.isLocked = true
                        await unlock(device)
                    }
                }
            } catch SyncTransportError.unavailable {
                // Offline.
            } catch VaultError.locked, VaultError.deviceRevoked {
                // Locked in the middle of a step by the schedule above, or told it was revoked.
            }
        }

        // Heal: everyone online, everything visible, everyone unlocked with the current password; sync until quiet.
        let survivors = devices.filter { !$0.isLost }
        for device in survivors { await server.setOffline(Fleet.deviceID(device.index), false) }
        var settled = false
        for _ in 0..<30 where !settled {
            settled = true
            await server.heal()
            for device in devices where !device.isLost {
                await server.setOffline(Fleet.deviceID(device.index), false)
            }
            for device in survivors {
                if device.isLocked { await unlock(device) }
                let report = try await device.session.syncAll()
                if report.awaitingNewPassword || device.isLocked {
                    await device.session.lock()
                    device.isLocked = true
                    await unlock(device)
                    settled = false
                    continue
                }
                let account = report.account
                let total = report.combined
                if total.applied > 0 || total.segmentsWritten > 0 || total.snapshotsWritten > 0
                    || account.registryEntriesFetched + account.registryEntriesPublished > 0
                    || account.vaultKeysFetched + account.vaultKeysPublished > 0
                    || account.vaultDeletionsFetched + account.vaultDeletionsPublished > 0
                    || account.candidateHeadersFetched > 0 || account.headerPublished
                {
                    settled = false
                }
            }
        }
        // The restore happened, once, in every run: a quarter of the way in, retried at each step until it unlocks.
        #expect(restores == 1, "seed \(seed): no device was restored from its backup")
        #expect(settled, "seed \(seed): devices kept changing after the partition healed")
        #expect(survivors.count >= 2, "seed \(seed)")

        // Every device still in the account holds the same vaults and the same items.
        let reference = try await Fleet.seen(survivors[0].vault)
        let vaults = try await survivors[0].session.vaults(includingDeleted: true)
        for device in survivors.dropFirst() {
            let theirs = try await Fleet.seen(device.vault)
            let diverged = Set(theirs.keys).union(reference.keys).filter { theirs[$0] != reference[$0] }
            let ids = diverged.map(\.uuidString).sorted()
            #expect(
                diverged.isEmpty, "seed \(seed): device \(device.index) differs on \(ids)\n\(history(of: diverged))")
            #expect(
                try await device.session.vaults(includingDeleted: true) == vaults, "seed \(seed): \(device.index)")
            #expect(try await device.session.deviceStanding() == .active, "seed \(seed): \(device.index)")
            #expect(try await device.session.items().unreadable.isEmpty, "seed \(seed)")
        }
        // And agrees on who is in it.
        let standing = try await survivors[0].session.devices().map { [$0.id.uuidString, "\($0.isRevoked)"] }
        for device in survivors.dropFirst() {
            let theirs = try await device.session.devices().map { [$0.id.uuidString, "\($0.isRevoked)"] }
            #expect(Set(theirs) == Set(standing), "seed \(seed): device \(device.index)")
        }

        // Nothing anyone typed was lost, unless a person discarded it (PRD F7.7).
        for device in survivors {
            let present = try await Self.tokens(on: device)
            let lost = typed.subtracting(discardable).subtracting(present)
            #expect(lost.isEmpty, "seed \(seed): device \(device.index) lost \(lost.sorted())")
        }

        // A device that enrols now, from whatever the transport still holds, sees the same account.
        let joinerIndex = devices.count
        var joined = false
        for _ in 0..<4 where !joined {
            await server.heal()
            joined = await enrol(joinerIndex)
        }
        #expect(joined, "seed \(seed): a new device could not enrol")
        if joined, let joiner = devices.last {
            for _ in 0..<6 {
                await server.heal()
                try await joiner.session.syncAll()
                for device in survivors { try await device.session.syncAll() }
            }
            #expect(try await Fleet.seen(joiner.vault) == Fleet.seen(survivors[0].vault), "seed \(seed): joiner")
            #expect(
                try await joiner.session.vaults(includingDeleted: true)
                    == survivors[0].session.vaults(includingDeleted: true), "seed \(seed): joiner")
        }

        // Transports carry ciphertext only (F7.3): no token, title or vault name the run wrote is in any object.
        let objects = await server.allObjects
        for needle in secrets + ["Title-", "Renamed-", "Vault-", "Device "] {
            let bytes = Array(needle.utf8)
            for (name, contents) in objects {
                #expect(!name.contains(needle))
                #expect(!contents.contains(subsequence: bytes), "seed \(seed): \(needle) reached the transport")
            }
        }
    }
}
