import Foundation
import Testing
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordSync

/// Milestone 3's exit criterion (docs/03-implementation-plan.md; docs/04-test-plan.md §3, F7.x): N devices, random
/// partitions, concurrent edits and deletions, an eventually consistent server that reorders and duplicates listings,
/// devices locking and unlocking — and after the partition heals, every device holds the same items.
///
/// Named `LongRunning…` so the nightly `test:long` run picks it up with `WATCHWORD_LONG_TESTS=1`, which widens the
/// schedule, and `WATCHWORD_TEST_SEED`, which varies it; a failing nightly is replayed with its seed.
@Suite("Multi-device sync simulation")
struct LongRunningSyncSimulationTests {
    @Test("devices converge under random schedules, partitions, delays, locks and offline edits", arguments: [1, 2, 3])
    func convergence(_ run: UInt64) async throws {
        let seed = TestEnvironment.seed(fallback: 0x5EED_0000) &+ run
        var generator = SeededGenerator(seed: seed)
        let deviceCount = TestEnvironment.iterations(standard: 3, long: 5)
        let steps = TestEnvironment.iterations(standard: 300, long: 2_500)

        let server = SimulatedServer(seed: seed, maximumVisibilityDelay: 4, duplicateListings: true)
        let keys = FakeAccountKeys(seed: seed)
        await keys.addVaultKey(vaultID: Household.vault)
        var configuration = SyncTestClient.configuration
        configuration.snapshotThreshold = 6
        var devices: [SyncTestClient] = []
        for _ in 0..<deviceCount {
            let id = UUID.random(using: &generator)
            await keys.trust(device: id)
            devices.append(
                SyncTestClient(
                    deviceID: id, vaultID: Household.vault, keys: keys, transport: await server.transport(for: id),
                    configuration: configuration))
        }

        // A stray object under the vault's prefix that nobody can verify.
        let stray = UUID.random(using: &generator)
        await server.plant(
            SyncObjectLocation.segment(vaultID: Household.vault, author: stray, sequence: 1).name, contents: [1, 2, 3])

        var itemIDs: [UUID] = []
        var secrets: [String] = []
        // Every field value any device saved, by item; and the items someone erased (explicitly).
        var savedValues: [UUID: Set<String>] = [:]
        var erased: Set<UUID> = []
        var savedStates: [Int: SyncState] = [:]
        var locked: Set<Int> = []
        var rejections: [SyncRejection] = []
        var plantedCopies = 0
        var forkedNames: Set<String> = []
        var forksMerged: Set<String> = []
        for step in 0..<steps {
            await server.advance()
            let index = Int.random(in: 0..<deviceCount, using: &generator)
            let device = devices[index]
            let roll = Int.random(in: 0..<100, using: &generator)
            // Opened only when the step needs them: decrypting every item at every step dominated the run time.
            let existing = (10..<49).contains(roll) && !locked.contains(index) ? try await device.items() : [:]
            switch roll {
            case 0..<10 where !locked.contains(index):
                let secret = "s3cret-\(seed)-\(step)"
                secrets.append(secret)
                let item = try await device.save(
                    Household.login(UUID.random(using: &generator), title: "Title-\(step)", password: secret))
                itemIDs.append(item.id)
                savedValues[item.id, default: []].formUnion(item.fields.map(\.value))
            case 10..<45 where !locked.contains(index) && !existing.isEmpty:
                let id = existing.keys.sorted { $0.precedes($1) }[Int.random(in: 0..<existing.count, using: &generator)]
                var edited = existing[id]!
                ItemMergeTests.randomEdit(&edited, using: &generator)
                let saved = try await device.save(edited)
                savedValues[id, default: []].formUnion(saved.fields.map(\.value))
            case 45..<49 where !locked.contains(index) && !existing.isEmpty:
                let id = existing.keys.sorted { $0.precedes($1) }[Int.random(in: 0..<existing.count, using: &generator)]
                try await device.delete(id)
                erased.insert(id)
            case 49..<55:
                // Offline about a third of the time it is decided.
                let target = Int.random(in: 0..<deviceCount, using: &generator)
                await server.setOffline(devices[target].deviceID, Int.random(in: 0..<3, using: &generator) == 0)
            case 55..<58 where !locked.contains(index):
                locked.insert(index)
                await device.keyring.lock()
            case 58:
                // Now and then the device's sync state is rolled back (a restored backup): it must recover.
                if let saved = savedStates[index] {
                    await device.syncState.tamper(saved)
                } else if let current = await device.state() {
                    savedStates[index] = current
                }
            case 59:
                // Someone with the store (A1) plants a junk copy beside an object: a conflict version, or a renamed
                // file (§7.5). It must cost a check and change nothing.
                let names = await server.allObjects.keys.sorted()
                if !names.isEmpty {
                    let name = names[Int.random(in: 0..<names.count, using: &generator)]
                    await server.plantCopy(name, contents: [UInt8(truncatingIfNeeded: step), 0x4A, 0x55, 0x4E, 0x4B])
                    plantedCopies += 1
                }
            case 60 where !locked.contains(index):
                // The device's stream forks: a second, validly signed copy of its newest segment, carrying what it
                // holds of its own writing now, as an installation restored from a backup would publish it.
                if let sequence = await device.state()?.lastPublishedSequence, sequence > 0 {
                    let name = SyncObjectLocation.segment(
                        vaultID: Household.vault, author: await device.deviceID, sequence: sequence
                    ).name
                    if await server.allObjects[name] != nil {
                        let id = await device.deviceID
                        let rows = await device.store.records(in: Household.vault, kind: .item).filter {
                            $0.deviceID == id
                        }
                        await server.plantCopy(name, contents: try await device.signedSegment(sequence, carrying: rows))
                        forkedNames.insert(name)
                    }
                }
            default:
                // A locked device syncs (download only) or is unlocked first, as the person returns to it.
                if locked.contains(index), Bool.random(using: &generator) {
                    locked.remove(index)
                    await device.keyring.unlock()
                }
                let report = try await device.sync()
                rejections += report.rejected
                forksMerged.formUnion(report.forkedObjects)
            }
        }

        // Heal: everyone online and unlocked, everything visible, sync until nothing changes.
        await server.heal()
        for device in devices { await device.keyring.unlock() }
        var settled = false
        for _ in 0..<16 where !settled {
            settled = true
            await server.heal()
            for device in devices {
                let report = try await device.sync()
                rejections += report.rejected
                forksMerged.formUnion(report.forkedObjects)
                #expect(report.quarantined.isEmpty)
                if report.applied > 0 || report.segmentsWritten > 0 || report.snapshotsWritten > 0 { settled = false }
            }
        }
        #expect(settled, "seed \(seed): devices kept changing after the partition healed")
        // The schedule did exercise conflict copies, and only names that were forked were merged as forks.
        #expect(plantedCopies > 0 && forksMerged.isSubset(of: forkedNames), "seed \(seed)")
        for device in devices {
            #expect(await device.state()?.handOnOwed == false, "seed \(seed): a fork was never handed on")
        }
        // The stray object is the only thing an honest run rejects.
        #expect(
            rejections.allSatisfy { $0.reason == .format(.badMagic) || $0.reason == .format(.truncated) },
            "seed \(seed): an honest run rejected \(rejections)")

        let reference = try await devices[0].items().mapValues(MergeFixtures.current)
        for device in devices.dropFirst() {
            let mine = try await device.items().mapValues(MergeFixtures.current)
            #expect(mine == reference, "seed \(seed)")
        }

        // Nothing anyone typed was lost: every field value saved for an item nobody erased is still in it on every
        // device — shown, kept as a conflict, retained after an edit settled one, or in its history (PRD F7.7).
        for device in devices {
            let items = try await device.items()
            for (id, values) in savedValues where !erased.contains(id) {
                guard let item = items[id] else {
                    Issue.record("seed \(seed): item \(id) disappeared though nobody erased it")
                    continue
                }
                var present = Set(item.fields.map(\.value))
                present.formUnion(item.history.flatMap(\.fields).map(\.value))
                for conflict in Array(item.conflicts.values.joined()) + item.retainedValues {
                    if case .field(let field?) = conflict.value { present.insert(field.value) }
                }
                let lost = values.subtracting(present)
                #expect(lost.isEmpty, "seed \(seed): values lost from \(id): \(lost)")
            }
        }

        // A device that joins now, from whatever snapshots and segments remain, sees the same vault.
        let late = UUID.random(using: &generator)
        await keys.trust(device: late)
        let joiner = SyncTestClient(
            deviceID: late, vaultID: Household.vault, keys: keys, transport: await server.transport(for: late),
            configuration: configuration)
        let joined = try await joiner.sync()
        #expect(
            joined.rejected.count == 1 && Set(joined.waiting.keys).isSubset(of: [stray]),
            "seed \(seed): \(joined.rejected) \(joined.waiting)")
        #expect(try await joiner.items().mapValues(MergeFixtures.current) == reference, "seed \(seed)")

        // Transports carry ciphertext only (F7.3): no title or password the run wrote appears in any object.
        let objects = await server.allObjects.values
        for secret in secrets.prefix(50) + ["Title-"] {
            let needle = Array(secret.utf8)
            for bytes in objects {
                let found =
                    bytes.count >= needle.count
                    && (0...(bytes.count - needle.count)).contains {
                        bytes[$0..<($0 + needle.count)].elementsEqual(needle)
                    }
                #expect(!found, "seed \(seed): \(secret) reached the transport")
            }
        }
    }
}

extension UUID {
    static func random(using generator: inout SeededGenerator) -> UUID {
        let a = generator.next()
        let b = generator.next()
        let bytes =
            (0..<8).map { UInt8(truncatingIfNeeded: a >> (8 * $0)) }
            + (0..<8).map {
                UInt8(truncatingIfNeeded: b >> (8 * $0))
            }
        return UUID(
            uuid: (
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6] & 0x0F | 0x40, bytes[7],
                bytes[8] & 0x3F | 0x80, bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
            ))
    }
}
