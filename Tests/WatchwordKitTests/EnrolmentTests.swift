import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit

@Suite("Vault session: enrolment from the transport (F5.2)")
struct EnrolmentTests {
    /// A, with an account, a second vault and an item in each, synced; nothing copied anywhere.
    static func account() async throws -> (
        transport: InMemorySyncTransport, a: TestVault, kit: EmergencyKit, work: VaultInfo
    ) {
        let transport = InMemorySyncTransport()
        let a = TestVault.syncing(over: transport, name: "Kitchen Mac")
        let kit = try await a.createAccount()
        let work = try await a.session.createVault(name: "Work")
        try await a.session.save(login(try #require(await a.session.personalVaultID), title: "Library"))
        try await a.session.save(login(work.id, title: "Payroll"))
        try await a.session.sync()
        return (transport, a, kit, work)
    }

    static func newDevice(over transport: any SyncTransport, name: String = "New phone", seed: UInt64 = 21)
        -> TestVault
    {
        TestVault.syncing(over: transport, seed: seed, name: name)
    }

    @Test("a second device joins from the transport, the password and the Secret Key alone")
    func enrol() async throws {
        let (transport, a, kit, work) = try await Self.account()
        let b = Self.newDevice(over: transport)
        #expect(try await b.session.state() == .noAccount)
        try await b.session.enrol(password: TestVault.password, secretKey: kit.setupCode)

        #expect(try await b.session.state() == .unlocked)
        let status = try await b.session.status()
        #expect(status.accountID == kit.accountID && status.emergencyKitConfirmed)
        #expect(await b.session.personalVaultID == a.session.personalVaultID)
        #expect(try await b.session.vaults().map(\.id).contains(work.id), "the vault directory came with it")
        #expect(await b.keychain.contains(.secretKey(accountID: kit.accountID)))
        #expect(await b.keychain.contains(.deviceRegistryAnchor(accountID: kit.accountID)))

        try await b.session.sync()
        #expect(try await b.session.items().items.map(\.title) == ["Library", "Payroll"])
        #expect(try await b.session.vaults().map(\.name) == ["Personal", "Work"])
        #expect(try await b.session.deviceStanding() == .active)

        // It is a device like any other: it locks, unlocks with the Keychain's Secret Key, writes, and is listed.
        await b.session.lock()
        try await b.session.unlock(password: TestVault.password)
        try await b.session.save(login(work.id, title: "From the new phone"))
        try await b.session.sync()
        try await a.session.sync()
        #expect(try await a.session.items(in: work.id).items.map(\.title) == ["From the new phone", "Payroll"])
        let devices = try await a.session.devices()
        #expect(devices.map(\.name) == ["Kitchen Mac", "New phone"])
        #expect(devices.map(\.isThisDevice) == [true, false])
        #expect(devices.allSatisfy { !$0.isRevoked && $0.addedBy == nil && $0.addedAt != nil })
    }

    @Test("the Secret Key typed by hand works too, given the account ID")
    func enrolWithTypedSecretKey() async throws {
        let (transport, _, kit, _) = try await Self.account()
        let b = Self.newDevice(over: transport)
        try await b.session.enrol(password: TestVault.password, secretKey: kit.secretKey, accountID: kit.accountID)
        #expect(try await b.session.state() == .unlocked)
    }

    @Test("a wrong password and a wrong Secret Key are the same failure, and leave nothing behind")
    func wrongCredentials() async throws {
        let (transport, _, kit, _) = try await Self.account()
        let other = try await TestVault(seed: 99).createAccount()
        let b = Self.newDevice(over: transport)
        await #expect(throws: CryptoError.authenticationFailed) {
            try await b.session.enrol(password: "not the password!", secretKey: kit.setupCode)
        }
        await #expect(throws: CryptoError.authenticationFailed) {
            try await b.session.enrol(
                password: TestVault.password, secretKey: other.secretKey, accountID: kit.accountID)
        }
        #expect(try await b.session.state() == .noAccount)
        #expect(await b.keychain.isEmpty)
        let store = try #require(b.store as? InMemoryRecordStore)
        #expect(await store.allRecords.isEmpty)
        // And then the right ones still work.
        try await b.session.enrol(password: TestVault.password, secretKey: kit.setupCode)
    }

    @Test("enrolment needs an empty device, a transport, and an account that is on it")
    func preconditions() async throws {
        let (transport, a, kit, _) = try await Self.account()
        await #expect(throws: VaultError.enrolmentUnavailable) {
            try await a.session.enrol(password: TestVault.password, secretKey: kit.setupCode)
        }
        await #expect(throws: VaultError.enrolmentUnavailable) {
            try await TestVault().session.enrol(password: TestVault.password, secretKey: kit.setupCode)
        }
        await #expect(throws: VaultError.enrolmentUnavailable) {
            try await Self.newDevice(over: transport).session.enrol(
                password: TestVault.password, secretKey: kit.secretKey)
        }
        await #expect(throws: VaultError.secretKeyForAnotherAccount) {
            try await Self.newDevice(over: transport).session.enrol(
                password: TestVault.password, secretKey: kit.setupCode, accountID: UUID())
        }
        await #expect(throws: VaultError.accountNotOnTransport) {
            try await Self.newDevice(over: InMemorySyncTransport()).session.enrol(
                password: TestVault.password, secretKey: kit.setupCode)
        }
    }

    @Test("a registered device can vouch for a new one before it has the Secret Key")
    func approvedDevice() async throws {
        let (transport, a, kit, _) = try await Self.account()
        let b = Self.newDevice(over: transport, name: "ignored: the approver names it")
        let identity = try await b.session.prepareDeviceIdentity(accountID: kit.accountID)
        try await a.session.approveDevice(id: identity.id, key: identity.key, name: "Guest tablet")
        try await a.session.sync()

        try await b.session.enrol(password: TestVault.password, secretKey: kit.setupCode, as: identity)
        try await b.session.sync()
        try await a.session.sync()
        let listed = try #require(try await a.session.devices().first { $0.id == identity.id })
        #expect(listed.name == "Guest tablet" && !listed.isRevoked)
        #expect(listed.addedBy == (try await a.session.devices()[0].id), "registered by the device that vouched")
        #expect(try await b.session.items().items.count == 2)

        // An identity this installation holds no key for is not one it can enrol as.
        let c = Self.newDevice(over: transport, seed: 33)
        await #expect(throws: VaultError.enrolmentUnavailable) {
            try await c.session.enrol(password: TestVault.password, secretKey: kit.setupCode, as: identity)
        }
    }

    @Test("an account created before the registry existed starts one at its next unlock")
    func legacyAccount() async throws {
        let transport = InMemorySyncTransport()
        let a = TestVault.syncing(over: transport)
        let kit = try await a.createAccount()
        await a.session.lock()
        // What such an account lacks: registry entries, the published header, the anchor and the device key.
        let store = try #require(a.store as? InMemoryRecordStore)
        let rows = await store.allRecords.filter { $0.kind == .deviceRegistry || $0.kind == .accountHeader }
        try await store.commit(StoreChange(deletions: rows.map(\.key)))
        await a.keychain.delete(.deviceRegistryAnchor(accountID: kit.accountID))
        await a.deviceKeys.forget(accountID: kit.accountID)
        await #expect(throws: VaultError.deviceRegistryUnavailable) { try await a.session.deviceStanding() }

        try await a.session.unlock(password: TestVault.password)
        #expect(try await a.session.deviceStanding() == .active)
        try await a.session.sync()
        let b = Self.newDevice(over: transport)
        try await b.session.enrol(password: TestVault.password, secretKey: kit.setupCode)
        #expect(try await b.session.deviceStanding() == .active)
    }

    @Test("a store restored onto other hardware has no device key, and registers as a new device")
    func restoredStore() async throws {
        let (transport, a, kit, work) = try await Self.account()
        let original = try #require(a.store as? InMemoryRecordStore)
        let oldDevice = try #require(await original.loadAccount()).deviceID
        // The backup: the database, but no Keychain item (they never leave a device).
        let restored = InMemoryRecordStore()
        try await restored.commit(
            StoreChange(
                account: .create(try #require(await original.loadAccount())), upserts: await original.allRecords))
        let b = TestVault(
            store: restored, sync: SyncSettings(state: InMemorySyncStateStore(), transport: transport), seed: 51,
            deviceName: "Restored phone")
        await #expect(throws: VaultError.secretKeyMissing) { try await b.session.unlock(password: TestVault.password) }
        try await b.session.unlock(password: TestVault.password, secretKey: kit.secretKey)

        let newDevice = try #require(await restored.loadAccount()).deviceID
        #expect(newDevice != oldDevice, "it cannot write as the device whose key it does not have")
        #expect(try await b.session.deviceStanding() == .active)
        try await b.session.save(login(work.id, title: "From the restored phone"))
        try await b.session.sync()
        try await a.session.sync()
        #expect(try await a.session.items(in: work.id).items.map(\.title).contains("From the restored phone"))
        #expect(try await a.session.devices().map(\.name) == ["Kitchen Mac", "Restored phone"])
    }
}

@Suite("Vault session: devices, revocation and password changes")
struct DeviceRegistrySessionTests {
    static let newPassword = "an entirely different passphrase"

    @Test("a password changed on one device is the account's: the others refuse the old one and take the new")
    func passwordChangeReachesOtherDevices() async throws {
        let fleet = try await Fleet.make()
        let (a, b) = (fleet.devices[0], fleet.devices[1])
        try await b.session.enableQuickUnlock(password: TestVault.password)
        let item = try await a.session.save(login(fleet.personal, title: "Saved before"))
        try await fleet.settle()
        await b.session.lock()

        try await a.session.changePassword(current: TestVault.password, new: Self.newPassword)
        try await a.session.save(login(fleet.personal, title: "Saved after"))
        try await a.session.sync()
        // B is told while locked: it downloads, and waits.
        let told = try await b.session.syncAll()
        #expect(told.awaitingNewPassword && told.account.candidateHeadersFetched == 1)
        #expect(try await b.session.isAwaitingNewPassword())

        await #expect(throws: VaultError.passwordChangedOnAnotherDevice) {
            try await b.session.unlock(password: TestVault.password)
        }
        await #expect(throws: VaultError.quickUnlockRefused(.credentialsChanged)) {
            try await b.session.quickUnlock()
        }
        let accountID = try #require(try await a.session.status().accountID)
        #expect(await !b.keychain.contains(.quickUnlockKey(accountID: accountID)))
        await #expect(throws: CryptoError.authenticationFailed) {
            try await b.session.unlock(password: "neither the old nor the new")
        }
        #expect(try await b.session.state() == .locked)

        try await b.session.unlock(password: Self.newPassword)
        #expect(try await !b.session.isAwaitingNewPassword())
        try await fleet.settle()
        #expect(try await b.session.items().items.map(\.title) == ["Saved after", "Saved before"])
        #expect(try await b.session.item(id: item.id).title == "Saved before")
        // The change is this device's own now: the old password is simply wrong, across a relaunch too.
        await b.session.lock()
        await #expect(throws: CryptoError.authenticationFailed) {
            try await b.relaunched().session.unlock(password: TestVault.password)
        }
        try await b.session.unlock(password: Self.newPassword)
        try await fleet.expectConverged()
    }

    @Test("a device that is unlocked when the password changes elsewhere stops merging and publishing until told it")
    func unlockedDeviceFreezes() async throws {
        let fleet = try await Fleet.make()
        let (a, b) = (fleet.devices[0], fleet.devices[1])
        try await a.session.changePassword(current: TestVault.password, new: Self.newPassword)
        let fromA = try await a.session.save(login(fleet.personal, title: "From A"))
        try await a.session.sync()

        let fromB = try await b.session.save(login(fleet.personal, title: "From B"))
        let frozen = try await b.session.sync()
        #expect(frozen.awaitingNewPassword && frozen.deferredUntilUnlock)
        #expect(frozen.applied == 0 && frozen.segmentsWritten == 0)
        #expect(try await b.session.items().items.map(\.id) == [fromB.id])
        // Nothing is lost by waiting: the person enters the new password, and both directions flow.
        await b.session.lock()
        try await b.session.unlock(password: Self.newPassword)
        try await fleet.settle()
        #expect(Set(try await a.session.items().items.map(\.id)) == [fromA.id, fromB.id])
        try await fleet.expectConverged()
    }

    @Test("after a password change, a device enrols with the new password and not with the old")
    func enrolAfterPasswordChange() async throws {
        var fleet = try await Fleet.make(1)
        let a = fleet.devices[0]
        try await a.session.changePassword(current: TestVault.password, new: Self.newPassword)
        try await a.session.sync()
        let kit = try await a.session.emergencyKit()
        let stale = EnrolmentTests.newDevice(over: fleet.transport, seed: 71)
        await #expect(throws: CryptoError.authenticationFailed) {
            try await stale.session.enrol(password: TestVault.password, secretKey: kit.setupCode)
        }
        let b = try await fleet.enrol(1, password: Self.newPassword)
        #expect(try await b.session.deviceStanding() == .active)
        try await fleet.settle()
        #expect(try await a.session.devices().count == 2)
    }

    @Test("a revoked device is refused by the others, stops publishing, and is listed as revoked")
    func revoke() async throws {
        let fleet = try await Fleet.make(3)
        let (a, b, lost) = (fleet.devices[0], fleet.devices[1], fleet.devices[2])
        let lostID = Fleet.deviceID(2)
        let before = try await lost.session.save(login(fleet.personal, title: "Before it was lost"))
        try await fleet.settle()

        await #expect(throws: CryptoError.authenticationFailed) {
            try await a.session.revokeDevice(lostID, password: .keepPassword(current: "not the password!"))
        }
        let self0 = try #require(await a.session.account?.deviceID)
        await #expect(throws: VaultError.cannotRevokeThisDevice) {
            try await a.session.revokeDevice(self0, password: .keepPassword(current: TestVault.password))
        }
        let stranger = UUID()
        await #expect(throws: VaultError.unknownDevice(stranger)) {
            try await a.session.revokeDevice(stranger, password: .keepPassword(current: TestVault.password))
        }

        try await a.session.revokeDevice(lostID, password: .keepPassword(current: TestVault.password))
        // The lost device keeps writing, for as long as it does not know.
        try await lost.session.save(login(fleet.personal, title: "Written after the revocation"))
        _ = try? await lost.session.sync()
        try await fleet.settle([a, b])

        for session in [a.session, b.session] {
            let titles = try await session.items().items.map(\.title)
            #expect(titles == ["Before it was lost"], "what it wrote before is kept; what it wrote after is not read")
            let devices = try await session.devices()
            #expect(devices.first { $0.id == lostID }?.isRevoked == true)
            #expect(devices.first { $0.id == lostID }?.revokedBy == self0)
        }
        #expect(try await a.session.item(id: before.id).title == "Before it was lost")
        let report = try await b.session.sync()
        #expect(report.retiredObjects >= 1 && report.rejected.isEmpty)

        // The lost device, once it syncs, learns what it is.
        let own = try await lost.session.syncAll()
        #expect(own.deviceStanding == .revoked && own.combined.deviceRevoked && own.combined.segmentsWritten == 0)
        #expect(try await lost.session.deviceStanding() == .revoked)
        await #expect(throws: VaultError.deviceRevoked) {
            try await lost.session.changePassword(current: TestVault.password, new: Self.newPassword)
        }
    }

    @Test("revoking with a password change is one step, and the revoked device cannot follow it")
    func revokeAndChangePassword() async throws {
        let fleet = try await Fleet.make(3)
        let (a, b, lost) = (fleet.devices[0], fleet.devices[1], fleet.devices[2])
        let lostID = Fleet.deviceID(2)
        try await fleet.settle()
        try await a.session.revokeDevice(
            lostID, password: .change(current: TestVault.password, new: Self.newPassword))
        try await a.session.sync()

        // B needs the new password, like after any password change; then it holds the revocation as final.
        try await b.session.sync()
        await b.session.lock()
        try await b.session.unlock(password: Self.newPassword)
        try await fleet.settle([a, b])
        #expect(try await b.session.devices().first { $0.id == lostID }?.isRevoked == true)

        // The revoked device knows the old password and holds the keyset. It cannot register itself again, and a
        // device it sets up with what it knows cannot enrol.
        _ = try? await lost.session.sync()
        #expect(try await lost.session.deviceStanding() == .revoked)
        let kit = try await a.session.emergencyKit()
        let sockPuppet = EnrolmentTests.newDevice(over: fleet.transport, seed: 81)
        await #expect(throws: CryptoError.authenticationFailed) {
            try await sockPuppet.session.enrol(password: TestVault.password, secretKey: kit.setupCode)
        }
        try await fleet.settle([a, b])
        #expect(try await a.session.devices().filter { !$0.isRevoked }.count == 2)
    }

    /// The password was changed by someone else — a device that is no longer the person's. On a device they still
    /// hold, the person unlocks with the password it has, revokes that device and sets a password of their own; the
    /// other devices follow whichever password the person then gives them.
    @Test("a password change the person did not make is undone from a device they still hold")
    func hostilePasswordChange() async throws {
        let fleet = try await Fleet.make(3)
        let (thief, b, c) = (fleet.devices[0], fleet.devices[1], fleet.devices[2])
        let thiefID = try #require(await thief.session.account?.deviceID)
        try await fleet.settle()
        await b.session.lock()
        await c.session.lock()
        try await thief.session.changePassword(current: TestVault.password, new: "the thief's own password")
        try await thief.session.sync()
        try await b.session.sync()

        await #expect(throws: VaultError.passwordChangedOnAnotherDevice) {
            try await b.session.unlock(password: TestVault.password)
        }
        try await b.session.unlock(password: TestVault.password, ignoringPasswordChange: true)
        try await b.session.revokeDevice(
            thiefID, password: .change(current: TestVault.password, new: Self.newPassword))
        try await b.session.save(login(fleet.personal, title: "Written after taking the account back"))
        try await b.session.sync()
        #expect(try await !b.session.isAwaitingNewPassword())
        #expect(try await b.session.devices().first { $0.id == thiefID }?.isRevoked == true)

        // C sees two password changes it has not been given. The person's opens; the thief's does not.
        try await c.session.sync()
        #expect(try await c.session.isAwaitingNewPassword())
        await #expect(throws: CryptoError.authenticationFailed) {
            try await c.session.unlock(password: "a guess at the thief's password")
        }
        try await c.session.unlock(password: Self.newPassword)
        try await fleet.settle([b, c])
        #expect(try await c.session.devices().first { $0.id == thiefID }?.isRevoked == true)
        #expect(try await c.session.items().items.map(\.title) == ["Written after taking the account back"])
        // What the thief's device writes now is read by neither.
        try await thief.session.save(login(fleet.personal, title: "Planted"))
        _ = try? await thief.session.sync()
        try await fleet.settle([b, c])
        #expect(try await c.session.items().items.count == 1)
        try await fleet.expectConverged([b, c])
    }

    /// The local file is not trusted (A8), and the Keychain anchor remembers what the registry had reached.
    @Test("a registry rolled back in the local file is refused, and restored by the next sync")
    func registryRollback() async throws {
        let fleet = try await Fleet.make(3)
        let (a, b) = (fleet.devices[0], fleet.devices[1])
        let lostID = Fleet.deviceID(2)
        try await fleet.settle()
        try await a.session.revokeDevice(lostID, password: .keepPassword(current: TestVault.password))
        try await fleet.settle([a, b])
        #expect(try await b.session.devices().first { $0.id == lostID }?.isRevoked == true)

        // Someone with the file removes the revocation from B's store.
        await b.session.lock()
        let store = try #require(b.store as? InMemoryRecordStore)
        let revocation = try #require(
            await store.allRecords.first {
                guard $0.kind == .deviceRegistry, let entry = try? RegistryEntry.parse($0.envelope) else {
                    return false
                }
                return entry.body == .revoke(lostID)
            })
        try await store.commit(StoreChange(deletions: [revocation.key]))
        let relaunched = b.relaunched()
        await #expect(throws: VaultError.deviceRegistryUnavailable) { try await relaunched.session.deviceStanding() }
        try await relaunched.session.unlock(password: TestVault.password)
        // Not believed: nothing verifies until the registry is whole again, which a sync makes it.
        let report = try await relaunched.session.syncAll()
        #expect(report.account.registryEntriesFetched == 1 && !report.registryUnavailable)
        #expect(try await relaunched.session.devices().first { $0.id == lostID }?.isRevoked == true)
    }
}
