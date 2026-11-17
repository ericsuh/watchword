import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit
@testable import WatchwordSync

/// The account's own objects — header, device registry, vault directory — after the sync store was reset
/// (docs/02-architecture.md §7.7, §7.10). Until this was built any device put back a header and a registry the store
/// had lost, at its next sync, so a store the person had emptied on purpose filled again by itself. **A1** can empty
/// the store at will; **a revoked device** still holds the account key and would like to be the one that answers.
extension AdversarialAccountTests {
    /// Threat: the person deleted the account's data from the sync store on another device (or A1 emptied it), and
    /// a device that syncs afterwards puts the account back unasked: its header, its device list, its wrapped vault
    /// keys. None of them is created by any sync, so a new device finds nothing to enrol from; after the person's
    /// yes on one device, a new device enrols from the store alone, with the password and the Secret Key, reads
    /// everything, and a wrong password is refused as ever.
    @Test("an emptied store holds no account until the person says so; then a new device enrols and reads everything")
    func enrolmentAfterAReset() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        try await b.session.save(Item(vaultID: f.personal, title: "Post", scopes: [], fields: []))
        try await b.session.sync()
        try await f.a.session.sync()
        await f.transport.removeEverything()

        for device in [f.a, b] {
            for _ in 0..<2 { #expect(try await device.session.syncAll().storeNeedsReupload) }
        }
        #expect(await f.transport.allObjects.isEmpty)
        await #expect(throws: VaultError.accountNotOnTransport) {
            try await f.fresh().session.enrol(password: TestVault.password, secretKey: f.kit.setupCode)
        }
        #expect(await f.transport.allObjects.isEmpty)

        let report = try await f.a.session.reuploadAfterStoreReset(confirming: try await f.a.session.reuploadPlan())
        #expect(report.account.headerPublished && report.account.registryEntriesPublished > 0)
        #expect(report.account.vaultKeysPublished > 0 && !report.storeNeedsReupload)
        await #expect(throws: CryptoError.authenticationFailed) {
            try await f.fresh(seed: 31).session.enrol(password: "not the password", secretKey: f.kit.setupCode)
        }
        let c = f.fresh(seed: 37)
        try await c.session.enrol(password: TestVault.password, secretKey: f.kit.setupCode)
        try await c.session.sync()
        #expect(Set(try await c.session.items().items.map(\.title)) == ["Bank", "Post"])
        // B was in step with A: it is asked nothing, and puts back only its own vouching for what it holds.
        let returning = try await b.session.syncAll()
        #expect(!returning.storeNeedsReupload && returning.combined.snapshotsWritten == 0)
    }

    /// Threat: a device that was revoked (lost, sold) still holds the account key and its own device key, and tries
    /// to be the device that fills the reset store, so that the account on the store is the account as it knew it,
    /// without its own revocation. Its session refuses, and its syncs publish nothing. When a trusted device has
    /// answered, the registry on the store holds the revocation: a new device sees the revoked one as revoked, and
    /// everything that device held reaches it from the trusted device alone.
    @Test("a revoked device cannot answer a reset; the registry uploaded again still revokes it")
    func revokedDeviceCannotAnswer() async throws {
        let f = try await Self.fixture()
        let b = try await f.enrolled(Self.deviceB)
        try await b.session.save(Item(vaultID: f.personal, title: "Written on the lost device", scopes: [], fields: []))
        try await b.session.sync()
        try await f.a.session.sync()
        let plan = try await b.session.reuploadPlan()
        try await f.a.session.revokeDevice(Self.deviceB, password: .keepPassword(current: TestVault.password))
        try await f.a.session.sync()
        try await b.session.sync()
        await f.transport.removeEverything()

        await #expect(throws: VaultError.deviceRevoked) {
            try await b.session.reuploadAfterStoreReset(confirming: plan)
        }
        _ = try await b.session.syncAll()
        #expect(await f.transport.allObjects.isEmpty)

        _ = try await f.a.session.reuploadAfterStoreReset(confirming: try await f.a.session.reuploadPlan())
        let c = f.fresh(seed: 41)
        try await c.session.enrol(password: TestVault.password, secretKey: f.kit.setupCode)
        try await c.session.sync()
        let devices = try await c.session.devices()
        #expect(devices.first { $0.id == Self.deviceB }?.isRevoked == true)
        #expect(
            Set(try await c.session.items().items.map(\.title)) == ["Bank", "Written on the lost device"])
        // What the revoked device publishes now is read by nobody.
        _ = try await b.session.syncAll()
        let after = try await c.session.syncAll()
        #expect(after.combined.applied == 0)
    }

    /// Threat: the password was changed (a device was lost) and then the store is reset. If the upload put back the
    /// account as it was before the change, the old password, which the finder of the lost device may know, would
    /// enrol a new device again. The header and the registry uploaded again are the current ones: the old password
    /// opens nothing, and the new one enrols.
    @Test("after a reset the old password still enrols nothing, and the new one does")
    func passwordChangeSurvivesAReset() async throws {
        let f = try await Self.fixture()
        try await f.a.session.changePassword(current: TestVault.password, new: Self.newPassword)
        try await f.a.session.sync()
        await f.transport.removeEverything()
        _ = try await f.a.session.reuploadAfterStoreReset(confirming: try await f.a.session.reuploadPlan())

        await #expect(throws: (any Error).self) {
            try await f.fresh(seed: 43).session.enrol(password: TestVault.password, secretKey: f.kit.setupCode)
        }
        let c = f.fresh(seed: 47)
        try await c.session.enrol(password: Self.newPassword, secretKey: f.kit.setupCode)
        try await c.session.sync()
        #expect(try await c.session.items().items.map(\.title) == ["Bank"])
    }
}
