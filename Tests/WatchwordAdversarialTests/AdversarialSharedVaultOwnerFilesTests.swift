import Foundation
import Testing
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel
import WatchwordSharing
import WatchwordStore
import WatchwordTestSupport

@testable import WatchwordKit

// Review finding Z77 (docs/06-adversarial-review.md): on the owner's devices "shared" rested on rows A8 can delete.
extension AdversarialSharedVaultTests {
    /// Threat: A8 with A4. The owner's key for the vault did not arrive by grant, so on the owner's devices the vault
    /// counts as shared only by the account's marker row and the sharing state, both in the App Group store. Whoever
    /// edits that file while the app is locked (A8) deletes both; the AutoFill extension never syncs them back. The
    /// vault then read as the owner's alone: a login the member (A4) had planted there shadowed the owner's own login
    /// and took a conditional passkey upgrade with no UI. Now a vault holding an item whose clock names a device
    /// outside this account (authenticated, inside the ciphertext; a deleted row cannot remove it) counts as shared.
    @Test("a vault whose items another account wrote is shared on the owner's device after its marker is deleted")
    func ownerDeviceStillKnowsTheVaultIsShared() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], name: "Household", seed: 1290)
        let (owner, member) = (home.owner, home.members[0])
        let personal = try await owner.session.defaultVaultID()
        _ = try await owner.session.save(
            Item(
                vaultID: personal, title: "www.shop.example",
                scopes: [ServiceScope(host: "www.shop.example", includeSubdomains: false)],
                fields: [
                    Field(kind: .username, label: "Username", value: "alice@x"),
                    Field(kind: .password, label: "Password", value: "owners-password"),
                ]))
        let planted = try await member.session.save(
            Item(
                vaultID: home.vaultID, title: "Shop", scopes: [ServiceScope(host: "shop.example")],
                fields: [
                    Field(kind: .username, label: "Username", value: "alice@x"),
                    Field(kind: .password, label: "Password", value: "anything"),
                ]))
        try await Self.syncAll([member, owner])
        #expect(try await owner.session.item(id: planted.id).vaultID == home.vaultID)

        // A8: the marker rows and the sharing state are gone; the extension starts over what is left.
        let accountID = owner.accountID
        let markers = try await owner.vault.store.records(in: accountID, kind: .vaultDirectory).filter {
            $0.envelope.first == VaultSession.sharedMarkerTag
        }
        #expect(!markers.isEmpty)
        try await owner.vault.store.commit(StoreChange(deletions: markers.map(\.key)))
        let extensionProcess = owner.vault.relaunched(seed: 1291)
        await extensionProcess.session.configureSharing(
            SharingSettings(
                state: InMemorySharingStateStore(), contacts: InMemoryVerifiedContactStore(),
                directory: household.directory))
        try await extensionProcess.session.unlock(password: TestVault.password)

        let snapshot = try await extensionProcess.session.credentialSnapshot()
        let described = snapshot.vaults.first { $0.id == home.vaultID }
        #expect(described == nil || described?.isShared == true, "the member's vault reads as the owner's alone")
        let model = CredentialProviderModel(
            vault: extensionProcess.session, clock: FakeClock(AutoFillFixtures.now), random: SeededGenerator(seed: 1292)
        )
        let request = PasskeyRegistrationRequest(
            relyingPartyID: "shop.example", user: PasskeyUser(handle: Data("handle".utf8), name: "alice@x"),
            clientDataHash: AutoFillFixtures.clientDataHash())
        #expect(await model.registerPasskeyWithoutInteraction(request) == .refused(.noItemToUpgrade))
        #expect(try await !extensionProcess.session.item(id: planted.id).fields.contains { $0.kind == .passkey })
    }
}
