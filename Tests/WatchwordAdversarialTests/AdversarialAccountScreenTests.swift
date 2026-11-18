import Foundation
import Testing
import WatchwordCrypto
import WatchwordKit
import WatchwordModel
import WatchwordPresentation
import WatchwordSharing
import WatchwordSync
import WatchwordTestSupport

/// The account screens' models (`WatchwordPresentation`) against the adversaries of docs/02-architecture.md §2 who
/// reach a person through what the screens show: a message with a code in it, an import file, a vault member's
/// choice of name, a device's choice of its own name. The session decides every refusal; these check that the screens
/// neither claim more than the session established nor hide what it reports (review of the account screens).
@Suite("Adversarial: account screens", .tags(.adversarial))
@MainActor
struct AdversarialAccountScreenTests {
    static func context(_ session: VaultSession) -> ScreenContext {
        ScreenContext(session: session)
    }

    /// Threat: anyone who can send the person a message (outside §2's list: no access to anything of Watchword's)
    /// sends a fingerprint code for an account of their own, hoping a paste is taken as a comparison. It names the
    /// account and nothing more: no pin is made without the full code typed (the person's own "they match" is no
    /// longer offered, ADR 0010), and the pin says how it was made (S16), never "scanned".
    @Test("a pasted fingerprint code pins nothing, and the pin made after a comparison says how it was made")
    func pastedCode() async throws {
        let household = SharedVaultHousehold()
        let owner = try await household.account(seed: 701)
        let stranger = try await household.account(seed: 702)
        let vaultID = try await owner.session.createVault(name: "Household").id
        try await owner.session.shareVault(vaultID)
        let invitation = InvitationModel(vaultID: vaultID, context: Self.context(owner.session))
        await invitation.useFullCode()
        invitation.accountText = OwnFingerprint(stranger.bundle).code
        await invitation.lookUp()
        guard case .compareFingerprint = invitation.step else {
            Issue.record("a pasted code skipped the comparison: \(invitation.step)")
            return
        }
        await invitation.confirmFingerprint()
        let pins = VerifiedContacts(store: owner.contacts, account: owner.bundle)
        #expect(try await pins.pinned(stranger.accountID) == nil, "pinned on a pasted code alone")
        invitation.confirmation.typedSafetyNumber = stranger.safetyNumber
        await invitation.confirmFingerprint()
        #expect(try await pins.pinned(stranger.accountID)?.method == .safetyNumber)
        #expect(invitation.verificationText == "You typed their full vault sharing code, and it matched.")
    }

    /// Threat: a hostile import file (A7) offers an existing item a look-alike of its own site, `аmazon.com` with a
    /// Cyrillic `а`, which renders as the real one. The merge shows the ASCII form, warns, and does not accept it on
    /// one switch.
    @Test("a look-alike host from an import file is shown in ASCII, warned about and held for a second confirmation")
    func lookAlikeHost() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)
        let amazon = try await vault.session.save(
            Item(
                vaultID: personal, title: "Amazon", scopes: [ServiceScope(host: "amazon.com")],
                fields: [Field(kind: .username, label: "Username", value: "pat")]))
        let file =
            #"{"version":{"major":1,"minor":0},"exporterRpId":"x.example","exporterDisplayName":"X","timestamp":1,"#
            + #""accounts":[{"id":"YQ","username":"","email":"","collections":[],"items":[{"id":"aQ","title":"Amazon","#
            + #""scope":{"urls":["https://amazon.com/","https://аmazon.com/"],"androidApps":[]},"credentials":["#
            + #"{"type":"basic-auth","username":{"fieldType":"string","value":"pat"}}]}]}]}"#
        let model = ImportModel(context: Self.context(vault.session))
        await model.load()
        model.format = .credentialExchange
        await model.read(Array(file.utf8))
        let duplicate = try #require(model.duplicates.first)
        await model.choose(.merge(into: amazon.id), for: duplicate.id)
        let host = try #require(model.merges[duplicate.id]?.hosts.first)
        #expect(host.ascii == "xn--mazon-3ve.com" && host.warning?.contains("amazon.com") == true)
        model.setHost(host.host, accepted: true, for: duplicate.id)
        #expect(!model.isAccepted(host: host.host, for: duplicate.id), "accepted on one switch")
        model.confirmAwaitingHost()
        await model.commit()
        let merged = try await vault.session.item(id: amazon.id)
        #expect(merged.scopes.map(\.host).contains(host.host), "the second confirmation is the person's to give")
    }

    /// Threat: an administrator of a shared vault (A4 with the role; a member who merely may write is refused, here
    /// and by every device's judge, §8.7) renames it "Personal", so a new item meant for the person's own vault
    /// lands in theirs. Every list labels vaults by ownership and role, not by name alone.
    @Test("a shared vault an administrator renamed Personal is labelled apart from the real Personal vault")
    func sharedVaultNamedPersonal() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.administrator, .readWrite], seed: 711)
        let member = home.members[0]
        await #expect(throws: SharedVaultError.renameRefused) {
            _ = try await home.members[1].session.renameVault(id: home.vaultID, to: "Personal")
        }
        _ = try await member.session.renameVault(id: home.vaultID, to: "Personal")
        try await member.session.sync()
        try await home.owner.session.sync()
        let rows = try await VaultRow.load(from: home.owner.session)
        let named = rows.filter { $0.name == "Personal" }
        #expect(named.count == 2)
        #expect(Set(named.map(\.label)).count == 2)
        #expect(named.first { !$0.isPersonal }?.badge == "Shared by you")
        #expect(named.first { $0.isPersonal }?.badge == "Your own vault")
    }

    /// Threat: whoever enrols a device (A4 with the password and Secret Key, or someone using a device of the
    /// person's) names it "Pat's Mac (this device)" with a right-to-left override, so that the Devices screen offers
    /// to remove the person's own Mac instead of it. The name is cleaned, and "this device" comes from the ID only.
    @Test("a device named to pass for this one is cleaned, and only this device is marked as this device")
    func deviceNameImpersonation() async throws {
        let transport = InMemorySyncTransport()
        let first = TestVault.syncing(over: transport, seed: 721, name: "Pat's Mac")
        try await first.createAccount()
        let impostorID = UUID(uuid: (0xD0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 0xC7))
        let impostor = try await first.enrolledDevice(
            deviceID: impostorID, over: transport, name: "Pat's Mac (This Device)\u{202E}")
        try await impostor.session.unlock(password: TestVault.password)
        try await impostor.session.sync()
        try await first.session.sync()
        let model = DevicesModel(context: Self.context(first.session))
        await model.load()
        let row = try #require(model.rows.first { $0.id == impostorID })
        #expect(row.name == "Pat's Mac" && !row.isThisDevice && row.mayRevoke)
        #expect(model.rows.filter(\.isThisDevice).map(\.id) != [impostorID])
        #expect(model.names[impostorID] == "“Pat's Mac”")
    }
}
