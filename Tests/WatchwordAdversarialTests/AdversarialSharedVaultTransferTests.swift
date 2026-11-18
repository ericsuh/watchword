import Foundation
import Testing
import WatchwordAutoFill
import WatchwordKit
import WatchwordMatching
import WatchwordModel
import WatchwordSharing
import WatchwordTestSupport

// Review finding Z72 (docs/06-adversarial-review.md): copy and move out of a shared vault, over real sessions.
extension AdversarialSharedVaultTests {
    /// Threat: A4, a member of a shared vault who may write. They plant "Bank" in the shared vault, scoped to the exact
    /// login host `login.bank.example` and to a look-alike `bаnk.example` (Cyrillic а), with the victim's user name.
    /// There it shadows nothing of the victim's and vouches for no look-alike (Z60). The victim copies or moves it into
    /// Personal: `transfer` checked only the scope policy, so in an own vault it outranked the victim's own Bank login
    /// on the login page (the next password typed there was offered only to it), and its look-alike scope, now the
    /// person's own word, filled the bank's password on `bаnk.example`. Now a copy or move out of a shared vault is
    /// judged like an import entry and refused until the call names what the person was shown.
    @Test("a copy or move out of a shared vault does not bring a member's scopes in unasked")
    func transferOutOfASharedVaultIsJudged() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], name: "Household", seed: 1270)
        let (victim, member) = (home.owner, home.members[0])
        let personal = try await victim.session.defaultVaultID()
        let own = try await victim.session.save(
            Item(
                vaultID: personal, title: "Bank", scopes: [ServiceScope(host: "bank.example")],
                fields: [
                    Field(kind: .username, label: "Username", value: "alice@x"),
                    Field(kind: .password, label: "Password", value: "real-password"),
                ]))
        let lookAlike = "b\u{0430}nk.example"
        let planted = try await member.session.save(
            Item(
                vaultID: home.vaultID, title: "Bank",
                scopes: [
                    ServiceScope(host: "login.bank.example", includeSubdomains: false), ServiceScope(host: lookAlike),
                ],
                fields: [
                    Field(kind: .username, label: "Username", value: "alice@x"),
                    Field(kind: .password, label: "Password", value: "member-password"),
                ]),
            confirmingHosts: [lookAlike])
        let plain = try await member.session.save(
            Item(
                vaultID: home.vaultID, title: "Streaming", scopes: [ServiceScope(host: "streaming.example")],
                fields: [Field(kind: .password, label: "Password", value: "family")]))
        try await Self.syncAll([member, victim])

        for move in [false, true] {
            let concern: TransferConcern
            do {
                if move {
                    _ = try await victim.session.move(itemID: planted.id, to: personal)
                } else {
                    _ = try await victim.session.copy(itemID: planted.id, to: personal)
                }
                Issue.record("the \(move ? "move" : "copy") went through unasked")
                return
            } catch VaultError.transferNeedsConfirmation(let found) {
                concern = found
            }
            #expect(concern.hidden.map(\.itemID) == [own.id])
            #expect(concern.hidden.first?.host == "login.bank.example")
            #expect(concern.lookAlikeHosts.map(\.host) == [lookAlike])
            #expect(concern.lookAlikeHosts.first?.resembles == ["bank.example"])
            // Nothing was written: the original is where it was, and Personal holds only the person's own item.
            #expect(try await victim.session.items(in: personal).items.map(\.id) == [own.id])
            #expect(try await victim.session.item(id: planted.id).isTrashed == false)
            // A confirmation of something else is not this one.
            var other = concern
            other.lookAlikeHosts = []
            await #expect(throws: VaultError.transferNeedsConfirmation(concern)) {
                try await victim.session.copy(itemID: planted.id, to: personal, confirming: other)
            }
        }
        // With the confirmation the person was shown, it is theirs to do.
        let concern = try await victim.session.transferConcern(itemID: planted.id, to: personal)
        let copied = try await victim.session.copy(itemID: planted.id, to: personal, confirming: concern)
        #expect(copied.vaultID == personal)

        // An item that affects nothing of the person's is copied as before.
        #expect(try await victim.session.transferConcern(itemID: plain.id, to: personal).isEmpty)
        _ = try await victim.session.copy(itemID: plain.id, to: personal)
        // And within the person's own vaults nothing is asked: that is their own word already.
        let work = try await victim.session.createVault(name: "Work").id
        _ = try await victim.session.copy(itemID: own.id, to: work)
    }
}
