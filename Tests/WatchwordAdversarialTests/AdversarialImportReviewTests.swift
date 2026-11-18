import Foundation
import Testing
import WatchwordAutoFill
import WatchwordInterchange
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordKit

// Findings of the review of the Z62 fix (docs/06-adversarial-review.md, rows Z73 to Z75). The adversary is A7 of
// docs/02-architecture.md §2: whoever hands the person the import file.
extension AdversarialSessionInterchangeTests {
    /// A 1PUX export holding one login per `(title, state, urls)`.
    static func onePUX(_ items: [(title: String, state: String, urls: [String])]) -> [UInt8] {
        let entries = items.enumerated().map { index, item in
            let urls = item.urls.map { #"{"label": "", "url": "\#($0)"}"# }.joined(separator: ", ")
            return #"""
                {"uuid": "item\#(index)aaaaaaaaaaaaaaaaaaaa", "createdAt": 1614298956, "updatedAt": 1635346445,
                 "state": "\#(item.state)", "categoryUuid": "001",
                 "details": {"loginFields": [
                   {"value": "wendy", "id": "", "name": "username", "fieldType": "T", "designation": "username"},
                   {"value": "file-password", "id": "", "name": "password", "fieldType": "P", "designation": "password"}
                 ]},
                 "overview": {"title": "\#(item.title)", "urls": [\#(urls)]}}
                """#
        }
        let document = Array(
            #"""
            {"accounts": [{"attrs": {"accountName": "Wendy", "name": "Wendy", "uuid": "D4RI47B7BJDT25C2LWA7LEJLHZ"},
              "vaults": [{"attrs": {"uuid": "rr3lr6c2opoggvrete23q72ahi", "name": "Personal", "type": "P"},
                "items": [\#(entries.joined(separator: ", "))]}]}]}
            """#.utf8)
        let attributes = #"{"version":3,"description":"1Password Unencrypted Export","createdAt":1635346500}"#
        return ZIPFixture([
            ZIPFixture.Member(name: "export.attributes", contents: Array(attributes.utf8)),
            ZIPFixture.Member(name: "export.data", contents: document, data: DeflateFixture.stored(document)),
        ]).bytes()
    }

    /// Threat (Z73): with "include trash" on, A7's file holds trashed entries scoped to the bank's login host. The
    /// review skipped trashed entries, so none raised a concern; each was then created live and moved to the trash in
    /// a second write. A `lock()` between the two (an auto-lock during a long import) or any `VaultError` from the
    /// trash left the item live and unreviewed, hiding the saved bank login on its sign-in page; and a later Restore
    /// from the trash did the same with no warning. Now a trashed entry is created in the trash in its one write, and
    /// it is reviewed like any other, so the decision is the person's before it can ever rank.
    @Test("a trashed entry is reviewed, and saved in the trash in one write")
    func trashedEntryIsReviewedAndWrittenOnce() async throws {
        let (vault, personal) = try await Self.vault()
        let bank = try await vault.session.save(Self.bank(personal))
        let file = Self.onePUX([("Bank", "trashed", ["https://login.bank.example/"])])
        let preview = try await vault.session.previewImport(
            file, format: .onePUX, into: personal, options: ImportOptions(includesTrashed: true))
        let entry = try #require(preview.entries.first)
        #expect(entry.state == .trashed)
        let concern = preview.concerns.first
        #expect(concern != nil, "a trashed entry was not reviewed")
        #expect(concern?.importedID == entry.id && concern?.isTrashed == true)
        #expect(concern?.hidden.map(\.itemID) == [bank.id])
        await #expect(throws: InterchangeSessionError.decisionRequired(importedID: entry.id)) {
            try await vault.session.commitImport(preview.id, decisions: [:])
        }

        let outcome = try await vault.session.commitImport(preview.id, decisions: [entry.id: .keepBoth])
        let created = try #require(outcome.created.first)
        let item = try await vault.session.item(id: created)
        #expect(item.isTrashedByPerson)
        // One revision after the person's own item: created in the trash, never live in between.
        #expect(item.version == bank.version + 1, "created, then trashed in a second write")
    }

    /// Threat (Z74): A7's entry is scoped to `amazon.com` and `amaz0n.com`, imported into a vault that holds no Amazon
    /// item. Nothing saved resembles either host, and since Z62 an entry's hosts were compared only with what is
    /// saved, so there was no concern. The item then filled on `amaz0n.com`, and so did every later password the
    /// person saved to it from `amazon.com`. Now each host is also compared with the entry's other hosts, for
    /// resemblance only (they vouch for nothing), bounded by the 32 URLs an entry may have.
    @Test("a look-alike beside its original in one entry needs a decision")
    func lookAlikeWithinOneEntry() async throws {
        let (vault, personal) = try await Self.vault()
        let file = Self.onePUX([
            ("Amazon", "active", ["https://amazon.com/", "https://amaz0n.com/"]),
            ("Shop", "active", ["https://shop.example/", "https://www.shop.example/"]),
        ])
        let preview = try await vault.session.previewImport(file, format: .onePUX, into: personal)
        #expect(preview.concerns.count == 1, "\(preview.concerns)")
        let concern = try #require(preview.concerns.first)
        #expect(concern.importedID == preview.entries.first?.id)
        #expect(Set(concern.lookAlikeHosts.map(\.host)) == ["amazon.com", "amaz0n.com"])
        #expect(concern.lookAlikeHosts.first { $0.host == "amaz0n.com" }?.resembles == ["amazon.com"])
        #expect(InterchangeLimits.standard.maximumURLsPerItem <= 32, "the pairwise comparison is bounded")
    }
}
