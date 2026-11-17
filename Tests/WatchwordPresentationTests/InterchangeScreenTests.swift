import Foundation
import Testing
import WatchwordInterchange
import WatchwordKit
import WatchwordModel
import WatchwordPresentation
import WatchwordTestSupport

/// The file the UI tests import: Apple Passwords' header, one entry duplicating the Library item with a `www` host,
/// a password of its own and a URL, and one new item. Kept in step with `UITestSample.csv` in Apps/Shared.
let sampleCSV = """
    Title,URL,Username,Password,Notes,OTPAuth
    Library,https://www.citylibrary.org/login,pat,imported-Library-9!,From the old app,
    Garden club,https://gardenclub.org/,pat@example.com,imported-Garden-4!,,
    """

@Suite("Screen models: import, export and restore")
@MainActor
struct InterchangeScreenTests {
    func vaultWithLibrary() async throws -> (TestVault, Item) {
        let vault = TestVault()
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)
        let library = try await vault.session.save(
            login(personal, "Library", host: "citylibrary.org", username: "pat", password: "x7#Vq9!mLp2$Zr8@Wn4&"))
        return (vault, library)
    }

    @Test("a duplicate needs a choice; a merge names each host and sign-in field it would add, none accepted")
    func duplicateReview() async throws {
        let (vault, library) = try await vaultWithLibrary()
        let model = ImportModel(context: ContextProbe().context(vault.session))
        await model.load()
        #expect(model.vaultID == (await vault.session.personalVaultID))
        await model.read(Array(sampleCSV.utf8))
        #expect(model.stage == .review, "\(model.errorMessage ?? "")")
        #expect(model.formatName == "Apple Passwords CSV")
        #expect(model.entries.map(\.title) == ["Library", "Garden club"])
        #expect(model.entries.first?.apexScopesAdded == ["citylibrary.org"])
        let duplicate = try #require(model.duplicates.first)
        #expect(model.duplicates.count == 1 && duplicate.title == "Library")
        let option = try #require(duplicate.options.first)
        #expect(option.id == library.id && option.newHosts == ["www.citylibrary.org"])
        #expect(option.hasNewSignInFields)
        #expect(option.summary.contains("www.citylibrary.org"))
        #expect(!model.canCommit, "a duplicate without a choice")
        await model.commit()
        #expect(model.errorMessage?.contains("every duplicate") == true)

        await model.choose(.merge(into: library.id), for: duplicate.id)
        let review = try #require(model.merges[duplicate.id])
        #expect(review.hosts.map(\.host) == ["www.citylibrary.org"])
        #expect(review.hosts.first?.registrable == "citylibrary.org" && review.hosts.first?.warning == nil)
        let password = try #require(review.signInFields.first { $0.isSecret })
        #expect(password.value == "imported-Library-9!" && password.label == "Password")
        #expect(!review.urlFields.isEmpty)
        #expect(model.accepted[duplicate.id] == MergeChoices.none, "never pre-filled")
        #expect(!model.isAccepted(host: "www.citylibrary.org", for: duplicate.id))
        #expect(model.revealed.isEmpty, "secrets start hidden")

        model.setHost("www.citylibrary.org", accepted: true, for: duplicate.id)
        model.setHost("evil.example", accepted: true, for: duplicate.id)
        #expect(model.accepted[duplicate.id]?.hosts == ["www.citylibrary.org"], "only a host the merge offered")
        #expect(model.canCommit)
        await model.commit()
        #expect(model.stage == .done(ImportSummary(created: 1, merged: 1, skipped: 0, failed: 0)))
        let merged = try await vault.session.item(id: library.id)
        #expect(Set(merged.scopes.map(\.host)) == ["citylibrary.org", "www.citylibrary.org"])
        #expect(merged.field(.password)?.value == "x7#Vq9!mLp2$Zr8@Wn4&", "the password not accepted was not added")
        #expect(model.entries.isEmpty && model.merges.isEmpty, "nothing of the file is kept after the commit")
    }

    /// A hostile file (A7) offers, beside the real site, a look-alike with a Cyrillic `а` for an existing item: the
    /// merge shows it in ASCII with a warning, and accepting it takes a second confirmation.
    @Test("a look-alike host in a merge is shown in ASCII, warned about, and needs a second confirmation")
    func lookAlikeHost() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        let personal = try #require(await vault.session.personalVaultID)
        let amazon = try await vault.session.save(
            login(personal, "Amazon", host: "amazon.com", username: "pat", password: "x7#Vq9!mLp2$Zr8@Wn4&"))
        // A CXF document, which can name several websites for one entry.
        let file =
            #"{"version":{"major":1,"minor":0},"exporterRpId":"x.example","exporterDisplayName":"X","timestamp":1,"#
            + #""accounts":[{"id":"YQ","username":"","email":"","collections":[],"items":[{"id":"aQ","title":"Amazon","#
            + #""scope":{"urls":["https://amazon.com/","https://аmazon.com/"],"androidApps":[]},"credentials":["#
            + #"{"type":"basic-auth","username":{"fieldType":"string","value":"pat"}}]}]}]}"#
        let model = ImportModel(context: ContextProbe().context(vault.session))
        await model.load()
        model.format = .credentialExchange
        await model.read(Array(file.utf8))
        let duplicate = try #require(model.duplicates.first, "\(model.errorMessage ?? "") \(model.reportLines)")
        await model.choose(.merge(into: amazon.id), for: duplicate.id)
        let host = try #require(model.merges[duplicate.id]?.hosts.first)
        #expect(host.ascii == "xn--mazon-3ve.com")
        #expect(host.warning?.contains("amazon.com") == true, "\(host.warning ?? "no warning")")
        model.setHost(host.host, accepted: true, for: duplicate.id)
        #expect(!model.isAccepted(host: host.host, for: duplicate.id), "accepted on one switch")
        #expect(model.hostAwaitingConfirmation?.host == host)
        model.cancelAwaitingHost()
        #expect(model.hostAwaitingConfirmation == nil && !model.isAccepted(host: host.host, for: duplicate.id))
        model.setHost(host.host, accepted: true, for: duplicate.id)
        model.confirmAwaitingHost()
        #expect(model.isAccepted(host: host.host, for: duplicate.id))
    }

    /// The staged copy is the only file the app writes: in a folder of its own, removed once the file mover is done
    /// with it, and the bytes zeroised once saved (review of the account screens, finding 5).
    @Test("an export is staged in a folder of its own, removed after the save, and its bytes then dropped")
    func staging() async throws {
        let (vault, _) = try await vaultWithLibrary()
        let model = ExportModel(context: ContextProbe().context(vault.session))
        await model.load()
        model.kind = .applePasswordsCSV
        model.password = TestVault.password
        await model.export()
        let file = try #require(model.file)
        #expect(model.archiveBytes == nil, "a plaintext export's bytes leave only through stage")
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let staged = try model.stage(in: root, options: [])
        #expect(staged.lastPathComponent == file.filename)
        #expect(try String(contentsOf: staged, encoding: .utf8).contains("citylibrary.org"))
        model.finishSaving(saved: false)
        #expect(!FileManager.default.fileExists(atPath: staged.path), "a cancelled save left the staged copy")
        #expect(model.holdsContents, "a cancelled save keeps the file to save again")
        _ = try model.stage(in: root, options: [])
        model.finishSaving(saved: true)
        #expect(!model.holdsContents && model.file == nil)
        #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).isEmpty)
    }

    /// A lock while the merge review or the export report is on screen (A2, someone who picks up the unlocked device
    /// after it locks): the models drop the merge's values, what was revealed and the export's bytes from the
    /// session's lock signal, whether or not any view goes away (finding 6).
    @Test("a lock of the session clears the merge review and the export's bytes")
    func clearedOnLock() async throws {
        let (vault, library) = try await vaultWithLibrary()
        let locks = await LockSignal.watching(vault.session)
        defer { locks.stop() }
        let context = ScreenContext(session: vault.session, locks: locks)
        let importing = ImportModel(context: context)
        await importing.load()
        await importing.read(Array(sampleCSV.utf8))
        let duplicate = try #require(importing.duplicates.first)
        await importing.choose(.merge(into: library.id), for: duplicate.id)
        let secret = try #require(importing.merges[duplicate.id]?.signInFields.first { $0.isSecret })
        importing.revealed.insert(secret.id)
        let exporting = ExportModel(context: context)
        await exporting.load()
        exporting.kind = .applePasswordsCSV
        exporting.password = TestVault.password
        await exporting.export()
        #expect(exporting.holdsContents)

        await vault.session.lock()
        for _ in 0..<1000 where exporting.holdsContents || !importing.merges.isEmpty { await Task.yield() }
        #expect(importing.merges.isEmpty && importing.revealed.isEmpty && importing.duplicates.isEmpty)
        #expect(importing.stage == .choose)
        #expect(!exporting.holdsContents && exporting.file == nil)
    }

    @Test("cancelling drops the session's drafts, so a commit of that preview is refused")
    func cancel() async throws {
        let (vault, _) = try await vaultWithLibrary()
        let model = ImportModel(context: ContextProbe().context(vault.session))
        await model.load()
        await model.read(Array(sampleCSV.utf8))
        await model.cancel()
        #expect(model.stage == .choose && model.duplicates.isEmpty)
    }

    @Test("a plaintext export needs the password, shows the report, and writes values exactly as stored")
    func plaintextExport() async throws {
        let (vault, library) = try await vaultWithLibrary()
        let personal = library.vaultID
        _ = try await vault.session.save(
            login(personal, "=HYPERLINK(\"https://evil.example\")", host: "example.com", username: "+1", password: "@x")
        )
        let model = ExportModel(context: ContextProbe().context(vault.session))
        await model.load()
        model.kind = .applePasswordsCSV
        #expect(model.problem == "Enter your account password.")
        model.password = "not the password"
        await model.export()
        #expect(model.errorMessage == "Incorrect password." && model.file == nil)
        #expect(model.password.isEmpty, "a typed password is dropped whatever the outcome")

        model.password = TestVault.password
        await model.export()
        let file = try #require(model.file)
        #expect(file.itemCount == 2 && file.kind.isPlaintext)
        #expect(file.filename.hasSuffix(".csv"))
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let text = try String(contentsOf: try model.stage(in: root, options: []), encoding: .utf8)
        #expect(text.contains("\"=HYPERLINK(\"\"https://evil.example\"\")\""), "kept exactly, quoted per RFC 4180")
        #expect(text.contains(",+1,") && text.contains("@x"))
        #expect(ExportModel.plaintextWarning.contains("not encrypted"))
        model.discardFile()
        #expect(model.file == nil)
    }

    @Test("an archive is exported under a passphrase and restored with its date shown")
    func archiveRoundTrip() async throws {
        let (vault, _) = try await vaultWithLibrary()
        let export = ExportModel(context: ContextProbe().context(vault.session))
        await export.load()
        export.kind = .archive
        export.password = TestVault.password
        export.passphrase = "garden shed padlock"
        export.passphraseConfirmation = "garden shed padlock, mistyped"
        #expect(export.problem == "The passphrases do not match.")
        export.passphraseConfirmation = "garden shed padlock"
        await export.export()
        let file = try #require(export.file, "\(export.errorMessage ?? "")")
        #expect(!file.kind.isPlaintext && file.itemCount == 1 && file.filename.hasSuffix(".wwarchive"))
        let archive = try #require(export.archiveBytes)

        let restore = ImportModel(context: ContextProbe().context(vault.session))
        await restore.load()
        restore.archivePassphrase = "wrong passphrase entirely"
        await restore.readArchive(archive)
        #expect(restore.errorMessage == "Incorrect password.")
        restore.archivePassphrase = "garden shed padlock"
        await restore.readArchive(archive)
        #expect(restore.stage == .review, "\(restore.errorMessage ?? "")")
        #expect(restore.archiveCreatedAt == (await vault.clock.now()))
        #expect(restore.archivePassphrase.isEmpty)
        #expect(restore.formatName == "Encrypted Watchword archive")
        let duplicate = try #require(restore.duplicates.first)
        await restore.choose(.skip, for: duplicate.id)
        await restore.commit()
        #expect(restore.stage == .done(ImportSummary(created: 0, merged: 0, skipped: 1, failed: 0)))
    }

    @Test(
        "the export file name carries the UTC date, whatever the locale",
        arguments: zip([1_800_000_000, 951_782_400, 0], ["2027-01-15", "2000-02-29", "1970-01-01"]))
    func stamp(seconds: TimeInterval, date: String) {
        #expect(ExportModel.stamp(Date(timeIntervalSince1970: seconds)) == date)
    }

    @Test("the archive is the export offered first, and the only one that is not plaintext")
    func kinds() {
        #expect(ExportKind.allCases.first == .archive)
        #expect(ExportKind.allCases.filter { !$0.isPlaintext } == [.archive])
        #expect(ExportKind.allCases.map(\.fileExtension) == ["wwarchive", "csv", "1pux"])
    }
}

@Suite("Screen models: security report")
@MainActor
struct HygieneScreenTests {
    @Test("Check now runs the scan, sitting out short waits, and the report lists breached and reused passwords")
    func checkNow() async throws {
        let fixture = await HygieneSessionFixture()
        try await fixture.session.createAccount(password: TestVault.password)
        let personal = try #require(await fixture.session.personalVaultID)
        for (title, host) in [("Forum", "forum.example"), ("Shop", "shop.example")] {
            _ = try await fixture.session.save(
                login(personal, title, host: host, username: "pat", password: "password"))
        }
        let clock = fixture.clock
        let sleeps = SleepRecorder()
        let model = HygieneModel(
            context: ContextProbe().context(fixture.session), breachChecksAvailable: true,
            now: { await clock.now() },
            sleep: { duration in
                await sleeps.record(duration)
                await clock.advance(by: Double(duration.components.seconds) + 1)
            })
        await model.load()
        #expect(model.isAvailable)
        await model.checkNow()
        #expect(model.errorMessage == nil, "\(model.errorMessage ?? "")")
        #expect(model.scanStatus?.contains("2 item(s) checked") == true, "\(model.scanStatus ?? "")")
        let slept = await sleeps.durations
        #expect(slept.allSatisfy { $0 <= .seconds(HygieneModel.longestInlineWait + 1) })
        let kinds = model.sections.map(\.kind)
        #expect(kinds.prefix(3) == [.breached, .reused, .weak])
        let breached = try #require(model.sections.first)
        #expect(Set(breached.rows.map(\.title)) == ["Forum", "Shop"])
        #expect(breached.rows.allSatisfy { $0.source == nil }, "this device's own checks name no other source")
        let reused = try #require(model.sections.first { $0.kind == .reused })
        #expect(reused.rows.first { $0.title == "Forum" }?.sharedWith == ["Shop"])
        #expect(model.itemsNeedingAttention == 2)
    }

    @Test("without a network the report still shows reuse and weakness, and Check now sends nothing")
    func noBreachChecks() async throws {
        let fixture = await HygieneSessionFixture()
        try await fixture.session.createAccount(password: TestVault.password)
        let personal = try #require(await fixture.session.personalVaultID)
        _ = try await fixture.session.save(
            login(personal, "Forum", host: "forum.example", username: "p", password: "abc123"))
        let model = HygieneModel(context: ContextProbe().context(fixture.session), breachChecksAvailable: false)
        await model.checkNow()
        #expect(await fixture.http.requests.isEmpty)
        await model.load()
        #expect(model.sections.contains { $0.kind == .weak })
        #expect(model.itemsAwaitingBreachCheck == 1)
    }

    @Test("a session without hygiene settings shows the report as unavailable, not as an error")
    func unavailable() async throws {
        let vault = TestVault()
        try await vault.createAccount()
        let model = HygieneModel(context: ContextProbe().context(vault.session), breachChecksAvailable: false)
        await model.load()
        #expect(!model.isAvailable && model.errorMessage == nil)
    }
}

actor SleepRecorder {
    private(set) var durations: [Duration] = []

    func record(_ duration: Duration) {
        durations.append(duration)
    }
}
