import Foundation
import Testing
import WatchwordMatching
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordInterchange

@Suite("Import mapping into the vault")
struct ImportMappingTests {
    @Test(
        "A URL becomes the scope of its host",
        arguments: zip(
            [
                "https://example.com/login?next=/", "http://Example.COM:8443/", "example.com",
                " https://a.b.example.co.uk ",
                "https://пример.рф/", "https://192.168.1.1/admin", "https://www.example.com/",
            ],
            [
                "example.com", "example.com", "example.com", "a.b.example.co.uk", "пример.рф", "192.168.1.1",
                "www.example.com",
            ]))
    func derivesScope(_ url: String, _ host: String) throws {
        let scope = try ScopeDerivation.scope(forURL: url).get()
        #expect(scope.host == host)
        #expect(scope.excludedHosts.isEmpty)
        // Whatever is derived is something the vault would accept.
        try ScopePolicy.validate(scope)
    }

    @Test("An address scope does not include subdomains; a host scope does")
    func subdomains() throws {
        #expect(try !ScopeDerivation.scope(forURL: "http://10.0.0.1/").get().includeSubdomains)
        #expect(try ScopeDerivation.scope(forURL: "https://example.com/").get().includeSubdomains)
    }

    @Test("Stripping www is opt-in, and never strips down to a public suffix")
    func leadingWWW() throws {
        #expect(
            try ScopeDerivation.scope(forURL: "https://www.example.com/", stripsLeadingWWW: true).get().host
                == "example.com")
        #expect(
            try ScopeDerivation.scope(forURL: "https://www.co.uk/", stripsLeadingWWW: true).get().host == "www.co.uk")
        #expect(
            try ScopeDerivation.scope(forURL: "https://wwwexample.com/", stripsLeadingWWW: true).get().host
                == "wwwexample.com")
    }

    @Test(
        "Hosts a scope may not name are refused by the policy",
        arguments: [
            "https://com/", "https://co.uk/", "https://github.io/", "http://localhost:3000/", "https://herokuapp.com",
            "intranet",
        ])
    func policyRefusals(_ url: String) {
        guard case .failure(.policy) = ScopeDerivation.scope(forURL: url) else {
            Issue.record("\(url) was not refused by the policy")
            return
        }
    }

    @Test(
        "Anything that is not unambiguously a web host is refused by the normaliser",
        arguments: [
            "https://example.com@evil.example/", "ftp://example.com/", "android://com.example.app/",
            "javascript://example.com/%0Aalert(1)",
            "example.com/login", "example.com:443", "https://exa%6Dple.com/", "https://", "not a url",
            "file:///etc/passwd",
            "example.com\u{200B}", "exam\u{202E}ple.com", "data:text/html,hi",
        ])
    func normaliserRefusals(_ url: String) {
        guard case .failure(.notAHost) = ScopeDerivation.scope(forURL: url) else {
            Issue.record("\(url) was not refused by the normaliser")
            return
        }
    }

    @Test("Limits can be tightened and never loosened")
    func limits() {
        let standard = InterchangeLimits.standard
        #expect(standard.maximumInputBytes == 100 * 1024 * 1024)
        #expect(standard.maximumArchiveEntries == 50_000)
        #expect(standard.maximumItems == 50_000)
        #expect(standard.maximumCompressionRatio == 100)
        #expect(InterchangeLimits() == standard)
        let loose = InterchangeLimits(
            maximumInputBytes: .max, maximumDocumentBytes: .max, maximumArchiveEntries: .max, maximumItems: .max,
            maximumCompressionRatio: .max, maximumEntryBytes: .max, maximumFieldBytes: .max, maximumFieldsPerItem: .max,
            maximumNestingDepth: .max, maximumEntryNameBytes: .max)
        #expect(loose == standard)
        let tight = InterchangeLimits(maximumItems: 3, maximumCompressionRatio: 0, maximumNestingDepth: -4)
        #expect(tight.maximumItems == 3)
        #expect(tight.maximumCompressionRatio == 1)
        #expect(tight.maximumNestingDepth == 1)
        for kind in InterchangeLimits.Kind.allCases {
            #expect(tight.value(of: kind) >= 1)
            #expect(tight.value(of: kind) <= standard.value(of: kind))
        }
    }

    @Test("Identifiers are version-4 UUIDs from the injected generator")
    func identifiers() {
        var generator = SeededGenerator(seed: 5)
        let first = RandomUUID.make(using: &generator)
        let second = RandomUUID.make(using: &generator)
        var again = SeededGenerator(seed: 5)
        #expect(RandomUUID.make(using: &again) == first)
        #expect(first != second)
        #expect(first.uuid.6 >> 4 == 4)
        #expect(first.uuid.8 >> 6 == 2)
        #expect(UUID(uuid: first.uuid) == first)
        #expect(RandomUUID.bytes(of: first).count == 16)
    }

    @Test("One-time-password values are stored in canonical form")
    func oneTimePasswords() throws {
        let canonical =
            "otpauth://totp/Example:wendy?secret=\(Fixtures.totpSecret)&issuer=Example&algorithm=SHA1&digits=6&period=30"
        #expect(
            try ImportAssembler.canonicalOneTimePasswordURI(
                "OTPAUTH://totp/Example:wendy?issuer=Example&secret=gezdgnbvgy3tqojqgezdgnbvgy3tqojq") == canonical)
        #expect(try ImportAssembler.canonicalOneTimePasswordURI("  \(canonical)\n") == canonical)
        #expect(
            try ImportAssembler.canonicalOneTimePasswordURI("gezd gnbv gy3t qojq")
                == "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=6&period=30")
        #expect(throws: OTPAuthError.malformedSecret) { try ImportAssembler.canonicalOneTimePasswordURI("hunter2!") }
        #expect(throws: OTPAuthError.missingSecret) { try ImportAssembler.canonicalOneTimePasswordURI(" - ") }
        #expect(throws: OTPAuthError.secretLength(5)) { try ImportAssembler.canonicalOneTimePasswordURI("GEZDGNBV") }
        #expect(throws: OTPAuthError.unsupportedType("hotp")) {
            try ImportAssembler.canonicalOneTimePasswordURI("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ")
        }
        #expect(throws: OTPAuthError.tooLong) {
            try ImportAssembler.canonicalOneTimePasswordURI(String(repeating: "A", count: 5_000))
        }
    }

    @Test("Calendar dates round-trip without a formatter")
    func civilDates() {
        #expect(CivilDate.string(seconds: 0) == "1970-01-01")
        #expect(CivilDate.string(seconds: 951_782_400) == "2000-02-29")
        #expect(CivilDate.string(seconds: 1_709_251_199) == "2024-02-29")
        #expect(CivilDate.string(seconds: 253_402_300_799) == "9999-12-31")
        #expect(CivilDate.seconds(fromDate: "2000-02-29") == Int64(951_825_600))
        #expect(CivilDate.seconds(fromDate: "2023-02-29") == nil)
        #expect(CivilDate.seconds(fromDate: "2023-13-01") == nil)
        #expect(CivilDate.seconds(fromDate: "2023-1-1") == nil)
        #expect(CivilDate.seconds(fromDate: "+023-01-01") == nil)
        #expect(CivilDate.string(monthYear: 203_012) == "2030-12")
        #expect(CivilDate.string(monthYear: 203_013) == nil)
        #expect(CivilDate.string(monthYear: -1) == nil)
        #expect(CivilDate.monthYear(from: "2030-12") == 203_012)
        #expect(CivilDate.monthYear(from: "2030-00") == nil)
        for seconds: Int64 in stride(from: 0, to: 4_000_000_000, by: 86_400 * 37) {
            let text = CivilDate.string(seconds: seconds)
            #expect(CivilDate.seconds(fromDate: text) == seconds - seconds % 86_400 + 43_200)
        }
    }
}

@Suite("Duplicate detection")
struct DuplicateDetectorTests {
    private func item(
        _ title: String, hosts: [String] = [], username: String? = nil, password: String? = nil, notes: String = "",
        tags: Set<String> = [], trashed: Bool = false
    ) -> Item {
        var fields: [Field] = []
        if let username { fields.append(Field(kind: .username, label: "Username", value: username)) }
        if let password { fields.append(Field(kind: .password, label: "Password", value: password)) }
        return Item(
            vaultID: Fixtures.vaultID, title: title, scopes: hosts.map { ServiceScope(host: $0) }, fields: fields,
            tags: tags, notes: notes, trashedAt: trashed ? Date(timeIntervalSince1970: 1) : nil)
    }

    @Test("Finds identical items and the same account with different contents")
    func matches() {
        let existing = [
            item("Example", hosts: ["example.com"], username: "wendy", password: "old"),
            item("Other", hosts: ["other.example"], username: "wendy", password: "pw"),
            item("Safe", notes: "behind the painting"),
            item("Gone", hosts: ["gone.example"], username: "wendy", password: "pw", trashed: true),
        ]
        let imported = [
            item("Example", hosts: ["example.com"], username: "wendy", password: "old"),
            item("Example (renamed)", hosts: ["example.com", "example.org"], username: "WENDY", password: "new"),
            item("Example", hosts: ["example.com"], username: "peter", password: "old"),
            item("safe", notes: "something else"),
            item("Gone", hosts: ["gone.example"], username: "wendy", password: "pw"),
            item("New", hosts: ["new.example"], username: "wendy", password: "pw"),
        ]
        let matches = DuplicateDetector.matches(imported: imported, existing: existing)
        #expect(
            matches == [
                DuplicateMatch(importedID: imported[0].id, existingID: existing[0].id, kind: .identical),
                DuplicateMatch(importedID: imported[1].id, existingID: existing[0].id, kind: .sameAccount),
                DuplicateMatch(importedID: imported[3].id, existingID: existing[2].id, kind: .sameAccount),
            ])
    }

    @Test("Detection changes nothing, and each resolution is the caller's to apply")
    func resolutions() {
        let existing = item(
            "Example", hosts: ["example.com"], username: "wendy", password: "old", notes: "kept", tags: ["a"])
        var imported = item(
            "Example", hosts: ["example.com", "login.example.com"], username: "wendy", password: "new", notes: "added",
            tags: ["b"])
        imported.fields.append(Field(kind: .pin, label: "PIN", value: "0420"))

        #expect(DuplicateDetector.resolve(.skip, imported: imported, existing: existing) == nil)
        #expect(DuplicateDetector.resolve(.keepBoth, imported: imported, existing: existing) == imported)

        let merged = DuplicateDetector.merged(imported, into: existing)
        #expect(DuplicateDetector.resolve(.merge, imported: imported, existing: existing) == merged)
        #expect(merged.id == existing.id)
        #expect(merged.title == "Example")
        #expect(merged.scopes.map(\.host) == ["example.com", "login.example.com"])
        // Nothing of the existing item is replaced: the differing password arrives beside the old one.
        #expect(merged.fields.map(\.value) == ["wendy", "old", "new", "0420"])
        #expect(merged.tags == ["a", "b"])
        #expect(merged.notes == "kept\n\nadded")
        // Merging again adds nothing.
        #expect(DuplicateDetector.merged(imported, into: merged) == merged)
    }

    @Test("The work stays bounded when everything resembles everything")
    func bounded() {
        let existing = (0..<200).map { _ in item("Same", hosts: ["example.com"], username: "wendy", password: "pw") }
        let imported = (0..<200).map { _ in item("Same", hosts: ["example.com"], username: "wendy", password: "pw") }
        let matches = DuplicateDetector.matches(imported: imported, existing: existing)
        #expect(matches.count == 200 * DuplicateDetector.maximumMatchesPerItem)
        #expect(matches.allSatisfy { $0.kind == .identical })
    }
}

@Suite("Interchange instructions")
struct InterchangeGuideTests {
    @Test("There is a guide for each direction and each app")
    func coverage() {
        #expect(InterchangeGuide.all.map(\.id) == InterchangeGuide.ID.allCases)
        #expect(InterchangeGuide.all.allSatisfy { !$0.routes.isEmpty && !$0.title.isEmpty && !$0.summary.isEmpty })
        let routes = InterchangeGuide.all.flatMap(\.routes)
        #expect(Set(routes.map(\.id)).count == routes.count)
        #expect(routes.allSatisfy { $0.steps.count >= 3 })
        // The app-to-app route, which writes no file, is always offered first.
        #expect(InterchangeGuide.all.allSatisfy { $0.routes.first?.format == .credentialExchange })
    }

    @Test("Every route that writes a file says the file is plaintext, and tells the person to delete it")
    func plaintextCaveat() {
        for route in InterchangeGuide.all.flatMap(\.routes) {
            let kinds = route.caveats.map(\.kind)
            #expect(route.writesPlaintextFile == (route.format != .credentialExchange), "\(route.id)")
            #expect(kinds.contains(.plaintextFile) == route.writesPlaintextFile, "\(route.id)")
            if route.writesPlaintextFile {
                #expect(route.steps.last?.hasPrefix("Delete the") == true, "\(route.id)")
            }
        }
    }

    @Test("The research caveats are where they apply")
    func researchCaveats() {
        for guide in InterchangeGuide.all {
            for route in guide.routes {
                let kinds = Set(route.caveats.map(\.kind))
                switch route.format {
                case .applePasswordsCSV, .onePassword8CSV, .onePassword7CSV:
                    #expect(kinds.contains(.passkeysNotInCSV), "\(route.id)")
                case .onePUX:
                    #expect(kinds.contains(.passkeysNotIn1PUX), "\(route.id)")
                case .credentialExchange:
                    #expect(kinds.contains(.transferMayDeliverNothing), "\(route.id)")
                }
            }
        }
        let fromApple = InterchangeGuide.guide(.exportFromApplePasswords)
        #expect(fromApple.routes[0].caveats.map(\.kind).contains(.wifiNotInCredentialExchange))
        let intoApple = InterchangeGuide.guide(.importIntoApplePasswords)
        #expect(
            Set(intoApple.routes[1].caveats.map(\.kind)).isSuperset(of: [.fieldsMovedToNotes, .formulaCellsChanged]))
        #expect(InterchangeGuide.guide(.exportFrom1Password).routes[2].caveats.map(\.kind).contains(.limitedCSV))
    }

    @Test("Snapshot: moving from Apple Passwords")
    func snapshotFromApple() {
        #expect(InterchangeGuide.guide(.exportFromApplePasswords).plainText == InterchangeGuideTests.fromApple)
    }

    @Test("Snapshot: moving to Apple Passwords")
    func snapshotIntoApple() {
        #expect(InterchangeGuide.guide(.importIntoApplePasswords).plainText == InterchangeGuideTests.intoApple)
    }

    @Test("Snapshot: moving from 1Password")
    func snapshotFrom1Password() {
        #expect(InterchangeGuide.guide(.exportFrom1Password).plainText == InterchangeGuideTests.from1Password)
    }

    @Test("Snapshot: moving to 1Password")
    func snapshotInto1Password() {
        #expect(InterchangeGuide.guide(.importInto1Password).plainText == InterchangeGuideTests.into1Password)
    }

    static let fromApple = """
        Move from Apple Passwords to Watchword
        Export your passwords from the Passwords app, then import them here. Nothing is removed from Passwords.

        ## Directly, app to app
        Needs: iOS 26, iPadOS 26 or macOS 26 or later, and a version of the other app that supports exporting to another app.
        1. Open the Passwords app.
        2. Choose Export Data to Another App: in the File menu on a Mac, or in the menu at the top of the list on iPhone and iPad.
        3. Confirm with Face ID, Touch ID or your passcode, and choose what to export.
        4. Choose Watchword from the list of apps.
        5. Watchword opens and shows what it received. Review the import report: it lists every item imported, every item skipped and why, and every value that was kept in a different form. Then save.
        ! Wi-Fi passwords are not included in a transfer to another app.
        ! Nothing is written to a file: the data passes directly between the two apps. Compare the number of items imported with the number you expected before you delete anything from the app you are leaving.
        ! If the other app does not open, or opens and shows nothing, update both apps and try again. A transfer that delivers nothing has removed nothing: your data is still where it was.

        ## With a CSV file
        Needs: A Mac.
        1. On a Mac, open the Passwords app. Before macOS 15, open System Settings and choose Passwords.
        2. Choose File > Export All Passwords to File. Before macOS 15, use the menu marked with three dots and choose Export All Passwords.
        3. Confirm with Touch ID or your login password, choose Export Passwords, and save the file.
        4. In Watchword, choose Import, then CSV file, and select the file.
        5. Review the import report: it lists every item imported, every item skipped and why, and every value that was kept in a different form. Then save.
        6. Delete the CSV file, and empty the Trash.
        ! The CSV file is not encrypted: anyone who can read it can read every password in it. Save it to a folder on this device that is not synced or shared, and delete it as soon as the import is done.
        ! Passkeys, Wi-Fi passwords and passwords in shared groups are not reliably in the file. Move passkeys with Export Data to Another App, or sign in and create new ones.
        ! Compare the number of items imported with the number you expected before you delete anything from the app you are leaving.
        """
    static let intoApple = """
        Move from Watchword to Apple Passwords
        Export your items from Watchword, then import them into the Passwords app. Nothing is removed from Watchword.

        ## Directly, app to app
        Needs: iOS 26, iPadOS 26 or macOS 26 or later, and a version of the other app that supports exporting to another app.
        1. In Watchword, choose Export, then Export to Another App.
        2. Enter your Watchword account password.
        3. Choose Passwords from the list of apps, and confirm with Face ID, Touch ID or your passcode.
        4. Passwords opens and shows what it received. Follow its steps to finish the import.
        ! Nothing is written to a file: the data passes directly between the two apps. Compare the number of items imported with the number you expected before you delete anything from the app you are leaving.
        ! If the other app does not open, or opens and shows nothing, update both apps and try again. A transfer that delivers nothing has removed nothing: your data is still where it was.

        ## With a CSV file
        Needs: A Mac, to import the file into Passwords.
        1. In Watchword, choose Export, then Apple Passwords (CSV).
        2. Enter your Watchword account password, and save the file.
        3. On a Mac, open the Passwords app and choose File > Import Passwords from File.
        4. Select the CSV file and choose Import.
        5. Delete the CSV file, and empty the Trash.
        ! The CSV file is not encrypted: anyone who can read it can read every password in it. Save it to a folder on this device that is not synced or shared, and delete it as soon as the import is done.
        ! Passkeys cannot be written to a CSV file. Move them with Export to Another App, or sign in and create new passkeys afterwards.
        ! Passwords keeps one username, one password, one verification code and notes for each website. Security questions, PINs, recovery codes and other fields are written into the notes, and an item with several websites becomes one entry for each.
        ! A value that begins with =, +, - or @ is written with an apostrophe in front, so that a spreadsheet opening the file cannot run it as a formula. Passwords imports the apostrophe as part of the value. The export report lists each value changed: correct them in Passwords afterwards, or choose to write values unchanged if the file will only ever be opened by Passwords.
        """
    static let from1Password = """
        Move from 1Password to Watchword
        Export your data from 1Password, then import it here. Nothing is removed from 1Password.

        ## Directly, app to app
        Needs: iOS 26, iPadOS 26 or macOS 26 or later, and a version of the other app that supports exporting to another app.
        1. On this device, open 1Password and unlock it.
        2. In 1Password's settings, choose to export your data to another app.
        3. Choose Watchword from the list of apps, and confirm with Face ID, Touch ID or your passcode.
        4. Watchword opens and shows what it received. Review the import report: it lists every item imported, every item skipped and why, and every value that was kept in a different form. Then save.
        ! Nothing is written to a file: the data passes directly between the two apps. Compare the number of items imported with the number you expected before you delete anything from the app you are leaving.
        ! If the other app does not open, or opens and shows nothing, update both apps and try again. A transfer that delivers nothing has removed nothing: your data is still where it was.

        ## With a 1PUX file
        Needs: The 1Password app for Mac, Windows or Linux. The mobile apps cannot export a file.
        1. Open the 1Password desktop app and unlock it.
        2. On a Mac, choose File > Export and then the account to export. On Windows or Linux, open the menu at the top of the sidebar and choose Export.
        3. Enter your 1Password account password.
        4. Choose 1PUX as the format, select Export Data, and save the file.
        5. In Watchword, choose Import, then 1Password (1PUX), and select the file.
        6. Review the import report: it lists every item imported, every item skipped and why, and every value that was kept in a different form. Then save.
        7. Delete the 1PUX file, and empty the Trash or Recycle Bin.
        ! The 1PUX file is not encrypted: anyone who can read it can read every password in it. Save it to a folder on this device that is not synced or shared, and delete it as soon as the import is done.
        ! File attachments and links between items are not imported. The report lists each one.
        ! Passkeys are not imported from a 1PUX file. Move them app to app, or sign in and create new passkeys afterwards.
        ! Compare the number of items imported with the number you expected before you delete anything from the app you are leaving.

        ## With a CSV file
        Needs: The 1Password app for Mac, Windows or Linux.
        1. Open the 1Password desktop app and unlock it.
        2. Choose Export as for a 1PUX file, and enter your 1Password account password.
        3. Choose CSV as the format, select Export Data, and save the file.
        4. In Watchword, choose Import, then CSV file, and select the file.
        5. Review the import report: it lists every item imported, every item skipped and why, and every value that was kept in a different form. Then save.
        6. Delete the CSV file, and empty the Trash or Recycle Bin.
        ! The CSV file is not encrypted: anyone who can read it can read every password in it. Save it to a folder on this device that is not synced or shared, and delete it as soon as the import is done.
        ! 1Password's CSV holds only Login and Password items, and only their title, website, username, password, one-time password, favourite and archived marks, tags and notes. Security questions, custom fields and every other kind of item are left out. Use a 1PUX file if you can.
        ! Passkeys cannot be written to a CSV file. Move them with Export to Another App, or sign in and create new passkeys afterwards.
        """
    static let into1Password = """
        Move from Watchword to 1Password
        Export your items from Watchword, then import them into 1Password. Nothing is removed from Watchword.

        ## Directly, app to app
        Needs: iOS 26, iPadOS 26 or macOS 26 or later, and a version of the other app that supports exporting to another app.
        1. In Watchword, choose Export, then Export to Another App.
        2. Enter your Watchword account password.
        3. Choose 1Password from the list of apps, and confirm with Face ID, Touch ID or your passcode.
        4. 1Password opens and shows what it received. Follow its steps to finish the import.
        ! Nothing is written to a file: the data passes directly between the two apps. Compare the number of items imported with the number you expected before you delete anything from the app you are leaving.
        ! If the other app does not open, or opens and shows nothing, update both apps and try again. A transfer that delivers nothing has removed nothing: your data is still where it was.

        ## With a 1PUX file
        Needs: The 1Password app for Mac, Windows or Linux.
        1. In Watchword, choose Export, then 1Password (1PUX).
        2. Enter your Watchword account password, and save the file.
        3. Open the 1Password desktop app and unlock it.
        4. On a Mac, choose File > Import. On Windows or Linux, open the menu at the top of the sidebar and choose Import.
        5. Choose 1Password as the app the data comes from, select the 1PUX file, and choose the vault to import into.
        6. Delete the 1PUX file, and empty the Trash or Recycle Bin.
        ! The 1PUX file is not encrypted: anyone who can read it can read every password in it. Save it to a folder on this device that is not synced or shared, and delete it as soon as the import is done.
        ! Passkeys are not written to a 1PUX file; the export report lists the items that have one. Move them app to app, or create new passkeys in 1Password.
        ! Compare the number of items imported with the number you expected before you delete anything from the app you are leaving.
        """
}
