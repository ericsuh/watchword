import Foundation

/// Step-by-step instructions for moving data between Watchword, 1Password and Apple Passwords (PRD F8.5), as data
/// the UI renders: this module decides what is said, the app decides how it looks.
///
/// The caveats are the ones research turned up (docs/00-research.md §1.1, §1.3, §2.2): passkeys do not survive CSV,
/// Wi-Fi passwords are left out of Credential Exchange, and an exported file is plaintext. Every route that writes
/// a file carries the plaintext caveat, and tests hold that to be so. The wording is snapshot-tested, so a change
/// to it is a deliberate one; menu names in the other apps are as of the research date and are the part most
/// likely to need one.
public struct InterchangeGuide: Hashable, Sendable, Identifiable {
    public enum ID: String, Hashable, Sendable, CaseIterable {
        case exportFrom1Password
        case importInto1Password
        case exportFromApplePasswords
        case importIntoApplePasswords
    }

    public enum CaveatKind: String, Hashable, Sendable, CaseIterable {
        /// The file holds every secret unencrypted.
        case plaintextFile
        case passkeysNotInCSV
        case passkeysNotIn1PUX
        case wifiNotInCredentialExchange
        /// 1Password's CSV carries Login and Password items only, and only their basic fields.
        case limitedCSV
        case attachmentsNotImported
        /// Fields Apple Passwords has no place for are written into the notes.
        case fieldsMovedToNotes
        /// Cells that look like spreadsheet formulas are prefixed with an apostrophe.
        case formulaCellsChanged
        /// A Credential Exchange transfer that delivers nothing leaves the source untouched.
        case transferMayDeliverNothing
        case compareCounts
        /// An export lists what the format could not carry; it is to be read before anything is deleted here.
        case exportReport
    }

    public struct Caveat: Hashable, Sendable {
        public var kind: CaveatKind
        public var text: String

        public init(_ kind: CaveatKind, _ text: String) {
            self.kind = kind
            self.text = text
        }
    }

    /// One way of making the move. A guide lists the better way first.
    public struct Route: Hashable, Sendable, Identifiable {
        /// A stable key, for localisation and for the UI to remember a choice.
        public var id: String
        public var title: String
        public var format: InterchangeFormat
        /// What the route needs before it can be used at all.
        public var requirement: String?
        /// Whether following the route leaves an unencrypted file on disk.
        public var writesPlaintextFile: Bool
        public var steps: [String]
        public var caveats: [Caveat]
    }

    public var id: ID
    public var title: String
    public var summary: String
    public var routes: [Route]

    public static func guide(_ id: ID) -> InterchangeGuide {
        switch id {
        case .exportFrom1Password: return exportFrom1Password
        case .importInto1Password: return importInto1Password
        case .exportFromApplePasswords: return exportFromApplePasswords
        case .importIntoApplePasswords: return importIntoApplePasswords
        }
    }

    public static var all: [InterchangeGuide] { ID.allCases.map(guide) }

    /// The guide as plain text: what a screen reader would read, and what the snapshot tests pin.
    public var plainText: String {
        var lines = [title, summary]
        for route in routes {
            lines.append("")
            lines.append("## \(route.title)")
            if let requirement = route.requirement { lines.append("Needs: \(requirement)") }
            for (index, step) in route.steps.enumerated() {
                lines.append("\(index + 1). \(step)")
            }
            for caveat in route.caveats {
                lines.append("! \(caveat.text)")
            }
        }
        return lines.joined(separator: "\n")
    }

    // MARK: Shared wording

    private static func plaintext(_ file: String) -> Caveat {
        Caveat(
            .plaintextFile,
            "The \(file) file is not encrypted: anyone who can read it can read every password in it. Save it to a "
                + "folder on this device that is not synced or shared, and delete it as soon as the import is done.")
    }

    private static let credentialExchangeRequirement =
        "iOS 26, iPadOS 26 or macOS 26 or later, and a version of the other app that supports exporting to another app."
    private static let nothingOnDisk = "Nothing is written to a file: the data passes directly between the two apps."
    private static let wifi = Caveat(
        .wifiNotInCredentialExchange, "Wi-Fi passwords are not included in a transfer to another app.")
    private static let deliversNothing = Caveat(
        .transferMayDeliverNothing,
        "If the other app does not open, or opens and shows nothing, update both apps and try again. A transfer that "
            + "delivers nothing has removed nothing: your data is still where it was.")
    private static let compareCounts = Caveat(
        .compareCounts,
        "Compare the number of items imported with the number you expected before you delete anything from the app "
            + "you are leaving.")
    private static let exportReport = Caveat(
        .exportReport,
        "Watchword's export report lists what the file or transfer could not carry as it was: earlier versions of "
            + "an item, tags and archived marks where the other app has no place for them, an item limited to one "
            + "host or with hosts excluded, and values still waiting for you to choose between. Read it before you "
            + "delete anything from Watchword.")
    private static let passkeysNotInCSV = Caveat(
        .passkeysNotInCSV,
        "Passkeys cannot be written to a CSV file. Move them with Export to Another App, or sign in and create new "
            + "passkeys afterwards.")
    private static let reviewReport =
        "Review the import report: it lists every item imported, every item skipped and why, and every value that "
        + "was kept in a different form. Then save."

    // MARK: Guides

    private static let exportFrom1Password = InterchangeGuide(
        id: .exportFrom1Password,
        title: "Move from 1Password to Watchword",
        summary: "Export your data from 1Password, then import it here. Nothing is removed from 1Password.",
        routes: [
            Route(
                id: "1password.to-watchword.credential-exchange",
                title: "Directly, app to app",
                format: .credentialExchange,
                requirement: credentialExchangeRequirement,
                writesPlaintextFile: false,
                steps: [
                    "On this device, open 1Password and unlock it.",
                    "In 1Password's settings, choose to export your data to another app.",
                    "Choose Watchword from the list of apps, and confirm with Face ID, Touch ID or your passcode.",
                    "Watchword opens and shows what it received. " + reviewReport,
                ],
                caveats: [Caveat(.compareCounts, nothingOnDisk + " " + compareCounts.text), deliversNothing]),
            Route(
                id: "1password.to-watchword.1pux",
                title: "With a 1PUX file",
                format: .onePUX,
                requirement: "The 1Password app for Mac, Windows or Linux. The mobile apps cannot export a file.",
                writesPlaintextFile: true,
                steps: [
                    "Open the 1Password desktop app and unlock it.",
                    "On a Mac, choose File > Export and then the account to export. On Windows or Linux, open the "
                        + "menu at the top of the sidebar and choose Export.",
                    "Enter your 1Password account password.",
                    "Choose 1PUX as the format, select Export Data, and save the file.",
                    "In Watchword, choose Import, then 1Password (1PUX), and select the file.",
                    reviewReport,
                    "Delete the 1PUX file, and empty the Trash or Recycle Bin.",
                ],
                caveats: [
                    plaintext("1PUX"),
                    Caveat(
                        .attachmentsNotImported,
                        "File attachments and links between items are not imported. The report lists each one."),
                    Caveat(
                        .passkeysNotIn1PUX,
                        "Passkeys are not imported from a 1PUX file. Move them app to app, or sign in and create new "
                            + "passkeys afterwards."),
                    compareCounts,
                ]),
            Route(
                id: "1password.to-watchword.csv",
                title: "With a CSV file",
                format: .onePassword8CSV,
                requirement: "The 1Password app for Mac, Windows or Linux.",
                writesPlaintextFile: true,
                steps: [
                    "Open the 1Password desktop app and unlock it.",
                    "Choose Export as for a 1PUX file, and enter your 1Password account password.",
                    "Choose CSV as the format, select Export Data, and save the file.",
                    "In Watchword, choose Import, then CSV file, and select the file.",
                    reviewReport,
                    "Delete the CSV file, and empty the Trash or Recycle Bin.",
                ],
                caveats: [
                    plaintext("CSV"),
                    Caveat(
                        .limitedCSV,
                        "1Password's CSV holds only Login and Password items, and only their title, website, "
                            + "username, password, one-time password, favourite and archived marks, tags and notes. "
                            + "Security questions, custom fields and every other kind of item are left out. Use a "
                            + "1PUX file if you can."),
                    passkeysNotInCSV,
                ]),
        ])

    private static let importInto1Password = InterchangeGuide(
        id: .importInto1Password,
        title: "Move from Watchword to 1Password",
        summary:
            "Export your items from Watchword, then import them into 1Password. Nothing is removed from Watchword.",
        routes: [
            Route(
                id: "watchword.to-1password.credential-exchange",
                title: "Directly, app to app",
                format: .credentialExchange,
                requirement: credentialExchangeRequirement,
                writesPlaintextFile: false,
                steps: [
                    "In Watchword, choose Export, then Export to Another App.",
                    "Enter your Watchword account password.",
                    "Choose 1Password from the list of apps, and confirm with Face ID, Touch ID or your passcode.",
                    "1Password opens and shows what it received. Follow its steps to finish the import.",
                ],
                caveats: [
                    Caveat(.compareCounts, nothingOnDisk + " " + compareCounts.text), deliversNothing, exportReport,
                ]),
            Route(
                id: "watchword.to-1password.1pux",
                title: "With a 1PUX file",
                format: .onePUX,
                requirement: "The 1Password app for Mac, Windows or Linux.",
                writesPlaintextFile: true,
                steps: [
                    "In Watchword, choose Export, then 1Password (1PUX).",
                    "Enter your Watchword account password, and save the file.",
                    "Open the 1Password desktop app and unlock it.",
                    "On a Mac, choose File > Import. On Windows or Linux, open the menu at the top of the sidebar "
                        + "and choose Import.",
                    "Choose 1Password as the app the data comes from, select the 1PUX file, and choose the vault "
                        + "to import into.",
                    "Delete the 1PUX file, and empty the Trash or Recycle Bin.",
                ],
                caveats: [
                    plaintext("1PUX"),
                    Caveat(
                        .passkeysNotIn1PUX,
                        "Passkeys are not written to a 1PUX file; the export report lists the items that have one. "
                            + "Move them app to app, or create new passkeys in 1Password."),
                    compareCounts,
                    exportReport,
                ]),
        ])

    private static let exportFromApplePasswords = InterchangeGuide(
        id: .exportFromApplePasswords,
        title: "Move from Apple Passwords to Watchword",
        summary:
            "Export your passwords from the Passwords app, then import them here. Nothing is removed from Passwords.",
        routes: [
            Route(
                id: "apple.to-watchword.credential-exchange",
                title: "Directly, app to app",
                format: .credentialExchange,
                requirement: credentialExchangeRequirement,
                writesPlaintextFile: false,
                steps: [
                    "Open the Passwords app.",
                    "Choose Export Data to Another App: in the File menu on a Mac, or in the menu at the top of the "
                        + "list on iPhone and iPad.",
                    "Confirm with Face ID, Touch ID or your passcode, and choose what to export.",
                    "Choose Watchword from the list of apps.",
                    "Watchword opens and shows what it received. " + reviewReport,
                ],
                caveats: [wifi, Caveat(.compareCounts, nothingOnDisk + " " + compareCounts.text), deliversNothing]),
            Route(
                id: "apple.to-watchword.csv",
                title: "With a CSV file",
                format: .applePasswordsCSV,
                requirement: "A Mac.",
                writesPlaintextFile: true,
                steps: [
                    "On a Mac, open the Passwords app. Before macOS 15, open System Settings and choose Passwords.",
                    "Choose File > Export All Passwords to File. Before macOS 15, use the menu marked with three "
                        + "dots and choose Export All Passwords.",
                    "Confirm with Touch ID or your login password, choose Export Passwords, and save the file.",
                    "In Watchword, choose Import, then CSV file, and select the file.",
                    reviewReport,
                    "Delete the CSV file, and empty the Trash.",
                ],
                caveats: [
                    plaintext("CSV"),
                    Caveat(
                        .passkeysNotInCSV,
                        "Passkeys, Wi-Fi passwords and passwords in shared groups are not reliably in the file. "
                            + "Move passkeys with Export Data to Another App, or sign in and create new ones."),
                    compareCounts,
                ]),
        ])

    private static let importIntoApplePasswords = InterchangeGuide(
        id: .importIntoApplePasswords,
        title: "Move from Watchword to Apple Passwords",
        summary: "Export your items from Watchword, then import them into the Passwords app. Nothing is removed from "
            + "Watchword.",
        routes: [
            Route(
                id: "watchword.to-apple.credential-exchange",
                title: "Directly, app to app",
                format: .credentialExchange,
                requirement: credentialExchangeRequirement,
                writesPlaintextFile: false,
                steps: [
                    "In Watchword, choose Export, then Export to Another App.",
                    "Enter your Watchword account password.",
                    "Choose Passwords from the list of apps, and confirm with Face ID, Touch ID or your passcode.",
                    "Passwords opens and shows what it received. Follow its steps to finish the import.",
                ],
                caveats: [
                    Caveat(.compareCounts, nothingOnDisk + " " + compareCounts.text), deliversNothing, exportReport,
                ]),
            Route(
                id: "watchword.to-apple.csv",
                title: "With a CSV file",
                format: .applePasswordsCSV,
                requirement: "A Mac, to import the file into Passwords.",
                writesPlaintextFile: true,
                steps: [
                    "In Watchword, choose Export, then Apple Passwords (CSV).",
                    "Enter your Watchword account password, and save the file.",
                    "On a Mac, open the Passwords app and choose File > Import Passwords from File.",
                    "Select the CSV file and choose Import.",
                    "Delete the CSV file, and empty the Trash.",
                ],
                caveats: [
                    plaintext("CSV"),
                    passkeysNotInCSV,
                    Caveat(
                        .fieldsMovedToNotes,
                        "Passwords keeps one username, one password, one verification code and notes for each "
                            + "website. Security questions, PINs, recovery codes and other fields are written into "
                            + "the notes, and an item with several websites becomes one entry for each."),
                    Caveat(
                        .formulaCellsChanged,
                        "A value that begins with =, +, - or @ is written with an apostrophe in front, so that a "
                            + "spreadsheet opening the file cannot run it as a formula. Passwords imports the "
                            + "apostrophe as part of the value. The export report lists each value changed: correct "
                            + "them in Passwords afterwards, or choose to write values unchanged if the file will "
                            + "only ever be opened by Passwords."),
                    exportReport,
                ]),
        ])
}
