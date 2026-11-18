import Foundation

/// The accessibility identifiers of the screens for vaults, sharing, devices, the quarantine, the security report,
/// import and export. Compiled into the apps and into both UI-test bundles (`Apps/project.yml`), so the two agree by
/// construction; the identifiers are stable, and a UI test or the screenshot tour that finds an element by one keeps
/// working across layout changes. Rename one only with every test that names it. Foundation only: the UI-test bundles
/// compile this file without the app's modules.
///
/// Earlier screens' identifiers (`items.*`, `detail.*`, `edit.*`, `settings.*`, `unlock.*`, `kit.*`, `conflict.*`)
/// are literals in their views and tests.
enum AccessibilityID {
    /// The Done button on every screen opened from Settings' account section; it closes that screen's sheet.
    static let screenDone = "screen.done"

    enum Settings {
        static let vaults = "settings.vaults"
        static let devices = "settings.devices"
        static let quarantine = "settings.quarantine"
        static let hygiene = "settings.hygiene"
        static let importItems = "settings.import"
        static let export = "settings.export"
        static let restore = "settings.restore"
        static let syncNotice = "settings.syncNotice"
    }

    enum Vaults {
        static let list = "vaults.list"
        static let add = "vaults.add"
        static let accept = "vaults.accept"
        static let newName = "vaults.newName"
        static let create = "vaults.create"
        static func row(_ name: String) -> String { "vaults.row.\(name)" }
    }

    enum Vault {
        static let name = "vault.name"
        static let rename = "vault.rename"
        static let renameField = "vault.renameField"
        static let renameSave = "vault.renameSave"
        static let renameRefused = "vault.renameRefused"
        static let readOnly = "vault.readOnly"
        static let share = "vault.share"
        static let awaitingOwnerCheck = "vault.awaitingOwnerCheck"
        static let setUpAgain = "vault.setUpAgain"
        static let invite = "vault.invite"
        static let leave = "vault.leave"
        static let leaveConfirm = "vault.leaveConfirm"
        static let rotate = "vault.rotate"
        static let notice = "vault.notice"
        static let heldAside = "vault.heldAside"
        static let fingerprint = "vault.fingerprint"
        static let ownSafetyNumber = "vault.ownSafetyNumber"
        static func member(_ name: String) -> String { "vault.member.\(name)" }
        /// Outside `member(_:)`'s prefix, so a query for member rows never finds the button.
        static func memberCheck(_ name: String) -> String { "vault.memberCheck.\(name)" }
        static func memberRole(_ name: String) -> String { "vault.member.\(name).role" }
        static func pending(_ index: Int) -> String { "vault.pending.\(index)" }
    }

    enum Invite {
        static let startSession = "invite.startSession"
        static let number = "invite.number"
        static let qr = "invite.qr"
        static let checkAgain = "invite.checkAgain"
        static let typedCode = "invite.typedCode"
        static let confirmCode = "invite.confirmCode"
        static let scan = "invite.scan"
        static let ownCode = "invite.ownCode"
        static let useNewKeys = "invite.useNewKeys"
        static let failed = "invite.failed"
        static let startOver = "invite.startOver"
        static let fullCode = "invite.fullCode"
        static let account = "invite.account"
        static let lookUp = "invite.lookUp"
        static let ownSafetyNumber = "invite.ownSafetyNumber"
        static let typedNumber = "invite.typedNumber"
        static let confirm = "invite.confirm"
        static let role = "invite.role"
        static let invitee = "invite.invitee"
        static let send = "invite.send"
        static let sent = "invite.sent"
        static let code = "invite.code"
        static let copy = "invite.copy"
        static let done = "invite.done"
        static let uiTestFill = "debug.inviteFill"
    }

    enum Accept {
        static let number = "accept.number"
        static let joinWithNumber = "accept.joinWithNumber"
        static let scan = "accept.scan"
        static let waiting = "accept.waiting"
        static let ownCode = "accept.ownCode"
        static let typedCode = "accept.typedCode"
        static let confirmCode = "accept.confirmCode"
        static let awaitingInvitation = "accept.awaitingInvitation"
        static let scannedAccount = "accept.scannedAccount"
        static let confirmScan = "accept.confirmScan"
        static let ownerNotVerified = "accept.ownerNotVerified"
        static let checkOwner = "accept.checkOwner"
        static let useNewKeys = "accept.useNewKeys"
        static let failed = "accept.failed"
        static let startOver = "accept.startOver"
        static let fullCode = "accept.fullCode"
        static let code = "accept.code"
        static let read = "accept.read"
        static let ownSafetyNumber = "accept.ownSafetyNumber"
        static let typedNumber = "accept.typedNumber"
        static let join = "accept.join"
        static let confirmText = "accept.confirmText"
        static let joined = "accept.joined"
        static let done = "accept.done"
    }

    /// Checking a member of a shared vault with a vault sharing code session (`MemberVerificationView`).
    enum MemberCheck {
        static let notListed = "memberCheck.notListed"
        static let start = "memberCheck.start"
        static let number = "memberCheck.number"
        static let typedCode = "memberCheck.typedCode"
        static let confirm = "memberCheck.confirm"
        static let scan = "memberCheck.scan"
        static let ownCode = "memberCheck.ownCode"
        static let verified = "memberCheck.verified"
        static let useNewKeys = "memberCheck.useNewKeys"
        static let failed = "memberCheck.failed"
    }

    /// The camera scanner (`CodeScannerView`, iPhone and iPad).
    enum Scanner {
        static let view = "scanner.view"
        static let unavailable = "scanner.unavailable"
        static let cancel = "scanner.cancel"
    }

    enum Devices {
        static let list = "devices.list"
        static let syncNow = "devices.syncNow"
        static let syncStatus = "devices.syncStatus"
        static let uploadAgain = "devices.uploadAgain"
        static let thisDevice = "devices.thisDevice"
        static let notice = "devices.notice"
        static func row(_ name: String) -> String { "devices.row.\(name)" }
        static func revoke(_ name: String) -> String { "devices.revoke.\(name)" }
        static let changePassword = "revoke.changePassword"
        static let current = "revoke.current"
        static let new = "revoke.new"
        static let confirmation = "revoke.confirmation"
        static let wasLocked = "revoke.wasLocked"
        static let passwordUnknown = "revoke.passwordUnknown"
        static let confirm = "revoke.confirm"
        static let cancel = "revoke.cancel"
    }

    enum Quarantine {
        static let list = "quarantine.list"
        static let empty = "quarantine.empty"
        static func row(_ index: Int) -> String { "quarantine.row.\(index)" }
        static func discard(_ index: Int) -> String { "quarantine.discard.\(index)" }
        static let discardConfirm = "quarantine.discardConfirm"
    }

    enum Hygiene {
        static let list = "hygiene.list"
        static let checkNow = "hygiene.checkNow"
        static let status = "hygiene.status"
        static let unavailable = "hygiene.unavailable"
        static func section(_ kind: String) -> String { "hygiene.section.\(kind)" }
        static func row(_ kind: String, _ title: String) -> String { "hygiene.\(kind).\(title)" }
    }

    enum Import {
        static let vault = "import.vault"
        static let format = "import.format"
        static let chooseFile = "import.chooseFile"
        static let uiTestSample = "debug.importSample"
        static let entries = "import.entries"
        static let report = "import.report"
        static let commit = "import.commit"
        static let cancel = "import.cancel"
        static let summary = "import.summary"
        static let done = "import.done"
        static let archiveDate = "import.archiveDate"
        static let passphrase = "restore.passphrase"
        static let secretKey = "restore.secretKey"
        static let uiTestArchive = "debug.restoreArchive"
        static func duplicate(_ title: String) -> String { "import.duplicate.\(title)" }
        static func choice(_ title: String) -> String { "import.choice.\(title)" }
        static func host(_ host: String) -> String { "merge.host.\(host)" }
        static func hostWarning(_ host: String) -> String { "merge.hostWarning.\(host)" }
        static let hostConfirm = "merge.hostConfirm"
        static func field(_ label: String) -> String { "merge.field.\(label)" }
        static func reveal(_ label: String) -> String { "merge.reveal.\(label)" }
    }

    enum Export {
        static let warning = "export.warning"
        static let kind = "export.kind"
        static let password = "export.password"
        static let passphrase = "export.passphrase"
        static let passphraseConfirmation = "export.passphraseConfirmation"
        static let run = "export.run"
        static let report = "export.report"
        static let count = "export.count"
        static let save = "export.save"
        static func vault(_ name: String) -> String { "export.vault.\(name)" }
    }

    enum Unlock {
        static let passwordChanged = "unlock.passwordChanged"
        static let ignoreChange = "unlock.ignoreChange"
    }

    enum Debug {
        static let peerJoin = "debug.peerJoin"
        static let peerPassword = "debug.peerPassword"
        static let peerImplausible = "debug.peerImplausible"
        static let householdAccept = "debug.householdAccept"
        /// Stand-ins for the other person at a vault sharing code session (`UITestPeer`): they type what this screen
        /// shows, read out what theirs shows, scan this screen, or are scanned.
        static let memberJoins = "debug.memberJoins"
        static let fillMemberCode = "debug.fillMemberCode"
        static let scanMember = "debug.scanMember"
        static let memberTypes = "debug.memberTypes"
        static let memberAcceptsSession = "debug.memberAcceptsSession"
        static let memberStarts = "debug.memberStarts"
        static let memberInvites = "debug.memberInvites"
        static let lockNow = "debug.lockNow"
    }
}
