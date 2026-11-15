import Foundation
import WatchwordModel

/// 1Password Unencrypted Export (1PUX), in and out (PRD F8.1, F8.4; docs/02-architecture.md §14).
///
/// A `.1pux` file is a ZIP archive whose `export.data` member is JSON: `accounts[].vaults[].items[]`, each item
/// with an `overview` (title, URLs, tags) and `details` (login fields, sections of typed fields, notes, password
/// history). The import reads that one member through `ZIPArchive` and walks it without holding the document: one
/// item is materialised at a time, and an item larger than `maximumEntryBytes` is skipped, not parsed.
///
/// Every category imports. Login, Password, Secure Note, API Credential, Bank Account and Membership keep their
/// shape (the fields 1Password gives those categories map to the matching Watchword field kinds); every other
/// category becomes an item of custom fields, typed by each field's value type. Nothing is dropped without a line
/// in the report, with one exception stated here: the checkbox, radio-button and button entries of a saved web
/// form, which are a page's state and not account data.
public enum OnePUX {
    public static let dataEntryName = "export.data"
    public static let attributesEntryName = "export.attributes"

    /// 1Password's category identifiers for the six categories with a shape of their own.
    private static let categories: [String: ImportedKind] = [
        "001": .login, "003": .secureNote, "005": .password, "101": .bankAccount, "105": .membership,
        "112": .apiCredential,
    ]

    /// Field identifiers 1Password's templates use, and the Watchword kind each means. Applied only when the
    /// field's own type agrees about secrecy: a concealed `accountNo` stays concealed.
    private static let wellKnownFields: [String: FieldKind] = [
        "username": .username, "password": .password, "credential": .apiKey, "pin": .pin, "telephonePin": .pin,
        "accountNo": .accountNumber, "routingNo": .accountNumber, "iban": .accountNumber, "swift": .accountNumber,
        "membership_no": .accountNumber,
    ]
    private static let bankFieldIDs: Set<String> = ["accountNo", "routingNo", "iban", "swift"]
    private static let loginFieldType = "loginField"
    private static let longestKeptIdentifier = 128

    // MARK: Import

    /// Imports a `.1pux` archive as item drafts for `vaultID`.
    public static func importArchive(
        _ archive: [UInt8], into vaultID: UUID, limits: InterchangeLimits = .standard,
        options: ImportOptions = ImportOptions(), using generator: inout some RandomNumberGenerator
    ) throws -> ImportResult {
        let document = try ZIPArchive(archive, limits: limits).contents(of: dataEntryName)
        return try importDocument(document, into: vaultID, limits: limits, options: options, using: &generator)
    }

    /// Imports the JSON of an archive's `export.data` member.
    public static func importDocument(
        _ document: [UInt8], into vaultID: UUID, limits: InterchangeLimits = .standard,
        options: ImportOptions = ImportOptions(), using generator: inout some RandomNumberGenerator
    ) throws -> ImportResult {
        guard document.count <= limits.maximumDocumentBytes else { throw limits.exceeded(.documentBytes) }
        let range = try UTF8Text.validatedRange(of: document)
        var reader = JSONReader(bytes: document, range: range, limits: limits)
        var assembler = ImportAssembler(format: .onePUX, vaultID: vaultID, limits: limits, options: options)
        var sawAccounts = false

        try reader.readObject(path: "$") { key, reader in
            guard key == "accounts" else { return }
            sawAccounts = true
            try reader.readArray(path: "accounts") { reader in
                try assembler.visit()
                try reader.readObject(path: "accounts[]") { key, reader in
                    guard key == "vaults" else { return }
                    try reader.readArray(path: "accounts[].vaults") { reader in
                        try assembler.visit()
                        let mark = assembler.mark
                        var vaultName: String?
                        try reader.readObject(path: "accounts[].vaults[]") { key, reader in
                            switch key {
                            case "attrs":
                                vaultName = try reader.readBoundedValue()?.object?.string("name")
                            case "items":
                                try reader.readArray(path: "accounts[].vaults[].items") { reader in
                                    let index = try assembler.beginEntry()
                                    let reference = ImportEntryReference(index: index)
                                    guard let value = try reader.readBoundedValue() else {
                                        assembler.skip(
                                            reference, .tooLarge(.entryBytes, limit: limits.maximumEntryBytes))
                                        return
                                    }
                                    guard let item = value.object else {
                                        assembler.skip(reference, .malformed(path: "items[]"))
                                        return
                                    }
                                    assembler.add(record(from: item, reference: reference), using: &generator)
                                }
                            default:
                                break
                            }
                        }
                        if let vaultName, vaultName.utf8.count <= limits.maximumFieldBytes {
                            assembler.setContainer(vaultName, since: mark)
                        }
                    }
                }
            }
        }
        try reader.finish()
        guard sawAccounts else { throw InterchangeError.unexpectedStructure(path: "accounts") }
        return assembler.result
    }

    private static func record(from item: JSONObject, reference: ImportEntryReference) -> SourceRecord {
        let overview = item.object("overview") ?? JSONObject()
        let details = item.object("details") ?? JSONObject()
        var reference = reference
        reference.sourceID = item.string("uuid")
        reference.title = overview.string("title") ?? ""
        var record = SourceRecord(
            reference: reference, kind: categories[item.string("categoryUuid") ?? ""] ?? .other,
            title: reference.title)

        if let state = item.string("state") {
            switch state {
            case "active": record.state = .active
            case "archived": record.state = .archived
            case "trashed", "deleted": record.state = .trashed
            default: record.warnings.append(.unknownState(state))
            }
        }
        if item.bool("trashed") == true { record.state = .trashed }
        record.favorite = (item.integer("favIndex") ?? 0) != 0
        record.createdAt = date(item, "createdAt", into: &record)
        record.modifiedAt = date(item, "updatedAt", into: &record)

        if let url = overview.string("url"), !url.isEmpty { record.urls.append(url) }
        // Repeats are dropped where the URLs become scopes and fields.
        for entry in overview.array("urls") ?? [] {
            if let url = entry.object?.string("url"), !url.isEmpty { record.urls.append(url) }
        }
        record.tags = (overview.array("tags") ?? []).compactMap(\.string)
        record.notes = details.string("notesPlain") ?? ""

        for entry in details.array("loginFields") ?? [] {
            guard let field = entry.object, let value = text(field["value"]), !value.isEmpty else { continue }
            let name = field.string("name") ?? ""
            switch field.string("designation") {
            case "username":
                record.fields.append(SourceField(kind: .plain(.username), label: "Username", value: value))
            case "password":
                record.fields.append(SourceField(kind: .plain(.password), label: "Password", value: value))
            default:
                let kind: FieldKind
                switch field.string("fieldType") ?? "T" {
                case "T", "N": kind = .text
                case "E": kind = .email
                case "U": kind = .url
                case "TEL": kind = .phoneNumber
                case "P": kind = .custom
                // Checkboxes, radio buttons and buttons of a saved web form: page state, not account data.
                default: continue
                }
                record.fields.append(
                    SourceField(
                        kind: .plain(kind), label: name.isEmpty ? "Web form field" : name, value: value,
                        meta: [InterchangeMeta.sourceType: loginFieldType]))
            }
        }
        // The Password category keeps its one value outside the sections.
        if let password = details.string("password"), !password.isEmpty {
            record.fields.append(SourceField(kind: .plain(.password), label: "Password", value: password))
        }
        for entry in details.array("sections") ?? [] {
            guard let section = entry.object else { continue }
            let title = section.string("title") ?? ""
            for entry in section.array("fields") ?? [] {
                guard let field = entry.object, let values = field.object("value") else { continue }
                // Looked up once, outside the loop: a lookup is a scan of the object, and a field with thousands
                // of members and thousands of values would otherwise cost their product.
                let label = field.string("title") ?? ""
                let identifier = field.string("id") ?? ""
                for member in values.members {
                    appendField(
                        type: member.key, value: member.value, label: label, identifier: identifier, section: title,
                        to: &record)
                }
            }
        }
        for entry in details.array("passwordHistory") ?? [] {
            guard let past = entry.object, let value = past.string("value") else { continue }
            record.pastPasswords.append(
                SourcePassword(value: value, replacedAt: ImportAssembler.date(seconds: past.integer("time"))))
        }
        if let document = details.object("documentAttributes") {
            record.warnings.append(.attachmentNotImported(name: document.string("fileName") ?? ""))
            record.hadUnimportableContent = true
        }
        return record
    }

    private static func date(_ item: JSONObject, _ key: String, into record: inout SourceRecord) -> Date? {
        guard let seconds = item.integer(key) else { return nil }
        guard let date = ImportAssembler.date(seconds: seconds) else {
            record.warnings.append(.implausibleDate(label: key))
            return nil
        }
        return date
    }

    /// The text of a value that should be text: a string, or an integer written without quotes.
    private static func text(_ value: JSONValue?) -> String? {
        switch value {
        case .string(let text): return text
        case .integer(let number): return String(number)
        default: return nil
        }
    }

    /// Maps one typed value of a section field (`{"concealed": "…"}`, `{"date": 1700000000}`, …).
    private static func appendField(
        type: String, value: JSONValue, label: String, identifier: String, section: String,
        to record: inout SourceRecord
    ) {
        var meta = [InterchangeMeta.sourceType: type]
        if !section.isEmpty { meta[InterchangeMeta.section] = section }
        if !identifier.isEmpty, identifier.utf8.count <= longestKeptIdentifier {
            meta[InterchangeMeta.sourceID] = identifier
        }
        let label = label.isEmpty ? (identifier.isEmpty ? "Field" : identifier) : label
        func add(_ kind: FieldKind, _ value: String?) {
            guard let value, !value.isEmpty else { return }
            record.fields.append(SourceField(kind: .plain(kind), label: label, value: value, meta: meta))
        }
        func wellKnown(secret: Bool, otherwise kind: FieldKind) -> FieldKind {
            guard let known = wellKnownFields[identifier], known.isSecret == secret else { return kind }
            return known
        }

        switch type {
        case "string":
            add(wellKnown(secret: false, otherwise: .text), text(value))
        case "concealed":
            add(wellKnown(secret: true, otherwise: .custom), text(value))
        case "totp":
            if let secret = text(value), !secret.isEmpty {
                record.fields.append(SourceField(kind: .oneTimePassword, label: label, value: secret, meta: meta))
            }
        case "url":
            add(.url, text(value))
        case "email":
            add(.email, text(value) ?? value.object?.string("email_address"))
        case "phone":
            add(.phoneNumber, text(value))
        case "date":
            guard let seconds = value.integer else { return }
            if ImportAssembler.date(seconds: seconds) != nil {
                add(.date, CivilDate.string(seconds: seconds))
            } else {
                record.warnings.append(.implausibleDate(label: label))
            }
        case "monthYear":
            guard let number = value.integer else { return }
            if let text = CivilDate.string(monthYear: number) {
                add(.date, text)
            } else {
                record.warnings.append(.implausibleDate(label: label))
            }
        case "creditCardNumber":
            add(.custom, text(value))
        case "creditCardType", "gender", "menu":
            add(.text, text(value))
        case "address":
            guard let address = value.object else { return }
            let lines = ["street", "city", "state", "zip", "country"].compactMap { address.string($0) }
            add(.text, lines.filter { !$0.isEmpty }.joined(separator: "\n"))
        case "sshKey":
            guard let key = value.object else { return }
            add(.custom, key.string("privateKey"))
            if let publicKey = key.object("metadata")?.string("publicKey"), !publicKey.isEmpty {
                record.fields.append(
                    SourceField(kind: .plain(.text), label: label + " (public key)", value: publicKey, meta: meta))
            }
        case "reference":
            if !value.isNull {
                record.warnings.append(.linkedItemNotImported(label: label))
                record.hadUnimportableContent = true
            }
        case "file":
            if let file = value.object {
                record.warnings.append(.attachmentNotImported(name: file.string("fileName") ?? label))
                record.hadUnimportableContent = true
            }
        default:
            guard !value.isNull else { return }
            record.warnings.append(.unsupportedFieldType(label: label, type: type))
            if let text = text(value), !text.isEmpty {
                add(.custom, text)
            } else {
                record.hadUnimportableContent = true
            }
        }
    }

    // MARK: Export

    public struct ExportOptions: Hashable, Sendable {
        /// Shown by 1Password as the account the data came from.
        public var accountName: String
        public var accountEmail: String
        public var accountID: UUID
        public var vaultName: String
        public var vaultID: UUID
        /// The export's own timestamp, injected.
        public var createdAt: Date
        /// Items carrying this tag are marked as favourites.
        public var favoriteTag: String?

        public init(
            accountName: String = "Watchword", accountEmail: String = "", accountID: UUID,
            vaultName: String = "Watchword", vaultID: UUID, createdAt: Date, favoriteTag: String? = "Favorite"
        ) {
            self.accountName = accountName
            self.accountEmail = accountEmail
            self.accountID = accountID
            self.vaultName = vaultName
            self.vaultID = vaultID
            self.createdAt = createdAt
            self.favoriteTag = favoriteTag
        }
    }

    /// Exports `items` as a `.1pux` archive that 1Password's importer reads (PRD F8.4): `export.attributes` and
    /// `export.data`, stored uncompressed. The bytes are plaintext (`ExportResult`).
    ///
    /// A passkey has no place in the format and is left out, with a warning; trashed items are left out likewise.
    public static func exportArchive(
        _ items: [Item], options: ExportOptions, limits: InterchangeLimits = .standard
    ) throws -> ExportResult {
        let (document, report) = exportDocument(items, options: options)
        var attributes = JSONObject()
        attributes.append("version", .integer(3))
        attributes.append("description", .string("1Password Unencrypted Export"))
        attributes.append("createdAt", .integer(seconds(options.createdAt)))
        let archive = try ZIPWriter.archive(
            [
                ZIPWriter.Member(name: attributesEntryName, contents: JSONWriter.encode(.object(attributes))),
                ZIPWriter.Member(name: dataEntryName, contents: document),
            ], limits: limits)
        return ExportResult(bytes: archive, report: report)
    }

    /// The JSON of `export.data` for `items`.
    public static func exportDocument(_ items: [Item], options: ExportOptions) -> (
        document: [UInt8], report: ExportReport
    ) {
        var report = ExportReport()
        var exported: [JSONValue] = []
        for item in items {
            guard !item.isTrashed else {
                report.warnings.append(.trashedItemOmitted(itemID: item.id))
                continue
            }
            exported.append(.object(export(item, options: options, report: &report)))
            report.exportedCount += 1
        }
        var accountAttributes = JSONObject()
        accountAttributes.append("accountName", .string(options.accountName))
        accountAttributes.append("name", .string(options.accountName))
        accountAttributes.append("avatar", .string(""))
        accountAttributes.append("email", .string(options.accountEmail))
        accountAttributes.append("uuid", .string(identifier(options.accountID)))
        accountAttributes.append("domain", .string("https://my.1password.com/"))
        var vaultAttributes = JSONObject()
        vaultAttributes.append("uuid", .string(identifier(options.vaultID)))
        vaultAttributes.append("desc", .string(""))
        vaultAttributes.append("avatar", .string(""))
        vaultAttributes.append("name", .string(options.vaultName))
        vaultAttributes.append("type", .string("U"))
        let vault = JSONObject([("attrs", .object(vaultAttributes)), ("items", .array(exported))])
        let account = JSONObject([("attrs", .object(accountAttributes)), ("vaults", .array([.object(vault)]))])
        let root = JSONObject([("accounts", .array([.object(account)]))])
        return (JSONWriter.encode(.object(root)), report)
    }

    private static func seconds(_ date: Date) -> Int64 {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0, seconds <= Double(ImportAssembler.latestPlausibleTimestamp) else {
            return 0
        }
        return Int64(seconds)
    }

    /// 1Password writes identifiers as 26 lower-case Base32 characters, which is what 16 bytes come to.
    private static func identifier(_ uuid: UUID) -> String {
        Base32.encode(RandomUUID.bytes(of: uuid)).lowercased()
    }

    /// The category an item is exported as. Watchword items carry no category, so it is read off the fields.
    static func category(for item: Item) -> String {
        let kinds = Set(item.fields.map(\.kind))
        let identifiers = Set(item.fields.compactMap { $0.meta[InterchangeMeta.sourceID] })
        let websites = item.fields.contains { $0.meta[InterchangeMeta.sourceType] == InterchangeMeta.websiteType }
        let hasSite = !item.scopes.isEmpty || websites
        let hasLogin = kinds.contains(.password) || kinds.contains(.passkey) || kinds.contains(.totp)
        if item.fields.isEmpty, !hasSite { return "003" }
        if kinds.contains(.apiKey), !hasLogin { return "112" }
        if !hasLogin, !hasSite, !identifiers.isDisjoint(with: bankFieldIDs) { return "101" }
        if !hasLogin, !hasSite, kinds.contains(.accountNumber) { return "105" }
        if kinds == [.password], !hasSite { return "005" }
        return "001"
    }

    private static func export(_ item: Item, options: ExportOptions, report: inout ExportReport) -> JSONObject {
        let category = category(for: item)
        let isLogin = category == "001"
        let username = isLogin ? item.fields.first { $0.kind == .username } : nil
        let password = isLogin || category == "005" ? item.field(.password) : nil

        var urls = item.scopes.map { "https://\($0.host)/" }
        var loginFields: [JSONValue] = []
        if let username { loginFields.append(loginField(username, designation: "username", type: "T")) }
        if let password, isLogin { loginFields.append(loginField(password, designation: "password", type: "P")) }

        var sections: [(title: String, fields: [JSONValue])] = []
        // An item may come from another member of a shared vault, so even an export avoids quadratic searches.
        var sectionIndex: [String: Int] = [:]
        var usedIdentifiers = Set<String>()
        for field in item.fields where field.id != username?.id && field.id != password?.id {
            let sourceType = field.meta[InterchangeMeta.sourceType]
            if field.kind == .url, sourceType == InterchangeMeta.websiteType {
                urls.append(field.value)
                continue
            }
            if sourceType == loginFieldType, isLogin {
                let type: String
                switch field.kind {
                case .email: type = "E"
                case .url: type = "U"
                case .phoneNumber: type = "TEL"
                case .custom: type = "P"
                default: type = "T"
                }
                loginFields.append(loginField(field, designation: "", type: type))
                continue
            }
            guard let value = typedValue(of: field, itemID: item.id, report: &report) else { continue }
            var identifier = field.meta[InterchangeMeta.sourceID] ?? defaultIdentifier(for: field.kind, in: category)
            if identifier.isEmpty || !usedIdentifiers.insert(identifier).inserted {
                identifier = field.id.uuidString.replacingOccurrences(of: "-", with: "")
                usedIdentifiers.insert(identifier)
            }
            var exported = JSONObject()
            exported.append("title", .string(field.label))
            exported.append("id", .string(identifier))
            exported.append("value", .object(value))
            exported.append("guarded", .bool(false))
            exported.append("multiline", .bool(field.value.unicodeScalars.contains { $0 == "\n" }))
            exported.append("dontGenerate", .bool(false))
            exported.append(
                "inputTraits",
                .object(
                    JSONObject([
                        ("keyboard", .string("default")), ("correction", .string("default")),
                        ("capitalization", .string("default")),
                    ])))
            let title = field.meta[InterchangeMeta.section] ?? ""
            if let index = sectionIndex[title] {
                sections[index].fields.append(.object(exported))
            } else {
                sectionIndex[title] = sections.count
                sections.append((title, [.object(exported)]))
            }
        }

        var details = JSONObject()
        details.append("loginFields", .array(loginFields))
        if category == "005", let password { details.append("password", .string(password.value)) }
        details.append("notesPlain", .string(item.notes))
        details.append(
            "sections",
            .array(
                sections.enumerated().map { index, section in
                    .object(
                        JSONObject([
                            ("title", .string(section.title)), ("name", .string("Section_\(index + 1)")),
                            ("fields", .array(section.fields)),
                        ]))
                }))
        var history: [JSONValue] = []
        var previous = item.field(.password)?.value
        for entry in item.history {
            guard let value = entry.fields.first(where: { $0.kind == .password })?.value, value != previous else {
                continue
            }
            previous = value
            history.append(
                .object(JSONObject([("value", .string(value)), ("time", .integer(seconds(entry.replacedAt)))])))
        }
        details.append("passwordHistory", .array(history))

        var overview = JSONObject()
        overview.append("subtitle", .string(username?.value ?? ""))
        overview.append(
            "urls",
            .array(urls.map { .object(JSONObject([("label", .string("website")), ("url", .string($0))])) }))
        overview.append("title", .string(item.title))
        overview.append("url", .string(urls.first ?? ""))
        overview.append("tags", .array(item.tags.sorted().map { .string($0) }))

        var exported = JSONObject()
        exported.append("uuid", .string(identifier(item.id)))
        let isFavorite = options.favoriteTag.map { item.tags.contains($0) } ?? false
        exported.append("favIndex", .integer(isFavorite ? 1 : 0))
        exported.append("createdAt", .integer(seconds(item.createdAt)))
        exported.append("updatedAt", .integer(seconds(item.modifiedAt)))
        exported.append("state", .string(item.archived ? "archived" : "active"))
        exported.append("categoryUuid", .string(category))
        exported.append("details", .object(details))
        exported.append("overview", .object(overview))
        return exported
    }

    private static func loginField(_ field: Field, designation: String, type: String) -> JSONValue {
        .object(
            JSONObject([
                ("value", .string(field.value)), ("id", .string("")),
                ("name", .string(designation.isEmpty ? field.label : designation)), ("fieldType", .string(type)),
                ("designation", .string(designation)),
            ]))
    }

    /// The identifier 1Password's own template gives a field of this kind, so the first such field lands where
    /// 1Password expects it.
    private static func defaultIdentifier(for kind: FieldKind, in category: String) -> String {
        switch kind {
        case .username: return "username"
        case .password: return "password"
        case .apiKey: return "credential"
        case .pin: return category == "101" ? "telephonePin" : "pin"
        case .accountNumber: return category == "105" ? "membership_no" : (category == "101" ? "accountNo" : "")
        default: return ""
        }
    }

    /// A field's value as 1PUX types it, or `nil` for a field the format cannot carry (reported).
    private static func typedValue(of field: Field, itemID: UUID, report: inout ExportReport) -> JSONObject? {
        let sourceType = field.meta[InterchangeMeta.sourceType]
        func value(_ type: String, _ value: JSONValue) -> JSONObject { JSONObject([(type, value)]) }
        switch field.kind {
        case .passkey:
            report.warnings.append(.passkeyOmitted(itemID: itemID))
            return nil
        case .totp:
            guard (try? field.otpParameters()) != nil else {
                report.warnings.append(.oneTimePasswordUnusable(itemID: itemID))
                return value("concealed", .string(field.value))
            }
            return value("totp", .string(field.value))
        case .password, .apiKey, .pin, .securityQuestion, .recoveryCodes:
            return value("concealed", .string(field.value))
        case .custom:
            return value(sourceType == "creditCardNumber" ? "creditCardNumber" : "concealed", .string(field.value))
        case .username, .text, .accountNumber:
            let type = ["creditCardType", "gender", "menu"].contains(sourceType ?? "") ? sourceType! : "string"
            return value(type, .string(field.value))
        case .email:
            return value(
                "email",
                .object(JSONObject([("email_address", .string(field.value)), ("provider", .null)])))
        case .url:
            return value("url", .string(field.value))
        case .phoneNumber:
            return value("phone", .string(field.value))
        case .date:
            if let seconds = CivilDate.seconds(fromDate: field.value) { return value("date", .integer(seconds)) }
            if let number = CivilDate.monthYear(from: field.value) { return value("monthYear", .integer(number)) }
            return value("string", .string(field.value))
        }
    }
}
