import Foundation
import WatchwordModel

/// The FIDO Credential Exchange Format (CXF) 1.0, in and out (PRD F8.3, F8.4; docs/02-architecture.md §14).
///
/// This is the JSON the OS Credential Exchange APIs carry between apps on iOS 26 and macOS 26, and equally a file
/// that can be moved by hand. Either way it arrives from another program and is read as hostile (adversary A7):
/// walked one item at a time under the same limits as every other import, with nothing in it trusted for an
/// identity, a scope or a size.
///
/// Read and written: `basic-auth`, `passkey`, `totp`, `api-key`, `note` and `custom-fields` credentials. Security
/// questions, PINs, recovery codes and every other Watchword field without a credential type of its own are
/// written as `custom-fields`. A credential of any other type is tolerated: its text is kept as custom fields and
/// the report names the type. An item whose identifier repeats an earlier one is skipped and reported, and binary
/// values beyond a passkey's bounds refuse that passkey alone, with a warning.
public enum CredentialExchange {
    /// The major version this module reads and writes.
    public static let majorVersion: Int64 = 1

    private static let passkeyLabel = "Passkey"
    private static let apiKeyType = "api-key"
    /// The members of an `api-key` credential besides the key and the user name, and the field type of each.
    private static let apiKeyMembers = [
        "keyType": "string", "url": "string", "validFrom": "date", "expiryDate": "date",
    ]

    // MARK: Import

    /// Imports a CXF document as item drafts for `vaultID`.
    public static func importDocument(
        _ document: [UInt8], into vaultID: UUID, limits: InterchangeLimits = .standard,
        options: ImportOptions = ImportOptions(), using generator: inout some RandomNumberGenerator
    ) throws -> ImportResult {
        try limits.checkInput(document.count)
        let range = try UTF8Text.validatedRange(of: document)
        var reader = JSONReader(bytes: document, range: range, limits: limits)
        var assembler = ImportAssembler(
            format: .credentialExchange, vaultID: vaultID, limits: limits, options: options)
        var version: JSONValue?
        var sawAccounts = false

        try reader.readObject(path: "$") { key, reader in
            switch key {
            case "version":
                version = try reader.readBoundedValue()
            case "accounts":
                sawAccounts = true
                try reader.readArray(path: "accounts") { reader in
                    try assembler.visit()
                    let mark = assembler.mark
                    var accountName: String?
                    var collectionTags: [String: [String]] = [:]
                    try reader.readObject(path: "accounts[]") { key, reader in
                        switch key {
                        case "collections":
                            // Collections are the source's folders: each becomes a tag on the items it lists. One
                            // larger than an entry may be is passed over, as an item would be.
                            for collection in try reader.readBoundedValue()?.array ?? [] {
                                collect(collection, path: "", into: &collectionTags)
                            }
                        case "username", "email":
                            if let name = try reader.readBoundedValue()?.string, !name.isEmpty {
                                accountName = accountName ?? name
                            }
                        case "items":
                            try reader.readArray(path: "accounts[].items") { reader in
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
                                guard let credentials = item.array("credentials") else {
                                    var reference = reference
                                    reference.title = item.string("title") ?? ""
                                    reference.sourceID = item.string("id")
                                    assembler.skip(reference, .malformed(path: "items[].credentials"))
                                    return
                                }
                                try assembler.add(
                                    record(from: item, credentials: credentials, reference: reference, limits: limits),
                                    using: &generator)
                            }
                        default:
                            break
                        }
                    }
                    try assembler.addTags(collectionTags, since: mark)
                    if let accountName, accountName.utf8.count <= limits.maximumFieldBytes {
                        assembler.setContainer(accountName, since: mark)
                    }
                }
            default:
                break
            }
        }
        try reader.finish()
        // A JSON object's members come in any order, so the version is judged once the whole document is read; a
        // document of another major version yields nothing, whatever was walked on the way.
        guard let versionObject = version?.object, let major = versionObject.integer("major"),
            let minor = versionObject.integer("minor")
        else { throw InterchangeError.unexpectedStructure(path: "version") }
        guard major == majorVersion, (0...255).contains(minor) else {
            throw InterchangeError.unsupportedVersion("\(major).\(minor)")
        }
        guard sawAccounts else { throw InterchangeError.unexpectedStructure(path: "accounts") }
        return assembler.result
    }

    /// The most collection tags one item takes: a file can list an item in any number of collections.
    private static let maximumCollectionTags = 32
    /// The longest collection path that becomes a tag. A longer one, and everything inside it, is passed over.
    private static let maximumCollectionPathBytes = 1_024

    /// Records, for each item a collection (or a collection inside it) lists, the collection's path as a tag.
    private static func collect(_ value: JSONValue, path: String, into tags: inout [String: [String]]) {
        guard let collection = value.object, let title = collection.string("title"), !title.isEmpty else { return }
        // Checked before the path is built: every collection under a long path would otherwise carry its own copy
        // of it, and a few hundred kilobytes of nesting would become gigabytes of names.
        guard path.utf8.count + title.utf8.count < maximumCollectionPathBytes else { return }
        let name = path.isEmpty ? title : path + "/" + title
        for entry in collection.array("items") ?? [] {
            guard let identifier = entry.object?.string("item") else { continue }
            if tags[identifier, default: []].count < maximumCollectionTags {
                tags[identifier, default: []].append(name)
            }
        }
        for inner in collection.array("subCollections") ?? [] {
            collect(inner, path: name, into: &tags)
        }
    }

    private static func record(
        from item: JSONObject, credentials: [JSONValue], reference: ImportEntryReference, limits: InterchangeLimits
    ) -> SourceRecord {
        var reference = reference
        reference.sourceID = item.string("id")
        reference.title = item.string("title") ?? ""
        var record = SourceRecord(reference: reference, kind: .other, title: reference.title)
        record.favorite = item.bool("favorite") ?? false
        record.tags = (item.array("tags") ?? []).compactMap(\.string)
        record.createdAt = date(item, "creationAt", into: &record)
        record.modifiedAt = date(item, "modifiedAt", into: &record)
        record.urls = (item.object("scope")?.array("urls") ?? []).compactMap(\.string)
        // Android apps a credential belongs to have no place in an item, and are not passed over in silence.
        if let apps = item.object("scope")?.array("androidApps"), !apps.isEmpty {
            record.warnings.append(.androidAppsNotImported(count: apps.count))
        }

        var types = Set<String>()
        for entry in credentials {
            guard let credential = entry.object, let type = credential.string("type") else {
                record.hadUnimportableContent = true
                continue
            }
            types.insert(type)
            switch type {
            case "basic-auth":
                // Earlier drafts of the format kept a login's URLs here; they are honoured as URLs, not trusted more.
                record.urls += (credential.array("urls") ?? []).compactMap(\.string)
                if let username = editable(credential["username"], named: "Username", in: &record) {
                    let kind: FieldKind = username.type == "email" ? .email : .username
                    record.fields.append(
                        SourceField(kind: .plain(kind), label: username.label ?? "Username", value: username.value))
                }
                if let password = editable(credential["password"], named: "Password", in: &record) {
                    record.fields.append(
                        SourceField(kind: .plain(.password), label: password.label ?? "Password", value: password.value)
                    )
                }
            case "totp":
                appendOneTimePassword(credential, to: &record)
            case "passkey":
                appendPasskey(credential, createdAt: record.createdAt, to: &record)
            case "api-key":
                let members: [(String, FieldKind, String)] = [
                    ("key", .apiKey, "API key"), ("username", .username, "Username"), ("keyType", .text, "Key type"),
                    ("url", .url, "URL"), ("validFrom", .date, "Valid from"), ("expiryDate", .date, "Expires"),
                ]
                for (member, kind, label) in members {
                    guard let field = editable(credential[member], named: label, in: &record) else { continue }
                    // The member's name is kept, so an export can put the value back where it was.
                    let meta =
                        member == "key"
                        ? [:] : [InterchangeMeta.sourceType: apiKeyType, InterchangeMeta.sourceID: member]
                    record.fields.append(
                        SourceField(kind: .plain(kind), label: field.label ?? label, value: field.value, meta: meta))
                }
            case "note":
                guard let content = editable(credential["content"], named: "Note", in: &record) else { continue }
                record.notes += (record.notes.isEmpty ? "" : "\n\n") + content.value
            case "custom-fields":
                let section = credential.string("label") ?? ""
                for entry in credential.array("fields") ?? [] {
                    guard let field = editable(entry, named: "Field", in: &record) else { continue }
                    record.fields.append(customField(field, label: field.label ?? "Field", section: section))
                }
            default:
                appendUnknown(credential, type: type, to: &record)
            }
        }
        // A subtitle is kept when it says something the title and the fields do not: most exporters fill it with the
        // user name, and that is already here.
        if let subtitle = item.string("subtitle"), !subtitle.isEmpty, subtitle != record.title,
            !record.fields.contains(where: { $0.value == subtitle })
        {
            record.fields.append(
                SourceField(
                    kind: .plain(.text), label: "Subtitle", value: subtitle,
                    meta: [InterchangeMeta.sourceType: InterchangeMeta.subtitleType]))
        }
        if types.contains("basic-auth") {
            record.kind = .login
        } else if types.contains("passkey") {
            record.kind = .passkey
        } else if types.contains("totp") {
            record.kind = .oneTimePassword
        } else if types.contains("api-key") {
            record.kind = .apiCredential
        } else if types == ["note"] {
            record.kind = .secureNote
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

    /// An `EditableField`: `{"fieldType": …, "value": …, "label": …}`. `nil` unless it is an object whose value has
    /// text: a string, or a number or boolean written without quotes (a `number` or `boolean` field may be).
    private static func editable(_ value: JSONValue?) -> (type: String, value: String, label: String?)? {
        guard let field = value?.object, let text = field["value"]?.scalarText else { return nil }
        let label = field.string("label").flatMap { $0.isEmpty ? nil : $0 }
        return (field.string("fieldType") ?? "string", text, label)
    }

    /// `editable`, with a line in the report for a field that is there and has no text to keep: an `EditableField`
    /// whose value is an array or an object, or something that is not an `EditableField` at all.
    private static func editable(_ value: JSONValue?, named name: String, in record: inout SourceRecord) -> (
        type: String, value: String, label: String?
    )? {
        if let field = editable(value) { return field }
        guard let value, !value.isNull else { return nil }
        if let field = value.object, field["value"]?.isNull ?? true { return nil }
        let field = value.object
        record.warnings.append(
            .unsupportedFieldType(
                label: field?.string("label") ?? name, type: field?.string("fieldType") ?? "unknown"))
        record.hadUnimportableContent = true
        return nil
    }

    private static func customField(
        _ field: (type: String, value: String, label: String?), label: String, section: String
    ) -> SourceField {
        let kind: FieldKind
        switch field.type {
        case "concealed-string": kind = .custom
        case "email": kind = .email
        case "date", "year-month": kind = .date
        case "string", "number", "boolean", "country-code", "subdivision-code", "wifi-network-security-type":
            kind = .text
        // A field type this importer does not know is concealed: the safe reading of an unknown value.
        default: kind = .custom
        }
        var meta = [InterchangeMeta.sourceType: field.type]
        if !section.isEmpty { meta[InterchangeMeta.section] = section }
        return SourceField(kind: .plain(kind), label: label, value: field.value, meta: meta)
    }

    private static func appendOneTimePassword(_ credential: JSONObject, to record: inout SourceRecord) {
        guard let encoded = credential.string("secret") else {
            record.hadUnimportableContent = true
            return
        }
        let label = "One-time password"
        do {
            guard let secret = Base32.decode(encoded.filter { $0 != " " && $0 != "-" }) else {
                throw OTPAuthError.malformedSecret
            }
            let name = credential.string("algorithm") ?? "sha1"
            let folded = name.uppercased().replacingOccurrences(of: "-", with: "")
            guard let algorithm = OTPParameters.Algorithm(rawValue: folded) else {
                throw OTPAuthError.unsupportedAlgorithm(name)
            }
            guard let digits = credential["digits"].map({ $0.integer }) ?? 6 else {
                throw OTPAuthError.digitsOutOfRange("")
            }
            guard let period = credential["period"].map({ $0.integer }) ?? 30 else {
                throw OTPAuthError.periodOutOfRange("")
            }
            guard let digitCount = Int(exactly: digits) else { throw OTPAuthError.digitsOutOfRange(String(digits)) }
            guard let seconds = Int(exactly: period) else { throw OTPAuthError.periodOutOfRange(String(period)) }
            let parameters = try OTPParameters(
                secret: secret, algorithm: algorithm, digits: digitCount, period: seconds,
                issuer: credential.string("issuer").flatMap { $0.isEmpty ? nil : $0 },
                account: credential.string("username").flatMap { $0.isEmpty ? nil : $0 })
            record.fields.append(SourceField(kind: .oneTimePassword, label: label, value: parameters.uri))
        } catch {
            let reason = (error as? OTPAuthError) ?? .malformedSecret
            record.fields.append(SourceField(kind: .unusableOneTimePassword(reason), label: label, value: encoded))
        }
    }

    /// Maps a `passkey` credential through `PasskeyCredential`, whose bounds are the bounds: a credential outside
    /// them is refused whole, never truncated or repaired.
    private static func appendPasskey(_ credential: JSONObject, createdAt: Date?, to record: inout SourceRecord) {
        func refuse(_ reason: String) {
            record.warnings.append(.passkeyRefused(reason: reason))
            record.hadUnimportableContent = true
        }
        func binary(_ key: String, in object: JSONObject) -> Data? {
            object.string(key).flatMap { Base64URL.decode($0) }
        }
        guard let credentialID = binary("credentialId", in: credential) else { return refuse("credentialId") }
        guard let userHandle = binary("userHandle", in: credential) else { return refuse("userHandle") }
        guard let key = binary("key", in: credential) else { return refuse("key") }
        // Compared as written: a mixed-case relying party is refused, not folded into a different party's.
        guard let relyingParty = credential.string("rpId"), relyingParty == relyingParty.lowercased() else {
            return refuse("rpId")
        }

        var prfSecret: Data?
        var largeBlob: Data?
        if let extensions = credential.object("fido2Extensions") {
            if let hmac = extensions.object("hmacCredentials") {
                let withVerification = binary("credWithUV", in: hmac)
                let without = binary("credWithoutUV", in: hmac)
                if let secret = withVerification ?? without, secret.count == PasskeyCredential.prfSecretLength {
                    prfSecret = secret
                    if let without, withVerification != nil, without != secret {
                        record.warnings.append(.passkeyDetailDropped("hmacCredentials.credWithoutUV"))
                    }
                } else {
                    record.warnings.append(.passkeyDetailDropped("hmacCredentials"))
                }
            }
            if let blob = extensions.object("largeBlob") {
                largeBlob = decodeLargeBlob(blob)
                if largeBlob == nil { record.warnings.append(.passkeyDetailDropped("largeBlob")) }
            }
            for other in ["credBlob", "supplementalKeys", "payments"] where extensions[other] != nil {
                record.warnings.append(.passkeyDetailDropped(other))
            }
        }
        do {
            let passkey = try PasskeyCredential(
                credentialID: credentialID, relyingPartyID: relyingParty, userHandle: userHandle,
                userName: credential.string("username") ?? "",
                userDisplayName: credential.string("userDisplayName") ?? "", privateKeyPKCS8: key,
                createdAt: createdAt ?? Date(timeIntervalSince1970: 0), prfSecret: prfSecret, largeBlob: largeBlob)
            // The field value is checked here so an oversized one refuses the passkey, not the item.
            let value = try passkey.fieldValue()
            record.fields.append(SourceField(kind: .passkey(passkey), label: passkeyLabel, value: value))
        } catch PasskeyCodingError.invalid(let name) {
            refuse(name)
        } catch {
            refuse("encoding")
        }
    }

    /// A large blob is carried DEFLATE-compressed with its uncompressed size. It is inflated under the passkey's own
    /// bound; a writer that stored it uncompressed after all is recognised by its length matching exactly.
    private static func decodeLargeBlob(_ blob: JSONObject) -> Data? {
        guard let data = blob.string("data").flatMap({ Base64URL.decode($0) }),
            let size = blob.integer("uncompressedSize"), size >= 0,
            size <= Int64(PasskeyCredential.maximumLargeBlobLength)
        else { return nil }
        let limits = InterchangeLimits(maximumDocumentBytes: PasskeyCredential.maximumLargeBlobLength)
        let bytes = Array(data)
        if let inflated = try? Inflater.inflate(
            bytes, range: 0..<bytes.count, expectedLength: Int(size), limits: limits)
        {
            return Data(inflated)
        }
        return data.count == Int(size) ? data : nil
    }

    /// A credential type with no mapping here. Its `EditableField` members and plain strings are kept as concealed
    /// custom fields, labelled with the type and the member's name, and the report names the type.
    private static func appendUnknown(_ credential: JSONObject, type: String, to record: inout SourceRecord) {
        record.warnings.append(.unsupportedCredentialType(type))
        var kept = 0
        for member in credential.members where member.key != "type" {
            let text: String?
            let label: String?
            if let field = editable(member.value) {
                text = field.value
                label = field.label
            } else {
                text = member.value.scalarText
                label = nil
            }
            guard let text, !text.isEmpty else { continue }
            record.fields.append(
                SourceField(
                    kind: .plain(.custom), label: label ?? "\(type): \(member.key)", value: text,
                    meta: [InterchangeMeta.sourceType: type, InterchangeMeta.section: type]))
            kept += 1
        }
        if kept == 0 { record.hadUnimportableContent = true }
    }

    // MARK: Export

    public struct ExportOptions: Hashable, Sendable {
        /// The exporting app's relying-party identifier, which the format requires.
        public var exporterRelyingPartyID: String
        public var exporterDisplayName: String
        public var accountID: UUID
        public var accountName: String
        public var accountEmail: String
        /// The export's own timestamp, injected.
        public var timestamp: Date
        /// Items carrying this tag are marked as favourites.
        public var favoriteTag: String?

        public init(
            exporterRelyingPartyID: String, exporterDisplayName: String = "Watchword", accountID: UUID,
            accountName: String = "", accountEmail: String = "", timestamp: Date, favoriteTag: String? = "Favorite"
        ) {
            self.exporterRelyingPartyID = exporterRelyingPartyID
            self.exporterDisplayName = exporterDisplayName
            self.accountID = accountID
            self.accountName = accountName
            self.accountEmail = accountEmail
            self.timestamp = timestamp
            self.favoriteTag = favoriteTag
        }
    }

    /// Exports `items` as a CXF 1.0 document: the payload for the OS Credential Exchange export, or a file. The
    /// bytes are plaintext (`ExportResult`). Trashed items are left out and reported.
    public static func exportDocument(_ items: [Item], options: ExportOptions) -> ExportResult {
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
        var account = JSONObject()
        account.append("id", .string(Base64URL.encode(RandomUUID.bytes(of: options.accountID))))
        account.append("username", .string(options.accountName))
        account.append("email", .string(options.accountEmail))
        account.append("collections", .array([]))
        account.append("items", .array(exported))
        var root = JSONObject()
        root.append(
            "version", .object(JSONObject([("major", .integer(majorVersion)), ("minor", .integer(0))])))
        root.append("exporterRpId", .string(options.exporterRelyingPartyID))
        root.append("exporterDisplayName", .string(options.exporterDisplayName))
        root.append("timestamp", .integer(seconds(options.timestamp)))
        root.append("accounts", .array([.object(account)]))
        return ExportResult(bytes: JSONWriter.encode(.object(root)), report: report)
    }

    private static func seconds(_ date: Date) -> Int64 {
        let seconds = date.timeIntervalSince1970
        guard seconds.isFinite, seconds >= 0, seconds <= Double(ImportAssembler.latestPlausibleTimestamp) else {
            return 0
        }
        return Int64(seconds)
    }

    private static func editable(_ value: String, type: String, label: String? = nil) -> JSONValue {
        var field = JSONObject([("fieldType", .string(type)), ("value", .string(value))])
        field.append("label", ifPresent: label.map { .string($0) })
        return .object(field)
    }

    private static func export(_ item: Item, options: ExportOptions, report: inout ExportReport) -> JSONObject {
        var credentials: [JSONValue] = []
        var custom: [(section: String, fields: [JSONValue])] = []
        var customIndex: [String: Int] = [:]
        let (urls, websiteFields) = ExportSupport.websites(of: item)
        var subtitle: String?
        ExportSupport.commonWarnings(for: item, into: &report)
        if item.archived { report.warnings.append(.archivedStateOmitted(itemID: item.id)) }
        if !item.history.isEmpty {
            report.warnings.append(.historyOmitted(itemID: item.id, entries: item.history.count))
        }
        func appendCustom(_ field: Field, concealed: Bool) {
            let section = field.meta[InterchangeMeta.section] ?? ""
            let type: String
            switch field.kind {
            case .email: type = "email"
            case .date: type = CivilDate.monthYear(from: field.value) != nil ? "year-month" : "date"
            default: type = concealed ? "concealed-string" : textType(of: field)
            }
            let exported = editable(field.value, type: type, label: field.label)
            if let index = customIndex[section] {
                custom[index].fields.append(exported)
            } else {
                customIndex[section] = custom.count
                custom.append((section, [exported]))
            }
        }

        // A basic-auth credential holds one name and one password; further ones are custom fields. An item with an
        // API key and no password is an API credential, and its user name belongs to the key.
        let username = item.fields.first { $0.kind == .username } ?? item.fields.first { $0.kind == .email }
        let password = item.field(.password)
        let isAPICredential = password == nil && item.field(.apiKey) != nil
        var apiKey = JSONObject([("type", .string("api-key"))])
        if isAPICredential {
            if let username { apiKey.append("username", editable(username.value, type: "string")) }
        } else if username != nil || password != nil {
            var basic = JSONObject([("type", .string("basic-auth"))])
            if let username {
                basic.append("username", editable(username.value, type: username.kind == .email ? "email" : "string"))
            }
            if let password { basic.append("password", editable(password.value, type: "concealed-string")) }
            credentials.append(.object(basic))
        }
        for field in item.fields where field.id != username?.id && field.id != password?.id {
            if isAPICredential, field.meta[InterchangeMeta.sourceType] == apiKeyType,
                let member = field.meta[InterchangeMeta.sourceID], let type = apiKeyMembers[member],
                apiKey[member] == nil
            {
                apiKey.append(member, editable(field.value, type: type))
                continue
            }
            switch field.kind {
            case .totp:
                guard let parameters = try? field.otpParameters() else {
                    report.warnings.append(.oneTimePasswordUnusable(itemID: item.id))
                    appendCustom(field, concealed: true)
                    continue
                }
                var totp = JSONObject([("type", .string("totp"))])
                totp.append("secret", .string(Base32.encode(parameters.secret)))
                totp.append("period", .integer(Int64(parameters.period)))
                totp.append("digits", .integer(Int64(parameters.digits)))
                totp.append("username", ifPresent: parameters.account.map { .string($0) })
                totp.append("algorithm", .string(parameters.algorithm.rawValue.lowercased()))
                totp.append("issuer", ifPresent: parameters.issuer.map { .string($0) })
                credentials.append(.object(totp))
            case .passkey:
                guard let passkey = try? field.passkeyCredential() else {
                    report.warnings.append(.passkeyUnreadable(itemID: item.id))
                    continue
                }
                credentials.append(.object(export(passkey)))
            case .apiKey where apiKey["key"] == nil:
                apiKey.append("key", editable(field.value, type: "concealed-string"))
            case .url where websiteFields.contains(field.id):
                // Written among the item's URLs.
                break
            case .text where field.meta[InterchangeMeta.sourceType] == InterchangeMeta.subtitleType && subtitle == nil:
                subtitle = field.value
            default:
                appendCustom(field, concealed: field.kind.isSecret)
            }
        }
        if apiKey["key"] != nil { credentials.append(.object(apiKey)) }
        if !item.notes.isEmpty {
            credentials.append(
                .object(JSONObject([("type", .string("note")), ("content", editable(item.notes, type: "string"))])))
        }
        for group in custom {
            var credential = JSONObject([("type", .string("custom-fields"))])
            if !group.section.isEmpty { credential.append("label", .string(group.section)) }
            credential.append("fields", .array(group.fields))
            credentials.append(.object(credential))
        }
        // What sync is keeping for the person to choose between goes too, concealed and labelled (PRD F7.7).
        let unresolved = ExportSupport.unresolvedValues(of: item)
        if !unresolved.fields.isEmpty {
            var credential = JSONObject([("type", .string("custom-fields"))])
            credential.append("label", .string(ExportSupport.unresolvedLabel))
            credential.append(
                "fields",
                .array(unresolved.fields.map { editable($0.value, type: "concealed-string", label: $0.label) }))
            credentials.append(.object(credential))
            report.warnings.append(.unresolvedValuesAdded(itemID: item.id, count: unresolved.fields.count))
        }
        if unresolved.omitted > 0 {
            report.warnings.append(.unresolvedValuesOmitted(itemID: item.id, count: unresolved.omitted))
        }

        var exported = JSONObject()
        exported.append("id", .string(Base64URL.encode(RandomUUID.bytes(of: item.id))))
        exported.append("creationAt", .integer(seconds(item.createdAt)))
        exported.append("modifiedAt", .integer(seconds(item.modifiedAt)))
        exported.append("title", .string(item.title))
        exported.append("subtitle", ifPresent: subtitle.map { .string($0) })
        let isFavorite = options.favoriteTag.map { item.tags.contains($0) } ?? false
        exported.append("favorite", .bool(isFavorite))
        exported.append(
            "scope", .object(JSONObject([("urls", .array(urls.map { .string($0) })), ("androidApps", .array([]))])))
        exported.append("credentials", .array(credentials))
        exported.append("tags", .array(item.tags.sorted().map { .string($0) }))
        return exported
    }

    /// The field type a text field is written with: the one it was imported with, where the value still is one,
    /// and `string` otherwise. A hint, checked like any other input.
    private static func textType(of field: Field) -> String {
        let value = field.value
        switch field.meta[InterchangeMeta.sourceType] {
        case "boolean" where value == "true" || value == "false": return "boolean"
        case "number" where Double(value)?.isFinite == true && value.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }):
            return "number"
        case "country-code": return "country-code"
        case "subdivision-code": return "subdivision-code"
        case "wifi-network-security-type": return "wifi-network-security-type"
        default: return "string"
        }
    }

    private static func export(_ passkey: PasskeyCredential) -> JSONObject {
        var credential = JSONObject([("type", .string("passkey"))])
        credential.append("credentialId", .string(Base64URL.encode(passkey.credentialID)))
        credential.append("rpId", .string(passkey.relyingPartyID))
        credential.append("username", .string(passkey.userName))
        credential.append("userDisplayName", .string(passkey.userDisplayName))
        credential.append("userHandle", .string(Base64URL.encode(passkey.userHandle)))
        credential.append("key", .string(Base64URL.encode(passkey.privateKeyPKCS8)))
        var extensions = JSONObject()
        if let secret = passkey.prfSecret {
            // Watchword keeps one PRF secret per credential and uses it with or without user verification.
            let encoded = JSONValue.string(Base64URL.encode(secret))
            extensions.append(
                "hmacCredentials",
                .object(
                    JSONObject([
                        ("algorithm", .string("hmac-sha256")), ("credWithUV", encoded), ("credWithoutUV", encoded),
                    ])))
        }
        if let blob = passkey.largeBlob {
            extensions.append(
                "largeBlob",
                .object(
                    JSONObject([
                        ("uncompressedSize", .integer(Int64(blob.count))),
                        ("data", .string(Base64URL.encode(Inflater.storedStream(Array(blob))))),
                    ])))
        }
        if !extensions.members.isEmpty { credential.append("fido2Extensions", .object(extensions)) }
        return credential
    }
}
