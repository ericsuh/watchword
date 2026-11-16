import Foundation
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordInterchange
import WatchwordMatching
import WatchwordModel
import WatchwordStore
import WatchwordSync

/// One parser under fuzzing. Each target takes arbitrary bytes and must end in a value or a thrown error: a trap, a
/// hang or a broken invariant (`require`) is a finding, and libFuzzer keeps the input.
///
/// The targets that are not about `WatchwordInterchange` are here because the harness makes them cheap: the envelope,
/// sync-object, host, one-time-password and passkey parsers also read bytes an adversary chose.
enum FuzzTarget: String, CaseIterable, Sendable {
    case csv
    case passwordCSV = "password-csv"
    case inflate
    case zip
    case onePUX = "1pux"
    case onePUXArchive = "1pux-archive"
    case credentialExchange = "cxf"
    case amplify
    case envelope
    case syncPayload = "sync-payload"
    case signedObject = "signed-object"
    case host
    case otpauth
    case passkey
    /// The encrypted Watchword archive's parser: everything it checks before a key is derived (no derivation here, so
    /// a run spends its time on the parser, not on PBKDF2).
    case archive

    /// Tight limits, so a run spends its time in the parsers and not in megabytes of input. The standard limits are
    /// the same code with larger numbers.
    static let limits = InterchangeLimits(
        maximumInputBytes: 1 << 20, maximumDocumentBytes: 1 << 20, maximumArchiveEntries: 256, maximumItems: 256,
        maximumEntryBytes: 1 << 16, maximumFieldBytes: 1 << 14, maximumFieldsPerItem: 128, maximumNestingDepth: 32)

    static let vaultID = UUID(uuid: (0xF0, 0x22, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 1))
    static let envelopeContext = EnvelopeContext(
        recordID: UUID(uuid: (1, 1, 1, 1, 1, 1, 0x41, 1, 0x81, 1, 1, 1, 1, 1, 1, 1)), vaultID: vaultID,
        schemaVersion: 1, kind: .item, keyID: UUID(uuid: (2, 2, 2, 2, 2, 2, 0x42, 2, 0x82, 2, 2, 2, 2, 2, 2, 2)),
        recordVersion: 7)

    func run(_ bytes: [UInt8]) {
        var generator = FuzzGenerator(seed: 0x5EED)
        let limits = FuzzTarget.limits
        switch self {
        case .csv:
            guard let records = try? CSVReader.parse(bytes, limits: limits) else { return }
            // What the reader read, the writer writes and the reader reads again.
            // Compared byte for byte: string equality would forgive a change of normalisation.
            let rows = records.map(\.fields)
            let written = Array(CSVWriter.encode(rows).utf8)
            let reread = try? CSVReader.parse(written, limits: .standard)
            let expected = rows.filter { $0 != [""] }.map { $0.map { Array($0.utf8) } }
            require(reread?.map { $0.fields.map { Array($0.utf8) } } == expected, "CSV does not round-trip")
        case .passwordCSV:
            guard
                let result = try? PasswordCSV.importFile(
                    bytes, into: FuzzTarget.vaultID, limits: limits, using: &generator)
            else { return }
            check(result)
            let exported = PasswordCSV.exportApplePasswords(result.entries.map(\.item))
            // An export may be larger than a file an import accepts (fields moved into the notes); one that reads
            // back must not have widened.
            if let reread = try? PasswordCSV.importFile(
                exported.bytes, into: FuzzTarget.vaultID, limits: .standard, using: &generator)
            {
                requireNoNewHosts(in: reread, beyond: result)
            }
        case .inflate:
            guard let output = try? Inflater.inflate(bytes, limits: limits) else { return }
            require(output.count <= limits.maximumDocumentBytes, "inflated past the document limit")
            require(output.count <= bytes.count * limits.maximumCompressionRatio, "inflated past the ratio")
        case .zip:
            guard let archive = try? ZIPArchive(bytes, limits: limits) else { return }
            require(archive.entries.count <= limits.maximumArchiveEntries, "too many members")
            for entry in archive.entries {
                require((try? ZIPArchive.validateEntryName(entry.name)) != nil, "member name was not validated")
                // And independently of the validator, on the bytes an extractor would act on.
                let name = Array(entry.name.utf8)
                let components = name.split(separator: UInt8(ascii: "/"), omittingEmptySubsequences: false)
                require(name.first != UInt8(ascii: "/"), "an absolute member name was accepted")
                require(!components.contains { $0.elementsEqual([0x2E, 0x2E]) }, "a member name climbs a directory")
                if let contents = try? archive.contents(of: entry.name) {
                    require(contents.count == entry.uncompressedSize, "member size differs from its declaration")
                    require(contents.count <= limits.maximumDocumentBytes, "member past the document limit")
                }
            }
        case .onePUX:
            guard
                let result = try? OnePUX.importDocument(
                    bytes, into: FuzzTarget.vaultID, limits: limits, using: &generator)
            else { return }
            check(result)
            let options = OnePUX.ExportOptions(
                accountID: FuzzTarget.vaultID, vaultID: FuzzTarget.vaultID, createdAt: Date(timeIntervalSince1970: 1))
            let exported = OnePUX.exportDocument(result.entries.map(\.item), options: options)
            let reread = try? OnePUX.importDocument(
                exported.document, into: FuzzTarget.vaultID, limits: .standard, using: &generator)
            require(reread != nil, "a 1PUX export does not read back")
            if let reread { requireNoNewHosts(in: reread, beyond: result) }
        case .onePUXArchive:
            guard
                let result = try? OnePUX.importArchive(
                    bytes, into: FuzzTarget.vaultID, limits: limits, using: &generator)
            else { return }
            check(result)
        case .credentialExchange:
            guard
                let result = try? CredentialExchange.importDocument(
                    bytes, into: FuzzTarget.vaultID, limits: limits, using: &generator)
            else { return }
            check(result)
            let options = CredentialExchange.ExportOptions(
                exporterRelyingPartyID: "fuzz.example", accountID: FuzzTarget.vaultID,
                timestamp: Date(timeIntervalSince1970: 1))
            let exported = CredentialExchange.exportDocument(result.entries.map(\.item), options: options)
            let reread = try? CredentialExchange.importDocument(
                exported.bytes, into: FuzzTarget.vaultID, limits: .standard, using: &generator)
            require(reread != nil, "a CXF export does not read back")
            if let reread { requireNoNewHosts(in: reread, beyond: result) }
        case .amplify:
            amplify(bytes, using: &generator)
        case .envelope:
            guard let envelope = try? Envelope.parse(bytes, expecting: FuzzTarget.envelopeContext) else { return }
            require(envelope.serialized() == bytes, "an accepted envelope does not serialise to its own bytes")
        case .syncPayload:
            guard let payload = try? SyncPayload.parse(bytes, allowedKinds: Set(EnvelopeKind.allCases)) else { return }
            let reread = try? SyncPayload.parse(payload.encoded(), allowedKinds: Set(EnvelopeKind.allCases))
            require(reread == payload, "a sync payload does not round-trip")
        case .signedObject:
            guard let object = try? SignedObject.parse(bytes) else { return }
            require((try? SignedObject.parse(object.serialized())) == object, "a signed object does not round-trip")
        case .host:
            let text = String(decoding: bytes, as: UTF8.self)
            for kind in [ServiceIdentifierKind.domain, .url] {
                guard let host = try? HostNormalizer.normalize(ServiceIdentifier(text, kind: kind)) else { continue }
                require(!host.value.isEmpty, "an empty host was vouched for")
                require(host.value == host.value.lowercased(), "a host was not lower-cased")
            }
            // One host, one normalised form: as a domain and as the URL of that domain (HostNormalizer.mapLikeAURL).
            if let domain = try? HostNormalizer.normalize(ServiceIdentifier(text, kind: .domain)),
                let url = try? HostNormalizer.normalize(ServiceIdentifier("https://\(text)/", kind: .url))
            {
                require(domain == url, "a host normalised differently as a domain and as a URL")
            }
            for strips in [false, true] {
                if case .success(let scope) = ScopeDerivation.scope(forURL: text, stripsLeadingWWW: strips) {
                    require(ScopePolicy.isAcceptable(scope), "a derived scope is one the policy refuses")
                }
            }
        case .otpauth:
            let text = String(decoding: bytes, as: UTF8.self)
            guard let parameters = try? OTPParameters(uri: text) else { return }
            require(OTPParameters.secretLengthRange.contains(parameters.secret.count), "secret out of range")
            require(OTPParameters.digitsRange.contains(parameters.digits), "digits out of range")
            require(OTPParameters.periodRange.contains(parameters.period), "period out of range")
            _ = parameters.uri
        case .passkey:
            let text = String(decoding: bytes, as: UTF8.self)
            guard let passkey = try? PasskeyCredential(fieldValue: text) else { return }
            guard let value = try? passkey.fieldValue() else {
                require(false, "an accepted passkey cannot be written back")
                return
            }
            require((try? PasskeyCredential(fieldValue: value)) == passkey, "a passkey does not round-trip")
        case .archive:
            guard let archive = try? AccountArchive.parse(bytes) else { return }
            require(archive.entryCount <= AccountArchive.maximumEntries, "an archive past the entry limit was read")
            require((try? archive.kdf.validate()) != nil, "an archive's KDF parameters were not validated")
            require(bytes.count <= AccountArchive.maximumLength, "an archive past the size limit was read")
        }
    }

    /// The largest file `amplify` builds. Far past libFuzzer's input length, and small enough to run thousands of
    /// times: what is being looked for is cost out of proportion to the file, which shows at any size.
    static let amplifiedBytes = 1 << 20

    /// A small input expanded into a large file, imported under the **standard** limits: the other targets run with
    /// tight limits and inputs of at most 64 KiB, and so can never see a file that keeps every per-entry limit and
    /// spends their product. The first byte chooses the format, the next two a repeat count, and the rest is the
    /// unit repeated: rows of a CSV file, items of a 1PUX or CXF document, URLs or fields of one item. What comes
    /// back must stay inside the import-wide budgets; libFuzzer's memory limit and timeout judge the rest.
    private func amplify(_ bytes: [UInt8], using generator: inout FuzzGenerator) {
        guard bytes.count > 3 else { return }
        let unit = Array(bytes[3...])
        let wanted = 1 + (Int(bytes[1]) << 8 | Int(bytes[2])) * 16
        let count = min(wanted, FuzzTarget.amplifiedBytes / (unit.count + 1))
        var repeated: [UInt8] = []
        repeated.reserveCapacity(count * (unit.count + 1))
        func text(_ string: String) -> [UInt8] { Array(string.utf8) }
        /// `count` units as the members of JSON arrays of at most 512, each array wrapped in an item.
        func grouped(_ opening: String, _ closing: String, _ member: ([UInt8]) -> [UInt8]) -> [UInt8] {
            var items: [UInt8] = []
            var written = 0
            while written < count {
                let members = min(count - written, 512)
                if written > 0 { items.append(0x2C) }
                items += text(opening)
                for index in 0..<members {
                    items += (index == 0 ? [] : [0x2C]) + member(unit)
                }
                items += text(closing)
                written += members
            }
            return items
        }
        let limits = InterchangeLimits.standard
        let onePUXOpening = text(#"{"accounts":[{"vaults":[{"items":["#)
        let onePUXClosing = text("]}]}]}")
        let result: ImportResult?
        switch bytes[0] % 5 {
        case 0:
            // Rows of a CSV file.
            for _ in 0..<count {
                repeated += unit + [0x0A]
            }
            let file = text("Title,URL,Username,Password,Notes,OTPAuth,a,b,c,d\n") + repeated
            result = try? PasswordCSV.importFile(file, into: FuzzTarget.vaultID, limits: limits, using: &generator)
        case 1:
            // Items of a 1PUX document.
            for index in 0..<count {
                repeated += (index == 0 ? [] : [0x2C]) + unit
            }
            result = try? OnePUX.importDocument(
                onePUXOpening + repeated + onePUXClosing, into: FuzzTarget.vaultID, limits: limits, using: &generator)
        case 2:
            // URLs of the items of a 1PUX document, a few hundred to each.
            let items = grouped(#"{"overview":{"title":"t","urls":["#, #"]},"details":{}}"#) {
                text(#"{"url":""#) + $0 + text(#""}"#)
            }
            result = try? OnePUX.importDocument(
                onePUXOpening + items + onePUXClosing, into: FuzzTarget.vaultID, limits: limits, using: &generator)
        case 3:
            // Section fields of the items of a 1PUX document.
            let items = grouped(#"{"overview":{"title":"t"},"details":{"sections":[{"fields":["#, "]}]}}") { $0 }
            result = try? OnePUX.importDocument(
                onePUXOpening + items + onePUXClosing, into: FuzzTarget.vaultID, limits: limits, using: &generator)
        default:
            // Items of a CXF document.
            for index in 0..<count {
                repeated += (index == 0 ? [] : [0x2C]) + unit
            }
            let file =
                text(#"{"version":{"major":1,"minor":0},"accounts":[{"items":["#) + repeated + text("]}]}")
            result = try? CredentialExchange.importDocument(
                file, into: FuzzTarget.vaultID, limits: limits, using: &generator)
        }
        guard let result else { return }
        check(result, limits: limits)
    }

    /// An export never widens (PRD SEC6, F11.2): read back, a file names no host that none of the exported items
    /// was scoped to. An exporter writes an item's scopes and the URLs that stand for them, and no other URL an item
    /// happens to hold where the next reader would take it for a sign-in URL.
    private func requireNoNewHosts(in reread: ImportResult, beyond result: ImportResult) {
        var hosts = Set<String>()
        for entry in result.entries {
            for scope in entry.item.scopes {
                hosts.insert(scope.host)
            }
        }
        for entry in reread.entries {
            for scope in entry.item.scopes {
                require(hosts.contains(scope.host), "an export named a host no item was scoped to")
            }
        }
    }

    /// What must hold of every import, whatever the file said (PRD F11.2, SEC7).
    private func check(_ result: ImportResult, limits: InterchangeLimits = FuzzTarget.limits) {
        require(result.entries.count <= limits.maximumItems, "more entries than the item limit")
        // The import-wide budgets: what bounds the memory the drafts take, whatever the per-entry limits allow.
        var parts = 0
        for entry in result.entries {
            let item = entry.item
            parts += item.fields.count + item.tags.count + item.history.count
            require(item.scopes.count <= limits.maximumURLsPerItem, "more scopes than URLs considered")
            require(
                StoredItemSize.estimate(item) <= limits.maximumStoredItemBytes, "a draft the vault could not store")
        }
        require(parts <= limits.maximumTotalFields, "more fields than the import budget")
        require(result.report.skipped.count <= limits.maximumItems, "more skip records than entries")
        require(result.report.warnings.count <= ImportReport.maximumWarnings, "more warnings than the cap")
        require(result.report.importedCount == result.entries.count, "the counts disagree with the entries")
        var identifiers = Set<UUID>()
        for entry in result.entries {
            let item = entry.item
            require(item.vaultID == FuzzTarget.vaultID, "an item for another vault")
            require(identifiers.insert(item.id).inserted, "two items share an identifier")
            require(item.trashedAt == nil && item.version == 0, "a draft carries vault-owned state")
            for scope in item.scopes {
                require(ScopePolicy.isAcceptable(scope), "a scope the policy refuses was imported")
            }
            for field in item.fields {
                switch field.kind {
                case .totp:
                    require((try? field.otpParameters()) != nil, "an unusable one-time password was imported as one")
                case .passkey:
                    require((try? field.passkeyCredential()) != nil, "an undecodable passkey was imported")
                default:
                    break
                }
            }
        }
    }
}

/// Stops the process, which is how a fuzz target reports a broken invariant.
func require(_ condition: Bool, _ message: String) {
    if !condition { fatalError("fuzz invariant broken: \(message)") }
}

/// SplitMix64, for the identifiers the importers draw and for the blind mutator. Deterministic: a finding replays.
struct FuzzGenerator: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var value = state
        value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
        value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
        return value ^ (value >> 31)
    }
}
