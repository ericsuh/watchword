import Foundation

/// The hard limits every import parser enforces before or while it reads, never afterwards (PRD SEC7, SEC9;
/// docs/02-architecture.md §14).
///
/// An import file is hostile input (adversary A7): each limit bounds the time or memory a crafted file can cost, and
/// each is checked at the point where the cost would be incurred. `standard` holds the ceilings. A caller may tighten
/// any of them (tests do, and a memory-constrained extension may), but no initialiser can raise one above its ceiling
/// or below one, so the bounds stay two-sided whatever a caller passes.
public struct InterchangeLimits: Hashable, Sendable {
    /// Names the limit a file ran into, for `InterchangeError.limitExceeded`.
    public enum Kind: String, Hashable, Sendable, CaseIterable {
        case inputBytes
        case documentBytes
        case archiveEntries
        case items
        case compressionRatio
        case entryBytes
        case fieldBytes
        case fieldsPerItem
        case nestingDepth
        case entryNameBytes
        case totalFields
        case csvColumns
        case urlsPerItem
        case scopeDerivations
        case storedItemBytes
        case totalStoredBytes
    }

    /// The whole file as handed to a parser: an archive, a CSV file or a JSON document. 100 MB.
    public private(set) var maximumInputBytes: Int
    /// The decompressed size of the one archive member that is read. 100 MB.
    public private(set) var maximumDocumentBytes: Int
    /// Members in an archive's central directory. 50,000.
    public private(set) var maximumArchiveEntries: Int
    /// Rows, items or credentials-bearing entries in one import. 50,000.
    public private(set) var maximumItems: Int
    /// Decompressed bytes per compressed byte, enforced while inflating. 100.
    public private(set) var maximumCompressionRatio: Int
    /// One CSV row, or one item as written in a JSON document: the bound on what one entry costs to read. 512 KiB.
    /// It is not the bound on what the vault will store for the entry, which `maximumStoredItemBytes` is: the stored
    /// form escapes control characters six-fold and carries sync metadata for every field and every line of notes.
    public private(set) var maximumEntryBytes: Int
    /// One CSV cell or one field value. 256 KiB.
    public private(set) var maximumFieldBytes: Int
    /// Fields, URLs, tags and history entries in one item; members of a walked JSON object. 1,000.
    public private(set) var maximumFieldsPerItem: Int
    /// Nested arrays and objects in a JSON document. 64.
    public private(set) var maximumNestingDepth: Int
    /// The name of an archive member. 1,024 bytes.
    public private(set) var maximumEntryNameBytes: Int
    /// Fields, URLs, tags and history entries over the whole import, and cells in a CSV file read whole. 1,000,000.
    /// The per-entry and per-file limits do not bound their product: fifty thousand entries of a thousand two-byte
    /// fields fit in 100 MB and are fifty million `Field`s. This is the bound on what the drafts of one import can
    /// occupy (a quarter of a gigabyte, measured), and reaching it fails the file.
    public private(set) var maximumTotalFields: Int
    /// Columns in a CSV file. 100: real exports have about ten.
    public private(set) var maximumCSVColumns: Int
    /// URLs of one entry that are considered as scopes. 32. Further ones are kept as `url` fields, with a warning.
    public private(set) var maximumURLsPerItem: Int
    /// URLs considered as scopes over the whole import. 100,000, two for each of the most entries a file may hold:
    /// deriving a scope parses a URL, which is the most expensive thing an import does per byte of input. Further
    /// ones are kept as `url` fields, with a warning.
    public private(set) var maximumScopeDerivations: Int
    /// The size of one draft as the vault will store it, by `StoredItemSize`'s estimate. 768 KiB, under the vault's
    /// 1 MiB item payload (`ItemCodec.maximumPayloadLength`) with room for the item to be edited afterwards.
    public private(set) var maximumStoredItemBytes: Int
    /// The drafts of the whole import as the vault will store them, the sum of `StoredItemSize`'s estimates. 512 MiB,
    /// above what `maximumTotalFields` of small fields store (each costs about 270 bytes stored), so it binds only on
    /// shapes that cost more stored than their fields count.
    /// The stored form costs far more than the file for some shapes (each line of notes is stored again with its sync
    /// metadata, about 272 bytes for one line feed), so a few megabytes of file could otherwise commit gigabytes of
    /// sealed rows, published to every device of the account (review §Z, Z81). Reaching it fails the file.
    public private(set) var maximumTotalStoredBytes: Int

    /// The ceilings for a file from another app (docs/02-architecture.md §14). No initialiser can loosen them.
    public static let standard = InterchangeLimits(
        uncheckedInputBytes: 100 * 1024 * 1024,
        documentBytes: 100 * 1024 * 1024,
        archiveEntries: 50_000,
        items: 50_000,
        compressionRatio: 100,
        entryBytes: 512 * 1024,
        fieldBytes: 256 * 1024,
        fieldsPerItem: 1_000,
        nestingDepth: 64,
        entryNameBytes: 1_024,
        totalFields: 1_000_000,
        csvColumns: 100,
        urlsPerItem: 32,
        scopeDerivations: 100_000,
        storedItemBytes: 768 * 1024,
        totalStoredBytes: 512 << 20)

    /// The limits for an encrypted Watchword archive, sized to what the vault and the archive format accept, so that
    /// an archive this app wrote restores (review §Z, Z82). The file is bounded by `AccountArchive` (256 MiB, 200,000
    /// entries of at most 1 MiB and 64 KiB) before any of this is reached, and each entry was decoded as `ItemCodec`
    /// decodes a stored item (1 MiB of payload at most):
    ///
    /// - items: `AccountArchive.maximumEntries`, 200,000;
    /// - stored size of one draft: the vault's own payload limit, 1 MiB (`ItemCodec.maximumPayloadLength`);
    /// - fields, scopes, tags and unresolved values in one item: 16,384, more than an item within 1 MiB can hold;
    /// - fields over the whole archive, history included: 4,194,304, one for every 64 bytes the largest archive holds,
    ///   which no field `ItemCodec` writes is shorter than (`InterchangeSessionTests` holds both numbers to the
    ///   codec), so the budget cannot fail an archive this app wrote;
    /// - scopes considered: 1,024 in one item and 400,000 in all, two per entry;
    /// - stored size over the whole archive: 1 GiB, four times the largest archive, for the drafts' sync metadata
    ///   that the archive does not carry (an attacker's archive can still leave its notes' line metadata out: the
    ///   budget is what bounds that).
    ///
    /// Only `ArchivedItems` uses it, and only the session's restore reaches that; the public initialiser still clamps
    /// to `standard`. Whatever an archive holds beyond these is listed when it is made (`exportArchive` reports it).
    public static let archive = InterchangeLimits(
        uncheckedInputBytes: 100 * 1024 * 1024,
        documentBytes: 100 * 1024 * 1024,
        archiveEntries: 50_000,
        items: 200_000,
        compressionRatio: 100,
        entryBytes: 512 * 1024,
        fieldBytes: 1024 * 1024,
        fieldsPerItem: 16_384,
        nestingDepth: 64,
        entryNameBytes: 1_024,
        totalFields: 4_194_304,
        csvColumns: 100,
        urlsPerItem: 1_024,
        scopeDerivations: 400_000,
        storedItemBytes: 1 << 20,
        totalStoredBytes: 1 << 30)

    /// The limits for an archive another account made, opened with a Secret Key typed from its Kit (review finding
    /// Z128). The code cannot tell a genuine restore into a new account from an archive A7 sealed under an account of
    /// its own and handed over with its Kit, so such an archive is a file from elsewhere: it keeps what the format and
    /// the vault need of each item (`archive`'s item count, per-item stored size, fields per item and field size) and
    /// has `standard`'s import-wide budgets (stored size, fields, scope derivations, URLs per item). An honest archive
    /// past those still restores into the account that made it; `exportArchive` says when one would not restore
    /// into another (`ArchiveRestoreCheck.limitReachedInAnotherAccount`).
    public static let archiveOfAnotherAccount = InterchangeLimits(
        uncheckedInputBytes: archive.maximumInputBytes,
        documentBytes: archive.maximumDocumentBytes,
        archiveEntries: archive.maximumArchiveEntries,
        items: archive.maximumItems,
        compressionRatio: archive.maximumCompressionRatio,
        entryBytes: archive.maximumEntryBytes,
        fieldBytes: archive.maximumFieldBytes,
        fieldsPerItem: archive.maximumFieldsPerItem,
        nestingDepth: archive.maximumNestingDepth,
        entryNameBytes: archive.maximumEntryNameBytes,
        totalFields: standard.maximumTotalFields,
        csvColumns: archive.maximumCSVColumns,
        urlsPerItem: standard.maximumURLsPerItem,
        scopeDerivations: standard.maximumScopeDerivations,
        storedItemBytes: archive.maximumStoredItemBytes,
        totalStoredBytes: standard.maximumTotalStoredBytes)

    private init(
        uncheckedInputBytes: Int, documentBytes: Int, archiveEntries: Int, items: Int, compressionRatio: Int,
        entryBytes: Int, fieldBytes: Int, fieldsPerItem: Int, nestingDepth: Int, entryNameBytes: Int,
        totalFields: Int, csvColumns: Int, urlsPerItem: Int, scopeDerivations: Int, storedItemBytes: Int,
        totalStoredBytes: Int
    ) {
        maximumInputBytes = uncheckedInputBytes
        maximumDocumentBytes = documentBytes
        maximumArchiveEntries = archiveEntries
        maximumItems = items
        maximumCompressionRatio = compressionRatio
        maximumEntryBytes = entryBytes
        maximumFieldBytes = fieldBytes
        maximumFieldsPerItem = fieldsPerItem
        maximumNestingDepth = nestingDepth
        maximumEntryNameBytes = entryNameBytes
        maximumTotalFields = totalFields
        maximumCSVColumns = csvColumns
        maximumURLsPerItem = urlsPerItem
        maximumScopeDerivations = scopeDerivations
        maximumStoredItemBytes = storedItemBytes
        maximumTotalStoredBytes = totalStoredBytes
    }

    /// Limits no looser than `standard`: each argument is clamped to `1...ceiling`, and one left out is the ceiling.
    public init(
        maximumInputBytes: Int? = nil, maximumDocumentBytes: Int? = nil, maximumArchiveEntries: Int? = nil,
        maximumItems: Int? = nil, maximumCompressionRatio: Int? = nil, maximumEntryBytes: Int? = nil,
        maximumFieldBytes: Int? = nil, maximumFieldsPerItem: Int? = nil, maximumNestingDepth: Int? = nil,
        maximumEntryNameBytes: Int? = nil, maximumTotalFields: Int? = nil, maximumCSVColumns: Int? = nil,
        maximumURLsPerItem: Int? = nil, maximumScopeDerivations: Int? = nil, maximumStoredItemBytes: Int? = nil,
        maximumTotalStoredBytes: Int? = nil
    ) {
        let ceiling = InterchangeLimits.standard
        func clamp(_ value: Int?, _ ceiling: Int) -> Int {
            guard let value else { return ceiling }
            return min(max(value, 1), ceiling)
        }
        self.init(
            uncheckedInputBytes: clamp(maximumInputBytes, ceiling.maximumInputBytes),
            documentBytes: clamp(maximumDocumentBytes, ceiling.maximumDocumentBytes),
            archiveEntries: clamp(maximumArchiveEntries, ceiling.maximumArchiveEntries),
            items: clamp(maximumItems, ceiling.maximumItems),
            compressionRatio: clamp(maximumCompressionRatio, ceiling.maximumCompressionRatio),
            entryBytes: clamp(maximumEntryBytes, ceiling.maximumEntryBytes),
            fieldBytes: clamp(maximumFieldBytes, ceiling.maximumFieldBytes),
            fieldsPerItem: clamp(maximumFieldsPerItem, ceiling.maximumFieldsPerItem),
            nestingDepth: clamp(maximumNestingDepth, ceiling.maximumNestingDepth),
            entryNameBytes: clamp(maximumEntryNameBytes, ceiling.maximumEntryNameBytes),
            totalFields: clamp(maximumTotalFields, ceiling.maximumTotalFields),
            csvColumns: clamp(maximumCSVColumns, ceiling.maximumCSVColumns),
            urlsPerItem: clamp(maximumURLsPerItem, ceiling.maximumURLsPerItem),
            scopeDerivations: clamp(maximumScopeDerivations, ceiling.maximumScopeDerivations),
            storedItemBytes: clamp(maximumStoredItemBytes, ceiling.maximumStoredItemBytes),
            totalStoredBytes: clamp(maximumTotalStoredBytes, ceiling.maximumTotalStoredBytes))
    }

    /// The value of the limit named `kind`.
    public func value(of kind: Kind) -> Int {
        switch kind {
        case .inputBytes: return maximumInputBytes
        case .documentBytes: return maximumDocumentBytes
        case .archiveEntries: return maximumArchiveEntries
        case .items: return maximumItems
        case .compressionRatio: return maximumCompressionRatio
        case .entryBytes: return maximumEntryBytes
        case .fieldBytes: return maximumFieldBytes
        case .fieldsPerItem: return maximumFieldsPerItem
        case .nestingDepth: return maximumNestingDepth
        case .entryNameBytes: return maximumEntryNameBytes
        case .totalFields: return maximumTotalFields
        case .csvColumns: return maximumCSVColumns
        case .urlsPerItem: return maximumURLsPerItem
        case .scopeDerivations: return maximumScopeDerivations
        case .storedItemBytes: return maximumStoredItemBytes
        case .totalStoredBytes: return maximumTotalStoredBytes
        }
    }

    /// The error for running into `kind`.
    func exceeded(_ kind: Kind) -> InterchangeError {
        .limitExceeded(kind, limit: value(of: kind))
    }

    /// Throws unless `count` bytes may be handed to a parser at all.
    func checkInput(_ count: Int) throws {
        guard count <= maximumInputBytes else { throw exceeded(.inputBytes) }
    }
}
