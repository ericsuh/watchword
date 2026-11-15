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
    /// One CSV row, or one item as written in a JSON document. 512 KiB, under the vault's 1 MiB item payload.
    public private(set) var maximumEntryBytes: Int
    /// One CSV cell or one field value. 256 KiB.
    public private(set) var maximumFieldBytes: Int
    /// Columns in a CSV row; fields, URLs, tags and history entries in one item. 1,000.
    public private(set) var maximumFieldsPerItem: Int
    /// Nested arrays and objects in a JSON document. 64.
    public private(set) var maximumNestingDepth: Int
    /// The name of an archive member. 1,024 bytes.
    public private(set) var maximumEntryNameBytes: Int

    /// The ceilings (docs/02-architecture.md §14).
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
        entryNameBytes: 1_024)

    private init(
        uncheckedInputBytes: Int, documentBytes: Int, archiveEntries: Int, items: Int, compressionRatio: Int,
        entryBytes: Int, fieldBytes: Int, fieldsPerItem: Int, nestingDepth: Int, entryNameBytes: Int
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
    }

    /// Limits no looser than `standard`: each argument is clamped to `1...ceiling`, and one left out is the ceiling.
    public init(
        maximumInputBytes: Int? = nil, maximumDocumentBytes: Int? = nil, maximumArchiveEntries: Int? = nil,
        maximumItems: Int? = nil, maximumCompressionRatio: Int? = nil, maximumEntryBytes: Int? = nil,
        maximumFieldBytes: Int? = nil, maximumFieldsPerItem: Int? = nil, maximumNestingDepth: Int? = nil,
        maximumEntryNameBytes: Int? = nil
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
            entryNameBytes: clamp(maximumEntryNameBytes, ceiling.maximumEntryNameBytes))
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
