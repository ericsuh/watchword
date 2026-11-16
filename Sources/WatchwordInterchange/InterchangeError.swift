import Foundation

/// The one error type every parser and exporter in this module throws (PRD SEC7): a hostile or damaged file ends in
/// exactly one of these, never in a crash, a hang or a partial import.
///
/// A per-entry problem (one oversized item, one unknown credential type) is not an error: the entry is skipped or
/// degraded and the `ImportReport` says so. These cases are for a file that cannot be read as what it claims to be.
public enum InterchangeError: Error, Hashable, Sendable {
    /// A hard limit was reached; nothing past it was read.
    case limitExceeded(InterchangeLimits.Kind, limit: Int)
    /// The bytes are not valid UTF-8. Refused rather than repaired: a replacement character inside a password is a
    /// different password.
    case invalidUTF8(byteOffset: Int)
    /// A UTF-16 or UTF-32 byte-order mark. Only UTF-8 is read.
    case unsupportedTextEncoding
    case malformedArchive(ArchiveDefect)
    /// A well-formed archive using something this reader deliberately does not implement.
    case unsupportedArchive(ArchiveFeature)
    /// An archive member whose name could escape a directory if it were ever extracted (zip-slip). Nothing here
    /// extracts to disk, and such an archive is refused all the same.
    case forbiddenEntryName(String)
    case missingArchiveEntry(String)
    case duplicateArchiveEntry(String)
    case malformedDeflate(DeflateDefect)
    /// The decompressed bytes do not have the CRC-32 the archive records for them.
    case checksumMismatch
    case malformedCSV(CSVDefect, line: Int)
    /// The first row is not a header this importer knows: it names fewer than two of the columns it understands.
    case unrecognisedCSVHeader
    case malformedJSON(JSONDefect, byteOffset: Int)
    /// Well-formed JSON that is not shaped like the format: the value at `path` is missing or of the wrong type.
    case unexpectedStructure(path: String)
    /// A format version this importer does not read.
    case unsupportedVersion(String)
    /// An item cannot be written in the requested format at all (as opposed to losing a field, which the
    /// `ExportReport` records).
    case unexportable(String)
}

public enum ArchiveDefect: String, Hashable, Sendable {
    /// No end-of-central-directory record where one must be.
    case missingEndOfCentralDirectory
    /// The central directory does not lie where the end record says, or does not end where the end record begins.
    case centralDirectoryBounds
    case centralDirectoryEntry
    /// The count in the end record disagrees with the entries present.
    case entryCount
    case extraField
    case localHeader
    /// The local header disagrees with the central directory about the same member.
    case headerMismatch
    /// A member's data runs past the central directory or into another member (the overlapping-files bomb).
    case overlappingEntries
    /// The sizes recorded for a member cannot both be true.
    case sizeMismatch
}

public enum ArchiveFeature: Hashable, Sendable {
    case encryption
    case zip64
    case multipleDisks
    /// Anything but stored (0) and deflate (8).
    case compressionMethod(UInt16)
    /// General-purpose flag bits other than the deflate options, the data descriptor and UTF-8 names.
    case flags(UInt16)
}

public enum DeflateDefect: String, Hashable, Sendable {
    case truncated
    case reservedBlockType
    case storedLengthMismatch
    case invalidCodeLengths
    case missingEndOfBlock
    case invalidSymbol
    case distanceTooFar
    /// Bytes remain after the final block.
    case trailingData
    /// The stream decodes to fewer or more bytes than declared.
    case lengthMismatch
    /// More than a thousand blocks, averaging under 256 bytes of output each. Valid DEFLATE, and refused: every block
    /// header is work, and a stream of empty blocks is work without output.
    case excessiveBlocks
}

public enum CSVDefect: String, Hashable, Sendable {
    case unterminatedQuote
    /// A quote inside a field that did not begin with one.
    case quoteInUnquotedField
    case textAfterClosingQuote
    /// A carriage return outside quotes that is not followed by a line feed.
    case strayCarriageReturn
    case nulCharacter
    case empty
    case duplicateColumn
}

public enum JSONDefect: String, Hashable, Sendable {
    case unexpectedEnd
    case unexpectedCharacter
    case invalidNumber
    case invalidEscape
    case loneSurrogate
    case controlCharacterInString
    case nulCharacter
    /// The same key twice in one object: refused rather than resolved by position.
    case duplicateKey
    case trailingData
}
