import Foundation

/// A minimal, strict ZIP reader for 1PUX archives (PRD F8.1, SEC7; docs/02-architecture.md §14).
///
/// It reads the central directory, validates every member, and decompresses exactly one member the caller names.
/// Nothing is ever extracted to disk, and nested archives are never opened. What it refuses, each with its own
/// error, is everything a hostile archive (adversary A7) is built from:
///
/// - **Zip-slip.** Every member's name is validated (`validateEntryName`) even though no name becomes a path here;
///   one bad name refuses the archive.
/// - **Bombs.** A member's declared size is checked against the document and ratio caps before any work, and
///   `Inflater` enforces the same caps while it runs, so a member that lies about its size stops at the lie. Members
///   whose data overlaps (the non-recursive bomb) are refused.
/// - **Parser differentials.** One reading only: the end record must be the last thing in the file, the directory
///   must end where the end record begins, counts must agree, local headers must agree with the directory, and
///   names are unique.
/// - **Features nobody needs here.** Encryption, ZIP64, multi-disk archives and every compression method but stored
///   and deflate.
public struct ZIPArchive: Sendable {
    public struct Entry: Hashable, Sendable {
        public let name: String
        public let compressedSize: Int
        public let uncompressedSize: Int
        /// A name ending in a slash, judged on its bytes.
        public var isDirectory: Bool { nameBytes.last == UInt8(ascii: "/") }

        let nameBytes: [UInt8]
        let flags: UInt16
        let method: UInt16
        let crc: UInt32
        let localHeaderOffset: Int
        /// Where this member's data must end: the next member's header, or the central directory.
        var dataLimit: Int
    }

    public let entries: [Entry]
    private let bytes: [UInt8]
    private let limits: InterchangeLimits

    private static let endSignature: UInt32 = 0x0605_4B50
    private static let centralSignature: UInt32 = 0x0201_4B50
    private static let localSignature: UInt32 = 0x0403_4B50
    private static let zip64LocatorSignature: UInt32 = 0x0706_4B50
    private static let endLength = 22
    private static let centralHeaderLength = 46
    private static let localHeaderLength = 30
    /// Deflate options (bits 1 and 2), data descriptor (3) and UTF-8 names (11).
    private static let permittedFlags: UInt16 = 0x080E
    /// Traditional encryption (bit 0), strong encryption (6) and masked headers (13).
    private static let encryptionFlags: UInt16 = 0x2041

    /// Reads and validates the central directory of `bytes`. No member is decompressed.
    public init(_ bytes: [UInt8], limits: InterchangeLimits = .standard) throws {
        try limits.checkInput(bytes.count)
        self.bytes = bytes
        self.limits = limits

        // The end record is the last thing in the file: its comment length must account for every byte after it.
        var endOffset: Int?
        var candidate = bytes.count - ZIPArchive.endLength
        let lowest = max(0, candidate - 0xFFFF)
        while candidate >= lowest {
            if ZIPArchive.u32(bytes, candidate) == ZIPArchive.endSignature,
                candidate + ZIPArchive.endLength + ZIPArchive.u16(bytes, candidate + 20) == bytes.count
            {
                endOffset = candidate
                break
            }
            candidate -= 1
        }
        guard let endOffset else { throw InterchangeError.malformedArchive(.missingEndOfCentralDirectory) }
        if endOffset >= 20, ZIPArchive.u32(bytes, endOffset - 20) == ZIPArchive.zip64LocatorSignature {
            throw InterchangeError.unsupportedArchive(.zip64)
        }
        let disk = ZIPArchive.u16(bytes, endOffset + 4)
        let directoryDisk = ZIPArchive.u16(bytes, endOffset + 6)
        let entriesOnDisk = ZIPArchive.u16(bytes, endOffset + 8)
        let entryCount = ZIPArchive.u16(bytes, endOffset + 10)
        let directorySize = Int(ZIPArchive.u32(bytes, endOffset + 12))
        let directoryOffset = Int(ZIPArchive.u32(bytes, endOffset + 16))
        if disk == 0xFFFF || directoryDisk == 0xFFFF || entriesOnDisk == 0xFFFF || entryCount == 0xFFFF
            || directorySize == 0xFFFF_FFFF || directoryOffset == 0xFFFF_FFFF
        {
            throw InterchangeError.unsupportedArchive(.zip64)
        }
        guard disk == 0, directoryDisk == 0, entriesOnDisk == entryCount else {
            throw InterchangeError.unsupportedArchive(.multipleDisks)
        }
        guard entryCount <= limits.maximumArchiveEntries else { throw limits.exceeded(.archiveEntries) }
        guard directoryOffset + directorySize == endOffset else {
            throw InterchangeError.malformedArchive(.centralDirectoryBounds)
        }
        guard entryCount * ZIPArchive.centralHeaderLength <= directorySize else {
            throw InterchangeError.malformedArchive(.entryCount)
        }

        var entries: [Entry] = []
        entries.reserveCapacity(entryCount)
        var names = Set<String>()
        var position = directoryOffset
        for _ in 0..<entryCount {
            guard endOffset - position >= ZIPArchive.centralHeaderLength,
                ZIPArchive.u32(bytes, position) == ZIPArchive.centralSignature
            else { throw InterchangeError.malformedArchive(.centralDirectoryEntry) }
            let flags = UInt16(ZIPArchive.u16(bytes, position + 8))
            let method = UInt16(ZIPArchive.u16(bytes, position + 10))
            let crc = ZIPArchive.u32(bytes, position + 16)
            let compressedSize = Int(ZIPArchive.u32(bytes, position + 20))
            let uncompressedSize = Int(ZIPArchive.u32(bytes, position + 24))
            let nameLength = ZIPArchive.u16(bytes, position + 28)
            let extraLength = ZIPArchive.u16(bytes, position + 30)
            let commentLength = ZIPArchive.u16(bytes, position + 32)
            let startDisk = ZIPArchive.u16(bytes, position + 34)
            let localHeaderOffset = Int(ZIPArchive.u32(bytes, position + 42))
            let nameStart = position + ZIPArchive.centralHeaderLength
            let extraStart = nameStart + nameLength
            let next = extraStart + extraLength + commentLength
            guard next <= endOffset else { throw InterchangeError.malformedArchive(.centralDirectoryEntry) }

            guard flags & ZIPArchive.encryptionFlags == 0 else {
                throw InterchangeError.unsupportedArchive(.encryption)
            }
            guard flags & ~ZIPArchive.permittedFlags == 0 else {
                throw InterchangeError.unsupportedArchive(.flags(flags))
            }
            if compressedSize == 0xFFFF_FFFF || uncompressedSize == 0xFFFF_FFFF || localHeaderOffset == 0xFFFF_FFFF
                || startDisk == 0xFFFF
            {
                throw InterchangeError.unsupportedArchive(.zip64)
            }
            try ZIPArchive.checkExtraField(bytes, range: extraStart..<extraStart + extraLength)
            guard startDisk == 0 else { throw InterchangeError.unsupportedArchive(.multipleDisks) }
            guard method == 0 || method == 8 else {
                throw InterchangeError.unsupportedArchive(.compressionMethod(method))
            }

            guard nameLength <= limits.maximumEntryNameBytes else { throw limits.exceeded(.entryNameBytes) }
            let nameBytes = Array(bytes[nameStart..<extraStart])
            guard UTF8Text.firstInvalidOffset(in: nameBytes, range: 0..<nameBytes.count) == nil else {
                throw InterchangeError.forbiddenEntryName(String(decoding: nameBytes, as: UTF8.self))
            }
            let name = UTF8Text.string(nameBytes)
            try ZIPArchive.validateEntryName(name)
            guard names.insert(name).inserted else { throw InterchangeError.duplicateArchiveEntry(name) }

            let isDirectory = nameBytes.last == UInt8(ascii: "/")
            if method == 0 || isDirectory {
                guard compressedSize == uncompressedSize else { throw InterchangeError.malformedArchive(.sizeMismatch) }
            }
            if isDirectory {
                guard uncompressedSize == 0 else { throw InterchangeError.malformedArchive(.sizeMismatch) }
            }
            guard
                localHeaderOffset + ZIPArchive.localHeaderLength + nameLength + compressedSize <= directoryOffset
            else { throw InterchangeError.malformedArchive(.overlappingEntries) }

            entries.append(
                Entry(
                    name: name, compressedSize: compressedSize, uncompressedSize: uncompressedSize,
                    nameBytes: nameBytes, flags: flags, method: method, crc: crc,
                    localHeaderOffset: localHeaderOffset, dataLimit: directoryOffset))
            position = next
        }
        guard position == endOffset else { throw InterchangeError.malformedArchive(.entryCount) }

        // No member's header and data may run into the next member's: many directory entries over one stretch of
        // compressed data is how an archive is made to inflate far beyond its own ratio.
        let order = entries.indices.sorted { entries[$0].localHeaderOffset < entries[$1].localHeaderOffset }
        for (rank, index) in order.enumerated() where rank + 1 < order.count {
            let entry = entries[index]
            let limit = entries[order[rank + 1]].localHeaderOffset
            let minimumEnd =
                entry.localHeaderOffset + ZIPArchive.localHeaderLength + entry.nameBytes.count + entry.compressedSize
            guard minimumEnd <= limit else { throw InterchangeError.malformedArchive(.overlappingEntries) }
            entries[index].dataLimit = limit
        }
        self.entries = entries
    }

    /// The decompressed contents of the member named exactly `name`, checked against its recorded size and CRC-32.
    /// This is the only way data leaves the archive.
    public func contents(of name: String) throws -> [UInt8] {
        // Byte for byte: string equality would also accept a canonically equivalent spelling of the name.
        let wanted = Array(name.utf8)
        guard let entry = entries.first(where: { $0.nameBytes == wanted }) else {
            throw InterchangeError.missingArchiveEntry(name)
        }
        guard entry.uncompressedSize <= limits.maximumDocumentBytes else { throw limits.exceeded(.documentBytes) }

        let header = entry.localHeaderOffset
        guard entry.dataLimit - header >= ZIPArchive.localHeaderLength,
            ZIPArchive.u32(bytes, header) == ZIPArchive.localSignature
        else { throw InterchangeError.malformedArchive(.localHeader) }
        let flags = UInt16(ZIPArchive.u16(bytes, header + 6))
        let method = UInt16(ZIPArchive.u16(bytes, header + 8))
        let crc = ZIPArchive.u32(bytes, header + 14)
        let compressedSize = Int(ZIPArchive.u32(bytes, header + 18))
        let uncompressedSize = Int(ZIPArchive.u32(bytes, header + 22))
        let nameLength = ZIPArchive.u16(bytes, header + 26)
        let extraLength = ZIPArchive.u16(bytes, header + 28)
        let nameStart = header + ZIPArchive.localHeaderLength
        let dataStart = nameStart + nameLength + extraLength
        guard dataStart <= entry.dataLimit, entry.dataLimit - dataStart >= entry.compressedSize else {
            throw InterchangeError.malformedArchive(.overlappingEntries)
        }
        // A streaming writer can put ZIP64 sizes in the local header alone.
        if compressedSize == 0xFFFF_FFFF || uncompressedSize == 0xFFFF_FFFF {
            throw InterchangeError.unsupportedArchive(.zip64)
        }
        try ZIPArchive.checkExtraField(bytes, range: nameStart + nameLength..<dataStart)
        guard flags == entry.flags, method == entry.method, nameLength == entry.nameBytes.count,
            bytes[nameStart..<nameStart + nameLength].elementsEqual(entry.nameBytes)
        else { throw InterchangeError.malformedArchive(.headerMismatch) }
        // With a data descriptor the local header may leave these zero; otherwise it must agree with the directory,
        // which is the copy this reader acts on.
        let deferred = flags & 0x0008 != 0 && crc == 0 && compressedSize == 0 && uncompressedSize == 0
        guard
            deferred
                || (crc == entry.crc && compressedSize == entry.compressedSize
                    && uncompressedSize == entry.uncompressedSize)
        else { throw InterchangeError.malformedArchive(.headerMismatch) }

        let data = dataStart..<dataStart + entry.compressedSize
        let contents: [UInt8]
        if entry.method == 0 {
            contents = Array(bytes[data])
        } else {
            contents = try Inflater.inflate(
                bytes, range: data, expectedLength: entry.uncompressedSize, limits: limits)
        }
        guard CRC32.checksum(contents) == entry.crc else { throw InterchangeError.checksumMismatch }
        return contents
    }

    /// Refuses a member name that could leave the directory an archive is extracted into (zip-slip): an absolute
    /// path, a drive letter, a `..` or `.` component, an empty component, a backslash (a separator on Windows), or
    /// a control character. Only a trailing slash, marking a directory, may leave a component empty.
    public static func validateEntryName(_ name: String) throws {
        // On bytes, as a file system or an extractor would see the name. By characters, a slash followed by a
        // combining mark is one character that is not a slash, and `../` + U+0301 would pass as an ordinary name.
        let refusal = InterchangeError.forbiddenEntryName(name)
        let bytes = Array(name.utf8)
        let slash = UInt8(ascii: "/")
        let dot = UInt8(ascii: ".")
        guard let first = bytes.first, first != slash else { throw refusal }
        for byte in bytes {
            guard byte >= 0x20, byte != 0x7F, byte != UInt8(ascii: "\\") else { throw refusal }
        }
        let isLetter =
            (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(first)
            || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(first)
        if isLetter, bytes.count >= 2, bytes[1] == UInt8(ascii: ":") { throw refusal }
        var components = bytes.split(separator: slash, omittingEmptySubsequences: false)
        if components.last?.isEmpty == true {
            components.removeLast()
        }
        guard !components.isEmpty else { throw refusal }
        for component in components {
            guard !component.isEmpty, !component.elementsEqual([dot]), !component.elementsEqual([dot, dot]) else {
                throw refusal
            }
        }
    }

    /// An extra field is a list of `id(2) length(2) data` blocks. Only its shape and the ZIP64 block are of interest.
    private static func checkExtraField(_ bytes: [UInt8], range: Range<Int>) throws {
        var position = range.lowerBound
        while position < range.upperBound {
            guard range.upperBound - position >= 4 else { throw InterchangeError.malformedArchive(.extraField) }
            let identifier = u16(bytes, position)
            let length = u16(bytes, position + 2)
            guard range.upperBound - (position + 4) >= length else {
                throw InterchangeError.malformedArchive(.extraField)
            }
            if identifier == 0x0001 { throw InterchangeError.unsupportedArchive(.zip64) }
            position += 4 + length
        }
    }

    /// Little-endian reads. Callers have checked the bounds; an unchecked one traps rather than reads out of range.
    private static func u16(_ bytes: [UInt8], _ offset: Int) -> Int {
        Int(bytes[offset]) | Int(bytes[offset + 1]) << 8
    }

    private static func u32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) | UInt32(bytes[offset + 1]) << 8 | UInt32(bytes[offset + 2]) << 16
            | UInt32(bytes[offset + 3]) << 24
    }
}

/// Writes a ZIP archive of stored (uncompressed) members, for the 1PUX-compatible export (PRD F8.4). The output is
/// deterministic: fixed timestamps, members in the order given.
public enum ZIPWriter {
    public struct Member: Hashable, Sendable {
        public var name: String
        public var contents: [UInt8]

        public init(name: String, contents: [UInt8]) {
            self.name = name
            self.contents = contents
        }
    }

    /// The archive. Names are held to the same rules the reader applies, and the result to the reader's size limit,
    /// so this module never writes an archive it would refuse to read.
    public static func archive(_ members: [Member], limits: InterchangeLimits = .standard) throws -> [UInt8] {
        guard members.count <= min(limits.maximumArchiveEntries, 0xFFFE) else {
            throw limits.exceeded(.archiveEntries)
        }
        var names = Set<String>()
        var total = 22
        for member in members {
            try ZIPArchive.validateEntryName(member.name)
            guard member.name.utf8.count <= limits.maximumEntryNameBytes else { throw limits.exceeded(.entryNameBytes) }
            guard names.insert(member.name).inserted else { throw InterchangeError.duplicateArchiveEntry(member.name) }
            guard member.contents.count <= limits.maximumDocumentBytes else { throw limits.exceeded(.documentBytes) }
            total += 30 + 46 + 2 * member.name.utf8.count + member.contents.count
            guard total <= limits.maximumInputBytes else { throw limits.exceeded(.inputBytes) }
        }

        var output: [UInt8] = []
        output.reserveCapacity(total)
        var directory: [UInt8] = []
        for member in members {
            let name = Array(member.name.utf8)
            let crc = CRC32.checksum(member.contents)
            let offset = output.count
            // version needed 2.0, UTF-8 names, stored, 1980-01-01 00:00.
            let common: [UInt8] = [20, 0, 0x00, 0x08, 0, 0, 0, 0, 0x21, 0]
            append32(0x0403_4B50, to: &output)
            output.append(contentsOf: common)
            append32(crc, to: &output)
            append32(UInt32(member.contents.count), to: &output)
            append32(UInt32(member.contents.count), to: &output)
            append16(name.count, to: &output)
            append16(0, to: &output)
            output.append(contentsOf: name)
            output.append(contentsOf: member.contents)

            append32(0x0201_4B50, to: &directory)
            directory.append(contentsOf: [20, 0])
            directory.append(contentsOf: common)
            append32(crc, to: &directory)
            append32(UInt32(member.contents.count), to: &directory)
            append32(UInt32(member.contents.count), to: &directory)
            append16(name.count, to: &directory)
            // Extra length, comment length, start disk, internal attributes; then external attributes.
            directory.append(contentsOf: [UInt8](repeating: 0, count: 8))
            append32(0, to: &directory)
            append32(UInt32(offset), to: &directory)
            directory.append(contentsOf: name)
        }
        let directoryOffset = output.count
        output.append(contentsOf: directory)
        append32(0x0605_4B50, to: &output)
        output.append(contentsOf: [0, 0, 0, 0])
        append16(members.count, to: &output)
        append16(members.count, to: &output)
        append32(UInt32(directory.count), to: &output)
        append32(UInt32(directoryOffset), to: &output)
        append16(0, to: &output)
        return output
    }

    private static func append16(_ value: Int, to output: inout [UInt8]) {
        output.append(UInt8(value & 0xFF))
        output.append(UInt8((value >> 8) & 0xFF))
    }

    private static func append32(_ value: UInt32, to output: inout [UInt8]) {
        for shift in stride(from: 0, through: 24, by: 8) {
            output.append(UInt8((value >> UInt32(shift)) & 0xFF))
        }
    }
}
