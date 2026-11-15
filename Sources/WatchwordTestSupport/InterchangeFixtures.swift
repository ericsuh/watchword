import Foundation

/// Builds ZIP archives byte by byte for import tests, with every header field open to being wrong: the archives a
/// hostile 1PUX file is made of (docs/04-test-plan.md §6.5) cannot be produced by a well-behaved ZIP writer.
///
/// Independent of `WatchwordInterchange` on purpose, down to its own CRC-32, so a test never checks the reader
/// against the writer it ships with.
public struct ZIPFixture: Sendable {
    public struct Member: Sendable {
        /// Raw bytes, so a name need not be valid UTF-8.
        public var name: [UInt8]
        /// The member's uncompressed contents.
        public var contents: [UInt8]
        /// The bytes stored in the archive when they differ from `contents`: a DEFLATE stream.
        public var data: [UInt8]?
        public var method: UInt16
        public var flags: UInt16
        /// Overrides, for archives that lie. `nil` is the honest value.
        public var crc: UInt32?
        public var declaredCompressedSize: UInt32?
        public var declaredUncompressedSize: UInt32?
        public var localName: [UInt8]?
        public var localHeaderOffset: UInt32?
        public var localMethod: UInt16?
        public var extra: [UInt8]
        public var startDisk: UInt16
        /// Leave the local header's CRC and sizes zero and append a data descriptor, as a streaming writer does.
        public var usesDataDescriptor: Bool

        public init(
            name: String, contents: [UInt8], data: [UInt8]? = nil, method: UInt16? = nil, flags: UInt16 = 0x0800,
            crc: UInt32? = nil, declaredCompressedSize: UInt32? = nil, declaredUncompressedSize: UInt32? = nil,
            localName: [UInt8]? = nil, localHeaderOffset: UInt32? = nil, localMethod: UInt16? = nil,
            extra: [UInt8] = [], startDisk: UInt16 = 0, usesDataDescriptor: Bool = false
        ) {
            self.name = Array(name.utf8)
            self.contents = contents
            self.data = data
            self.method = method ?? (data == nil ? 0 : 8)
            self.flags = flags
            self.crc = crc
            self.declaredCompressedSize = declaredCompressedSize
            self.declaredUncompressedSize = declaredUncompressedSize
            self.localName = localName
            self.localHeaderOffset = localHeaderOffset
            self.localMethod = localMethod
            self.extra = extra
            self.startDisk = startDisk
            self.usesDataDescriptor = usesDataDescriptor
        }
    }

    public var members: [Member]
    public var comment: [UInt8]
    /// Bytes before the first local header.
    public var prefix: [UInt8]
    public var declaredEntryCount: UInt16?
    public var diskNumber: UInt16
    public var directoryDisk: UInt16
    /// Added to the central directory offset the end record declares.
    public var directoryOffsetAdjustment: Int
    /// Bytes inserted between the central directory and the end record.
    public var beforeEndRecord: [UInt8]

    public init(
        _ members: [Member], comment: [UInt8] = [], prefix: [UInt8] = [], declaredEntryCount: UInt16? = nil,
        diskNumber: UInt16 = 0, directoryDisk: UInt16 = 0, directoryOffsetAdjustment: Int = 0,
        beforeEndRecord: [UInt8] = []
    ) {
        self.members = members
        self.comment = comment
        self.prefix = prefix
        self.declaredEntryCount = declaredEntryCount
        self.diskNumber = diskNumber
        self.directoryDisk = directoryDisk
        self.directoryOffsetAdjustment = directoryOffsetAdjustment
        self.beforeEndRecord = beforeEndRecord
    }

    /// The archive.
    public func bytes() -> [UInt8] {
        var output = prefix
        var directory: [UInt8] = []
        for member in members {
            let data = member.data ?? member.contents
            let crc = member.crc ?? ZIPFixture.crc32(member.contents)
            let compressedSize = member.declaredCompressedSize ?? UInt32(data.count)
            let uncompressedSize = member.declaredUncompressedSize ?? UInt32(member.contents.count)
            let flags = member.usesDataDescriptor ? member.flags | 0x0008 : member.flags
            let offset = member.localHeaderOffset ?? UInt32(output.count)
            let localName = member.localName ?? member.name

            ZIPFixture.append32(0x0403_4B50, to: &output)
            ZIPFixture.append16(20, to: &output)
            ZIPFixture.append16(flags, to: &output)
            ZIPFixture.append16(member.localMethod ?? member.method, to: &output)
            ZIPFixture.append32(0x0021_0000, to: &output)
            ZIPFixture.append32(member.usesDataDescriptor ? 0 : crc, to: &output)
            ZIPFixture.append32(member.usesDataDescriptor ? 0 : compressedSize, to: &output)
            ZIPFixture.append32(member.usesDataDescriptor ? 0 : uncompressedSize, to: &output)
            ZIPFixture.append16(UInt16(localName.count), to: &output)
            ZIPFixture.append16(0, to: &output)
            output += localName
            output += data
            if member.usesDataDescriptor {
                ZIPFixture.append32(0x0807_4B50, to: &output)
                ZIPFixture.append32(crc, to: &output)
                ZIPFixture.append32(compressedSize, to: &output)
                ZIPFixture.append32(uncompressedSize, to: &output)
            }

            ZIPFixture.append32(0x0201_4B50, to: &directory)
            ZIPFixture.append16(20, to: &directory)
            ZIPFixture.append16(20, to: &directory)
            ZIPFixture.append16(flags, to: &directory)
            ZIPFixture.append16(member.method, to: &directory)
            ZIPFixture.append32(0x0021_0000, to: &directory)
            ZIPFixture.append32(crc, to: &directory)
            ZIPFixture.append32(compressedSize, to: &directory)
            ZIPFixture.append32(uncompressedSize, to: &directory)
            ZIPFixture.append16(UInt16(member.name.count), to: &directory)
            ZIPFixture.append16(UInt16(member.extra.count), to: &directory)
            ZIPFixture.append16(0, to: &directory)
            ZIPFixture.append16(member.startDisk, to: &directory)
            ZIPFixture.append16(0, to: &directory)
            ZIPFixture.append32(0, to: &directory)
            ZIPFixture.append32(offset, to: &directory)
            directory += member.name
            directory += member.extra
        }
        let directoryOffset = output.count
        output += directory
        output += beforeEndRecord
        let count = declaredEntryCount ?? UInt16(members.count)
        ZIPFixture.append32(0x0605_4B50, to: &output)
        ZIPFixture.append16(diskNumber, to: &output)
        ZIPFixture.append16(directoryDisk, to: &output)
        ZIPFixture.append16(count, to: &output)
        ZIPFixture.append16(count, to: &output)
        ZIPFixture.append32(UInt32(directory.count), to: &output)
        ZIPFixture.append32(UInt32(directoryOffset + directoryOffsetAdjustment), to: &output)
        ZIPFixture.append16(UInt16(comment.count), to: &output)
        output += comment
        return output
    }

    /// CRC-32 computed a bit at a time: slow, and nothing like the table-driven one under test.
    public static func crc32(_ bytes: [UInt8]) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                crc = crc & 1 == 1 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1
            }
        }
        return ~crc
    }

    private static func append16(_ value: UInt16, to output: inout [UInt8]) {
        output.append(UInt8(value & 0xFF))
        output.append(UInt8(value >> 8))
    }

    private static func append32(_ value: UInt32, to output: inout [UInt8]) {
        for shift in stride(from: UInt32(0), through: 24, by: 8) {
            output.append(UInt8((value >> shift) & 0xFF))
        }
    }
}

/// Hand-assembled DEFLATE streams for the cases no compressor will produce: bombs and malformed blocks.
public struct DeflateFixture: Sendable {
    public private(set) var bytes: [UInt8] = []
    private var bitCount = 0

    public init() {}

    /// Appends the low `count` bits of `value`, least significant first, as RFC 1951 packs header and extra bits.
    public mutating func append(bits value: UInt32, count: Int) {
        for index in 0..<count {
            if bitCount % 8 == 0 { bytes.append(0) }
            if (value >> UInt32(index)) & 1 == 1 {
                bytes[bytes.count - 1] |= UInt8(1 << (bitCount % 8))
            }
            bitCount += 1
        }
    }

    /// Appends a Huffman code, most significant bit first, as RFC 1951 packs codes.
    public mutating func append(code: UInt32, length: Int) {
        for index in stride(from: length - 1, through: 0, by: -1) {
            append(bits: (code >> UInt32(index)) & 1, count: 1)
        }
    }

    /// A single fixed-Huffman block that inflates to `count` zero bytes: one literal, then matches of the greatest
    /// length at distance one. About 158 bytes out for each byte in: a decompression bomb.
    public static func zeros(count: Int) -> [UInt8] {
        precondition(count >= 1)
        var stream = DeflateFixture()
        stream.append(bits: 1, count: 1)
        stream.append(bits: 1, count: 2)
        // Literal 0 is the eight-bit code 00110000.
        stream.append(code: 0b0011_0000, length: 8)
        var remaining = count - 1
        while remaining > 0 {
            let length = min(remaining, 258)
            guard length >= 3 else {
                for _ in 0..<length {
                    stream.append(code: 0b0011_0000, length: 8)
                }
                break
            }
            stream.appendFixedLength(length)
            // Distance 1 is the five-bit code 00000.
            stream.append(code: 0, length: 5)
            remaining -= length
        }
        // End of block is the seven-bit code 0000000.
        stream.append(code: 0, length: 7)
        return stream.bytes
    }

    /// The fixed-Huffman code for a match length (RFC 1951 §3.2.5 and §3.2.6).
    private mutating func appendFixedLength(_ length: Int) {
        let bases = [
            3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195,
            227, 258,
        ]
        let extras = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
        let index = bases.lastIndex { $0 <= length }!
        let symbol = 257 + index
        if symbol <= 279 {
            append(code: UInt32(symbol - 256), length: 7)
        } else {
            append(code: UInt32(0b1100_0000 + symbol - 280), length: 8)
        }
        append(bits: UInt32(length - bases[index]), count: extras[index])
    }

    /// `bytes` as stored blocks.
    public static func stored(_ bytes: [UInt8]) -> [UInt8] {
        var output: [UInt8] = []
        var offset = 0
        repeat {
            let length = min(bytes.count - offset, 0xFFFF)
            output.append(offset + length == bytes.count ? 1 : 0)
            output += [UInt8(length & 0xFF), UInt8(length >> 8), UInt8(~length & 0xFF), UInt8((~length >> 8) & 0xFF)]
            output += bytes[offset..<offset + length]
            offset += length
        } while offset < bytes.count
        return output
    }
}
