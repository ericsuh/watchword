import Foundation

/// A DEFLATE decompressor (RFC 1951) in safe Swift, for the one compressed member a 1PUX archive is read for
/// (docs/02-architecture.md §14).
///
/// Written here rather than taken from zlib or Compression.framework because the input is hostile (adversary A7) and
/// the module is portable and has no unsafe code: every index is bounds-checked by the language, and every way a
/// stream can be malformed ends in a `DeflateDefect`. Output is capped *while* inflating, so a decompression bomb
/// costs at most the cap, and the work done is linear in the compressed and decompressed sizes.
///
/// Strictness follows zlib's `inflate`: over-subscribed and incomplete code sets are refused (a lone one-bit code is
/// the permitted exception), a block must be able to end, and distances may not reach before the output. Bytes left
/// after the final block are refused too, which zlib leaves to its caller. One thing zlib accepts is refused here: a
/// stream of more than a thousand blocks that average under 256 bytes of output each (`DeflateDefect.excessiveBlocks`),
/// which no compressor writes and which is otherwise the cheapest way to buy work with input.
public enum Inflater {
    /// Inflates a raw DEFLATE stream. The output may be at most `limits.maximumCompressionRatio` times the size of
    /// `compressed`, and at most `limits.maximumDocumentBytes`; reaching either cap stops the work and throws
    /// `InterchangeError.limitExceeded`.
    public static func inflate(_ compressed: [UInt8], limits: InterchangeLimits = .standard) throws -> [UInt8] {
        try limits.checkInput(compressed.count)
        return try inflate(compressed, range: 0..<compressed.count, expectedLength: nil, limits: limits)
    }

    /// Inflates `range` of `bytes`. With `expectedLength`, the output must be exactly that long, and it is refused
    /// before any work if it already exceeds a cap.
    static func inflate(_ bytes: [UInt8], range: Range<Int>, expectedLength: Int?, limits: InterchangeLimits) throws
        -> [UInt8]
    {
        let (ratioCap, overflow) = range.count.multipliedReportingOverflow(by: limits.maximumCompressionRatio)
        var cap = limits.maximumDocumentBytes
        var capError = limits.exceeded(.documentBytes)
        if !overflow, ratioCap < cap {
            cap = ratioCap
            capError = limits.exceeded(.compressionRatio)
        }
        if let expectedLength {
            guard expectedLength >= 0 else { throw InterchangeError.malformedDeflate(.lengthMismatch) }
            guard expectedLength <= limits.maximumDocumentBytes else { throw limits.exceeded(.documentBytes) }
            guard expectedLength <= cap else { throw capError }
        }
        var stream = InflateStream(bytes: bytes, range: range, cap: cap, capError: capError)
        // A declared length also bounds the output, so a stream that lies about its size stops at the lie.
        if let expectedLength {
            stream.cap = expectedLength
            stream.capError = InterchangeError.malformedDeflate(.lengthMismatch)
        }
        try stream.run()
        if let expectedLength, stream.output.count != expectedLength {
            throw InterchangeError.malformedDeflate(.lengthMismatch)
        }
        return stream.output
    }

    /// `bytes` as a valid DEFLATE stream of stored blocks: no compression, for the few places an export format asks
    /// for DEFLATE data and this module has no compressor.
    static func storedStream(_ bytes: [UInt8]) -> [UInt8] {
        var output: [UInt8] = []
        output.reserveCapacity(bytes.count + 5 * (bytes.count / 0xFFFF + 1))
        var offset = 0
        repeat {
            let length = min(bytes.count - offset, 0xFFFF)
            let final = offset + length == bytes.count
            output.append(final ? 1 : 0)
            output.append(UInt8(length & 0xFF))
            output.append(UInt8(length >> 8))
            output.append(UInt8(~length & 0xFF))
            output.append(UInt8((~length >> 8) & 0xFF))
            output.append(contentsOf: bytes[offset..<offset + length])
            offset += length
        } while offset < bytes.count
        return output
    }
}

/// A canonical Huffman code as RFC 1951 §3.2.2 defines one: the number of codes of each length, and the symbols in
/// code order.
struct HuffmanCode {
    static let maximumLength = 15

    var counts: [Int]
    var symbols: [Int]
    /// The unused part of the code space, in units of the longest code: zero for a complete set.
    var unused: Int
    var longest: Int

    /// Builds the code for `lengths` (one per symbol, zero for an unused symbol). Throws for an over-subscribed set:
    /// more codes of some length than the shorter codes leave room for.
    init(lengths: ArraySlice<Int>) throws {
        var counts = [Int](repeating: 0, count: HuffmanCode.maximumLength + 1)
        for length in lengths {
            counts[length] += 1
        }
        var left = 1
        var longest = 0
        for length in 1...HuffmanCode.maximumLength {
            left <<= 1
            left -= counts[length]
            guard left >= 0 else { throw InterchangeError.malformedDeflate(.invalidCodeLengths) }
            if counts[length] > 0 { longest = length }
        }
        var offsets = [Int](repeating: 0, count: HuffmanCode.maximumLength + 2)
        for length in 1...HuffmanCode.maximumLength {
            offsets[length + 1] = offsets[length] + counts[length]
        }
        var symbols = [Int](repeating: 0, count: lengths.count - counts[0])
        for (symbol, length) in lengths.enumerated() where length != 0 {
            symbols[offsets[length]] = symbol
            offsets[length] += 1
        }
        self.counts = counts
        self.symbols = symbols
        self.unused = left
        self.longest = longest
    }

    /// The fixed codes of RFC 1951 §3.2.6. Both are complete, and both can spell symbols no block may use
    /// (literal/length 286 and 287, distance 30 and 31), which the decoder refuses when it meets them.
    static let fixedLiteral: HuffmanCode = {
        var lengths = [Int](repeating: 8, count: 288)
        for symbol in 144..<256 {
            lengths[symbol] = 9
        }
        for symbol in 256..<280 {
            lengths[symbol] = 7
        }
        return try! HuffmanCode(lengths: lengths[...])
    }()
    static let fixedDistance: HuffmanCode = try! HuffmanCode(lengths: [Int](repeating: 5, count: 32)[...])
}

private struct InflateStream {
    private static let lengthBase = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227,
        258,
    ]
    private static let lengthExtra = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ]
    private static let distanceBase = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
        6145, 8193, 12289, 16385, 24577,
    ]
    private static let distanceExtra = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
    ]
    private static let codeLengthOrder = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

    let bytes: [UInt8]
    var position: Int
    let end: Int
    /// Bits read from `bytes` and not yet consumed, least significant first.
    var buffer: UInt64 = 0
    var buffered = 0
    var output: [UInt8] = []
    var cap: Int
    var capError: InterchangeError

    init(bytes: [UInt8], range: Range<Int>, cap: Int, capError: InterchangeError) {
        self.bytes = bytes
        self.position = range.lowerBound
        self.end = range.upperBound
        self.cap = cap
        self.capError = capError
    }

    /// Blocks a stream may hold whatever they emit: far more than a compressor's flushes leave in a document.
    static let unaccountedBlocks = 1_024
    /// Beyond those, the output a stream must have produced for each block it has begun. zlib ends a block every
    /// sixteen thousand symbols and a stored block holds up to 64 KiB, so only a writer that flushes every few
    /// bytes, thousands of times, comes near this; at this figure the worst a 100 MB document can ask for is four
    /// hundred thousand block headers.
    static let bytesPerAccountedBlock = 256

    mutating func run() throws {
        var final = false
        var blocks = 0
        repeat {
            // A block's header costs a fixed amount of work (three code tables for a dynamic one) whatever the block
            // emits, and an empty dynamic block is under twelve bytes: without this, 100 MB of them is half a
            // minute of work for no output, which neither the ratio cap nor the document cap would notice.
            blocks += 1
            guard blocks - InflateStream.unaccountedBlocks <= output.count / InflateStream.bytesPerAccountedBlock
            else { throw InterchangeError.malformedDeflate(.excessiveBlocks) }
            final = try bits(1) == 1
            switch try bits(2) {
            case 0: try storedBlock()
            case 1: try compressedBlock(literal: .fixedLiteral, distance: .fixedDistance)
            case 2: try dynamicBlock()
            default: throw InterchangeError.malformedDeflate(.reservedBlockType)
            }
        } while !final
        alignToByte()
        guard position == end else { throw InterchangeError.malformedDeflate(.trailingData) }
    }

    /// Reads `count` bits (at most 16), least significant first.
    private mutating func bits(_ count: Int) throws -> Int {
        while buffered < count {
            guard position < end else { throw InterchangeError.malformedDeflate(.truncated) }
            buffer |= UInt64(bytes[position]) << UInt64(buffered)
            position += 1
            buffered += 8
        }
        let value = Int(buffer & ((1 << UInt64(count)) - 1))
        buffer >>= UInt64(count)
        buffered -= count
        return value
    }

    /// Drops the rest of the current byte and hands whole buffered bytes back to `position`.
    private mutating func alignToByte() {
        position -= buffered / 8
        buffer = 0
        buffered = 0
    }

    /// Decodes one symbol: walks the code a bit at a time, as RFC 1951 §3.2.2 lays it out, over bits fetched ahead.
    private mutating func symbol(_ code: HuffmanCode) throws -> Int {
        while buffered < HuffmanCode.maximumLength, position < end {
            buffer |= UInt64(bytes[position]) << UInt64(buffered)
            position += 1
            buffered += 8
        }
        var pending = buffer
        var value = 0
        var first = 0
        var index = 0
        for length in 1...HuffmanCode.maximumLength {
            guard length <= buffered else { throw InterchangeError.malformedDeflate(.truncated) }
            value |= Int(pending & 1)
            pending >>= 1
            let count = code.counts[length]
            if value - count < first {
                buffer >>= UInt64(length)
                buffered -= length
                return code.symbols[index + (value - first)]
            }
            index += count
            first += count
            first <<= 1
            value <<= 1
        }
        throw InterchangeError.malformedDeflate(.invalidSymbol)
    }

    private mutating func storedBlock() throws {
        alignToByte()
        guard end - position >= 4 else { throw InterchangeError.malformedDeflate(.truncated) }
        let length = Int(bytes[position]) | Int(bytes[position + 1]) << 8
        let complement = Int(bytes[position + 2]) | Int(bytes[position + 3]) << 8
        guard length == ~complement & 0xFFFF else { throw InterchangeError.malformedDeflate(.storedLengthMismatch) }
        position += 4
        guard end - position >= length else { throw InterchangeError.malformedDeflate(.truncated) }
        guard cap - output.count >= length else { throw capError }
        output.append(contentsOf: bytes[position..<position + length])
        position += length
    }

    private mutating func dynamicBlock() throws {
        let literalCount = try bits(5) + 257
        let distanceCount = try bits(5) + 1
        let codeLengthCount = try bits(4) + 4
        guard literalCount <= 286, distanceCount <= 30 else {
            throw InterchangeError.malformedDeflate(.invalidCodeLengths)
        }
        var codeLengths = [Int](repeating: 0, count: 19)
        for index in 0..<codeLengthCount {
            codeLengths[InflateStream.codeLengthOrder[index]] = try bits(3)
        }
        let codeLengthCode = try HuffmanCode(lengths: codeLengths[...])
        guard codeLengthCode.unused == 0 else { throw InterchangeError.malformedDeflate(.invalidCodeLengths) }

        let total = literalCount + distanceCount
        var lengths = [Int](repeating: 0, count: total)
        var index = 0
        while index < total {
            let symbol = try symbol(codeLengthCode)
            if symbol < 16 {
                lengths[index] = symbol
                index += 1
                continue
            }
            var value = 0
            let repeats: Int
            switch symbol {
            case 16:
                guard index > 0 else { throw InterchangeError.malformedDeflate(.invalidCodeLengths) }
                value = lengths[index - 1]
                repeats = 3 + (try bits(2))
            case 17:
                repeats = 3 + (try bits(3))
            default:
                repeats = 11 + (try bits(7))
            }
            guard index + repeats <= total else { throw InterchangeError.malformedDeflate(.invalidCodeLengths) }
            for _ in 0..<repeats {
                lengths[index] = value
                index += 1
            }
        }
        guard lengths[256] != 0 else { throw InterchangeError.malformedDeflate(.missingEndOfBlock) }
        let literal = try HuffmanCode(lengths: lengths[..<literalCount])
        // An incomplete set is an error unless it is a single one-bit code (zlib's rule); a distance set may also be
        // empty, for a block of literals only.
        guard literal.unused == 0 || literal.longest == 1 else {
            throw InterchangeError.malformedDeflate(.invalidCodeLengths)
        }
        let distance = try HuffmanCode(lengths: lengths[literalCount...])
        guard distance.unused == 0 || distance.longest <= 1 else {
            throw InterchangeError.malformedDeflate(.invalidCodeLengths)
        }
        try compressedBlock(literal: literal, distance: distance)
    }

    private mutating func compressedBlock(literal: HuffmanCode, distance: HuffmanCode) throws {
        while true {
            let symbol = try symbol(literal)
            if symbol < 256 {
                guard output.count < cap else { throw capError }
                output.append(UInt8(symbol))
                continue
            }
            if symbol == 256 { return }
            let lengthIndex = symbol - 257
            guard lengthIndex < InflateStream.lengthBase.count else {
                throw InterchangeError.malformedDeflate(.invalidSymbol)
            }
            let length = InflateStream.lengthBase[lengthIndex] + (try bits(InflateStream.lengthExtra[lengthIndex]))
            let distanceIndex = try self.symbol(distance)
            guard distanceIndex < InflateStream.distanceBase.count else {
                throw InterchangeError.malformedDeflate(.invalidSymbol)
            }
            let offset =
                InflateStream.distanceBase[distanceIndex] + (try bits(InflateStream.distanceExtra[distanceIndex]))
            guard offset <= output.count else { throw InterchangeError.malformedDeflate(.distanceTooFar) }
            guard cap - output.count >= length else { throw capError }
            // Byte by byte: the source may overlap the bytes being written, which is how a run is encoded.
            let start = output.count - offset
            for step in 0..<length {
                output.append(output[start + step])
            }
        }
    }
}

/// CRC-32 (IEEE 802.3, the polynomial ZIP uses), table-driven.
public enum CRC32 {
    private static let table: [UInt32] = (0..<256).map { index in
        var value = UInt32(index)
        for _ in 0..<8 {
            value = value & 1 == 1 ? 0xEDB8_8320 ^ (value >> 1) : value >> 1
        }
        return value
    }

    public static func checksum(_ bytes: some Sequence<UInt8>) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            crc = table[Int((crc ^ UInt32(byte)) & 0xFF)] ^ (crc >> 8)
        }
        return crc ^ 0xFFFF_FFFF
    }
}
