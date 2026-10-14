import Foundation

extension UUID {
    var byteArray: [UInt8] {
        let u = uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }

    init(byteArray b: [UInt8]) {
        precondition(b.count == 16)
        self.init(
            uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
        )
    }

    /// A version-4 UUID drawn from `generator`, so key IDs are reproducible under a seeded test generator.
    static func randomVersion4<R: RandomNumberGenerator>(using generator: inout R) -> UUID {
        var bytes = (0..<2).flatMap { _ in
            let word = generator.next()
            return (0..<8).map { UInt8(truncatingIfNeeded: word >> (8 * $0)) }
        }
        bytes[6] = (bytes[6] & 0x0F) | 0x40
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return UUID(byteArray: bytes)
    }
}
