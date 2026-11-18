import Foundation
import WatchwordCrypto
import WatchwordSharing

/// Two accounts, a sharing board and a key directory for vault sharing code sessions (ADR 0010), driven step by step
/// without a `VaultSession`: the protocol core as `VaultSession+SharingCode.swift` drives it. Test code only.
public struct SharingCodeRig: Sendable {
    public static let now = Date(timeIntervalSince1970: 1_800_000_000)

    public let starter: SharingParty
    public let joiner: SharingParty
    public let board = InMemorySharingBoard()
    public let directory = InMemoryKeyBundleDirectory()

    public init(seed: UInt64) async throws {
        starter = try SharingParty(seed: seed)
        joiner = try SharingParty(seed: seed + 1)
        await directory.publish(starter.bundle)
        await directory.publish(joiner.bundle)
    }

    /// A starter whose commitment is on `board`.
    public func start(seed: UInt64, on board: (any SharingBoard)? = nil, at now: Date = SharingCodeRig.now)
        async throws -> SharingCodeStarter
    {
        var generator = SeededGenerator(seed: seed)
        var session = SharingCodeStarter.draw(as: starter.bundle, using: &generator, at: now)
        try await session.publish(on: board ?? self.board, at: now)
        return session
    }

    /// The joiner answering `number`, with a nonce drawn from `seed`.
    public func join(
        _ number: SharingSessionNumber, seed: UInt64, scanned: ScannedSharingCode? = nil, as party: SharingParty? = nil,
        board: (any SharingBoard)? = nil, directory: (any KeyBundleDirectory)? = nil,
        at now: Date = SharingCodeRig.now
    ) async throws -> SharingCodeJoiner {
        var generator = SeededGenerator(seed: seed)
        return try await SharingCodeJoiner.join(
            number, scanned: scanned, as: (party ?? joiner).bundle, board: board ?? self.board,
            directory: directory ?? self.directory, nonce: SharingNonce.draw(using: &generator), at: now)
    }

    /// The digits of a grouped code ("123 456" as "123456").
    public static func digits(_ code: String?) -> String {
        (code ?? "").filter(\.isNumber)
    }

    /// A six-digit code that is not `code`.
    public static func wrong(_ code: String?) -> String {
        let digits = Self.digits(code)
        guard let first = digits.first else { return "000000" }
        return (first == "0" ? "1" : "0") + digits.dropFirst()
    }
}
