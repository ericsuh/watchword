import Foundation

/// The few CBOR items a WebAuthn authenticator emits (RFC 8949), written in CTAP2 canonical form: shortest-form
/// heads, definite lengths, and map keys in the order the caller writes them, which every caller here writes already
/// sorted.
///
/// An encoder only. Nothing in this module parses CBOR: what the relying party sends reaches the extension as values
/// the operating system has already decoded, so no attacker-supplied CBOR meets a parser here. `WatchwordEnvelope`'s
/// `CBORValue` is not used because it has, deliberately, neither negative integers nor text strings, and a COSE key
/// and an attestation object need both.
struct CBORWriter {
    private(set) var bytes: [UInt8] = []

    mutating func unsigned(_ value: UInt64) {
        head(major: 0, argument: value)
    }

    /// The negative integer `-1 - magnitude` (so `negative(6)` is -7).
    mutating func negative(_ magnitude: UInt64) {
        head(major: 1, argument: magnitude)
    }

    mutating func byteString(_ value: some Collection<UInt8>) {
        head(major: 2, argument: UInt64(value.count))
        bytes.append(contentsOf: value)
    }

    /// ASCII only: every text string an authenticator writes is a fixed key or format name.
    mutating func text(_ value: StaticString) {
        let utf8 = Array(value.description.utf8)
        precondition(utf8.allSatisfy { $0 < 0x80 }, "non-ASCII CBOR text")
        head(major: 3, argument: UInt64(utf8.count))
        bytes.append(contentsOf: utf8)
    }

    mutating func mapHeader(count: UInt64) {
        head(major: 5, argument: count)
    }

    private mutating func head(major: UInt8, argument: UInt64) {
        let type = major << 5
        switch argument {
        case 0..<24:
            bytes.append(type | UInt8(argument))
        case 24...0xFF:
            bytes.append(type | 24)
            bigEndian(argument, byteCount: 1)
        case 0x100...0xFFFF:
            bytes.append(type | 25)
            bigEndian(argument, byteCount: 2)
        case 0x1_0000...0xFFFF_FFFF:
            bytes.append(type | 26)
            bigEndian(argument, byteCount: 4)
        default:
            bytes.append(type | 27)
            bigEndian(argument, byteCount: 8)
        }
    }

    private mutating func bigEndian(_ value: UInt64, byteCount: Int) {
        for shift in stride(from: (byteCount - 1) * 8, through: 0, by: -8) {
            bytes.append(UInt8(truncatingIfNeeded: value >> UInt64(shift)))
        }
    }
}

/// The flags byte of authenticator data (WebAuthn §6.1).
public struct AuthenticatorFlags: OptionSet, Hashable, Sendable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// UP: the person took part in this request.
    public static let userPresent = AuthenticatorFlags(rawValue: 0x01)
    /// UV: the person was verified (password or biometry) for this request.
    public static let userVerified = AuthenticatorFlags(rawValue: 0x04)
    /// BE: the credential may be synced. Fixed for the credential's lifetime.
    public static let backupEligible = AuthenticatorFlags(rawValue: 0x08)
    /// BS: the credential is synced now.
    public static let backedUp = AuthenticatorFlags(rawValue: 0x10)
    /// AT: attested credential data follows the counter (registration only).
    public static let attestedCredentialData = AuthenticatorFlags(rawValue: 0x40)
    /// ED: extension data follows. Never set: `prf` and `largeBlob` results are client extension outputs.
    public static let extensionData = AuthenticatorFlags(rawValue: 0x80)
}

enum WebAuthnEncoding {
    /// `rpIdHash ‖ flags ‖ signCount`, then attested credential data when registering.
    ///
    /// The signature counter is always zero: a synced credential has no single counter to keep, and Apple's guidance
    /// for synced passkeys is to leave it at zero, which a relying party reads as "no counter"
    /// (docs/02-architecture.md §9.1).
    static func authenticatorData(
        relyingParty: RelyingPartyID, flags: AuthenticatorFlags, attested: (credentialID: Data, coseKey: [UInt8])? = nil
    ) -> Data {
        var data = relyingParty.hash
        data.append(flags.rawValue)
        data.append(contentsOf: [0, 0, 0, 0])
        if let attested {
            data.append(contentsOf: PasskeyAuthenticator.aaguidBytes)
            data.append(UInt8(truncatingIfNeeded: attested.credentialID.count >> 8))
            data.append(UInt8(truncatingIfNeeded: attested.credentialID.count))
            data.append(attested.credentialID)
            data.append(contentsOf: attested.coseKey)
        }
        return data
    }

    /// The COSE_Key of an ES256 public key (RFC 9053 §2.1, RFC 9052 §7): `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`, an
    /// EC2 key on P-256 for ECDSA with SHA-256. `x963` is the uncompressed point `04 ‖ x ‖ y`.
    static func coseES256Key(x963: Data) -> [UInt8] {
        precondition(x963.count == 65 && x963.first == 0x04, "not an uncompressed P-256 point")
        let coordinates = Array(x963.dropFirst())
        var writer = CBORWriter()
        writer.mapHeader(count: 5)
        writer.unsigned(1)  // kty
        writer.unsigned(2)  // EC2
        writer.unsigned(3)  // alg
        writer.negative(6)  // ES256 (-7)
        writer.negative(0)  // crv (-1)
        writer.unsigned(1)  // P-256
        writer.negative(1)  // x (-2)
        writer.byteString(coordinates[0..<32])
        writer.negative(2)  // y (-3)
        writer.byteString(coordinates[32..<64])
        return writer.bytes
    }

    /// `{"fmt": "none", "attStmt": {}, "authData": …}`: no attestation, which is what a software authenticator can
    /// truthfully offer. Keys are in CTAP2 canonical order (shorter first).
    static func attestationObject(authenticatorData: Data) -> Data {
        var writer = CBORWriter()
        writer.mapHeader(count: 3)
        writer.text("fmt")
        writer.text("none")
        writer.text("attStmt")
        writer.mapHeader(count: 0)
        writer.text("authData")
        writer.byteString(authenticatorData)
        return Data(writer.bytes)
    }
}
