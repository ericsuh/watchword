import Foundation
import WatchwordAutoFill
import WatchwordMatching
import WatchwordModel

/// A `CredentialProviderModel` over fakes, with a handle on each (docs/04-test-plan.md §2, "Scenario builders").
public struct AutoFillHarness: Sendable {
    public let vault: FakeCredentialVault
    public let clock: FakeClock
    public let publisher: FakeCredentialIdentityPublisher
    public let model: CredentialProviderModel

    public init(
        items: [Item] = [], backedUp: Bool = true, seed: UInt64 = 42,
        publisher: FakeCredentialIdentityPublisher = FakeCredentialIdentityPublisher()
    ) {
        clock = FakeClock(AutoFillFixtures.now)
        vault = FakeCredentialVault(vaultID: AutoFillFixtures.vaultID, clock: clock, backedUp: backedUp, items: items)
        self.publisher = publisher
        model = CredentialProviderModel(
            vault: vault, clock: clock, publisher: publisher,
            random: SeededGenerator(seed: TestEnvironment.seed(fallback: seed)))
    }
}

extension AutoFillHarness {
    /// Publishes the vault's identities and returns what the system's store now holds.
    public func publishedIdentities() async throws -> [CredentialIdentity] {
        _ = try await model.publishAllIdentities().value
        return await publisher.published
    }

    public func publishedPasswords() async throws -> [PasswordIdentity] {
        try await publishedIdentities().compactMap {
            if case .password(let identity) = $0 { return identity }
            return nil
        }
    }

    public func publishedCodes() async throws -> [OneTimeCodeIdentity] {
        try await publishedIdentities().compactMap {
            if case .oneTimeCode(let identity) = $0 { return identity }
            return nil
        }
    }
}

// What the system does when the person taps a suggestion: it hands the stored identity back, verbatim, and says
// nothing about the page. Tests of the requests made without the person build their input this way and no other,
// because a request carrying the page's URL is one the system never makes.

extension PasswordIdentity {
    public var handedBack: PasswordIdentityRequest {
        PasswordIdentityRequest(
            serviceIdentifier: ServiceIdentifier(host, kind: .domain), user: user,
            recordIdentifier: recordIdentifier.text)
    }
}

extension OneTimeCodeIdentity {
    public var handedBack: OneTimeCodeIdentityRequest {
        OneTimeCodeIdentityRequest(
            serviceIdentifier: ServiceIdentifier(host, kind: .domain), label: label,
            recordIdentifier: recordIdentifier.text)
    }
}

extension PasskeyIdentity {
    public var handedBack: PasskeyIdentityRequest {
        PasskeyIdentityRequest(recordIdentifier: recordIdentifier.text, credentialID: credentialID)
    }
}

/// The items of PRD scenarios S1 to S4, with fixed IDs so a failure names the same item every run.
public enum AutoFillFixtures {
    public static let vaultID = UUID(uuidString: "00000000-0000-4000-8000-0000000000AA")!
    public static let now = Date(timeIntervalSince1970: 1_800_000_000)
    public static let email = "pat@example.com"

    public static func id(_ number: Int) -> UUID {
        UUID(
            uuidString: "00000000-0000-4000-8000-" + String(repeating: "0", count: 12 - String(number).count)
                + "\(number)")!
    }

    /// A TOTP field whose secret is `secret` as ASCII (at least ten characters).
    public static func totp(_ secret: String, id: UUID = UUID(), digits: Int = 6) -> Field {
        Field(
            id: id, kind: .totp, label: "One-time code",
            value: "otpauth://totp/Watchword?secret=\(Base32.encode(Array(secret.utf8)))&digits=\(digits)")
    }

    /// A passkey field made by the real authenticator, from a seed.
    public static func passkey(
        relyingParty: String, userName: String = email, userHandle: String = "user-handle", seed: UInt64,
        id: UUID = UUID()
    ) -> Field {
        var generator = SeededGenerator(seed: seed)
        do {
            let registration = try PasskeyAuthenticator.register(
                relyingParty: try RelyingPartyID(relyingParty),
                user: PasskeyUser(handle: Data(userHandle.utf8), name: userName), presence: .verified, backedUp: true,
                now: now, using: &generator)
            return try Field.passkey(registration.credential, id: id)
        } catch {
            preconditionFailure("fixture passkey for \(relyingParty): \(error)")
        }
    }

    public static let retailSecret = "retail-totp-secret-1"
    public static let awsSecret = "aws-root-totp-secret"

    /// S1: the Amazon retail account, for `amazon.com` and everything under it.
    public static let amazonRetail = Item(
        id: id(1), vaultID: vaultID, title: "Amazon", scopes: [ServiceScope(host: "amazon.com")],
        fields: [
            Field(id: id(101), kind: .email, label: "Email", value: email),
            Field(id: id(102), kind: .password, label: "Password", value: "retail-password"),
            totp(retailSecret, id: id(103)),
        ], version: 1)

    /// S1: the AWS root account, same email, for the console's two hosts.
    public static let awsRoot = Item(
        id: id(2), vaultID: vaultID, title: "AWS root",
        scopes: [
            ServiceScope(host: "signin.aws.amazon.com", includeSubdomains: false),
            ServiceScope(host: "console.aws.amazon.com"),
        ],
        fields: [
            Field(id: id(201), kind: .email, label: "Email", value: email),
            Field(id: id(202), kind: .password, label: "Password", value: "aws-password"),
            totp(awsSecret, id: id(203)),
        ], version: 1)

    /// S2: Google, with a passkey and recovery codes in one item.
    public static let google = Item(
        id: id(3), vaultID: vaultID, title: "Google", scopes: [ServiceScope(host: "google.com")],
        fields: [
            Field(id: id(301), kind: .email, label: "Email", value: email),
            passkey(relyingParty: "google.com", seed: 3, id: id(302)),
            Field(
                id: id(303), kind: .recoveryCodes, label: "Backup codes", value: "1111-2222\n3333-4444\n5555-6666"),
        ], version: 1)

    /// S3: the bank, with three security questions.
    public static let bank = Item(
        id: id(4), vaultID: vaultID, title: "First Bank", scopes: [ServiceScope(host: "firstbank.co.uk")],
        fields: [
            Field(id: id(401), kind: .username, label: "Customer number", value: "40012345"),
            Field(id: id(402), kind: .phoneNumber, label: "Phone", value: "+44 20 7946 0000"),
            Field(id: id(403), kind: .password, label: "Password", value: "bank-password"),
            totp("bank-totp-secret-000", id: id(404)),
            Field(
                id: id(405), kind: .securityQuestion, label: "Question 1", value: "Rex",
                meta: ["question": "First pet?"]),
            Field(
                id: id(406), kind: .securityQuestion, label: "Question 2", value: "Elm Street",
                meta: ["question": "First street?"]),
            Field(
                id: id(407), kind: .securityQuestion, label: "Question 3", value: "Ms Okafor",
                meta: ["question": "First teacher?"]),
        ], version: 1)

    /// S4: the library card.
    public static let library = Item(
        id: id(5), vaultID: vaultID, title: "Library", scopes: [ServiceScope(host: "library.example.org")],
        fields: [
            Field(id: id(501), kind: .accountNumber, label: "Card number", value: "2 1234 56789 0"),
            Field(id: id(502), kind: .username, label: "Username", value: "pat"),
            Field(id: id(503), kind: .password, label: "Password", value: "library-password"),
            Field(id: id(504), kind: .pin, label: "PIN", value: "4821"),
        ], version: 1)

    public static let all = [amazonRetail, awsRoot, google, bank, library]

    public static func url(_ text: String) -> ServiceIdentifier {
        ServiceIdentifier(text, kind: .url)
    }

    public static func domain(_ text: String) -> ServiceIdentifier {
        ServiceIdentifier(text, kind: .domain)
    }

    /// SHA-256-sized client data hash, distinct per `tag`.
    public static func clientDataHash(_ tag: UInt8 = 1) -> Data {
        Data(repeating: tag, count: 32)
    }
}

/// Thrown by the `value` accessors below when a request did not succeed; the description is the outcome.
public struct UnexpectedOutcome: Error, CustomStringConvertible {
    public let description: String

    public init(description: String) {
        self.description = description
    }
}

extension Outcome {
    /// The success value, or a thrown description of what came back instead.
    public var value: Value {
        get throws {
            guard case .success(let value) = self else { throw UnexpectedOutcome(description: "\(self)") }
            return value
        }
    }

    public var refusal: ProviderRefusal? {
        if case .refused(let refusal) = self { return refusal }
        return nil
    }
}

extension SilentOutcome {
    public var value: Value {
        get throws {
            guard case .success(let value) = self else { throw UnexpectedOutcome(description: "\(self)") }
            return value
        }
    }

    public var refusal: ProviderRefusal? {
        if case .refused(let refusal) = self { return refusal }
        return nil
    }
}

extension ProviderRefusal {
    /// Whether this is the gate saying the item is not for the host, or that nothing is.
    public var isGateRefusal: Bool {
        if case .gate = self { return true }
        return false
    }
}
