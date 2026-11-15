import Foundation
import WatchwordGenerator
import WatchwordMatching
import WatchwordModel

// The request and result values of `CredentialProviderModel`. Each mirrors a type of AuthenticationServices without
// importing it (CLAUDE.md, "Conventions"): the extension converts one way on the way in and the other on the way out,
// and decides nothing.

// MARK: - Outcomes

/// Why the model released or wrote nothing. A refusal is final for the request: no value of this type, and no other
/// part of this API, lets the extension proceed anyway (PRD F11.4, F11.7).
public enum ProviderRefusal: Error, Equatable, Sendable {
    /// The system named no site or app, so there is no host to authorise a release for.
    case noServiceIdentifier
    /// `AutoFillGate` refused: the identifier is not a usable hostname, nothing is scoped to the host, or the chosen
    /// item is not for it. Carries the look-alike assessment, so the extension can say why.
    case gate(FillRefusal)
    /// The identity or choice names no item or field the vault holds: a stale identity store, or a made-up one.
    case unknownRecord
    /// The item is archived or in the trash.
    case itemNotInUse
    /// The item or field holds nothing of the kind asked for.
    case nothingToRelease
    /// A field kind that is never text to insert (a passkey), or one that is withheld when the system names no host
    /// (a password, a one-time code): those have their own host-checked requests.
    case fieldWithheld(FieldKind)
    case oneTimeCode(OTPAuthError)
    case clock(OneTimeCodeError)
    case passkey(PasskeyError)
    /// A request value outside its bounds, named.
    case invalidRequest(String)
    case scopeRejected(ScopeValidationError)
    case passwordRules(PasswordRulesError)
    /// A conditional passkey registration found no single saved password login to upgrade.
    case noItemToUpgrade
    case vault(CredentialVaultError)
}

/// The result of a request the person is taking part in.
public enum Outcome<Value: Equatable & Sendable>: Equatable, Sendable {
    case success(Value)
    /// The vault has no keys in memory. The extension unlocks it, with its own UI, and asks again; the model never
    /// works around a locked vault.
    case vaultLocked
    case refused(ProviderRefusal)
}

/// Why a request made without the person cannot be answered without them.
public enum InteractionReason: Hashable, Sendable {
    case vaultLocked
    /// Several items tie for this host, or the published identity no longer matches the item: the person must look
    /// and choose (PRD F11.5).
    case ambiguousMatch
    case staleIdentity
    case userPresence
    case userVerification
    /// A change to existing data that only the person can approve (updating a saved password).
    case confirmation
}

/// The result of a request the system makes on the person's behalf, with no UI.
public enum SilentOutcome<Value: Equatable & Sendable>: Equatable, Sendable {
    case success(Value)
    /// Nothing was released; the system should start the request again with the extension's UI.
    case requiresInteraction(InteractionReason)
    case refused(ProviderRefusal)
}

// MARK: - Credential list

/// Shown in place of an empty list when the host resembles a saved site and is not it (PRD F11.3;
/// docs/05-anti-phishing.md §3). There is nothing to choose and nothing to override: the extension offers "go back"
/// and "open the real site".
public struct LookAlikeWarning: Hashable, Sendable {
    /// The host as normalised, punycode left as it arrived.
    public let host: String
    public let signals: Set<PhishingSignal>
    /// The saved hosts it resembles, sorted; empty when the address merely cannot be verified by eye.
    public let impersonating: [String]
}

/// A password login the gate will release for the request's host.
public struct PasswordEntry: Hashable, Sendable {
    public let itemID: UUID
    public let title: String
    /// Empty when the item has no username or email.
    public let userName: String
    /// The scope that matched, to tell two accounts apart (docs/05-anti-phishing.md §3, "Ambiguous match").
    public let matchedHost: String
    public let hasOneTimeCode: Bool
    /// The site reported this password as no longer used (PRD F6.7).
    public let reportedUnused: Bool
}

/// A passkey the gate will release for the request's relying party.
public struct PasskeyEntry: Hashable, Sendable {
    public let itemID: UUID
    public let fieldID: UUID
    public let title: String
    public let userName: String
    public let relyingPartyID: String
    public let credentialID: Data
    /// The relying party reported it does not know this passkey (PRD F6.7).
    public let reportedUnknown: Bool
}

/// An account that matches the host less specifically than another one does (PRD F6.6): shown under "other accounts
/// on this site" so the person can see why it is not offered, never pre-selected, and not released from here. To use
/// it on this host the person adds the host to the item, in the app (F11.7).
public struct OtherAccountEntry: Hashable, Sendable {
    public let itemID: UUID
    public let title: String
    public let userName: String
    public let matchedHost: String
}

public struct CredentialList: Equatable, Sendable {
    /// The normalised hosts the request named.
    public let hosts: [String]
    public let passwords: [PasswordEntry]
    public let passkeys: [PasskeyEntry]
    public let otherAccounts: [OtherAccountEntry]
    /// The one login to offer first: set only when a single item is the most specific match. Never one of
    /// `otherAccounts`, and `nil` whenever accounts tie (PRD F11.5).
    public let suggested: PasswordEntry?
    /// Why no passkey is listed although the request asked for some, if the relying party itself was refused.
    public let passkeyRefusal: ProviderRefusal?

    public var isEmpty: Bool { passwords.isEmpty && passkeys.isEmpty && otherAccounts.isEmpty }
}

public enum CredentialListOutcome: Equatable, Sendable {
    case vaultLocked
    /// Possibly empty: a site the person has nothing saved for.
    case list(CredentialList)
    case warning(LookAlikeWarning)
    case refused(ProviderRefusal)
}

// MARK: - Passwords

public struct PasswordChoice: Hashable, Sendable {
    public var itemID: UUID
    public var userName: String

    public init(itemID: UUID, userName: String) {
        self.itemID = itemID
        self.userName = userName
    }
}

/// `ASPasswordCredentialIdentity` as the system hands it back for a QuickType suggestion.
public struct PasswordIdentityRequest: Hashable, Sendable {
    public var serviceIdentifier: ServiceIdentifier
    public var user: String
    public var recordIdentifier: String

    public init(serviceIdentifier: ServiceIdentifier, user: String, recordIdentifier: String) {
        self.serviceIdentifier = serviceIdentifier
        self.user = user
        self.recordIdentifier = recordIdentifier
    }
}

/// `ASPasswordCredential`.
public struct PasswordCredential: Hashable, Sendable, CustomStringConvertible, CustomReflectable {
    public let user: String
    public let password: String

    public var description: String { "PasswordCredential(redacted)" }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }

    public init(user: String, password: String) {
        self.user = user
        self.password = password
    }
}

// MARK: - One-time codes

public struct OneTimeCodeEntry: Hashable, Sendable {
    public let itemID: UUID
    public let fieldID: UUID
    public let title: String
    public let userName: String
    public let label: String
}

public enum OneTimeCodeListOutcome: Equatable, Sendable {
    case vaultLocked
    case list([OneTimeCodeEntry])
    case warning(LookAlikeWarning)
    case refused(ProviderRefusal)
}

public struct FieldChoice: Hashable, Sendable {
    public var itemID: UUID
    public var fieldID: UUID

    public init(itemID: UUID, fieldID: UUID) {
        self.itemID = itemID
        self.fieldID = fieldID
    }
}

/// `ASOneTimeCodeCredentialIdentity` as the system hands it back.
public struct OneTimeCodeIdentityRequest: Hashable, Sendable {
    public var serviceIdentifier: ServiceIdentifier
    public var recordIdentifier: String

    public init(serviceIdentifier: ServiceIdentifier, recordIdentifier: String) {
        self.serviceIdentifier = serviceIdentifier
        self.recordIdentifier = recordIdentifier
    }
}

// MARK: - Text to insert

/// Which part of a field to insert.
public enum TextPart: Hashable, Sendable {
    /// The field's value; for a one-time code field, the current code (never the `otpauth` URI).
    case whole
    /// One code of a recovery-codes field, by its position.
    case recoveryCode(index: Int)
}

public struct TextChoice: Hashable, Sendable {
    public var itemID: UUID
    public var fieldID: UUID
    public var part: TextPart

    public init(itemID: UUID, fieldID: UUID, part: TextPart = .whole) {
        self.itemID = itemID
        self.fieldID = fieldID
        self.part = part
    }
}

/// The text handed to `completeRequest(withTextToInsert:)`. A wrapper so that printing a result does not print it.
public struct TextToInsert: Hashable, Sendable, ExpressibleByStringLiteral, CustomStringConvertible, CustomReflectable {
    public let text: String

    public init(_ text: String) {
        self.text = text
    }

    public init(stringLiteral value: String) {
        self.init(value)
    }

    public var description: String { "TextToInsert(redacted)" }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

public struct InsertableField: Hashable, Sendable {
    public let fieldID: UUID
    public let kind: FieldKind
    public let label: String
    /// A security question's text.
    public let question: String?
    /// The value of a field that is not a secret, to show in the list. Secrets are fetched when chosen.
    public let preview: String?
    /// For a recovery-codes field: how many codes it holds and which are spent.
    public let recoveryCodeCount: Int
    public let usedRecoveryCodes: Set<Int>
}

public struct InsertableItem: Hashable, Sendable {
    public let itemID: UUID
    public let title: String
    public let userName: String
    public let fields: [InsertableField]
}

public struct TextInsertionList: Hashable, Sendable {
    public let items: [InsertableItem]
    /// `false` when the system named no site or app. Passwords, one-time codes and passkeys are then left out:
    /// they are only released for a host an item is scoped to.
    public let hostVerified: Bool
}

public enum TextInsertionListOutcome: Equatable, Sendable {
    case vaultLocked
    case list(TextInsertionList)
    case warning(LookAlikeWarning)
    case refused(ProviderRefusal)
}

// MARK: - Passkeys

/// `ASAuthorizationPublicKeyCredentialUserVerificationPreference`.
public enum UserVerificationPreference: Hashable, Sendable {
    case required
    case preferred
    case discouraged
}

public struct PRFAssertionInput: Hashable, Sendable {
    public var inputValues: PRFInputValues?
    /// Inputs for particular credentials, by credential ID (`evalByCredential`); they win over `inputValues`.
    public var perCredential: [Data: PRFInputValues]

    public init(inputValues: PRFInputValues? = nil, perCredential: [Data: PRFInputValues] = [:]) {
        self.inputValues = inputValues
        self.perCredential = perCredential
    }
}

public enum LargeBlobAssertionInput: Hashable, Sendable {
    case read
    case write(Data)
}

public enum LargeBlobAssertionOutput: Hashable, Sendable {
    /// The stored blob, or `nil` when the credential has none.
    case read(Data?)
    case write(didWrite: Bool)
}

public struct PasskeyAssertionExtensions: Hashable, Sendable {
    public var prf: PRFAssertionInput?
    public var largeBlob: LargeBlobAssertionInput?

    public init(prf: PRFAssertionInput? = nil, largeBlob: LargeBlobAssertionInput? = nil) {
        self.prf = prf
        self.largeBlob = largeBlob
    }
}

/// `ASPasskeyCredentialRequestParameters`, and the request half of `ASPasskeyCredentialRequest`.
public struct PasskeyAssertionRequest: Hashable, Sendable {
    public var relyingPartyID: String
    public var clientDataHash: Data
    /// Empty means any discoverable credential of the relying party.
    public var allowedCredentialIDs: [Data]
    public var userVerification: UserVerificationPreference
    public var extensions: PasskeyAssertionExtensions

    public init(
        relyingPartyID: String, clientDataHash: Data, allowedCredentialIDs: [Data] = [],
        userVerification: UserVerificationPreference = .preferred,
        extensions: PasskeyAssertionExtensions = PasskeyAssertionExtensions()
    ) {
        self.relyingPartyID = relyingPartyID
        self.clientDataHash = clientDataHash
        self.allowedCredentialIDs = allowedCredentialIDs
        self.userVerification = userVerification
        self.extensions = extensions
    }
}

/// The identity half of `ASPasskeyCredentialRequest`, as the system hands it back.
public struct PasskeyIdentityRequest: Hashable, Sendable {
    public var recordIdentifier: String
    public var credentialID: Data

    public init(recordIdentifier: String, credentialID: Data) {
        self.recordIdentifier = recordIdentifier
        self.credentialID = credentialID
    }
}

/// `ASPasskeyAssertionCredential` with its extension output.
public struct PasskeyAssertionResult: Hashable, Sendable {
    public let assertion: PasskeyAssertion
    public let prf: PRFOutputValues?
    public let largeBlob: LargeBlobAssertionOutput?
}

public enum PRFRegistrationInput: Hashable, Sendable {
    case checkForSupport
    case evaluate(PRFInputValues)
}

public struct PRFRegistrationOutput: Hashable, Sendable {
    public let isSupported: Bool
    public let values: PRFOutputValues?

    public init(isSupported: Bool, values: PRFOutputValues?) {
        self.isSupported = isSupported
        self.values = values
    }
}

public struct PasskeyRegistrationExtensions: Hashable, Sendable {
    public var prf: PRFRegistrationInput?
    /// Whether the relying party asked about `largeBlob` support at all.
    public var largeBlobRequested: Bool

    public init(prf: PRFRegistrationInput? = nil, largeBlobRequested: Bool = false) {
        self.prf = prf
        self.largeBlobRequested = largeBlobRequested
    }
}

/// `ASPasskeyCredentialRequest` for a registration.
public struct PasskeyRegistrationRequest: Hashable, Sendable {
    public var relyingPartyID: String
    public var user: PasskeyUser
    public var clientDataHash: Data
    /// COSE algorithm identifiers the relying party accepts.
    public var supportedAlgorithms: [Int]
    public var userVerification: UserVerificationPreference
    public var excludedCredentialIDs: [Data]
    public var extensions: PasskeyRegistrationExtensions

    public init(
        relyingPartyID: String, user: PasskeyUser, clientDataHash: Data,
        supportedAlgorithms: [Int] = [PasskeyAuthenticator.es256],
        userVerification: UserVerificationPreference = .preferred, excludedCredentialIDs: [Data] = [],
        extensions: PasskeyRegistrationExtensions = PasskeyRegistrationExtensions()
    ) {
        self.relyingPartyID = relyingPartyID
        self.user = user
        self.clientDataHash = clientDataHash
        self.supportedAlgorithms = supportedAlgorithms
        self.userVerification = userVerification
        self.excludedCredentialIDs = excludedCredentialIDs
        self.extensions = extensions
    }
}

/// Where a new passkey goes.
public enum PasskeyDestination: Hashable, Sendable {
    /// A new item, titled and scoped by the relying party ID.
    case newItem
    /// An item the gate authorises for the relying party. Its scopes are not touched.
    case existingItem(UUID)
}

public struct PasskeyRegistrationCandidate: Hashable, Sendable {
    public let itemID: UUID
    public let title: String
    public let userName: String
    /// The item's login names include the name the relying party gave.
    public let matchesUserName: Bool
}

/// What the registration sheet shows before the person confirms.
public struct PasskeyRegistrationOptions: Hashable, Sendable {
    public let relyingPartyID: String
    public let userName: String
    /// Items the passkey may be added to.
    public let existingItems: [PasskeyRegistrationCandidate]
    public let suggested: PasskeyDestination
}

/// `ASPasskeyRegistrationCredential` with its extension output, and where the credential was stored.
public struct PasskeyRegistrationResult: Hashable, Sendable {
    public let relyingPartyID: String
    public let credentialID: Data
    public let clientDataHash: Data
    public let attestationObject: Data
    public let itemID: UUID
    public let fieldID: UUID
    public let createdItem: Bool
    public let prf: PRFRegistrationOutput?
    /// `true` when the relying party asked; a blob can always be stored.
    public let largeBlobSupported: Bool?
}

// MARK: - Saving and generating passwords

/// `ASSavePasswordRequest`. The page's own title for the login is deliberately not part of it: a new item is titled
/// by its host, which the page cannot choose.
public struct SavePasswordRequest: Hashable, Sendable {
    public var serviceIdentifier: ServiceIdentifier
    public var userName: String
    public var password: String

    public init(serviceIdentifier: ServiceIdentifier, userName: String, password: String) {
        self.serviceIdentifier = serviceIdentifier
        self.userName = userName
        self.password = password
    }
}

public struct NewItemProposal: Hashable, Sendable {
    public let title: String
    /// The exact host the login was made on; subdomains are not included.
    public let scopeHost: String
    public let userName: String
    /// Set when the host resembles a saved site: the sheet shows it before anything is saved.
    public let warning: LookAlikeWarning?

    public init(title: String, scopeHost: String, userName: String, warning: LookAlikeWarning?) {
        self.title = title
        self.scopeHost = scopeHost
        self.userName = userName
        self.warning = warning
    }
}

public struct SaveCandidate: Hashable, Sendable {
    public let itemID: UUID
    public let title: String
    public let userName: String
    public let matchedHost: String
    public let passwordDiffers: Bool
}

public enum SavePasswordPlan: Hashable, Sendable {
    /// An item for this host already holds this user name and this password.
    case alreadySaved(itemID: UUID)
    /// One or more items for this host could be this account: offer to update one, or to create a new item.
    case offerUpdate(candidates: [SaveCandidate], newItem: NewItemProposal)
    case createItem(NewItemProposal)
}

public enum SaveDestination: Hashable, Sendable {
    case newItem
    case existingItem(UUID)
}

public struct SavedPassword: Hashable, Sendable {
    public let itemID: UUID
    public let createdItem: Bool

    public init(itemID: UUID, createdItem: Bool) {
        self.itemID = itemID
        self.createdItem = createdItem
    }
}

/// `ASGeneratePasswordsRequest`.
public struct GeneratePasswordRequest: Hashable, Sendable {
    /// The site's `passwordrules`, if it declared any.
    public var passwordRules: String?

    public init(passwordRules: String? = nil) {
        self.passwordRules = passwordRules
    }
}

public struct GeneratedPassword: Hashable, Sendable, CustomStringConvertible, CustomReflectable {
    public let password: String
    /// From the generation process (PRD F3.4); the sheet warns below `Entropy.warningThresholdBits`.
    public let entropyBits: Double
    public let policy: RandomPasswordPolicy

    public var description: String { "GeneratedPassword(redacted)" }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

// MARK: - Credential-update reports

/// What a relying party tells the credential manager about credentials it holds (PRD F6.7): the WebAuthn signal
/// methods and their password counterpart, as the system delivers them.
public enum CredentialUpdateReport: Hashable, Sendable {
    /// The site no longer accepts this user's password (the account now signs in another way).
    case unusedPassword(domain: String, userName: String)
    /// The account's name changed at the relying party.
    case passkeyRenamed(relyingPartyID: String, userHandle: Data, newName: String)
    /// The relying party does not recognise this credential.
    case unknownPasskey(relyingPartyID: String, credentialID: Data)
    /// The complete list of the user's credentials the relying party accepts.
    case acceptedPasskeys(relyingPartyID: String, userHandle: Data, acceptedCredentialIDs: [Data])
}

public struct ReportChange: Hashable, Sendable {
    public enum Kind: Hashable, Sendable {
        case flaggedUnusedPassword
        case flaggedUnknownPasskey
        case clearedUnknownPasskey
        case renamedPasskey
    }

    public let itemID: UUID
    public let fieldID: UUID
    public let kind: Kind

    public init(itemID: UUID, fieldID: UUID, kind: Kind) {
        self.itemID = itemID
        self.fieldID = fieldID
        self.kind = kind
    }
}

/// What a report did. It can flag a field or rename a passkey's account; nothing a remote party sends deletes a
/// field, an item, or a value from an item's history.
public struct ReportResult: Hashable, Sendable {
    public var changes: [ReportChange]
    /// Fields a report would have changed, had a report not already changed them within `reportInterval`.
    public var rateLimited: Int
    /// Items that changed underneath the report; the next report will find them.
    public var conflicts: Int

    public init(changes: [ReportChange], rateLimited: Int, conflicts: Int) {
        self.changes = changes
        self.rateLimited = rateLimited
        self.conflicts = conflicts
    }
}
