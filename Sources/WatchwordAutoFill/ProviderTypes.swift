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
    /// `AutoFillGate` refused: the identifier is not a usable hostname, the page was loaded over plain `http`, nothing
    /// is scoped to the host, or the chosen item is not for it. Carries the look-alike assessment, so the extension
    /// can say why.
    case gate(FillRefusal)
    /// The identity or choice names no item or field the vault holds: a stale identity store, or a made-up one.
    case unknownRecord
    /// Two readable items carry this ID, so it names neither (see `CredentialSnapshot.items`).
    case duplicateRecord
    /// The item is archived, in the trash, or marked "exclude from AutoFill suggestions": such an item is reachable
    /// only by opening the app (PRD F6.8).
    case itemNotInUse
    /// The item or field holds nothing of the kind asked for.
    case nothingToRelease
    /// A field kind that is never text to insert (a passkey), or a secret asked for when the system named no host:
    /// a secret leaves only for a host its item is scoped to.
    case fieldWithheld(FieldKind)
    case oneTimeCode(OTPAuthError)
    case clock(OneTimeCodeError)
    case passkey(PasskeyError)
    /// A request value outside its bounds, named.
    case invalidRequest(String)
    case scopeRejected(ScopeValidationError)
    case passwordRules(PasswordRulesError)
    /// A conditional passkey registration found no single saved password login to upgrade, in a vault only this
    /// account reads: nothing is written to an item of a shared vault without the person (review finding Z60).
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
    /// The identity is the item's, but other items now make it one Watchword would not publish: somewhere on its
    /// site another account is more specific, or shares its user name. The system cannot say which page the person
    /// is on, so they choose from the extension's list, which is told (PRD F6.6, F11.5).
    case ambiguousMatch
    /// The identity is not one the item would publish as it is now: its user name, its field or its scope changed.
    /// The same remedy, and the identity store is due a refresh.
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

/// The vault an entry's item is in, and whose it is (review finding Z60).
///
/// Every list entry, every candidate for a save or a registration and every proposal carries one, because the
/// vault decides who reads what is saved there and who wrote what is offered from there. In a shared vault any
/// member who may write chose the item's title, user name, scopes and even the vault's name ("Personal" included),
/// so a sheet shows `isShared` wherever it shows the entry, and never the name alone.
public struct EntryVault: Hashable, Sendable {
    public let id: UUID
    public let name: String
    /// Accounts other than this one read this vault, and those who may write there can add and change its items.
    /// Also `true` for a vault the session did not describe.
    public let isShared: Bool

    public init(id: UUID, name: String, isShared: Bool) {
        self.id = id
        self.name = name
        self.isShared = isShared
    }

    /// Whether a secret written to an item of this vault is one every member of the vault can read. A sheet that
    /// offers such an item as the destination of a password or a passkey says so before the person confirms.
    public var everyMemberSeesWhatIsSaved: Bool { isShared }
}

/// A password login the gate will release for the request's host.
public struct PasswordEntry: Hashable, Sendable {
    public let itemID: UUID
    /// The vault the login is in. Two entries alike in every other field can differ here.
    public let vault: EntryVault
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
    public let vault: EntryVault
    public let title: String
    public let userName: String
    public let relyingPartyID: String
    public let credentialID: Data
    /// The relying party reported it does not know this passkey (PRD F6.7).
    public let reportedUnknown: Bool
}

public struct CredentialList: Equatable, Sendable {
    /// The normalised hosts the request named.
    public let hosts: [String]
    public let passwords: [PasswordEntry]
    public let passkeys: [PasskeyEntry]
    /// The one login to offer first: set only when a single item is the most specific match, and `nil` whenever
    /// accounts tie (PRD F11.5) or an item of a shared vault stands beside one of the person's own.
    public let suggested: PasswordEntry?
    /// Why no passkey is listed although the request asked for some, if the relying party itself was refused.
    public let passkeyRefusal: ProviderRefusal?

    public var isEmpty: Bool { passwords.isEmpty && passkeys.isEmpty }
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
///
/// Everything in it is what Watchword published: the system returns the stored identity and does not say which
/// page or app the person is on. `serviceIdentifier` is therefore the identity's own, a lookup key like the record
/// identifier, and never evidence about the page (docs/02-architecture.md §9.2, "Published identities").
public struct PasswordIdentityRequest: Hashable, Sendable {
    /// The identifier of the published identity (`PasswordIdentity.host`, as a domain). Not the page.
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
    public let vault: EntryVault
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

/// `ASOneTimeCodeCredentialIdentity` as the system hands it back. As for `PasswordIdentityRequest`, it says what
/// Watchword published and nothing about the page.
public struct OneTimeCodeIdentityRequest: Hashable, Sendable {
    /// The identifier of the published identity (`OneTimeCodeIdentity.host`, as a domain). Not the page.
    public var serviceIdentifier: ServiceIdentifier
    /// The name the suggestion showed (`OneTimeCodeIdentity.label`): what the person saw when they tapped.
    public var label: String
    public var recordIdentifier: String

    public init(serviceIdentifier: ServiceIdentifier, label: String, recordIdentifier: String) {
        self.serviceIdentifier = serviceIdentifier
        self.label = label
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
    public let vault: EntryVault
    public let title: String
    public let userName: String
    public let fields: [InsertableField]
}

public struct TextInsertionList: Hashable, Sendable {
    public let items: [InsertableItem]
    /// `false` when the system named no site or app. Every secret field is then left out: a secret is only
    /// released for a host its item is scoped to.
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
    /// A new item, titled by the relying party ID and scoped to it and the hosts below it.
    case newItem
    /// A new item with the scope of the items already offered for the relying party
    /// (`PasskeyRegistrationOptions.newItem.besideExisting`), so that it ties with them instead of outranking them.
    /// Where there are none to be beside, the same as `newItem`.
    case newItemBesideExisting
    /// An item the gate authorises for the relying party. Its scopes are not touched.
    case existingItem(UUID)
}

public struct PasskeyRegistrationCandidate: Hashable, Sendable {
    public let itemID: UUID
    /// The vault the passkey would be saved in. Where it is shared, every member of it could use the passkey: the
    /// sheet says so beside the candidate (`EntryVault.everyMemberSeesWhatIsSaved`).
    public let vault: EntryVault
    public let title: String
    public let userName: String
    /// The item's login names include the name the relying party gave.
    public let matchesUserName: Bool
}

/// What the registration sheet shows before the person confirms.
public struct PasskeyRegistrationOptions: Hashable, Sendable {
    public let relyingPartyID: String
    public let userName: String
    /// Items the passkey may be added to: those the gate authorises for the relying party.
    public let existingItems: [PasskeyRegistrationCandidate]
    /// Logins with this user name that are scoped at or under the relying party and yet cannot take the passkey,
    /// because the gate would not release it from them for the relying party (a login saved for
    /// `www.shop.example` when the relying party is `shop.example`). The sheet names them so the person knows the
    /// account will be in two items, and that the remedy is to add the relying party to the login, in the app
    /// (PRD F11.7): this request never changes an item's scopes.
    public let relatedLogins: [PasskeyRegistrationCandidate]
    /// The item `PasskeyDestination.newItem` would create, and what that would do to the items already offered.
    public let newItem: NewItemProposal
    /// The one existing item with the user name, if there is exactly one and it is in a vault only this account
    /// reads; otherwise a new item, beside the person's own items already offered for the relying party where there
    /// are any: the suggestion never hides an account, and never puts a new passkey where other people can use it.
    /// An item of a shared vault is a destination the person picks, not one picked for them.
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

/// The scope that puts a new item beside the person's own accounts already offered on the request's host.
public struct SharedScopeProposal: Hashable, Sendable {
    /// The scope host of those accounts, which the new item would take. Always the scope of items in vaults only
    /// this account writes: a scope a member of a shared vault chose is never copied into a new item.
    public let scopeHost: String
    public let includesSubdomains: Bool
    /// How many accounts the new one would tie with. The person then chooses among them each time (PRD F11.5).
    public let accounts: Int

    public init(scopeHost: String, includesSubdomains: Bool, accounts: Int) {
        self.scopeHost = scopeHost
        self.includesSubdomains = includesSubdomains
        self.accounts = accounts
    }
}

/// The item a `newItem` destination would create, for the sheet to show before the person confirms.
public struct NewItemProposal: Hashable, Sendable {
    /// The vault the item would be created in: the default (Personal) vault.
    public let vault: EntryVault
    public let title: String
    /// The host the new item is scoped to: the exact host the login was made on, or a passkey's relying party.
    public let scopeHost: String
    /// Whether the scope covers the hosts below `scopeHost`: never for a saved login, always for a passkey (that is
    /// what a relying party ID means).
    public let includesSubdomains: Bool
    public let userName: String
    /// Set when the host resembles a saved site: the sheet shows it before anything is saved.
    public let warning: LookAlikeWarning?
    /// How many accounts now offered on the request's host this item would outrank there. They would no longer be
    /// listed or released on that host from the extension, only reachable in the app (PRD F6.6). Right
    /// for a different service under the same domain (scenario S1), wrong for a second account on the same one;
    /// the sheet says so, and offers `besideExisting` as the alternative.
    public let hiddenAccounts: Int
    /// Set when `hiddenAccounts` is not zero: what the `newItemBesideExisting` destination would do instead.
    public let besideExisting: SharedScopeProposal?

    public init(
        vault: EntryVault, title: String, scopeHost: String, includesSubdomains: Bool, userName: String,
        warning: LookAlikeWarning?, hiddenAccounts: Int, besideExisting: SharedScopeProposal?
    ) {
        self.vault = vault
        self.title = title
        self.scopeHost = scopeHost
        self.includesSubdomains = includesSubdomains
        self.userName = userName
        self.warning = warning
        self.hiddenAccounts = hiddenAccounts
        self.besideExisting = besideExisting
    }
}

/// An existing item a save could update. `vault` names where the password would be written: in a shared vault
/// every member reads it, and a member who may write there chose everything else this candidate shows, so two
/// candidates alike in title, user name and host are told apart by their vaults (review finding Z60).
public struct SaveCandidate: Hashable, Sendable {
    public let itemID: UUID
    public let vault: EntryVault
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
    /// A new item scoped to the exact host of the request (`NewItemProposal.scopeHost`).
    case newItem
    /// A new item with the scope of the accounts already offered on the host (`NewItemProposal.besideExisting`).
    /// Where there are none to be beside, the same as `newItem`.
    case newItemBesideExisting
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
    /// The page the password is for, when the system names one (`ASGeneratePasswordsRequest.serviceIdentifier`).
    /// A page loaded over plain `http` is refused (PRD F6.9).
    public var serviceIdentifier: ServiceIdentifier?

    public init(passwordRules: String? = nil, serviceIdentifier: ServiceIdentifier? = nil) {
        self.passwordRules = passwordRules
        self.serviceIdentifier = serviceIdentifier
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
    /// Fields a report would have changed, had the change not taken the item past
    /// `CredentialProviderModel.remoteWriteItemBudget` (review finding Z71).
    public var overBudget: Int

    public init(changes: [ReportChange], rateLimited: Int, conflicts: Int, overBudget: Int = 0) {
        self.changes = changes
        self.rateLimited = rateLimited
        self.conflicts = conflicts
        self.overBudget = overBudget
    }
}
