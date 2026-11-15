import Foundation
import WatchwordMatching
import WatchwordModel

/// The items of one request, read from the vault once.
struct VaultSnapshot: Sendable {
    /// Everything readable, as stored, trashed and archived included. Secrets are read from these, and writes start
    /// from them.
    let all: [Item]
    /// What the gate ranks among: every item outside the trash, each with only the scopes the scope policy accepts.
    ///
    /// Archived items and items excluded from AutoFill stay in, so such an account still marks its host as its own
    /// and a less specific item is not offered there in its place; they are never released themselves
    /// (`Authorization` is only made for items in use). A scope the policy refuses (`com`, `co.uk`) cannot be
    /// created through the vault, but an item can arrive from another vault member or an import, and such a scope
    /// would match every site under it; here it matches nothing (PRD F11.2). The stored item is not rewritten.
    let rankable: [Item]
    /// IDs more than one readable item carries. No honest client writes two items with one ID, and everything here
    /// names an item by its ID alone (a choice, a record identifier, the ranker's "is this the match"), so with two
    /// candidates the gate could say yes about one and the secret be read from the other. Such items keep ranking,
    /// which can only narrow what is offered, and are never listed, released, written or published.
    let duplicatedIDs: Set<UUID>

    init(_ items: [Item]) {
        all = items
        rankable = items.filter { !$0.isTrashed }.map { item in
            var view = item
            view.scopes = item.scopes.filter(ScopePolicy.isAcceptable)
            return view
        }
        var seen = Set<UUID>()
        var duplicated = Set<UUID>()
        for item in items where !seen.insert(item.id).inserted {
            duplicated.insert(item.id)
        }
        duplicatedIDs = duplicated
    }

    /// Whether a credential may be released from `item`, or the item written to, by the extension: not in the
    /// trash, not archived, not marked "exclude from AutoFill suggestions" (PRD F6.8: reachable only by opening the
    /// app), and the only item with its ID.
    func isInUse(_ item: Item) -> Bool {
        !item.isTrashed && !item.archived && !item.excludedFromSuggestions && !duplicatedIDs.contains(item.id)
    }

    /// Items a credential may be released from, as stored.
    var inUse: [Item] {
        all.filter(isInUse)
    }

    /// The one stored item with this ID.
    func item(_ id: UUID) -> Result<Item, ProviderRefusal> {
        guard !duplicatedIDs.contains(id) else { return .failure(.duplicateRecord) }
        guard let item = all.first(where: { $0.id == id }) else { return .failure(.unknownRecord) }
        return .success(item)
    }

    /// The one stored item with this ID, if a credential may be released from it or it may be written to.
    func itemInUse(_ id: UUID) -> Result<Item, ProviderRefusal> {
        item(id).flatMap { isInUse($0) ? .success($0) : .failure(.itemNotInUse) }
    }
}

/// Proof that `AutoFillGate` authorised `item` for `host` in this request (PRD SEC6, F11.1).
///
/// The initialiser is private to this file and `ReleaseGate.authorize` is its only caller, and every function that
/// reads a secret out of an item is a method of this type. So in this module there is no way to hand a password, a
/// one-time code or a signing key to the operating system without the gate having said yes for that item and that
/// host, by construction rather than by convention; and because nothing constructs one from a refusal, there is no
/// override to add (F11.7).
struct Authorization: Sendable {
    let item: Item
    let host: NormalizedHost

    fileprivate init(item: Item, host: NormalizedHost) {
        self.item = item
        self.host = host
    }
}

/// An item the person picked by hand when the system named no site or app (the system's text-insertion request).
/// There is no host, so the gate has nothing to check, and this type can read only fields that are not secrets:
/// never a password, a one-time code, a passkey, a recovery code, an API key, a security answer or a PIN.
struct ManualChoice: Sendable {
    let item: Item

    fileprivate init(item: Item) {
        self.item = item
    }
}

enum ReleaseGate {
    /// An app can declare many associated domains; a request naming more than this is cut short, which can only
    /// narrow what matches.
    static let maximumIdentifiers = 64

    enum Purpose {
        case credential
        case oneTimeCode
    }

    /// The single place a release is authorised. `itemID` must name the one item in use with that ID, and
    /// `AutoFillGate` must authorise it for at least one of the identifiers the system supplied, among everything
    /// outside the trash.
    static func authorize(
        itemID: UUID, for identifiers: [ServiceIdentifier], in snapshot: VaultSnapshot, purpose: Purpose = .credential
    ) -> Result<Authorization, ProviderRefusal> {
        guard !identifiers.isEmpty else { return .failure(.noServiceIdentifier) }
        let item: Item
        switch snapshot.itemInUse(itemID) {
        case .success(let found): item = found
        case .failure(let refusal): return .failure(refusal)
        }
        // The gate is asked about the very item the secret will be read from, in the form it ranks: its ID is
        // unique in the snapshot, so "the match with this ID" can only be this item.
        guard let ranked = snapshot.rankable.first(where: { $0.id == itemID }) else { return .failure(.itemNotInUse) }

        var refusals: [FillRefusal] = []
        for identifier in identifiers.prefix(maximumIdentifiers) {
            let result: Result<NormalizedHost, FillRefusal>
            switch purpose {
            case .credential:
                result = AutoFillGate.authorize(ranked, for: identifier, among: snapshot.rankable)
            case .oneTimeCode:
                result = AutoFillGate.authorizeOneTimeCode(ranked, for: identifier, among: snapshot.rankable)
            }
            switch result {
            case .success(let host): return .success(Authorization(item: item, host: host))
            case .failure(let refusal): refusals.append(refusal)
            }
        }
        return .failure(.gate(mostInformative(refusals)))
    }

    /// Every item in use the gate authorises for `identifier`: the candidates for a list, a registration or a
    /// report. Ranked once, then each most specific match is authorised like any single release.
    static func authorizedItems(for identifier: ServiceIdentifier, in snapshot: VaultSnapshot) -> [Authorization] {
        guard let host = try? HostNormalizer.normalize(identifier) else { return [] }
        return ItemRanker.rank(items: snapshot.rankable, host: host).primary.compactMap { match in
            try? authorize(itemID: match.item.id, for: [identifier], in: snapshot).get()
        }
    }

    /// The item for a hand-picked text insertion with no host. In use, and nothing else can be asked.
    static func manualChoice(itemID: UUID, in snapshot: VaultSnapshot) -> Result<ManualChoice, ProviderRefusal> {
        snapshot.itemInUse(itemID).map(ManualChoice.init(item:))
    }

    /// Of several refusals, the one that warns: a look-alike assessment beats "nothing matches", which beats an
    /// identifier that could not be read.
    static func mostInformative(_ refusals: [FillRefusal]) -> FillRefusal {
        func weight(_ refusal: FillRefusal) -> Int {
            switch refusal {
            case .itemNotScopedToHost(let assessment), .noMatchingItem(let assessment):
                return assessment.isSuspicious ? 3 : 2
            case .unusableIdentifier:
                return 1
            }
        }
        var best = refusals.first ?? .unusableIdentifier(.empty)
        for refusal in refusals where weight(refusal) > weight(best) {
            best = refusal
        }
        return best
    }
}

// MARK: - Reading secrets, gate first

extension Authorization {
    /// The password for one of the item's login names. `userName` must be one of them, or empty for an item with
    /// none; the password is the item's first password field.
    func password(userName: String) -> Result<PasswordCredential, ProviderRefusal> {
        let names = item.loginNames.filter { !$0.isEmpty }
        guard names.contains(userName) || (userName.isEmpty && names.isEmpty) else { return .failure(.unknownRecord) }
        guard let field = item.field(.password), !field.value.isEmpty else { return .failure(.nothingToRelease) }
        return .success(PasswordCredential(user: userName, password: field.value))
    }

    /// The current code of one of the item's one-time code fields.
    func oneTimeCode(fieldID: UUID, at date: Date) -> Result<OneTimeCode, ProviderRefusal> {
        guard let field = item.fields.first(where: { $0.id == fieldID && $0.kind == .totp }) else {
            return .failure(.unknownRecord)
        }
        return Authorization.code(of: field, at: date)
    }

    /// The credential in one of the item's passkey fields.
    func passkey(fieldID: UUID) -> Result<PasskeyCredential, ProviderRefusal> {
        guard let field = item.fields.first(where: { $0.id == fieldID && $0.kind == .passkey }) else {
            return .failure(.unknownRecord)
        }
        do {
            return .success(try field.passkeyCredential())
        } catch let error as PasskeyCodingError {
            return .failure(.passkey(.malformedCredential(error)))
        } catch {
            return .failure(.passkey(.malformedCredential(.malformed)))
        }
    }

    /// Text to insert from any field but a passkey, whose private key is never text.
    func text(fieldID: UUID, part: TextPart, at date: Date) -> Result<TextToInsert, ProviderRefusal> {
        guard let field = item.fields.first(where: { $0.id == fieldID }) else { return .failure(.unknownRecord) }
        switch field.kind {
        case .passkey:
            return .failure(.fieldWithheld(.passkey))
        case .totp:
            guard part == .whole else { return .failure(.nothingToRelease) }
            return Authorization.code(of: field, at: date).map { TextToInsert($0.code) }
        default:
            return plainText(of: field, part: part)
        }
    }

    private static func code(of field: Field, at date: Date) -> Result<OneTimeCode, ProviderRefusal> {
        do {
            return .success(try TOTP.code(for: try field.otpParameters(), at: date))
        } catch let error as OTPAuthError {
            return .failure(.oneTimeCode(error))
        } catch let error as OneTimeCodeError {
            return .failure(.clock(error))
        } catch {
            return .failure(.nothingToRelease)
        }
    }
}

extension ManualChoice {
    /// Whether a field of this kind may be inserted when the system named no site: only what is not a secret.
    ///
    /// A password, a one-time code and a passkey have host-checked requests of their own. A recovery code is a
    /// one-time code that needs no device, and an API key is a bearer credential: typed into a look-alike page they
    /// are replayed at once, which is why PRD F11.4 withholds codes on a mismatch instead of warning, and with no
    /// host there is no way to tell a mismatch. Security answers, PINs and custom secret fields are held to the same
    /// rule: each signs someone in, or recovers an account, somewhere. What remains is what a person reads off a
    /// card or a letter: user names, emails, phone, account and card numbers, dates, addresses.
    static func isInsertable(_ kind: FieldKind) -> Bool {
        !kind.isSecret
    }

    func text(fieldID: UUID, part: TextPart) -> Result<TextToInsert, ProviderRefusal> {
        guard let field = item.fields.first(where: { $0.id == fieldID }) else { return .failure(.unknownRecord) }
        guard ManualChoice.isInsertable(field.kind) else { return .failure(.fieldWithheld(field.kind)) }
        return plainText(of: field, part: part)
    }
}

/// A field's value as text, or one recovery code. Callers have already dealt with the kinds that are not plain text.
private func plainText(of field: Field, part: TextPart) -> Result<TextToInsert, ProviderRefusal> {
    switch (field.kind, part) {
    case (.recoveryCodes, .recoveryCode(let index)):
        let codes = field.recoveryCodes
        guard codes.indices.contains(index) else { return .failure(.nothingToRelease) }
        return .success(TextToInsert(codes[index]))
    case (.recoveryCodes, .whole), (_, .recoveryCode):
        // A whole list of recovery codes is never what one text field wants, and other fields have no codes.
        return .failure(.nothingToRelease)
    case (_, .whole):
        guard !field.value.isEmpty else { return .failure(.nothingToRelease) }
        return .success(TextToInsert(field.value))
    }
}
