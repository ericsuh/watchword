import Foundation
import WatchwordMatching
import WatchwordModel

/// Relying-party credential-update reports (PRD F6.7).
///
/// A report is a remote party's claim about credentials it holds, relayed by the operating system. It is honoured
/// only where that party could be handed the credential anyway: the item must pass `AutoFillGate` for the reporting
/// domain or relying party, and a passkey's stored relying party must equal the reporter exactly. What it can do is
/// small on purpose: set or clear a flag on a field, or change a passkey's account name. It cannot remove a field,
/// trash an item or touch a scope, and because every change is a new item version in a history that is never
/// pruned (F1.4), a field accepts at most one report-made change per `reportInterval`, so a site cannot grow an item
/// until it no longer saves.
extension CredentialProviderModel {
    /// How often a report may change one field.
    public static let reportInterval: TimeInterval = 24 * 60 * 60

    public func handle(_ report: CredentialUpdateReport) async -> Outcome<ReportResult> {
        await outcome {
            switch report {
            case .unusedPassword(let domain, let userName):
                guard !userName.isEmpty, Self.isDisplayable(userName) else {
                    throw Blocked.refused(.invalidRequest("userName"))
                }
                let identifier = ServiceIdentifier(domain, kind: .domain)
                do {
                    _ = try HostNormalizer.normalize(identifier)
                } catch {
                    throw Blocked.refused(
                        .gate(.unusableIdentifier((error as? HostNormalizationError) ?? .invalidHost(domain))))
                }
                return try await self.apply(to: identifier) { item, field in
                    // The item's first password, the one a fill would return, for that login.
                    guard field.kind == .password, field.id == item.field(.password)?.id,
                        item.loginNames.contains(userName), field.reportedUnusedAt == nil
                    else { return nil }
                    return (.flaggedUnusedPassword, { $0.setTimestamp($1, for: Field.reportedUnusedKey) })
                }

            case .passkeyRenamed(let relyingPartyID, let userHandle, let newName):
                let relyingParty = try Self.relyingParty(relyingPartyID)
                guard PasskeyCredential.userHandleLengthRange.contains(userHandle.count) else {
                    throw Blocked.refused(.invalidRequest("userHandle"))
                }
                guard !newName.isEmpty, Self.isDisplayable(newName) else {
                    throw Blocked.refused(.invalidRequest("newName"))
                }
                return try await self.apply(to: relyingParty.serviceIdentifier) { _, field in
                    guard let credential = Self.credential(in: field, of: relyingParty),
                        credential.userHandle == userHandle, credential.userName != newName
                    else { return nil }
                    var renamed = credential
                    renamed.userName = newName
                    guard let value = try? renamed.fieldValue() else { return nil }
                    return (.renamedPasskey, { field, _ in field.value = value })
                }

            case .unknownPasskey(let relyingPartyID, let credentialID):
                let relyingParty = try Self.relyingParty(relyingPartyID)
                try Self.checkCredentialList([credentialID])
                return try await self.apply(to: relyingParty.serviceIdentifier) { _, field in
                    guard let credential = Self.credential(in: field, of: relyingParty),
                        credential.credentialID == credentialID, field.reportedUnknownAt == nil
                    else { return nil }
                    return (.flaggedUnknownPasskey, { $0.setTimestamp($1, for: Field.reportedUnknownKey) })
                }

            case .acceptedPasskeys(let relyingPartyID, let userHandle, let acceptedCredentialIDs):
                let relyingParty = try Self.relyingParty(relyingPartyID)
                guard PasskeyCredential.userHandleLengthRange.contains(userHandle.count) else {
                    throw Blocked.refused(.invalidRequest("userHandle"))
                }
                try Self.checkCredentialList(acceptedCredentialIDs)
                let accepted = Set(acceptedCredentialIDs)
                return try await self.apply(to: relyingParty.serviceIdentifier) { _, field in
                    guard let credential = Self.credential(in: field, of: relyingParty),
                        credential.userHandle == userHandle
                    else { return nil }
                    switch (accepted.contains(credential.credentialID), field.reportedUnknownAt != nil) {
                    case (false, false):
                        return (.flaggedUnknownPasskey, { $0.setTimestamp($1, for: Field.reportedUnknownKey) })
                    case (true, true):
                        return (
                            .clearedUnknownPasskey,
                            { field, _ in field.setTimestamp(nil, for: Field.reportedUnknownKey) }
                        )
                    default:
                        return nil
                    }
                }
            }
        }
    }

    /// The passkey in `field`, if it decodes and belongs to `relyingParty`.
    private static func credential(in field: Field, of relyingParty: RelyingPartyID) -> PasskeyCredential? {
        guard field.kind == .passkey, let credential = try? field.passkeyCredential(),
            credential.relyingPartyID == relyingParty.value
        else { return nil }
        return credential
    }

    /// What a report wants to do to one field: the kind of change, and the edit, which is given the field and the
    /// time of the report.
    private typealias FieldEdit = (kind: ReportChange.Kind, edit: (inout Field, Date) -> Void)

    /// Applies `decide` to every field of every item in use that the gate authorises for `identifier`, at most one
    /// report-made change per field per `reportInterval`, one save per item.
    private func apply(
        to identifier: ServiceIdentifier, _ decide: (Item, Field) -> FieldEdit?
    ) async throws -> ReportResult {
        let snapshot = try await load()
        let now = await clock.now()
        var result = ReportResult(changes: [], rateLimited: 0, conflicts: 0)
        for item in ReleaseGate.authorizedItems(for: identifier, in: snapshot).map(\.item) {
            var updated = item
            var changes: [ReportChange] = []
            for position in item.fields.indices {
                guard let (kind, edit) = decide(item, item.fields[position]) else { continue }
                if let last = item.fields[position].lastReportAt, now.timeIntervalSince(last) < Self.reportInterval {
                    result.rateLimited += 1
                    continue
                }
                edit(&updated.fields[position], now)
                updated.fields[position].setTimestamp(now, for: Field.lastReportKey)
                changes.append(ReportChange(itemID: item.id, fieldID: item.fields[position].id, kind: kind))
            }
            guard !changes.isEmpty else { continue }
            do {
                _ = try await save(updated, replacing: item)
                result.changes.append(contentsOf: changes)
            } catch {
                switch Self.blocked(error) {
                case .locked: throw Blocked.locked
                case .refused(.vault(.versionConflict)): result.conflicts += 1
                case .refused(let refusal): throw Blocked.refused(refusal)
                }
            }
        }
        return result
    }
}
