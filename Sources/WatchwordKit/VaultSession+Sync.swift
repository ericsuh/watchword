#if canImport(CryptoKit) && canImport(CommonCrypto)
    import Foundation
    import SecureMemory
    import WatchwordCrypto
    import WatchwordEnvelope
    import WatchwordMatching
    import WatchwordModel
    import WatchwordStore
    import WatchwordSync

    // Sync (PRD F7, docs/02-architecture.md §7): the production `SyncKeyring` and `ItemSealer` are this session, because
    // they need the keys it holds and must lose them when it locks.
    extension VaultSession {
        public nonisolated var isSyncConfigured: Bool {
            syncSettings != nil
        }

        /// Downloads, merges, publishes and maintains the personal vault's log (`SyncEngine.sync`). While locked only
        /// the download runs, with signatures checked against the account key kept in the Keychain; the report's
        /// `deferredUntilUnlock` says so (§7.4).
        @discardableResult
        public func sync(reconcile: Bool = false) async throws -> SyncReport {
            guard let syncSettings, let syncState else { throw VaultError.syncNotConfigured }
            guard let record = try await loadAccount() else { throw VaultError.noAccount }
            guard !syncInFlight else { throw SyncError.syncInProgress }
            syncInFlight = true
            defer { syncInFlight = false }
            let adapter = VaultSyncAdapter(session: self)
            let engine = SyncEngine(
                vaultID: record.personalVaultID, deviceID: record.deviceID, store: store,
                syncState: syncState, transport: syncSettings.transport, keyring: adapter,
                merger: ItemRecordMerger(sealer: adapter, deviceID: record.deviceID),
                configuration: syncSettings.configuration)
            return try await engine.sync(reconcile: reconcile)
        }

        // MARK: - Conflicts and the quarantine (PRD F7.6, F7.7)

        /// Resolves a conflict by the person's explicit choice: `group` takes `value`, which must be the value the
        /// item shows or one of those kept in `Item.conflicts`, and every other value for the group is discarded
        /// (`ItemMerge.resolve`). The only way sync's kept values are ever dropped, short of a permanent deletion.
        @discardableResult
        public func resolveConflict(itemID: UUID, group: ItemGroup, choosing value: ItemGroupValue) async throws
            -> Item
        {
            if case .scopes(let scopes) = value {
                for scope in scopes {
                    do {
                        try ScopePolicy.validate(scope)
                    } catch let error as ScopeValidationError {
                        throw VaultError.scopeRejected(error)
                    }
                }
            }
            let epoch = lockEpoch
            _ = try requireKeys()
            guard let record = try await loadAccount() else { throw VaultError.noAccount }
            let now = await clock.now()
            guard let row = try await store.record(RecordKey(recordID: itemID, kind: .item)) else {
                throw VaultError.itemNotFound(itemID)
            }
            let keys = try requireKeys(since: epoch)
            let item = try openItem(row, keys: keys)
            let held = [ItemMerge.currentValue(of: group, in: item)] + (item.conflicts[group] ?? []).map(\.value)
            guard held.contains(value) else { throw VaultError.conflictValueNotHeld }
            guard row.vaultID == record.personalVaultID, let vaultKey = keys.vaultKeys[record.personalVaultKeyID]
            else { throw VaultError.unknownVault(row.vaultID) }
            let revision = try nextRevision(in: row.vaultID, above: row, account: record)
            var resolved = ItemMerge.resolve(
                item, group: group, choosing: value, origin: Self.origin(row), revision: revision)
            resolved.modifiedAt = max(now, resolved.modifiedAt)
            try await commitItem(resolved, replacing: row, vaultKey: vaultKey, account: record)
            return resolved
        }

        /// Remote versions sync refused as implausible (review finding U5), kept until the person discards them.
        public func quarantinedVersions() async throws -> [SyncEntry] {
            guard let syncSettings else { return [] }
            guard let record = try await loadAccount() else { throw VaultError.noAccount }
            return try await syncSettings.state.quarantined(vaultID: record.personalVaultID)
        }

        /// Discards quarantined versions: the person's choice, so it needs the vault unlocked (PRD F7.7).
        public func discardQuarantined(_ entries: [SyncEntry]) async throws {
            _ = try requireKeys()
            guard let syncSettings else { throw VaultError.syncNotConfigured }
            guard let record = try await loadAccount() else { throw VaultError.noAccount }
            try await syncSettings.state.discardQuarantined(entries, vaultID: record.personalVaultID)
        }

        // MARK: - Keyring (called by `VaultSyncAdapter`)

        /// The keys and the account, or `SyncKeyringError.locked`. Every caller below is synchronous from here on, so
        /// a `lock()` cannot land between this check and the use of the keys.
        private func syncKeys() throws -> (UnlockedKeys, AccountRecord) {
            guard let keys, let account else { throw SyncKeyringError.locked }
            return (keys, account)
        }

        func syncSeal(_ payload: [UInt8], at location: SyncObjectLocation) throws -> [UInt8] {
            let (keys, record) = try syncKeys()
            guard location.vaultID == record.personalVaultID, let vaultKey = keys.vaultKeys[record.personalVaultKeyID]
            else { throw SyncKeyringError.unknownKey(location.vaultID) }
            return try RecordCipher.seal(
                payload, context: location.envelopeContext(keyID: vaultKey.key.keyID), key: vaultKey.key,
                using: &random)
        }

        func syncOpen(_ envelope: [UInt8], context: EnvelopeContext) throws -> [UInt8] {
            let (keys, _) = try syncKeys()
            guard let vaultKey = keys.vaultKeys[context.keyID], vaultKey.vaultID == context.vaultID else {
                throw SyncKeyringError.unknownKey(context.keyID)
            }
            let plaintext: SecureBytes
            do {
                plaintext = try RecordCipher.open(envelope, context: context, key: vaultKey.key)
            } catch {
                throw SyncKeyringError.authenticationFailed
            }
            defer { plaintext.zeroise() }
            // A segment's plaintext is storage locations and record envelopes, each sealed again on its own (§7.3).
            return plaintext.unprotectedCopy()
        }

        func syncSign(_ envelope: [UInt8], at location: SyncObjectLocation) throws -> [UInt8] {
            let (keys, record) = try syncKeys()
            guard location.author == record.deviceID, location.vaultID == record.personalVaultID else {
                throw SyncKeyringError.untrustedAuthor(location.author)
            }
            return try keys.keyset.sign(Self.syncSignedMessage(envelope, at: location), domain: .logSegment)
        }

        /// Checks a signature against the account's Ed25519 key: the keyset's own while unlocked, otherwise the copy in
        /// the Keychain. Until the device registry (review finding D9) lands, any device of the account may write; an
        /// object signed by any other key is refused. With no copy to check against (never unlocked since enrolment,
        /// or the Keychain refresh at the last unlock failed), every object is refused as `trustedKeyUnavailable`, so
        /// the report says why rather than blaming the author. The read cannot show UI: `SystemKeychainStore` sets
        /// `interactionNotAllowed` for every item but the Local Unlock Key.
        func syncVerify(_ signature: [UInt8], over envelope: [UInt8], at location: SyncObjectLocation) async throws {
            guard let record = try await loadAccount(), location.vaultID == record.personalVaultID else {
                throw SyncKeyringError.untrustedAuthor(location.author)
            }
            let signingKey: [UInt8]
            if let keys {
                signingKey = try keys.keyset.publicKeyBundle().signingKey
            } else {
                guard
                    let stored = try? await keychain.read(.accountSigningKey(accountID: record.accountID), prompt: "")
                else { throw SyncKeyringError.trustedKeyUnavailable }
                defer { stored.zeroise() }
                signingKey = stored.unprotectedCopy()
            }
            do {
                try Signatures.verify(
                    signature, for: Self.syncSignedMessage(envelope, at: location), domain: .logSegment,
                    signingKey: signingKey)
            } catch {
                throw SyncKeyringError.authenticationFailed
            }
        }

        /// What a sync object's signature covers: its name and its envelope. The envelope already binds the location
        /// (`SyncObjectLocation.envelopeContext`), but that is checked only once the vault is unlocked; binding the
        /// name into the signature also refuses a moved object at download, while locked.
        static func syncSignedMessage(_ envelope: [UInt8], at location: SyncObjectLocation) -> [UInt8] {
            Array(location.name.utf8) + [0x00] + envelope
        }

        func syncOpenItem(_ row: StoredRecord) throws -> Item {
            let (keys, _) = try syncKeys()
            return try openItem(row, keys: keys)
        }

        func syncSealItem(_ item: Item) throws -> StoredRecord {
            let (keys, record) = try syncKeys()
            guard item.vaultID == record.personalVaultID, let vaultKey = keys.vaultKeys[record.personalVaultKeyID]
            else { throw SyncKeyringError.unknownKey(item.vaultID) }
            let row = try sealItem(item, vaultKey: vaultKey, account: record)
            highestVersionSeen[item.vaultID] = max(highestVersionSeen[item.vaultID] ?? 0, item.version)
            return row
        }

        // MARK: - Pending deletions (called by `AuthenticatedSyncState`)

        /// What a pending deletion's signature covers: every field of it, fixed-length fields first and the deleted
        /// row's envelope last, so the encoding is unambiguous.
        static func pendingDeletionMessage(_ deletion: PendingDeletion) -> [UInt8] {
            let row = deletion.record
            func bytes(_ id: UUID) -> [UInt8] {
                let u = id.uuid
                return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
            }
            func bytes(_ value: UInt64) -> [UInt8] {
                (0..<8).map { UInt8(truncatingIfNeeded: value >> (56 - 8 * $0)) }
            }
            return bytes(row.vaultID) + bytes(row.recordID) + [row.kind.rawValue] + bytes(deletion.stamp.version)
                + bytes(deletion.stamp.device) + bytes(row.keyID) + bytes(row.version) + bytes(row.deviceID)
                + row.envelope
        }

        /// Signs a deletion this session just committed, so the sync layer can tell it from one planted in the state
        /// store's file (A8).
        func authenticatePendingDeletion(_ deletion: PendingDeletion) throws -> PendingDeletion {
            let (keys, record) = try syncKeys()
            guard deletion.stamp.device == record.deviceID, deletion.stamp.deleted,
                deletion.record.vaultID == record.personalVaultID
            else { throw SyncKeyringError.untrustedAuthor(deletion.stamp.device) }
            var signed = deletion
            signed.authenticator = try keys.keyset.sign(
                Self.pendingDeletionMessage(deletion), domain: .pendingDeletion)
            return signed
        }

        /// The pending deletions this device's session made: each must be this device's, in the personal vault, and
        /// signed by the account key. Any other row is ignored — never published, never treated as an erasure — so
        /// editing the file cannot erase an item everywhere. Needs the keyset; the engine reads pending deletions only
        /// to merge or publish, both of which need the vault unlocked anyway.
        func verifiedPendingDeletions(_ deletions: [RecordKey: PendingDeletion]) throws -> [RecordKey: PendingDeletion]
        {
            let (keys, record) = try syncKeys()
            let signingKey = try keys.keyset.publicKeyBundle().signingKey
            return deletions.filter { key, deletion in
                guard key == deletion.record.key, deletion.stamp.device == record.deviceID, deletion.stamp.deleted,
                    deletion.record.vaultID == record.personalVaultID
                else { return false }
                return
                    (try? Signatures.verify(
                        deletion.authenticator, for: Self.pendingDeletionMessage(deletion), domain: .pendingDeletion,
                        signingKey: signingKey)) != nil
            }
        }

        /// Copies the account's public signing key to the Keychain, for checking downloads while locked.
        func refreshSigningKey(account: AccountRecord, keys: UnlockedKeys) async throws {
            var signingKey = try keys.keyset.publicKeyBundle().signingKey
            try await keychain.store(
                SecureBytes(wiping: &signingKey), for: .accountSigningKey(accountID: account.accountID))
        }
    }

    /// The sync state store the session and its engine use: everything passes through to `base`, except that pending
    /// deletions are signed by the session as they are recorded and checked as they are read
    /// (`PendingDeletion.authenticator`, review of milestone 3).
    struct AuthenticatedSyncState: SyncStateStore {
        let base: any SyncStateStore
        let session: VaultSession

        func loadState(vaultID: UUID) async throws -> SyncState? {
            try await base.loadState(vaultID: vaultID)
        }

        func saveState(_ state: SyncState) async throws {
            try await base.saveState(state)
        }

        func stage(_ object: StagedObject) async throws {
            try await base.stage(object)
        }

        func staged(vaultID: UUID) async throws -> [StagedObject] {
            try await base.staged(vaultID: vaultID)
        }

        func unstage(_ locations: [SyncObjectLocation]) async throws {
            try await base.unstage(locations)
        }

        func addPendingDeletion(_ deletion: PendingDeletion) async throws {
            try await base.addPendingDeletion(try await session.authenticatePendingDeletion(deletion))
        }

        func pendingDeletions(vaultID: UUID) async throws -> [RecordKey: PendingDeletion] {
            try await session.verifiedPendingDeletions(try await base.pendingDeletions(vaultID: vaultID))
        }

        func removePendingDeletions(_ deletions: [RecordKey: RecordStamp], vaultID: UUID) async throws {
            try await base.removePendingDeletions(deletions, vaultID: vaultID)
        }

        func quarantine(_ entry: SyncEntry, vaultID: UUID) async throws {
            try await base.quarantine(entry, vaultID: vaultID)
        }

        func quarantined(vaultID: UUID) async throws -> [SyncEntry] {
            try await base.quarantined(vaultID: vaultID)
        }

        func discardQuarantined(_ entries: [SyncEntry], vaultID: UUID) async throws {
            try await base.discardQuarantined(entries, vaultID: vaultID)
        }

        func eraseAll() async throws {
            try await base.eraseAll()
        }
    }

    /// The session as the sync engine's keyring and the item merger's sealer. Holds the session, never a key: every
    /// call goes back to the actor, which throws `SyncKeyringError.locked` once `lock()` has run.
    struct VaultSyncAdapter: SyncKeyring, ItemSealer {
        let session: VaultSession

        func seal(_ payload: [UInt8], at location: SyncObjectLocation) async throws -> [UInt8] {
            try await session.syncSeal(payload, at: location)
        }

        func open(_ envelope: [UInt8], context: EnvelopeContext) async throws -> [UInt8] {
            try await session.syncOpen(envelope, context: context)
        }

        func sign(_ envelope: [UInt8], at location: SyncObjectLocation) async throws -> [UInt8] {
            try await session.syncSign(envelope, at: location)
        }

        func verify(_ signature: [UInt8], over envelope: [UInt8], at location: SyncObjectLocation) async throws {
            try await session.syncVerify(signature, over: envelope, at: location)
        }

        func openItem(_ row: StoredRecord) async throws -> Item {
            try await session.syncOpenItem(row)
        }

        func sealItem(_ item: Item) async throws -> StoredRecord {
            try await session.syncSealItem(item)
        }
    }
#endif
