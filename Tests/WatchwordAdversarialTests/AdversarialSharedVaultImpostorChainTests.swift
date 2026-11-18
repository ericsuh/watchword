import Foundation
import Testing
import WatchwordCrypto
import WatchwordEnvelope
import WatchwordModel
import WatchwordStore
import WatchwordSync
import WatchwordTestSupport

@testable import WatchwordKit
@testable import WatchwordSharing

/// A view of the household's transport run by the store (A1) that lists every object and serves none of those under
/// `prefix`: the names are there, and every fetch of one comes back empty.
actor NamesOnlyTransport: SyncTransport {
    let base: InMemorySyncTransport
    let prefix: String

    init(base: InMemorySyncTransport, prefix: String) {
        self.base = base
        self.prefix = prefix
    }

    func list(prefix: String) async throws -> [String] { await base.list(prefix: prefix) }

    func fetch(_ name: String, maximumLength: Int) async throws -> [UInt8]? {
        name.hasPrefix(prefix) ? nil : try await base.fetch(name, maximumLength: maximumLength)
    }

    func create(_ name: String, contents: [UInt8]) async throws { try await base.create(name, contents: contents) }

    func delete(_ name: String) async throws { await base.delete(name) }
}

// Review finding Z59 (docs/06-adversarial-review.md): a member's new device that holds nothing of a vault can be led
// into a chain someone else signed for the same vault ID, and it must never seal the account's real items under that
// chain's key.
extension AdversarialSharedVaultTests {
    /// The setting: an owner and a read-write member with an item of the member's in the shared vault; the member
    /// enrols a laptop over a view of the store that keeps from it every object the account's directory holds of the
    /// vault (its key wraps and markers); someone the person has reason to verify (a former member, A5) files a chain
    /// of their own for the same vault ID, listing the member under their real keys, with a grant of a key of their
    /// making, and the laptop accepts their invitation after an honest comparison of their safety number.
    struct ImpostorChain {
        let household: SharedVaultHousehold
        let owner: SharingAccount
        let member: SharingAccount
        let laptop: SharingAccount
        let view: WithholdingTransport
        let impostor: Keyset
        let vaultID: UUID
        let real: Item
        let realKey: UUID
        let impostorKey: UUID

        var directoryPrefix: String {
            AccountObjectLocation.vaultsPrefix(member.accountID) + "\(vaultID.uuidString)/"
        }

        /// `namingTheRealKeyID` makes the impostor's chain name the real key's ID (which is public) after the genesis
        /// and before the key it grants.
        static func make(seed: UInt64, namingTheRealKeyID: Bool = false) async throws -> ImpostorChain {
            let household = SharedVaultHousehold()
            let home = try await household.household(roles: [.readWrite], seed: seed)
            let (owner, member, vaultID) = (home.owner, home.members[0], home.vaultID)
            var real = AdversarialSharedVaultTests.bank(in: vaultID)
            real.title = "The household's real item"
            real = try await member.session.save(real)
            try await AdversarialSharedVaultTests.syncAll([member, owner])
            let realKey = try await member.session.sharedVaultStatus(vaultID).membership.vaultKeyID

            let view = WithholdingTransport(base: household.transport)
            let prefix = AccountObjectLocation.vaultsPrefix(member.accountID) + "\(vaultID.uuidString)/"
            await view.withhold(Set(await household.transport.list(prefix: prefix)))
            await view.withholdNew(under: prefix)
            let laptop = try await member.enrolledDevice(over: view, directory: household.directory)

            let impostor = AdversarialSharedVaultTests.forgedKeyset(for: UUID(), seed: seed + 1)
            await household.directory.publish(try impostor.publicKeyBundle())
            if namingTheRealKeyID {
                try await plantChainNaming(
                    realKey, for: vaultID, ownedBy: impostor, adding: member, on: household.transport)
            } else {
                try await AdversarialSharedVaultTests.plantChain(
                    for: vaultID, ownedBy: impostor, adding: member, granting: true, on: household.transport)
            }
            try await laptop.session.acceptInvitation(
                Invitation(vaultID: vaultID, ownerAccountID: impostor.accountID),
                ownerEvidence: .safetyNumber(try impostor.publicKeyBundle().fingerprint.safetyNumber))
            let impostorKey = try await laptop.session.sharedVaultStatus(vaultID).membership.vaultKeyID
            try await laptop.session.sync()
            return ImpostorChain(
                household: household, owner: owner, member: member, laptop: laptop, view: view, impostor: impostor,
                vaultID: vaultID, real: real, realKey: realKey, impostorKey: impostorKey)
        }

        /// A chain whose genesis key is the impostor's, which then rotates to `named` (with no grant: the impostor
        /// does not hold that key) and then to a key it grants the member.
        static func plantChainNaming(
            _ named: UUID, for vaultID: UUID, ownedBy impostor: Keyset, adding member: SharingAccount,
            on transport: InMemorySyncTransport
        ) async throws {
            var generator = SeededGenerator(seed: 5990)
            let first = VaultKey.generate(vaultID: vaultID, using: &generator)
            var ledger = try MembershipLedger.create(vaultKey: first, owner: impostor)
            let contacts = VerifiedContacts(
                store: InMemoryVerifiedContactStore(), account: try impostor.publicKeyBundle())
            let victim = try await contacts.verify(
                member.bundle, evidence: .safetyNumber(member.safetyNumber), signedBy: impostor, at: Date())
            var records = [ledger.chain[0].record]
            let addition = try ledger.proposeAddition(of: victim, as: .readWrite, signedBy: impostor)
            records.append(addition)
            var report = ledger.ingest([addition.encoded()])
            #expect(report.rejected.isEmpty)
            let rotation = try ledger.propose(.rotateKey, newKeyID: named, adding: nil, signedBy: impostor).record
            records.append(rotation)
            report = ledger.ingest([rotation.encoded()])
            #expect(report.rejected.isEmpty)
            let last = VaultKey.generate(vaultID: vaultID, using: &generator)
            let again = try ledger.propose(.rotateKey, newKeyID: last.key.keyID, adding: nil, signedBy: impostor)
                .record
            records.append(again)
            report = ledger.ingest([again.encoded()])
            #expect(report.rejected.isEmpty)
            #expect(ledger.keyEpoch(of: named) != nil, "the chain does not name the real key's ID")
            for record in records {
                let object = SharingObject(record)
                await transport.tamper(object.name, contents: object.contents)
            }
            let grant = try KeyGrantCodec.encode(VaultKeyGrant.seal(last, to: member.bundle, from: impostor))
            await transport.tamper(
                SharingObjectLocation.grantPrefix(vaultID: vaultID, keyID: last.key.keyID, recipient: member.accountID)
                    + SharingObjectLocation.digest(of: grant).map { String(format: "%02x", $0) }.joined(),
                contents: grant)
        }

        /// What the laptop holds of the real item, and every key its segments in the vault's log are sealed under.
        func laptopExposure() async throws -> (rowKey: UUID?, published: Set<UUID>) {
            let row = try await laptop.vault.store.record(RecordKey(recordID: real.id, kind: .item))
            let device = try await AdversarialSharedVaultTests.deviceID(of: laptop)
            var published: Set<UUID> = []
            for name in await household.transport.list(prefix: "vault/\(vaultID.uuidString)/log/\(device.uuidString)/")
            {
                guard let location = SyncObjectLocation(name: name),
                    let bytes = try await household.transport.fetch(name, maximumLength: 1 << 22)
                else { continue }
                let object = try SignedObject.parse(bytes)
                published.insert(
                    try EnvelopeHeader.parse(object.envelope, expecting: location.envelopeKind).header.keyID)
            }
            return (row?.keyID, published)
        }
    }

    /// Threat: the store (A1) with someone the person has reason to verify (A5). The laptop, holding nothing of the
    /// vault, joins the other party's chain: nothing on it can tell. Then the store hands it the account's directory:
    /// the real key's wrap and the phone's marker. The laptop made the real key resident with no check against the
    /// chain it holds, opened the phone's segments (on the other chain the member is a writer, and the stream is the
    /// member's), and sealed the real item again under the other chain's key, which it published: everything the
    /// account wrote in the vault, readable by the other party. The marker dispute this left was noticed and ignored.
    @Test("a member's new device led into another owner's chain never seals the account's items under its key")
    func impostorChainThenTheDirectory() async throws {
        let setting = try await ImpostorChain.make(seed: 5900)
        await setting.view.reveal()
        try await setting.laptop.session.sync()
        try await setting.laptop.session.sync()
        let exposure = try await setting.laptopExposure()
        #expect(exposure.rowKey != setting.impostorKey, "the real item was sealed under the other chain's key")
        #expect(
            !exposure.published.contains(setting.impostorKey),
            "the laptop published under the other chain's key what it had of the account's vault")
    }

    /// Threat: the same, with the store keeping the phone's marker from the laptop and handing it only the real
    /// key's wrap, so that no dispute is seen. A key of a vault this device holds a ledger for is used only once
    /// that ledger hands it to this account.
    @Test("a key the account's directory brings is not used under a ledger that never handed it to the account")
    func impostorChainThenTheKeyAlone() async throws {
        let setting = try await ImpostorChain.make(seed: 5910)
        await setting.view.reveal()
        await setting.view.withhold(
            Set(await setting.household.transport.list(prefix: setting.directoryPrefix + "shared/")))
        try await setting.laptop.session.sync()
        try await setting.laptop.session.sync()
        #expect(await setting.laptop.session.keys?.vaultKeys[setting.realKey] == nil, "the real key is resident")
        let exposure = try await setting.laptopExposure()
        #expect(exposure.rowKey == nil, "the laptop merged the account's real item into the other chain's vault")
        #expect(!exposure.published.contains(setting.impostorKey))
    }

    /// Threat: the same, where the other party also names the real key's ID in its own chain (key IDs are public:
    /// envelope headers carry them), so that a rule by key ID would take the real key as that chain's. Only a grant
    /// the chain makes to this account, opened and found to hold the same bytes, shows a key to be the chain's.
    @Test("a chain that names the real key's ID does not get the real key used under it")
    func impostorChainNamingTheRealKeyID() async throws {
        let setting = try await ImpostorChain.make(seed: 5920, namingTheRealKeyID: true)
        await setting.view.reveal()
        await setting.view.withhold(
            Set(await setting.household.transport.list(prefix: setting.directoryPrefix + "shared/")))
        try await setting.laptop.session.sync()
        try await setting.laptop.session.sync()
        #expect(await setting.laptop.session.keys?.vaultKeys[setting.realKey] == nil, "the real key is resident")
        let exposure = try await setting.laptopExposure()
        #expect(exposure.rowKey == nil, "the laptop merged the account's real item into the other chain's vault")
        #expect(!exposure.published.contains(setting.impostorKey))
    }

    /// Threat: the same two, seen from the account's side once the markers meet. The laptop's marker names the other
    /// party, the phone's names the real owner, and both devices hold a verified ledger. Nothing on either can tell
    /// which chain the person meant, so the vault is held closed on both: no write, nothing sealed or published, no
    /// proposal, not offered to AutoFill, and the vault listed as disputed. Its items stay readable. Nothing ends the
    /// dispute in this version; it is reported, not resolved.
    @Test("a vault whose owner the account's devices disagree about is held closed on all of them, ledger or not")
    func disputedOwnerHoldsTheVaultClosed() async throws {
        let setting = try await ImpostorChain.make(seed: 5930)
        let (member, laptop, vaultID) = (setting.member, setting.laptop, setting.vaultID)
        await setting.view.reveal()
        try await laptop.session.sync()
        try await member.session.sync()

        for device in [member, laptop] {
            #expect(try await device.session.sharedVaultStatus(vaultID).ownerDisputed)
            let info = try #require(try await device.session.vaults().first { $0.id == vaultID })
            #expect(info.isOwnerDisputed && info.isSharedUnavailable)
            await #expect(throws: SharedVaultError.ownerDisputed(vaultID)) {
                try await device.session.save(Self.bank(in: vaultID))
            }
            #expect(try await device.session.vaultsWithheldFromAutoFill().contains(vaultID))
            await #expect(throws: SharedVaultError.ownerDisputed(vaultID)) {
                try await device.session.rotateVaultKey(vaultID)
            }
        }
        // The phone still reads what it held.
        #expect(try await member.session.item(id: setting.real.id).title == setting.real.title)
        // Nothing the phone writes reaches the vault's log from here: its stream does not grow.
        let phoneDevice = try await Self.deviceID(of: member)
        let stream = "vault/\(vaultID.uuidString)/log/\(phoneDevice.uuidString)/"
        let before = await setting.household.transport.list(prefix: stream).count
        try await Self.syncAll([member, laptop])
        #expect(await setting.household.transport.list(prefix: stream).count == before)

        // A restart forgets nothing: the dispute is kept in the markers' rows.
        await member.session.lock()
        let relaunched = member.vault.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: member.state, contacts: member.contacts, directory: setting.household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        #expect(try await relaunched.session.sharedVaultStatus(vaultID).ownerDisputed)
    }

    /// Threat: the store (A1) lists the account's directory objects for the vault and serves none of them to a new
    /// device, so that the device holds no key and no marker of a vault its account knows. The listing says the
    /// account's other devices know the vault: the device does not answer "nobody owns it" and takes an invitation
    /// naming someone else; it waits for the objects. A device that has not listed the directory at all in this
    /// session waits the same way.
    @Test("a device whose account's directory names a vault, or has not been listed yet, takes no stranger's word")
    func directoryListingNamesTheVault() async throws {
        let household = SharedVaultHousehold()
        let home = try await household.household(roles: [.readWrite], seed: 5940)
        let (member, vaultID) = (home.members[0], home.vaultID)
        let view = NamesOnlyTransport(
            base: household.transport,
            prefix: AccountObjectLocation.vaultsPrefix(member.accountID) + "\(vaultID.uuidString)/")
        let laptop = try await member.vault.enrolledDevice(over: view)
        let state = InMemorySharingStateStore()
        let contacts = InMemoryVerifiedContactStore()
        await laptop.session.configureSharing(
            SharingSettings(state: state, contacts: contacts, directory: household.directory))
        try await laptop.session.unlock(password: TestVault.password)
        let impostor = Self.forgedKeyset(for: UUID(), seed: 5941)
        await household.directory.publish(try impostor.publicKeyBundle())
        try await Self.plantChain(
            for: vaultID, ownedBy: impostor, adding: member, granting: true, on: household.transport)
        let invitation = Invitation(vaultID: vaultID, ownerAccountID: impostor.accountID)
        let evidence = VerificationEvidence.safetyNumber(try impostor.publicKeyBundle().fingerprint.safetyNumber)

        // Listed, naming the vault, nothing served.
        try await laptop.session.sync()
        #expect(try await laptop.session.sharedVaultInvitation(vaultID) == nil, "the marker was served after all")
        await #expect(throws: SharedVaultError.ownerUnknown(vaultID)) {
            try await laptop.session.acceptInvitation(invitation, ownerEvidence: evidence)
        }
        #expect(try await laptop.session.sharedVaultIDs().isEmpty)

        // A session that has not listed the directory yet (the app relaunched, no sync since) waits the same way.
        await laptop.session.lock()
        let relaunched = laptop.relaunched()
        await relaunched.session.configureSharing(
            SharingSettings(state: state, contacts: contacts, directory: household.directory))
        try await relaunched.session.unlock(password: TestVault.password)
        await #expect(throws: SharedVaultError.ownerUnknown(vaultID)) {
            try await relaunched.session.acceptInvitation(invitation, ownerEvidence: evidence)
        }
    }
}
