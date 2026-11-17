import Foundation
import SecureMemory
import WatchwordCrypto
import WatchwordKit

/// A wall clock tests move by hand, so time-based policy (F5.4 expiry, F5.5 auto-lock, F1.5 retention) is tested
/// without sleeping (CLAUDE.md, "Tests").
public actor FakeClock: WallClock {
    private var current: Date

    public init(_ start: Date = Date(timeIntervalSince1970: 1_800_000_000)) {
        current = start
    }

    public func now() -> Date {
        current
    }

    public func advance(by interval: TimeInterval) {
        current = current.addingTimeInterval(interval)
    }

    public func set(_ date: Date) {
        current = date
    }
}

/// A biometric gate whose enrolment the test controls (docs/04-test-plan.md §2).
public actor FakeBiometricGate: BiometricGate {
    private var state: BiometricEnrolment

    public init(_ state: BiometricEnrolment = .enrolled(domainState: [0x01, 0x02, 0x03])) {
        self.state = state
    }

    public func enrolment() -> BiometricEnrolment {
        state
    }

    public func set(_ state: BiometricEnrolment) {
        self.state = state
    }
}

/// A Keychain that simulates what the real one does to the quick-unlock item (docs/04-test-plan.md §2): scripted
/// biometric outcomes, invalidation on enrolment change, and a way to make it release the wrong bytes.
public actor FakeKeychain: KeychainStore {
    /// What the next biometric prompt (a read of `.quickUnlockKey`) does.
    public enum BiometricOutcome: Sendable {
        case succeed
        case fail
        case cancel
        /// The OS released something, but not the stored key: models a Keychain that has been tampered with or a
        /// buggy adapter. Unlock must still fail.
        case releaseBytes([UInt8])
        /// The item is gone, as after `biometryCurrentSet` invalidation.
        case invalidated
        /// The prompt never ends: the app is killed while it is up. The read returns nothing to its caller, ever;
        /// it ends only when the task that made it is cancelled.
        case neverReturns
    }

    private var items: [KeychainItem: [UInt8]] = [:]
    private var outcomes: [BiometricOutcome] = []
    public private(set) var biometricPrompts = 0
    public private(set) var prompts: [String] = []
    private var readHook: (@Sendable (KeychainItem) async -> Void)?
    private var storeHook: (@Sendable (KeychainItem) async -> Void)?
    private var heldPrompts: [AsyncStream<Void>.Continuation] = []
    private var heldWaiters: [CheckedContinuation<Void, Never>] = []
    /// Prompts that went up and never ended (`BiometricOutcome.neverReturns`), counted from the start.
    public var promptsHeld: Int { heldPrompts.count }

    public init() {}

    public func store(_ value: SecureBytes, for item: KeychainItem) async {
        if let storeHook { await storeHook(item) }
        items[item] = value.unprotectedCopy()
    }

    public func read(_ item: KeychainItem, prompt: String) async throws -> SecureBytes? {
        if let readHook { await readHook(item) }
        guard case .quickUnlockKey = item else {
            return items[item].map { SecureBytes(copying: $0) }
        }
        biometricPrompts += 1
        prompts.append(prompt)
        let outcome = outcomes.isEmpty ? .succeed : outcomes.removeFirst()
        switch outcome {
        case .succeed: return items[item].map { SecureBytes(copying: $0) }
        case .fail: throw KeychainError.authenticationFailed
        case .cancel: throw KeychainError.userCancelled
        case .releaseBytes(let bytes): return SecureBytes(copying: bytes)
        case .invalidated:
            items[item] = nil
            return nil
        case .neverReturns:
            let (stream, continuation) = AsyncStream<Void>.makeStream()
            heldPrompts.append(continuation)
            for waiter in heldWaiters { waiter.resume() }
            heldWaiters = []
            for await _ in stream {}
            throw CancellationError()
        }
    }

    public func delete(_ item: KeychainItem) {
        items[item] = nil
    }

    // MARK: Scripting

    public func script(_ outcomes: BiometricOutcome...) {
        self.outcomes.append(contentsOf: outcomes)
    }

    /// Runs `hook` at the start of every read, before the item is looked up: where a test lands a `lock()`, or a
    /// write to the store, in the middle of an operation that is waiting on the Keychain. `nil` removes it.
    public func onRead(_ hook: (@Sendable (KeychainItem) async -> Void)?) {
        readHook = hook
    }

    /// As `onRead`, at the start of every store, before the item is written.
    public func onStore(_ hook: (@Sendable (KeychainItem) async -> Void)?) {
        storeHook = hook
    }

    /// Returns once `count` prompts have gone up that will never end.
    public func waitUntilPromptsHeld(_ count: Int) async {
        while heldPrompts.count < count {
            await withCheckedContinuation { heldWaiters.append($0) }
        }
    }

    /// Drops every biometry-bound item, as the OS does when the enrolled set changes.
    public func invalidateBiometricItems() {
        for key in items.keys {
            if case .quickUnlockKey = key { items[key] = nil }
        }
    }

    public func contains(_ item: KeychainItem) -> Bool {
        items[item] != nil
    }

    public func raw(_ item: KeychainItem) -> [UInt8]? {
        items[item]
    }

    public func overwrite(_ item: KeychainItem, with bytes: [UInt8]) {
        items[item] = bytes
    }

    public var isEmpty: Bool {
        items.isEmpty
    }
}

/// A `DeviceKeyStore` in memory: a software Ed25519 key per account, as `KeychainDeviceKeyStore` keeps, with handles
/// for what a test needs to do to it (docs/02-architecture.md §7.8).
public actor FakeDeviceKeyStore: DeviceKeyStore {
    private var held: [UUID: (deviceID: UUID, key: SoftwareDeviceKey)] = [:]
    private var generator: SeededGenerator
    public private(set) var signatures = 0

    public init(seed: UInt64 = 1) {
        generator = SeededGenerator(seed: seed)
    }

    public func create(accountID: UUID, deviceID: UUID) throws -> DevicePublicKey {
        let key = SoftwareDeviceKey.generate(using: &generator)
        held[accountID] = (deviceID, key)
        return try key.publicKey()
    }

    public func publicKey(accountID: UUID, deviceID: UUID) throws -> DevicePublicKey? {
        guard let entry = held[accountID], entry.deviceID == deviceID else { return nil }
        return try entry.key.publicKey()
    }

    public func sign(_ prepared: [UInt8], accountID: UUID, deviceID: UUID) throws -> [UInt8] {
        guard let entry = held[accountID], entry.deviceID == deviceID else { throw DeviceKeyError.keyMissing }
        signatures += 1
        return try entry.key.sign(prepared: prepared)
    }

    public func delete(accountID: UUID) {
        held[accountID] = nil
    }

    // MARK: - Test seams

    /// Loses the key, as a store restored onto other hardware does (Keychain items never leave a device).
    public func forget(accountID: UUID) {
        held[accountID] = nil
    }

    /// The key itself: what someone who extracted it from the device holds.
    public func extracted(accountID: UUID) -> SoftwareDeviceKey? {
        held[accountID]?.key
    }

    public func isEmpty() -> Bool {
        held.isEmpty
    }
}
