import Foundation
import Testing
import WatchwordKit

/// PRD F5.3/F5.4 as table tests (docs/04-test-plan.md §3, "F5.x unlock").
@Suite("Quick-unlock policy")
struct UnlockPolicyTests {
    static let enrolled = BiometricEnrolment.enrolled(domainState: [1, 2, 3])
    static let lastPassword = Date(timeIntervalSince1970: 1_800_000_000)

    static func state(failedAttempts: Int = 0, generation: UInt64 = 4, version: String = "1.0") -> QuickUnlockState {
        QuickUnlockState(
            enrolledAt: lastPassword,
            lastPasswordUnlockAt: lastPassword,
            failedAttempts: failedAttempts,
            appVersion: version,
            credentialGeneration: generation,
            biometricDomainState: Data([1, 2, 3]),
            unlockKeyID: UUID(),
            accountUnlockKeyID: UUID(),
            wrappedAccountUnlockKey: Data([0xAA])
        )
    }

    static func decide(
        state: QuickUnlockState? = state(),
        after interval: TimeInterval = 60,
        enrolment: BiometricEnrolment = enrolled,
        generation: UInt64 = 4,
        version: String = "1.0"
    ) -> UnlockDecision {
        UnlockPolicy.evaluate(
            now: lastPassword.addingTimeInterval(interval),
            state: state,
            currentAppVersion: version,
            currentCredentialGeneration: generation,
            enrolment: enrolment,
            settings: .standard
        )
    }

    @Test("allowed inside the interval with an unchanged enrolment")
    func allowed() {
        #expect(Self.decide() == .allowed)
        #expect(Self.decide(after: 14 * 86_400 - 1) == .allowed)
        #expect(Self.decide(state: Self.state(failedAttempts: 2)) == .allowed)
    }

    @Test(
        "each F5.4 expiry reason requires the password",
        arguments: zip(
            [
                decide(state: nil),
                decide(enrolment: .unavailable),
                decide(enrolment: .enrolled(domainState: [1, 2, 4])),
                decide(generation: 5),
                decide(version: "1.1"),
                decide(after: -1),
                decide(after: 14 * 86_400),
                decide(state: state(failedAttempts: 3)),
            ],
            [
                QuickUnlockRefusal.notEnabled, .biometryUnavailable, .enrolmentChanged, .credentialsChanged,
                .appUpdated,
                .clockMovedBackwards, .passwordIntervalExpired, .tooManyFailedAttempts,
            ]
        )
    )
    func refusals(_ decision: UnlockDecision, _ reason: QuickUnlockRefusal) {
        #expect(decision == .requirePassword(reason))
    }

    @Test("settings are honoured")
    func customSettings() {
        let settings = QuickUnlockSettings(passwordInterval: 3_600, maximumFailedAttempts: 1)
        let early = UnlockPolicy.evaluate(
            now: Self.lastPassword.addingTimeInterval(3_599), state: Self.state(), currentAppVersion: "1.0",
            currentCredentialGeneration: 4, enrolment: Self.enrolled, settings: settings)
        let late = UnlockPolicy.evaluate(
            now: Self.lastPassword.addingTimeInterval(3_600), state: Self.state(), currentAppVersion: "1.0",
            currentCredentialGeneration: 4, enrolment: Self.enrolled, settings: settings)
        let failed = UnlockPolicy.evaluate(
            now: Self.lastPassword, state: Self.state(failedAttempts: 1), currentAppVersion: "1.0",
            currentCredentialGeneration: 4, enrolment: Self.enrolled, settings: settings)
        #expect(early == .allowed)
        #expect(late == .requirePassword(.passwordIntervalExpired))
        #expect(failed == .requirePassword(.tooManyFailedAttempts))
    }
}

@Suite("Auto-lock policy")
struct AutoLockPolicyTests {
    static let start = Date(timeIntervalSince1970: 1_800_000_000)
    static let settings = AutoLockSettings(idleTimeout: 300, backgroundGracePeriod: 60)

    static func decide(_ event: AutoLockEvent, at offset: TimeInterval, backgroundedAt: TimeInterval? = nil)
        -> LockReason?
    {
        AutoLockPolicy.decide(
            event: event, now: start.addingTimeInterval(offset), lastActivity: start,
            backgroundedAt: backgroundedAt.map(start.addingTimeInterval), settings: settings)
    }

    @Test("idle timeout")
    func idle() {
        #expect(Self.decide(.tick, at: 299) == nil)
        #expect(Self.decide(.tick, at: 300) == .idleTimeout)
    }

    @Test("background grace period")
    func background() {
        #expect(Self.decide(.enteredBackground, at: 10) == nil)
        #expect(Self.decide(.enteringForeground, at: 69, backgroundedAt: 10) == nil)
        #expect(Self.decide(.enteringForeground, at: 70, backgroundedAt: 10) == .backgrounded)
        let immediate = AutoLockPolicy.decide(
            event: .enteredBackground, now: Self.start, lastActivity: Self.start, backgroundedAt: nil,
            settings: AutoLockSettings(idleTimeout: 300))
        #expect(immediate == .backgrounded)
    }

    @Test("sleep locks when configured")
    func sleep() {
        #expect(Self.decide(.systemSleep, at: 1) == .systemSleep)
        let keepAwake = AutoLockPolicy.decide(
            event: .systemSleep, now: Self.start, lastActivity: Self.start, backgroundedAt: nil,
            settings: AutoLockSettings(idleTimeout: 300, lockOnSleep: false))
        #expect(keepAwake == nil)
    }

    @Test("a clock that moved backwards locks rather than extending the session")
    func clockBackwards() {
        #expect(Self.decide(.tick, at: -1) == .idleTimeout)
        #expect(Self.decide(.enteringForeground, at: 5, backgroundedAt: 10) == .backgrounded)
    }

    @Test("platform defaults match F5.5")
    func defaults() {
        #expect(AutoLockSettings.iOSDefault.idleTimeout == 300)
        #expect(AutoLockSettings.macOSDefault.idleTimeout == 600)
    }
}
