import Testing

extension Tag {
    /// Tests that model an attacker (tampering, downgrade, spoofing, resource exhaustion).
    /// The CI job `adversarial-tests` runs this target on its own so a regression is visible as
    /// its own red check (docs/04-test-plan.md §6).
    @Tag static var adversarial: Self
}
