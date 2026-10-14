import XCTest

/// Best-effort attempt to enable the AutoFill provider from Settings (docs/04-test-plan.md §5). Enabling a third-party
/// provider from automation is unreliable on the simulator, and the extension has nothing to fill until milestone 5, so
/// the CI step that runs this is `continue-on-error` and the test skips itself for now.
final class AutoFillSettingsTests: XCTestCase {
    func testEnableAutoFillProvider() throws {
        throw XCTSkip("The AutoFill extension answers requests from milestone 5; nothing to enable yet.")
    }
}
