import SwiftUI

@main
struct WatchwordApp: App {
    @State private var model = AppModel(environment: AppEnvironment.make())
    #if os(macOS)
        @NSApplicationDelegateAdaptor(MacAppDelegate.self) private var appDelegate
    #endif

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .task { await model.start() }
                #if DEBUG
                    .preferredColorScheme(AppEnvironment.uiTestAppearance().map { $0 == .dark ? .dark : .light })
                #endif
        }
        #if os(macOS)
            // Small enough for a 1024×768 screen with the menu bar and the title bar, the CI runners' among them:
            // Settings and the account screens' sheets sit inside the window's frame, and their content scrolls.
            .defaultSize(width: 820, height: 600)
        #endif
    }
}
