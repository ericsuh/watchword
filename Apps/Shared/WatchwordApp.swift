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
            // Tall enough for Settings and the account screens' sheets, which sit inside the window's frame.
            .defaultSize(width: 900, height: 780)
        #endif
    }
}
