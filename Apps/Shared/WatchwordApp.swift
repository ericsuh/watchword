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
            .defaultSize(width: 820, height: 560)
        #endif
    }
}
