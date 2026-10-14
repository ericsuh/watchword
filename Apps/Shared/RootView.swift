import SwiftUI
import WatchwordKit

struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        content
            .overlay {
                // Hides vault contents from the app-switcher snapshot (PRD F5.7).
                if scenePhase != .active && model.phase == .unlocked {
                    PrivacyCover()
                }
            }
            .onChange(of: scenePhase) { _, phase in
                Task {
                    switch phase {
                    case .background: await model.handle(.enteredBackground)
                    case .active: await model.handle(.enteringForeground)
                    default: break
                    }
                }
            }
            .task(id: model.phase) {
                // Idle check while unlocked; time comes from the session's clock, this only schedules the checks.
                while model.phase == .unlocked, !Task.isCancelled {
                    try? await Task.sleep(for: .seconds(15))
                    await model.handle(.tick)
                }
            }
            .onReceive(PlatformLifecycle.sleepNotifications) { _ in
                Task { await model.handle(.systemSleep) }
            }
    }

    @ViewBuilder private var content: some View {
        switch model.phase {
        case .loading:
            ProgressView()
        case .unavailable(let message):
            ContentUnavailableView(
                "Vault unavailable", systemImage: "lock.trianglebadge.exclamationmark", description: Text(message))
        case .onboarding:
            OnboardingView()
        case .emergencyKit(let kit):
            EmergencyKitView(kit: kit, isOnboarding: true)
        case .locked:
            UnlockView()
        case .unlocked:
            ItemListView()
        }
    }
}

struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.background)
            Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.secondary)
        }
        .ignoresSafeArea()
    }
}

/// An error line that VoiceOver announces.
struct ErrorText: View {
    let message: String?

    var body: some View {
        if let message, !message.isEmpty {
            Text(message)
                .foregroundStyle(.red)
                .accessibilityIdentifier("error")
        }
    }
}
