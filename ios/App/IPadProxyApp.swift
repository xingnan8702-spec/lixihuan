#if canImport(SwiftUI) && canImport(NetworkExtension)
import SwiftUI

@main
struct IPadProxyApp: App {
    @StateObject private var viewModel = AppViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView(viewModel: viewModel)
        }
    }
}
#endif
