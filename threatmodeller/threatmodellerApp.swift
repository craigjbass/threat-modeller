import SwiftUI
import ThreatModelKit

@main
struct ThreatModellerApp: App {
    /// Read once, at launch. The catalogue does not change while the
    /// application runs, and a failed load leaves the window saying so.
    private let catalogue: ViewCatalogueVersionResponse? = {
        guard let useCases = try? Dependencies() else { return nil }
        return useCases.viewCatalogueVersion().execute(ViewCatalogueVersionRequest())
    }()

    var body: some Scene {
        DocumentGroup(newDocument: ThreatModelDocument()) { file in
            ContentView(document: file.document)
        }
        .defaultSize(width: 1400, height: 900)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Threat Modeller") { openAbout() }
            }
            ThreatModelCommands()
        }

        Window("About Threat Modeller", id: Self.aboutWindowId) {
            AboutWindow(catalogue: catalogue)
        }
        .windowResizability(.contentSize)
    }

    static let aboutWindowId = "about"

    @Environment(\.openWindow) private var openWindow

    private func openAbout() {
        openWindow(id: Self.aboutWindowId)
    }
}
