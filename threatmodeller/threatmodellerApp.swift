import AppKit
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

    /// One project session for this application. A project is a directory, and
    /// a second window on the same directory would fight the first over its
    /// files. It is nil only when the catalogue could not be loaded.
    private let project: ProjectSession? = {
        guard let useCases = try? Dependencies() else { return nil }
        let session = ProjectSession(useCases: useCases)
        // A path on the command line opens a project at launch. The interface
        // test uses it, because an open panel cannot be driven from one.
        if let root = ProjectLaunchArgument.path() { session.open(root: root) }
        return session
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

            CommandGroup(after: .newItem) {
                Button("Open Project\u{2026}") { openProject() }
                    .keyboardShortcut("o", modifiers: [.command, .option])
                    .disabled(project == nil)

                Button("Save Project System") { project?.save() }
                    .keyboardShortcut("s", modifiers: [.command, .option])
                    .disabled(project?.chosenSystem == nil)
            }
            ThreatModelCommands()
        }

        Window("Threat Modeller Project", id: Self.projectWindowId) {
            if let project {
                ProjectWindow(session: project)
                    .frame(minWidth: 900, minHeight: 600)
            } else {
                ContentUnavailableView(
                    "The catalogue could not be loaded",
                    systemImage: "exclamationmark.triangle"
                )
                .frame(minWidth: 600, minHeight: 400)
            }
        }
        .defaultSize(width: 1400, height: 900)

        Window("About Threat Modeller", id: Self.aboutWindowId) {
            AboutWindow(catalogue: catalogue)
        }
        .windowResizability(.contentSize)
    }

    static let aboutWindowId = "about"
    static let projectWindowId = "project"

    @Environment(\.openWindow) private var openWindow

    private func openAbout() {
        openWindow(id: Self.aboutWindowId)
    }

    /// The panel's grant covers the folder and everything in it, which is what
    /// a project needs. Nothing opens a directory the user did not choose.
    private func openProject() {
        guard let project else { return }
        openWindow(id: Self.projectWindowId)

        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Open Project"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        project.open(root: url.path)
    }


}
