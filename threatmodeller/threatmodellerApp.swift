import AppKit
import SwiftUI
import ThreatModelKit

/// macOS opens an untitled document at launch when the application declares a
/// document type. This application opens on the welcome window instead.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldOpenUntitledFile(_ sender: NSApplication) -> Bool { false }

    /// Clicking the Dock icon with no window open brings the welcome window
    /// back. When that window is gone, AppKit does what it does by default.
    func applicationShouldHandleReopen(
        _ sender: NSApplication,
        hasVisibleWindows: Bool
    ) -> Bool {
        guard hasVisibleWindows == false else { return true }

        guard let welcome = sender.windows.first(where: { $0.title == "Threat Modeller" })
        else { return true }

        welcome.makeKeyAndOrderFront(nil)
        return false
    }
}

@main
struct ThreatModellerApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    /// The project roots the user opened before, for the welcome window.
    private let recents = RecentProjects()

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
        // First in the body, so macOS opens this window at launch rather than
        // the file open panel the document type would otherwise bring up.
        Window("Threat Modeller", id: Self.welcomeWindowId) {
            WelcomeWindow(
                catalogue: catalogue,
                recents: recents,
                openProject: { openProject() },
                openRecentProject: { entry in openRecent(entry) }
            )
        }
        .windowResizability(.contentSize)

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

                Button("Synchronise Project System") { project?.save() }
                    .keyboardShortcut("s", modifiers: [.command, .option])
                    .disabled(project?.chosenSystem == nil)

                Button("Generate Report") { project?.compileReport() }
                    .keyboardShortcut("r", modifiers: [.command, .option])
                    .disabled(project?.chosenSystem == nil)
            }
            CommandGroup(after: .windowList) {
                Button("Welcome") { openWindow(id: Self.welcomeWindowId) }
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
    static let welcomeWindowId = "welcome"

    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismissWindow) private var dismissWindow

    private func openAbout() {
        openWindow(id: Self.aboutWindowId)
    }

    /// The panel's grant covers the folder and everything in it, which is what
    /// a project needs. Nothing opens a directory the user did not choose.
    private func openProject() {
        guard let project else { return }

        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Open Project"
        guard panel.runModal() == .OK, let url = panel.url else { return }

        recents.record(url: url)
        openWindow(id: Self.projectWindowId)
        project.open(root: url.path)
        dismissWindow(id: Self.welcomeWindowId)
    }

    /// A recent root was chosen. The bookmark grants the sandbox access, so
    /// the panel is not needed.
    private func openRecent(_ entry: RecentProject) {
        guard let project, let url = recents.resolve(entry) else { return }
        guard url.startAccessingSecurityScopedResource() else { return }

        openWindow(id: Self.projectWindowId)
        project.open(root: url.path)
        dismissWindow(id: Self.welcomeWindowId)
    }


}
