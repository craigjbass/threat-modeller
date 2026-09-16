import AppKit
import SwiftUI
import ThreatModelKit
import UniformTypeIdentifiers

/// The application opens on the welcome window.
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// What opens a `.arch` or a `.controls` file the user double-clicked.
    /// The scene sets it, because the scene owns the project session and the
    /// windows. Until it does, a file that arrives is kept and opened then:
    /// macOS delivers the file before the first window draws.
    var openSystemFile: ((URL) -> Void)? {
        didSet {
            guard let openSystemFile else { return }
            for url in waiting { openSystemFile(url) }
            waiting = []
        }
    }

    private var waiting: [URL] = []

    func application(_ application: NSApplication, open urls: [URL]) {
        // One system at a time: a second window on the same project would
        // fight the first over its files.
        guard let url = urls.first else { return }

        if let openSystemFile {
            openSystemFile(url)
        } else {
            waiting = [url]
        }
    }

    /// Clicking the Dock icon with no window open brings the welcome window
    /// back. When that window is gone, AppKit does what it does by default.
    func applicationShouldHandleReopen(
        _ sender: NSApplication,
        hasVisibleWindows: Bool
    ) -> Bool {
        guard hasVisibleWindows == false else { return true }

        guard let welcome = sender.windows.first(where: { $0.title == "Craig's Threat Modeller" })
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

    init() {
        guard let useCases = dependencies.useCases else {
            project = nil
            return
        }
        let session = ProjectSession(useCases: useCases)
        // A path on the command line opens a project at launch, and so does
        // the setting that carries a person on where they left off.
        let choice = LaunchChoice.choose(
            commandLinePath: ProjectLaunchArgument.path(),
            reopensLastProject: UserDefaults.standard.bool(forKey: LaunchChoice.reopenKey),
            lastProject: RecentProjects().mostRecent()?.path,
            exists: { path in RecentProjects().exists(RecentProject(path: path, name: "")) }
        )
        if case .project(let root) = choice { session.reopen(root: root) }
        project = session
    }

    /// Built once, at launch. Building it parses the vendored catalogue, so
    /// nothing builds a second one.
    private let dependencies = LaunchDependencies()

    /// What the About window states about the catalogue. Nil when the
    /// dependencies could not be built, and the window says so.
    private var catalogue: ViewCatalogueVersionResponse? { dependencies.catalogue }

    /// One project session for this application. A project is a directory, and
    /// a second window on the same directory would fight the first over its
    /// files. It is nil only when the catalogue could not be loaded.
    private let project: ProjectSession?

    /// What the application opens at launch.
    private var launchChoice: LaunchChoice {
        LaunchChoice.choose(
            commandLinePath: ProjectLaunchArgument.path(),
            reopensLastProject: UserDefaults.standard.bool(forKey: LaunchChoice.reopenKey),
            lastProject: recents.mostRecent()?.path,
            exists: { path in recents.exists(RecentProject(path: path, name: "")) }
        )
    }

    var body: some Scene {
        // First in the body, so macOS opens this window at launch.
        Window("Craig's Threat Modeller", id: Self.welcomeWindowId) {
            WelcomeWindow(
                catalogue: catalogue,
                recents: recents,
                openProject: { openProject() },
                openRecentProject: { entry in openRecent(entry) }
            )
            .onAppear {
                appDelegate.openSystemFile = { url in openSystemFile(url) }
                // The project is already open by now, so the welcome window
                // steps aside and the project window comes forward.
                if case .project = launchChoice {
                    openWindow(id: Self.projectWindowId)
                    dismissWindow(id: Self.welcomeWindowId)
                }
            }
        }
        .windowResizability(.contentSize)

        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Craig's Threat Modeller") { openAbout() }

                Divider()

                Button("Install Command Line Tool\u{2026}") { openCommandLineTool() }
            }

            CommandGroup(after: .newItem) {
                Button("Open Project\u{2026}") { openProject() }
                    .keyboardShortcut("o", modifiers: [.command, .option])
                    .disabled(project == nil)

                // A person who works in one project opens it from here rather
                // than through the panel every morning.
                Menu("Open Recent") {
                    ForEach(recents.list()) { entry in
                        Button(entry.name + " \u{2014} " + entry.path) { openRecent(entry) }
                            .disabled(recents.exists(entry) == false)
                            .accessibilityIdentifier("recent-" + entry.name)
                    }

                    Divider()

                    Button("Clear Menu") { recents.clear() }
                        .accessibilityIdentifier("clear-recents")
                }
                .accessibilityIdentifier("open-recent")

                Button("Synchronise Project System") { project?.saveNow() }
                    .keyboardShortcut("s", modifiers: [.command, .option])
                    .disabled(project?.chosenSystem == nil)

                Button("Generate Report") { project?.compileReport() }
                    .keyboardShortcut("r", modifiers: [.command, .option])
                    .disabled(project?.chosenSystem == nil)

                Button("Import from Terraform\u{2026}") { importFromTerraform() }
                    .disabled(project?.chosenSystem == nil)
                    .accessibilityIdentifier("import-terraform")
            }
            CommandGroup(after: .windowList) {
                Button("Welcome") { openWindow(id: Self.welcomeWindowId) }
            }
            ThreatModelCommands()
        }

        Window("Craig's Threat Modeller Project", id: Self.projectWindowId) {
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

        Window("Command Line Tool", id: Self.commandLineWindowId) {
            CommandLineToolSheet(
                tool: CommandLineTool(),
                dismiss: { dismissWindow(id: Self.commandLineWindowId) }
            )
        }
        .windowResizability(.contentSize)

        Window("About Craig's Threat Modeller", id: Self.aboutWindowId) {
            AboutWindow(
                catalogue: catalogue,
                libraries: project?.libraries ?? [],
                attack: project?.attackHolding,
                verify: project?.attackAgreement
            )
        }
        .windowResizability(.contentSize)
    }

    static let aboutWindowId = "about"
    static let commandLineWindowId = "command-line-tool"
    static let projectWindowId = "project"
    static let welcomeWindowId = "welcome"

    @Environment(\.openWindow) private var openWindow
    @Environment(\.dismissWindow) private var dismissWindow

    private func openAbout() {
        openWindow(id: Self.aboutWindowId)
    }

    private func openCommandLineTool() {
        openWindow(id: Self.commandLineWindowId)
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
        project.reopen(root: url.path)
        dismissWindow(id: Self.welcomeWindowId)
    }

    /// A `.arch` or a `.controls` file was opened from Finder, or dropped on
    /// the Dock icon. It names the project that holds it and the system in it.
    private func openSystemFile(_ url: URL) {
        guard let project else { return }

        openWindow(id: Self.projectWindowId)
        Task {
            guard await project.openSystemFile(at: url.path) else { return }
            recents.record(url: URL(fileURLWithPath: project.root ?? url.path))
            dismissWindow(id: Self.welcomeWindowId)
        }
    }

    /// A recent root was chosen. The application is not sandboxed, so the path
    /// is enough and the panel is not needed.
    private func openRecent(_ entry: RecentProject) {
        guard let project, let url = recents.resolve(entry) else { return }

        openWindow(id: Self.projectWindowId)
        project.reopen(root: url.path)
        dismissWindow(id: Self.welcomeWindowId)
    }

    /// The file `terraform show -json` wrote. The panel takes JSON, the way
    /// the executable reads it from standard input.
    private func importFromTerraform() {
        guard let project else { return }

        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.json]
        panel.prompt = "Import"
        guard panel.runModal() == .OK, let url = panel.url else { return }

        Task { await project.importTerraform(fileAt: url.path) }
    }
}
