import SwiftUI
import ThreatModelKit

/// What the application opens on.
///
/// There is one way in: a project, which is a directory of .arch files. A
/// system is a file in that directory, so nothing here opens a single file.
struct WelcomeWindow: View {
    /// Nil when the catalogue could not be loaded. The window then offers no
    /// route, because the route would not work.
    let catalogue: ViewCatalogueVersionResponse?
    let recents: RecentProjects
    /// Runs the same open panel the File menu runs.
    let openProject: () -> Void
    let openRecentProject: (RecentProject) -> Void

    var body: some View {
        VStack(spacing: 18) {
            header

            if catalogue == nil {
                ContentUnavailableView(
                    "The catalogue could not be loaded",
                    systemImage: "exclamationmark.triangle",
                    description: Text("This application cannot open a model until it loads.")
                )
            } else {
                openProjectRoute

                recentList
            }
        }
        .padding(28)
        .frame(width: 620, height: 520)
        .accessibilityIdentifier("welcome-window")
    }

    private var header: some View {
        VStack(spacing: 4) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 40))
                .foregroundStyle(.tint)

            Text("Craig's Threat Modeller")
                .font(.largeTitle.bold())

            if let catalogue {
                Text("catalogue \(catalogue.tag)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var openProjectRoute: some View {
        route(
            title: "Open Project\u{2026}",
            explanation: "A folder of .arch files, one per system. "
                + "An empty folder starts a new one.",
            systemImage: "folder",
            identifier: "welcome-open-project",
            action: openProject
        )
    }

    private func route(
        title: String,
        explanation: String,
        systemImage: String,
        identifier: String,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: systemImage)
                    .font(.system(size: 30))
                Text(title)
                    .font(.headline)
                Text(explanation)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    // The card is one line tall without this, and the
                    // explanation is longer than one line.
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(width: 360)
            .padding(.vertical, 20)
            .contentShape(Rectangle())
        }
        .buttonStyle(.bordered)
        .accessibilityIdentifier(identifier)
    }

    @ViewBuilder
    private var recentList: some View {
        let projects = recents.list()

        if projects.isEmpty == false {
            VStack(alignment: .leading, spacing: 4) {
                Text("Recent")
                    .font(.headline)

                List {
                    ForEach(projects) { project in
                        Button {
                            openRecentProject(project)
                        } label: {
                            Label(project.name, systemImage: "folder")
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("recent-project-\(project.name)")
                    }
                }
                .frame(height: 130)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityIdentifier("welcome-recent")
        }
    }
}
