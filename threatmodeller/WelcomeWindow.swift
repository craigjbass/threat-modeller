import AppKit
import SwiftUI
import ThreatModelKit

/// What the application opens on.
///
/// It offers the two ways in: a project, which is a directory of .arch files,
/// and a model file, which is one document. The file open panel is no longer
/// the first thing a user meets.
struct WelcomeWindow: View {
    /// Nil when the catalogue could not be loaded. The window then offers no
    /// route, because neither route would work.
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
                routes

                Button("New Model File") { NSDocumentController.shared.newDocument(nil) }
                    .accessibilityIdentifier("welcome-new-model")

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

    private var routes: some View {
        HStack(spacing: 16) {
            route(
                title: "Open Project\u{2026}",
                explanation: "A folder of .arch files, one per system.",
                systemImage: "folder",
                identifier: "welcome-open-project",
                action: openProject
            )
            route(
                title: "Open Model File\u{2026}",
                explanation: "One document you drew in this application.",
                systemImage: "doc",
                identifier: "welcome-open-file",
                action: { NSDocumentController.shared.openDocument(nil) }
            )
        }
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
            }
            .frame(width: 220, height: 140)
            .contentShape(Rectangle())
        }
        .buttonStyle(.bordered)
        .accessibilityIdentifier(identifier)
    }

    @ViewBuilder
    private var recentList: some View {
        let projects = recents.list()
        let files = Array(NSDocumentController.shared.recentDocumentURLs.prefix(5))

        if projects.isEmpty == false || files.isEmpty == false {
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

                    ForEach(files, id: \.self) { url in
                        Button {
                            NSDocumentController.shared.openDocument(
                                withContentsOf: url,
                                display: true
                            ) { _, _, _ in }
                        } label: {
                            Label(url.lastPathComponent, systemImage: "doc")
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityIdentifier("recent-file-\(url.lastPathComponent)")
                    }
                }
                .frame(height: 130)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityIdentifier("welcome-recent")
        }
    }
}
