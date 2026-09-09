import SwiftUI

/// The two things a user does with a project, as buttons in the window.
///
/// The menu carries the same two commands and the same shortcuts. This bar is
/// what tells a user who never opens a menu that they exist.
struct WorkflowBar: View {
    let session: ProjectSession

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 12) {
                Button {
                    session.save()
                } label: {
                    Label("Synchronise", systemImage: "arrow.triangle.2.circlepath")
                        .frame(minWidth: 130)
                }
                .controlSize(.large)
                .disabled(session.chosenSystem == nil)
                .accessibilityIdentifier("synchronise")

                Button {
                    session.compileReport()
                } label: {
                    Label("Generate Report", systemImage: "doc.text")
                        .frame(minWidth: 150)
                }
                .controlSize(.large)
                .disabled(session.chosenSystem == nil)
                .accessibilityIdentifier("generate-report")

                Spacer(minLength: 8)

                Toggle("Auto Sync", isOn: autoSync)
                    .toggleStyle(.checkbox)
                    .help(
                        "Redraw the diagram when a .arch or .controls file "
                            + "changes on disk."
                    )
                    .accessibilityIdentifier("auto-sync")
            }

            if let message = session.lastActionMessage {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("last-action-message")
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.bar)
        .accessibilityIdentifier("workflow-bar")
    }

    private var autoSync: Binding<Bool> {
        Binding(
            get: { session.isAutoSyncOn },
            set: { session.isAutoSyncOn = $0 }
        )
    }
}
