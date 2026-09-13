import SwiftUI

/// The two things a user does with a project, as buttons in the window.
///
/// The menu carries the same two commands and the same shortcuts. This bar is
/// what tells a user who never opens a menu that they exist.
///
/// Auto Sync writes the files on its own, so a user who leaves it on presses
/// Synchronise for nothing. The button stays for the user who turns it off.
struct WorkflowBar: View {
    let session: ProjectSession

    /// The stage the window draws. Every stage keeps this bar, so the stage
    /// is a view of the work and never a mode a user has to leave.
    @Binding var stage: WorkStage

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 12) {
                Picker("Stage", selection: $stage) {
                    ForEach(WorkStage.allCases) { stage in
                        Label(stage.label, systemImage: stage.systemImage).tag(stage)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .controlSize(.large)
                .fixedSize()
                .accessibilityIdentifier("stage")

                Divider()
                    .frame(height: 20)

                Button {
                    session.saveNow()
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
                        "Save the .arch and .controls files when you change "
                            + "the model, and redraw the diagram when those "
                            + "files change on disk."
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
