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
                    Label("Save System", systemImage: "square.and.arrow.down")
                        .frame(minWidth: 130)
                }
                .controlSize(.large)
                .disabled(session.chosenSystem == nil)
                .accessibilityIdentifier("save-system")

                Button {
                    session.compileReport()
                } label: {
                    Label("Compile Report", systemImage: "doc.text")
                        .frame(minWidth: 150)
                }
                .controlSize(.large)
                .disabled(session.chosenSystem == nil)
                .accessibilityIdentifier("compile-report")

                Spacer(minLength: 8)
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
}
