import SwiftUI
import ThreatModelKit

/// Joins the selected components into one.
///
/// The sheet lists which component stays and, for each attribute the
/// components differ in, which value stays. `MergeDraft` holds the answers;
/// the Merge button writes them through one session verb.
struct MergeSheet: View {
    let session: ThreatModelSession
    let canvas: CanvasState

    @Environment(\.dismiss) private var dismiss
    @State private var draft: MergeDraft

    init(session: ThreatModelSession, canvas: CanvasState) {
        self.session = session
        self.canvas = canvas
        _draft = State(initialValue: MergeDraft(session: session, componentIds: canvas.mergeCandidateIds))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Merge \(draft.components.count) Components")
                .font(.title2.bold())
            Text(
                "Every flow of the merged components moves to the kept one, and a flow that "
                    + "would repeat another joins it. Answers written against the merged "
                    + "components move with them."
            )
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            Form {
                Picker("Keep", selection: keep) {
                    ForEach(draft.components, id: \.id) { component in
                        Text("\(component.name) (\(component.id))").tag(component.id)
                    }
                }
                .accessibilityIdentifier("merge-keep")

                if draft.differences.isEmpty {
                    Text("The components state the same values.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(draft.differences) { difference in
                        Picker(difference.attribute.label, selection: pick(difference.attribute)) {
                            ForEach(difference.choices) { choice in
                                Text("\(choice.label) (\(choice.componentName))").tag(choice.componentId)
                            }
                        }
                        .accessibilityIdentifier("merge-\(difference.attribute.rawValue)")
                    }
                }
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("Cancel") { close() }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("merge-cancel")
                Button("Merge") { merge() }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("merge-confirm")
            }
        }
        .padding(20)
        .frame(width: 520)
        .accessibilityIdentifier("merge-sheet")
    }

    private var keep: Binding<String> {
        Binding(get: { draft.survivorId }, set: { draft.keep($0) })
    }

    private func pick(_ attribute: MergeDraft.Attribute) -> Binding<String> {
        Binding(get: { draft.picked(attribute) }, set: { draft.pick(attribute, from: $0) })
    }

    private func merge() {
        let survivor = draft.survivorId
        if session.mergeComponents(draft.resolved) {
            canvas.select(componentId: survivor, addingToSelection: false)
        }
        close()
    }

    private func close() {
        canvas.stopMerging()
        dismiss()
    }
}
