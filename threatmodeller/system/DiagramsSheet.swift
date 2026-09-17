import SwiftUI
import ThreatModelKit

/// The pictures a team keeps beside the diagram the canvas draws.
///
/// A sequence diagram of a login, or a deployment diagram, says something the
/// data-flow diagram cannot. The report prints each one as Mermaid.
struct DiagramsSheet: View {
    let session: ThreatModelSession
    let dismiss: () -> Void

    /// The fields of one `diagram` block, as a person edits them.
    struct Draft: Equatable {
        var label = ""
        var text = ""
    }

    @State private var draft: Draft
    /// The label of the diagram a person opened with Edit, or nil while the
    /// form writes a new one.
    @State private var editing: String?

    init(
        session: ThreatModelSession,
        dismiss: @escaping () -> Void,
        draft: Draft = Draft()
    ) {
        self.session = session
        self.dismiss = dismiss
        _draft = State(initialValue: draft)
        _editing = State(initialValue: nil)
    }

    var body: some View {
        SystemSheet(
            kind: .diagrams,
            says: "Pictures this system keeps beside the diagram the canvas draws. "
                + "The report prints each one as Mermaid.",
            fileName: session.architectureFileName,
            isWritable: SystemSheetWriting.states(draft.label, draft.text),
            isEditing: editing != nil,
            dismiss: dismiss,
            write: write
        ) {
            if session.canvas.diagrams.isEmpty {
                SystemSheetEmptyNote(
                    says: "No diagram is written. A report shows only the diagram the canvas draws."
                )
            } else {
                ForEach(session.canvas.diagrams, id: \.label) { diagram in
                    SystemSheetRow(
                        identifier: "diagram-\(diagram.label)",
                        edit: { read(diagram) },
                        remove: { remove(diagram) }
                    ) {
                        Text(diagram.label)
                            .font(.callout.weight(.semibold))
                        Text(diagram.text)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            .lineLimit(4)
                    }
                }
            }
        } form: {
            TextField("Label", text: $draft.label)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("diagram-label")
            TextField("Mermaid text", text: $draft.text, axis: .vertical)
                .lineLimit(8 ... 20)
                .textFieldStyle(.roundedBorder)
                .font(.system(.body, design: .monospaced))
                .accessibilityIdentifier("diagram-text")
        }
    }

    /// Writes a new diagram, or changes the one whose label the form holds.
    func write() {
        session.setSystemDiagram(
            label: draft.label.trimmingCharacters(in: .whitespaces),
            text: draft.text.trimmingCharacters(in: .whitespaces)
        )
        if session.errorMessage == nil { startANewOne() }
    }

    private func read(_ diagram: ViewedSystemDiagram) {
        editing = diagram.label
        draft = Draft(label: diagram.label, text: diagram.text)
    }

    private func remove(_ diagram: ViewedSystemDiagram) {
        if editing == diagram.label { startANewOne() }
        session.removeSystemDiagram(label: diagram.label)
    }

    private func startANewOne() {
        editing = nil
        draft = Draft()
    }
}
