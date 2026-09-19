import SwiftUI
import ThreatModelKit

/// What a person does with the system.
///
/// A report reads these under Scope, so a reader can tell a flow modelled and
/// found safe from a flow nobody modelled.
struct UseCasesSheet: View {
    let session: ThreatModelSession
    let dismiss: () -> Void

    /// The fields of one `use_case` block, as a person edits them.
    struct Draft: Equatable {
        var label = ""
        var text = ""
    }

    @State private var draft: Draft
    /// The label of the use case a person opened with Edit, or nil while the
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
            kind: .useCases,
            says: "What a person does with this system. The report reads these under Scope.",
            fileName: session.architectureFileName,
            isWritable: SystemSheetWriting.states(draft.label, draft.text),
            isEditing: editing != nil,
            dismiss: dismiss,
            write: write
        ) {
            if session.canvas.useCases.isEmpty {
                SystemSheetEmptyNote(
                    says: "No use case is stated. A reader cannot tell what this model covers."
                )
            } else {
                ForEach(session.canvas.useCases, id: \.label) { useCase in
                    SystemSheetRow(
                        identifier: "use-case-\(useCase.label)",
                        edit: { read(useCase) },
                        remove: { remove(useCase) }
                    ) {
                        Text(useCase.label)
                            .font(.callout.weight(.semibold))
                        Text(useCase.text)
                            .font(.caption)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        } form: {
            TextField("Label", text: $draft.label)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("use-case-label")
            TextField("What a person does", text: $draft.text, axis: .vertical)
                .lineLimit(3 ... 8)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("use-case-text")
        }
    }

    func write() {
        session.setSystemUseCase(
            label: draft.label.trimmingCharacters(in: .whitespaces),
            text: draft.text.trimmingCharacters(in: .whitespaces)
        )
        if session.errorMessage == nil { startANewOne() }
    }

    private func read(_ useCase: ViewedUseCase) {
        editing = useCase.label
        draft = Draft(label: useCase.label, text: useCase.text)
    }

    private func remove(_ useCase: ViewedUseCase) {
        if editing == useCase.label { startANewOne() }
        session.removeSystemUseCase(label: useCase.label)
    }

    private func startANewOne() {
        editing = nil
        draft = Draft()
    }
}
