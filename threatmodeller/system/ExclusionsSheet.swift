import SwiftUI
import ThreatModelKit

/// What this model does not cover, and why.
///
/// A rationale is required: an exclusion with no reason is a gap.
struct ExclusionsSheet: View {
    let session: ThreatModelSession
    let dismiss: () -> Void

    /// The fields of one `exclusion` block, as a person edits them.
    struct Draft: Equatable {
        var label = ""
        var text = ""
        var rationale = ""
    }

    @State private var draft: Draft
    /// The label of the exclusion a person opened with Edit, or nil while the
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
            kind: .exclusions,
            says: "What this model does not cover, and why. An exclusion with no reason is a gap, "
                + "so the sheet writes none.",
            fileName: session.architectureFileName,
            isWritable: isWritable,
            isEditing: editing != nil,
            dismiss: dismiss,
            write: write
        ) {
            if session.canvas.exclusions.isEmpty {
                SystemSheetEmptyNote(
                    says: "Nothing is excluded. A report says so, and a reader knows the model "
                        + "claims to cover the whole system."
                )
            } else {
                ForEach(session.canvas.exclusions, id: \.label) { exclusion in
                    SystemSheetRow(
                        identifier: "exclusion-\(exclusion.label)",
                        edit: { read(exclusion) },
                        remove: { remove(exclusion) }
                    ) {
                        Text(exclusion.label)
                            .font(.callout.weight(.semibold))
                        Text(exclusion.text)
                            .font(.caption)
                            .fixedSize(horizontal: false, vertical: true)
                        Text("Rationale: \(exclusion.rationale)")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        } form: {
            TextField("Label", text: $draft.label)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("exclusion-label")
            TextField("What the model does not cover", text: $draft.text, axis: .vertical)
                .lineLimit(3 ... 6)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("exclusion-text")
            TextField("Why", text: $draft.rationale, axis: .vertical)
                .lineLimit(3 ... 6)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("exclusion-rationale")
        }
    }

    private var isWritable: Bool {
        SystemSheetWriting.states(draft.label, draft.text)
            && SystemSheetWriting.states(draft.rationale)
    }

    /// Writes a new exclusion, or changes the one whose label the form holds.
    func write() {
        session.setExclusion(
            label: draft.label.trimmingCharacters(in: .whitespaces),
            text: draft.text.trimmingCharacters(in: .whitespaces),
            rationale: draft.rationale.trimmingCharacters(in: .whitespaces)
        )
        if session.errorMessage == nil { startANewOne() }
    }

    private func read(_ exclusion: ViewedExclusion) {
        editing = exclusion.label
        draft = Draft(
            label: exclusion.label,
            text: exclusion.text,
            rationale: exclusion.rationale
        )
    }

    private func remove(_ exclusion: ViewedExclusion) {
        if editing == exclusion.label { startANewOne() }
        session.removeExclusion(label: exclusion.label)
    }

    private func startANewOne() {
        editing = nil
        draft = Draft()
    }
}
