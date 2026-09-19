import SwiftUI
import ThreatModelKit

/// The vetting levels this system states, and how far each one answers the
/// threats an insider performs.
///
/// Issue #259. The team writing the model defines the levels, so the sheet
/// offers an empty form rather than a fixed scheme. The user panel picks one
/// of these for each person.
struct ClearancesSheet: View {
    let session: ThreatModelSession
    let dismiss: () -> Void

    /// The fields of one `clearance` block, as a person edits them.
    struct Draft: Equatable {
        var id = ""
        var name = ""
        var description = ""
        var reducesInsiderRiskBy = 0
        var rationale = ""
        var sources = ""
    }

    @State private var draft: Draft
    /// The id of the clearance a person opened with Edit, or nil while the
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
            kind: .clearances,
            says: "The vetting levels this organisation uses. A clearance every user"
                + " that reaches a component holds takes its stated percentage off"
                + " the threats an insider performs there.",
            fileName: session.architectureFileName,
            isWritable: SystemSheetWriting.states(draft.id, draft.name)
                && SystemSheetWriting.states(draft.rationale),
            isEditing: editing != nil,
            dismiss: dismiss,
            write: write
        ) {
            if session.canvas.clearances.isEmpty {
                SystemSheetEmptyNote(
                    says: "No clearance is stated. Every insider threat keeps the score it has."
                )
            } else {
                ForEach(session.canvas.clearances, id: \.id) { clearance in
                    SystemSheetRow(
                        identifier: "clearance-\(clearance.id)",
                        edit: { read(clearance) },
                        remove: { remove(clearance) }
                    ) {
                        Text("\(clearance.name) (\u{2212}\(clearance.reducesInsiderRiskBy)%)")
                            .font(.callout.weight(.semibold))
                        if clearance.description.isEmpty == false {
                            Text(clearance.description)
                                .font(.caption)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Text(clearance.rationale)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        } form: {
            TextField("Identifier", text: $draft.id)
                .textFieldStyle(.roundedBorder)
                .disabled(editing != nil)
                .accessibilityIdentifier("clearance-id")
            TextField("Name", text: $draft.name)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("clearance-name")
            TextField("What this level checks", text: $draft.description, axis: .vertical)
                .lineLimit(2 ... 4)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("clearance-description")
            Stepper(
                "Reduces insider risk by \(draft.reducesInsiderRiskBy)%",
                value: $draft.reducesInsiderRiskBy,
                in: 0 ... 100,
                step: 5
            )
            .accessibilityIdentifier("clearance-reduces-insider-risk-by")
            TextField("Why this level answers insider risk", text: $draft.rationale, axis: .vertical)
                .lineLimit(2 ... 6)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("clearance-rationale")
            TextField("Sources, separated by a comma", text: $draft.sources)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("clearance-sources")
        }
    }

    func write() {
        session.setClearance(
            id: draft.id.trimmingCharacters(in: .whitespaces),
            name: draft.name.trimmingCharacters(in: .whitespaces),
            description: draft.description.trimmingCharacters(in: .whitespaces),
            reducesInsiderRiskBy: draft.reducesInsiderRiskBy,
            rationale: draft.rationale.trimmingCharacters(in: .whitespaces),
            sources: SystemSheetWriting.split(draft.sources)
        )
        if session.errorMessage == nil { startANewOne() }
    }

    private func read(_ clearance: ViewedClearance) {
        editing = clearance.id
        draft = Draft(
            id: clearance.id,
            name: clearance.name,
            description: clearance.description,
            reducesInsiderRiskBy: clearance.reducesInsiderRiskBy,
            rationale: clearance.rationale,
            sources: SystemSheetWriting.joined(clearance.sources)
        )
    }

    private func remove(_ clearance: ViewedClearance) {
        if editing == clearance.id { startANewOne() }
        session.removeClearance(id: clearance.id)
    }

    private func startANewOne() {
        editing = nil
        draft = Draft()
    }
}
