import SwiftUI
import ThreatModelKit

/// Says what severity an assessor decided one threat has on one source, and
/// why.
///
/// It writes the `severity_override` block of the `.controls` file: the block
/// `threatmodeller compile` keeps and the resolver reads ahead of the
/// technology-wide override. The rationale is required, because a decision a
/// reader cannot check is a number somebody made up.
struct SeverityDecisionSheet: View {
    let threat: AssessedThreat
    let severityChoices: [AssessedSeverity]
    let project: ProjectSession

    @Environment(\.dismiss) private var dismiss

    @State private var severityId = ""
    @State private var rationale = ""
    @State private var sources = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("How bad is \(threat.name) here?")
                .font(.headline)
            Text("On \(threat.source.displayName). The catalogue says \(catalogueSeverityLabel).")
                .font(.callout)
                .foregroundStyle(.secondary)

            Form {
                Picker("Severity", selection: $severityId) {
                    ForEach(severityChoices, id: \.id) { severity in
                        Text(severity.label).tag(severity.id)
                    }
                }
                .accessibilityIdentifier("severity-decision-severity")

                TextField("Why you say so", text: $rationale, axis: .vertical)
                    .lineLimit(2 ... 5)
                    .accessibilityIdentifier("severity-decision-rationale")

                TextField("Sources, one a line", text: $sources, axis: .vertical)
                    .lineLimit(1 ... 4)
                    .accessibilityIdentifier("severity-decision-sources")
            }
            .formStyle(.grouped)

            HStack {
                if threat.severityDecision != nil {
                    Button("Remove", role: .destructive) {
                        guard case .threat(let threatId, let sourceKind, let sourceId)?
                            = GovernanceSheet.place(of: threat.threatKey) else { return }
                        project.deleteSeverityDecision(
                            threatId: threatId,
                            sourceKind: sourceKind,
                            sourceId: sourceId
                        )
                        dismiss()
                    }
                    .accessibilityIdentifier("remove-severity-decision")
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save", action: write)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isWritable == false)
                    .accessibilityIdentifier("save-severity-decision")
            }
        }
        .padding(16)
        .frame(width: 460)
        .onAppear(perform: readWhatIsThere)
        .accessibilityIdentifier("severity-decision-sheet")
    }

    private var isWritable: Bool {
        rationale.trimmingCharacters(in: .whitespaces).isEmpty == false
            && severityId.isEmpty == false
    }

    /// What the catalogue states before any decision, for the sheet's second
    /// line.
    private var catalogueSeverityLabel: String {
        threat.severityDecision?.fromLabel ?? threat.severityLabel
    }

    /// The decision the threat already holds, so an edit starts from it. A
    /// threat with none starts from its severity as it stands.
    private func readWhatIsThere() {
        severityId = severityChoices.first { $0.label == threat.severityDecision?.toLabel }?.id
            ?? threat.severityId
        guard let decision = threat.severityDecision else { return }
        rationale = decision.rationale
        sources = decision.sources.joined(separator: "\n")
    }

    private func write() {
        guard case .threat(let threatId, let sourceKind, let sourceId)?
            = GovernanceSheet.place(of: threat.threatKey) else { return }

        project.saveSeverityDecision(
            threatId: threatId,
            sourceKind: sourceKind,
            sourceId: sourceId,
            decision: SeverityDecision(
                severityId: severityId,
                rationale: rationale.trimmingCharacters(in: .whitespaces),
                sources: sources
                    .split(separator: "\n")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { $0.isEmpty == false }
            )
        )
        dismiss()
    }
}
