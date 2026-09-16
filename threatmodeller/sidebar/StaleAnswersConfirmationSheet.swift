import SwiftUI
import ThreatModelKit

/// Lists what every stale answer holds, before "Delete all" removes every
/// one of them in one write of the controls file.
///
/// A stale stanza holds more than its controls: a likelihood finding, a
/// severity decision, compensating controls and recommendations. A person
/// sees what each stanza holds before it is gone, the way the single-row
/// Delete button already states the control count beside its own row.
struct StaleAnswersConfirmationSheet: View {
    let project: ProjectSession
    let answers: [StaleAnswer]
    let dismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Delete every stale answer?")
                .font(.headline)
            Text(
                "Each row below is answered but no longer raised. A dash means the "
                    + "stanza holds nothing there."
            )
            .font(.callout)
            .foregroundStyle(.secondary)

            Table(answers) {
                TableColumn("Threat") { Text($0.threatId) }
                TableColumn("Source") { Text("\($0.sourceKind) \"\($0.sourceId)\"") }
                TableColumn("Controls") { Text(Self.cell($0.controlCount)) }
                TableColumn("Likelihood") { Text($0.hasLikelihoodFinding ? "1" : "\u{2013}") }
                TableColumn("Severity") { Text($0.hasSeverityDecision ? "1" : "\u{2013}") }
                TableColumn("Compensating") { Text(Self.cell($0.compensatingCount)) }
                TableColumn("Recommendations") { Text(Self.cell($0.recommendationCount)) }
            }
            .frame(minHeight: 160)
            .accessibilityIdentifier("stale-answers-confirmation-table")

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .accessibilityIdentifier("cancel-delete-all-stale")
                Button("Delete", role: .destructive) {
                    project.deleteStaleAnswers()
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("confirm-delete-all-stale")
            }
        }
        .padding(20)
        .frame(minWidth: 560, minHeight: 320)
        .accessibilityIdentifier("stale-answers-confirmation-sheet")
    }

    /// A count as the table states it: the number, or a dash for none.
    private static func cell(_ count: Int) -> String {
        count > 0 ? String(count) : "\u{2013}"
    }
}
