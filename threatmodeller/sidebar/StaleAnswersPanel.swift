import SwiftUI
import ThreatModelKit

/// The answers the controls file still holds for threats the architecture no
/// longer raises.
///
/// Nothing deletes one on its own, and the application does not apply what it
/// holds. It is work for a person: read the answer, then either put back what
/// raised the threat or delete the answer. `threatmodeller check` exits 1
/// while one remains, so this panel is what clears that exit code.
struct StaleAnswersPanel: View {
    let project: ProjectSession

    @State private var confirmingDeleteAll = false

    var body: some View {
        let answers = project.staleAnswers
        if answers.isEmpty == false {
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline) {
                    Label(Self.label(for: answers.count), systemImage: "exclamationmark.triangle.fill")
                        .font(.subheadline.weight(.semibold))
                    Spacer(minLength: 4)
                    Button("Delete all", role: .destructive) {
                        confirmingDeleteAll = true
                    }
                    .font(.caption)
                    .accessibilityIdentifier("delete-all-stale")
                }

                ForEach(answers, id: \.described) { answer in
                    row(answer)
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.yellow.opacity(0.18))
            .accessibilityIdentifier("stale-answers")
            .sheet(isPresented: $confirmingDeleteAll) {
                StaleAnswersConfirmationSheet(project: project, answers: project.staleAnswers) {
                    confirmingDeleteAll = false
                }
            }
        }
    }

    /// What the heading says for a count of stale answers.
    static func label(for count: Int) -> String {
        count == 1
            ? "1 answer is for a threat this system no longer raises"
            : "\(count) answers are for threats this system no longer raises"
    }

    private func row(_ answer: StaleAnswer) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            VStack(alignment: .leading, spacing: 1) {
                Text(answer.threatId)
                    .font(.callout)
                Text("On \(answer.sourceKind) \"\(answer.sourceId)\" \u{00B7} \(answer.controlCount) answered")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 4)
            Button("Delete", role: .destructive) {
                project.deleteStaleAnswer(answer)
            }
            .font(.caption)
            .accessibilityIdentifier("delete-stale-\(answer.threatId)")
        }
    }
}
