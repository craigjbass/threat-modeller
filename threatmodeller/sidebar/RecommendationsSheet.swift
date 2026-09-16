import SwiftUI
import ThreatModelKit

/// Says what a team should do about one threat.
///
/// It writes the `recommendation` blocks of the `.controls` file: the blocks
/// `threatmodeller compile` keeps, the report prints in its Recommendations
/// section, and the `.governance` file plans work against.
///
/// A block carries no id, so its text names it. The list on the left states
/// what the threat holds; the form on the right writes a new block or
/// replaces the one a person chose.
struct RecommendationsSheet: View {
    let threat: AssessedThreat
    let project: ProjectSession

    @Environment(\.dismiss) private var dismiss

    /// The text of the block being edited, or nil while writing a new one.
    @State private var editing: String?
    @State private var text = ""
    @State private var note = ""
    @State private var sources = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("What should be done about \(threat.name)?")
                .font(.headline)
            Text("On \(threat.source.displayName). The report lists these in order of risk.")
                .font(.callout)
                .foregroundStyle(.secondary)

            written

            Divider()

            Form {
                TextField("What should be done", text: $text, axis: .vertical)
                    .lineLimit(1 ... 3)
                    .accessibilityIdentifier("recommendation-text")

                TextField("Why, or how", text: $note, axis: .vertical)
                    .lineLimit(1 ... 4)
                    .accessibilityIdentifier("recommendation-note")

                TextField("Sources, one a line", text: $sources, axis: .vertical)
                    .lineLimit(1 ... 4)
                    .accessibilityIdentifier("recommendation-sources")
            }
            .formStyle(.grouped)

            HStack {
                if editing != nil {
                    Button("New Recommendation") { startANewOne() }
                        .accessibilityIdentifier("new-recommendation")
                }
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(editing == nil ? "Add" : "Save", action: write)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isWritable == false)
                    .accessibilityIdentifier("save-recommendation")
            }
        }
        .padding(16)
        .frame(width: 480)
        .accessibilityIdentifier("recommendations-sheet")
    }

    /// The blocks the file holds for this threat. Each row opens for editing
    /// or comes off.
    @ViewBuilder
    private var written: some View {
        if threat.recommendations.isEmpty {
            Text("No recommendation names this threat yet.")
                .font(.caption)
                .foregroundStyle(.secondary)
        } else {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(threat.recommendations, id: \.text) { recommendation in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        VStack(alignment: .leading, spacing: 1) {
                            Text(recommendation.text)
                                .font(.callout)
                                .fixedSize(horizontal: false, vertical: true)
                            if let note = recommendation.note {
                                Text(note)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            if recommendation.sources.isEmpty == false {
                                Text(recommendation.sources.joined(separator: ", "))
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        Spacer(minLength: 4)
                        Button("Edit\u{2026}") { read(recommendation) }
                            .font(.caption)
                            .accessibilityIdentifier("edit-recommendation-\(recommendation.text)")
                        Button("Remove", role: .destructive) { remove(recommendation) }
                            .font(.caption)
                            .accessibilityIdentifier("remove-recommendation-\(recommendation.text)")
                    }
                    .accessibilityIdentifier("recommendation-row-\(recommendation.text)")
                }
            }
        }
    }

    private var isWritable: Bool {
        text.trimmingCharacters(in: .whitespaces).isEmpty == false
    }

    /// Puts one written block into the form, so a person edits it instead of
    /// typing it again.
    private func read(_ recommendation: AssessedRecommendation) {
        editing = recommendation.text
        text = recommendation.text
        note = recommendation.note ?? ""
        sources = recommendation.sources.joined(separator: "\n")
    }

    private func startANewOne() {
        editing = nil
        text = ""
        note = ""
        sources = ""
    }

    private func write() {
        guard case .threat(let threatId, let sourceKind, let sourceId)?
            = GovernanceSheet.place(of: threat.threatKey) else { return }

        let written = text.trimmingCharacters(in: .whitespaces)
        let writtenNote = note.trimmingCharacters(in: .whitespaces)
        project.saveRecommendation(
            threatId: threatId,
            sourceKind: sourceKind,
            sourceId: sourceId,
            replacing: editing,
            text: written,
            note: writtenNote.isEmpty ? nil : writtenNote,
            sources: sources
                .split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { $0.isEmpty == false }
        )
        startANewOne()
    }

    private func remove(_ recommendation: AssessedRecommendation) {
        guard case .threat(let threatId, let sourceKind, let sourceId)?
            = GovernanceSheet.place(of: threat.threatKey) else { return }

        if editing == recommendation.text { startANewOne() }
        project.deleteRecommendation(
            threatId: threatId,
            sourceKind: sourceKind,
            sourceId: sourceId,
            text: recommendation.text
        )
    }
}
