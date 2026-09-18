import SwiftUI
import ThreatModelKit

/// Names the threats one component lowers on another, and by how much.
///
/// An edge is `adopted` when the team runs it today, and `assumed` when the
/// team would run it. An assumed edge does not lower the score: it lowers the
/// score the report states the system would reach, and it carries the action
/// that would make it true.
struct MitigatesSheet: View {
    let session: ThreatModelSession
    let protector: ViewedComponent
    let protected: ViewedComponent
    let existing: ViewedMitigation?

    @Environment(\.dismiss) private var dismiss

    @State private var chosen: Set<String> = []
    @State private var percent = 50.0
    @State private var status = "adopted"
    @State private var search = ""
    @State private var actionLabel = ""
    @State private var actionText = ""
    @State private var actionNote = ""
    /// The label of the assumption that holds the action up, or "" for none.
    @State private var blockedBy = ""
    @State private var actionSources = ""

    /// The threats the protected component raises. An edge that names a
    /// threat this component never raises lowers nothing, so the list is what
    /// is on the table.
    private var choices: [AssessedThreat] {
        let raised = session.threats.filter { $0.source.id == "component:\(protected.id)" }
        guard search.trimmingCharacters(in: .whitespaces).isEmpty == false else { return raised }
        return raised.filter {
            $0.name.localizedCaseInsensitiveContains(search)
                || $0.threatId.localizedCaseInsensitiveContains(search)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("\(protector.name) lowers threats on \(protected.name)")
                .font(.headline)

            TextField("Search the threats", text: $search)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("mitigates-search")

            threatList

            Form {
                LabeledContent("Lowers each by") {
                    HStack {
                        Slider(value: $percent, in: 0 ... 100, step: 5)
                            .accessibilityIdentifier("mitigates-percent")
                        Text("\(Int(percent))%")
                            .monospacedDigit()
                            .frame(width: 50, alignment: .trailing)
                    }
                }

                Picker("The team", selection: $status) {
                    Text("runs this today").tag("adopted")
                    Text("would run this").tag("assumed")
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("mitigates-status")

                if status == "assumed" {
                    TextField("What would be done", text: $actionLabel)
                        .accessibilityIdentifier("mitigates-action-label")
                    TextField("How", text: $actionText, axis: .vertical)
                        .lineLimit(1 ... 3)
                        .accessibilityIdentifier("mitigates-action-text")
                    TextField("Why, or what it costs", text: $actionNote, axis: .vertical)
                        .lineLimit(1 ... 3)
                        .accessibilityIdentifier("mitigates-action-note")
                    Picker("Held up by", selection: $blockedBy) {
                        ForEach(
                            Self.blockedByChoices(declaring: session.canvas.assumptions),
                            id: \.tag
                        ) { choice in
                            Text(choice.word).tag(choice.tag)
                        }
                    }
                    .accessibilityIdentifier("mitigates-action-blocked-by")
                    TextField("Sources, one a line", text: $actionSources, axis: .vertical)
                        .lineLimit(1 ... 4)
                        .accessibilityIdentifier("mitigates-action-sources")
                }
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save", action: write)
                    .keyboardShortcut(.defaultAction)
                    .disabled(chosen.isEmpty)
                    .accessibilityIdentifier("save-mitigates")
            }
        }
        .padding(16)
        .frame(width: 520, height: 660)
        .onAppear(perform: readWhatIsThere)
        .accessibilityIdentifier("mitigates-sheet")
    }

    private var threatList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 4) {
                if choices.isEmpty {
                    Text("\(protected.name) raises no threats to lower.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                ForEach(choices, id: \.threatKey) { threat in
                    Toggle(isOn: binding(for: threat.threatId)) {
                        VStack(alignment: .leading, spacing: 0) {
                            Text(threat.name).font(.callout)
                            Text("\(threat.severityLabel) \u{00B7} \(threat.riskScore)")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .toggleStyle(.checkbox)
                    .accessibilityIdentifier("mitigates-threat-\(threat.threatId)")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(height: 220)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .controlBackgroundColor)))
    }

    private func binding(for threatId: String) -> Binding<Bool> {
        Binding(
            get: { chosen.contains(threatId) },
            set: { isOn in
                if isOn { chosen.insert(threatId) } else { chosen.remove(threatId) }
            }
        )
    }

    /// One choice the "Held up by" picker offers: no assumption, or one the
    /// model declares.
    enum BlockedByChoice: Equatable {
        case nothing
        case declared(String)

        /// The word the picker prints for this choice.
        var word: String {
            switch self {
            case .nothing: return "nothing"
            case .declared(let label): return label
            }
        }

        /// The value the picker's selection binds to.
        var tag: String {
            switch self {
            case .nothing: return ""
            case .declared(let label): return label
            }
        }
    }

    /// The picker's choices: `nothing`, then every assumption the model
    /// declares, and no other word.
    static func blockedByChoices(declaring assumptions: [ViewedAssumption]) -> [BlockedByChoice] {
        [.nothing] + assumptions.map { .declared($0.label) }
    }

    /// The picker's opening choice for one edge's blocker: the blocker when
    /// the model still declares it, or `nothing` when the model no longer
    /// declares it.
    static func openingBlockedBy(
        actionBlockedBy: String?,
        declaring assumptions: [ViewedAssumption]
    ) -> BlockedByChoice {
        guard let actionBlockedBy,
              assumptions.contains(where: { $0.label == actionBlockedBy }) else {
            return .nothing
        }
        return .declared(actionBlockedBy)
    }

    func readWhatIsThere() {
        guard let existing else { return }
        chosen = Set(existing.threatIds)
        percent = Double(existing.reducesRiskBy)
        status = existing.status
        actionLabel = existing.actionLabel ?? ""
        actionText = existing.actionText ?? ""
        actionNote = existing.actionNote ?? ""
        blockedBy = Self.openingBlockedBy(
            actionBlockedBy: existing.actionBlockedBy,
            declaring: session.canvas.assumptions
        ).tag
        actionSources = existing.actionSources.joined(separator: "\n")
    }

    func write() {
        let label = actionLabel.trimmingCharacters(in: .whitespaces)
        session.setMitigatesEdge(
            from: protector.id,
            to: protected.id,
            threatIds: chosen.sorted(),
            reducesRiskBy: Int(percent),
            status: status,
            actionLabel: status == "assumed" && label.isEmpty == false ? label : nil,
            actionText: written(actionText),
            actionNote: written(actionNote),
            blockedBy: blockedBy.isEmpty ? nil : blockedBy,
            sources: actionSources
                .split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { $0.isEmpty == false }
        )
        dismiss()
    }

    /// One field of the action, trimmed, or nil when a person typed nothing.
    private func written(_ field: String) -> String? {
        let trimmed = field.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? nil : trimmed
    }
}
