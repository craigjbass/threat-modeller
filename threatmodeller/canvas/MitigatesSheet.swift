import SwiftUI
import ThreatModelKit

/// Says that one component lowers threats on another, and whether the team
/// runs it today.
///
/// An edge is `live` when the team runs it today, and `proposed` when the team
/// would run it. Which threats it answers, and how much it takes off, are not
/// stated here: a person ticks the edge on each control it implements, on the
/// threat card, and states the reduction there. The catalogue generates the
/// controls, so the edge repeating their threats would state the same fact
/// twice. A proposed edge lowers no score today: it lowers the score the
/// report states the system would reach, and it carries the action that would
/// make it true.
struct MitigatesSheet: View {
    let session: ThreatModelSession
    let protector: ViewedComponent
    let protected: ViewedComponent
    let existing: ViewedMitigation?

    @Environment(\.dismiss) private var dismiss

    @State private var status = ComponentStatus.default.rawValue
    @State private var actionLabel = ""
    @State private var actionText = ""
    @State private var actionNote = ""
    /// The label of the assumption that holds the action up, or "" for none.
    @State private var blockedBy = ""
    @State private var actionSources = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("\(protector.name) lowers threats on \(protected.name)")
                .font(.headline)

            Form {
                Picker("The team", selection: $status) {
                    Text("runs this today").tag(ComponentStatus.live.rawValue)
                    Text("would run this").tag(ComponentStatus.proposed.rawValue)
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("mitigates-status")

                if status == ComponentStatus.proposed.rawValue {
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
                    .accessibilityIdentifier("save-mitigates")
            }
        }
        .padding(16)
        .frame(width: 520, height: 420)
        .onAppear(perform: readWhatIsThere)
        .accessibilityIdentifier("mitigates-sheet")
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
            status: status,
            actionLabel: status == ComponentStatus.proposed.rawValue && label.isEmpty == false
                ? label
                : nil,
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
