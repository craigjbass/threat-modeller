import SwiftUI
import ThreatModelKit

/// The planned work the governance file states: who does each recommendation
/// and each action, how big it is, by when and where it stands.
///
/// The list on the left is what the file states; the editor on the right
/// writes one stanza through the same use case `threatmodeller compile`
/// keeps, so the two write the same bytes.
struct PlannedWorkSheet: View {
    let project: ProjectSession
    /// The threats the model raises, so new work names one of them rather
    /// than a place a person typed.
    let threats: [AssessedThreat]
    let dismiss: () -> Void

    /// The stanza in front, or nil while none is chosen.
    @State private var chosen: String?
    /// What a person is writing, or nil while nothing is edited.
    @State private var draft: Draft?

    /// The place key a draft uses for an action stanza.
    static let actionKey = "action"

    /// The fields of one work stanza, as a person edits them.
    struct Draft: Equatable {
        var label = ""
        /// A threat key from the assessment, or `actionKey`.
        var placeKey = PlannedWorkSheet.actionKey
        /// True for a stanza the file does not hold yet, whose label and
        /// place a person still picks.
        var isNew = false
        var owner = ""
        /// One of the three efforts, or empty for none.
        var effort = ""
        var statesDueBy = false
        var dueBy = Date()
        var status = SourcePlannedWork.defaultStatus
        var acceptance = ""
        var note = ""
        var sources = ""
    }

    private var items: [PlannedWorkItem] { project.plannedWork }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Planned work")
                .font(.headline)
            Text(
                "Who does each recommendation and each action, how big it is, "
                    + "by when and where it stands. The governance file states it."
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            HStack(alignment: .top, spacing: 16) {
                list
                Divider()
                editor
            }
            .frame(minHeight: 320)

            if let message = project.errorMessage {
                Text(message)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("planned-work-error")
            }

            HStack {
                Button("Add Work") { addWork() }
                    .accessibilityIdentifier("add-planned-work")
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("planned-work-done")
            }
        }
        .padding(20)
        .frame(minWidth: 760, minHeight: 480)
    }

    // MARK: the work the file states

    private var list: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("This system's work")
                .font(.subheadline.weight(.semibold))

            if items.isEmpty {
                Text(
                    "This system plans no work. A recommendation in the controls "
                        + "file and an action in the architecture each take a stanza."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("no-planned-work")
            }

            List(items, selection: $chosen) { item in
                VStack(alignment: .leading, spacing: 2) {
                    Text(item.work.label)
                        .font(.callout.weight(.semibold))
                        .lineLimit(2)
                    Text("On \(item.placeSays)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(item.work.says ?? "Nothing is stated yet.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .tag(item.id)
                .accessibilityIdentifier("planned-work-\(item.id)")
            }
            .frame(width: 300)
            .onChange(of: chosen) { _, _ in openTheChosenWork() }
        }
    }

    // MARK: the stanza in front

    @ViewBuilder
    private var editor: some View {
        if draft != nil {
            let held = Binding(
                get: { draft ?? Draft() },
                set: { draft = $0 }
            )
            VStack(alignment: .leading, spacing: 8) {
                if held.wrappedValue.isNew {
                    TextField("What the work is", text: held.label)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityIdentifier("planned-work-label")

                    Picker("On", selection: held.placeKey) {
                        Text("An action the architecture declares").tag(Self.actionKey)
                        ForEach(threats, id: \.threatKey) { threat in
                            Text("\(threat.name) on \(threat.source.displayName)")
                                .tag(threat.threatKey)
                        }
                    }
                    .accessibilityIdentifier("planned-work-place")
                } else {
                    Text(held.wrappedValue.label)
                        .font(.callout.weight(.semibold))
                        .fixedSize(horizontal: false, vertical: true)
                }

                Form {
                    TextField("Owner", text: held.owner)
                        .accessibilityIdentifier("planned-work-owner")

                    Picker("Effort", selection: held.effort) {
                        Text("Not stated").tag("")
                        ForEach(SourcePlannedWork.efforts, id: \.self) { effort in
                            Text(effort).tag(effort)
                        }
                    }
                    .accessibilityIdentifier("planned-work-effort")

                    HStack {
                        Toggle("Due by", isOn: held.statesDueBy)
                            .accessibilityIdentifier("planned-work-due-by-states")
                        Spacer()
                        DatePicker("", selection: held.dueBy, displayedComponents: .date)
                            .labelsHidden()
                            .disabled(held.wrappedValue.statesDueBy == false)
                            .accessibilityIdentifier("planned-work-due-by")
                    }

                    Picker("Status", selection: held.status) {
                        ForEach(SourcePlannedWork.statuses, id: \.self) { status in
                            Text(PlannedWork.Status(rawValue: status)?.label ?? status)
                                .tag(status)
                        }
                    }
                    .accessibilityIdentifier("planned-work-status")

                    TextField("Done when", text: held.acceptance, axis: .vertical)
                        .lineLimit(1 ... 4)
                        .accessibilityIdentifier("planned-work-acceptance")

                    TextField("Note", text: held.note, axis: .vertical)
                        .lineLimit(1 ... 3)
                        .accessibilityIdentifier("planned-work-note")

                    TextField("Sources, one a line", text: held.sources, axis: .vertical)
                        .lineLimit(1 ... 3)
                        .accessibilityIdentifier("planned-work-sources")
                }
                .formStyle(.grouped)

                HStack {
                    Spacer()
                    Button("Save", action: write)
                        .keyboardShortcut(.defaultAction)
                        .disabled(
                            held.wrappedValue.label
                                .trimmingCharacters(in: .whitespaces).isEmpty
                        )
                        .accessibilityIdentifier("save-planned-work")
                }
            }
        } else {
            Text("Pick a piece of work, or add one.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    // MARK: what a person changes

    private func openTheChosenWork() {
        guard let chosen, let item = items.first(where: { $0.id == chosen }) else { return }
        var opened = Draft()
        opened.label = item.work.label
        opened.isNew = false
        opened.placeKey = Self.key(of: item.place)
        opened.owner = item.work.owner
        opened.effort = item.work.effort ?? ""
        if let held = GovernanceSheet.date(of: item.work.dueBy) {
            opened.statesDueBy = true
            opened.dueBy = held
        }
        opened.status = item.work.status
        opened.acceptance = item.work.acceptance
        opened.note = item.work.note
        opened.sources = item.work.sources.joined(separator: "\n")
        draft = opened
    }

    private func addWork() {
        chosen = nil
        var added = Draft()
        added.isNew = true
        draft = added
    }

    private func write() {
        guard let draft else { return }
        let place: PlannedWorkPlace = draft.placeKey == Self.actionKey
            ? .action
            : GovernanceSheet.place(of: draft.placeKey) ?? .action

        project.savePlannedWork(
            place: place,
            work: SourcePlannedWork(
                label: draft.label.trimmingCharacters(in: .whitespaces),
                owner: draft.owner.trimmingCharacters(in: .whitespaces),
                effort: draft.effort.isEmpty ? nil : draft.effort,
                dueBy: draft.statesDueBy ? GovernanceSheet.text(of: draft.dueBy) : nil,
                status: draft.status,
                acceptance: draft.acceptance.trimmingCharacters(in: .whitespaces),
                note: draft.note.trimmingCharacters(in: .whitespaces),
                sources: draft.sources
                    .split(separator: "\n")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { $0.isEmpty == false }
            )
        )
    }

    /// The draft key one place takes: a threat key the way the assessment
    /// writes it, or `actionKey`.
    private static func key(of place: PlannedWorkPlace) -> String {
        switch place {
        case .action:
            Self.actionKey
        case .threat(let threatId, let sourceKind, let sourceId):
            "\(threatId)@\(sourceKind == "flow" ? "connection" : sourceKind):\(sourceId)"
        }
    }
}
