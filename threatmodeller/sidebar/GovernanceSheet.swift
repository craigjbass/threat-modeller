import SwiftUI
import ThreatModelKit

/// Says who carries one accepted risk, and when they read it again.
///
/// The stanza it writes is the one `threatmodeller compile` keeps and
/// `threatmodeller check` reads: an accepted risk with no owner and no review
/// date fails the check, so the sheet says so.
struct GovernanceSheet: View {
    let threat: AssessedThreat
    let control: AssessedControl
    let project: ProjectSession

    @Environment(\.dismiss) private var dismiss

    @State private var owner = ""
    @State private var statesAcceptedOn = false
    @State private var acceptedOn = Date()
    @State private var statesReviewBy = false
    @State private var reviewBy = Date()
    @State private var rationale = ""
    @State private var sources = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Who carries \(threat.name)?")
                .font(.headline)
            Text("\"\(control.description)\" on \(threat.source.displayName).")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Form {
                TextField("Owner", text: $owner)
                    .accessibilityIdentifier("governance-owner")

                dateRow(
                    "Accepted on",
                    states: $statesAcceptedOn,
                    date: $acceptedOn,
                    identifier: "governance-accepted-on"
                )
                dateRow(
                    "Review by",
                    states: $statesReviewBy,
                    date: $reviewBy,
                    identifier: "governance-review-by"
                )

                TextField("Why the team carries it", text: $rationale, axis: .vertical)
                    .lineLimit(2 ... 5)
                    .accessibilityIdentifier("governance-rationale")

                TextField("Sources, one a line", text: $sources, axis: .vertical)
                    .lineLimit(1 ... 4)
                    .accessibilityIdentifier("governance-sources")
            }
            .formStyle(.grouped)

            Text(
                "threatmodeller check fails an accepted risk with no owner, "
                    + "no review date, or a review date that has passed."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save", action: write)
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("save-governance")
            }
        }
        .padding(16)
        .frame(width: 480)
        .onAppear(perform: readWhatIsThere)
        .accessibilityIdentifier("governance-sheet")
    }

    /// A date the stanza may state: a checkbox for whether it does, and a
    /// picker for the day, so nobody types a date as text.
    private func dateRow(
        _ label: String,
        states: Binding<Bool>,
        date: Binding<Date>,
        identifier: String
    ) -> some View {
        HStack {
            Toggle(label, isOn: states)
                .accessibilityIdentifier("\(identifier)-states")
            Spacer()
            DatePicker("", selection: date, displayedComponents: .date)
                .labelsHidden()
                .disabled(states.wrappedValue == false)
                .accessibilityIdentifier(identifier)
        }
    }

    /// The stanza the file already states, so an edit starts from it.
    private func readWhatIsThere() {
        guard case .threat(let threatId, let sourceKind, let sourceId)?
            = Self.place(of: threat.threatKey) else { return }
        let key = ThreatKey(threatId: threatId, sourceId: "\(sourceKind):\(sourceId)")
        guard let governed = project.governanceSource?.threat(for: key),
              let stanza = governed.accepted.first(where: {
                  $0.control == control.description && $0.isStale == false
              }) else { return }

        owner = stanza.owner
        rationale = stanza.rationale
        sources = stanza.sources.joined(separator: "\n")
        if let held = Self.date(of: stanza.acceptedOn) {
            statesAcceptedOn = true
            acceptedOn = held
        }
        if let held = Self.date(of: stanza.reviewBy) {
            statesReviewBy = true
            reviewBy = held
        }
    }

    private func write() {
        guard case .threat(let threatId, let sourceKind, let sourceId)?
            = Self.place(of: threat.threatKey) else { return }

        project.saveRiskAcceptance(
            threatId: threatId,
            sourceKind: sourceKind,
            sourceId: sourceId,
            accepted: SourceAcceptedRisk(
                control: control.description,
                owner: owner.trimmingCharacters(in: .whitespaces),
                acceptedOn: statesAcceptedOn ? Self.text(of: acceptedOn) : nil,
                reviewBy: statesReviewBy ? Self.text(of: reviewBy) : nil,
                rationale: rationale.trimmingCharacters(in: .whitespaces),
                sources: sources
                    .split(separator: "\n")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { $0.isEmpty == false }
            )
        )
        dismiss()
    }

    /// The governed place one of the assessment's threat keys names, or nil
    /// for a key this cannot read. A flow is a `connection` in the
    /// assessment's keys and a `flow` in the file, and one rule reads both.
    static func place(of key: String) -> PlannedWorkPlace? {
        let parts = key.split(separator: "@", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { return nil }
        let source = parts[1].split(separator: ":", maxSplits: 1).map(String.init)
        guard source.count == 2 else { return nil }
        return .threat(
            threatId: parts[0],
            sourceKind: source[0] == "connection" ? "flow" : source[0],
            sourceId: source[1]
        )
    }

    /// The day the picker holds, written the way the file states a date.
    static func text(of date: Date) -> String {
        let parts = Calendar.current.dateComponents([.year, .month, .day], from: date)
        return String(
            format: "%04d-%02d-%02d",
            parts.year ?? 1970,
            parts.month ?? 1,
            parts.day ?? 1
        )
    }

    /// The day a stanza states, for the picker. Nil for a stanza that states
    /// none, and for a text that is not a date.
    static func date(of raw: String?) -> Date? {
        guard let raw, case .success(let day) = GovernanceDate.read(raw) else { return nil }
        var parts = DateComponents()
        parts.year = day.year
        parts.month = day.month
        parts.day = day.day
        parts.hour = 12
        return Calendar.current.date(from: parts)
    }
}
