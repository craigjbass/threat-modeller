import SwiftUI
import ThreatModelKit

/// One threat: what it is, how bad it is here, and what answers it.
struct ThreatCard: View {
    let threat: AssessedThreat
    /// What this card is for. The threats stage asks how often a threat
    /// happens. The controls stage asks what answers it.
    var focus: ThreatSidebar.Focus = .controls
    let severityChoices: [AssessedSeverity]
    let onSetControl: (_ key: String, _ implemented: Bool) -> Void
    let onSetControlStatus: (_ key: String, _ statusId: String) -> Void
    /// Opens the evidence editor for one implemented control.
    var onEvidence: (AssessedControl) -> Void = { _ in }
    let onCompensate: () -> Void
    var onLikelihood: () -> Void = {}
    /// Opens the governance editor for one accepted control, or nil in a
    /// window that has no project to write the file into.
    var onGovern: ((AssessedControl) -> Void)?
    /// Opens the severity decision editor, or nil in a window that has no
    /// project. With a project, the severity tag opens this editor and the
    /// technology-wide menu is not offered: the editor writes a rationale the
    /// file keeps, and the menu's override is not written anywhere.
    var onDecideSeverity: (() -> Void)?
    let onOverride: (_ severityId: String) -> Void
    let onClearOverride: () -> Void
    /// Writes the whole `impacts` list, or nil in a window that has no
    /// project to write the `.controls` file into. With a project, each chip
    /// is a toggle; with none, the chips are read-only tags.
    var onSetImpacts: ((_ impacts: [String]) -> Void)?

    /// Opens the recommendations editor, or nil in a window that has no
    /// project to write the `.controls` file into. With none, the card still
    /// lists what the file holds.
    var onRecommend: (() -> Void)?

    /// Puts the threat's id on the clipboard, so a person can name it in a
    /// file or a ticket. A test gives its own.
    var clipboard: Clipboard = SystemClipboard()

    /// `Known vulnerabilities: CVE-2023-44487 (KEV, 1+), CVE-2024-7347 (4)`,
    /// or nil for a threat whose component states no CVE.
    static func knownVulnerabilitiesLine(_ threat: AssessedThreat) -> String? {
        guard threat.knownVulnerabilities.isEmpty == false else { return nil }
        return "Known vulnerabilities: "
            + threat.knownVulnerabilities.map(\.described).joined(separator: ", ")
    }

    /// `The tree <name> is closed by <control>.`, one line per tree that
    /// names this threat as its goal and is closed by a sufficient control.
    static func treeClosureLines(_ threat: AssessedThreat) -> [String] {
        threat.closedByTrees.map { "The tree \($0.treeName) is closed by \($0.control)." }
    }

    /// One line per tree this threat is on, stating the role, the tree's
    /// name, whether the tree is open, and the boost it gives the goal. An
    /// open step says why it is open.
    ///
    /// The design
    /// `docs/superpowers/specs/2026-09-17-trees-in-the-threat-list-design.md`
    /// states the words.
    static func treeLines(_ threat: AssessedThreat) -> [String] {
        threat.trees.map { role in
            let head = role.isGoal ? "Goal of \(role.treeName)." : "Step on \(role.treeName)."
            if role.isTreeStale { return "\(head) The tree is stale and raises nothing." }
            guard role.isTreeOpen else { return "\(head) The tree is closed and raises nothing." }
            if role.isGoal {
                return "\(head) The tree is open and raises this threat by "
                    + "\(role.raisesRiskBy) per cent, \(role.scoreBefore) \u{2192} \(role.score)."
            }
            var said = "\(head) The tree is open and raises its goal by \(role.raisesRiskBy) per cent."
            if let because = role.stepIsOpenBecause {
                said += " This step is open: \(because)."
            } else if let closedBy = role.stepClosedBy {
                said += " This step is closed by \(closedBy)."
            }
            return said
        }
    }

    /// `Closing this breaks the tree <name>.`, one line per open tree this
    /// control closes a step on. Empty for a control that closes no route.
    static func breaksTreeLines(_ control: AssessedControl) -> [String] {
        control.closesTreeNames.map { "Closing this breaks the tree \($0)." }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            header
            tags

            Text(threat.context ?? threat.description)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)

            ForEach(threat.mitreTechniques, id: \.id) { technique in
                // The id is a link, so a reader reaches the technique without
                // copying the id and typing the address by hand.
                HStack(spacing: 4) {
                    Link(technique.id, destination: URL(string: MitreLink.address(of: technique.id))!)
                        .font(.caption)
                        .accessibilityIdentifier("mitre-\(technique.id)")
                    Text("· \(technique.name) · \(technique.tactic)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            // Read only. A person who wants a different actor set edits the
            // `.arch` file, and the application reloads it.
            if threat.performedByLabels.isEmpty == false {
                Text("Performed by: \(threat.performedByLabels.joined(separator: ", "))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("performed-by-\(threat.threatKey)")
            }

            // Read only. The component panel writes the CVEs; the lock file
            // ranks them.
            if let line = Self.knownVulnerabilitiesLine(threat) {
                Text(line)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("known-vulnerabilities-\(threat.threatKey)")
            }

            // Read only. The Attack Trees stage draws the route; this list
            // is where a person answers it.
            ForEach(Self.treeLines(threat), id: \.self) { line in
                Text(line)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("on-tree-\(threat.threatKey)")
            }

            // Read only. The Attack Trees stage names the control; the
            // Controls stage marks it implemented.
            ForEach(Self.treeClosureLines(threat), id: \.self) { line in
                Text(line)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("closed-by-tree-\(threat.threatKey)")
            }

            if focus == .controls {
                if threat.controls.isEmpty == false {
                    Divider()
                    ForEach(threat.controls, id: \.key) { control in
                        VStack(alignment: .leading, spacing: 2) {
                            controlRow(control)
                            breaksTree(control)
                            evidence(control)
                            governance(control)
                        }
                    }
                }

                compensation
                recommendations
            } else {
                likelihood
            }
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(
            RoundedRectangle(cornerRadius: 8).strokeBorder(Color.secondary.opacity(0.25), lineWidth: 1)
        )
        .accessibilityIdentifier("threat-card-\(threat.threatId)#\(threat.source.id)")
        .contextMenu {
            Button("Copy Threat Id") { clipboard.put(text: threat.threatId) }
                .accessibilityIdentifier("copy-threat-id")
        }
    }

    /// Who carries an accepted risk, and when they read it again. The
    /// governance file states both, and the Govern button writes that file.
    @ViewBuilder
    private func governance(_ control: AssessedControl) -> some View {
        if control.statusId == "accepted" || control.acceptedBy != nil || control.reviewBy != nil {
            HStack(spacing: 4) {
                if let owner = control.acceptedBy {
                    Text("Accepted by \(owner)")
                } else {
                    // The words the check uses, so the gap reads as the
                    // failure it is.
                    Text("Accepted by nobody")
                        .foregroundStyle(Color.red)
                }
                if let reviewBy = control.reviewBy {
                    Text(
                        control.isReviewOverdue
                            ? "· review was due \(reviewBy)"
                            : "· review by \(reviewBy)"
                    )
                    .foregroundStyle(control.isReviewOverdue ? Color.red : Color.secondary)
                } else {
                    Text("· no review date")
                        .foregroundStyle(Color.red)
                }
                if let onGovern {
                    Spacer(minLength: 4)
                    Button("Govern\u{2026}") { onGovern(control) }
                        .font(.caption2)
                        .accessibilityIdentifier("govern-\(control.key)")
                }
            }
            .font(.caption2)
            .foregroundStyle(.secondary)
            .accessibilityIdentifier("governance-\(control.key)")
        }
    }

    /// Which open tree this control closes a step on. The order rule puts
    /// such a control first, and this line says what closing it would break.
    @ViewBuilder
    private func breaksTree(_ control: AssessedControl) -> some View {
        ForEach(Self.breaksTreeLines(control), id: \.self) { line in
            Text(line)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("breaks-tree-\(control.key)")
        }
    }

    /// What proves an implemented control is in place, and the button that
    /// writes it.
    @ViewBuilder
    private func evidence(_ control: AssessedControl) -> some View {
        if control.isImplemented {
            HStack(spacing: 4) {
                if let tier = control.evidenceId {
                    Text("Evidence: \(tier)")
                    if let reference = control.evidenceReference {
                        Text("· \(reference)")
                    }
                    if let verifiedOn = control.verifiedOn {
                        Text("· verified \(verifiedOn)")
                    }
                } else {
                    Text("No evidence")
                }
                Spacer(minLength: 4)
                Button("Evidence\u{2026}") { onEvidence(control) }
                    .font(.caption2)
                    .accessibilityIdentifier("evidence-edit-\(control.key)")
            }
            .font(.caption2)
            .foregroundStyle(.secondary)
            .accessibilityIdentifier("evidence-\(control.key)")
        }
    }

    /// A control carries a status, not a tick: a person may say a control is
    /// not applicable or that the risk is accepted, and a report reads both.
    private func controlRow(_ control: AssessedControl) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Toggle(isOn: Binding(
                get: { control.isImplemented },
                set: { onSetControl(control.key, $0) }
            )) {
                Text(control.description)
                    .font(.caption)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .toggleStyle(.checkbox)
            .accessibilityIdentifier("control-\(control.key)")

            Spacer(minLength: 4)

            Picker("Status", selection: Binding(
                get: { control.statusId },
                set: { onSetControlStatus(control.key, $0) }
            )) {
                ForEach(Self.statuses, id: \.0) { Text($0.1).tag($0.0) }
            }
            .labelsHidden()
            .frame(width: 140)
            .accessibilityIdentifier("control-status-\(control.key)")
        }
    }

    private static let statuses = [
        ("implemented", "Implemented"),
        ("not_implemented", "Not implemented"),
        ("not_applicable", "Not applicable"),
        ("accepted", "Accepted")
    ]

    /// What a team should do about this threat. The controls file holds one
    /// `recommendation` block a row, the report prints them in order of
    /// risk, and the governance file plans work against each text.
    @ViewBuilder
    private var recommendations: some View {
        if threat.recommendations.isEmpty == false || onRecommend != nil {
            Divider()
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                VStack(alignment: .leading, spacing: 2) {
                    if threat.recommendations.isEmpty {
                        Text("No recommendation names this threat.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(threat.recommendations, id: \.text) { recommendation in
                        VStack(alignment: .leading, spacing: 0) {
                            Text(recommendation.text)
                                .font(.caption)
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
                        .accessibilityIdentifier(
                            "recommendation-\(recommendation.text)-\(threat.threatKey)"
                        )
                    }
                }
                Spacer(minLength: 4)
                if let onRecommend {
                    Button(threat.recommendations.isEmpty ? "Recommend\u{2026}" : "Edit\u{2026}") {
                        onRecommend()
                    }
                    .font(.caption)
                    .accessibilityIdentifier("recommend-\(threat.threatKey)")
                }
            }
            .accessibilityIdentifier("recommendations-\(threat.threatKey)")
        }
    }

    @ViewBuilder
    private var compensation: some View {
        Divider()
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            if threat.compensatingLabels.isEmpty {
                Text("Nothing compensates this threat.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 1) {
                    ForEach(threat.compensatingLabels, id: \.self) { label in
                        Text(label).font(.caption)
                    }
                    if let tier = threat.compensatingEvidenceId {
                        HStack(spacing: 4) {
                            Text("Evidence: \(tier)")
                            if let reference = threat.compensatingEvidenceReference {
                                Text("· \(reference)")
                            }
                            if let verifiedOn = threat.compensatingVerifiedOn {
                                Text("· verified \(verifiedOn)")
                            }
                        }
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("compensating-evidence-\(threat.threatKey)")
                    }
                    Text("\(threat.scoreBeforeCompensation) \u{2192} \(threat.riskScore)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 4)
            Button(threat.compensatingLabels.isEmpty ? "Compensate\u{2026}" : "Edit\u{2026}") {
                onCompensate()
            }
            .font(.caption)
            .accessibilityIdentifier("compensate-\(threat.threatId)#\(threat.source.id)")
        }
    }

    /// How often an attack of this kind happens, and what a person learned
    /// that says so. The stage the threats are read in is where this belongs:
    /// it is a fact about the world, not about what the team runs.
    @ViewBuilder
    private var likelihood: some View {
        Divider()
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            VStack(alignment: .leading, spacing: 1) {
                Text("Happens: \(threat.likelihoodLabel)")
                    .font(.caption)
                Text(threat.likelihoodReason)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("likelihood-reason-\(threat.threatKey)")
                if threat.scoreBeforeLikelihood != threat.riskScore {
                    Text("\(threat.scoreBeforeLikelihood) \u{2192} \(threat.riskScore)")
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                if let rationale = threat.likelihoodRationale {
                    Text(rationale)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 4)
            Button(threat.likelihoodRationale == nil ? "How often\u{2026}" : "Edit\u{2026}") {
                onLikelihood()
            }
            .font(.caption)
            .accessibilityIdentifier("likelihood-\(threat.threatKey)")
        }
    }

    private var header: some View {
        VStack(alignment: .trailing, spacing: 1) {
            HStack(alignment: .firstTextBaseline) {
                Text(threat.name)
                    .font(.headline)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 8)
                if threat.pathwayMitigationLabels.isEmpty == false,
                   threat.scoreBeforePathwayMitigation != threat.riskScore {
                    Text("\(threat.scoreBeforePathwayMitigation)")
                        .font(.caption.monospacedDigit())
                        .strikethrough()
                        .foregroundStyle(.tertiary)
                        .help(threat.pathwayMitigationLabels.joined(separator: ", "))
                }
                Text("\(threat.riskLevel.capitalized) · \(threat.riskScore)")
                    .font(.caption.monospacedDigit())
                    .padding(.horizontal, 6)
                    .padding(.vertical, 1)
                    .background(
                        Capsule().fill(RiskPalette.background(forLevelId: threat.riskLevel))
                    )
            }
            if threat.inherentScore != threat.riskScore {
                Text("Before controls \(threat.inherentScore)")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var tags: some View {
        HStack(spacing: 6) {
            severityMenu

            ForEach(threat.stride, id: \.self) { category in
                Text(category.replacingOccurrences(of: "-", with: " ").capitalized)
                    .font(.caption2)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(Color.secondary.opacity(0.15)))
            }

            ForEach(ThreatImpact.allCases, id: \.self) { impact in
                impactChip(impact)
            }

            if threat.isTlsMitigated {
                Label("TLS", systemImage: "lock")
                    .font(.caption2)
                    .help("An endpoint enforces encryption. This does not change the score.")
            }

            Spacer(minLength: 0)
        }
    }

    /// One impact chip. Filled is on, outlined is off. A tap toggles it and
    /// writes the whole list. The last chip a threat holds stays on: an
    /// empty write cannot mean "harms nothing", so the window never offers
    /// one.
    private func impactChip(_ impact: ThreatImpact) -> some View {
        let isOn = threat.impacts.contains(impact.rawValue)
        let isLastOn = isOn && threat.impacts.count == 1

        return Button {
            toggleImpact(impact)
        } label: {
            Text(impact.label)
                .font(.caption2)
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background(
                    Capsule()
                        .fill(isOn ? Color.accentColor.opacity(0.15) : Color.clear)
                )
                .overlay(
                    Capsule().strokeBorder(
                        isOn ? Color.accentColor.opacity(0.4) : Color.secondary.opacity(0.3)
                    )
                )
        }
        .buttonStyle(.plain)
        .disabled(onSetImpacts == nil || isLastOn)
        .help(
            isLastOn
                ? "This threat needs at least one impact."
                : "This threat harms \(impact.label.lowercased())."
        )
        .accessibilityIdentifier("impact-\(impact.rawValue)-\(threat.threatKey)")
    }

    private func toggleImpact(_ impact: ThreatImpact) {
        guard let onSetImpacts else { return }
        var updated = threat.impacts
        if let index = updated.firstIndex(of: impact.rawValue) {
            updated.remove(at: index)
        } else {
            updated.append(impact.rawValue)
        }
        onSetImpacts(updated)
    }

    /// The severity control: a label, and the one number on the card the
    /// user is allowed to disagree with.
    ///
    /// In a window with a project it opens the decision editor, which writes
    /// the `severity_override` block: one threat on one source, a required
    /// rationale, kept by the compile. In a window with no project there is
    /// no controls file, so a menu writes the technology-wide override into
    /// the model instead.
    @ViewBuilder
    private var severityMenu: some View {
        if let onDecideSeverity {
            Button(action: onDecideSeverity) {
                severityTag
            }
            .buttonStyle(.plain)
            .contentShape(Rectangle())
            .accessibilityIdentifier("decide-severity-\(threat.threatKey)")
            .help(severityHelpText)
        } else {
            severityOverrideMenu
        }
    }

    private var severityTag: some View {
        HStack(spacing: 3) {
            Text(threat.severityLabel)
            if threat.overriddenSeverityId != nil || threat.severityDecision != nil {
                Image(systemName: "pencil").font(.caption2)
            }
        }
        .font(.caption2)
    }

    private var severityOverrideMenu: some View {
        Menu {
            ForEach(severityChoices, id: \.id) { severity in
                Button(severity.label) { onOverride(severity.id) }
            }
            if threat.overriddenSeverityId != nil {
                Divider()
                Button("Use the catalogue's severity") { onClearOverride() }
            }
        } label: {
            severityTag
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .disabled(threat.severityDecision != nil)
        .accessibilityIdentifier("override-\(threat.overrideKey)")
        .help(severityHelpText)
    }

    private var severityHelpText: String {
        if let decision = threat.severityDecision {
            return decision.rationale
        }
        if onDecideSeverity != nil {
            return "The severity here. Choose one and say why; the controls file keeps both."
        }
        if threat.overriddenSeverityId != nil {
            return "You set this severity. It applies everywhere this threat is raised from the same source kind."
        }
        return "The catalogue's severity"
    }
}
