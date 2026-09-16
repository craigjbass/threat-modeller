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

    /// Puts the threat's id on the clipboard, so a person can name it in a
    /// file or a ticket. A test gives its own.
    var clipboard: Clipboard = SystemClipboard()

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

            if focus == .controls {
                if threat.controls.isEmpty == false {
                    Divider()
                    ForEach(threat.controls, id: \.key) { control in
                        VStack(alignment: .leading, spacing: 2) {
                            controlRow(control)
                            evidence(control)
                            governance(control)
                        }
                    }
                }

                compensation
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

            ForEach(threat.impacts, id: \.self) { impact in
                Text(ThreatImpact(rawValue: impact)?.label ?? impact)
                    .font(.caption2)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(Color.accentColor.opacity(0.15)))
                    .help("This threat harms \(ThreatImpact(rawValue: impact)?.label.lowercased() ?? impact).")
            }

            if threat.isTlsMitigated {
                Label("TLS", systemImage: "lock")
                    .font(.caption2)
                    .help("An endpoint enforces encryption. This does not change the score.")
            }

            Spacer(minLength: 0)
        }
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
