import SwiftUI
import ThreatModelKit

/// One threat: what it is, how bad it is here, and what answers it.
struct ThreatCard: View {
    let threat: AssessedThreat
    let severityChoices: [AssessedSeverity]
    let onSetControl: (_ key: String, _ implemented: Bool) -> Void
    let onSetControlStatus: (_ key: String, _ statusId: String) -> Void
    let onCompensate: () -> Void
    let onOverride: (_ severityId: String) -> Void
    let onClearOverride: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            header
            tags

            Text(threat.context ?? threat.description)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)

            ForEach(threat.mitreTechniques, id: \.id) { technique in
                Text("\(technique.id) · \(technique.name) · \(technique.tactic)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if threat.controls.isEmpty == false {
                Divider()
                ForEach(threat.controls, id: \.key) { control in
                    controlRow(control)
                }
            }

            compensation
        }
        .padding(10)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(
            RoundedRectangle(cornerRadius: 8).strokeBorder(Color.secondary.opacity(0.25), lineWidth: 1)
        )
        .accessibilityIdentifier("threat-card-\(threat.threatId)#\(threat.source.id)")
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

            if threat.isTlsMitigated {
                Label("TLS", systemImage: "lock")
                    .font(.caption2)
                    .help("An endpoint enforces encryption. This does not change the score.")
            }

            Spacer(minLength: 0)
        }
    }

    /// The severity is a menu, because it is both a label and the one number
    /// on the card the user is allowed to disagree with.
    private var severityMenu: some View {
        Menu {
            ForEach(severityChoices, id: \.id) { severity in
                Button(severity.label) { onOverride(severity.id) }
            }
            if threat.overriddenSeverityId != nil {
                Divider()
                Button("Use the catalogue's severity") { onClearOverride() }
            }
        } label: {
            HStack(spacing: 3) {
                Text(threat.severityLabel)
                if threat.overriddenSeverityId != nil {
                    Image(systemName: "pencil").font(.caption2)
                }
            }
            .font(.caption2)
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .accessibilityIdentifier("override-\(threat.overrideKey)")
        .help(threat.overriddenSeverityId == nil
              ? "The catalogue's severity"
              : "You set this severity. It applies everywhere this threat is raised from the same source kind.")
    }
}
