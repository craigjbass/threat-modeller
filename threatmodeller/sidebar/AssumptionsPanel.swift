import SwiftUI
import ThreatModelKit

/// What the system takes on trust, what level a finding may answer up to, and
/// what one component lowers on another.
///
/// These three are facts about the architecture that the diagram cannot draw:
/// an assumption is a sentence, the tolerance is one level, and a mitigates
/// edge names threats. The architecture stage keeps them in the column beside
/// the diagram, so a person writes them while the system is in front of them.
///
/// The other seven editors this panel once held now open from the System menu,
/// one sheet each. `docs/superpowers/specs/2026-09-16-system-menu-and-sheets-design.md`
/// states the rule that sorts an editor into this column or into a sheet.
struct AssumptionsPanel: View {
    let session: ThreatModelSession

    @State private var label = ""
    @State private var text = ""
    @State private var owner = ""

    /// The padding the column draws on every edge. A test adds it to the
    /// height of what sits above the assumptions, and reads how far down the
    /// column the assumptions header starts.
    static let topPadding: Double = 12

    /// What the column draws above the assumptions. The assumptions come
    /// first, so this holds nothing. A test measures it, so a section put
    /// above the assumptions moves the header down and the test fails.
    var aboveTheAssumptions: some View {
        EmptyView()
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                aboveTheAssumptions

                Text("What this system takes on trust")
                    .font(.subheadline.weight(.semibold))

                if session.canvas.assumptions.isEmpty {
                    Text("Nothing is assumed. A report says so, and a reader knows what was not checked.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    ForEach(session.canvas.assumptions, id: \.label) { assumption in
                        assumptionRow(assumption)
                    }
                }

                if let unblockedActionsNote = session.unblockedActionsNote {
                    Text(unblockedActionsNote)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("unblocked-actions-note")
                }

                writeOne

                Divider()
                riskTolerance

                Divider()
                requiresEvidenceAbove

                if session.canvas.mitigations.isEmpty == false {
                    Divider()
                    Text("What one component lowers on another")
                        .font(.subheadline.weight(.semibold))
                    ForEach(session.canvas.mitigations) { mitigation in
                        mitigationRow(mitigation)
                    }
                }
            }
            .padding(Self.topPadding)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle("Assumptions")
        .accessibilityIdentifier("assumptions-panel")
    }


    /// The risk level a likelihood finding may answer up to. A system that
    /// states none reads as Low, the same default `threatmodeller check`
    /// uses, so the picker never shows a level the file does not back.
    private var riskTolerance: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Risk tolerance")
                .font(.subheadline.weight(.semibold))
            Text("The level a likelihood finding may bring a threat down to.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Picker("Risk tolerance", selection: riskToleranceBinding) {
                ForEach(RiskLevel.allCases, id: \.rawValue) { level in
                    Text(level.label).tag(level.rawValue)
                }
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .accessibilityIdentifier("risk-tolerance")
        }
    }

    private var riskToleranceBinding: Binding<String> {
        Binding(
            get: { session.canvas.riskTolerance },
            set: { session.setRiskTolerance($0) }
        )
    }

    /// The tier a picker shows for "no tier needs evidence".
    private static let noEvidenceTier = ""

    /// The risk level at and above which an implemented control must state
    /// evidence. A system that states none asks for no evidence at any tier.
    private var requiresEvidenceAbove: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Requires evidence above")
                .font(.subheadline.weight(.semibold))
            Text("The tier at and above which an implemented control must state evidence.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Picker("Requires evidence above", selection: requiresEvidenceAboveBinding) {
                Text("None").tag(Self.noEvidenceTier)
                ForEach(RiskLevel.allCases, id: \.rawValue) { level in
                    Text(level.label).tag(level.rawValue)
                }
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .accessibilityIdentifier("requires-evidence-above")
        }
    }

    private var requiresEvidenceAboveBinding: Binding<String> {
        Binding(
            get: { session.canvas.requiresEvidenceAbove },
            set: { session.setRequiresEvidenceAbove($0) }
        )
    }

    private func assumptionRow(_ assumption: ViewedAssumption) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(assumption.label)
                    .font(.callout.weight(.semibold))
                Spacer(minLength: 4)
                Button {
                    session.removeAssumption(label: assumption.label)
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("remove-assumption-\(assumption.label)")
            }
            Text(assumption.text)
                .font(.caption)
                .fixedSize(horizontal: false, vertical: true)
            if let owner = assumption.owner {
                Text("Owner: \(owner)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .controlBackgroundColor)))
    }

    private func mitigationRow(_ mitigation: ViewedMitigation) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text("\(name(of: mitigation.sourceComponentId)) \u{2192} \(name(of: mitigation.targetComponentId))")
                    .font(.callout)
                Spacer(minLength: 4)
                Button {
                    session.removeMitigatesEdge(
                        from: mitigation.sourceComponentId,
                        to: mitigation.targetComponentId
                    )
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("remove-mitigates-\(mitigation.sourceComponentId)")
            }
            Text(mitigation.status.capitalized)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .controlBackgroundColor)))
    }

    private func name(of componentId: String) -> String {
        session.canvas.components.first { $0.id == componentId }?.name ?? componentId
    }

    private var writeOne: some View {
        VStack(alignment: .leading, spacing: 6) {
            TextField("Label", text: $label)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("assumption-label")

            TextField("What is taken on trust", text: $text, axis: .vertical)
                .lineLimit(2 ... 4)
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("assumption-text")

            HStack(spacing: 6) {
                TextField("Owner (optional)", text: $owner)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("assumption-owner")

                Button("Add", action: write)
                    .disabled(isWritable == false)
                    .accessibilityIdentifier("add-assumption")
            }
        }
    }

    private var isWritable: Bool {
        label.trimmingCharacters(in: .whitespaces).isEmpty == false
            && text.trimmingCharacters(in: .whitespaces).isEmpty == false
    }

    private func write() {
        let owner = owner.trimmingCharacters(in: .whitespaces)
        session.setAssumption(
            label: label.trimmingCharacters(in: .whitespaces),
            text: text.trimmingCharacters(in: .whitespaces),
            owner: owner.isEmpty ? nil : owner
        )
        label = ""
        text = ""
        self.owner = ""
    }
}
