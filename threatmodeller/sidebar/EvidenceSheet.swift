import SwiftUI
import ThreatModelKit

/// Says what proves one control is in place: the tier, where the proof is,
/// and when somebody last checked.
///
/// The tier moves no score. With `requires_evidence_above` stated,
/// `threatmodeller check` fails an implemented control that names no tier,
/// and this sheet is where a person names one.
struct EvidenceSheet: View {
    let threat: AssessedThreat
    let control: AssessedControl
    let session: ThreatModelSession

    @Environment(\.dismiss) private var dismiss

    @State private var tierId = ""
    @State private var reference = ""
    @State private var statesVerifiedOn = false
    @State private var verifiedOn = Date()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("What proves this control?")
                .font(.headline)
            Text("\"\(control.description)\" on \(threat.source.displayName).")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Form {
                Picker("Tier", selection: $tierId) {
                    Text("No evidence").tag("")
                    ForEach(ControlEvidence.allCases, id: \.rawValue) { tier in
                        Text(tier.label.capitalized).tag(tier.rawValue)
                    }
                }
                .accessibilityIdentifier("evidence-tier")

                TextField("Where the proof is", text: $reference)
                    .accessibilityIdentifier("evidence-reference")

                HStack {
                    Toggle("Verified on", isOn: $statesVerifiedOn)
                        .accessibilityIdentifier("evidence-verified-on-states")
                    Spacer()
                    DatePicker("", selection: $verifiedOn, displayedComponents: .date)
                        .labelsHidden()
                        .disabled(statesVerifiedOn == false)
                        .accessibilityIdentifier("evidence-verified-on")
                }
            }
            .formStyle(.grouped)

            Text(
                "The tier moves no score. It says how well a reader can check "
                    + "the claim: weakest is asserted, strongest is audited."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            if let errorMessage = session.errorMessage {
                Text(errorMessage)
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save", action: save)
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("save-evidence")
            }
        }
        .padding(16)
        .frame(width: 480)
        .onAppear(perform: readWhatIsThere)
        .accessibilityIdentifier("evidence-sheet")
    }

    /// What the control already states, so an edit starts from it.
    private func readWhatIsThere() {
        tierId = control.evidenceId ?? ""
        reference = control.evidenceReference ?? ""
        if let held = GovernanceSheet.date(of: control.verifiedOn) {
            statesVerifiedOn = true
            verifiedOn = held
        }
    }

    private func save() {
        session.setControlEvidence(
            key: control.key,
            evidenceId: tierId.isEmpty ? nil : tierId,
            reference: reference.trimmingCharacters(in: .whitespaces),
            verifiedOn: statesVerifiedOn ? GovernanceSheet.text(of: verifiedOn) : nil
        )
        if session.errorMessage == nil { dismiss() }
    }
}
