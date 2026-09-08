import SwiftUI
import ThreatModelKit

/// Says what a team does that answers a threat the catalogue's controls do not.
///
/// This is the one control in the application that moves a score, so the
/// rationale is required and the sheet says what the reduction buys.
struct CompensatingControlSheet: View {
    let threat: AssessedThreat
    let session: ThreatModelSession

    @Environment(\.dismiss) private var dismiss

    @State private var label = ""
    @State private var percent = 40.0
    @State private var rationale = ""

    private var threatKey: String { "\(threat.threatId)@\(threat.source.id)" }

    private var wouldScore: Int {
        max(1, Int((Double(threat.scoreBeforeCompensation) * (1 - percent / 100)).rounded()))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Compensate \(threat.name)")
                .font(.headline)
            Text("On \(threat.source.displayName).")
                .font(.callout)
                .foregroundStyle(.secondary)

            Form {
                TextField("What you do instead", text: $label)
                    .accessibilityIdentifier("compensating-label")

                HStack {
                    Slider(value: $percent, in: 0 ... 100, step: 5)
                        .accessibilityIdentifier("compensating-percent")
                    Text("\(Int(percent))%")
                        .monospacedDigit()
                        .frame(width: 46, alignment: .trailing)
                }

                TextField("Why that is enough", text: $rationale, axis: .vertical)
                    .lineLimit(2 ... 5)
                    .accessibilityIdentifier("compensating-rationale")
            }
            .formStyle(.grouped)

            Text("This threat scores \(threat.scoreBeforeCompensation) now, and would score \(wouldScore).")
                .font(.callout)

            if let errorMessage = session.errorMessage {
                Text(errorMessage)
                    .font(.callout)
                    .foregroundStyle(.red)
            }

            HStack {
                if threat.compensatingLabels.isEmpty == false {
                    Button("Remove", role: .destructive) {
                        session.setCompensatingControl(
                            threatKey: threatKey,
                            label: "",
                            reducesRiskBy: 0,
                            rationale: ""
                        )
                        dismiss()
                    }
                }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(
                        label.trimmingCharacters(in: .whitespaces).isEmpty
                            || rationale.trimmingCharacters(in: .whitespaces).isEmpty
                    )
                    .accessibilityIdentifier("compensating-save")
            }
        }
        .padding(16)
        .frame(width: 460, height: 420)
        .onAppear {
            label = threat.compensatingLabels.first ?? ""
        }
    }

    private func save() {
        session.setCompensatingControl(
            threatKey: threatKey,
            label: label,
            reducesRiskBy: Int(percent),
            rationale: rationale
        )
        if session.errorMessage == nil { dismiss() }
    }
}
