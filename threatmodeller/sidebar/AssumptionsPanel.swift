import SwiftUI
import ThreatModelKit

/// What the system takes on trust, and what one component lowers on another.
///
/// Both of these are facts about the architecture that the diagram cannot
/// draw: an assumption is a sentence, and a mitigates edge names threats. The
/// architecture stage keeps them in the column beside the diagram, so a
/// person writes them while the system is in front of them.
struct AssumptionsPanel: View {
    let session: ThreatModelSession

    @State private var label = ""
    @State private var text = ""
    @State private var owner = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
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

                Divider()
                writeOne

                if session.canvas.mitigations.isEmpty == false {
                    Divider()
                    Text("What one component lowers on another")
                        .font(.subheadline.weight(.semibold))
                    ForEach(session.canvas.mitigations, id: \.sourceComponentId) { mitigation in
                        mitigationRow(mitigation)
                    }
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle("Assumptions")
        .accessibilityIdentifier("assumptions-panel")
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
            Text("\(mitigation.status.capitalized) \u{00B7} lowers \(mitigation.threatIds.count) by \(mitigation.reducesRiskBy)%")
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
