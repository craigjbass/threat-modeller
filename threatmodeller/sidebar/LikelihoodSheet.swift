import SwiftUI
import ThreatModelKit

/// Says how often an attack of this kind happens, and why a person says so.
///
/// A finding states a tier or a percentage, never both. The tier is what most
/// findings use; the percentage is for a team that has a number of its own.
/// The rationale is required, because a score a reader cannot check is a
/// number somebody made up.
///
/// It writes the `likelihood` block of the `.controls` file, the way the
/// severity decision sheet writes the `severity_override` block, so a
/// finding survives the project closing and reopening.
struct LikelihoodSheet: View {
    let threat: AssessedThreat
    let session: ThreatModelSession
    let project: ProjectSession

    @Environment(\.dismiss) private var dismiss

    @State private var label = ""
    @State private var tier = Likelihood.research.id
    @State private var usesPrior = false
    @State private var prior = 25.0
    @State private var rationale = ""
    @State private var sources = ""

    /// The score this finding would leave, so a person sees what the tier
    /// buys before they write it.
    private var wouldScore: Int {
        let likelihood = usesPrior
            ? Likelihood(prior: Int(prior)) ?? .commodity
            : Likelihood(rawValue: tier) ?? .commodity
        return Likelihood.apply(to: threat.scoreBeforeLikelihood, likelihood: likelihood)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("How often does \(threat.name) happen?")
                .font(.headline)
            Text("On \(threat.source.displayName).")
                .font(.callout)
                .foregroundStyle(.secondary)

            Form {
                TextField("What you learned", text: $label)
                    .accessibilityIdentifier("likelihood-label")

                Picker("States", selection: $usesPrior) {
                    Text("A tier").tag(false)
                    Text("A percentage").tag(true)
                }
                .pickerStyle(.segmented)
                .accessibilityIdentifier("likelihood-kind")

                if usesPrior {
                    HStack {
                        Slider(value: $prior, in: 0 ... 100, step: 5)
                            .accessibilityIdentifier("likelihood-prior")
                        Text("\(Int(prior))%")
                            .monospacedDigit()
                            .frame(width: 50, alignment: .trailing)
                    }
                } else {
                    Picker("Tier", selection: $tier) {
                        ForEach(Likelihood.allTiers, id: \.id) { tier in
                            Text(tier.label).tag(tier.id)
                        }
                    }
                    .accessibilityIdentifier("likelihood-tier")
                }

                TextField("Why you say so", text: $rationale, axis: .vertical)
                    .lineLimit(2 ... 5)
                    .accessibilityIdentifier("likelihood-rationale")

                TextField("Sources, one a line", text: $sources, axis: .vertical)
                    .lineLimit(1 ... 4)
                    .accessibilityIdentifier("likelihood-sources")
            }
            .formStyle(.grouped)

            Text("\(threat.scoreBeforeLikelihood) \u{2192} \(wouldScore)")
                .font(.callout.monospacedDigit())
                .foregroundStyle(.secondary)

            HStack {
                if threat.likelihoodRationale != nil {
                    Button("Remove", role: .destructive) {
                        session.removeLikelihoodFinding(threatKey: threat.threatKey)
                        dismiss()
                    }
                    .accessibilityIdentifier("remove-likelihood")
                }
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save", action: write)
                    .keyboardShortcut(.defaultAction)
                    .disabled(isWritable == false)
                    .accessibilityIdentifier("save-likelihood")
            }
        }
        .padding(16)
        .frame(width: 460)
        .onAppear(perform: readWhatIsThere)
        .accessibilityIdentifier("likelihood-sheet")
    }

    private var isWritable: Bool {
        label.trimmingCharacters(in: .whitespaces).isEmpty == false
            && rationale.trimmingCharacters(in: .whitespaces).isEmpty == false
    }

    /// The finding the threat already holds, so an edit starts from it.
    private func readWhatIsThere() {
        guard let rationale = threat.likelihoodRationale else { return }
        self.rationale = rationale
        sources = threat.likelihoodSources.joined(separator: "\n")
        if let number = Int(threat.likelihoodId) {
            usesPrior = true
            prior = Double(number)
        } else {
            tier = threat.likelihoodId
        }
    }

    private func write() {
        guard case .threat(let threatId, let sourceKind, let sourceId)?
            = GovernanceSheet.place(of: threat.threatKey) else { return }

        project.saveLikelihoodFinding(
            threatId: threatId,
            sourceKind: sourceKind,
            sourceId: sourceId,
            label: label.trimmingCharacters(in: .whitespaces),
            tier: usesPrior ? nil : tier,
            prior: usesPrior ? Int(prior) : nil,
            rationale: rationale.trimmingCharacters(in: .whitespaces),
            sources: sources
                .split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { $0.isEmpty == false }
        )
        dismiss()
    }
}
