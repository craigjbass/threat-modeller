import SwiftUI
import ThreatModelKit

/// The controls the user says are real on their system.
///
/// Nothing here changes a score until the master toggle goes on, so the panel
/// starts collapsed and says how many mitigations this diagram can actually
/// use. A mitigation nothing on the diagram provides is shown greyed with what
/// would provide it, rather than hidden: the user is choosing what to build as
/// much as what they have.
struct PathwayMitigationsPanel: View {
    let session: ThreatModelSession

    @State private var isExpanded: Bool

    /// `isExpanded` is a parameter so a preview can draw the expanded panel.
    /// A preview cannot press the header, and the expanded panel is the state
    /// the layout fault appears in.
    init(session: ThreatModelSession, isExpanded: Bool = false) {
        self.session = session
        _isExpanded = State(initialValue: isExpanded)
    }

    private var usable: Int {
        session.pathwayMitigations.mitigations.filter(\.isProvidedOnThisModel).count
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            header

            if isExpanded {
                Toggle("Apply pathway mitigations", isOn: Binding(
                    get: { session.pathwayMitigations.isMasterEnabled },
                    set: { session.setPathwayMaster($0) }
                ))
                .toggleStyle(.switch)
                .accessibilityIdentifier("pathway-master")

                ForEach(session.pathwayMitigations.mitigations, id: \.id) { mitigation in
                    row(mitigation)
                }
            }
        }
        .padding(12)
    }

    private var header: some View {
        Button {
            isExpanded.toggle()
        } label: {
            HStack(spacing: 6) {
                Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .frame(width: 10)
                Text("Pathway mitigations")
                    .font(.subheadline.weight(.semibold))
                Spacer(minLength: 4)
                Text(session.pathwayMitigations.isMasterEnabled ? "\(usable) in use" : "Off")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier("pathway-mitigations")
    }

    private func row(_ mitigation: ListedPathwayMitigation) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Toggle(isOn: Binding(
                get: { mitigation.isEnabled },
                set: {
                    session.setPathwayMitigation(
                        id: mitigation.id,
                        isEnabled: $0,
                        mode: mitigation.mode,
                        reductionPercent: mitigation.reductionPercent
                    )
                }
            )) {
                Text(mitigation.label).font(.caption)
            }
            .toggleStyle(.checkbox)
            .accessibilityIdentifier("pathway-\(mitigation.id)-enabled")

            if mitigation.isProvidedOnThisModel == false {
                Text("Nothing on this diagram provides it. \(mitigation.providedByTechnologyNames.joined(separator: ", ")) would.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if mitigation.isEnabled {
                // The picker takes a line of its own and the slider takes the
                // next. Side by side their fixed widths came to 356 points
                // against a column that can be 300, so the row drew under
                // both edges of the column.
                VStack(alignment: .leading, spacing: 6) {
                    Picker("Mode", selection: Binding(
                        get: { mitigation.mode },
                        set: {
                            session.setPathwayMitigation(
                                id: mitigation.id,
                                isEnabled: mitigation.isEnabled,
                                mode: $0,
                                reductionPercent: mitigation.reductionPercent
                            )
                        }
                    )) {
                        Text("Lower the score").tag("reduce")
                        Text("Remove the threat").tag("remove")
                    }
                    .labelsHidden()
                    .frame(maxWidth: 220)
                    .accessibilityIdentifier("pathway-\(mitigation.id)-mode")

                    if mitigation.mode == "reduce" {
                        HStack(spacing: 8) {
                            Slider(
                                value: Binding(
                                    get: { Double(mitigation.reductionPercent) },
                                    set: {
                                        session.setPathwayMitigation(
                                            id: mitigation.id,
                                            isEnabled: mitigation.isEnabled,
                                            mode: mitigation.mode,
                                            reductionPercent: Int($0.rounded())
                                        )
                                    }
                                ),
                                in: 0...100,
                                step: 5
                            )
                            .frame(maxWidth: 180)
                            .accessibilityIdentifier("pathway-\(mitigation.id)-percent")
                            Text("\(mitigation.reductionPercent)%")
                                .font(.caption2.monospacedDigit())
                        }
                    }
                }
            }
        }
        .padding(.leading, 16)
        .opacity(mitigation.isProvidedOnThisModel ? 1 : 0.6)
    }
}
