import SwiftUI
import ThreatModelKit

private extension AssessedThreat {
    /// Row key for the sidebar. `AssessedThreat` carries no identity field of
    /// its own, so two equal threats would collide as one row. The pair of
    /// `threatId` and the source's id identifies a row.
    var rowIdentity: String { "\(threatId)#\(source.id)" }
}

/// The threat list: a summary, then one group per source, worst first.
struct ThreatSidebar: View {
    let session: ThreatModelSession

    @State private var collapsed: Set<String> = []

    /// One group per source, each holding that source's threats. Groups are
    /// ordered by their worst threat, so the component needing most attention
    /// is at the top. `session.threats` is already worst first, so the first
    /// time a source appears is its worst threat.
    private var groups: [(id: String, name: String, threats: [AssessedThreat])] {
        var order: [String] = []
        var bySource: [String: [AssessedThreat]] = [:]
        var names: [String: String] = [:]

        for threat in session.threats {
            let id = threat.source.id
            if bySource[id] == nil {
                order.append(id)
                names[id] = threat.source.displayName
            }
            bySource[id, default: []].append(threat)
        }

        return order.map { (id: $0, name: names[$0] ?? $0, threats: bySource[$0] ?? []) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let errorMessage = session.errorMessage {
                Text(errorMessage)
                    .foregroundStyle(.red)
                    .padding(.horizontal, 12)
                    .padding(.top, 8)
            }

            if session.threats.isEmpty {
                ContentUnavailableView(
                    "No threats yet",
                    systemImage: "shield",
                    description: Text("Add a technology from the palette to see the threats it carries.")
                )
            } else {
                PathwayMitigationsPanel(session: session)
                Divider()
                RiskSummaryView(summary: session.summary)
                Divider()
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 10, pinnedViews: [.sectionHeaders]) {
                        ForEach(groups, id: \.id) { group in
                            Section {
                                if collapsed.contains(group.id) == false {
                                    ForEach(group.threats, id: \.rowIdentity) { threat in
                                        ThreatCard(
                                            threat: threat,
                                            severityChoices: session.severityChoices,
                                            onSetControl: { key, implemented in
                                                session.setControl(key: key, implemented: implemented)
                                            },
                                            onOverride: { severityId in
                                                session.overrideSeverity(
                                                    overrideKey: threat.overrideKey,
                                                    severityId: severityId
                                                )
                                            },
                                            onClearOverride: {
                                                session.clearOverride(overrideKey: threat.overrideKey)
                                            }
                                        )
                                    }
                                }
                            } header: {
                                groupHeader(group)
                            }
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                }
            }
        }
        .navigationTitle("Threats")
    }

    private func groupHeader(_ group: (id: String, name: String, threats: [AssessedThreat])) -> some View {
        let isCollapsed = collapsed.contains(group.id)

        return Button {
            if isCollapsed { collapsed.remove(group.id) } else { collapsed.insert(group.id) }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: isCollapsed ? "chevron.right" : "chevron.down")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .frame(width: 10)
                Text(group.name)
                    .font(.subheadline.weight(.semibold))
                    .lineLimit(1)
                Spacer(minLength: 4)
                Text("\(group.threats.count)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 4)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .background(.bar)
        .accessibilityIdentifier("threat-group-\(group.id)")
    }
}
