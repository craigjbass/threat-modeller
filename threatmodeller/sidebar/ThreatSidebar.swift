import SwiftUI
import ThreatModelKit

private extension AssessedThreat {
    /// Row key for the sidebar. `AssessedThreat` carries no identity field of
    /// its own, so two equal threats would collide as one row. The pair of
    /// `threatId` and the source's id identifies a row.
    var rowIdentity: String { "\(threatId)#\(source.id)" }
}

/// The threat list: a summary, then one group per source, worst first.
/// `sheet(item:)` needs identity, and a threat is named by itself and by what
/// raised it.
struct CompensatedThreat: Identifiable {
    let threat: AssessedThreat
    var id: String { threat.threatKey }
}

struct ThreatSidebar: View {
    /// Which part of a threat a stage is about. The threats stage is for
    /// reading what the architecture raises and saying how often it happens.
    /// The controls stage is for answering what a team runs against it.
    enum Focus {
        case likelihood
        case controls
    }

    let session: ThreatModelSession

    /// What the cards show. The default is the controls stage, which is what
    /// a document window gives a user.
    var focus: Focus = .controls

    /// The project the model was read from, or nil for a window that has no
    /// project. The controls stage lists the answers its files still hold for
    /// threats the architecture no longer raises.
    var project: ProjectSession?

    /// The state the pathway panel starts in. A preview sets it, because a
    /// preview cannot press the panel header.
    var pathwayExpanded = false

    /// The threat whose compensating control the user is editing.
    @State private var compensating: CompensatedThreat?

    /// The threat whose likelihood finding the user is writing.
    @State private var likelihooding: CompensatedThreat?

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
        sidebar
            .sheet(item: $compensating) { chosen in
                CompensatingControlSheet(threat: chosen.threat, session: session)
            }
            .sheet(item: $likelihooding) { chosen in
                LikelihoodSheet(threat: chosen.threat, session: session)
            }
    }

    private var sidebar: some View {
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
                // The panel and the summary scroll with the threat cards. A
                // view outside the scroll area keeps its whole height, and an
                // expanded pathway panel is 497 points tall in a 300 point
                // column: it took the threat list's height, and then the
                // column overflowed and carried its own header above the top
                // of the window, where nothing could collapse it again.
                ScrollView {
                    VStack(alignment: .leading, spacing: 0) {
                        if let project, focus == .controls {
                            StaleAnswersPanel(project: project)
                            Divider()
                        }
                        PathwayMitigationsPanel(session: session, isExpanded: pathwayExpanded)
                        Divider()
                        RiskSummaryView(summary: session.summary)
                        Divider()

                        LazyVStack(alignment: .leading, spacing: 10, pinnedViews: [.sectionHeaders]) {
                            ForEach(groups, id: \.id) { group in
                                Section {
                                    if collapsed.contains(group.id) == false {
                                        ForEach(group.threats, id: \.rowIdentity) { threat in
                                            ThreatCard(
                                                threat: threat,
                                                focus: focus,
                                                severityChoices: session.severityChoices,
                                                onSetControl: { key, implemented in
                                                    session.setControl(key: key, implemented: implemented)
                                                },
                                                onSetControlStatus: { key, statusId in
                                                    session.setControlStatus(key: key, statusId: statusId)
                                                },
                                                onCompensate: { compensating = CompensatedThreat(threat: threat) },
                                                onLikelihood: { likelihooding = CompensatedThreat(threat: threat) },
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
                    // The controls stage gives this list the whole window. A
                    // card the width of a 1400 point window puts its status
                    // picker a screen away from the control it states, so the
                    // list keeps a column a person reads across.
                    .frame(maxWidth: 1000)
                    .frame(maxWidth: .infinity)
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
