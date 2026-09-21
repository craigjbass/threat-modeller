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

/// One accepted control under one threat, for the governance sheet.
/// `sheet(item:)` needs identity, and a control is named by its threat and by
/// its own key.
struct GovernedControl: Identifiable {
    let threat: AssessedThreat
    let control: AssessedControl
    var id: String { "\(threat.threatKey)#\(control.key)" }
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

    /// The accepted control whose governance the user is writing.
    @State private var governing: GovernedControl?

    /// The implemented control whose evidence the user is writing.
    @State private var evidencing: GovernedControl?

    /// The threat whose severity decision the user is writing.
    @State private var deciding: CompensatedThreat?

    /// The threat whose recommendations the user is writing.
    @State private var recommending: CompensatedThreat?
    /// The threat whose component is being looked up for CVEs, or nil.
    @State private var lookingUp: CompensatedThreat?

    /// The group at the top of the view. Reordering puts it back, so the
    /// place a person was reading stays on screen.
    @State private var topGroup: String?

    /// What the search field and the filter menu keep. A model with hundreds
    /// of threats is read by narrowing it.
    @State private var filter = ThreatFilter()

    /// One group per source, each holding that source's threats. Groups are
    /// ordered by their worst threat, so the component needing most attention
    /// is at the top. `session.threats` is already worst first, so the first
    /// time a source appears is its worst threat.
    private var groups: [(id: String, name: String, threats: [AssessedThreat])] {
        var order: [String] = []
        var bySource: [String: [AssessedThreat]] = [:]
        var names: [String: String] = [:]

        // A group with no matching threat is not drawn, because a heading
        // over nothing is a row a person reads and learns nothing from.
        for threat in shownThreats {
            let id = threat.source.id
            if bySource[id] == nil {
                order.append(id)
                names[id] = threat.source.displayName
            }
            bySource[id, default: []].append(threat)
        }

        return order.map { (id: $0, name: names[$0] ?? $0, threats: bySource[$0] ?? []) }
    }

    /// The threats the list draws. The summary counts the whole model.
    ///
    /// A context menu on the diagram focuses one element, and the list then
    /// draws that element's threats until a person clears it.
    private var shownThreats: [AssessedThreat] {
        let threats = session.threats.filter {
            session.focusedElementId == nil || $0.source.id == session.focusedElementId
        }
        return filter.narrow(threats)
    }

    /// The name of the element the list is narrowed to, or nil.
    private var focusedElementName: String? {
        guard let focusedElementId = session.focusedElementId else { return nil }
        return session.threats.first { $0.source.id == focusedElementId }?.source.displayName
            ?? focusedElementId
    }

    private var hiddenCount: Int {
        session.threats.count - shownThreats.count
    }

    /// The trees the filter offers. Read from the threats the list already
    /// holds, so drawing the bar assesses nothing again.
    private var treeChoices: [ThreatFilter.TreeChoice] {
        ThreatFilter.trees(of: session.threats)
    }

    var body: some View {
        sidebar
            // A stage is a different reading of one model, so entering one
            // starts from the worst-first order.
            .onChange(of: focus) { session.resortThreats() }
            .sheet(item: $compensating) { chosen in
                CompensatingControlSheet(threat: chosen.threat, session: session)
            }
            .sheet(item: $likelihooding) { chosen in
                if let project {
                    LikelihoodSheet(threat: chosen.threat, session: session, project: project)
                } else {
                    NeedsProjectSheet()
                }
            }
            .sheet(item: $evidencing) { chosen in
                EvidenceSheet(
                    threat: chosen.threat,
                    control: chosen.control,
                    session: session
                )
            }
            .sheet(item: $governing) { chosen in
                if let project {
                    GovernanceSheet(
                        threat: chosen.threat,
                        control: chosen.control,
                        project: project
                    )
                } else {
                    NeedsProjectSheet()
                }
            }
            .sheet(item: $deciding) { chosen in
                if let project {
                    SeverityDecisionSheet(
                        threat: chosen.threat,
                        severityChoices: session.severityChoices,
                        project: project
                    )
                } else {
                    NeedsProjectSheet()
                }
            }
            .sheet(item: $lookingUp) { chosen in
                if let project {
                    VulnerabilityLookupSheet(threat: chosen.threat, session: session, project: project)
                } else {
                    NeedsProjectSheet()
                }
            }
            .sheet(item: $recommending) { chosen in
                if let project {
                    // The card holds the stale copy the sheet opened on, so
                    // the sheet reads the threat the session holds now and
                    // shows every block a write just added.
                    RecommendationsSheet(
                        threat: session.threats.first { $0.threatKey == chosen.threat.threatKey }
                            ?? chosen.threat,
                        project: project
                    )
                } else {
                    NeedsProjectSheet()
                }
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
                        if focus == .controls, let project {
                            StaleAnswersPanel(project: project)
                            Divider()
                        }
                        PathwayMitigationsPanel(session: session, isExpanded: pathwayExpanded)
                        Divider()
                        RiskSummaryView(summary: session.summary)
                        reorderBar
                        Divider()
                        filterBar
                        Divider()

                        LazyVStack(alignment: .leading, spacing: 10, pinnedViews: [.sectionHeaders]) {
                            ForEach(groups, id: \.id) { group in
                                Section {
                                    if session.collapsedGroups.contains(group.id) == false {
                                        ForEach(group.threats, id: \.rowIdentity) { threat in
                                            card(for: threat)
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
                .scrollPosition(id: $topGroup, anchor: .top)
                // The element a context menu focused is the one the reader
                // asked for, so the list starts at its group.
                .onChange(of: session.focusedElementId) { _, elementId in
                    guard let elementId else { return }
                    topGroup = elementId
                }
            }
        }
        .navigationTitle("Threats")
    }

    /// The search field and the filter menu.
    ///
    /// The summary above keeps counting the whole model, so this bar states
    /// how many rows the filter hides rather than changing a number a person
    /// reads as the state of the system.
    private var filterBar: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Button("Collapse All") { session.collapseEveryGroup(groups.map(\.id)) }
                    .font(.caption)
                    .accessibilityIdentifier("collapse-all-groups")
                Button("Expand All") { session.expandEveryGroup() }
                    .font(.caption)
                    .accessibilityIdentifier("expand-all-groups")
                Spacer(minLength: 0)
            }

            if let focusedElementName {
                HStack(spacing: 6) {
                    Text("Showing \(focusedElementName)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Button("Show Everything") { session.clearElementFocus() }
                        .font(.caption)
                        .accessibilityIdentifier("clear-element-focus")
                    Spacer(minLength: 0)
                }
            }

            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                    .font(.caption)
                TextField("Search threats", text: $filter.text)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("threat-search")
                if filter.isNarrowing {
                    Button("Clear") { filter = ThreatFilter() }
                        .font(.caption)
                        .accessibilityIdentifier("clear-threat-filter")
                }
            }

            HStack(spacing: 6) {
                Picker("Risk", selection: $filter.levelId) {
                    Text("Every level").tag(String?.none)
                    ForEach(session.summary.byLevel, id: \.levelId) { level in
                        Text(level.label).tag(String?.some(level.levelId))
                    }
                }
                .accessibilityIdentifier("threat-level-filter")

                Picker("STRIDE", selection: $filter.strideId) {
                    Text("Every category").tag(String?.none)
                    ForEach(session.summary.byStride, id: \.strideId) { stride in
                        Text(stride.label).tag(String?.some(stride.strideId))
                    }
                }
                .accessibilityIdentifier("threat-stride-filter")

                Picker("Impact", selection: $filter.impactId) {
                    Text("Every impact").tag(String?.none)
                    ForEach(ThreatImpact.allCases, id: \.rawValue) { impact in
                        Text(impact.label).tag(String?.some(impact.rawValue))
                    }
                }
                .accessibilityIdentifier("threat-impact-filter")

                // One entry per tree, so the list narrows to one route: the
                // goal and every step.
                if treeChoices.isEmpty == false {
                    Picker("On a tree", selection: $filter.treeId) {
                        Text("Every tree").tag(String?.none)
                        ForEach(treeChoices) { tree in
                            Text(tree.name).tag(String?.some(tree.id))
                        }
                    }
                    .accessibilityIdentifier("threat-tree-filter")
                }

                Picker("Answered", selection: $filter.answered) {
                    ForEach(ThreatFilter.Answered.allCases) { state in
                        Text(state.label).tag(state)
                    }
                }
                .accessibilityIdentifier("threat-answered-filter")
            }
            .labelsHidden()
            .font(.caption)

            if hiddenCount > 0 {
                Text(
                    hiddenCount == 1
                        ? "1 threat is hidden by the filter"
                        : "\(hiddenCount) threats are hidden by the filter"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("threats-hidden")
            }

            if shownThreats.isEmpty {
                Text("No threat matches this search.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    /// One threat's card, with every writer the sidebar gives it.
    ///
    /// It is its own method because the card takes fourteen closures, and the
    /// type checker gives up on that many inside the list's builder.
    private func card(for threat: AssessedThreat) -> some View {
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
            onSetControlMitigatedBy: { key, edgeId, percent in
                session.setControlMitigatedBy(key: key, edgeId: edgeId, reducesRiskBy: percent)
            },
            onEvidence: { control in
                evidencing = GovernedControl(
                    threat: threat,
                    control: control
                )
            },
            onCompensate: { compensating = CompensatedThreat(threat: threat) },
            // The editor writes a file in
            // the project, so a window
            // with no project disables
            // the button instead of
            // opening an empty sheet.
            onLikelihood: project == nil ? nil : {
                likelihooding = CompensatedThreat(threat: threat)
            },
            // The editor writes a file in
            // the project, so a window
            // with no project offers none.
            onGovern: project == nil ? nil : { control in
                governing = GovernedControl(
                    threat: threat,
                    control: control
                )
            },
            // The editor writes a file in
            // the project, so a window
            // with no project offers none.
            onDecideSeverity: project == nil ? nil : {
                deciding = CompensatedThreat(threat: threat)
            },
            onOverride: { severityId in
                session.overrideSeverity(
                    overrideKey: threat.overrideKey,
                    severityId: severityId
                )
            },
            onClearOverride: {
                session.clearOverride(overrideKey: threat.overrideKey)
            },
            // The writer writes a file in
            // the project, so a window
            // with no project offers no
            // toggle.
            onSetImpacts: project == nil ? nil : { impacts in
                guard case .threat(let threatId, let sourceKind, let sourceId)?
                    = GovernanceSheet.place(of: threat.threatKey) else { return }
                project?.saveImpacts(
                    threatId: threatId,
                    sourceKind: sourceKind,
                    sourceId: sourceId,
                    impacts: impacts
                )
            },
            // The editor writes a file in
            // the project, so a window
            // with no project offers none.
            onRecommend: project == nil ? nil : {
                recommending = CompensatedThreat(threat: threat)
            },
            // The lookup writes the
            // `.arch` file, so a window
            // with no project offers none.
            onLookUpVulnerabilities: project == nil ? nil : {
                lookingUp = CompensatedThreat(threat: threat)
            }
        )
    }

    /// The Reorder button, beside the risk summary.
    ///
    /// The list holds its order while a person answers it, so an edit that
    /// changes a score leaves the cards where they are and this button says
    /// how many rows a sort would move.
    @ViewBuilder
    private var reorderBar: some View {
        if session.rowsOutOfOrder > 0 {
            HStack(spacing: 8) {
                Button {
                    // The group the person is reading stays on screen: the
                    // sort moves the cards, and the view does not move with
                    // them.
                    let wasOnTop = topGroup
                    withAnimation(.easeInOut(duration: 0.25)) { session.resortThreats() }
                    topGroup = wasOnTop
                } label: {
                    Label("Reorder", systemImage: "arrow.up.arrow.down")
                }
                .keyboardShortcut("r", modifiers: [.command, .shift])
                .accessibilityIdentifier("reorder-threats")

                Text(rowsOutOfOrderSays)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
        }
    }

    private var rowsOutOfOrderSays: String {
        session.rowsOutOfOrder == 1
            ? "1 row is out of order"
            : "\(session.rowsOutOfOrder) rows are out of order"
    }

    private func groupHeader(_ group: (id: String, name: String, threats: [AssessedThreat])) -> some View {
        let isCollapsed = session.collapsedGroups.contains(group.id)

        return Button {
            // Option-click closes or opens every group, the way Finder reads
            // one.
            session.toggleGroup(
                group.id,
                everyGroupId: groups.map(\.id),
                appliesToEveryGroup: NSEvent.modifierFlags.contains(.option)
            )
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

/// What a sheet shows instead of itself, when the finding it writes needs a
/// project this window does not have. A model with no project, opened from a
/// single file, reaches this rather than an empty sheet.
struct NeedsProjectSheet: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 16) {
            Text("This finding needs an open project.")
                .font(.callout)
                .accessibilityIdentifier("needs-project-message")
            Button("Close") { dismiss() }
                .keyboardShortcut(.cancelAction)
                .accessibilityIdentifier("needs-project-close")
        }
        .padding(24)
        .frame(width: 320)
        .accessibilityIdentifier("needs-project-sheet")
    }
}
