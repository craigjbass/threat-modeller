import SwiftUI
import ThreatModelKit

/// The right sidebar of the Architecture stage.
///
/// The design in
/// `docs/superpowers/specs/2026-09-16-selection-editor-in-the-sidebar-design.md`
/// states the rule: the column holds the editor for what is selected, and its
/// default content when nothing is selected.
struct SelectionSidebar: View {
    let session: ThreatModelSession
    let canvas: CanvasState

    /// What the column shows.
    var selection: CanvasSelection {
        CanvasSelection.of(session: session, canvas: canvas)
    }

    private var isEditing: Bool { selection != .nothing }

    var body: some View {
        ZStack(alignment: .topLeading) {
            defaultContent
                .opacity(isEditing ? 0 : 1)
                .allowsHitTesting(isEditing == false)
                .accessibilityHidden(isEditing)

            if isEditing {
                editor
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
        }
        .accessibilityIdentifier("selection-sidebar")
    }

    /// What the column holds while nothing is selected. #145 changes what
    /// this view holds and changes nothing else here.
    private var defaultContent: some View {
        AssumptionsPanel(session: session)
    }

    @ViewBuilder
    private var editor: some View {
        switch selection {
        case .nothing:
            EmptyView()
        case .component(let component):
            ComponentPanel(session: session, canvas: canvas, component: component)
        case .user(let user):
            UserPanel(session: session, user: user)
        case .zone(let zone):
            ZonePanel(session: session, zone: zone)
        case .connection(let connection):
            ConnectionPanel(session: session, connection: connection)
        case .several(let several):
            MultiSelectionPanel(session: session, canvas: canvas, several: several)
        }
    }
}

/// What the right sidebar shows, as words a test reads.
///
/// `TreeSelection` states the same thing for the Attack Trees stage. One case
/// per state, so no view decides twice what is selected.
enum CanvasSelection: Equatable {
    /// Two or more selected elements: how many of each kind, and what the
    /// column offers for them.
    struct Several: Equatable {
        /// One line per kind, as "2 components", "1 zone", "1 flow".
        let counts: [String]
        /// The selected components, in the order the model holds them.
        let componentIds: [String]
        /// True while Merge joins this selection. #124 states the condition:
        /// two or more components and no user among them.
        let offersMerge: Bool
        /// The two components a mitigates edge would run between, or nil.
        let mitigates: Pair?
    }

    /// The two ends of a mitigates edge, in the order the model holds them.
    struct Pair: Equatable {
        let source: ViewedComponent
        let target: ViewedComponent
    }

    case nothing
    case component(ViewedComponent)
    case user(ViewedComponent)
    case zone(ViewedZone)
    case connection(ViewedConnection)
    case several(Several)

    @MainActor
    static func of(session: ThreatModelSession, canvas: CanvasState) -> CanvasSelection {
        let model = session.canvas
        let components = model.components.filter { canvas.isSelected(componentId: $0.id) }
        let zones = model.zones.filter { canvas.isSelected(zoneId: $0.id) }
        let connections = model.connections.filter { canvas.isSelected(connectionId: $0.id) }
        let count = components.count + zones.count + connections.count

        guard count > 0 else { return .nothing }
        if count == 1 {
            if let component = components.first {
                return component.isUser ? .user(component) : .component(component)
            }
            if let zone = zones.first { return .zone(zone) }
            if let connection = connections.first { return .connection(connection) }
        }

        let holdsAUser = components.contains { $0.isUser }
        let pair = MitigatesGeometry.ordered(components, mitigations: model.mitigations)
        return .several(Several(
            counts: counts(components: components.count, zones: zones.count, flows: connections.count),
            componentIds: components.map(\.id),
            offersMerge: components.count >= 2 && holdsAUser == false,
            mitigates: pair.map { Pair(source: $0.source, target: $0.target) }
        ))
    }

    /// One line per kind that has a member, with the plural the count needs.
    private static func counts(components: Int, zones: Int, flows: Int) -> [String] {
        var said: [String] = []
        if components > 0 {
            said.append("\(components) component\(components == 1 ? "" : "s")")
        }
        if zones > 0 {
            said.append("\(zones) zone\(zones == 1 ? "" : "s")")
        }
        if flows > 0 {
            said.append("\(flows) flow\(flows == 1 ? "" : "s")")
        }
        return said
    }
}

/// The shape every selection editor draws in: a scrolling column with a
/// heading and one field per row.
///
/// The column is 280 points at its narrowest, so a label sits above its
/// control rather than beside it and every control takes the column's width.
struct SelectionEditor<Content: View>: View {
    let title: String
    let identifier: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                content()
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .accessibilityIdentifier(identifier)
    }
}

/// One field of a selection editor: its label, then the control under it.
struct SelectionField<Content: View>: View {
    let label: String
    @ViewBuilder let content: () -> Content

    init(_ label: String, @ViewBuilder content: @escaping () -> Content) {
        self.label = label
        self.content = content
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// What the column shows while two or more elements are selected: how many of
/// each kind, then what the whole selection is offered.
struct MultiSelectionPanel: View {
    let session: ThreatModelSession
    let canvas: CanvasState
    let several: CanvasSelection.Several

    var body: some View {
        SelectionEditor(title: "Several things", identifier: "multi-selection-panel") {
            ForEach(several.counts, id: \.self) { line in
                Text(line)
                    .font(.callout)
            }

            Divider()

            if several.offersMerge {
                Button("Merge\u{2026}") {
                    canvas.startMerging(componentIds: several.componentIds)
                }
                .accessibilityIdentifier("multi-selection-merge")
            }

            if let pair = several.mitigates {
                MitigatesPanel(session: session, source: pair.source, target: pair.target)
                Divider()
            }

            Button("Delete", role: .destructive) {
                CanvasGestures(session: session, canvas: canvas).deleteSelection()
            }
            .accessibilityIdentifier("multi-selection-delete")
        }
    }
}
