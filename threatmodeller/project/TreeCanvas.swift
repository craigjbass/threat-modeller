import SwiftUI
import ThreatModelKit

/// One element the `.arch` file states, offered beside the tree canvas with
/// the threats the model raises on it.
struct TreeElement: Identifiable, Equatable {
    /// `component`, `zone` or `flow` — the kinds the tree language states.
    let kind: String
    let sourceId: String
    let name: String
    let threats: [AssessedThreat]

    var id: String { payload }
    /// What a drag from the list carries.
    var payload: String { "\(kind):\(sourceId)" }

    /// Every element the model states, with the threats raised on it, in the
    /// order the canvas holds them: components, flows, zones.
    static func list(
        threats: [AssessedThreat],
        components: [ViewedComponent],
        connections: [ViewedConnection],
        zones: [ViewedZone]
    ) -> [TreeElement] {
        func raised(_ kind: String, _ id: String) -> [AssessedThreat] {
            threats.filter { threat in
                switch threat.source {
                case .component(let componentId, _, _):
                    kind == "component" && componentId == id
                case .connection(let connectionId, _, _):
                    kind == "flow" && connectionId == id
                case .zone(let zoneId, _):
                    kind == "zone" && zoneId == id
                }
            }
        }
        func componentName(_ id: String) -> String {
            components.first { $0.id == id }?.name ?? id
        }
        var rows = components.map {
            TreeElement(
                kind: "component", sourceId: $0.id, name: $0.name,
                threats: raised("component", $0.id)
            )
        }
        rows += connections.map {
            TreeElement(
                kind: "flow", sourceId: $0.id,
                name: "\(componentName($0.sourceComponentId)) \u{2192} "
                    + componentName($0.targetComponentId),
                threats: raised("flow", $0.id)
            )
        }
        rows += zones.map {
            TreeElement(kind: "zone", sourceId: $0.id, name: $0.name, threats: raised("zone", $0.id))
        }
        return rows
    }
}

/// An element dropped on the canvas that has not picked a threat yet. It is
/// not written, and it cannot be joined.
struct PendingElement: Identifiable, Equatable {
    let id: UUID
    let element: TreeElement
    var point: CGPoint
}

/// The canvas one tree is drawn on.
///
/// The design in
/// `docs/superpowers/specs/2026-09-15-attack-tree-canvas-design.md` states the
/// shape: nodes laid out from the tree each time, edges stating what feeds
/// what, the goal told apart at a glance, and every change written through
/// the use cases by the sheet that owns the graph.
struct TreeCanvas: View {
    @Binding var graph: TreeGraph
    @Binding var pending: [PendingElement]
    /// The elements the list beside the canvas offers, for the threats a
    /// dropped element offers.
    let elements: [TreeElement]
    /// What the assessment bound for this tree, or nil while it is unwritten.
    let bound: BoundAttackTree?

    static let nodeSize = CGSize(width: 190, height: 56)
    static let junctionSize = CGSize(width: 90, height: 40)
    private static let horizontalGap: CGFloat = 56
    private static let verticalGap: CGFloat = 28
    private static let margin: CGFloat = 32

    /// Where a drag holds a node until the next open lays it out again.
    @State private var held: [String: CGSize] = [:]
    /// The join being dragged, from a node to the pointer.
    @State private var joining: JoinDrag?

    struct JoinDrag {
        let from: String
        var to: CGPoint
    }

    var body: some View {
        ScrollView([.horizontal, .vertical]) {
            ZStack(alignment: .topLeading) {
                edgeLines
                joinLine
                ForEach(graph.nodes) { node in
                    nodeView(node)
                        .position(position(of: node.id))
                        .gesture(joinOrHold(node.id))
                }
                ForEach($pending) { $item in
                    pendingView($item)
                        .position(item.point)
                }
            }
            .frame(width: contentSize.width, height: contentSize.height, alignment: .topLeading)
            .coordinateSpace(name: "tree-canvas")
            .dropDestination(for: String.self) { payloads, location in
                drop(payloads, at: location)
            }
        }
        .background(Color(nsColor: .textBackgroundColor))
        .accessibilityIdentifier("tree-canvas")
    }

    // MARK: where everything sits

    private var laidOut: [String: CGPoint] {
        graph.positions(
            nodeSize: Self.nodeSize,
            horizontalGap: Self.horizontalGap,
            verticalGap: Self.verticalGap
        )
    }

    private func position(of id: String) -> CGPoint {
        let base = laidOut[id] ?? .zero
        let hold = held[id] ?? .zero
        return CGPoint(
            x: base.x + Self.margin + hold.width,
            y: base.y + Self.margin + hold.height
        )
    }

    private var contentSize: CGSize {
        var width: CGFloat = 400
        var height: CGFloat = 300
        for id in graph.nodes.map(\.id) {
            let point = position(of: id)
            width = max(width, point.x + Self.nodeSize.width)
            height = max(height, point.y + Self.nodeSize.height)
        }
        for item in pending {
            width = max(width, item.point.x + Self.nodeSize.width)
            height = max(height, item.point.y + Self.nodeSize.height)
        }
        return CGSize(width: width, height: height)
    }

    // MARK: the edges

    private var edgeLines: some View {
        Path { path in
            for edge in graph.edges {
                let from = position(of: edge.from)
                let to = position(of: edge.to)
                let start = CGPoint(x: from.x + size(of: edge.from).width / 2, y: from.y)
                let end = CGPoint(x: to.x - size(of: edge.to).width / 2, y: to.y)
                path.move(to: start)
                path.addLine(to: end)

                // The head states what feeds what.
                let angle = atan2(end.y - start.y, end.x - start.x)
                for turn in [angle + .pi * 0.85, angle - .pi * 0.85] {
                    path.move(to: end)
                    path.addLine(to: CGPoint(
                        x: end.x + 10 * cos(turn),
                        y: end.y + 10 * sin(turn)
                    ))
                }
            }
        }
        .stroke(Color.secondary, lineWidth: 1.5)
    }

    @ViewBuilder
    private var joinLine: some View {
        if let joining {
            Path { path in
                path.move(to: position(of: joining.from))
                path.addLine(to: joining.to)
            }
            .stroke(Color.accentColor, style: StrokeStyle(lineWidth: 1.5, dash: [4, 4]))
        }
    }

    private func size(of id: String) -> CGSize {
        switch graph.node(id)?.kind {
        case .allOf, .anyOf: Self.junctionSize
        default: Self.nodeSize
        }
    }

    // MARK: the nodes

    @ViewBuilder
    private func nodeView(_ node: TreeGraph.Node) -> some View {
        let isGoal = graph.goalId == node.id
        Group {
            switch node.kind {
            case .step:
                VStack(spacing: 2) {
                    if isGoal {
                        Text("GOAL")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(.secondary)
                    }
                    Text(node.title)
                        .font(.callout.weight(.semibold))
                        .lineLimit(1)
                    HStack(spacing: 4) {
                        stateDot(of: node)
                        Text(node.subtitle)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                .padding(.horizontal, 8)
                .frame(width: Self.nodeSize.width, height: Self.nodeSize.height)
                .background(RoundedRectangle(cornerRadius: 8).fill(.bar))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .strokeBorder(isGoal ? Color.accentColor : .secondary, lineWidth: isGoal ? 2 : 1)
                )
                .overlay(
                    // The goal is told apart at a glance: a doubled border.
                    RoundedRectangle(cornerRadius: 11)
                        .strokeBorder(Color.accentColor, lineWidth: isGoal ? 1 : 0)
                        .padding(-4)
                )
            case .allOf, .anyOf:
                Text(node.title)
                    .font(.caption.weight(.bold))
                    .frame(width: Self.junctionSize.width, height: Self.junctionSize.height)
                    .background(Capsule().fill(.bar))
                    .overlay(Capsule().strokeBorder(Color.secondary, lineWidth: 1))
            }
        }
        .contextMenu {
            if case .step = node.kind, isGoal == false {
                Button("Set as Goal") { graph.goalId = node.id }
            }
            if graph.edges.contains(where: { $0.from == node.id }) {
                Button("Cut the Outgoing Join") {
                    for edge in graph.edges where edge.from == node.id {
                        graph.disconnect(from: edge.from, to: edge.to)
                    }
                }
            }
            Button("Delete", role: .destructive) { graph.remove(node.id) }
        }
        .accessibilityIdentifier("tree-node-\(node.id)")
    }

    private func stateDot(of node: TreeGraph.Node) -> some View {
        Circle()
            .fill(stateColor(of: node))
            .frame(width: 7, height: 7)
            .help(stateHelp(of: node))
    }

    private func boundStep(of node: TreeGraph.Node) -> BoundStep? {
        guard case .step(let target, _) = node.kind else { return nil }
        return bound?.steps.first { $0.key.value == TreeDraft.key(of: target) }
    }

    private func stateColor(of node: TreeGraph.Node) -> Color {
        switch boundStep(of: node)?.state {
        case .open: .orange
        case .closed: .green
        case .unbound: .red
        case nil: .secondary
        }
    }

    private func stateHelp(of node: TreeGraph.Node) -> String {
        switch boundStep(of: node)?.state {
        case .open: "Open: nothing closes this step."
        case .closed: "Closed: a control answers this step."
        case .unbound: "Unbound: the model no longer raises this threat here."
        case nil: "Not written yet."
        }
    }

    // MARK: what a drop and a pick make

    private func drop(_ payloads: [String], at location: CGPoint) -> Bool {
        guard let payload = payloads.first else { return false }
        if payload == "junction:all" {
            graph.add(.allOf, title: "ALL")
            return true
        }
        if payload == "junction:any" {
            graph.add(.anyOf, title: "ANY")
            return true
        }
        guard let element = elements.first(where: { $0.payload == payload }) else { return false }
        pending.append(PendingElement(id: UUID(), element: element, point: location))
        return true
    }

    @ViewBuilder
    private func pendingView(_ item: Binding<PendingElement>) -> some View {
        let element = item.wrappedValue.element
        VStack(spacing: 2) {
            Text(element.name)
                .font(.callout)
                .lineLimit(1)
            if element.threats.isEmpty {
                Text("raises no threat")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Menu("Pick a threat") {
                    ForEach(element.threats, id: \.threatKey) { threat in
                        Button(threat.name) { pick(threat, for: item.wrappedValue) }
                    }
                }
                .font(.caption)
                .accessibilityIdentifier("pick-threat-\(element.payload)")
            }
        }
        .padding(.horizontal, 8)
        .frame(width: Self.nodeSize.width, height: Self.nodeSize.height)
        .background(RoundedRectangle(cornerRadius: 8).fill(.bar).opacity(0.8))
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(Color.secondary, style: StrokeStyle(lineWidth: 1, dash: [4, 3]))
        )
        .contextMenu {
            Button("Delete", role: .destructive) {
                pending.removeAll { $0.id == item.wrappedValue.id }
            }
        }
    }

    private func pick(_ threat: AssessedThreat, for item: PendingElement) {
        let target = SourceTreeTarget(
            threatId: threat.threatId,
            sourceKind: item.element.kind,
            sourceId: item.element.sourceId
        )
        let id = graph.add(
            .step(target: target, note: nil),
            title: threat.name,
            subtitle: item.element.name
        )
        // A tree reaches a threat, so the first step a person makes is the
        // goal until they move the mark.
        if graph.goalId == nil { graph.goalId = id }
        pending.removeAll { $0.id == item.id }
    }

    // MARK: a drag joins, or holds

    /// A drag ending on another node joins the two; one ending on open canvas
    /// holds the node there until the next open lays it out again.
    private func joinOrHold(_ id: String) -> some Gesture {
        DragGesture(minimumDistance: 2, coordinateSpace: .named("tree-canvas"))
            .onChanged { value in
                joining = JoinDrag(from: id, to: value.location)
            }
            .onEnded { value in
                joining = nil
                if let target = node(at: value.location), target != id {
                    graph.join(from: id, to: target)
                } else {
                    let hold = held[id] ?? .zero
                    held[id] = CGSize(
                        width: hold.width + value.translation.width,
                        height: hold.height + value.translation.height
                    )
                }
            }
    }

    private func node(at point: CGPoint) -> String? {
        graph.nodes.first { node in
            let centre = position(of: node.id)
            let size = size(of: node.id)
            return CGRect(
                x: centre.x - size.width / 2,
                y: centre.y - size.height / 2,
                width: size.width,
                height: size.height
            ).contains(point)
        }?.id
    }
}
