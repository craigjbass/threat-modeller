import CoreGraphics

/// Where each node of one tree sits on the canvas, by node id.
///
/// The design in
/// `docs/superpowers/specs/2026-09-16-tree-node-points-design.md` states the
/// rule: a node holds its own point, in model units, for the centre of the
/// node. Nothing is added to that point but the drag in flight. The layout
/// `TreeGraph.positions` states runs only on Lay Out Tree and for a node
/// that has no point.
///
/// This type holds the metrics the canvas draws with, so the editor and the
/// gestures read one name for a node's size and for the room the layout
/// keeps from the origin.
struct TreeLayout: Equatable {
    static let nodeSize = CGSize(width: 190, height: 56)
    static let junctionSize = CGSize(width: 90, height: 40)
    static let horizontalGap: CGFloat = 56
    static let verticalGap: CGFloat = 28
    /// The room the laid out points keep from the origin.
    static let margin: CGFloat = 32

    /// The point of each node the window has placed, by node id.
    private(set) var points: [String: CGPoint] = [:]

    init() {}

    /// A layout that places every node of one graph, for a tree the window
    /// has not placed yet.
    init(laidOut graph: TreeGraph) {
        layOut(graph)
    }

    /// The point one node sits at, or nil when the window has not placed it.
    func point(of id: String) -> CGPoint? { points[id] }

    /// Puts one node at one point.
    mutating func place(_ id: String, at point: CGPoint) {
        points[id] = point
    }

    /// Moves the named nodes by one distance. A node with no point is left
    /// alone.
    mutating func move(_ ids: Set<String>, by shift: CGSize) {
        for id in ids {
            guard let point = points[id] else { continue }
            points[id] = CGPoint(x: point.x + shift.width, y: point.y + shift.height)
        }
    }

    /// Gives a point to each node of the graph that has none. A node that
    /// has a point keeps it.
    mutating func placeUnplaced(in graph: TreeGraph) {
        let unplaced = graph.nodes.map(\.id).filter { points[$0] == nil }
        guard unplaced.isEmpty == false else { return }
        let laid = Self.laidOut(graph)
        for id in unplaced { points[id] = laid[id] }
    }

    /// Drops the points of nodes the graph no longer holds.
    mutating func retainOnly(_ ids: Set<String>) {
        points = points.filter { ids.contains($0.key) }
    }

    /// Every node takes the point the graph's layout states. Lay Out Tree
    /// calls this.
    mutating func layOut(_ graph: TreeGraph) {
        points = Self.laidOut(graph)
    }

    /// The point the layout states for each node of one graph, with the room
    /// the canvas keeps from the origin.
    static func laidOut(_ graph: TreeGraph) -> [String: CGPoint] {
        graph.positions(
            nodeSize: nodeSize,
            horizontalGap: horizontalGap,
            verticalGap: verticalGap
        ).mapValues { CGPoint(x: $0.x + margin, y: $0.y + margin) }
    }
}
