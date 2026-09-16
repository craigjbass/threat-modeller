import Foundation
import ThreatModelKit

/// The graph a person draws on the tree canvas, before it is a tree.
///
/// The design in
/// `docs/superpowers/specs/2026-09-15-attack-tree-canvas-design.md` states the
/// shape: nodes and edges, one node marked as the goal, and a conversion that
/// refuses any graph the language cannot state, with the node named.
struct TreeGraph: Equatable {
    /// What one node is.
    enum Kind: Equatable {
        /// An element with a threat picked. It is written as a step, or as
        /// the goal statement when the node is the goal.
        case step(target: SourceTreeTarget, note: String?)
        case allOf
        case anyOf
    }

    struct Node: Equatable, Identifiable {
        let id: String
        var kind: Kind
        /// What the node shows. The conversion never reads these.
        var title: String
        var subtitle: String
    }

    /// `from` feeds `to`: `from` sits under `to` in the file.
    ///
    /// The canvas selects an edge, so the type states an id and hashes.
    /// Declared `nonisolated`: the app target defaults every type to the main
    /// actor, and this one is a pure value with no shared state.
    nonisolated struct Edge: Hashable, Identifiable {
        let from: String
        let to: String

        var id: String { "\(from)->\(to)" }
    }

    private(set) var nodes: [Node] = []
    private(set) var edges: [Edge] = []
    /// The node the tree reaches, written as the `goal` statement.
    var goalId: String?

    private var nextNumber = 1

    // MARK: what a person draws

    /// Adds one node and returns its id.
    @discardableResult
    mutating func add(_ kind: Kind, title: String, subtitle: String = "") -> String {
        let id = "n\(nextNumber)"
        nextNumber += 1
        nodes.append(Node(id: id, kind: kind, title: title, subtitle: subtitle))
        return id
    }

    /// Joins two nodes: `from` feeds `to`. Joining a pair twice, a node to
    /// itself, or an id the graph does not hold changes nothing.
    mutating func join(from: String, to: String) {
        guard from != to,
              nodes.contains(where: { $0.id == from }),
              nodes.contains(where: { $0.id == to }),
              edges.contains(Edge(from: from, to: to)) == false else { return }
        edges.append(Edge(from: from, to: to))
    }

    /// Removes one node and every edge that names it.
    mutating func remove(_ id: String) {
        nodes.removeAll { $0.id == id }
        edges.removeAll { $0.from == id || $0.to == id }
        if goalId == id { goalId = nil }
    }

    /// Removes one edge.
    mutating func disconnect(from: String, to: String) {
        edges.removeAll { $0.from == from && $0.to == to }
    }

    func node(_ id: String) -> Node? { nodes.first { $0.id == id } }

    // MARK: what a join is allowed to be

    /// True when `from` may feed `to`. The rules are the ones `tree(id:...)`
    /// refuses a graph by: the goal feeds nothing, every other node feeds one
    /// node, a step holds nothing under it except the goal, one root feeds
    /// the goal, and no route comes back to the node it left.
    func canJoin(from: String, to: String) -> Bool {
        guard from != to, node(from) != nil, let target = node(to) else { return false }
        guard goalId != from else { return false }
        guard edges.contains(where: { $0.from == from }) == false else { return false }
        if to == goalId {
            guard edges.contains(where: { $0.to == to }) == false else { return false }
        } else if case .step = target.kind {
            return false
        }

        var seen: Set<String> = [to]
        var current = to
        while let next = edges.first(where: { $0.from == current })?.to {
            if next == from { return false }
            guard seen.insert(next).inserted else { break }
            current = next
        }
        return true
    }

    /// Every join one node is offered, in the order the nodes were added.
    ///
    /// A node is offered each join it may feed. A junction is offered the
    /// nodes it may take as well, because a junction holds what feeds it and
    /// a step holds nothing.
    func joinsOffered(for id: String) -> [Edge] {
        nodes.compactMap { other in
            guard other.id != id else { return nil }
            if canJoin(from: id, to: other.id) { return Edge(from: id, to: other.id) }
            if canJoin(from: other.id, to: id) { return Edge(from: other.id, to: id) }
            return nil
        }
    }

    // MARK: the graph becomes the tree, or is refused

    /// The fault that stops a graph becoming a tree. Each message mirrors the
    /// parser's own rule, so the canvas and a hand-written file refuse the
    /// same shapes.
    enum Refusal: Error, Equatable {
        case noGoal
        case junctionGoal
        case feedsTwo(node: String)
        case feedsAStep(node: String)
        case cycle(node: String)
        case reachesNoGoal(node: String)
        case noSteps
        case twoRoots
        case junctionHoldsNothing(kind: String)

        var message: String {
            switch self {
            case .noGoal:
                "the tree states no goal"
            case .junctionGoal:
                "the goal names a threat; an all_of or an any_of is not one"
            case .feedsTwo(let node):
                "\"\(node)\" feeds two nodes; a step sits under one"
            case .feedsAStep(let node):
                "\"\(node)\" feeds a step; a step sits under an all_of or an any_of"
            case .cycle(let node):
                "the route through \"\(node)\" comes back to itself"
            case .reachesNoGoal(let node):
                "\"\(node)\" reaches no goal"
            case .noSteps:
                "the tree holds no steps"
            case .twoRoots:
                "two nodes feed the goal; one root feeds it"
            case .junctionHoldsNothing(let kind):
                "the \(kind) holds nothing"
            }
        }
    }

    /// The tree this graph states, or the refusal that stops it.
    func tree(
        id: String,
        name: String?,
        description: String?,
        raisesRiskBy: Int
    ) -> Result<SourceAttackTree, Refusal> {
        guard let goalId, let goalNode = node(goalId) else { return .failure(.noGoal) }
        guard case .step(let goalTarget, _) = goalNode.kind else {
            return .failure(.junctionGoal)
        }

        // Every node but the goal feeds exactly one node.
        for node in nodes where node.id != goalId {
            let out = edges.filter { $0.from == node.id }
            if out.count > 1 { return .failure(.feedsTwo(node: node.title)) }
        }
        if edges.contains(where: { $0.from == goalId }) {
            return .failure(.feedsTwo(node: goalNode.title))
        }

        // A step holds no children: steps are leaves.
        for edge in edges {
            guard let into = node(edge.to), into.id != goalId else { continue }
            if case .step = into.kind {
                return .failure(.feedsAStep(node: node(edge.from)?.title ?? edge.from))
            }
        }

        // A route that never ends is a cycle; one that ends anywhere but the
        // goal reaches no goal.
        for start in nodes where start.id != goalId {
            var seen: Set<String> = [start.id]
            var current = start.id
            while let next = edges.first(where: { $0.from == current })?.to {
                if next == goalId { break }
                if seen.insert(next).inserted == false {
                    return .failure(.cycle(node: start.title))
                }
                current = next
            }
            if edges.first(where: { $0.from == current })?.to != goalId {
                return .failure(.reachesNoGoal(node: start.title))
            }
        }

        // A junction holds what feeds it.
        for node in nodes {
            switch node.kind {
            case .allOf where feeders(of: node.id).isEmpty:
                return .failure(.junctionHoldsNothing(kind: "all_of"))
            case .anyOf where feeders(of: node.id).isEmpty:
                return .failure(.junctionHoldsNothing(kind: "any_of"))
            default:
                break
            }
        }

        let roots = feeders(of: goalId)
        guard roots.isEmpty == false else { return .failure(.noSteps) }
        guard roots.count == 1 else { return .failure(.twoRoots) }

        return .success(SourceAttackTree(
            id: id,
            name: name,
            description: description,
            raisesRiskBy: raisesRiskBy,
            goal: goalTarget,
            root: subtree(of: roots[0])
        ))
    }

    /// The nodes feeding one node, in the order they were added.
    private func feeders(of id: String) -> [String] {
        nodes.map(\.id).filter { from in edges.contains(Edge(from: from, to: id)) }
    }

    private func subtree(of id: String) -> SourceTreeNode {
        guard let node = node(id) else { return .all([]) }
        switch node.kind {
        case .step(let target, let note):
            return .step(SourceTreeStep(target: target, note: note))
        case .allOf:
            return .all(feeders(of: id).map { subtree(of: $0) })
        case .anyOf:
            return .any(feeders(of: id).map { subtree(of: $0) })
        }
    }

    // MARK: a tree becomes the graph

    /// The graph one tree states, laid out again from the file: the file
    /// holds the model and nothing about the drawing. `naming` turns a target
    /// into the title and subtitle a node shows; the ids stand in without it.
    static func graph(
        of tree: SourceAttackTree,
        naming: (SourceTreeTarget) -> (title: String, subtitle: String) = {
            ($0.threatId, "\($0.sourceKind) \($0.sourceId)")
        }
    ) -> TreeGraph {
        var graph = TreeGraph()
        let said = naming(tree.goal)
        let goal = graph.add(
            .step(target: tree.goal, note: nil),
            title: said.title,
            subtitle: said.subtitle
        )
        graph.goalId = goal
        graph.grow(tree.root, feeding: goal, naming: naming)
        return graph
    }

    private mutating func grow(
        _ node: SourceTreeNode,
        feeding parent: String,
        naming: (SourceTreeTarget) -> (title: String, subtitle: String)
    ) {
        switch node {
        case .step(let step):
            let said = naming(step.target)
            let id = add(
                .step(target: step.target, note: step.note),
                title: said.title,
                subtitle: said.subtitle
            )
            join(from: id, to: parent)
        case .all(let children):
            let id = add(.allOf, title: "ALL")
            join(from: id, to: parent)
            for child in children { grow(child, feeding: id, naming: naming) }
        case .any(let children):
            let id = add(.anyOf, title: "ANY")
            join(from: id, to: parent)
            for child in children { grow(child, feeding: id, naming: naming) }
        }
    }

    // MARK: where a node sits

    /// Where each node sits: the goal at the right, each depth one column to
    /// its left, siblings stacked in the order they were added. The same
    /// graph lays out the same way every time.
    func positions(
        nodeSize: CGSize,
        horizontalGap: CGFloat,
        verticalGap: CGFloat
    ) -> [String: CGPoint] {
        var depths: [String: Int] = [:]
        for node in nodes {
            var depth = 0
            var seen: Set<String> = [node.id]
            var current = node.id
            while let next = edges.first(where: { $0.from == current })?.to,
                  seen.insert(next).inserted {
                depth += 1
                current = next
            }
            depths[node.id] = depth
        }
        let deepest = depths.values.max() ?? 0

        var rows: [Int: Int] = [:]
        var positions: [String: CGPoint] = [:]
        for node in nodes {
            let depth = depths[node.id] ?? 0
            let column = deepest - depth
            let row = rows[column] ?? 0
            rows[column] = row + 1
            positions[node.id] = CGPoint(
                x: nodeSize.width / 2 + CGFloat(column) * (nodeSize.width + horizontalGap),
                y: nodeSize.height / 2 + CGFloat(row) * (nodeSize.height + verticalGap)
            )
        }
        return positions
    }
}
