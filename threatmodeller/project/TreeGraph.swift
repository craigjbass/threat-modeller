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
        /// A box waiting for an element, then a threat. It is never written:
        /// `tree(id:...)` refuses a graph that holds one. The design in
        /// `docs/superpowers/specs/2026-09-16-tree-connectable-elements-design.md`
        /// states it.
        case placeholder(element: TreeElement?)

        /// True for a node that takes one feeder: a step, and a box, which
        /// becomes a step.
        var takesOneFeeder: Bool {
            switch self {
            case .step, .placeholder: true
            case .allOf, .anyOf: false
            }
        }
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

    /// Changes what one node is and what it shows. The id and the edges
    /// stay, so a box that becomes a step keeps its joins.
    mutating func set(_ id: String, kind: Kind, title: String, subtitle: String) {
        guard let at = nodes.firstIndex(where: { $0.id == id }) else { return }
        nodes[at].kind = kind
        nodes[at].title = title
        nodes[at].subtitle = subtitle
    }

    // MARK: what a join is allowed to be

    /// True when `from` may feed `to`. The rules are the ones `tree(id:...)`
    /// refuses a graph by: the goal feeds nothing, every other node feeds one
    /// node, a step takes one feeder, which is the node that comes before it
    /// in a chain, and no route comes back to the node it left. The goal is
    /// a step, so one root feeds it by the same rule.
    func canJoin(from: String, to: String) -> Bool {
        guard from != to, node(from) != nil, let target = node(to) else { return false }
        guard goalId != from else { return false }
        guard edges.contains(where: { $0.from == from }) == false else { return false }
        if target.kind.takesOneFeeder {
            guard edges.contains(where: { $0.to == to }) == false else { return false }
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
    /// A node is offered each join it may feed, then each join it may take.
    /// A junction takes many feeders, and a step takes the one node that
    /// comes before it, so both are offered what may feed them.
    func joinsOffered(for id: String) -> [Edge] {
        nodes.flatMap { other -> [Edge] in
            guard other.id != id else { return [] }
            var offered: [Edge] = []
            if canJoin(from: id, to: other.id) { offered.append(Edge(from: id, to: other.id)) }
            if canJoin(from: other.id, to: id) { offered.append(Edge(from: other.id, to: id)) }
            return offered
        }
    }

    // MARK: the chain a step is a link of

    /// The links of the chain one node sits in, first link first, ending at
    /// the last step before a junction or the goal. A node outside every
    /// chain gives one link: itself.
    ///
    /// A step's feeder is the link before it. A junction is the first link
    /// of a chain when it feeds a step; it is never a later link, because
    /// its own feeders are its children.
    func chain(holding id: String) -> [String] {
        guard let start = node(id) else { return [] }
        var links = [id]
        // Back to the first link: while this link is a step with a feeder.
        var current = start
        var seen: Set<String> = [id]
        while case .step = current.kind,
              let feeder = edges.first(where: { $0.to == current.id })?.from,
              seen.insert(feeder).inserted,
              let node = node(feeder) {
            links.insert(feeder, at: 0)
            current = node
        }
        // Forward to the last link: while this link feeds a step that is not
        // the goal.
        current = start
        while let next = edges.first(where: { $0.from == current.id })?.to,
              next != goalId,
              let node = node(next),
              case .step = node.kind,
              seen.insert(next).inserted {
            links.append(next)
            current = node
        }
        return links
    }

    // MARK: the graph becomes the tree, or is refused

    /// The fault that stops a graph becoming a tree. Each message mirrors the
    /// parser's own rule, so the canvas and a hand-written file refuse the
    /// same shapes.
    enum Refusal: Error, Equatable {
        case noGoal
        case junctionGoal
        case feedsTwo(node: String)
        case feedsAFedStep(node: String)
        case cycle(node: String)
        case reachesNoGoal(node: String)
        case noSteps
        case twoRoots
        case junctionHoldsNothing(kind: String)
        case unfilledBox
        case boxNamesNoThreat(element: String)

        var message: String {
            switch self {
            case .noGoal:
                "the tree states no goal"
            case .junctionGoal:
                "the goal names a threat; an all_of or an any_of is not one"
            case .feedsTwo(let node):
                "\"\(node)\" feeds two nodes; a step sits under one"
            case .feedsAFedStep(let node):
                "\"\(node)\" feeds a step that comes after another node"
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
            case .unfilledBox:
                "a box holds no element yet; pick one, or delete the box"
            case .boxNamesNoThreat(let element):
                "\"\(element)\" names no threat yet; pick one"
            }
        }
    }

    /// The tree this graph states, or the refusal that stops it.
    func tree(
        id: String,
        name: String?,
        description: String?,
        raisesRiskBy: Int,
        closedBy: [String] = []
    ) -> Result<SourceAttackTree, Refusal> {
        guard let goalId, let goalNode = node(goalId) else { return .failure(.noGoal) }
        guard case .step(let goalTarget, _) = goalNode.kind else {
            return .failure(.junctionGoal)
        }

        // A box is never written. The save waits until it is filled, then
        // given a threat, or removed.
        for node in nodes {
            if case .placeholder(let element) = node.kind {
                guard let element else { return .failure(.unfilledBox) }
                return .failure(.boxNamesNoThreat(element: element.name))
            }
        }

        // Every node but the goal feeds exactly one node.
        for node in nodes where node.id != goalId {
            let out = edges.filter { $0.from == node.id }
            if out.count > 1 { return .failure(.feedsTwo(node: node.title)) }
        }
        if edges.contains(where: { $0.from == goalId }) {
            return .failure(.feedsTwo(node: goalNode.title))
        }

        // A step takes one feeder: the node that comes before it in a chain.
        // The goal is a step too, and `twoRoots` names that case below.
        for node in nodes where node.id != goalId {
            guard case .step = node.kind else { continue }
            let feeders = feeders(of: node.id)
            if feeders.count > 1 {
                return .failure(.feedsAFedStep(node: self.node(feeders[1])?.title ?? feeders[1]))
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
            closedBy: closedBy,
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
            let step = SourceTreeNode.step(SourceTreeStep(target: target, note: note))
            // A step with a feeder is the last link of a chain. A feeder
            // that is itself a chain flattens into this one, so three steps
            // feeding each other write as one `then`.
            guard let before = feeders(of: id).first else { return step }
            switch subtree(of: before) {
            case .then(let links):
                return .then(links + [step])
            case let link:
                return .then([link, step])
            }
        case .allOf:
            return .all(feeders(of: id).map { subtree(of: $0) })
        case .anyOf:
            return .any(feeders(of: id).map { subtree(of: $0) })
        case .placeholder:
            // `tree(id:...)` refuses a graph that holds a box before it
            // reaches here.
            return .all([])
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

    /// Grows one node under `parent` and returns the id of the node that
    /// feeds the parent.
    @discardableResult
    private mutating func grow(
        _ node: SourceTreeNode,
        feeding parent: String,
        naming: (SourceTreeTarget) -> (title: String, subtitle: String)
    ) -> String {
        switch node {
        case .step(let step):
            let said = naming(step.target)
            let id = add(
                .step(target: step.target, note: step.note),
                title: said.title,
                subtitle: said.subtitle
            )
            join(from: id, to: parent)
            return id
        case .then(let links):
            // The last link feeds the parent, and each earlier link feeds
            // the link after it. The parser holds every later link to a
            // step, so each one takes its one feeder.
            var next = parent
            for link in links.reversed() {
                next = grow(link, feeding: next, naming: naming)
            }
            return next
        case .all(let children):
            let id = add(.allOf, title: "ALL")
            join(from: id, to: parent)
            for child in children { grow(child, feeding: id, naming: naming) }
            return id
        case .any(let children):
            let id = add(.anyOf, title: "ANY")
            join(from: id, to: parent)
            for child in children { grow(child, feeding: id, naming: naming) }
            return id
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
