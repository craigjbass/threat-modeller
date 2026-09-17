import CoreGraphics
import Observation
import ThreatModelKit

/// The tree in front on the Attack Trees stage.
///
/// The design in
/// `docs/superpowers/specs/2026-09-16-attack-tree-stage-design.md` states the
/// shape: the window owns one of these beside `CanvasState`, so the tree in
/// front and its history survive a change of stage. Every change goes
/// through one method that records the history, converts the graph and
/// writes through the project when the graph is a tree. A tree is not in the
/// in-memory model, so the model's undo cannot take a change back; this
/// history can.
@MainActor
@Observable
final class TreeEditor {
    /// The project the tree is written to. The stage sets it. With none, a
    /// change records its history and writes nothing.
    var project: ProjectSession?

    /// Everything a change can touch, so one snapshot puts all of it back.
    struct Draft: Equatable {
        var graph = TreeGraph()
        /// Where each node sits. The window holds the points; the file
        /// states none.
        var layout = TreeLayout()
        var pending: [PendingElement] = []
        var name = ""
        var description = ""
        var raisesRiskBy = 0
        /// The controls that are each sufficient to close the whole route,
        /// in the order the file states them.
        var closedBy: [String] = []
    }

    /// The id of the tree in front. The file names a tree by it.
    private(set) var id = ""
    private(set) var draft = Draft()
    /// Why the graph is not a tree, or nil while it writes.
    private(set) var refusal: String?
    /// The last tree written, so an unchanged graph writes nothing.
    private(set) var lastWritten: SourceAttackTree?
    /// True once a tree is chosen or added, so the canvas has something to be.
    private(set) var isEditing = false

    private var past: [(label: String, draft: Draft)] = []
    private var future: [(label: String, draft: Draft)] = []
    private var nextPendingNumber = 1

    var graph: TreeGraph { draft.graph }
    var layout: TreeLayout { draft.layout }
    var pending: [PendingElement] { draft.pending }
    var name: String { draft.name }
    var description: String { draft.description }
    var raisesRiskBy: Int { draft.raisesRiskBy }
    var closedBy: [String] { draft.closedBy }

    // MARK: history

    var canUndo: Bool { past.isEmpty == false }
    var canRedo: Bool { future.isEmpty == false }
    /// What the Edit menu names: the change Undo takes back, or nil.
    var undoLabel: String? { past.last?.label }
    var redoLabel: String? { future.last?.label }

    func undo() {
        guard let last = past.popLast() else { return }
        future.append((label: last.label, draft: draft))
        draft = last.draft
        save()
    }

    func redo() {
        guard let next = future.popLast() else { return }
        past.append((label: next.label, draft: draft))
        draft = next.draft
        save()
    }

    /// One change: the history records the draft before it, the redo history
    /// empties, and the result writes when it is a tree.
    private func change(_ label: String, _ apply: (inout Draft) -> Void) {
        let before = draft
        apply(&draft)
        draft.layout.retainOnly(Set(draft.graph.nodes.map(\.id)))
        draft.layout.placeUnplaced(in: draft.graph)
        guard draft != before else { return }
        past.append((label: label, draft: before))
        future = []
        save()
    }

    // MARK: opening and closing

    /// Opens one tree the file states. The file holds no point, so every
    /// node takes the layout's point once.
    func open(_ tree: SourceAttackTree, threats: [AssessedThreat]) {
        id = tree.id
        let graph = TreeGraph.graph(of: tree) { target in
            let key = TreeDraft.key(of: target)
            guard let threat = threats.first(where: { $0.threatKey == key }) else {
                return (target.threatId, "\(target.sourceKind) \(target.sourceId)")
            }
            return (threat.name, threat.source.displayName)
        }
        // The file states no point, so the window places every node once,
        // from the layout.
        draft = Draft(
            graph: graph,
            layout: TreeLayout(laidOut: graph),
            pending: [],
            name: tree.name ?? tree.id,
            description: tree.description ?? "",
            raisesRiskBy: tree.raisesRiskBy,
            closedBy: tree.closedBy
        )
        past = []
        future = []
        refusal = nil
        lastWritten = tree
        isEditing = true
    }

    /// Starts a new, empty tree with the first id the file does not hold.
    func addTree(among trees: [SourceAttackTree]) {
        var number = trees.count + 1
        while trees.contains(where: { $0.id == "tree-\(number)" }) { number += 1 }
        id = "tree-\(number)"
        draft = Draft(name: "A new tree")
        past = []
        future = []
        refusal = TreeGraph.Refusal.noGoal.message
        lastWritten = nil
        isEditing = true
    }

    /// Leaves no tree in front. Choosing another system calls this.
    func close() {
        id = ""
        draft = Draft()
        past = []
        future = []
        refusal = nil
        lastWritten = nil
        isEditing = false
    }

    /// Deletes the tree in front from the file and closes it.
    func deleteTree() {
        let deleted = id
        close()
        project?.deleteAttackTree(deleted)
    }

    // MARK: what a person draws

    /// A drop from the element list. A junction becomes a node at once; an
    /// element waits, pending, until a threat is picked. Returns the id of
    /// what was dropped, or nil for a payload the list does not offer.
    @discardableResult
    func drop(_ payload: String, at point: CGPoint, elements: [TreeElement]) -> String? {
        if payload == "junction:all" {
            var id = ""
            change("Drop") {
                id = $0.graph.add(.allOf, title: "ALL")
                $0.layout.place(id, at: point)
            }
            return id
        }
        if payload == "junction:any" {
            var id = ""
            change("Drop") {
                id = $0.graph.add(.anyOf, title: "ANY")
                $0.layout.place(id, at: point)
            }
            return id
        }
        if payload == TreeElement.boxPayload {
            var id = ""
            change("Drop") {
                id = $0.graph.add(.placeholder(element: nil), title: Self.boxTitle(nil))
                $0.layout.place(id, at: point)
            }
            return id
        }
        guard let element = elements.first(where: { $0.payload == payload }) else { return nil }
        let id = "p\(nextPendingNumber)"
        nextPendingNumber += 1
        change("Drop") {
            $0.pending.append(PendingElement(id: id, element: element, point: point))
        }
        return id
    }

    /// What a box shows: the element it holds, or **Any element**.
    static func boxTitle(_ element: TreeElement?) -> String {
        element?.name ?? "Any element"
    }

    /// Fills a box with the element picked from the search, or empties it
    /// again with nil. The box keeps its id, its point and its joins.
    func fill(_ id: String, with element: TreeElement?) {
        guard case .placeholder = draft.graph.node(id)?.kind else { return }
        change(element == nil ? "Empty the Box" : "Pick Element") {
            $0.graph.set(
                id,
                kind: .placeholder(element: element),
                title: Self.boxTitle(element),
                subtitle: element?.kind ?? ""
            )
        }
    }

    /// Picking a threat makes the pending element, or the filled box, a
    /// step. A tree reaches a threat, so the first step a person makes is
    /// the goal until they move the mark.
    func pick(_ threat: AssessedThreat, for pendingId: String) {
        if case .placeholder(let element?) = draft.graph.node(pendingId)?.kind {
            change("Pick Threat") { draft in
                let target = SourceTreeTarget(
                    threatId: threat.threatId,
                    sourceKind: element.kind,
                    sourceId: element.sourceId
                )
                draft.graph.set(
                    pendingId,
                    kind: .step(target: target, note: nil),
                    title: threat.name,
                    subtitle: element.name
                )
                if draft.graph.goalId == nil { draft.graph.goalId = pendingId }
            }
            return
        }
        guard let item = draft.pending.first(where: { $0.id == pendingId }) else { return }
        change("Pick Threat") { draft in
            let target = SourceTreeTarget(
                threatId: threat.threatId,
                sourceKind: item.element.kind,
                sourceId: item.element.sourceId
            )
            let id = draft.graph.add(
                .step(target: target, note: nil),
                title: threat.name,
                subtitle: item.element.name
            )
            draft.layout.place(id, at: item.point)
            if draft.graph.goalId == nil { draft.graph.goalId = id }
            draft.pending.removeAll { $0.id == pendingId }
        }
    }

    /// `from` feeds `to`.
    func join(from: String, to: String) {
        change("Join") { $0.graph.join(from: from, to: to) }
    }

    /// Cuts every edge leaving one node.
    func cutOutgoingJoin(of id: String) {
        change("Cut Join") { draft in
            for edge in draft.graph.edges where edge.from == id {
                draft.graph.disconnect(from: edge.from, to: edge.to)
            }
        }
    }

    /// Cuts one edge. The menu on the edge and the selection panel call this.
    func cut(_ edge: TreeGraph.Edge) {
        change("Cut Join") { $0.graph.disconnect(from: edge.from, to: edge.to) }
    }

    /// Removes nodes, pending elements and edges. One change, so one undo
    /// puts every one of them back.
    func remove(_ ids: Set<String>, edges: Set<TreeGraph.Edge> = []) {
        change("Delete") { draft in
            for edge in edges { draft.graph.disconnect(from: edge.from, to: edge.to) }
            for id in ids { draft.graph.remove(id) }
            draft.pending.removeAll { ids.contains($0.id) }
        }
    }

    /// Moves the named nodes and pending elements by one distance. The drag
    /// on the canvas ends here, so one drag is one undoable change.
    func move(_ ids: Set<String>, by shift: CGSize) {
        guard ids.isEmpty == false, shift != .zero else { return }
        change("Move") { draft in
            draft.layout.move(ids, by: shift)
            draft.pending = draft.pending.map { item in
                guard ids.contains(item.id) else { return item }
                return PendingElement(
                    id: item.id,
                    element: item.element,
                    point: CGPoint(x: item.point.x + shift.width, y: item.point.y + shift.height)
                )
            }
        }
    }

    /// Every node takes the point the layout states. Lay Out Tree calls this,
    /// and one undo puts the old points back.
    func layOutTree() {
        change("Lay Out Tree") { $0.layout.layOut($0.graph) }
    }

    func setGoal(_ id: String) {
        change("Set as Goal") { $0.graph.goalId = id }
    }

    func setName(_ name: String) {
        change("Rename") { $0.name = name }
    }

    func setDescription(_ description: String) {
        change("Describe") { $0.description = description }
    }

    func setRaisesRiskBy(_ percent: Int) {
        change("Raises Risk By") { $0.raisesRiskBy = percent }
    }

    /// Names one more control as sufficient to close the whole route. A
    /// control the tree names already is not named twice.
    func addSufficientControl(_ description: String) {
        guard draft.closedBy.contains(description) == false else { return }
        change("Add Sufficient Control") { $0.closedBy.append(description) }
    }

    func removeSufficientControl(_ description: String) {
        change("Remove Sufficient Control") { $0.closedBy.removeAll { $0 == description } }
    }

    // MARK: what is written

    /// Writes the graph when it states a tree, or states the refusal. There
    /// is no Save button to forget: a valid change writes at once.
    private func save() {
        let result = draft.graph.tree(
            id: id,
            name: draft.name.isEmpty ? nil : draft.name,
            description: draft.description.isEmpty ? nil : draft.description,
            raisesRiskBy: draft.raisesRiskBy,
            closedBy: draft.closedBy
        )
        switch result {
        case .success(let tree):
            refusal = nil
            guard tree != lastWritten else { return }
            lastWritten = tree
            project?.saveAttackTree(tree)
        case .failure(let fault):
            refusal = fault.message
        }
    }
}
