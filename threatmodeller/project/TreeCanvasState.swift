import CoreGraphics
import Observation

/// Everything the tree canvas needs that is not part of the tree.
///
/// The tree canvas's own `CanvasState`: the viewport, the selected ids, the
/// drag in flight and the join in flight. A node's point lives in
/// `TreeEditor`, so the history undoes a move. `CanvasState` is
/// not reused because it selects components, zones and connections, and a
/// tree canvas selects none of those. This object calls no use case.
@MainActor
@Observable
final class TreeCanvasState: CanvasViewport {
    var transform = CanvasTransform()
    var visibleSize: CGSize = .zero
    var isPanning = false
    var lastPanTranslation: CGSize = .zero
    var marquee: (start: CGPoint, end: CGPoint)?

    /// The selected nodes and pending elements, in the order they were
    /// selected. The order states what Join joins: the first selected node
    /// feeds the second.
    private(set) var selectedInOrder: [String] = []

    /// The selected joins, in the order they were selected.
    private(set) var selectedEdges: [TreeGraph.Edge] = []

    /// The selected nodes and pending elements, by id.
    var selectedIds: Set<String> { Set(selectedInOrder) }

    /// How far the selection has moved while a node drag is in flight, in
    /// model units. Nil when no drag is in flight.
    var dragTranslation: CGSize?

    /// The join being dragged: the node it started from, and where the
    /// pointer is now, in model coordinates.
    var joining: (from: String, to: CGPoint)?

    var marqueeRect: CGRect? {
        marquee.map { MarqueeSelection.rect(from: $0.start, to: $0.end) }
    }

    var hasSelection: Bool {
        selectedInOrder.isEmpty == false || selectedEdges.isEmpty == false
    }

    /// How many things are selected: the nodes and the joins together.
    var selectionCount: Int { selectedInOrder.count + selectedEdges.count }

    func isSelected(_ id: String) -> Bool { selectedInOrder.contains(id) }

    func isSelected(_ edge: TreeGraph.Edge) -> Bool { selectedEdges.contains(edge) }

    /// A plain click selects only that node. A shift-click adds it, or
    /// removes it when it is already selected.
    func select(_ id: String, addingToSelection: Bool) {
        guard addingToSelection else {
            selectedInOrder = [id]
            selectedEdges = []
            return
        }
        if let at = selectedInOrder.firstIndex(of: id) {
            selectedInOrder.remove(at: at)
        } else {
            selectedInOrder.append(id)
        }
    }

    /// A plain click selects only that join. A shift-click adds it, or
    /// removes it when it is already selected.
    func select(_ edge: TreeGraph.Edge, addingToSelection: Bool) {
        guard addingToSelection else {
            selectedEdges = [edge]
            selectedInOrder = []
            return
        }
        if let at = selectedEdges.firstIndex(of: edge) {
            selectedEdges.remove(at: at)
        } else {
            selectedEdges.append(edge)
        }
    }

    /// The result of a marquee drag or Select All. It replaces the selection.
    func select(_ ids: [String]) {
        selectedInOrder = ids
        selectedEdges = []
    }

    func clearSelection() {
        selectedInOrder = []
        selectedEdges = []
    }

    /// Drops the selected nodes and joins the tree no longer holds. Call
    /// after any removal.
    func retainOnly(_ ids: Set<String>, edges: Set<TreeGraph.Edge> = []) {
        selectedInOrder.removeAll { ids.contains($0) == false }
        selectedEdges.removeAll { edges.contains($0) == false }
    }

    /// Escape: cancel a join in flight, else clear the selection. Returns
    /// true when it changed something.
    @discardableResult
    func cancel() -> Bool {
        if joining != nil {
            joining = nil
            return true
        }
        if hasSelection {
            clearSelection()
            return true
        }
        return false
    }
}
