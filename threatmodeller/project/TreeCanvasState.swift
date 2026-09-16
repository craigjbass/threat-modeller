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

    /// The selected nodes and pending elements, by id.
    private(set) var selectedIds: Set<String> = []

    /// How far the selection has moved while a node drag is in flight, in
    /// model units. Nil when no drag is in flight.
    var dragTranslation: CGSize?

    /// The join being dragged: the node it started from, and where the
    /// pointer is now, in model coordinates.
    var joining: (from: String, to: CGPoint)?

    var marqueeRect: CGRect? {
        marquee.map { MarqueeSelection.rect(from: $0.start, to: $0.end) }
    }

    var hasSelection: Bool { selectedIds.isEmpty == false }

    func isSelected(_ id: String) -> Bool { selectedIds.contains(id) }

    /// A plain click selects only that node. A shift-click adds it, or
    /// removes it when it is already selected.
    func select(_ id: String, addingToSelection: Bool) {
        guard addingToSelection else {
            selectedIds = [id]
            return
        }
        if selectedIds.contains(id) {
            selectedIds.remove(id)
        } else {
            selectedIds.insert(id)
        }
    }

    /// The result of a marquee drag or Select All. It replaces the selection.
    func select(_ ids: [String]) {
        selectedIds = Set(ids)
    }

    func clearSelection() {
        selectedIds = []
    }

    /// Drops selected ids the tree no longer holds. Call after any removal.
    func retainOnly(_ ids: Set<String>) {
        selectedIds.formIntersection(ids)
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
