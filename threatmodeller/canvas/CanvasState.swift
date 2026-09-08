import CoreGraphics
import Observation

/// Everything the canvas needs that is not part of the threat model.
///
/// Spec section 3.6 keeps pan, zoom, selection, a drag in flight, the marquee
/// and the connection preview in the delivery mechanism. This object calls no
/// use case and holds no business rule, so a drag changing 60 times a second
/// never touches the object the threat list observes.
@MainActor
@Observable
final class CanvasState {
    var transform = CanvasTransform()

    private(set) var selectedComponentIds: Set<String> = []
    private(set) var selectedConnectionIds: Set<String> = []

    /// How far the selection has moved while a node drag is in flight, in
    /// model units. Nil when no drag is in flight.
    var dragTranslation: CGSize?

    /// The marquee's two corners in model coordinates while a marquee drag is
    /// in flight.
    var marquee: (start: CGPoint, end: CGPoint)?

    /// The component a connection drag started from, and where the pointer is
    /// now, in model coordinates.
    var connectionDrag: (sourceComponentId: String, currentPoint: CGPoint)?

    var marqueeRect: CGRect? {
        marquee.map { MarqueeSelection.rect(from: $0.start, to: $0.end) }
    }

    var hasSelection: Bool {
        selectedComponentIds.isEmpty == false || selectedConnectionIds.isEmpty == false
    }

    func isSelected(componentId: String) -> Bool { selectedComponentIds.contains(componentId) }

    func isSelected(connectionId: String) -> Bool { selectedConnectionIds.contains(connectionId) }

    func clearSelection() {
        selectedComponentIds = []
        selectedConnectionIds = []
    }

    /// A plain click selects only that component. A shift-click adds it, or
    /// removes it when it is already selected.
    func select(componentId: String, addingToSelection: Bool) {
        selectedConnectionIds = []
        guard addingToSelection else {
            selectedComponentIds = [componentId]
            return
        }
        if selectedComponentIds.contains(componentId) {
            selectedComponentIds.remove(componentId)
        } else {
            selectedComponentIds.insert(componentId)
        }
    }

    func select(connectionId: String, addingToSelection: Bool) {
        selectedComponentIds = []
        guard addingToSelection else {
            selectedConnectionIds = [connectionId]
            return
        }
        if selectedConnectionIds.contains(connectionId) {
            selectedConnectionIds.remove(connectionId)
        } else {
            selectedConnectionIds.insert(connectionId)
        }
    }

    /// The result of a marquee drag. It replaces the whole selection.
    func select(componentIds: [String]) {
        selectedComponentIds = Set(componentIds)
        selectedConnectionIds = []
    }

    /// Drops selected rows the model no longer holds. Call after any removal.
    func retainOnly(componentIds: Set<String>, connectionIds: Set<String>) {
        selectedComponentIds.formIntersection(componentIds)
        selectedConnectionIds.formIntersection(connectionIds)
    }

    /// Escape: cancel a connection drag when one is in flight, else clear the
    /// selection. Returns true when it changed something.
    @discardableResult
    func cancel() -> Bool {
        if connectionDrag != nil {
            connectionDrag = nil
            return true
        }
        if hasSelection {
            clearSelection()
            return true
        }
        return false
    }
}
