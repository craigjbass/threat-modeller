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
    private(set) var selectedZoneIds: Set<String> = []

    /// How tall the selection panel under the canvas is, or zero while no
    /// selection panel is shown. The floating workflow panel reads it and
    /// floats above it, so the two never cover each other.
    var selectionPanelHeight: CGFloat = 0

    /// True while the next background drag draws a zone rather than a marquee.
    private(set) var isDrawingZone = false
    /// Which element's name is being edited in place, or nil.
    private(set) var editingName: NameEdit?

    /// The two corners of the zone being drawn, in model coordinates.
    var zoneDraft: (start: CGPoint, end: CGPoint)?

    /// The zone being moved or resized, the grip the drag started from, and
    /// how far it has moved in model units. A nil handle means the drag started
    /// on the header, which moves the zone rather than resizing it.
    var zoneDrag: (zoneId: String, handle: ZoneHandle?, translation: CGSize)?

    /// How far the selection has moved while a node drag is in flight, in
    /// model units. Nil when no drag is in flight.
    var dragTranslation: CGSize?

    /// The marquee's two corners in model coordinates while a marquee drag is
    /// in flight.
    var marquee: (start: CGPoint, end: CGPoint)?

    /// The component a connection drag started from, and where the pointer is
    /// now, in model coordinates.
    var connectionDrag: (sourceComponentId: String, currentPoint: CGPoint)?

    /// How much of a Command-drag has already been applied to the pan. A drag
    /// reports the translation from where it started, so the pan applies the
    /// step since the last change rather than the whole translation again.
    var lastPanTranslation: CGSize = .zero

    var marqueeRect: CGRect? {
        marquee.map { MarqueeSelection.rect(from: $0.start, to: $0.end) }
    }

    var zoneDraftRect: CGRect? {
        zoneDraft.map { MarqueeSelection.rect(from: $0.start, to: $0.end) }
    }

    var hasSelection: Bool {
        selectedComponentIds.isEmpty == false
            || selectedConnectionIds.isEmpty == false
            || selectedZoneIds.isEmpty == false
    }

    func isSelected(componentId: String) -> Bool { selectedComponentIds.contains(componentId) }

    func isSelected(connectionId: String) -> Bool { selectedConnectionIds.contains(connectionId) }

    func isSelected(zoneId: String) -> Bool { selectedZoneIds.contains(zoneId) }

    func clearSelection() {
        selectedComponentIds = []
        selectedConnectionIds = []
        selectedZoneIds = []
    }

    /// A plain click selects only that component. A shift-click adds it, or
    /// removes it when it is already selected.
    func select(componentId: String, addingToSelection: Bool) {
        selectedConnectionIds = []
        selectedZoneIds = []
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
        selectedZoneIds = []
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
    func select(componentIds: [String], zoneIds: [String] = []) {
        selectedComponentIds = Set(componentIds)
        selectedConnectionIds = []
        selectedZoneIds = Set(zoneIds)
    }

    /// A plain click selects only that zone. A shift-click adds it, or removes
    /// it when it is already selected, so several zones move and are deleted
    /// together.
    func select(zoneId: String, addingToSelection: Bool = false) {
        selectedComponentIds = []
        selectedConnectionIds = []
        guard addingToSelection else {
            selectedZoneIds = [zoneId]
            return
        }
        if selectedZoneIds.contains(zoneId) {
            selectedZoneIds.remove(zoneId)
        } else {
            selectedZoneIds.insert(zoneId)
        }
    }

    /// Selects exactly what is named. Used by Select All and by what a paste
    /// just made, so the user can move it straight away.
    func selectAll(componentIds: [String], zoneIds: [String]) {
        selectedComponentIds = Set(componentIds)
        selectedZoneIds = Set(zoneIds)
        selectedConnectionIds = []
    }

    /// Which element's name is being edited in place, or nil.
    ///
    /// One at a time: a second double-click moves the edit rather than opening
    /// two fields.
    enum NameEdit: Equatable {
        case component(String)
        case zone(String)
        case connection(String)
    }

    func isEditingName(_ edit: NameEdit) -> Bool {
        editingName == edit
    }

    func startEditingName(_ edit: NameEdit) {
        editingName = edit
    }

    func stopEditingName() {
        editingName = nil
    }

    func startDrawingZone() {
        isDrawingZone = true
        zoneDraft = nil
    }

    func stopDrawingZone() {
        isDrawingZone = false
        zoneDraft = nil
    }

    /// Drops selected rows the model no longer holds. Call after any removal.
    func retainOnly(componentIds: Set<String>, connectionIds: Set<String>, zoneIds: Set<String>) {
        selectedComponentIds.formIntersection(componentIds)
        selectedConnectionIds.formIntersection(connectionIds)
        selectedZoneIds.formIntersection(zoneIds)
    }

    /// Escape: cancel a connection drag when one is in flight, else leave the
    /// zone drawing mode, else clear the selection. Returns true when it
    /// changed something.
    @discardableResult
    func cancel() -> Bool {
        if connectionDrag != nil {
            connectionDrag = nil
            return true
        }
        if isDrawingZone {
            stopDrawingZone()
            return true
        }
        if hasSelection {
            clearSelection()
            return true
        }
        return false
    }
}
