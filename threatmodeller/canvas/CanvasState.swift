import CoreGraphics
import Observation
import ThreatModelKit

/// What lays a narrowed set out for the canvas, and what the model holds.
///
/// `ThreatModelSession` conforms. The canvas holds this rather than the whole
/// session, so `CanvasState` still calls no use case of its own and a test
/// hands it whatever it likes.
@MainActor
protocol NarrowedDiagramLayouts: AnyObject {
    /// The model the canvas draws.
    var model: ViewThreatModelResponse { get }
    /// Where the named components and zones go, laid out on their own. It
    /// writes no model and no file.
    func layOutSubset(componentIds: [String], zoneIds: [String]) -> LayOutSubsetResponse
}

/// Everything the canvas needs that is not part of the threat model.
///
/// Spec section 3.6 keeps pan, zoom, selection, a drag in flight, the marquee
/// and the connection preview in the delivery mechanism. This object calls no
/// use case and holds no business rule, so a drag changing 60 times a second
/// never touches the object the threat list observes.
@MainActor
@Observable
final class CanvasState: CanvasViewport {
    var transform = CanvasTransform()

    private(set) var selectedComponentIds: Set<String> = []
    private(set) var selectedConnectionIds: Set<String> = []
    private(set) var selectedZoneIds: Set<String> = []

    /// Changes the stage the window draws. The window sets it; a context menu
    /// on the diagram calls it. Nil in a window that has no stages.
    var showStage: ((WorkStage) -> Void)?

    var visibleSize: CGSize = .zero

    var isPanning = false

    /// Whether the canvas fits the whole diagram the next time it appears.
    ///
    /// The layout preview draws the diagram fitted to the column, so the
    /// canvas must take over at that fit or the picture jumps. The window
    /// sets this while the preview is on screen, and a change of stage does
    /// not, so switching to the report and back keeps the transform the
    /// person set.
    var fitsOnNextAppearance = true

    /// Which tags the canvas draws. This is view state: it writes no file and
    /// changes no score, so the threat list keeps scoring the whole model.
    private(set) var tagFilter = TagFilter()

    /// The one component Focus draws, and its neighbours out to
    /// `tagFilter.neighbourDepth` flows. Nil draws by the tag filter alone.
    /// This is view state: it writes no file and changes no score.
    private(set) var focusedComponentId: String?

    /// What lays the narrowed set out. The window sets it. A canvas with none
    /// draws the model's own coordinates, which is what a preview wants.
    var layouts: (any NarrowedDiagramLayouts)?

    /// Where the narrowed set draws, by component id, and by zone id.
    ///
    /// Both are empty while nothing narrows the canvas. This is view state:
    /// it writes no file and moves no element of the model, so a save while a
    /// filter is on writes the full layout the file already holds.
    private(set) var narrowedComponentPositions: [String: CGPoint] = [:]
    private(set) var narrowedZoneRects: [String: CGRect] = [:]

    /// True while the tag filter or Focus narrows the canvas.
    var isNarrowing: Bool { focusedComponentId != nil || tagFilter.isNarrowing }

    /// True while the next background drag draws a zone rather than a marquee.
    private(set) var isDrawingZone = false
    /// Which element's name is being edited in place, or nil.
    private(set) var editingName: NameEdit?

    /// The two corners of the zone being drawn, in model coordinates.
    var zoneDraft: (start: CGPoint, end: CGPoint)?

    /// The components the merge sheet is open for. Empty while no merge
    /// sheet is open.
    private(set) var mergeCandidateIds: [String] = []

    /// True while the merge sheet is open.
    var isMerging: Bool { mergeCandidateIds.isEmpty == false }

    func startMerging(componentIds: [String]) {
        mergeCandidateIds = componentIds
    }

    func stopMerging() {
        mergeCandidateIds = []
    }

    /// The zone being moved or resized, the grip the drag started from, and
    /// how far it has moved in model units. A nil handle means the drag started
    /// on the header, which moves the zone rather than resizing it.
    var zoneDrag: (zoneId: String, handle: ZoneHandle?, translation: CGSize)?

    /// How far the selection has moved while a node drag is in flight, in
    /// model units. Nil when no drag is in flight.
    var dragTranslation: CGSize?

    var marquee: (start: CGPoint, end: CGPoint)?

    /// The component a connection drag started from, and where the pointer is
    /// now, in model coordinates.
    var connectionDrag: (sourceComponentId: String, currentPoint: CGPoint)?

    /// The background drag's translation already applied to the pan.
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

    /// Picks a tag the canvas draws, or drops it when it is picked already.
    func pick(tag: String) {
        tagFilter.pick(tag)
        clearSelection()
        layOutNarrowedSet()
    }

    /// Draws the whole model again. Clears Focus too, so the one button
    /// undoes whichever of the two narrowed the canvas.
    func clearTagFilter() {
        tagFilter.clear()
        focusedComponentId = nil
        layOutNarrowedSet()
    }

    /// Sets how many flows out the tag filter and Focus draw around what
    /// they pick. The value holds while the window is open, and changing
    /// the picked tags or Focus does not reset it.
    func setNeighbourDepth(_ depth: Int) {
        tagFilter.setNeighbourDepth(depth)
        layOutNarrowedSet()
    }

    /// Draws one component and its neighbours. Focus and the tag filter
    /// never both narrow the canvas, so this clears the tag filter first: a
    /// component the filter was hiding is drawn once Focus picks it.
    func focus(componentId: String) {
        tagFilter.clear()
        focusedComponentId = componentId
        clearSelection()
        layOutNarrowedSet()
    }

    /// The one diagram the window draws, hit tests and acts on: Focus
    /// narrows it to one component and its neighbours; else the tag filter
    /// narrows it, and with neither on that is the whole model.
    ///
    /// The view, the gestures and the menus all call this, so a click, a
    /// marquee, Select All and the drawing itself never disagree about what
    /// a person can see.
    func drawn(in model: ViewThreatModelResponse) -> DrawnDiagram {
        narrowedSet(of: model).placed(
            componentPositions: narrowedComponentPositions,
            zoneRects: narrowedZoneRects
        )
    }

    /// Which elements the canvas draws, at the model's own coordinates.
    ///
    /// The narrowed layout reads this, so every run starts from the model and
    /// never from the run before. Two tags picked in either order draw the
    /// same picture.
    private func narrowedSet(of model: ViewThreatModelResponse) -> DrawnDiagram {
        if let focusedComponentId {
            return TagFilter.focus(
                on: focusedComponentId,
                depth: tagFilter.neighbourDepth,
                in: model
            )
        }
        return tagFilter.narrow(model)
    }

    /// Lays the drawn set out on its own, and fits the result. Call this from
    /// a narrowing verb, never from `drawn(in:)`.
    ///
    /// With nothing narrowed the canvas draws the model's own coordinates and
    /// fits the whole diagram, which is what Zoom to Fit does.
    func layOutNarrowedSet() {
        guard let layouts else { return }
        let model = layouts.model

        guard isNarrowing else {
            narrowedComponentPositions = [:]
            narrowedZoneRects = [:]
            fit(
                components: model.components.map { ($0.x, $0.y) },
                zones: model.zones.map { ($0.x, $0.y, $0.width, $0.height) }
            )
            return
        }

        let set = narrowedSet(of: model)
        let laidOut = layouts.layOutSubset(
            componentIds: set.components.map(\.id),
            zoneIds: set.zones.map(\.id)
        )
        guard case .laidOut(let components, let zones) = laidOut else { return }

        narrowedComponentPositions = Dictionary(
            uniqueKeysWithValues: components.map { ($0.id, CGPoint(x: $0.x, y: $0.y)) }
        )
        narrowedZoneRects = Dictionary(
            uniqueKeysWithValues: zones.map {
                ($0.id, CGRect(x: $0.x, y: $0.y, width: $0.width, height: $0.height))
            }
        )
        fit(
            components: components.map { ($0.x, $0.y) },
            zones: zones.map { ($0.x, $0.y, $0.width, $0.height) }
        )
    }

    /// Lays the narrowed set out again after an edit. A canvas that narrows
    /// nothing keeps the transform the person set, so adding a component
    /// never moves the diagram under them.
    func layOutNarrowedSetAgain() {
        guard isNarrowing else { return }
        layOutNarrowedSet()
    }

    /// Moves the named components in the picture alone.
    ///
    /// A drag while a filter is on calls this. It writes the narrowed
    /// coordinates, calls no use case, and so moves nothing in the model. The
    /// move is dropped at the next filter change, because every layout run
    /// starts from the model's own coordinates.
    func moveNarrowed(componentIds: Set<String>, by shift: CGSize) {
        guard let layouts else { return }
        for component in drawn(in: layouts.model).components
        where componentIds.contains(component.id) {
            narrowedComponentPositions[component.id] = CGPoint(
                x: component.x + shift.width,
                y: component.y + shift.height
            )
        }
    }

    /// Fits a drawn set in the visible canvas. A component draws at
    /// `Component.size`, the way `CanvasGestures.zoomToFit` measures one.
    private func fit(
        components: [(x: Double, y: Double)],
        zones: [(x: Double, y: Double, width: Double, height: Double)]
    ) {
        ViewportGestures(viewport: self).fit(
            SelectionBounds.rect(
                components: components.map {
                    ($0.x, $0.y, Component.size.width, Component.size.height)
                },
                zones: zones
            )
        )
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
