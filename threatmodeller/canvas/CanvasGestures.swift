import AppKit
import SwiftUI
import ThreatModelKit

/// Every gesture the canvas installs, and what each one commits.
///
/// Split out of `CanvasView` so that view holds layout only. This type reads
/// the session and the canvas state and calls use cases through the session.
/// It draws nothing.
@MainActor
struct CanvasGestures: CanvasZooming {
    let session: ThreatModelSession
    let canvas: CanvasState

    /// The rules shared with the tree canvas: pan, marquee, scroll and zoom.
    private var viewport: ViewportGestures { ViewportGestures(viewport: canvas) }

    private var boxes: [String: ComponentBox] {
        CanvasHitTest.boxes(
            for: session.canvas.components,
            selected: canvas.selectedComponentIds,
            dragTranslation: canvas.dragTranslation ?? .zero
        )
    }

    /// The flows as the canvas draws them, so a click lands where the picture
    /// says it should.
    private var flows: FlowGeometry {
        FlowGeometry.of(
            connections: session.canvas.connections,
            boxes: boxes,
            componentsById: Dictionary(
                uniqueKeysWithValues: session.canvas.components.map { ($0.id, $0) }
            ),
            zones: session.canvas.zones,
            guards: session.elementGuards,
            risks: session.elementRisks,
            outOfScopeComponentIds: Set(
                session.canvas.components.filter(\.threatsDisabled).map(\.id)
            )
        )
    }

    // MARK: background

    var backgroundTap: some Gesture {
        SpatialTapGesture(coordinateSpace: .named("canvas")).onEnded { value in
            let point = canvas.transform.modelPoint(value.location)
            // The flows are hit tested against the curves the canvas drew,
            // and a callout counts as part of its own flow.
            if let connectionId = flows.connection(
                under: point,
                within: ConnectionPath.hitTolerance / canvas.transform.zoom
            ) {
                canvas.select(connectionId: connectionId, addingToSelection: false)
            } else if let zoneId = CanvasHitTest.zone(under: point, zones: session.canvas.zones) {
                canvas.select(zoneId: zoneId, addingToSelection: false)
            } else {
                canvas.clearSelection()
            }
        }
    }

    /// A double-click on a flow edits its label where the flow is.
    var backgroundDoubleTap: some Gesture {
        SpatialTapGesture(count: 2, coordinateSpace: .named("canvas")).onEnded { value in
            let point = canvas.transform.modelPoint(value.location)
            guard let connectionId = flows.connection(
                under: point,
                within: ConnectionPath.hitTolerance / canvas.transform.zoom
            ) else { return }

            canvas.select(connectionId: connectionId, addingToSelection: false)
            canvas.startEditingName(.connection(connectionId))
        }
    }

    /// The flow under a point in model coordinates, hit tested against the
    /// curves the canvas drew, or nil. A secondary click reads it, the way a
    /// plain click does.
    func connection(under point: CGPoint) -> String? {
        flows.connection(
            under: point,
            within: ConnectionPath.hitTolerance / canvas.transform.zoom
        )
    }

    /// Where a flow's label sits, so the field opens on the flow rather than
    /// at the pointer.
    func calloutRect(of connectionId: String) -> CGRect? {
        let geometry = flows
        if let callout = geometry.callouts.first(where: { $0.connectionId == connectionId }) {
            return CGRect(callout.rect)
        }
        // A flow with no label yet has no callout, so the field opens at the
        // middle of the curve.
        guard let curve = geometry.curves[connectionId] else { return nil }
        let middle = curve.point(at: 0.5)
        return CGRect(x: middle.x - 90, y: middle.y - 12, width: 180, height: 24)
    }

    var backgroundDrag: some Gesture {
        // A plain drag on the background moves the diagram, which is what a
        // person reaching for a canvas expects. Shift-drag draws the marquee:
        // there is nothing on empty canvas for a shift to extend, so the key
        // is free here even though shift-click extends a selection on a node.
        // A drag while the zone tool is on draws the zone, and never pans.
        //
        // One gesture, not a shift-gated one `exclusively(before:)` another:
        // a modifier-gated drag that never failed left the pan gesture
        // waiting for it, and a plain drag then moved nothing at all. This
        // reads the key itself, at the moment of the change.
        DragGesture(minimumDistance: 2, coordinateSpace: .named("canvas"))
            .onChanged { value in
                backgroundDragChanged(
                    from: value.startLocation,
                    to: value.location,
                    by: value.translation,
                    isShiftDown: NSEvent.modifierFlags.contains(.shift)
                )
            }
            .onEnded { _ in backgroundDragEnded() }
    }

    /// A drag on the background: the marquee while Shift is down or the zone
    /// tool is on, and the pan otherwise. Internal so a test can walk the
    /// drag without SwiftUI's gesture plumbing.
    func backgroundDragChanged(
        from start: CGPoint,
        to end: CGPoint,
        by translation: CGSize,
        isShiftDown: Bool
    ) {
        guard isShiftDown == false else {
            return marqueeDragChanged(from: start, to: end)
        }
        panDragChanged(from: start, to: end, by: translation)
    }

    /// A shift-drag on the background. Internal so a test can walk the drag
    /// without SwiftUI's gesture plumbing.
    func marqueeDragChanged(from start: CGPoint, to end: CGPoint) {
        guard canvas.isDrawingZone else {
            return viewport.marqueeDragChanged(from: start, to: end)
        }
        canvas.zoneDraft = (
            start: canvas.transform.modelPoint(start),
            end: canvas.transform.modelPoint(end)
        )
    }

    /// A plain drag on the background. A drag reports the translation from
    /// where it started, so the pan applies the step since the last change,
    /// not the whole translation again.
    func panDragChanged(from start: CGPoint, to end: CGPoint, by translation: CGSize) {
        guard canvas.isDrawingZone == false else {
            return marqueeDragChanged(from: start, to: end)
        }
        viewport.panDragChanged(by: translation)
    }

    /// The end of either background drag.
    func backgroundDragEnded() {
        canvas.lastPanTranslation = .zero
        canvas.isPanning = false
        if canvas.isDrawingZone {
            commitDraftZone()
        } else if canvas.marquee != nil {
            endMarqueeDrag()
        }
    }

    /// A two finger scroll moves the diagram, by the same transform a drag
    /// moves it by.
    ///
    /// macOS states a scrolling delta that already answers the person's own
    /// natural-scrolling setting, so the delta is applied as it arrives.
    /// Negating it a second time moved the diagram the wrong way.
    func scroll(by delta: CGSize) {
        viewport.scroll(by: delta)
    }

    /// Ends a zone drag. Internal so a test can walk the drag without
    /// SwiftUI's gesture plumbing.
    func commitDraftZone() {
        let rect = canvas.zoneDraftRect
        canvas.stopDrawingZone()
        guard let rect else { return }
        if let zoneId = session.addZone(
            x: rect.minX,
            y: rect.minY,
            width: rect.width,
            height: rect.height
        ) {
            canvas.select(zoneId: zoneId)
        }
    }

    /// Ends a marquee drag. Internal so a test can walk the drag without
    /// SwiftUI's gesture plumbing.
    func endMarqueeDrag() {
        if let rect = canvas.marqueeRect {
            canvas.select(
                componentIds: MarqueeSelection.selected(
                    in: rect,
                    from: session.canvas.components.map {
                        (id: $0.id, box: ComponentBox(x: $0.x, y: $0.y))
                    }
                ),
                zoneIds: MarqueeSelection.selectedZones(
                    in: rect,
                    from: session.canvas.zones.map {
                        (id: $0.id, rect: CGRect(x: $0.x, y: $0.y, width: $0.width, height: $0.height))
                    }
                )
            )
        }
        canvas.marquee = nil
    }

    // MARK: nodes

    func selectComponent(_ componentId: String, addingToSelection: Bool) {
        canvas.select(componentId: componentId, addingToSelection: addingToSelection)
    }

    func nodeDragChanged(_ componentId: String, _ translation: CGSize) {
        if canvas.isSelected(componentId: componentId) == false {
            canvas.select(componentId: componentId, addingToSelection: false)
        }
        canvas.dragTranslation = canvas.transform.modelDistance(translation)
    }

    func nodeDragEnded(_ translation: CGSize) {
        let shift = canvas.transform.modelDistance(translation)
        let moves = session.canvas.components
            .filter { canvas.isSelected(componentId: $0.id) }
            .map {
                ComponentMove(
                    componentId: $0.id,
                    x: $0.x + shift.width,
                    y: $0.y + shift.height
                )
            }
        canvas.dragTranslation = nil
        guard moves.isEmpty == false else { return }
        session.move(moves)
    }

    func anchorDragChanged(_ componentId: String, _ location: CGPoint) {
        canvas.connectionDrag = (
            sourceComponentId: componentId,
            currentPoint: canvas.transform.modelPoint(location)
        )
    }

    func anchorDragEnded(_ componentId: String, _ location: CGPoint) {
        canvas.connectionDrag = nil
        let point = canvas.transform.modelPoint(location)
        guard let targetId = CanvasHitTest.component(
            under: point,
            components: session.canvas.components
        ) else { return }
        session.connect(sourceComponentId: componentId, targetComponentId: targetId)
    }

    // MARK: zones

    func zoneDragChanged(_ zoneId: String, handle: ZoneHandle?, translation: CGSize) {
        // A drag on a zone already in the selection moves the whole selection.
        // A drag on any other zone selects that one first.
        if canvas.isSelected(zoneId: zoneId) == false {
            canvas.select(zoneId: zoneId, addingToSelection: false)
        }
        canvas.zoneDrag = (
            zoneId: zoneId,
            handle: handle,
            translation: canvas.transform.modelDistance(translation)
        )
    }

    func zoneDragEnded(_ zoneId: String, handle: ZoneHandle?, translation: CGSize) {
        defer { canvas.zoneDrag = nil }

        // Only commit a move the user actually made. A gesture that ends on a
        // zone without ever having reported a change — the release of the drag
        // that drew it, for one — would otherwise move it the moment it
        // appeared.
        guard canvas.zoneDrag?.zoneId == zoneId else { return }
        guard let zone = session.canvas.zones.first(where: { $0.id == zoneId }) else { return }
        let shift = canvas.transform.modelDistance(translation)

        // A drag on a header moves every selected zone, as one change. A drag
        // on a grip resizes the one zone the grip belongs to.
        let moving = session.canvas.zones.filter { canvas.isSelected(zoneId: $0.id) }
        if handle == nil && moving.count > 1 {
            session.moveZones(
                moving.map {
                    ZoneMove(zoneId: $0.id, x: $0.x + shift.width, y: $0.y + shift.height)
                }
            )
            return
        }

        let rect = CanvasHitTest.rect(
            for: zone,
            drag: (zoneId: zoneId, handle: handle, translation: shift)
        )
        session.resizeZone(
            zoneId,
            x: rect.minX,
            y: rect.minY,
            width: rect.width,
            height: rect.height
        )
    }

    /// Puts the selected zones at the front or at the back of the drawing
    /// order. With no zone selected it changes nothing.
    func reorderSelectedZones(_ placement: ZonePlacement) {
        let zoneIds = session.canvas.zones
            .filter { canvas.isSelected(zoneId: $0.id) }
            .map(\.id)
        guard zoneIds.isEmpty == false else { return }
        session.reorderZones(zoneIds, placement: placement)
    }

    // MARK: commands

    /// Spec section 9: an arrow moves the selection 10 points, and shift-arrow
    /// moves it 1. The small step is for lining things up; the large one is for
    /// getting somewhere.
    static let nudgeStep = 10.0
    static let fineNudgeStep = 1.0

    // MARK: names edited in place

    /// Writes a node's new name, as one change. An empty name clears the
    /// custom name, which puts the technology's own name back.
    func renameComponent(_ componentId: String, to name: String) {
        canvas.stopEditingName()
        guard let component = session.canvas.components.first(where: { $0.id == componentId }) else {
            return
        }
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed != (component.customName ?? "") else { return }

        session.setComponentProperties(
            componentId: componentId,
            name: trimmed.isEmpty ? nil : trimmed,
            sensitivityId: component.sensitivityId,
            threatsDisabled: component.threatsDisabled,
            runsAsId: component.runsAsId,
            shapeId: nil
        )
    }

    func renameZone(_ zoneId: String, to name: String) {
        canvas.stopEditingName()
        guard let zone = session.canvas.zones.first(where: { $0.id == zoneId }) else { return }
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed != (zone.customName ?? "") else { return }

        session.setZoneProperties(
            zoneId: zoneId,
            name: trimmed.isEmpty ? nil : trimmed,
            networkZoneId: zone.networkZoneId,
            networkTypeId: zone.networkTypeId,
            riskReductionEnabled: zone.riskReductionEnabled,
            riskReductionPercent: zone.riskReductionPercent,
            boundaryId: zone.boundaryId
        )
    }

    /// Writes a flow's label, which is the description the connection panel
    /// edits: one field, one value.
    func labelConnection(_ connectionId: String, to label: String) {
        canvas.stopEditingName()
        session.labelConnection(connectionId: connectionId, label: label)
    }

    func nudge(dx: Double, dy: Double) {
        let moves = session.canvas.components
            .filter { canvas.isSelected(componentId: $0.id) }
            .map { ComponentMove(componentId: $0.id, x: $0.x + dx, y: $0.y + dy) }
        guard moves.isEmpty == false else { return }
        session.move(moves)
    }

    func deleteSelection() {
        for connectionId in canvas.selectedConnectionIds {
            session.removeConnection(connectionId)
        }
        for zoneId in canvas.selectedZoneIds {
            session.removeZone(zoneId)
        }
        if canvas.selectedComponentIds.isEmpty == false {
            session.removeComponents(Array(canvas.selectedComponentIds))
        }
        canvas.retainOnly(
            componentIds: Set(session.canvas.components.map(\.id)),
            connectionIds: Set(session.canvas.connections.map(\.id)),
            zoneIds: Set(session.canvas.zones.map(\.id))
        )
    }

    func zoom(by factor: CGFloat, about viewPoint: CGPoint) {
        viewport.zoom(by: factor, about: viewPoint)
    }

    /// One press of Zoom In or Zoom Out. The point under the middle of the
    /// visible canvas stays where it is.
    func zoomAStep(in closer: Bool) {
        viewport.zoomAStep(in: closer)
    }

    func zoomToActualSize() {
        viewport.zoomToActualSize()
    }

    /// Fits the whole diagram in the visible canvas.
    ///
    /// It fits what the model draws, not `CanvasHitTest.contentRect`: that
    /// rectangle is the drawing layer, which keeps a thousand points of room
    /// past the farthest element so a node can always be dragged further out.
    /// Fitting it would show mostly empty canvas.
    func zoomToFit() {
        viewport.fit(SelectionBounds.rect(
            components: session.canvas.components.map {
                ($0.x, $0.y, Component.size.width, Component.size.height)
            },
            zones: session.canvas.zones.map { ($0.x, $0.y, $0.width, $0.height) }
        ))
    }

    /// Fits what is selected in the visible canvas. With nothing selected it
    /// changes nothing.
    func zoomToSelection() {
        let components = session.canvas.components.filter { canvas.isSelected(componentId: $0.id) }
        let zones = session.canvas.zones.filter { canvas.isSelected(zoneId: $0.id) }
        viewport.fit(SelectionBounds.rect(
            components: components.map {
                ($0.x, $0.y, Component.size.width, Component.size.height)
            },
            zones: zones.map { ($0.x, $0.y, $0.width, $0.height) }
        ))
    }
}
