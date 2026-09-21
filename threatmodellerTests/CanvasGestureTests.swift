import CoreGraphics
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The six gestures the canvas installs, each driven the way SwiftUI drives
/// it: through the closures the gesture calls.
///
/// SwiftUI does not deliver a synthetic `NSEvent` to a gesture, so nothing
/// short of macOS Automation Mode presses the mouse. `docs/TESTING.md` states
/// that and states this suite as what covers the gestures instead. Every test
/// here calls exactly what the gesture's `onChanged` and `onEnded` call, with
/// the numbers SwiftUI reports.
@MainActor
@Suite("Driving the canvas gestures")
struct CanvasGestureTests {
    private func drawn() -> (ThreatModelSession, CanvasState, CanvasGestures) {
        let session = ThreatModelSession(useCases: TestDependencies())
        let canvas = CanvasState()
        return (session, canvas, CanvasGestures(session: session, canvas: canvas))
    }

    private func twoNodes() -> (ThreatModelSession, CanvasState, CanvasGestures, String, String) {
        let (session, canvas, gestures) = drawn()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        let ids = session.canvas.components.map(\.id)
        return (session, canvas, gestures, ids[0], ids[1])
    }

    // MARK: node drag

    @Test func aNodeDragMovesTheNodeItStartedOn() {
        let (session, _, gestures, api, _) = twoNodes()

        gestures.nodeDragChanged(api, CGSize(width: 60, height: 40))
        gestures.nodeDragEnded(CGSize(width: 60, height: 40))

        let moved = session.canvas.components.first { $0.id == api }
        #expect(moved?.x == 60)
        #expect(moved?.y == 40)
    }

    @Test func aNodeDragMovesEveryNodeInTheSelection() {
        let (session, canvas, gestures, api, db) = twoNodes()
        canvas.select(componentId: api, addingToSelection: false)
        canvas.select(componentId: db, addingToSelection: true)

        gestures.nodeDragChanged(api, CGSize(width: 25, height: 0))
        gestures.nodeDragEnded(CGSize(width: 25, height: 0))

        let moved = Dictionary(uniqueKeysWithValues: session.canvas.components.map { ($0.id, $0) })
        #expect(moved[api]?.x == 25)
        #expect(moved[db]?.x == 425)
    }

    @Test func oneUndoTakesBackAWholeNodeDrag() {
        let (session, _, gestures, api, _) = twoNodes()

        gestures.nodeDragChanged(api, CGSize(width: 60, height: 40))
        gestures.nodeDragEnded(CGSize(width: 60, height: 40))
        session.undo()

        let back = session.canvas.components.first { $0.id == api }
        #expect(back?.x == 0)
        #expect(back?.y == 0)
    }

    /// A drag at a zoom other than 1 moves the node by the model distance, not
    /// by the view distance.
    @Test func aNodeDragAtHalfZoomMovesTwiceTheViewDistance() {
        let (session, canvas, gestures, api, _) = twoNodes()
        canvas.transform = CanvasTransform(zoom: 0.5)

        gestures.nodeDragChanged(api, CGSize(width: 50, height: 0))
        gestures.nodeDragEnded(CGSize(width: 50, height: 0))

        #expect(session.canvas.components.first { $0.id == api }?.x == 100)
    }

    // MARK: marquee

    @Test func aMarqueeSelectsEveryNodeItTouches() {
        let (_, canvas, gestures, api, db) = twoNodes()

        canvas.marquee = (start: CGPoint(x: -20, y: -20), end: CGPoint(x: 700, y: 200))
        gestures.endMarqueeDrag()

        #expect(canvas.selectedComponentIds == [api, db])
        #expect(canvas.marqueeRect == nil)
    }

    @Test func aMarqueeSelectsNothingWhenItTouchesNothing() {
        let (_, canvas, gestures, _, _) = twoNodes()

        canvas.marquee = (start: CGPoint(x: 900, y: 900), end: CGPoint(x: 1000, y: 1000))
        gestures.endMarqueeDrag()

        #expect(canvas.selectedComponentIds.isEmpty)
    }

    // MARK: drawing a connection

    @Test func anAnchorDragToASecondNodeDrawsAFlow() {
        let (session, canvas, gestures, api, db) = twoNodes()

        gestures.anchorDragChanged(api, CGPoint(x: 200, y: 20))
        #expect(canvas.connectionDrag?.sourceComponentId == api)
        gestures.anchorDragEnded(api, CGPoint(x: 460, y: 36))

        #expect(canvas.connectionDrag == nil)
        let flow = session.canvas.connections.first
        #expect(flow?.sourceComponentId == api)
        #expect(flow?.targetComponentId == db)
    }

    @Test func anAnchorDragEndingOnNothingDrawsNoFlow() {
        let (session, canvas, gestures, api, _) = twoNodes()

        gestures.anchorDragChanged(api, CGPoint(x: 200, y: 20))
        gestures.anchorDragEnded(api, CGPoint(x: 2000, y: 2000))

        #expect(session.canvas.connections.isEmpty)
        #expect(canvas.connectionDrag == nil)
    }

    @Test func oneUndoTakesBackADrawnFlow() {
        let (session, _, gestures, api, _) = twoNodes()
        gestures.anchorDragChanged(api, CGPoint(x: 200, y: 20))
        gestures.anchorDragEnded(api, CGPoint(x: 460, y: 36))

        session.undo()

        #expect(session.canvas.connections.isEmpty)
    }

    // MARK: clicking a mitigates mark

    /// Two nodes and the edge that states the first lowers a threat on the
    /// second.
    private func twoNodesAndAnEdge(
        status: String = "live"
    ) -> (ThreatModelSession, CanvasState, CanvasGestures, String, String) {
        let (session, canvas, gestures, api, db) = twoNodes()
        session.setMitigatesEdge(
            from: api,
            to: db,
            status: status
        )
        return (session, canvas, gestures, api, db)
    }

    /// The middle of the mark, in model coordinates, which is where a click
    /// has to land.
    private func markApex(_ session: ThreatModelSession) -> CGPoint? {
        MitigatesGeometry.of(
            mitigations: session.canvas.mitigations,
            boxes: CanvasHitTest.boxes(
                for: session.canvas.components,
                selected: [],
                dragTranslation: .zero
            )
        ).marks.first?.apex
    }

    /// A click on the mark selects both ends of the edge. Two selected
    /// components is what the canvas shows the mitigates bar for, so the
    /// click opens the bar that names the edge.
    @Test func aClickOnAMitigatesMarkSelectsBothItsComponents() throws {
        let (session, canvas, gestures, api, db) = twoNodesAndAnEdge()
        let apex = try #require(markApex(session))

        gestures.backgroundTapped(at: apex)

        #expect(canvas.selectedComponentIds == [api, db])
        #expect(canvas.selectedConnectionIds.isEmpty)
    }

    @Test func aClickAwayFromEveryMarkSelectsNothing() throws {
        let (session, canvas, gestures, _, _) = twoNodesAndAnEdge()
        let apex = try #require(markApex(session))

        gestures.backgroundTapped(at: CGPoint(x: apex.x, y: apex.y + 400))

        #expect(canvas.selectedComponentIds.isEmpty)
    }

    /// The edge is removed, and the mark goes with it. A click where the mark
    /// was then selects nothing.
    @Test func aClickWhereARemovedMarkWasSelectsNothing() throws {
        let (session, canvas, gestures, api, db) = twoNodesAndAnEdge()
        let apex = try #require(markApex(session))

        session.removeMitigatesEdge(from: api, to: db)
        gestures.backgroundTapped(at: apex)

        #expect(session.canvas.mitigations.isEmpty)
        #expect(markApex(session) == nil)
        #expect(canvas.selectedComponentIds.isEmpty)
    }

    /// A flow is read before a mark, so a flow keeps every click it had.
    @Test func aClickOnAFlowStillSelectsTheFlow() throws {
        let (session, canvas, gestures, api, db) = twoNodesAndAnEdge()
        session.connect(sourceComponentId: api, targetComponentId: db)
        let flowId = try #require(session.canvas.connections.first?.id)
        let flows = FlowGeometry.of(
            connections: session.canvas.connections,
            boxes: CanvasHitTest.boxes(
                for: session.canvas.components,
                selected: [],
                dragTranslation: .zero
            ),
            componentsById: Dictionary(
                uniqueKeysWithValues: session.canvas.components.map { ($0.id, $0) }
            ),
            zones: [],
            guards: [:],
            risks: [:],
            outOfScopeComponentIds: []
        )
        let curve = try #require(flows.curves[flowId])

        gestures.backgroundTapped(at: CGPoint(curve.point(at: 0.5)))

        #expect(canvas.selectedConnectionIds == [flowId])
    }

    // MARK: zone move and zone resize

    @Test func aZoneHeaderDragMovesTheZone() throws {
        let (session, _, gestures) = drawn()
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 400, height: 300))

        gestures.zoneDragChanged(zoneId, handle: nil, translation: CGSize(width: 40, height: 25))
        gestures.zoneDragEnded(zoneId, handle: nil, translation: CGSize(width: 40, height: 25))

        let zone = try #require(session.canvas.zones.first)
        #expect(zone.x == 40)
        #expect(zone.y == 25)
        #expect(zone.width == 400)
        #expect(zone.height == 300)
    }

    @Test func aGripDragResizesTheZoneAndLeavesTheOthers() throws {
        let (session, _, gestures) = drawn()
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 400, height: 300))
        _ = session.addZone(x: 500, y: 0, width: 400, height: 300)

        gestures.zoneDragChanged(
            zoneId,
            handle: .bottomRight,
            translation: CGSize(width: 60, height: 40)
        )
        gestures.zoneDragEnded(
            zoneId,
            handle: .bottomRight,
            translation: CGSize(width: 60, height: 40)
        )

        let resized = try #require(session.canvas.zones.first { $0.id == zoneId })
        #expect(resized.width == 460)
        #expect(resized.height == 340)
        let other = try #require(session.canvas.zones.last)
        #expect(other.width == 400)
    }

    @Test func oneUndoTakesBackAZoneResize() throws {
        let (session, _, gestures) = drawn()
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 400, height: 300))
        gestures.zoneDragChanged(
            zoneId,
            handle: .bottomRight,
            translation: CGSize(width: 60, height: 40)
        )
        gestures.zoneDragEnded(
            zoneId,
            handle: .bottomRight,
            translation: CGSize(width: 60, height: 40)
        )

        session.undo()

        let zone = try #require(session.canvas.zones.first)
        #expect(zone.width == 400)
        #expect(zone.height == 300)
    }

    /// A gesture that ends on a zone without ever reporting a change moves
    /// nothing. The release of the drag that drew the zone is one such.
    @Test func aZoneDragThatReportedNoChangeMovesNothing() throws {
        let (session, _, gestures) = drawn()
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 400, height: 300))

        gestures.zoneDragEnded(zoneId, handle: nil, translation: CGSize(width: 40, height: 25))

        let zone = try #require(session.canvas.zones.first)
        #expect(zone.x == 0)
        #expect(zone.y == 0)
    }

    // MARK: the background drag

    @Test func aPlainDragOnTheBackgroundMovesTheDiagram() {
        let (_, canvas, gestures) = drawn()

        gestures.panDragChanged(
            from: CGPoint(x: 100, y: 100),
            to: CGPoint(x: 140, y: 130),
            by: CGSize(width: 40, height: 30)
        )

        #expect(canvas.transform.pan == CGSize(width: 40, height: 30))
        #expect(canvas.marquee == nil)
        #expect(canvas.isPanning)
    }

    /// A drag reports the whole translation each time, so the pan applies the
    /// step since the last change and never the whole translation twice.
    @Test func aPlainDragAppliesEachStepOnce() {
        let (_, canvas, gestures) = drawn()

        gestures.panDragChanged(
            from: CGPoint(x: 100, y: 100),
            to: CGPoint(x: 120, y: 100),
            by: CGSize(width: 20, height: 0)
        )
        gestures.panDragChanged(
            from: CGPoint(x: 100, y: 100),
            to: CGPoint(x: 150, y: 100),
            by: CGSize(width: 50, height: 0)
        )

        #expect(canvas.transform.pan == CGSize(width: 50, height: 0))
    }

    @Test func theEndOfAPlainDragStopsThePan() {
        let (_, canvas, gestures) = drawn()
        gestures.panDragChanged(
            from: .zero,
            to: CGPoint(x: 10, y: 10),
            by: CGSize(width: 10, height: 10)
        )

        gestures.backgroundDragEnded()

        #expect(canvas.isPanning == false)
        #expect(canvas.lastPanTranslation == .zero)
    }

    @Test func aShiftDragOnTheBackgroundDrawsTheMarqueeAndMovesNothing() {
        let (_, canvas, gestures, api, _) = twoNodes()

        gestures.marqueeDragChanged(from: CGPoint(x: -20, y: -20), to: CGPoint(x: 300, y: 200))
        #expect(canvas.marqueeRect != nil)
        #expect(canvas.transform == CanvasTransform())
        gestures.backgroundDragEnded()

        #expect(canvas.selectedComponentIds == [api])
        #expect(canvas.transform == CanvasTransform())
    }

    @Test func aDragWhileDrawingAZoneDrawsTheZoneAndMovesNothing() {
        let (session, canvas, gestures) = drawn()
        canvas.startDrawingZone()

        gestures.panDragChanged(
            from: CGPoint(x: 0, y: 0),
            to: CGPoint(x: 400, y: 300),
            by: CGSize(width: 400, height: 300)
        )

        #expect(canvas.zoneDraftRect == CGRect(x: 0, y: 0, width: 400, height: 300))
        #expect(canvas.transform == CanvasTransform())
        #expect(canvas.isPanning == false)

        gestures.backgroundDragEnded()

        #expect(session.canvas.zones.count == 1)
        #expect(canvas.isDrawingZone == false)
    }

    /// macOS states a delta that already answers the person's own
    /// natural-scrolling setting, so the diagram moves the way the delta
    /// states. It used to move the other way.
    @Test func aTwoFingerScrollMovesTheDiagramTheWayTheDeltaStates() {
        let (_, canvas, gestures) = drawn()

        gestures.scroll(by: CGSize(width: 30, height: -20))

        #expect(canvas.transform.pan == CGSize(width: 30, height: -20))
    }

    /// A plain drag on the background pans. It stopped panning when the
    /// marquee gesture was gated on Shift and never failed.
    @Test func aPlainDragOnTheBackgroundPansTheDiagram() {
        let (_, canvas, gestures) = drawn()

        gestures.backgroundDragChanged(
            from: CGPoint(x: 100, y: 100),
            to: CGPoint(x: 140, y: 130),
            by: CGSize(width: 40, height: 30),
            isShiftDown: false
        )

        #expect(canvas.transform.pan == CGSize(width: 40, height: 30))
        #expect(canvas.isPanning)
        #expect(canvas.marquee == nil)

        gestures.backgroundDragEnded()
        #expect(canvas.isPanning == false)
    }

    /// A shift-drag draws the marquee and moves the diagram not at all.
    @Test func aShiftDragOnTheBackgroundDrawsTheMarquee() {
        let (_, canvas, gestures) = drawn()

        gestures.backgroundDragChanged(
            from: CGPoint(x: 100, y: 100),
            to: CGPoint(x: 140, y: 130),
            by: CGSize(width: 40, height: 30),
            isShiftDown: true
        )

        #expect(canvas.marquee != nil)
        #expect(canvas.transform.pan == .zero)
        #expect(canvas.isPanning == false)
    }

    /// A drag while the zone tool is on draws the zone, whatever the keys
    /// say, and never pans.
    @Test func aDragWhileTheZoneToolIsOnDrawsTheZone() {
        let (_, canvas, gestures) = drawn()
        canvas.startDrawingZone()

        gestures.backgroundDragChanged(
            from: CGPoint(x: 10, y: 10),
            to: CGPoint(x: 210, y: 130),
            by: CGSize(width: 200, height: 120),
            isShiftDown: false
        )

        #expect(canvas.zoneDraft != nil)
        #expect(canvas.transform.pan == .zero)
    }

    @Test func aTwoFingerScrollKeepsTheZoom() {
        let (_, canvas, gestures) = drawn()
        canvas.transform = CanvasTransform(zoom: 2)

        gestures.scroll(by: CGSize(width: 10, height: 10))

        #expect(canvas.transform.zoom == 2)
    }

    // MARK: a technology dropped from the palette

    /// A palette row carries the technology id as its payload. The canvas
    /// hands that payload and the drop point to the gestures, and this drives
    /// the same call the drop makes.
    @Test func aDropPlacesOneComponentOfThatTechnology() {
        let (session, _, gestures) = drawn()

        let placed = gestures.drop(["aws-rds"], at: CGPoint(x: 300, y: 200))

        #expect(placed)
        #expect(session.canvas.components.count == 1)
        #expect(session.canvas.components.first?.technologyId == "aws-rds")
    }

    /// The point the person let go is the middle of the node.
    @Test func aDropPlacesTheNodeAroundThePointItLandsOn() throws {
        let (session, _, gestures) = drawn()

        gestures.drop(["aws-ec2"], at: CGPoint(x: 300, y: 200))

        let node = try #require(session.canvas.components.first)
        #expect(node.x == 300 - Component.size.width / 2)
        #expect(node.y == 200 - Component.size.height / 2)
    }

    /// The drop point arrives in view points. A panned and zoomed canvas
    /// places the node where the pointer was, not where the raw number reads.
    @Test func aDropOnAPannedAndZoomedCanvasPlacesTheNodeUnderThePointer() throws {
        let (session, canvas, gestures) = drawn()
        canvas.transform = CanvasTransform(pan: CGSize(width: -900, height: -700), zoom: 0.5)

        gestures.drop(["aws-ec2"], at: CGPoint(x: 1240, y: 868))

        let node = try #require(session.canvas.components.first)
        #expect(node.x == 4280 - Component.size.width / 2)
        #expect(node.y == 3136 - Component.size.height / 2)
    }

    /// A drop inside a zone rectangle puts the component in that zone.
    @Test func aDropInsideAZonePlacesTheComponentInThatZone() throws {
        let (session, _, gestures) = drawn()
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 600, height: 400))

        gestures.drop(["aws-ec2"], at: CGPoint(x: 300, y: 200))

        #expect(session.canvas.components.first?.zoneId == zoneId)
    }

    /// A drop outside every zone leaves the component loose.
    @Test func aDropOutsideEveryZoneLeavesTheComponentLoose() throws {
        let (session, _, gestures) = drawn()
        _ = session.addZone(x: 0, y: 0, width: 200, height: 150)

        gestures.drop(["aws-ec2"], at: CGPoint(x: 900, y: 700))

        #expect(session.canvas.components.first?.zoneId == nil)
    }

    /// A drop that carries nothing places nothing.
    @Test func aDropThatCarriesNothingPlacesNothing() {
        let (session, _, gestures) = drawn()

        let placed = gestures.drop([], at: CGPoint(x: 300, y: 200))

        #expect(placed == false)
        #expect(session.canvas.components.isEmpty)
    }

    /// A payload the catalogue does not hold places nothing, and the drop
    /// states it took nothing.
    @Test func aDropOfATechnologyTheCatalogueDoesNotHoldPlacesNothing() {
        let (session, _, gestures) = drawn()

        let placed = gestures.drop(["not-a-technology"], at: CGPoint(x: 300, y: 200))

        #expect(placed == false)
        #expect(session.canvas.components.isEmpty)
        #expect(session.errorMessage == "That technology is not in the catalogue.")
    }

    /// A double-click on a palette row places at the default point, which is
    /// the other way to place a technology and stays as it was.
    @Test func aDoubleClickOnAPaletteRowPlacesAtTheDefaultPoint() throws {
        let (session, _, _) = drawn()

        session.addAtDefaultPoint(technologyId: "aws-ec2")

        let node = try #require(session.canvas.components.first)
        #expect(node.x == ThreatModelSession.defaultDropPoint.x)
        #expect(node.y == ThreatModelSession.defaultDropPoint.y)
    }

    // MARK: a node far from the origin

    /// Carry-forward item 27. A tap reports a point in view coordinates, the
    /// canvas turns it into a model point, and the hit test reads the same
    /// rectangle the canvas drew. This walks that chain for a node far from
    /// the origin, panned and zoomed, so a click lands where the node draws
    /// rather than where an untransformed rectangle would be.
    @Test func aNodeFarFromTheOriginIsFoundWhereItDraws() throws {
        let (session, canvas, _) = drawn()
        session.add(technologyId: "aws-ec2", x: 4200, y: 3100)
        let node = try #require(session.canvas.components.first)
        canvas.transform = CanvasTransform(pan: CGSize(width: -900, height: -700), zoom: 0.5)

        // Where the canvas draws the middle of that node.
        let middle = CanvasHitTest.box(for: node).centre
        let drawnAt = canvas.transform.viewPoint(middle)

        let found = CanvasHitTest.component(
            under: canvas.transform.modelPoint(drawnAt),
            components: session.canvas.components
        )

        #expect(drawnAt == CGPoint(x: 1240, y: 868))
        #expect(found == node.id)
    }

    /// The same node, clicked one point outside the drawn rectangle, is not
    /// found: the frame the click reads is the frame the canvas draws, not a
    /// larger one.
    @Test func aClickPastTheDrawnEdgeOfAFarNodeFindsNothing() throws {
        let (session, canvas, _) = drawn()
        session.add(technologyId: "aws-ec2", x: 4200, y: 3100)
        let node = try #require(session.canvas.components.first)
        canvas.transform = CanvasTransform(pan: CGSize(width: -900, height: -700), zoom: 0.5)
        let box = CanvasHitTest.box(for: node)

        let pastTheEdge = canvas.transform.viewPoint(
            CGPoint(x: box.rect.maxX + 1, y: box.centre.y)
        )

        #expect(
            CanvasHitTest.component(
                under: canvas.transform.modelPoint(pastTheEdge),
                components: session.canvas.components
            ) == nil
        )
    }

    // MARK: the pointer mode

    /// Trackpad mode is what the canvas always did: the wheel delta pans.
    @Test func aWheelInTrackpadModePansTheDiagram() {
        let (_, canvas, gestures) = drawn()

        gestures.wheel(
            by: CGSize(width: 30, height: -20),
            at: CGPoint(x: 100, y: 100),
            isShiftDown: false,
            mode: .trackpad
        )

        #expect(canvas.transform.pan == CGSize(width: 30, height: -20))
    }

    /// Trackpad mode keeps the pinch, which is the only zoom a trackpad has.
    @Test func aPinchZoomsTheDiagram() {
        let (_, canvas, gestures) = drawn()

        gestures.zoom(by: 1.5, about: CGPoint(x: 200, y: 200))

        #expect(canvas.transform.zoom == 1.5)
    }

    /// Mouse mode reads the wheel as a zoom about the pointer, so the model
    /// point under the pointer stays under the pointer.
    @Test func aWheelInMouseModeZoomsTheDiagramAboutThePointer() {
        let (_, canvas, gestures) = drawn()
        let pointer = CGPoint(x: 300, y: 200)
        let under = canvas.transform.modelPoint(pointer)

        gestures.wheel(by: CGSize(width: 0, height: 20), at: pointer, isShiftDown: false, mode: .mouse)

        #expect(canvas.transform.zoom > 1)
        let after = canvas.transform.modelPoint(pointer)
        #expect(abs(after.x - under.x) < 0.0001)
        #expect(abs(after.y - under.y) < 0.0001)
    }

    @Test func aShiftWheelInMouseModePansTheDiagramSideways() {
        let (_, canvas, gestures) = drawn()

        gestures.wheel(by: CGSize(width: 0, height: 24), at: CGPoint(x: 300, y: 200), isShiftDown: true, mode: .mouse)

        #expect(canvas.transform.pan == CGSize(width: 24, height: 0))
        #expect(canvas.transform.zoom == 1)
    }

    /// `CanvasView`'s monitor is installed once and keeps running; the
    /// closure it calls reads `PointerModeBox.mode` at event time, not the
    /// mode the box held when the closure was made. A change to the box
    /// after it is made must still reach the next wheel.
    @Test func aWheelReadsThePointerModeABoxHoldsAfterItChanges() {
        let (_, canvas, gestures) = drawn()
        let pointerMode = PointerModeBox(.trackpad)

        pointerMode.mode = .mouse
        gestures.wheel(
            by: CGSize(width: 0, height: 20),
            at: CGPoint(x: 300, y: 200),
            isShiftDown: false,
            mode: pointerMode.mode
        )

        #expect(canvas.transform.zoom > 1)
        let panAfterTheZoom = canvas.transform.pan

        pointerMode.mode = .trackpad
        gestures.wheel(
            by: CGSize(width: 0, height: 20),
            at: CGPoint(x: 300, y: 200),
            isShiftDown: false,
            mode: pointerMode.mode
        )

        #expect(
            canvas.transform.pan
                == CGSize(width: panAfterTheZoom.width, height: panAfterTheZoom.height + 20)
        )
    }

    /// A middle-button drag pans, in either mode.
    @Test func aMiddleButtonDragPansTheDiagram() {
        let (_, canvas, gestures) = drawn()

        gestures.panStep(by: CGSize(width: 40, height: 25))

        #expect(canvas.transform.pan == CGSize(width: 40, height: 25))
        #expect(canvas.isPanning)

        gestures.panStepEnded()

        #expect(canvas.isPanning == false)
    }

    /// Space held down pans, even while Shift is down and even while the zone
    /// tool is on: it is the pan a mouse user reaches for.
    @Test func aSpaceDragPansTheDiagramWhileTheZoneToolIsOn() {
        let (_, canvas, gestures) = drawn()
        canvas.startDrawingZone()

        gestures.backgroundDragChanged(
            from: CGPoint(x: 10, y: 10),
            to: CGPoint(x: 110, y: 70),
            by: CGSize(width: 100, height: 60),
            isShiftDown: true,
            isSpaceDown: true
        )

        #expect(canvas.transform.pan == CGSize(width: 100, height: 60))
        #expect(canvas.zoneDraft == nil)
        #expect(canvas.marquee == nil)
    }

    // MARK: one drawn set (#151)

    /// Three components in a line, with Focus on the middle one at depth
    /// zero. The other two, and the flow between them, are hidden.
    private func threeNodesFocusedOnTheMiddleOne() -> (
        session: ThreatModelSession,
        canvas: CanvasState,
        gestures: CanvasGestures,
        hiddenIds: [String],
        shownId: String
    ) {
        let (session, canvas, gestures) = drawn()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        session.add(technologyId: "aws-ec2", x: 800, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[2])
        canvas.focus(componentId: ids[1])
        return (session, canvas, gestures, [ids[0], ids[2]], ids[1])
    }

    @Test func aTapOnAComponentFocusHidesSelectsNothing() {
        let (_, canvas, gestures, _, _) = threeNodesFocusedOnTheMiddleOne()

        // The first component's rectangle, at (0, 0); Focus hides it, and no
        // flow, mark or zone is there either.
        gestures.backgroundTapped(at: CGPoint(x: 40, y: 20))

        #expect(canvas.hasSelection == false)
    }

    @Test func aMarqueeOverTheWholeModelSelectsOnlyWhatFocusDraws() {
        let (_, canvas, gestures, _, shownId) = threeNodesFocusedOnTheMiddleOne()

        canvas.marquee = (start: CGPoint(x: -50, y: -50), end: CGPoint(x: 900, y: 200))
        gestures.endMarqueeDrag()

        #expect(canvas.selectedComponentIds == [shownId])
    }

    /// Before this fix, `CanvasGestures.drawn` read the tag filter alone, so
    /// a flow between two components Focus hides still counted for a
    /// right-click's flow-or-background choice.
    @Test func aRightClickFindsNoFlowWhereFocusHidesBothEnds() {
        let (_, _, gestures, _, _) = threeNodesFocusedOnTheMiddleOne()

        #expect(gestures.drawn.components.count == 1)
        #expect(gestures.drawn.connections.isEmpty)
    }

    @Test func theDrawnSetTheGesturesReadEqualsTheDrawnSetTheViewDrawsWithATagFilterOn() {
        let (session, canvas, gestures) = drawn()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        canvas.pick(tag: "payments")
        let view = CanvasView(session: session, canvas: canvas)

        #expect(gestures.drawn.components.map(\.id) == view.drawn.components.map(\.id))
        #expect(gestures.drawn.connections.map(\.id) == view.drawn.connections.map(\.id))
        #expect(gestures.drawn.zones.map(\.id) == view.drawn.zones.map(\.id))
    }

    @Test func theDrawnSetTheGesturesReadEqualsTheDrawnSetTheViewDrawsWithFocusOn() {
        let (session, canvas, gestures, _, _) = threeNodesFocusedOnTheMiddleOne()
        let view = CanvasView(session: session, canvas: canvas)

        #expect(gestures.drawn.components.map(\.id) == view.drawn.components.map(\.id))
        #expect(gestures.drawn.connections.map(\.id) == view.drawn.connections.map(\.id))
        #expect(gestures.drawn.zones.map(\.id) == view.drawn.zones.map(\.id))
    }

    /// `CanvasState.drawn(in:)` is the one function that applies Focus and
    /// then the tag filter. No other file under `threatmodeller/canvas`
    /// computes the drawn set a second time.
    @Test func onlyCanvasStateComputesTheDrawnSet() throws {
        let canvasDirectory = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("threatmodeller/canvas")

        let files = try FileManager.default.contentsOfDirectory(
            at: canvasDirectory,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "swift" && $0.lastPathComponent != "CanvasState.swift" }

        for file in files {
            let text = try String(contentsOf: file, encoding: .utf8)
            #expect(
                text.contains("tagFilter.narrow(") == false,
                "\(file.lastPathComponent) computes the drawn set itself"
            )
            #expect(
                text.contains("TagFilter.focus(") == false,
                "\(file.lastPathComponent) computes the drawn set itself"
            )
        }
    }

    // MARK: the arrow key nudge

    @Test func anArrowKeyMovesEverySelectedComponentTenPoints() {
        let (session, canvas, gestures, api, db) = twoNodes()
        canvas.select(componentId: api, addingToSelection: false)
        canvas.select(componentId: db, addingToSelection: true)

        gestures.nudge(dx: CanvasGestures.nudgeStep, dy: 0)

        let moved = Dictionary(uniqueKeysWithValues: session.canvas.components.map { ($0.id, $0) })
        #expect(moved[api]?.x == 10)
        #expect(moved[db]?.x == 410)
    }

    @Test func aShiftArrowMovesTheSelectionOnePoint() {
        let (session, canvas, gestures, api, _) = twoNodes()
        canvas.select(componentId: api, addingToSelection: false)

        gestures.nudge(dx: CanvasGestures.fineNudgeStep, dy: 0)

        #expect(session.canvas.components.first { $0.id == api }?.x == 1)
    }

    @Test func nudgeWithNothingSelectedWritesNothing() {
        let (session, _, gestures, _, _) = twoNodes()
        let revision = session.revision

        gestures.nudge(dx: CanvasGestures.nudgeStep, dy: 0)

        #expect(session.revision == revision)
    }

    @Test func oneArrowPressIsOneUndo() {
        let (session, canvas, gestures, api, db) = twoNodes()
        canvas.select(componentId: api, addingToSelection: false)
        canvas.select(componentId: db, addingToSelection: true)

        gestures.nudge(dx: CanvasGestures.nudgeStep, dy: 0)
        session.undo()

        let moved = Dictionary(uniqueKeysWithValues: session.canvas.components.map { ($0.id, $0) })
        #expect(moved[api]?.x == 0)
        #expect(moved[db]?.x == 400)
    }

    /// The comment at `CanvasGestures.swift:428` named the selection, and the
    /// code at line 480 moved only the components in it. A selected zone
    /// moves under an arrow key, the same as a selected component.
    @Test func anArrowKeyMovesASelectedZone() throws {
        let (session, canvas, gestures) = drawn()
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 400, height: 300))
        canvas.select(zoneId: zoneId, addingToSelection: false)

        gestures.nudge(dx: CanvasGestures.nudgeStep, dy: 0)

        let zone = try #require(session.canvas.zones.first)
        #expect(zone.x == 10)
    }

    // MARK: renaming a node in place

    @Test func anEmptyNamePutsTheTechnologysOwnNameBack() throws {
        let (session, _, gestures, api, _) = twoNodes()
        let technologyName = try #require(session.canvas.components.first { $0.id == api }).name

        gestures.renameComponent(api, to: "Web tier")
        gestures.renameComponent(api, to: "")

        let renamed = try #require(session.canvas.components.first { $0.id == api })
        #expect(renamed.name == technologyName)
        #expect(renamed.customName == nil)
    }

    // MARK: the flow label rectangle

    @Test func calloutRectGivesTheLabelsOwnRectangleForALabelledFlow() throws {
        let (session, _, gestures, api, db) = twoNodes()
        session.connect(sourceComponentId: api, targetComponentId: db)
        let flowId = try #require(session.canvas.connections.first?.id)
        session.labelConnection(connectionId: flowId, label: "the card number")

        let callout = try #require(gestures.flows.callouts.first { $0.connectionId == flowId })
        let rect = try #require(gestures.calloutRect(of: flowId))

        #expect(rect == CGRect(callout.rect))
    }

    /// A use link, the path from a user to a client it holds, draws a curve
    /// but carries no label: `FlowGeometry` never puts one in a callout.
    @Test func calloutRectCentresOnTheCurveMiddleForAUseLinkWithNoLabel() throws {
        let (session, _, gestures) = drawn()
        session.addUser(x: 0, y: 0)
        let userId = try #require(session.canvas.components.first { $0.isUser }).id
        session.addClient(technologyId: "aws-ec2", to: userId)
        let clientId = try #require(session.canvas.components.first { $0.id != userId }).id
        let flowId = ViewedConnection.useLinkId(user: userId, client: clientId)

        #expect(gestures.flows.callouts.contains { $0.connectionId == flowId } == false)
        let curve = try #require(gestures.flows.curves[flowId])
        let middle = curve.point(at: 0.5)

        let rect = try #require(gestures.calloutRect(of: flowId))

        #expect(rect == CGRect(x: middle.x - 90, y: middle.y - 12, width: 180, height: 24))
    }

    @Test func calloutRectGivesNilForAConnectionIdTheBuildPlacesNoCurveFor() {
        let (_, _, gestures) = drawn()

        #expect(gestures.calloutRect(of: "no-such-connection") == nil)
    }
}

/// The zoom commands the View menu runs.
@MainActor
@Suite("Zooming from the View menu")
struct CanvasZoomCommandTests {
    private func drawn() -> (ThreatModelSession, CanvasState, CanvasGestures) {
        let session = ThreatModelSession(useCases: TestDependencies())
        let canvas = CanvasState()
        canvas.visibleSize = CGSize(width: 1000, height: 800)
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 2000, y: 1200)
        return (session, canvas, CanvasGestures(session: session, canvas: canvas))
    }

    @Test func zoomToFitPutsTheWholeDiagramInTheView() {
        let (session, canvas, gestures) = drawn()

        gestures.zoomToFit()

        let picture = try! #require(
            SelectionBounds.rect(
                components: session.canvas.components.map {
                    ($0.x, $0.y, Component.size.width, Component.size.height)
                },
                zones: session.canvas.zones.map { ($0.x, $0.y, $0.width, $0.height) }
            )
        )
        let topLeft = canvas.transform.viewPoint(picture.origin)
        let bottomRight = canvas.transform.viewPoint(
            CGPoint(x: picture.maxX, y: picture.maxY)
        )
        #expect(topLeft.x >= -0.001)
        #expect(bottomRight.x <= canvas.visibleSize.width + 0.001)
    }

    @Test func zoomToSelectionFitsWhatIsSelected() {
        let (session, canvas, gestures) = drawn()
        let far = session.canvas.components[1]
        canvas.select(componentId: far.id, addingToSelection: false)

        gestures.zoomToSelection()

        // The far node's middle sits in the middle of the view.
        let middle = canvas.transform.viewPoint(
            CGPoint(x: far.x + Component.size.width / 2, y: far.y + Component.size.height / 2)
        )
        #expect(abs(middle.x - canvas.visibleSize.width / 2) < 1)
        #expect(abs(middle.y - canvas.visibleSize.height / 2) < 1)
    }

    @Test func zoomToSelectionWithNothingSelectedChangesNothing() {
        let (_, canvas, gestures) = drawn()
        let before = canvas.transform

        gestures.zoomToSelection()

        #expect(canvas.transform == before)
    }

    @Test func actualSizeGoesBackToOneHundredPerCent() {
        let (_, canvas, gestures) = drawn()
        gestures.zoomAStep(in: true)
        #expect(canvas.transform.percentage == 125)

        gestures.zoomToActualSize()

        #expect(canvas.transform.percentage == 100)
    }
}

/// What the pointer says the canvas will do. A hand that promised a pan the
/// canvas did not answer was the wrong pointer.
@MainActor
@Suite("The pointer over open canvas")
struct CanvasPointerTests {
    @Test func statesAnOpenHandWhileADragWouldPan() {
        #expect(CanvasPointer.kind(isDrawingZone: false, isPanning: false) == .openHand)
    }

    @Test func statesAClosedHandWhileAPanIsInFlight() {
        #expect(CanvasPointer.kind(isDrawingZone: false, isPanning: true) == .closedHand)
    }

    /// The zone tool draws a rectangle, and a hand would promise a pan.
    @Test func statesTheRectanglePointerWhileTheZoneToolIsOn() {
        #expect(CanvasPointer.kind(isDrawingZone: true, isPanning: false) == .rectangle)
        #expect(CanvasPointer.kind(isDrawingZone: true, isPanning: true) == .rectangle)
    }
}
