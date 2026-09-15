import CoreGraphics
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

    @Test func aTwoFingerScrollMovesTheDiagram() {
        let (_, canvas, gestures) = drawn()

        gestures.scroll(by: CGSize(width: 30, height: -20))

        #expect(canvas.transform.pan == CGSize(width: -30, height: 20))
    }

    @Test func aTwoFingerScrollKeepsTheZoom() {
        let (_, canvas, gestures) = drawn()
        canvas.transform = CanvasTransform(zoom: 2)

        gestures.scroll(by: CGSize(width: 10, height: 10))

        #expect(canvas.transform.zoom == 2)
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
}
