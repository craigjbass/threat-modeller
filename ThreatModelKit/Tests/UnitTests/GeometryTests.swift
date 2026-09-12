import Foundation
import Testing
import ThreatModelKit

@Suite("The curve a flow draws")
struct FlowCurveTests {
    @Test func startsAndEndsWhereItWasAsked() {
        let curve = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 400, y: 100))

        #expect(curve.point(at: 0) == Point(x: 0, y: 0))
        #expect(curve.point(at: 1) == Point(x: 400, y: 100))
    }

    @Test func pullsSidewaysWithTheGap() {
        let curve = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 400, y: 0))

        #expect(curve.control1 == Point(x: 150, y: 0))
        #expect(curve.control2 == Point(x: 250, y: 0))
    }

    @Test func stillCurvesWhenTheGapIsTiny() {
        let curve = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 10, y: 0))

        #expect(curve.control1 == Point(x: 30, y: 0))
    }

    @Test func neverLoopsBackWhenTheGapIsHuge() {
        let curve = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 4000, y: 0))

        #expect(curve.control1 == Point(x: 150, y: 0))
        #expect(curve.control2 == Point(x: 3850, y: 0))
    }

    @Test func runsThroughTheMiddleOfALevelFlow() {
        let curve = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 400, y: 0))

        #expect(curve.point(at: 0.5) == Point(x: 200, y: 0))
    }
}

@Suite("Where a flow meets a component")
struct CoreAnchorGeometryTests {
    private let rect = Rect(x: 0, y: 0, width: 160, height: 72)

    @Test func placesTheFourAnchorsOnTheEdges() {
        #expect(AnchorGeometry.point(.top, of: rect) == Point(x: 80, y: 0))
        #expect(AnchorGeometry.point(.right, of: rect) == Point(x: 160, y: 36))
        #expect(AnchorGeometry.point(.bottom, of: rect) == Point(x: 80, y: 72))
        #expect(AnchorGeometry.point(.left, of: rect) == Point(x: 0, y: 36))
    }

    @Test func leavesFromTheRightAndArrivesOnTheLeftForABoxToTheRight() {
        let pair = AnchorGeometry.nearestPair(
            from: rect,
            to: Rect(x: 400, y: 0, width: 160, height: 72)
        )

        #expect(pair.source == .right)
        #expect(pair.target == .left)
    }

    @Test func leavesFromTheBottomAndArrivesOnTheTopForABoxBelow() {
        let pair = AnchorGeometry.nearestPair(
            from: rect,
            to: Rect(x: 0, y: 400, width: 160, height: 72)
        )

        #expect(pair.source == .bottom)
        #expect(pair.target == .top)
    }

    @Test func picksTheSamePairEveryTimeForTheSameLayout() {
        let target = Rect(x: 300, y: 300, width: 160, height: 72)

        #expect(
            AnchorGeometry.nearestPair(from: rect, to: target)
                == AnchorGeometry.nearestPair(from: rect, to: target)
        )
    }
}

@Suite("The rectangle a shape paints")
struct FootprintRectTests {
    @Test func centresEveryShapeOnTheSlot() {
        for shape in DiagramShape.allCases {
            let rect = Component.footprintRect(at: Point(x: 0, y: 0), shape: shape)

            #expect((rect.minX + rect.maxX) / 2 == 80)
            #expect((rect.minY + rect.maxY) / 2 == 36)
        }
    }

    @Test func paintsEachShapeAtItsOwnSize() {
        #expect(
            Component.footprintRect(at: Point(x: 0, y: 0), shape: .process).size
                == Size(width: 104, height: 104)
        )
        #expect(
            Component.footprintRect(at: Point(x: 0, y: 0), shape: .store).size
                == Size(width: 160, height: 64)
        )
    }
}

@Suite("A flow that goes through waypoints")
struct RoutedFlowCurveTests {
    @Test func drawsOnePieceWhenItGoesStraight() {
        let curve = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 400, y: 0))

        #expect(curve.segments.count == 1)
        #expect(curve.waypointCount == 0)
    }

    @Test func drawsOnePieceForEachLegOfTheDetour() {
        let curve = FlowCurve(
            from: Point(x: 0, y: 0),
            through: [Point(x: 200, y: -120)],
            to: Point(x: 400, y: 0)
        )

        #expect(curve.segments.count == 2)
        #expect(curve.waypointCount == 1)
    }

    @Test func startsAndEndsWhereItWasAskedHoweverManyWaypoints() {
        let curve = FlowCurve(
            from: Point(x: 0, y: 0),
            through: [Point(x: 100, y: -100), Point(x: 300, y: 100)],
            to: Point(x: 400, y: 0)
        )

        #expect(curve.point(at: 0) == Point(x: 0, y: 0))
        #expect(curve.point(at: 1) == Point(x: 400, y: 0))
    }

    @Test func passesThroughEveryWaypoint() {
        let waypoint = Point(x: 200, y: -120)
        let curve = FlowCurve(from: Point(x: 0, y: 0), through: [waypoint], to: Point(x: 400, y: 0))

        #expect(curve.point(at: 0.5) == waypoint)
    }

    @Test func runsWithoutAJumpAcrossAJoin() {
        let curve = FlowCurve(
            from: Point(x: 0, y: 0),
            through: [Point(x: 200, y: -120)],
            to: Point(x: 400, y: 0)
        )

        let before = curve.point(at: 0.49)
        let after = curve.point(at: 0.51)

        #expect(hypot(after.x - before.x, after.y - before.y) < 20)
    }
}
