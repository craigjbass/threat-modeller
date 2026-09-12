import Foundation
import Testing
import ThreatModelKit

@Suite("How easy a flow is to follow")
struct FlowShapeTests {
    @Test func chargesNothingForAStraightFlow() {
        let curve = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 400, y: 0))

        #expect(FlowShape.tightness(of: curve) == 0)
    }

    @Test func chargesNothingForAGentleCurve() {
        let curve = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 400, y: 200))

        #expect(FlowShape.tightness(of: curve) == 0)
    }

    @Test func chargesNothingForAWideQuarterTurn() {
        // A right angle taken on a wide arc is followed without stopping.
        let curve = FlowCurve(
            from: Point(x: 0, y: 0),
            through: [Point(x: 400, y: 0)],
            to: Point(x: 400, y: 400)
        )

        #expect(FlowShape.tightness(of: curve) == 0)
    }

    @Test func chargesForATurnTakenOnTheSpot() {
        let curve = FlowCurve(
            from: Point(x: 0, y: 0),
            through: [Point(x: 20, y: 0)],
            to: Point(x: 20, y: 20)
        )

        #expect(FlowShape.tightness(of: curve) > 0)
    }

    @Test func chargesMoreTheTighterTheTurn() {
        let wide = FlowCurve(
            from: Point(x: 0, y: 0),
            through: [Point(x: 400, y: 0)],
            to: Point(x: 400, y: 400)
        )
        let tight = FlowCurve(
            from: Point(x: 0, y: 0),
            through: [Point(x: 30, y: 0)],
            to: Point(x: 30, y: 30)
        )

        #expect(FlowShape.tightness(of: tight) > FlowShape.tightness(of: wide))
    }

    @Test func readsAStraightRunAsAnUnboundedRadius() {
        let radius = FlowShape.turnRadius(
            Point(x: 0, y: 0),
            Point(x: 10, y: 0),
            Point(x: 20, y: 0)
        )

        #expect(radius > 100_000)
    }

    @Test func readsThreePointsOnACircleAtItsRadius() {
        let radius = FlowShape.turnRadius(
            Point(x: -100, y: 0),
            Point(x: 0, y: 100),
            Point(x: 100, y: 0)
        )

        #expect(abs(radius - 100) < 0.001)
    }

    @Test func saysSoWhenTwoFlowsCross() {
        // Not through the same midpoint: two curves that meet exactly at a
        // point touch, and touching is not crossing.
        let one = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 400, y: 420))
        let other = FlowCurve(from: Point(x: 0, y: 400), to: Point(x: 400, y: 10))

        #expect(FlowShape.crosses(one, other))
    }

    @Test func saysNothingWhenTwoFlowsRunApart() {
        let one = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 400, y: 0))
        let other = FlowCurve(from: Point(x: 0, y: 400), to: Point(x: 400, y: 400))

        #expect(FlowShape.crosses(one, other) == false)
    }

    @Test func countsEachNodeAFlowRunsBehind() {
        let curve = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 600, y: 0))
        let behind = [
            Rect(x: 100, y: -40, width: 80, height: 80),
            Rect(x: 300, y: -40, width: 80, height: 80),
            Rect(x: 100, y: 400, width: 80, height: 80)
        ]

        #expect(FlowShape.timesBehind(curve, behind) == 2)
    }

    @Test func countsNothingBehindWhenThereIsNothingInTheWay() {
        let curve = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 600, y: 0))

        #expect(FlowShape.timesBehind(curve, []) == 0)
    }
}
