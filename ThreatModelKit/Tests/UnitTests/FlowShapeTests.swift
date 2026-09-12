import Foundation
import Testing
import ThreatModelKit

@Suite("How easy a flow is to follow")
struct FlowShapeTests {
    @Test func saysAStraightFlowTurnsNothing() {
        let curve = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 400, y: 0))

        #expect(FlowShape.turning(of: curve) < 0.01)
        #expect(FlowShape.sharpness(of: curve) == 0)
    }

    @Test func chargesNothingForAGentleCurve() {
        let curve = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 400, y: 200))

        #expect(FlowShape.turning(of: curve) < FlowShape.turnsFreely)
        #expect(FlowShape.sharpness(of: curve) == 0)
    }

    @Test func chargesForAFlowThatDoublesBack() {
        let curve = FlowCurve(
            from: Point(x: 0, y: 0),
            through: [Point(x: 200, y: -400)],
            to: Point(x: 10, y: 0)
        )

        #expect(FlowShape.turning(of: curve) > 2)
        #expect(FlowShape.sharpness(of: curve) > 0)
    }

    @Test func chargesMoreTheTighterTheCorner() {
        let gentle = FlowCurve(
            from: Point(x: 0, y: 0),
            through: [Point(x: 200, y: -60)],
            to: Point(x: 400, y: 0)
        )
        let tight = FlowCurve(
            from: Point(x: 0, y: 0),
            through: [Point(x: 200, y: -400)],
            to: Point(x: 10, y: 0)
        )

        #expect(FlowShape.sharpness(of: tight) > FlowShape.sharpness(of: gentle))
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
