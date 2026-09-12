import Foundation
import Testing
import ThreatModelKit

@Suite("Taking a flow round a zone it has nothing to do with")
struct FlowRoutingTests {
    private let middle = Rect(x: 150, y: 0, width: 100, height: 200)

    private func entersAnything(
        from start: Point,
        through waypoints: [Point],
        to end: Point,
        zones: [Rect]
    ) -> Bool {
        let curve = FlowCurve(from: start, through: waypoints, to: end)
        return (0...96).contains { step in
            let point = curve.point(at: Double(step) / 96)
            return zones.contains { $0.contains(point) }
        }
    }

    @Test func leavesAClearFlowAlone() {
        let found = FlowRouting.waypoints(
            from: Point(x: 0, y: 400),
            to: Point(x: 400, y: 400),
            avoiding: [middle]
        )

        #expect(found.isEmpty)
    }

    @Test func statesNoWaypointWhenThereIsNoZoneToAvoid() {
        let found = FlowRouting.waypoints(
            from: Point(x: 0, y: 100),
            to: Point(x: 400, y: 100),
            avoiding: []
        )

        #expect(found.isEmpty)
    }

    @Test func takesAFlowRoundTheOneZoneInItsWay() {
        let start = Point(x: 0, y: 20)
        let end = Point(x: 400, y: 20)
        let found = FlowRouting.waypoints(from: start, to: end, avoiding: [middle])

        #expect(found.count == 1)
        #expect(entersAnything(from: start, through: found, to: end, zones: [middle]) == false)
    }

    @Test func goesOverTheTopWhenTheTopIsNearer() {
        let found = FlowRouting.waypoints(
            from: Point(x: 0, y: 20),
            to: Point(x: 400, y: 20),
            avoiding: [middle]
        )

        #expect(found.first?.y == middle.minY - FlowRouting.clearance)
    }

    @Test func goesUnderTheBottomWhenTheBottomIsNearer() {
        let found = FlowRouting.waypoints(
            from: Point(x: 0, y: 180),
            to: Point(x: 400, y: 180),
            avoiding: [middle]
        )

        #expect(found.first?.y == middle.maxY + FlowRouting.clearance)
    }

    @Test func takesAFlowRoundTwoZonesInItsWay() {
        let second = Rect(x: 300, y: 0, width: 100, height: 200)
        let start = Point(x: 0, y: 20)
        let end = Point(x: 500, y: 20)
        let found = FlowRouting.waypoints(from: start, to: end, avoiding: [middle, second])

        #expect(found.count == 2)
    }

    @Test func neverTakesMoreDetoursThanItIsAllowed() {
        let many = (0 ..< 6).map { Rect(x: Double($0) * 90 + 60, y: 0, width: 60, height: 200) }
        let found = FlowRouting.waypoints(
            from: Point(x: 0, y: 20),
            to: Point(x: 700, y: 20),
            avoiding: many
        )

        #expect(found.count <= FlowRouting.mostWaypoints)
    }
}

@Suite("Taking an upright flow round a zone")
struct UprightFlowRoutingTests {
    private let across = Rect(x: 0, y: 200, width: 400, height: 100)

    @Test func goesRoundTheSideOfAZoneAcrossAnUprightFlow() {
        let start = Point(x: 60, y: 0)
        let end = Point(x: 60, y: 500)
        let found = FlowRouting.waypoints(from: start, to: end, avoiding: [across])

        #expect(found.isEmpty == false)
        // The left edge is nearer than the right, so it goes round the left.
        #expect(found[0].x == across.minX - FlowRouting.clearance)
    }

    @Test func goesRoundTheRightWhenTheRightIsNearer() {
        let found = FlowRouting.waypoints(
            from: Point(x: 340, y: 0),
            to: Point(x: 340, y: 500),
            avoiding: [across]
        )

        #expect(found[0].x == across.maxX + FlowRouting.clearance)
    }
}

@Suite("A detour that reads as a line, not a set of corners")
struct DetourShapeTests {
    @Test func neverTakesMoreDetoursThanTheCap() {
        let around = Rect(x: 0, y: 0, width: 400, height: 400)
        let found = FlowRouting.waypoints(
            from: Point(x: 100, y: 100),
            to: Point(x: 300, y: 300),
            avoiding: [around]
        )

        #expect(found.count <= FlowRouting.mostWaypoints)
    }

    @Test func picksTheWayRoundThatLeavesTheFlowInFewerZones() {
        // The near side is the top, and going over the top runs straight into
        // the second zone. Under the bottom is clear, so that is the way.
        let first = Rect(x: 150, y: 0, width: 100, height: 100)
        let second = Rect(x: 150, y: -200, width: 400, height: 180)
        let start = Point(x: 0, y: 20)
        let end = Point(x: 500, y: 20)

        let found = FlowRouting.waypoints(from: start, to: end, avoiding: [first, second])

        #expect(found.isEmpty == false)
        #expect(found[0].y > first.minY)
    }

    @Test func keepsAFlowRoundTwoZonesReadableAsOneLine() {
        let first = Rect(x: 150, y: 0, width: 80, height: 200)
        let second = Rect(x: 300, y: 0, width: 80, height: 200)
        let start = Point(x: 0, y: 100)
        let end = Point(x: 500, y: 100)

        let found = FlowRouting.waypoints(from: start, to: end, avoiding: [first, second])
        let curve = FlowCurve(from: start, through: found, to: end)

        // Well under a full turn: a flow that went back and forth to the cap
        // turned more than seven radians.
        #expect(FlowShape.turning(of: curve) < 2 * Double.pi)
    }
}
