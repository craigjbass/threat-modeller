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
