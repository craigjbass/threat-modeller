import Foundation
import Testing
import ThreatModelKit

@Suite("Where a flow crosses a trust boundary")
struct BoundaryCrossingsTests {
    private func zone(
        _ id: String,
        x: Double,
        y: Double,
        width: Double = 400,
        height: Double = 400,
        networkZoneId: String = "private"
    ) -> BoundaryZone {
        BoundaryZone(
            id: id,
            networkZoneId: networkZoneId,
            rect: Rect(x: x, y: y, width: width, height: height)
        )
    }

    /// A level flow from one component's right edge to another's left edge, the
    /// way the canvas draws one.
    private func crossings(
        fromX: Double,
        toX: Double,
        y: Double = 186,
        sourceZoneId: String?,
        targetZoneId: String?,
        zones: [BoundaryZone]
    ) -> [BoundaryCrossing] {
        BoundaryCrossings.of(
            connectionId: "f1",
            sourceZoneId: sourceZoneId,
            targetZoneId: targetZoneId,
            curve: FlowCurve(from: Point(x: fromX, y: y), to: Point(x: toX, y: y)),
            zones: zones
        )
    }

    @Test func marksNothingWhenBothEndsSitInTheSameZone() {
        let marks = crossings(
            fromX: 60,
            toX: 700,
            sourceZoneId: "z1",
            targetZoneId: "z1",
            zones: [zone("z1", x: 0, y: 0, width: 800)]
        )

        #expect(marks.isEmpty)
    }

    @Test func marksNothingWhenNeitherEndSitsInAZone() {
        let marks = crossings(
            fromX: 0,
            toX: 500,
            sourceZoneId: nil,
            targetZoneId: nil,
            zones: []
        )

        #expect(marks.isEmpty)
    }

    @Test func marksOnceWhereAFlowLeavesTheOnlyZone() {
        let marks = crossings(
            fromX: 192,
            toX: 728,
            sourceZoneId: "z1",
            targetZoneId: nil,
            zones: [zone("z1", x: 0, y: 0)]
        )

        #expect(marks.count == 1)
        #expect(marks[0].networkZoneId == "private")
        #expect(marks[0].zoneId == "z1")
        #expect(abs(marks[0].point.x - 400) < 6)
    }

    @Test func marksOnceWhereAFlowEntersTheOnlyZone() {
        let marks = crossings(
            fromX: 100,
            toX: 728,
            sourceZoneId: nil,
            targetZoneId: "z1",
            zones: [zone("z1", x: 600, y: 0)]
        )

        #expect(marks.count == 1)
        #expect(abs(marks[0].point.x - 600) < 6)
    }

    @Test func marksTwiceWhereAFlowLeavesOneZoneAndEntersAnother() {
        let marks = crossings(
            fromX: 192,
            toX: 728,
            sourceZoneId: "z1",
            targetZoneId: "z2",
            zones: [
                zone("z1", x: 0, y: 0, networkZoneId: "public"),
                zone("z2", x: 600, y: 0)
            ]
        )

        #expect(marks.count == 2)
        #expect(marks[0].networkZoneId == "public")
        #expect(marks[1].networkZoneId == "private")
        #expect(marks[0].point.x < marks[1].point.x)
    }

    @Test func statesTheTangentOfAFlowRunningStraightAcross() {
        let marks = crossings(
            fromX: 192,
            toX: 728,
            sourceZoneId: "z1",
            targetZoneId: nil,
            zones: [zone("z1", x: 0, y: 0)]
        )

        #expect(marks.count == 1)
        #expect(abs(marks[0].angle) < 0.05)
    }

    // MARK: one curve per boundary

    private func marked(
        _ zoneId: String,
        x: Double,
        y: Double,
        angle: Double = 0,
        guards: [EdgeGuard] = [],
        openCount: Int = 0
    ) -> BoundaryCrossings.MarkedCrossing {
        BoundaryCrossings.MarkedCrossing(
            connectionId: "f-\(x)-\(y)",
            crossing: BoundaryCrossing(
                point: Point(x: x, y: y),
                angle: angle,
                zoneId: zoneId,
                networkZoneId: "private"
            ),
            guards: guards,
            openCount: openCount
        )
    }

    @Test func drawsOneCurveThroughEveryFlowOneSetOfGuardsHolds() {
        let runs = BoundaryCrossings.runs([
            marked("z1", x: 400, y: 200, guards: [EdgeGuard(label: "opfilter", isAssumed: false)]),
            marked("z1", x: 400, y: 260, guards: [EdgeGuard(label: "opfilter", isAssumed: false)]),
            marked("z1", x: 400, y: 320, guards: [EdgeGuard(label: "opfilter", isAssumed: false)])
        ])

        #expect(runs.count == 1)
        #expect(runs[0].flowCount == 3)
        #expect(runs[0].start.y < 200)
        #expect(runs[0].end.y > 320)
    }

    @Test func drawsACurveForEachSetOfGuardsOnOneZone() {
        let runs = BoundaryCrossings.runs([
            marked("z1", x: 400, y: 200, guards: [EdgeGuard(label: "opfilter", isAssumed: false)]),
            marked("z1", x: 400, y: 260, guards: [EdgeGuard(label: "WAF", isAssumed: false)])
        ])

        #expect(runs.count == 2)
        #expect(runs.map(\.guards.first?.label) == ["opfilter", "WAF"])
    }

    @Test func drawsACurveForEachEndOfAZoneTheSameGuardsHold() {
        let runs = BoundaryCrossings.runs([
            marked("z1", x: 400, y: 100),
            marked("z1", x: 400, y: 900)
        ])

        #expect(runs.count == 2)
    }

    @Test func keepsTheTwoZonesOfOneCrossingPointApart() {
        let runs = BoundaryCrossings.runs([
            marked("z1", x: 400, y: 200),
            marked("z2", x: 402, y: 202)
        ])

        #expect(runs.count == 2)
    }

    @Test func drawsTheCurveAcrossTheFlowsThroughIt() {
        let runs = BoundaryCrossings.runs([marked("z1", x: 400, y: 200, angle: 0)])

        #expect(runs.count == 1)
        #expect(abs(runs[0].start.x - 400) < 0.001)
        #expect(abs(runs[0].end.x - 400) < 0.001)
        #expect(runs[0].end.y - runs[0].start.y == BoundaryCrossings.length)
    }

    @Test func bowsEveryCurveBackAlongTheFlows() {
        let runs = BoundaryCrossings.runs([marked("z1", x: 400, y: 200, angle: 0)])

        #expect(runs[0].control.x < 400)
    }

    @Test func addsUpTheOpenThreatsOfEveryFlowThroughTheCurve() {
        let runs = BoundaryCrossings.runs([
            marked("z1", x: 400, y: 200, openCount: 2),
            marked("z1", x: 400, y: 260, openCount: 3)
        ])

        #expect(runs.count == 1)
        #expect(runs[0].openCount == 5)
    }

    @Test func namesEveryFlowThroughTheCurve() {
        let runs = BoundaryCrossings.runs([
            marked("z1", x: 400, y: 200),
            marked("z1", x: 400, y: 260)
        ])

        #expect(runs[0].connectionIds == ["f-400.0-200.0", "f-400.0-260.0"])
    }
}
