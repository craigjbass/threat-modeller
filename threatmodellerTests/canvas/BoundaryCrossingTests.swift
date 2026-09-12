import CoreGraphics
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
@testable import threatmodeller

/// Where a flow crosses a trust boundary, and which boundary it crossed.
struct BoundaryCrossingTests {
    private func zone(
        _ id: String,
        x: Double,
        y: Double,
        width: Double = 400,
        height: Double = 400,
        networkZoneId: String = "private"
    ) -> ViewedZone {
        ViewedZone(
            id: id,
            name: id,
            customName: nil,
            networkZoneId: networkZoneId,
            networkTypeId: "generic",
            riskReductionEnabled: true,
            riskReductionPercent: 20,
            x: x,
            y: y,
            width: width,
            height: height
        )
    }

    private func component(_ id: String, x: Double, y: Double, zoneId: String?) -> ViewedComponent {
        ViewedComponent(
            id: id,
            technologyId: "aws-ec2",
            name: id,
            customName: nil,
            providerId: "aws",
            categoryId: "compute",
            x: x,
            y: y,
            sensitivityId: "internal",
            threatsDisabled: false,
            isUnknownTechnology: false,
            zoneId: zoneId
        )
    }

    private func crossings(
        from source: ViewedComponent,
        to target: ViewedComponent,
        zones: [ViewedZone]
    ) -> [BoundaryCrossing] {
        let connection = ViewedConnection(
            id: "f1",
            sourceComponentId: source.id,
            targetComponentId: target.id
        )
        let boxes = CanvasHitTest.boxes(
            for: [source, target],
            selected: [],
            dragTranslation: .zero
        )
        guard let path = CanvasHitTest.path(for: connection, boxes: boxes) else {
            Issue.record("the flow drew no path")
            return []
        }

        return BoundaryCrossings.of(
            connection,
            path: path,
            components: [source.id: source, target.id: target],
            zones: zones
        )
    }

    @Test func marksNothingWhenBothEndsSitInTheSameZone() {
        let inside = zone("z1", x: 0, y: 0, width: 800, height: 400)
        let marks = crossings(
            from: component("a", x: 60, y: 100, zoneId: "z1"),
            to: component("b", x: 500, y: 100, zoneId: "z1"),
            zones: [inside]
        )

        #expect(marks.isEmpty)
    }

    @Test func marksNothingWhenNeitherEndSitsInAZone() {
        let marks = crossings(
            from: component("a", x: 0, y: 0, zoneId: nil),
            to: component("b", x: 500, y: 0, zoneId: nil),
            zones: []
        )

        #expect(marks.isEmpty)
    }

    @Test func marksOnceWhereAFlowLeavesTheOnlyZone() {
        let inside = zone("z1", x: 0, y: 0, width: 400, height: 400)
        let marks = crossings(
            from: component("a", x: 60, y: 150, zoneId: "z1"),
            to: component("b", x: 700, y: 150, zoneId: nil),
            zones: [inside]
        )

        #expect(marks.count == 1)
        #expect(marks[0].networkZoneId == "private")
        // The zone's right edge is at 400, and the mark sits on it.
        #expect(abs(marks[0].point.x - 400) < 6)
    }

    @Test func marksTwiceWhereAFlowLeavesOneZoneAndEntersAnother() {
        let left = zone("z1", x: 0, y: 0, width: 400, height: 400, networkZoneId: "public")
        let right = zone("z2", x: 600, y: 0, width: 400, height: 400)
        let marks = crossings(
            from: component("a", x: 60, y: 150, zoneId: "z1"),
            to: component("b", x: 700, y: 150, zoneId: "z2"),
            zones: [left, right]
        )

        #expect(marks.count == 2)
        #expect(marks[0].networkZoneId == "public")
        #expect(marks[1].networkZoneId == "private")
        #expect(marks[0].point.x < marks[1].point.x)
    }

    @Test func statesTheTangentOfAFlowRunningStraightAcross() {
        let inside = zone("z1", x: 0, y: 0, width: 400, height: 400)
        let marks = crossings(
            from: component("a", x: 60, y: 150, zoneId: "z1"),
            to: component("b", x: 700, y: 150, zoneId: nil),
            zones: [inside]
        )

        // A flow between two nodes at the same height leaves and arrives level,
        // so its tangent at the crossing is horizontal and the curve drawn
        // across it stands upright.
        #expect(marks.count == 1)
        #expect(abs(marks[0].angle) < 0.05)
    }

    @Test func marksOnceWhereAFlowEntersTheOnlyZone() {
        let inside = zone("z1", x: 600, y: 0, width: 400, height: 400)
        let marks = crossings(
            from: component("a", x: 0, y: 150, zoneId: nil),
            to: component("b", x: 700, y: 150, zoneId: "z1"),
            zones: [inside]
        )

        #expect(marks.count == 1)
        #expect(abs(marks[0].point.x - 600) < 6)
    }

    // MARK: one curve per boundary

    private func marked(
        _ zoneId: String,
        x: Double,
        y: Double,
        angle: CGFloat = 0,
        guards: [EdgeGuard] = [],
        openCount: Int = 0
    ) -> BoundaryCrossings.MarkedCrossing {
        BoundaryCrossings.MarkedCrossing(
            crossing: BoundaryCrossing(
                point: CGPoint(x: x, y: y),
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
        // The curve reaches past the outermost flow through it.
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

        // The flows run level, so the curve stands upright through them.
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

    @Test func namesTheZoneWhoseEdgeTheFlowCrosses() {
        let inside = zone("z1", x: 0, y: 0, width: 400, height: 400)
        let marks = crossings(
            from: component("a", x: 60, y: 150, zoneId: "z1"),
            to: component("b", x: 700, y: 150, zoneId: nil),
            zones: [inside]
        )

        #expect(marks.first?.zoneId == "z1")
    }
}
