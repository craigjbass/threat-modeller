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

    @Test func bowsEveryMarkBackAlongTheFlow() {
        let left = zone("z1", x: 0, y: 0, width: 400, height: 400, networkZoneId: "public")
        let right = zone("z2", x: 600, y: 0, width: 400, height: 400)
        let marks = crossings(
            from: component("a", x: 60, y: 150, zoneId: "z1"),
            to: component("b", x: 700, y: 150, zoneId: "z2"),
            zones: [left, right]
        )

        #expect(marks.count == 2)
        let leaving = BoundaryCrossings.mark(for: marks[0]).boundingRect
        let entering = BoundaryCrossings.mark(for: marks[1]).boundingRect

        // Both marks bow back along the flow, so the pair reads the same way
        // whether the flow leaves a zone there or enters one.
        #expect(leaving.minX < marks[0].point.x)
        #expect(leaving.maxX <= marks[0].point.x + 1)
        #expect(entering.minX < marks[1].point.x)
        #expect(entering.maxX <= marks[1].point.x + 1)
    }

    @Test func statesTheTangentOfAFlowRunningStraightAcross() {
        let inside = zone("z1", x: 0, y: 0, width: 400, height: 400)
        let marks = crossings(
            from: component("a", x: 60, y: 150, zoneId: "z1"),
            to: component("b", x: 700, y: 150, zoneId: nil),
            zones: [inside]
        )

        // A flow between two nodes at the same height leaves and arrives level,
        // so its tangent at the crossing is horizontal and the mark drawn
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

    // MARK: one mark per place

    private func crossing(_ zoneId: String, x: Double, y: Double) -> BoundaryCrossing {
        BoundaryCrossing(
            point: CGPoint(x: x, y: y),
            angle: 0,
            zoneId: zoneId,
            networkZoneId: "private"
        )
    }

    @Test func keepsOneMarkWhereSeveralFlowsCrossOneEdgeTogether() {
        let places = BoundaryCrossings.places([
            crossing("z1", x: 400, y: 200),
            crossing("z1", x: 404, y: 206),
            crossing("z1", x: 412, y: 214)
        ])

        #expect(places.count == 1)
        #expect(places[0].point == CGPoint(x: 400, y: 200))
    }

    @Test func keepsBothMarksWhereTwoFlowsCrossOneEdgeFarApart() {
        let places = BoundaryCrossings.places([
            crossing("z1", x: 400, y: 200),
            crossing("z1", x: 400, y: 400)
        ])

        #expect(places.count == 2)
    }

    @Test func keepsBothMarksWhereTwoZoneEdgesMeetAtOnePoint() {
        let places = BoundaryCrossings.places([
            crossing("z1", x: 400, y: 200),
            crossing("z2", x: 402, y: 202)
        ])

        #expect(places.count == 2)
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
