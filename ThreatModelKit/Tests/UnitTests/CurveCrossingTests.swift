import Testing
import ThreatModelKit

@Suite("Whether two curves on the diagram cross")
struct CurveCrossingTests {
    private let across = [Point(x: 200, y: 0), Point(x: 200, y: 400)]

    @Test func saysSoWhenOneCurveRunsThroughTheOther() {
        let along = [Point(x: 0, y: 200), Point(x: 400, y: 200)]

        #expect(CurveCrossing.crosses(along, across))
        #expect(CurveCrossing.crossings(along, across) == [0])
    }

    @Test func saysNothingWhenTheTwoStayApart() {
        let along = [Point(x: 0, y: 200), Point(x: 100, y: 200)]

        #expect(CurveCrossing.crosses(along, across) == false)
    }

    @Test func doesNotCountTwoCurvesMeetingAtAnEndPoint() {
        let along = [Point(x: 0, y: 200), Point(x: 200, y: 200)]

        #expect(CurveCrossing.crosses(along, across) == false)
    }

    @Test func namesEverySegmentThatCrosses() {
        let zigzag = [
            Point(x: 0, y: 100),
            Point(x: 400, y: 150),
            Point(x: 0, y: 250),
            Point(x: 400, y: 300)
        ]

        #expect(CurveCrossing.crossings(zigzag, across).count == 3)
    }

    @Test func saysNothingAboutACurveOfOnePoint() {
        #expect(CurveCrossing.crosses([Point(x: 0, y: 0)], across) == false)
    }

    @Test func samplesAFlowFromEndToEnd() {
        let curve = FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 400, y: 0))
        let points = CurveCrossing.samples(of: curve)

        #expect(points.count == CurveCrossing.steps + 1)
        #expect(points.first == Point(x: 0, y: 0))
        #expect(points.last == Point(x: 400, y: 0))
    }

    @Test func samplesABoundaryFromEndToEnd() {
        let run = BoundaryCrossings.BoundaryRun(
            zoneId: "z1",
            networkZoneId: "private",
            guards: [],
            openCount: 0,
            connectionIds: ["f1"],
            start: Point(x: 200, y: 0),
            end: Point(x: 200, y: 400),
            control: Point(x: 180, y: 200)
        )
        let points = CurveCrossing.samples(of: run)

        #expect(points.first == Point(x: 200, y: 0))
        #expect(points.last == Point(x: 200, y: 400))
    }
}
