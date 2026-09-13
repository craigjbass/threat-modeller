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

    // MARK: how near a point has to be to count as touching

    /// A 3-4-5 triangle, so the distance is exactly 5 and the boundary is
    /// exact in binary floating point. Whatever `touches` compares, it must
    /// still answer the same at the reach itself.
    @Test func countsAPointExactlyAtTheReach() {
        let segment = [Point(x: 0, y: 0), Point(x: 6, y: 8)]
        let point = Point(x: 4, y: -3)

        #expect(CurveCrossing.touches(point, segment, within: 5))
    }

    @Test func countsAPointInsideTheReach() {
        let segment = [Point(x: 0, y: 0), Point(x: 100, y: 0)]

        #expect(CurveCrossing.touches(Point(x: 50, y: 4), segment, within: 4.5))
    }

    @Test func countsNothingOutsideTheReach() {
        let segment = [Point(x: 0, y: 0), Point(x: 100, y: 0)]

        #expect(CurveCrossing.touches(Point(x: 50, y: 4), segment, within: 3.5) == false)
    }

    /// The nearest point on a segment is one of its ends when the point sits
    /// beyond it, not the line the segment lies on.
    @Test func measuresToTheEndWhenThePointLiesBeyondTheSegment() {
        let segment = [Point(x: 0, y: 0), Point(x: 10, y: 0)]

        #expect(CurveCrossing.touches(Point(x: 13, y: 4), segment, within: 5))
        #expect(CurveCrossing.touches(Point(x: 13, y: 4), segment, within: 4.9) == false)
    }

    /// A segment of no length is a point, and the distance is to that point.
    @Test func measuresToThePointWhenASegmentHasNoLength() {
        let segment = [Point(x: 7, y: 7), Point(x: 7, y: 7)]

        #expect(CurveCrossing.touches(Point(x: 10, y: 11), segment, within: 5))
        #expect(CurveCrossing.touches(Point(x: 10, y: 11), segment, within: 4.9) == false)
    }

    /// Any segment of the polyline counts, not only the first.
    @Test func countsAPointNearALaterSegment() {
        let polyline = [Point(x: 0, y: 0), Point(x: 100, y: 0), Point(x: 100, y: 100)]

        #expect(CurveCrossing.touches(Point(x: 104, y: 50), polyline, within: 5))
    }

    @Test func countsNothingAgainstAPolylineOfOnePoint() {
        #expect(CurveCrossing.touches(Point(x: 0, y: 0), [Point(x: 0, y: 0)], within: 100) == false)
    }
}
