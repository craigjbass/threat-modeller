import CoreGraphics
import Testing
@testable import threatmodeller

struct ConnectionPathTests {
    private let straight = ConnectionPath(from: CGPoint(x: 0, y: 0), to: CGPoint(x: 200, y: 0))

    @Test func startsAtItsStartAndEndsAtItsEnd() {
        #expect(straight.point(at: 0) == CGPoint(x: 0, y: 0))
        #expect(straight.point(at: 1) == CGPoint(x: 200, y: 0))
    }

    @Test func selectsAClickOnTheLine() {
        #expect(straight.containsClick(at: CGPoint(x: 100, y: 0)))
        #expect(straight.containsClick(at: CGPoint(x: 100, y: ConnectionPath.hitTolerance - 1)))
    }

    @Test func ignoresAClickBeyondTheTolerance() {
        #expect(straight.containsClick(at: CGPoint(x: 100, y: ConnectionPath.hitTolerance + 20)) == false)
        #expect(straight.containsClick(at: CGPoint(x: 600, y: 0)) == false)
    }

    @Test func bulgesHorizontallyBetweenTwoOffsetPoints() {
        let curved = ConnectionPath(from: CGPoint(x: 0, y: 0), to: CGPoint(x: 200, y: 200))

        // The straight line between the two ends has x equal to y at every
        // point. The curve leaves the source horizontally, so a quarter of the
        // way along it has run ahead in x.
        let quarter = curved.point(at: 0.25)
        #expect(quarter.x > quarter.y)
        #expect(curved.containsClick(at: quarter))
        #expect(curved.containsClick(at: CGPoint(x: 0, y: 200)) == false)
    }

    @Test func pointsTheArrowheadAlongTheFinalDirection() {
        let head = straight.arrowhead(length: 10, width: 8)

        #expect(head.count == 3)
        #expect(head[0] == CGPoint(x: 200, y: 0))
        // The two base points sit 10 behind the tip and 4 either side of it.
        #expect(abs(head[1].x - 190) < 0.001)
        #expect(abs(head[2].x - 190) < 0.001)
        #expect(abs(abs(head[1].y - head[2].y) - 8) < 0.001)
    }
}
