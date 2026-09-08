import Testing
import ThreatModelKit

struct RectTests {
    private let rect = Rect(x: 10, y: 20, width: 100, height: 50)

    @Test func reportsItsEdges() {
        #expect(rect.origin == Point(x: 10, y: 20))
        #expect(rect.size == Size(width: 100, height: 50))
        #expect(rect.minX == 10)
        #expect(rect.minY == 20)
        #expect(rect.maxX == 110)
        #expect(rect.maxY == 70)
    }

    @Test func containsAPointInsideIt() {
        #expect(rect.contains(Point(x: 50, y: 40)))
        #expect(rect.contains(Point(x: 10, y: 20)))
    }

    @Test func excludesAPointOnItsFarEdges() {
        // Half-open, the way CGRect behaves: the near edges are inside and the
        // far edges are outside, so two rectangles sharing an edge never both
        // claim the same point.
        #expect(rect.contains(Point(x: 110, y: 40)) == false)
        #expect(rect.contains(Point(x: 50, y: 70)) == false)
    }

    @Test func excludesAPointOutsideIt() {
        #expect(rect.contains(Point(x: 9, y: 40)) == false)
        #expect(rect.contains(Point(x: 50, y: 19)) == false)
    }

    @Test func removesABandFromItsTop() {
        let inset = rect.insetFromTop(by: 40)

        #expect(inset.minY == 60)
        #expect(inset.maxY == 70)
        #expect(inset.minX == 10)
        #expect(inset.size.width == 100)
    }

    @Test func neverInsetsPastItsOwnBottom() {
        let inset = rect.insetFromTop(by: 500)

        #expect(inset.size.height == 0)
        #expect(inset.minY == 70)
    }
}
