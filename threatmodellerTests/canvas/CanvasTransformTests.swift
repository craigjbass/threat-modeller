import CoreGraphics
import Testing
@testable import threatmodeller

struct CanvasTransformTests {
    @Test func mapsAModelPointToTheView() {
        let transform = CanvasTransform(pan: CGSize(width: 30, height: 10), zoom: 2)

        #expect(transform.viewPoint(CGPoint(x: 100, y: 50)) == CGPoint(x: 230, y: 110))
    }

    @Test func mapsAViewPointBackToTheModel() {
        let transform = CanvasTransform(pan: CGSize(width: 30, height: 10), zoom: 2)

        #expect(transform.modelPoint(CGPoint(x: 230, y: 110)) == CGPoint(x: 100, y: 50))
    }

    @Test func roundTripsEveryPoint() {
        let transform = CanvasTransform(pan: CGSize(width: -17, height: 42), zoom: 0.75)
        let start = CGPoint(x: 12.5, y: -8)

        let round = transform.modelPoint(transform.viewPoint(start))
        #expect(abs(round.x - start.x) < 0.0001)
        #expect(abs(round.y - start.y) < 0.0001)
    }

    @Test func dividesADragTranslationByTheZoom() {
        let transform = CanvasTransform(zoom: 2)

        #expect(transform.modelDistance(CGSize(width: 40, height: 20)) == CGSize(width: 20, height: 10))
    }

    @Test func clampsTheZoomToItsRange() {
        #expect(CanvasTransform(zoom: 0.01).zoom == CanvasTransform.minimumZoom)
        #expect(CanvasTransform(zoom: 99).zoom == CanvasTransform.maximumZoom)
        #expect(CanvasTransform(zoom: 1.5).zoom == 1.5)
    }

    @Test func keepsTheModelPointUnderTheCursorWhileZooming() {
        let transform = CanvasTransform(pan: CGSize(width: 12, height: 8), zoom: 1)
        let cursor = CGPoint(x: 200, y: 140)
        let before = transform.modelPoint(cursor)

        let zoomed = transform.zoomed(by: 2, about: cursor)
        let after = zoomed.modelPoint(cursor)

        #expect(zoomed.zoom == 2)
        #expect(abs(after.x - before.x) < 0.0001)
        #expect(abs(after.y - before.y) < 0.0001)
    }

    @Test func doesNotMoveThePointWhenTheZoomIsAlreadyClamped() {
        let transform = CanvasTransform(zoom: CanvasTransform.maximumZoom)
        let cursor = CGPoint(x: 100, y: 100)

        let zoomed = transform.zoomed(by: 4, about: cursor)

        #expect(zoomed.zoom == CanvasTransform.maximumZoom)
        #expect(zoomed.modelPoint(cursor) == transform.modelPoint(cursor))
    }

    @Test func addsUpSuccessivePans() {
        let transform = CanvasTransform(pan: CGSize(width: 10, height: 10), zoom: 1)
            .panned(by: CGSize(width: 5, height: -3))

        #expect(transform.pan == CGSize(width: 15, height: 7))
        #expect(transform.zoom == 1)
    }
}
