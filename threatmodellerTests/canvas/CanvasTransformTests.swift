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

    // MARK: the View menu's zooms

    @Test func aStepInAndAStepOutLeaveTheCentreWhereItWas() {
        let view = CGSize(width: 1000, height: 600)
        let middle = CGPoint(x: 500, y: 300)
        let transform = CanvasTransform(pan: CGSize(width: 120, height: -40), zoom: 1)

        let closer = transform.zoomedAboutTheCentre(by: CanvasTransform.zoomStep, of: view)
        let back = closer.zoomedAboutTheCentre(by: 1 / CanvasTransform.zoomStep, of: view)

        #expect(closer.zoom == CanvasTransform.zoomStep)
        #expect(abs(closer.modelPoint(middle).x - transform.modelPoint(middle).x) < 0.001)
        #expect(abs(closer.modelPoint(middle).y - transform.modelPoint(middle).y) < 0.001)
        #expect(abs(back.zoom - transform.zoom) < 0.001)
    }

    @Test func actualSizeGoesBackToOneAndKeepsTheCentre() {
        let view = CGSize(width: 800, height: 600)
        let middle = CGPoint(x: 400, y: 300)
        let transform = CanvasTransform(pan: CGSize(width: -200, height: -100), zoom: 2)

        let actual = transform.atActualSize(in: view)

        #expect(actual.zoom == 1)
        #expect(abs(actual.modelPoint(middle).x - transform.modelPoint(middle).x) < 0.001)
        #expect(abs(actual.modelPoint(middle).y - transform.modelPoint(middle).y) < 0.001)
    }

    @Test func aFitPutsTheWholeRectangleInTheViewWithItsMargin() {
        let view = CGSize(width: 1000, height: 800)
        let picture = CGRect(x: 200, y: 100, width: 2000, height: 1000)

        let fitted = CanvasTransform().fitting(picture, in: view)

        // The picture is 2000 wide in a view 1000 wide less two 40 point
        // margins, so the zoom is 920/2000.
        #expect(abs(fitted.zoom - 0.46) < 0.001)
        let drawn = CGRect(
            x: fitted.viewPoint(CGPoint(x: picture.minX, y: picture.minY)).x,
            y: fitted.viewPoint(CGPoint(x: picture.minX, y: picture.minY)).y,
            width: picture.width * fitted.zoom,
            height: picture.height * fitted.zoom
        )
        #expect(drawn.minX >= CanvasTransform.fitMargin - 0.001)
        #expect(drawn.maxX <= view.width - CanvasTransform.fitMargin + 0.001)
        #expect(abs(drawn.midY - view.height / 2) < 0.001)
    }

    @Test func aFitOfNothingChangesNothing() {
        let transform = CanvasTransform(pan: CGSize(width: 5, height: 5), zoom: 2)

        #expect(
            transform.fitting(CGRect.zero, in: CGSize(width: 800, height: 600)) == transform
        )
        #expect(
            transform.fitting(
                CGRect(x: 0, y: 0, width: 100, height: 100),
                in: .zero
            ) == transform
        )
    }

    @Test func aFitNeverGoesPastTheZoomLimits() {
        let view = CGSize(width: 800, height: 600)

        let tiny = CanvasTransform().fitting(
            CGRect(x: 0, y: 0, width: 100_000, height: 100_000),
            in: view
        )
        let huge = CanvasTransform().fitting(CGRect(x: 0, y: 0, width: 4, height: 4), in: view)

        #expect(tiny.zoom == CanvasTransform.minimumZoom)
        #expect(huge.zoom == CanvasTransform.maximumZoom)
    }

    @Test func statesTheZoomAsAPercentage() {
        #expect(CanvasTransform(zoom: 1).percentage == 100)
        #expect(CanvasTransform(zoom: 0.5).percentage == 50)
        #expect(CanvasTransform(zoom: 1.25).percentage == 125)
    }
}
