import CoreGraphics
import Testing
@testable import threatmodeller

/// The gesture rules both canvases share: pan, marquee corners, scroll and
/// zoom. The design in
/// `docs/superpowers/specs/2026-09-16-attack-tree-stage-design.md` states one
/// rule moves both canvases, so each rule is stated once here against a
/// viewport of either kind.
@MainActor
struct ViewportGesturesTests {
    private func viewports() -> [(String, any CanvasViewport)] {
        [("the architecture canvas", CanvasState()), ("the tree canvas", TreeCanvasState())]
    }

    @Test func aPlainDragPansByTheStepSinceTheLastChange() {
        for (name, viewport) in viewports() {
            let gestures = ViewportGestures(viewport: viewport)

            gestures.panDragChanged(by: CGSize(width: 10, height: 5))
            gestures.panDragChanged(by: CGSize(width: 30, height: 15))

            #expect(viewport.transform.pan == CGSize(width: 30, height: 15), Comment(rawValue: name))
            #expect(viewport.isPanning, Comment(rawValue: name))
            #expect(viewport.lastPanTranslation == CGSize(width: 30, height: 15), Comment(rawValue: name))
        }
    }

    @Test func theEndOfADragClearsThePanAndGivesNoMarquee() {
        for (name, viewport) in viewports() {
            let gestures = ViewportGestures(viewport: viewport)
            gestures.panDragChanged(by: CGSize(width: 10, height: 5))

            let marquee = gestures.dragEnded()

            #expect(marquee == nil, Comment(rawValue: name))
            #expect(viewport.isPanning == false, Comment(rawValue: name))
            #expect(viewport.lastPanTranslation == .zero, Comment(rawValue: name))
        }
    }

    /// The corners are held in model coordinates, so a marquee drawn on a
    /// zoomed canvas selects what is under it, not what is under the same
    /// view points at actual size.
    @Test func aShiftDragHoldsTheMarqueeCornersInModelCoordinates() {
        for (name, viewport) in viewports() {
            viewport.transform = CanvasTransform(pan: CGSize(width: 100, height: 100), zoom: 2)
            let gestures = ViewportGestures(viewport: viewport)

            gestures.marqueeDragChanged(from: CGPoint(x: 100, y: 100), to: CGPoint(x: 300, y: 200))
            let rect = gestures.dragEnded()

            #expect(rect == CGRect(x: 0, y: 0, width: 100, height: 50), Comment(rawValue: name))
            #expect(viewport.marquee == nil, Comment(rawValue: name))
        }
    }

    @Test func aScrollPansByTheDeltaAsItArrives() {
        for (name, viewport) in viewports() {
            let gestures = ViewportGestures(viewport: viewport)

            gestures.scroll(by: CGSize(width: 30, height: -20))

            #expect(viewport.transform.pan == CGSize(width: 30, height: -20), Comment(rawValue: name))
        }
    }

    @Test func aZoomStepKeepsTheMiddleOfTheVisibleCanvasWhereItIs() {
        for (name, viewport) in viewports() {
            viewport.visibleSize = CGSize(width: 800, height: 600)
            let gestures = ViewportGestures(viewport: viewport)
            let middle = viewport.transform.modelPoint(CGPoint(x: 400, y: 300))

            gestures.zoomAStep(in: true)

            #expect(viewport.transform.zoom == CanvasTransform.zoomStep, Comment(rawValue: name))
            #expect(viewport.transform.modelPoint(CGPoint(x: 400, y: 300)) == middle, Comment(rawValue: name))
        }
    }

    @Test func actualSizePutsTheZoomBackToOne() {
        for (name, viewport) in viewports() {
            viewport.visibleSize = CGSize(width: 800, height: 600)
            viewport.transform = CanvasTransform(zoom: 2)
            let gestures = ViewportGestures(viewport: viewport)

            gestures.zoomToActualSize()

            #expect(viewport.transform.zoom == 1, Comment(rawValue: name))
        }
    }

    @Test func aFitPutsTheRectangleInTheMiddleOfTheVisibleCanvas() {
        for (name, viewport) in viewports() {
            viewport.visibleSize = CGSize(width: 800, height: 600)
            let gestures = ViewportGestures(viewport: viewport)

            gestures.fit(CGRect(x: 1000, y: 1000, width: 200, height: 100))

            let centre = viewport.transform.viewPoint(CGPoint(x: 1100, y: 1050))
            #expect(centre == CGPoint(x: 400, y: 300), Comment(rawValue: name))
        }
    }

    @Test func aFitOfNothingChangesNothing() {
        for (name, viewport) in viewports() {
            viewport.visibleSize = CGSize(width: 800, height: 600)
            let before = viewport.transform
            let gestures = ViewportGestures(viewport: viewport)

            gestures.fit(nil)

            #expect(viewport.transform == before, Comment(rawValue: name))
        }
    }
}
