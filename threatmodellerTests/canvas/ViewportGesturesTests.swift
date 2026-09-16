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

    // MARK: the pointer mode

    /// How close two model points have to be to count as the same point. A
    /// zoom about a pointer divides and multiplies by the same zoom, so the
    /// answer carries a little floating point error.
    private func isClose(_ one: CGPoint, _ other: CGPoint) -> Bool {
        abs(one.x - other.x) < 0.0001 && abs(one.y - other.y) < 0.0001
    }

    /// Trackpad mode is what both canvases always did: the wheel delta pans.
    @Test func aWheelInTrackpadModePansByTheDelta() {
        for (name, viewport) in viewports() {
            let gestures = ViewportGestures(viewport: viewport)

            gestures.wheel(
                by: CGSize(width: 30, height: -20),
                at: CGPoint(x: 100, y: 100),
                isShiftDown: false,
                mode: .trackpad
            )

            #expect(viewport.transform.pan == CGSize(width: 30, height: -20), Comment(rawValue: name))
            #expect(viewport.transform.zoom == 1, Comment(rawValue: name))
        }
    }

    /// A mouse has a wheel and no pinch. The wheel zooms, and the model point
    /// under the pointer stays under the pointer.
    @Test func aWheelInMouseModeZoomsAboutThePointer() {
        for (name, viewport) in viewports() {
            let gestures = ViewportGestures(viewport: viewport)
            let pointer = CGPoint(x: 240, y: 180)
            let under = viewport.transform.modelPoint(pointer)

            gestures.wheel(
                by: CGSize(width: 0, height: 20),
                at: pointer,
                isShiftDown: false,
                mode: .mouse
            )

            #expect(viewport.transform.zoom > 1, Comment(rawValue: name))
            #expect(isClose(viewport.transform.modelPoint(pointer), under), Comment(rawValue: name))
        }
    }

    /// A wheel towards the person zooms out.
    @Test func aWheelTowardsThePersonInMouseModeZoomsOut() {
        for (name, viewport) in viewports() {
            let gestures = ViewportGestures(viewport: viewport)

            gestures.wheel(
                by: CGSize(width: 0, height: -20),
                at: CGPoint(x: 240, y: 180),
                isShiftDown: false,
                mode: .mouse
            )

            #expect(viewport.transform.zoom < 1, Comment(rawValue: name))
        }
    }

    /// Shift-wheel pans left and right, and changes no zoom.
    @Test func aShiftWheelInMouseModePansSideways() {
        for (name, viewport) in viewports() {
            let gestures = ViewportGestures(viewport: viewport)

            gestures.wheel(
                by: CGSize(width: 0, height: 24),
                at: CGPoint(x: 100, y: 100),
                isShiftDown: true,
                mode: .mouse
            )

            #expect(viewport.transform.pan == CGSize(width: 24, height: 0), Comment(rawValue: name))
            #expect(viewport.transform.zoom == 1, Comment(rawValue: name))
        }
    }

    /// macOS states a shifted wheel on the horizontal axis on some mice and
    /// on the vertical axis on others, so the pan reads whichever axis the
    /// event carries.
    @Test func aShiftWheelReadsTheAxisTheEventCarries() {
        for (name, viewport) in viewports() {
            let gestures = ViewportGestures(viewport: viewport)

            gestures.wheel(
                by: CGSize(width: 18, height: 0),
                at: CGPoint(x: 100, y: 100),
                isShiftDown: true,
                mode: .mouse
            )

            #expect(viewport.transform.pan == CGSize(width: 18, height: 0), Comment(rawValue: name))
        }
    }

    /// A middle-button drag and a Space-drag both state the step since the
    /// last event, so the pan adds each step as it arrives.
    @Test func aPanStepAddsEachStepAndShowsTheClosedHand() {
        for (name, viewport) in viewports() {
            let gestures = ViewportGestures(viewport: viewport)

            gestures.panStep(by: CGSize(width: 12, height: 8))
            gestures.panStep(by: CGSize(width: 3, height: 2))

            #expect(viewport.transform.pan == CGSize(width: 15, height: 10), Comment(rawValue: name))
            #expect(viewport.isPanning, Comment(rawValue: name))

            gestures.panStepEnded()

            #expect(viewport.isPanning == false, Comment(rawValue: name))
        }
    }
}
