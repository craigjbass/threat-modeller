import CoreGraphics

/// What every canvas holds for its viewport: the transform, the room it
/// draws in, and the two background drags in flight.
///
/// The architecture canvas and the tree canvas draw different things and
/// select different things, and they pan, zoom and marquee the same way. The
/// design in `docs/superpowers/specs/2026-09-16-attack-tree-stage-design.md`
/// states this protocol as what the two share.
@MainActor
protocol CanvasViewport: AnyObject {
    var transform: CanvasTransform { get set }
    /// How big the visible canvas is. Zoom to Fit and a zoom step need it.
    var visibleSize: CGSize { get set }
    /// True while a pan is in flight, so the pointer shows a closed hand.
    var isPanning: Bool { get set }
    /// How much of a drag has already been applied to the pan.
    var lastPanTranslation: CGSize { get set }
    /// The marquee's two corners in model coordinates while a marquee drag is
    /// in flight.
    var marquee: (start: CGPoint, end: CGPoint)? { get set }
}

/// The gesture rules that do not depend on what a canvas draws.
///
/// `CanvasGestures` and `TreeCanvasGestures` call these for pan, marquee,
/// scroll and zoom, so one rule moves both canvases. This type draws nothing
/// and calls no use case.
@MainActor
struct ViewportGestures {
    let viewport: any CanvasViewport

    // MARK: the background drags

    /// A plain drag on the background. A drag reports the translation from
    /// where it started, so the pan applies the step since the last change,
    /// not the whole translation again.
    func panDragChanged(by translation: CGSize) {
        let step = CGSize(
            width: translation.width - viewport.lastPanTranslation.width,
            height: translation.height - viewport.lastPanTranslation.height
        )
        viewport.lastPanTranslation = translation
        viewport.transform = viewport.transform.panned(by: step)
        viewport.isPanning = true
    }

    /// A shift-drag on the background. The corners are held in model
    /// coordinates, so the rectangle is over the same things at any zoom.
    func marqueeDragChanged(from start: CGPoint, to end: CGPoint) {
        viewport.marquee = (
            start: viewport.transform.modelPoint(start),
            end: viewport.transform.modelPoint(end)
        )
    }

    /// The end of either background drag. It gives the marquee's rectangle in
    /// model coordinates when a marquee was in flight, and nil after a pan.
    @discardableResult
    func dragEnded() -> CGRect? {
        viewport.lastPanTranslation = .zero
        viewport.isPanning = false
        let rect = viewport.marquee.map { MarqueeSelection.rect(from: $0.start, to: $0.end) }
        viewport.marquee = nil
        return rect
    }

    /// A two finger scroll moves the canvas, by the same transform a drag
    /// moves it by.
    ///
    /// macOS states a scrolling delta that already answers the person's own
    /// natural-scrolling setting, so the delta is applied as it arrives.
    func scroll(by delta: CGSize) {
        viewport.transform = viewport.transform.panned(by: delta)
    }

    // MARK: zoom

    func zoom(by factor: CGFloat, about viewPoint: CGPoint) {
        viewport.transform = viewport.transform.zoomed(by: factor, about: viewPoint)
    }

    /// One press of Zoom In or Zoom Out. The point under the middle of the
    /// visible canvas stays where it is.
    func zoomAStep(in closer: Bool) {
        viewport.transform = viewport.transform.zoomedAboutTheCentre(
            by: closer ? CanvasTransform.zoomStep : 1 / CanvasTransform.zoomStep,
            of: viewport.visibleSize
        )
    }

    func zoomToActualSize() {
        viewport.transform = viewport.transform.atActualSize(in: viewport.visibleSize)
    }

    /// Fits a rectangle of the model in the visible canvas. A rectangle of
    /// nothing changes nothing: there is nothing to fit.
    func fit(_ rect: CGRect?) {
        guard let rect else { return }
        viewport.transform = viewport.transform.fitting(rect, in: viewport.visibleSize)
    }
}

/// The zoom commands the View menu and the floating panel call, on whichever
/// canvas is in front. `CanvasGestures` and `TreeCanvasGestures` conform.
@MainActor
protocol CanvasZooming {
    func zoomAStep(in closer: Bool)
    func zoomToActualSize()
    func zoomToFit()
    func zoomToSelection()
}
