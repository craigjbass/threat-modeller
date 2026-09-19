import CoreGraphics

/// Converts between model coordinates and canvas view coordinates.
///
/// The canvas draws its content with
/// `.scaleEffect(zoom, anchor: .topLeading).offset(pan)`, so a model point
/// lands at `modelPoint * zoom + pan`.
nonisolated struct CanvasTransform: Equatable {
    static let minimumZoom: CGFloat = 0.25
    static let maximumZoom: CGFloat = 4.0

    let pan: CGSize
    let zoom: CGFloat

    init(pan: CGSize = .zero, zoom: CGFloat = 1) {
        self.pan = pan
        self.zoom = Self.clamp(zoom)
    }

    static func clamp(_ zoom: CGFloat) -> CGFloat {
        min(max(zoom, minimumZoom), maximumZoom)
    }

    func viewPoint(_ modelPoint: CGPoint) -> CGPoint {
        CGPoint(x: modelPoint.x * zoom + pan.width, y: modelPoint.y * zoom + pan.height)
    }

    func modelPoint(_ viewPoint: CGPoint) -> CGPoint {
        CGPoint(x: (viewPoint.x - pan.width) / zoom, y: (viewPoint.y - pan.height) / zoom)
    }

    /// The model distance a view distance covers. A drag translation arrives in
    /// view points and has to become a move in model units.
    func modelDistance(_ viewDistance: CGSize) -> CGSize {
        CGSize(width: viewDistance.width / zoom, height: viewDistance.height / zoom)
    }

    /// One press of Zoom In. Zoom Out is one press of its reciprocal.
    static let zoomStep: CGFloat = 1.25

    /// The room a fit keeps around the picture.
    static let fitMargin: CGFloat = 40

    /// Zooms about the middle of the visible canvas, so the thing a person is
    /// looking at stays where they are looking.
    func zoomedAboutTheCentre(by factor: CGFloat, of size: CGSize) -> CanvasTransform {
        zoomed(by: factor, about: CGPoint(x: size.width / 2, y: size.height / 2))
    }

    /// The zoom that puts the picture at its own size, with the point under
    /// the middle of the visible canvas left where it is.
    func atActualSize(in size: CGSize) -> CanvasTransform {
        zoomedAboutTheCentre(by: 1 / zoom, of: size)
    }

    /// The transform that fits a rectangle of the model into the visible
    /// canvas, with a margin, and puts the middle of that rectangle in the
    /// middle of the view.
    ///
    /// A rectangle of nothing, or a view of nothing, leaves the transform as
    /// it is: there is nothing to fit.
    func fitting(_ rect: CGRect, in size: CGSize, margin: CGFloat = fitMargin) -> CanvasTransform {
        guard rect.width > 0, rect.height > 0, size.width > 0, size.height > 0 else { return self }

        let room = CGSize(
            width: max(size.width - margin * 2, 1),
            height: max(size.height - margin * 2, 1)
        )
        let fitted = Self.clamp(min(room.width / rect.width, room.height / rect.height))

        return CanvasTransform(
            pan: CGSize(
                width: size.width / 2 - rect.midX * fitted,
                height: size.height / 2 - rect.midY * fitted
            ),
            zoom: fitted
        )
    }

    /// What the zoom reads as, for the control that states it.
    var percentage: Int { Int((zoom * 100).rounded()) }

    func panned(by translation: CGSize) -> CanvasTransform {
        CanvasTransform(
            pan: CGSize(width: pan.width + translation.width, height: pan.height + translation.height),
            zoom: zoom
        )
    }

    /// Zooms about a fixed view point, so the model point under the pointer
    /// stays under the pointer. When the new zoom clamps, the pan changes to
    /// match the clamped zoom, which leaves the point where it was.
    func zoomed(by factor: CGFloat, about viewPoint: CGPoint) -> CanvasTransform {
        let anchor = modelPoint(viewPoint)
        let newZoom = Self.clamp(zoom * factor)
        return CanvasTransform(
            pan: CGSize(
                width: viewPoint.x - anchor.x * newZoom,
                height: viewPoint.y - anchor.y * newZoom
            ),
            zoom: newZoom
        )
    }
}
