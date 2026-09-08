import CoreGraphics

/// Converts between model coordinates and canvas view coordinates.
///
/// The canvas draws its content with
/// `.scaleEffect(zoom, anchor: .topLeading).offset(pan)`, so a model point
/// lands at `modelPoint * zoom + pan`.
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a pure value with no shared state.
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
