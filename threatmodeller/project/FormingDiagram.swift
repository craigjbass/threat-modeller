import CoreGraphics
import ThreatModelKit

/// The fit the layout preview draws at.
///
/// This was the view that drew the shape of a picture forming: a rectangle
/// for each component and an outline for each zone, because a layout report
/// holds geometry and nothing else. `FormingPicture` now draws the real
/// diagram over the subject the search states, and what is left here is the
/// fit alone.
///
/// The rectangle is measured the way `CanvasGestures.zoomToFit` measures the
/// model, so the preview and Zoom to Fit give one transform and the picture
/// does not move when the canvas takes over.
nonisolated enum FormingDiagram {
    /// The rectangle one layout report covers, or nil when the report placed
    /// nothing.
    static func rect(of layout: LayOutModelResponse) -> CGRect? {
        SelectionBounds.rect(
            components: layout.components.map {
                ($0.x, $0.y, Component.size.width, Component.size.height)
            },
            zones: layout.zones.map { ($0.x, $0.y, $0.width, $0.height) }
        )
    }
}
