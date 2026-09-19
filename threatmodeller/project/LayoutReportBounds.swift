import CoreGraphics
import ThreatModelKit

/// The rectangle one layout report covers, or nil when the report placed
/// nothing.
///
/// The rectangle is measured the way `CanvasGestures.zoomToFit` measures the
/// model, so the preview and Zoom to Fit give one transform and the picture
/// does not move when the canvas takes over.
nonisolated enum LayoutReportBounds {
    static func rect(of layout: LayOutModelResponse) -> CGRect? {
        SelectionBounds.rect(
            components: layout.components.map {
                ($0.x, $0.y, Component.size.width, Component.size.height)
            },
            zones: layout.zones.map { ($0.x, $0.y, $0.width, $0.height) }
        )
    }
}
