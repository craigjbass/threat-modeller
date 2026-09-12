import AppKit
import SwiftUI
import ThreatModelKit

/// Turns the canvas into PNG bytes.
///
/// The picture is the canvas as drawn, so the delivery mechanism draws it. A
/// use case says what to draw and what to call the file; this reads that and
/// hands back the bytes.
@MainActor
struct CanvasImageRenderer {
    /// Two pixels per point, so the picture is sharp on the display it was
    /// drawn on and in a document someone prints.
    static let scale = 2.0

    enum RenderError: Error, Equatable {
        case cannotDrawImage
    }

    func png(
        of canvas: ViewThreatModelResponse,
        risks: [String: ElementRisk],
        guards: [String: [EdgeGuard]],
        area: ExportModelAsImageResponse
    ) throws -> Data {
        let renderer = ImageRenderer(
            content: CanvasPicture(
                components: canvas.components,
                connections: canvas.connections,
                zones: canvas.zones,
                risks: risks,
                guards: guards,
                origin: CGPoint(x: area.x, y: area.y),
                size: CGSize(width: area.width, height: area.height)
            )
        )
        renderer.scale = Self.scale

        guard let image = renderer.cgImage else { throw RenderError.cannotDrawImage }
        let bitmap = NSBitmapImageRep(cgImage: image)
        guard let data = bitmap.representation(using: .png, properties: [:]) else {
            throw RenderError.cannotDrawImage
        }
        return data
    }
}
