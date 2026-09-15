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

    /// The same picture as PDF bytes, so an application that takes vector art
    /// gets vector art. One picture, two flavours, and the person pasting
    /// takes whichever their application reads.
    func pdf(
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

        let bytes = NSMutableData()
        var drawn = false
        renderer.render { size, draw in
            var box = CGRect(origin: .zero, size: size)
            guard let consumer = CGDataConsumer(data: bytes),
                  let context = CGContext(consumer: consumer, mediaBox: &box, nil) else { return }
            context.beginPDFPage(nil)
            draw(context)
            context.endPDFPage()
            context.closePDF()
            drawn = true
        }
        guard drawn, bytes.length > 0 else { throw RenderError.cannotDrawImage }
        return bytes as Data
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
