import Foundation
import ThreatModelKit

#if canImport(CoreGraphics) && canImport(ImageIO) && canImport(UniformTypeIdentifiers)
import CoreGraphics
import CoreText
import ImageIO
import UniformTypeIdentifiers
#endif

/// Writes a drawing as PNG, where the platform can draw one.
///
/// Apple's platforms supply a drawing engine, so this uses it. A static Linux
/// build has none, and answers nil rather than writing a broken file: the
/// command says PNG is not available and points at SVG.
public enum PngWriter {
    /// Two pixels per point, so the picture is sharp on a display and in a
    /// document someone prints.
    public static let scale = 2.0

    #if canImport(CoreGraphics) && canImport(ImageIO) && canImport(UniformTypeIdentifiers)
    public static func png(of drawing: DiagramDrawing) -> Data? {
        let width = Int((drawing.size.width * scale).rounded(.up))
        let height = Int((drawing.size.height * scale).rounded(.up))
        guard width > 0, height > 0 else { return nil }

        guard let context = CGContext(
            data: nil,
            width: width,
            height: height,
            bitsPerComponent: 8,
            bytesPerRow: 0,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        ) else { return nil }

        // The diagram measures down the page; a bitmap measures up it.
        context.translateBy(x: 0, y: Double(height))
        context.scaleBy(x: scale, y: -scale)
        context.translateBy(x: -drawing.origin.x, y: -drawing.origin.y)

        context.setFillColor(cgColour(drawing.background))
        context.fill(
            CGRect(
                x: drawing.origin.x,
                y: drawing.origin.y,
                width: drawing.size.width,
                height: drawing.size.height
            )
        )

        for shape in drawing.shapes { draw(shape, in: context) }

        guard let image = context.makeImage() else { return nil }
        let bytes = NSMutableData()
        guard let sink = CGImageDestinationCreateWithData(
            bytes as CFMutableData,
            UTType.png.identifier as CFString,
            1,
            nil
        ) else { return nil }

        CGImageDestinationAddImage(sink, image, nil)
        guard CGImageDestinationFinalize(sink) else { return nil }
        return bytes as Data
    }

    // MARK: one shape

    private static func draw(_ shape: DrawnShape, in context: CGContext) {
        switch shape {
        case .rectangle(let rect, let radius, let style):
            let path = CGPath(
                roundedRect: cgRect(rect),
                cornerWidth: radius,
                cornerHeight: radius,
                transform: nil
            )
            paint(path, style: style, in: context)

        case .ellipse(let rect, let style):
            paint(CGPath(ellipseIn: cgRect(rect), transform: nil), style: style, in: context)

        case .path(let steps, let style):
            let path = CGMutablePath()
            for step in steps {
                switch step {
                case .move(let point): path.move(to: CGPoint(x: point.x, y: point.y))
                case .line(let point): path.addLine(to: CGPoint(x: point.x, y: point.y))
                case .cubic(let one, let other, let end):
                    path.addCurve(
                        to: CGPoint(x: end.x, y: end.y),
                        control1: CGPoint(x: one.x, y: one.y),
                        control2: CGPoint(x: other.x, y: other.y)
                    )
                case .quadratic(let control, let end):
                    path.addQuadCurve(
                        to: CGPoint(x: end.x, y: end.y),
                        control: CGPoint(x: control.x, y: control.y)
                    )
                case .close: path.closeSubpath()
                }
            }
            paint(path, style: style, in: context)

        case .text(let text, let point, let anchor, let size, let bold, let ink):
            write(text, at: point, anchor: anchor, size: size, bold: bold, ink: ink, in: context)
        }
    }

    private static func paint(_ path: CGPath, style: DiagramStyle, in context: CGContext) {
        if let fill = style.fill {
            context.setFillColor(cgColour(fill))
            context.addPath(path)
            context.fillPath()
        }
        guard let stroke = style.stroke else { return }

        context.setStrokeColor(cgColour(stroke))
        context.setLineWidth(style.width)
        context.setLineCap(.round)
        context.setLineDash(phase: 0, lengths: style.dash.map { CGFloat($0) })
        context.addPath(path)
        context.strokePath()
        context.setLineDash(phase: 0, lengths: [])
    }

    private static func write(
        _ text: String,
        at point: Point,
        anchor: TextAnchor,
        size: Double,
        bold: Bool,
        ink: DiagramColour,
        in context: CGContext
    ) {
        let font = CTFontCreateWithName(
            (bold ? "HelveticaNeue-Medium" : "HelveticaNeue") as CFString,
            size,
            nil
        )
        let attributed = NSAttributedString(
            string: text,
            attributes: [
                NSAttributedString.Key(kCTFontAttributeName as String): font,
                NSAttributedString.Key(kCTForegroundColorAttributeName as String): cgColour(ink)
            ]
        )
        let line = CTLineCreateWithAttributedString(attributed)
        let width = CTLineGetTypographicBounds(line, nil, nil, nil)

        let x: Double
        switch anchor {
        case .leading: x = point.x
        case .centre: x = point.x - width / 2
        case .trailing: x = point.x - width
        }

        // The bitmap is flipped, so the text is flipped back to read the right
        // way up.
        context.saveGState()
        context.textMatrix = CGAffineTransform(scaleX: 1, y: -1)
        context.textPosition = CGPoint(x: x, y: point.y)
        CTLineDraw(line, context)
        context.restoreGState()
    }

    private static func cgRect(_ rect: Rect) -> CGRect {
        CGRect(x: rect.minX, y: rect.minY, width: rect.size.width, height: rect.size.height)
    }

    private static func cgColour(_ colour: DiagramColour) -> CGColor {
        CGColor(red: colour.red, green: colour.green, blue: colour.blue, alpha: colour.alpha)
    }
    #else
    /// This build has no drawing engine.
    public static func png(of drawing: DiagramDrawing) -> Data? { nil }
    #endif
}
