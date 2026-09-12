import Foundation
import ThreatModelKit

/// Writes a drawing as SVG.
///
/// SVG is text, so this runs wherever Swift runs, which is what the command
/// line tool needs: it ships as a static Linux binary and has no window to
/// draw in.
public enum SvgWriter {
    public static let font = "-apple-system, BlinkMacSystemFont, 'Helvetica Neue', Arial, sans-serif"

    public static func svg(of drawing: DiagramDrawing) -> String {
        let width = Int(drawing.size.width.rounded(.up))
        let height = Int(drawing.size.height.rounded(.up))
        let box = "\(number(drawing.origin.x)) \(number(drawing.origin.y)) "
            + "\(number(drawing.size.width)) \(number(drawing.size.height))"

        var lines = [
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"\(width)\" height=\"\(height)\" "
                + "viewBox=\"\(box)\">",
            "<rect x=\"\(number(drawing.origin.x))\" y=\"\(number(drawing.origin.y))\" "
                + "width=\"\(number(drawing.size.width))\" height=\"\(number(drawing.size.height))\" "
                + "fill=\"\(colour(drawing.background))\"/>"
        ]

        lines += drawing.shapes.map(element(of:))
        lines.append("</svg>")

        return lines.joined(separator: "\n") + "\n"
    }

    // MARK: one shape

    static func element(of shape: DrawnShape) -> String {
        switch shape {
        case .rectangle(let rect, let radius, let style):
            return "<rect x=\"\(number(rect.minX))\" y=\"\(number(rect.minY))\" "
                + "width=\"\(number(rect.size.width))\" height=\"\(number(rect.size.height))\" "
                + "rx=\"\(number(radius))\" \(paint(style))/>"

        case .ellipse(let rect, let style):
            return "<ellipse cx=\"\(number(rect.minX + rect.size.width / 2))\" "
                + "cy=\"\(number(rect.minY + rect.size.height / 2))\" "
                + "rx=\"\(number(rect.size.width / 2))\" ry=\"\(number(rect.size.height / 2))\" "
                + "\(paint(style))/>"

        case .path(let steps, let style):
            return "<path d=\"\(data(of: steps))\" \(paint(style))/>"

        case .text(let text, let point, let anchor, let size, let bold, let ink):
            return textElement(text, at: point, anchor: anchor, size: size, bold: bold, ink: ink)
        }
    }

    static func textElement(
        _ text: String,
        at point: Point,
        anchor: TextAnchor,
        size: Double,
        bold: Bool,
        ink: DiagramColour
    ) -> String {
        let placed: String
        switch anchor {
        case .leading: placed = "start"
        case .centre: placed = "middle"
        case .trailing: placed = "end"
        }

        var parts: [String] = ["<text"]
        parts.append("x=\"\(number(point.x))\"")
        parts.append("y=\"\(number(point.y))\"")
        parts.append("text-anchor=\"\(placed)\"")
        parts.append("font-family=\"\(font)\"")
        parts.append("font-size=\"\(number(size))\"")
        parts.append("font-weight=\"\(bold ? "600" : "400")\"")
        parts.append("fill=\"\(colour(ink))\">")

        return parts.joined(separator: " ") + escaped(text) + "</text>"
    }

    static func data(of steps: [PathStep]) -> String {
        steps.map { step in
            switch step {
            case .move(let point): "M \(number(point.x)) \(number(point.y))"
            case .line(let point): "L \(number(point.x)) \(number(point.y))"
            case .cubic(let one, let other, let end):
                "C \(number(one.x)) \(number(one.y)) \(number(other.x)) \(number(other.y)) "
                    + "\(number(end.x)) \(number(end.y))"
            case .quadratic(let control, let end):
                "Q \(number(control.x)) \(number(control.y)) \(number(end.x)) \(number(end.y))"
            case .close: "Z"
            }
        }
        .joined(separator: " ")
    }

    static func paint(_ style: DiagramStyle) -> String {
        var parts: [String] = []

        parts.append("fill=\"\(style.fill.map(colour) ?? "none")\"")
        if let stroke = style.stroke {
            parts.append("stroke=\"\(colour(stroke))\"")
            parts.append("stroke-width=\"\(number(style.width))\"")
            parts.append("stroke-linecap=\"round\"")
            if style.dash.isEmpty == false {
                parts.append("stroke-dasharray=\"\(style.dash.map(number).joined(separator: " "))\"")
            }
        }
        if let fill = style.fill, fill.alpha < 1 {
            parts.append("fill-opacity=\"\(number(fill.alpha))\"")
        }
        if let stroke = style.stroke, stroke.alpha < 1 {
            parts.append("stroke-opacity=\"\(number(stroke.alpha))\"")
        }

        return parts.joined(separator: " ")
    }

    static func colour(_ colour: DiagramColour) -> String {
        func channel(_ value: Double) -> String {
            String(format: "%02X", Int((min(max(value, 0), 1) * 255).rounded()))
        }
        return "#\(channel(colour.red))\(channel(colour.green))\(channel(colour.blue))"
    }

    /// A number with no trailing zeros, so a diff of one moved node is one
    /// line rather than a thousand.
    static func number(_ value: Double) -> String {
        let rounded = (value * 100).rounded() / 100
        return rounded == rounded.rounded()
            ? String(Int(rounded))
            : String(format: "%g", rounded)
    }

    static func escaped(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }
}
