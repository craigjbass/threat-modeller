import Foundation
import ThreatModelKit

/// Turns a threat model into the shapes a diagram draws.
///
/// Everything the application's canvas states is stated here too: the data
/// flow diagram shapes, the risk colour, the trust boundaries and what guards
/// them, the flows and their labels. What differs is that nothing here needs a
/// window, so the command line tool draws the same picture.
public enum DiagramBuilder {
    public static let padding = 60.0
    public static let nodeLabelSize = 12.0
    public static let chipSize = 8.5
    public static let zoneNameSize = 13.0

    public struct Model {
        public let components: [ViewedComponent]
        public let connections: [ViewedConnection]
        public let zones: [ViewedZone]
        public let risks: [String: ElementRisk]
        public let guards: [String: [EdgeGuard]]

        public init(
            components: [ViewedComponent],
            connections: [ViewedConnection],
            zones: [ViewedZone],
            risks: [String: ElementRisk] = [:],
            guards: [String: [EdgeGuard]] = [:]
        ) {
            self.components = components
            self.connections = connections
            self.zones = zones
            self.risks = risks
            self.guards = guards
        }
    }

    public static func drawing(of model: Model) -> DiagramDrawing {
        let boxes = Dictionary(
            uniqueKeysWithValues: model.components.map {
                ($0.id, Component.footprintRect(at: Point(x: $0.x, y: $0.y), shape: shape(of: $0)))
            }
        )
        let drawn = Dictionary(
            uniqueKeysWithValues: model.components.map {
                ($0.id, Component.drawnRect(at: Point(x: $0.x, y: $0.y), shape: shape(of: $0)))
            }
        )
        let bands = model.zones.map {
            Rect(x: $0.x, y: $0.y, width: $0.width, height: ZoneContainment.headerHeight)
        }

        var shapes: [DrawnShape] = []
        shapes += zoneShapes(model)

        let curves = flowCurves(model, boxes: boxes)
        shapes += flowShapes(model, curves: curves)

        let runs = boundaryRuns(model, curves: curves)
        let chips = chipRects(runs, bands: bands)
        shapes += boundaryShapes(runs, curves: curves, bands: bands)

        shapes += nodeShapes(model, boxes: boxes)
        shapes += calloutShapes(
            model,
            curves: curves,
            nodes: Array(drawn.values),
            bands: bands,
            chips: chips
        )

        // The picture is cut to what it drew, not to a guess: a label sits
        // where the placement put it, and only the shapes know where that is.
        let bounds = covered(by: shapes)

        return DiagramDrawing(
            origin: Point(x: bounds.minX - padding, y: bounds.minY - padding),
            size: Size(
                width: bounds.size.width + padding * 2,
                height: bounds.size.height + padding * 2
            ),
            shapes: shapes
        )
    }

    /// What the shapes cover between them.
    static func covered(by shapes: [DrawnShape]) -> Rect {
        var lowestX = Double.greatestFiniteMagnitude
        var lowestY = Double.greatestFiniteMagnitude
        var highestX = -Double.greatestFiniteMagnitude
        var highestY = -Double.greatestFiniteMagnitude

        func hold(_ point: Point) {
            lowestX = min(lowestX, point.x)
            lowestY = min(lowestY, point.y)
            highestX = max(highestX, point.x)
            highestY = max(highestY, point.y)
        }

        func hold(_ rect: Rect) {
            hold(Point(x: rect.minX, y: rect.minY))
            hold(Point(x: rect.maxX, y: rect.maxY))
        }

        for shape in shapes {
            switch shape {
            case .rectangle(let rect, _, _), .ellipse(let rect, _):
                hold(rect)
            case .path(let steps, _):
                for step in steps {
                    switch step {
                    case .move(let point), .line(let point): hold(point)
                    case .cubic(let one, let other, let end):
                        hold(one)
                        hold(other)
                        hold(end)
                    case .quadratic(let control, let end):
                        hold(control)
                        hold(end)
                    case .close: break
                    }
                }
            case .text(let text, let point, let anchor, let size, _, _):
                // A rough width: enough to keep the text inside the picture.
                let width = Double(text.count) * size * 0.6
                switch anchor {
                case .leading: hold(Point(x: point.x + width, y: point.y))
                case .centre:
                    hold(Point(x: point.x - width / 2, y: point.y))
                    hold(Point(x: point.x + width / 2, y: point.y))
                case .trailing: hold(Point(x: point.x - width, y: point.y))
                }
                hold(Point(x: point.x, y: point.y - size))
                hold(point)
            }
        }

        guard lowestX < highestX else { return Rect(x: 0, y: 0, width: 400, height: 400) }

        return Rect(
            x: lowestX,
            y: lowestY,
            width: highestX - lowestX,
            height: highestY - lowestY
        )
    }

    static func shape(of component: ViewedComponent) -> ThreatModelKit.DiagramShape {
        ThreatModelKit.DiagramShape(rawValue: component.shapeId) ?? .process
    }
}
