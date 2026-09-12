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

    public struct Model: Equatable, Sendable {
        public let components: [ViewedComponent]
        public let connections: [ViewedConnection]
        public let zones: [ViewedZone]
        public let risks: [String: ElementRisk]
        public let guards: [String: [EdgeGuard]]
        /// The one element this picture is about, as a source id, or nil when
        /// the picture is about all of it. What is not the focus draws quietly.
        public let focus: String?
        /// What the picture says it is about, written across the top.
        public let title: String?
        /// What the focus protects, by source id, with the count of threats it
        /// answers there. A picture of a control draws a dashed line to each
        /// one, because a control often guards a component no flow reaches it
        /// from.
        public let covers: [String: Int]

        public init(
            components: [ViewedComponent],
            connections: [ViewedConnection],
            zones: [ViewedZone],
            risks: [String: ElementRisk] = [:],
            guards: [String: [EdgeGuard]] = [:],
            focus: String? = nil,
            title: String? = nil,
            covers: [String: Int] = [:]
        ) {
            self.components = components
            self.connections = connections
            self.zones = zones
            self.risks = risks
            self.guards = guards
            self.focus = focus
            self.title = title
            self.covers = covers
        }

        /// How strongly one element draws. What the picture is not about draws
        /// at two fifths, so the eye finds what it is about.
        public func strength(of sourceId: String) -> Double {
            guard let focus else { return 1 }
            if sourceId == focus || covers[sourceId] != nil { return 1 }
            return 0.4
        }

        public func isFocused(_ sourceId: String) -> Bool { focus == sourceId }
    }

    /// How much heavier the one element a picture is about draws.
    public static let focusWidth = 3.5
    public static let titleSize = 15.0

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
        shapes += boundaryShapes(runs, curves: curves, bands: bands, model: model)

        shapes += coverShapes(model, boxes: boxes)
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
        var bounds = covered(by: shapes)

        if let title = model.title {
            shapes.insert(
                .text(
                    title,
                    at: Point(x: bounds.minX, y: bounds.minY - 12),
                    anchor: .leading,
                    size: titleSize,
                    bold: true,
                    .ink
                ),
                at: 0
            )
            bounds = Rect(
                x: bounds.minX,
                y: bounds.minY - titleSize - 14,
                width: max(bounds.size.width, Double(title.count) * titleSize * 0.55),
                height: bounds.size.height + titleSize + 14
            )
        }

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
