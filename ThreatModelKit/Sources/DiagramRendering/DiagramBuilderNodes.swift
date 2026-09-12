import Foundation
import ThreatModelKit

extension DiagramBuilder {
    // MARK: the nodes

    static func nodeShapes(_ model: Model, boxes: [String: Rect]) -> [DrawnShape] {
        model.components.flatMap { component -> [DrawnShape] in
            guard let rect = boxes[component.id] else { return [] }

            let source = "component:\(component.id)"
            let risk = model.risks[source]
            let outOfScope = component.threatsDisabled
            let strength = model.strength(of: source)
            let focused = model.isFocused(source)
            let colour = (outOfScope
                ? DiagramColour.quiet
                : DiagramColour.forLevel(risk?.highestLevelId)).faded(to: strength)
            let style = DiagramStyle(
                stroke: colour,
                width: focused ? DiagramBuilder.focusWidth : 1.5,
                dash: outOfScope ? [6, 4] : []
            )
            var built: [DrawnShape] = []

            switch shape(of: component) {
            case .actor:
                built.append(.rectangle(rect, cornerRadius: 4, DiagramStyle(fill: .paper)))
                built.append(.rectangle(rect, cornerRadius: 4, style))
            case .process:
                built.append(.ellipse(rect, DiagramStyle(fill: .paper)))
                built.append(.ellipse(rect, style))
            case .store:
                built.append(
                    .path(
                        [
                            .move(Point(x: rect.minX, y: rect.minY)),
                            .line(Point(x: rect.maxX, y: rect.minY)),
                            .move(Point(x: rect.minX, y: rect.maxY)),
                            .line(Point(x: rect.maxX, y: rect.maxY))
                        ],
                        style
                    )
                )
            }

            let middle = Point(x: rect.minX + rect.size.width / 2, y: rect.minY + rect.size.height / 2)
            built.append(
                .text(
                    shortName(of: component.name),
                    at: Point(x: middle.x, y: middle.y + 4),
                    anchor: .centre,
                    size: nodeLabelSize,
                    bold: true,
                    (outOfScope ? DiagramColour.quiet : .ink).faded(to: strength)
                )
            )

            var chips = [
                component.providerId.isEmpty ? "unknown" : component.providerId.uppercased(),
                component.sensitivityId.capitalized
            ]
            if let zoneId = component.zoneId,
               let zone = model.zones.first(where: { $0.id == zoneId }) {
                chips.append(shortName(of: zone.name))
            }
            built.append(
                .text(
                    chips.joined(separator: "  \u{00B7}  "),
                    at: Point(x: middle.x, y: rect.maxY + 14),
                    anchor: .centre,
                    size: chipSize,
                    bold: false,
                    DiagramColour.quiet.faded(to: strength)
                )
            )

            if outOfScope == false, let open = risk?.openCount, open > 0 {
                let badge = Rect(x: rect.maxX - 8, y: rect.minY - 8, width: 18, height: 16)
                built.append(
                    .rectangle(badge, cornerRadius: 8, DiagramStyle(stroke: colour, fill: .paper, width: 1))
                )
                built.append(
                    .text(
                        "\(open)",
                        at: Point(x: badge.minX + 9, y: badge.minY + 11),
                        anchor: .centre,
                        size: chipSize,
                        bold: true,
                        colour
                    )
                )
            }

            return built
        }
    }

    // MARK: the labels

    static func calloutShapes(
        _ model: Model,
        curves: [String: FlowCurve],
        nodes: [Rect],
        bands: [Rect],
        chips: [Rect]
    ) -> [DrawnShape] {
        let labels = model.connections.compactMap {
            connection -> (connectionId: String, text: String, curve: FlowCurve)? in
            guard let curve = curves[connection.id] else { return nil }
            let described = connection.description?.trimmingCharacters(in: .whitespaces) ?? ""
            let text = described.isEmpty
                ? (FlowKind(rawValue: connection.kindId)?.label ?? connection.kindId)
                : described
            return (connection.id, text, curve)
        }

        let placed = CalloutPlacement.place(
            labels,
            nodes: nodes,
            zoneHeaders: bands,
            boundaryChips: chips,
            flows: curves.values.map { CurveCrossing.samples(of: $0) },
            flowsById: curves.mapValues { CurveCrossing.samples(of: $0) }
        )
        var built: [DrawnShape] = []

        for callout in placed {
            let source = "connection:\(callout.connectionId)"
            let colour = DiagramColour
                .forLevel(model.risks[source]?.highestLevelId)
                .faded(to: model.strength(of: source))
            let middle = Point(
                x: callout.rect.minX + callout.rect.size.width / 2,
                y: callout.rect.minY + callout.rect.size.height / 2
            )

            built.append(
                .path(
                    [.move(middle), .line(callout.anchor)],
                    DiagramStyle(stroke: colour.faded(to: 0.5), width: 1, dash: [3, 3])
                )
            )
            built.append(
                .rectangle(
                    callout.rect,
                    cornerRadius: 5,
                    DiagramStyle(stroke: colour.faded(to: 0.6), fill: .paper, width: 1)
                )
            )
            built.append(
                .ellipse(
                    Rect(x: callout.anchor.x - 2.5, y: callout.anchor.y - 2.5, width: 5, height: 5),
                    DiagramStyle(fill: colour)
                )
            )

            let lines = CalloutPlacement.lines(of: callout.text)
            for (index, line) in lines.enumerated() {
                built.append(
                    .text(
                        line,
                        at: Point(
                            x: callout.rect.minX + 6,
                            y: callout.rect.minY + CalloutPlacement.padding / 2
                                + (Double(index) + 0.75) * CalloutPlacement.lineHeight
                        ),
                        anchor: .leading,
                        size: chipSize,
                        bold: false,
                        colour
                    )
                )
            }
        }

        return built
    }

    /// The text broken into lines, which is `CalloutPlacement.lines(of:)`. The
    /// core owns the rule, because the box is measured from it.
    public static func wrapped(_ text: String, perLine: Int) -> [String] {
        CalloutPlacement.lines(of: text, perLine: perLine)
    }
}
