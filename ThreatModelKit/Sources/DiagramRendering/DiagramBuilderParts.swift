import Foundation
import ThreatModelKit

extension DiagramBuilder {
    // MARK: the zones

    static func zoneShapes(_ model: Model) -> [DrawnShape] {
        model.zones.flatMap { zone -> [DrawnShape] in
            let tint: DiagramColour = zone.networkZoneId == "private" ? .green : .orange
            let rect = Rect(x: zone.x, y: zone.y, width: zone.width, height: zone.height)
            var built: [DrawnShape] = [
                .rectangle(
                    rect,
                    cornerRadius: 12,
                    DiagramStyle(
                        stroke: tint.faded(to: 0.35),
                        fill: tint.faded(to: 0.04),
                        width: 1,
                        dash: [2, 4]
                    )
                ),
                .text(
                    zone.name,
                    at: Point(x: zone.x + 12, y: zone.y + 18),
                    anchor: .leading,
                    size: zoneNameSize,
                    bold: true,
                    .ink
                )
            ]

            if zone.networkZoneId == "private" && zone.riskReductionEnabled {
                built.append(
                    .text(
                        "\u{2212}\(zone.riskReductionPercent)%",
                        at: Point(x: zone.x + 12, y: zone.y + 33),
                        anchor: .leading,
                        size: chipSize,
                        bold: false,
                        tint
                    )
                )
            }

            return built
        }
    }

    // MARK: the flows

    static func flowCurves(_ model: Model, boxes: [String: Rect]) -> [String: FlowCurve] {
        let zoneOf = Dictionary(
            uniqueKeysWithValues: model.components.compactMap { component in
                component.zoneId.map { (component.id, $0) }
            }
        )
        var routed: [FlowRouting.Routed] = []

        for connection in model.connections {
            guard let source = boxes[connection.sourceComponentId],
                  let target = boxes[connection.targetComponentId] else { continue }

            let avoid = FlowRouting.obstacles(
                zones: model.zones
                    .filter {
                        $0.id != zoneOf[connection.sourceComponentId]
                            && $0.id != zoneOf[connection.targetComponentId]
                    }
                    .map { Rect(x: $0.x, y: $0.y, width: $0.width, height: $0.height) },
                nodes: model.components
                    .filter {
                        $0.id != connection.sourceComponentId
                            && $0.id != connection.targetComponentId
                    }
                    .map {
                        Component.drawnRect(
                            at: Point(x: $0.x, y: $0.y),
                            shape: DiagramBuilder.shape(of: $0)
                        )
                    }
            )
            let anchors = AnchorGeometry.nearestPair(from: source, to: target, avoiding: avoid)

            routed.append(
                FlowRouting.Routed(
                    id: connection.id,
                    start: AnchorGeometry.point(anchors.source, of: source),
                    end: AnchorGeometry.point(anchors.target, of: target),
                    avoiding: avoid
                )
            )
        }

        return FlowRouting.curves(of: routed)
    }

    static func flowShapes(_ model: Model, curves: [String: FlowCurve]) -> [DrawnShape] {
        model.connections.flatMap { connection -> [DrawnShape] in
            guard let curve = curves[connection.id] else { return [] }
            let colour = DiagramColour.forLevel(
                model.risks["connection:\(connection.id)"]?.highestLevelId
            )

            var steps: [PathStep] = [.move(curve.start)]
            for segment in curve.segments {
                steps.append(
                    .cubic(control1: segment.control1, control2: segment.control2, to: segment.end)
                )
            }

            return [
                .path(steps, DiagramStyle(stroke: colour, width: 1.5)),
                .path(arrowhead(of: curve), DiagramStyle(fill: colour))
            ]
        }
    }

    /// The three points of the arrowhead, pointing along the curve's final
    /// direction.
    static func arrowhead(of curve: FlowCurve, length: Double = 10, width: Double = 8) -> [PathStep] {
        let approach = curve.point(at: 0.98)
        let end = curve.end
        let angle = atan2(end.y - approach.y, end.x - approach.x)
        let baseX = end.x - length * cos(angle)
        let baseY = end.y - length * sin(angle)

        return [
            .move(end),
            .line(Point(x: baseX - width / 2 * sin(angle), y: baseY + width / 2 * cos(angle))),
            .line(Point(x: baseX + width / 2 * sin(angle), y: baseY - width / 2 * cos(angle))),
            .close
        ]
    }

    // MARK: the boundaries

    static func boundaryRuns(
        _ model: Model,
        curves: [String: FlowCurve]
    ) -> [BoundaryCrossings.BoundaryRun] {
        let zoneOf = Dictionary(
            uniqueKeysWithValues: model.components.compactMap { component in
                component.zoneId.map { (component.id, $0) }
            }
        )
        let zones = model.zones.map {
            BoundaryZone(
                id: $0.id,
                networkZoneId: $0.networkZoneId,
                rect: Rect(x: $0.x, y: $0.y, width: $0.width, height: $0.height)
            )
        }
        var marked: [BoundaryCrossings.MarkedCrossing] = []

        for connection in model.connections {
            guard let curve = curves[connection.id] else { continue }

            marked += BoundaryCrossings.of(
                connectionId: connection.id,
                sourceZoneId: zoneOf[connection.sourceComponentId],
                targetZoneId: zoneOf[connection.targetComponentId],
                curve: curve,
                zones: zones
            ).map {
                BoundaryCrossings.MarkedCrossing(
                    connectionId: connection.id,
                    crossing: $0,
                    guards: EdgeGuards.merge(
                        model.guards["connection:\(connection.id)"] ?? [],
                        model.guards["component:\(connection.targetComponentId)"] ?? []
                    ),
                    openCount: model.risks["connection:\(connection.id)"]?.openCount ?? 0
                )
            }
        }

        return BoundaryCrossings.runs(marked)
    }

    static func chipTexts(of run: BoundaryCrossings.BoundaryRun) -> [String] {
        guard run.guards.isEmpty == false else {
            return run.openCount > 0 ? ["no guard"] : []
        }

        let shown = run.guards.prefix(2).map { shortName(of: $0.label) }
        let hidden = run.guards.count - shown.count
        return hidden > 0 ? shown + ["+\(hidden)"] : shown
    }

    /// A component's name, without what follows it in brackets or after a
    /// comma. That part is what a name is; the rest is a note.
    public static func shortName(of label: String) -> String {
        var ends = label.endIndex
        for mark in [" (", ", ", " - "] {
            if let found = label.range(of: mark), found.lowerBound < ends {
                ends = found.lowerBound
            }
        }
        return String(label[label.startIndex ..< ends])
    }

    static func chipRects(
        _ runs: [BoundaryCrossings.BoundaryRun],
        bands: [Rect]
    ) -> [Rect] {
        runs.flatMap { BoundaryChips.rects(of: $0, texts: chipTexts(of: $0), zoneHeaders: bands) }
    }

    static func boundaryShapes(
        _ runs: [BoundaryCrossings.BoundaryRun],
        curves: [String: FlowCurve],
        bands: [Rect]
    ) -> [DrawnShape] {
        let sampled = curves.mapValues { CurveCrossing.samples(of: $0) }
        var built: [DrawnShape] = []

        for run in runs {
            let tint: DiagramColour = run.networkZoneId == "private" ? .green : .orange
            let unrelated = sampled
                .filter { run.connectionIds.contains($0.key) == false }
                .map(\.value)

            for stretch in BoundaryCrossings.stretches(of: run, avoiding: unrelated) {
                guard let first = stretch.first else { continue }
                built.append(
                    .path(
                        [.move(first)] + stretch.dropFirst().map { PathStep.line($0) },
                        DiagramStyle(stroke: tint, width: 2, dash: [2, 5])
                    )
                )
            }

            let texts = chipTexts(of: run)
            let rects = BoundaryChips.rects(of: run, texts: texts, zoneHeaders: bands)
            let assumed = run.guards.prefix(2).map(\.isAssumed)

            for (index, text) in texts.enumerated() where index < rects.count {
                let colour: DiagramColour = run.guards.isEmpty ? .quiet : tint
                built.append(
                    .rectangle(
                        rects[index],
                        cornerRadius: 4,
                        DiagramStyle(
                            stroke: colour,
                            fill: .paper,
                            width: 1,
                            dash: index < assumed.count && assumed[index] ? [3, 3] : []
                        )
                    )
                )
                built.append(
                    .text(
                        text,
                        at: Point(
                            x: rects[index].minX + rects[index].size.width / 2,
                            y: rects[index].minY + rects[index].size.height / 2 + 3
                        ),
                        anchor: .centre,
                        size: chipSize,
                        bold: false,
                        colour
                    )
                )
            }
        }

        return built
    }
}
