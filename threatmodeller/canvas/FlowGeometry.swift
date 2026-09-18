import CoreGraphics
import Foundation
import ThreatModelKit

/// Everything the canvas draws for the flows, and what a click on it hits.
///
/// The layer used to build this while drawing and the hit test used to build
/// its own straight line. The two disagreed: a flow that stepped round a node
/// or aside from another flow was drawn in one place and clicked in another.
/// Both now read the same value.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this is a pure value computation with no shared state.
nonisolated struct FlowGeometry {
    /// How many guards a crossing names before it counts the rest.
    static let guardsShown = 2
    /// How long a guard's name may be on a chip.
    static let guardLimit = 30

    /// The curve every flow draws, by connection id.
    let curves: [String: FlowCurve]
    /// The flows in drawing order. The last one drawn is the one on top.
    let order: [String]
    /// Points along every flow that raises threats, by connection id. The
    /// boundary curves bend round these.
    let samples: [String: [Point]]
    /// One curve for each boundary, however many flows pass through it.
    let runs: [BoundaryCrossings.BoundaryRun]
    /// Where the guard chips sit. A callout never covers one.
    let chipRects: [Rect]
    /// Where each flow's label sits.
    let callouts: [Callout]
    /// The use links: the link from a user to a client it holds. Drawn,
    /// never hit, never labelled, never marked at a boundary.
    let useLinkIds: Set<String>

    static func of(
        connections: [ViewedConnection],
        boxes: [String: ComponentBox],
        componentsById: [String: ViewedComponent],
        zones: [ViewedZone],
        guards: [String: [EdgeGuard]],
        risks: [String: ElementRisk],
        outOfScopeComponentIds: Set<String>
    ) -> FlowGeometry {
        // Every curve is built before any is drawn: a flow that would trace
        // another steps aside, and it cannot know to until the others are
        // placed.
        var routed: [FlowRouting.Routed] = []
        for connection in connections {
            guard let source = boxes[connection.sourceComponentId],
                  let target = boxes[connection.targetComponentId] else { continue }

            let avoid = CanvasHitTest.zonesToAvoid(
                connection,
                components: componentsById,
                zones: zones,
                boxes: boxes
            )
            let anchors = AnchorGeometry.nearestPair(
                from: source.rect.modelRect,
                to: target.rect.modelRect,
                avoiding: avoid
            )
            routed.append(
                FlowRouting.Routed(
                    id: connection.id,
                    start: AnchorGeometry.point(anchors.source, of: source.rect.modelRect),
                    end: AnchorGeometry.point(anchors.target, of: target.rect.modelRect),
                    avoiding: avoid
                )
            )
        }
        let curves = FlowRouting.curves(of: routed)

        let bandRects = zones.map {
            Rect(x: $0.x, y: $0.y, width: $0.width, height: Double(ZoneBox.headerHeight))
        }
        let boundaryZones = zones.map {
            BoundaryZone(
                id: $0.id,
                networkZoneId: $0.networkZoneId,
                rect: Rect(x: $0.x, y: $0.y, width: $0.width, height: $0.height)
            )
        }

        var samples: [String: [Point]] = [:]
        var marked: [BoundaryCrossings.MarkedCrossing] = []
        var toLabel: [(connectionId: String, text: String, curve: FlowCurve)] = []

        for connection in connections {
            guard let curve = curves[connection.id] else { continue }
            guard connection.isUse == false else { continue }
            toLabel.append((connection.id, label(of: connection), curve))

            guard isOutOfScope(connection, outOfScopeComponentIds) == false else { continue }
            samples[connection.id] = CurveCrossing.samples(of: curve)
            marked += BoundaryCrossings.of(
                connectionId: connection.id,
                sourceZoneId: componentsById[connection.sourceComponentId]?.zoneId,
                targetZoneId: componentsById[connection.targetComponentId]?.zoneId,
                curve: curve,
                zones: boundaryZones
            ).map {
                BoundaryCrossings.MarkedCrossing(
                    connectionId: connection.id,
                    crossing: $0,
                    guards: self.guards(of: connection, in: guards),
                    openCount: risks["connection:\(connection.id)"]?.openCount ?? 0
                )
            }
        }

        let runs = BoundaryCrossings.runs(marked)
        let chipRects = runs.flatMap {
            BoundaryChips.rects(of: $0, texts: chipTexts(of: $0), zoneHeaders: bandRects)
        }

        return FlowGeometry(
            curves: curves,
            order: connections.map(\.id).filter { curves[$0] != nil },
            samples: samples,
            runs: runs,
            chipRects: chipRects,
            callouts: CalloutPlacement.place(
                toLabel,
                nodes: boxes.values.map(\.drawnRect),
                zoneHeaders: bandRects,
                boundaryChips: chipRects,
                flows: Array(samples.values),
                flowsById: samples
            ),
            useLinkIds: Set(connections.filter(\.isUse).map(\.id))
        )
    }

    // MARK: what a click hits

    /// The flow under the point, or nil.
    ///
    /// A callout wins over a curve, because a callout is drawn over
    /// everything else; a later flow wins over an earlier one, because it is
    /// drawn on top.
    ///
    /// `within` is how far from the curve a click still counts, in model
    /// units. A caller that draws at a zoom divides by that zoom, so the
    /// reach on screen is the same however far out the diagram is.
    func connection(
        under modelPoint: CGPoint,
        within reach: CGFloat = ConnectionPath.hitTolerance
    ) -> String? {
        if let callout = callouts.last(where: { $0.rect.contains(Point(x: modelPoint.x, y: modelPoint.y)) }) {
            return callout.connectionId
        }
        return order.last { id in
            guard useLinkIds.contains(id) == false, let curve = curves[id] else { return false }
            return ConnectionPath(curve).distance(to: modelPoint) <= reach
        }
    }

    // MARK: what a flow says

    /// The description when the user wrote one, else the flow kind.
    static func label(of connection: ViewedConnection) -> String {
        let described = connection.description?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard described.isEmpty == false else {
            return FlowKind(rawValue: connection.kindId)?.label ?? connection.kindId
        }
        // Whole: the callout is sized to the text rather than the text cut to
        // fit a line.
        return described
    }

    static func isOutOfScope(
        _ connection: ViewedConnection,
        _ outOfScopeComponentIds: Set<String>
    ) -> Bool {
        outOfScopeComponentIds.contains(connection.sourceComponentId)
            || outOfScopeComponentIds.contains(connection.targetComponentId)
    }

    /// What guards a flow at a boundary: the components that guard the far end
    /// of it, and any that guard the flow itself. A `mitigates` edge names a
    /// component, so what stands in the way of a crossing is what guards the
    /// component the crossing reaches.
    static func guards(
        of connection: ViewedConnection,
        in guards: [String: [EdgeGuard]]
    ) -> [EdgeGuard] {
        EdgeGuards.merge(
            guards["connection:\(connection.id)"] ?? [],
            guards["component:\(connection.targetComponentId)"] ?? []
        )
    }

    /// What this boundary writes: the components that guard it, or the words
    /// that say none does. An unguarded crossing carrying an open threat is
    /// what a reviewer looks for, so it is stated rather than left blank.
    static func chipTexts(of run: BoundaryCrossings.BoundaryRun) -> [String] {
        let shown = Array(run.guards.prefix(guardsShown))
        let hidden = run.guards.count - shown.count

        guard run.guards.isEmpty == false else {
            return run.openCount > 0 ? ["no guard"] : []
        }

        var texts = shown.map { name(of: $0.label) }
        if hidden > 0 { texts.append("+\(hidden)") }
        return texts
    }

    /// A component's name, without what follows it in brackets or after a
    /// comma. `opfilter System Extension (Endpoint Security)` reads
    /// `opfilter System Extension`, which is the name; cutting it to a
    /// character count read `opfilter System E…`, which is nothing.
    static func name(of label: String) -> String {
        var ends = label.endIndex
        for mark in [" (", ", ", " \u{2014} ", " - "] {
            if let found = label.range(of: mark), found.lowerBound < ends {
                ends = found.lowerBound
            }
        }
        return cut(String(label[label.startIndex ..< ends]), to: guardLimit)
    }

    /// The text, or as much of it as fits, with an ellipsis for the rest.
    static func cut(_ text: String, to limit: Int) -> String {
        guard text.count > limit else { return text }
        return text.prefix(limit - 1).trimmingCharacters(in: .whitespaces) + "\u{2026}"
    }
}
