import SwiftUI
import ThreatModelKit

/// Every link drawn in one `Canvas` pass, plus the preview line while a
/// connection drag is in flight. Spec section 9 sets this painting order.
///
/// A link takes the colour of the highest residual risk level it carries, and
/// states its description, or its flow kind when the user wrote none. A link
/// either end of which is out of scope draws grey and dashed.
///
/// Where a link crosses a zone edge the layer draws the dotted bow OWASP
/// Threat Dragon uses for a trust boundary, across the link at a right angle.
struct ConnectionsLayer: View {
    /// How many guards a crossing names before it counts the rest.
    static let guardsShown = 2
    /// How long a flow's label may be. A description is prose, and a whole
    /// sentence on the line covers the diagram.
    static let labelLimit = 28
    /// How long a guard's name may be on a chip. A component's name carries
    /// its product and its kind, and the whole of it covers the diagram.
    static let guardLimit = 18

    let connections: [ViewedConnection]
    let boxes: [String: ComponentBox]
    /// Every component by id, so the layer can tell which zone each end of a
    /// link sits in.
    let componentsById: [String: ViewedComponent]
    /// In drawing order, so the containment rule matches the core's.
    let zones: [ViewedZone]
    /// The risk of every element, by source id. A link reads
    /// "connection:<id>".
    let risks: [String: ElementRisk]
    /// What guards every element, by source id. A crossing states these, so a
    /// reader sees what stands in the way of a flow across a boundary.
    let guards: [String: [EdgeGuard]]
    /// The components the user turned threats off for.
    let outOfScopeComponentIds: Set<String>
    let selectedConnectionIds: Set<String>
    let preview: (start: CGPoint, end: CGPoint)?

    var body: some View {
        Canvas { context, _ in
            var marked: [BoundaryCrossings.MarkedCrossing] = []

            for connection in connections {
                guard let source = boxes[connection.sourceComponentId],
                      let target = boxes[connection.targetComponentId] else { continue }

                let anchors = AnchorGeometry.nearestPair(from: source, to: target)
                let path = ConnectionPath(
                    from: AnchorGeometry.point(anchors.source, of: source),
                    to: AnchorGeometry.point(anchors.target, of: target)
                )
                draw(connection, along: path, in: &context)

                guard isOutOfScope(connection) == false else { continue }
                marked += BoundaryCrossings.of(
                    connection,
                    path: path,
                    components: componentsById,
                    zones: zones
                ).map {
                    BoundaryCrossings.MarkedCrossing(
                        crossing: $0,
                        guards: guards(of: connection),
                        openCount: risk(of: connection)?.openCount ?? 0
                    )
                }
            }

            // One curve for each boundary, however many arrows pass through it.
            let runs = BoundaryCrossings.runs(marked)

            for run in runs {
                context.stroke(
                    run.curve,
                    with: .color(tint(of: run)),
                    style: StrokeStyle(lineWidth: 2, lineCap: .round, dash: [2, 5])
                )
            }

            // The chips go on last, so a link drawn later never covers one.
            for run in runs {
                writeGuards(of: run, in: &context)
            }

            if let preview {
                stroke(
                    ConnectionPath(from: preview.start, to: preview.end),
                    in: &context,
                    colour: .accentColor,
                    width: 2.5,
                    dashed: true
                )
            }
        }
        .allowsHitTesting(false)
    }

    private func tint(of run: BoundaryCrossings.BoundaryRun) -> Color {
        run.networkZoneId == "private" ? .green : .orange
    }

    /// What guards a flow at a boundary: the components that guard the far end
    /// of it, and any that guard the flow itself. A `mitigates` edge names a
    /// component, so what stands in the way of a crossing is what guards the
    /// component the crossing reaches.
    private func guards(of connection: ViewedConnection) -> [EdgeGuard] {
        EdgeGuards.merge(
            guards["connection:\(connection.id)"] ?? [],
            guards["component:\(connection.targetComponentId)"] ?? []
        )
    }

    // MARK: what one link looks like

    private func isOutOfScope(_ connection: ViewedConnection) -> Bool {
        outOfScopeComponentIds.contains(connection.sourceComponentId)
            || outOfScopeComponentIds.contains(connection.targetComponentId)
    }

    private func risk(of connection: ViewedConnection) -> ElementRisk? {
        risks["connection:\(connection.id)"]
    }

    private func colour(of connection: ViewedConnection) -> Color {
        if isOutOfScope(connection) { return .secondary }
        if selectedConnectionIds.contains(connection.id) { return .accentColor }
        guard let levelId = risk(of: connection)?.highestLevelId else { return .secondary }
        return RiskPalette.colour(forLevelId: levelId)
    }

    /// The description when the user wrote one, else the flow kind, cut to
    /// what fits on the line. The panel shows the whole of it.
    func labelForTesting(_ connection: ViewedConnection) -> String { label(of: connection) }

    private func label(of connection: ViewedConnection) -> String {
        let described = connection.description?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard described.isEmpty == false else {
            return FlowKind(rawValue: connection.kindId)?.label ?? connection.kindId
        }
        return Self.cut(described, to: Self.labelLimit)
    }

    /// The text, or as much of it as fits, with an ellipsis for the rest.
    static func cut(_ text: String, to limit: Int) -> String {
        guard text.count > limit else { return text }
        return text.prefix(limit - 1).trimmingCharacters(in: .whitespaces) + "\u{2026}"
    }

    private func draw(
        _ connection: ViewedConnection,
        along path: ConnectionPath,
        in context: inout GraphicsContext
    ) {
        let selected = selectedConnectionIds.contains(connection.id)
        let colour = colour(of: connection)

        stroke(
            path,
            in: &context,
            colour: colour,
            width: selected ? 2.5 : 1.5,
            dashed: isOutOfScope(connection)
        )

        let head = path.arrowhead()
        var arrow = Path()
        arrow.move(to: head[0])
        arrow.addLine(to: head[1])
        arrow.addLine(to: head[2])
        arrow.closeSubpath()
        context.fill(arrow, with: .color(colour))

        write(connection, at: path.point(at: 0.5), colour: colour, in: &context)
    }

    /// The components that guard this boundary, or the words that say none
    /// does. An unguarded crossing carrying an open threat is what a reviewer
    /// looks for, so it is stated rather than left blank.
    private func writeGuards(
        of run: BoundaryCrossings.BoundaryRun,
        in context: inout GraphicsContext
    ) {
        let tint = tint(of: run)
        let shown = Array(run.guards.prefix(Self.guardsShown))
        let hidden = run.guards.count - shown.count

        var chips: [(text: String, colour: Color, isAssumed: Bool)] = shown.map {
            (Self.cut($0.label, to: Self.guardLimit), tint, $0.isAssumed)
        }
        if hidden > 0 { chips.append(("+\(hidden)", tint, false)) }
        // Nothing guards it. That is worth saying only while a threat through
        // the boundary is still open.
        if run.guards.isEmpty {
            guard run.openCount > 0 else { return }
            chips = [("no guard", .secondary, false)]
        }

        // The chips stack past the curve's far end, so they never sit on a
        // flow's own label.
        let reach = hypot(run.end.x - run.start.x, run.end.y - run.start.y)
        guard reach > 0 else { return }
        let step = CGPoint(x: (run.end.x - run.start.x) / reach, y: (run.end.y - run.start.y) / reach)
        let x = run.end.x + 14 * step.x
        var y = run.end.y + 14 * step.y

        for chip in chips {
            let resolved = context.resolve(
                Text(chip.text).font(.caption2).foregroundStyle(chip.colour)
            )
            let size = resolved.measure(in: CGSize(width: 160, height: 30))
            let box = CGRect(
                x: x - size.width / 2 - 5,
                y: y - size.height / 2 - 2,
                width: size.width + 10,
                height: size.height + 4
            )

            context.fill(
                Path(roundedRect: box, cornerRadius: 4),
                with: .color(Color(nsColor: .textBackgroundColor))
            )
            context.stroke(
                Path(roundedRect: box, cornerRadius: 4),
                with: .color(chip.colour),
                style: StrokeStyle(lineWidth: 1, dash: chip.isAssumed ? [3, 3] : [])
            )
            context.draw(resolved, at: CGPoint(x: x, y: y), anchor: .center)

            y += box.height + 3
        }
    }

    private func stroke(
        _ path: ConnectionPath,
        in context: inout GraphicsContext,
        colour: Color,
        width: CGFloat,
        dashed: Bool
    ) {
        var curve = Path()
        curve.move(to: path.start)
        curve.addCurve(to: path.end, control1: path.control1, control2: path.control2)

        context.stroke(
            curve,
            with: .color(colour),
            style: StrokeStyle(lineWidth: width, dash: dashed ? [6, 4] : [])
        )
    }

    /// The label sits on a pill in the canvas colour, so the curve does not run
    /// through the text.
    private func write(
        _ connection: ViewedConnection,
        at point: CGPoint,
        colour: Color,
        in context: inout GraphicsContext
    ) {
        let open = isOutOfScope(connection) ? 0 : (risk(of: connection)?.openCount ?? 0)
        let written = open > 0 ? "\(label(of: connection))  ·  \(open)" : label(of: connection)

        let resolved = context.resolve(
            Text(written).font(.caption2).foregroundStyle(colour)
        )
        let size = resolved.measure(in: CGSize(width: 220, height: 40))
        let pill = CGRect(
            x: point.x - size.width / 2 - 5,
            y: point.y - size.height / 2 - 2,
            width: size.width + 10,
            height: size.height + 4
        )

        context.fill(
            Path(roundedRect: pill, cornerRadius: 4),
            with: .color(Color(nsColor: .textBackgroundColor))
        )
        context.draw(resolved, at: point, anchor: .center)
    }
}
