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
            var everyCrossing: [BoundaryCrossing] = []
            var chips: [(connection: ViewedConnection, crossing: BoundaryCrossing)] = []

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
                let crossings = BoundaryCrossings.of(
                    connection,
                    path: path,
                    components: componentsById,
                    zones: zones
                )
                everyCrossing += crossings
                // A guard answers the flow, not one edge of it, so a flow that
                // crosses two boundaries names its guards once.
                if let first = crossings.first {
                    chips.append((connection, first))
                }
            }

            // One mark per place, however many flows cross the edge there.
            for crossing in BoundaryCrossings.places(everyCrossing) {
                context.stroke(
                    BoundaryCrossings.mark(for: crossing),
                    with: .color(tint(of: crossing)),
                    style: StrokeStyle(lineWidth: 2, lineCap: .round, dash: [2, 5])
                )
            }

            // The chips go on last, so a link drawn later never covers one.
            for chip in chips {
                writeGuards(of: chip.connection, at: chip.crossing, in: &context)
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

    private func tint(of crossing: BoundaryCrossing) -> Color {
        crossing.networkZoneId == "private" ? .green : .orange
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
        guard described.count > Self.labelLimit else { return described }
        return described.prefix(Self.labelLimit - 1).trimmingCharacters(in: .whitespaces) + "\u{2026}"
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

    /// The components that guard this crossing, or the words that say none
    /// does. An unguarded crossing carrying an open threat is what a reviewer
    /// looks for, so it is stated rather than left blank.
    private func writeGuards(
        of connection: ViewedConnection,
        at crossing: BoundaryCrossing,
        in context: inout GraphicsContext
    ) {
        let tint = tint(of: crossing)
        let held = guards["connection:\(connection.id)"] ?? []
        let shown = Array(held.prefix(Self.guardsShown))
        let hidden = held.count - shown.count

        var chips: [(text: String, colour: Color, isAssumed: Bool)] = shown.map {
            ($0.label, tint, $0.isAssumed)
        }
        if hidden > 0 { chips.append(("+\(hidden)", tint, false)) }
        // Nothing guards it. That is worth saying only while a threat on the
        // flow is still open: a crossing every control answers needs no chip.
        if held.isEmpty {
            guard (risk(of: connection)?.openCount ?? 0) > 0 else { return }
            chips = [("no guard", .secondary, false)]
        }

        // The chips stack beyond the mark's far end, so they never sit on the
        // flow's own label.
        let across = crossing.angle + .pi / 2
        var y = crossing.point.y + (BoundaryCrossings.length / 2 + 12) * sin(across)
        let x = crossing.point.x + (BoundaryCrossings.length / 2 + 12) * cos(across)

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
