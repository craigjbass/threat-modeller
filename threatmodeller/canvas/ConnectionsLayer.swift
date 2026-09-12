import SwiftUI
import ThreatModelKit

/// Every link drawn in one `Canvas` pass, plus the preview line while a
/// connection drag is in flight. Spec section 9 sets this painting order.
///
/// A link takes the colour of the highest residual risk level it carries, and
/// states its description, or its flow kind when the user wrote none. A link
/// either end of which is out of scope draws grey and dashed.
struct ConnectionsLayer: View {
    let connections: [ViewedConnection]
    let boxes: [String: ComponentBox]
    /// The risk of every element, by source id. A link reads
    /// "connection:<id>".
    let risks: [String: ElementRisk]
    /// The components the user turned threats off for.
    let outOfScopeComponentIds: Set<String>
    let selectedConnectionIds: Set<String>
    let preview: (start: CGPoint, end: CGPoint)?

    var body: some View {
        Canvas { context, _ in
            for connection in connections {
                guard let source = boxes[connection.sourceComponentId],
                      let target = boxes[connection.targetComponentId] else { continue }

                let anchors = AnchorGeometry.nearestPair(from: source, to: target)
                let path = ConnectionPath(
                    from: AnchorGeometry.point(anchors.source, of: source),
                    to: AnchorGeometry.point(anchors.target, of: target)
                )
                draw(connection, along: path, in: &context)
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

    /// The description when the user wrote one, else the flow kind.
    private func label(of connection: ViewedConnection) -> String {
        let described = connection.description?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if described.isEmpty == false { return described }
        return FlowKind(rawValue: connection.kindId)?.label ?? connection.kindId
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
