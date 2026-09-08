import SwiftUI
import ThreatModelKit

/// Every link drawn in one `Canvas` pass, plus the preview line while a
/// connection drag is in flight. Spec section 9 sets this painting order.
struct ConnectionsLayer: View {
    let connections: [ViewedConnection]
    let boxes: [String: ComponentBox]
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
                draw(path, in: &context, selected: selectedConnectionIds.contains(connection.id))
            }

            if let preview {
                draw(
                    ConnectionPath(from: preview.start, to: preview.end),
                    in: &context,
                    selected: true,
                    dashed: true
                )
            }
        }
        .allowsHitTesting(false)
    }

    private func draw(
        _ connection: ConnectionPath,
        in context: inout GraphicsContext,
        selected: Bool,
        dashed: Bool = false
    ) {
        var curve = Path()
        curve.move(to: connection.start)
        curve.addCurve(to: connection.end, control1: connection.control1, control2: connection.control2)

        let colour: Color = selected ? .accentColor : .secondary
        context.stroke(
            curve,
            with: .color(colour),
            style: StrokeStyle(lineWidth: selected ? 2.5 : 1.5, dash: dashed ? [6, 4] : [])
        )

        let head = connection.arrowhead()
        var arrow = Path()
        arrow.move(to: head[0])
        arrow.addLine(to: head[1])
        arrow.addLine(to: head[2])
        arrow.closeSubpath()
        context.fill(arrow, with: .color(colour))
    }
}
