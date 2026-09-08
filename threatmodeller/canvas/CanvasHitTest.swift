import CoreGraphics
import ThreatModelKit

/// What a point on the canvas landed on.
///
/// Nothing here reads a view or a gesture, so every rule the canvas uses to
/// decide what a click hit is tested without a window. Declared `nonisolated`:
/// the app target defaults every type to the main actor, and this one holds no
/// state at all.
nonisolated enum CanvasHitTest {
    /// Where each component sits, with a drag in flight applied to the
    /// selected ones.
    static func boxes(
        for components: [ViewedComponent],
        selected: Set<String>,
        dragTranslation: CGSize
    ) -> [String: ComponentBox] {
        var found: [String: ComponentBox] = [:]
        for component in components {
            let shift = selected.contains(component.id) ? dragTranslation : CGSize.zero
            found[component.id] = ComponentBox(
                x: component.x + shift.width,
                y: component.y + shift.height
            )
        }
        return found
    }

    /// The curve a link draws, or nil when either end is missing.
    static func path(
        for connection: ViewedConnection,
        boxes: [String: ComponentBox]
    ) -> ConnectionPath? {
        guard let source = boxes[connection.sourceComponentId],
              let target = boxes[connection.targetComponentId] else { return nil }
        let anchors = AnchorGeometry.nearestPair(from: source, to: target)
        return ConnectionPath(
            from: AnchorGeometry.point(anchors.source, of: source),
            to: AnchorGeometry.point(anchors.target, of: target)
        )
    }

    /// The link under the point, or nil. A later link wins, so the one drawn
    /// on top is the one the click selects.
    static func connection(
        under modelPoint: CGPoint,
        connections: [ViewedConnection],
        boxes: [String: ComponentBox]
    ) -> String? {
        connections.last {
            path(for: $0, boxes: boxes)?.containsClick(at: modelPoint) == true
        }?.id
    }

    /// The component under the point, or nil. A later component wins.
    static func component(under modelPoint: CGPoint, components: [ViewedComponent]) -> String? {
        components.last { ComponentBox(x: $0.x, y: $0.y).contains(modelPoint) }?.id
    }
}
