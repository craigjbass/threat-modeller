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

    /// The zone under the point, or nil. A later zone wins, matching
    /// `ZoneContainment` in the core.
    static func zone(under modelPoint: CGPoint, zones: [ViewedZone]) -> String? {
        zones.last { ZoneBox(zone: $0).rect.contains(modelPoint) }?.id
    }

    /// Where a zone is drawn, with a move or resize in flight applied.
    static func rect(
        for zone: ViewedZone,
        drag: (zoneId: String, handle: ZoneHandle?, translation: CGSize)?
    ) -> CGRect {
        let box = ZoneBox(zone: zone)
        guard let drag, drag.zoneId == zone.id else { return box.rect }
        guard let handle = drag.handle else {
            return box.rect.offsetBy(dx: drag.translation.width, dy: drag.translation.height)
        }
        return box.resized(by: drag.translation, from: handle)
    }

    /// A canvas with nothing on it is still somewhere to draw.
    static let minimumContentSize = CGSize(width: 4000, height: 3000)
    /// Room past the farthest thing, so a node can always be dragged further
    /// out than whatever is currently farthest.
    static let contentMargin: CGFloat = 1000

    /// How big the drawing layer has to be to hold everything, with room to
    /// spare. A fixed square either wastes memory or clips a saved model that
    /// reaches past it.
    static func contentSize(components: [ViewedComponent], zones: [ViewedZone]) -> CGSize {
        var width = minimumContentSize.width - contentMargin
        var height = minimumContentSize.height - contentMargin

        for component in components {
            width = max(width, component.x + ComponentBox.size.width)
            height = max(height, component.y + ComponentBox.size.height)
        }
        for zone in zones {
            width = max(width, zone.x + zone.width)
            height = max(height, zone.y + zone.height)
        }

        return CGSize(width: width + contentMargin, height: height + contentMargin)
    }
}
