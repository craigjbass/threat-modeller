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
            found[component.id] = Self.box(for: component, shiftedBy: shift)
        }
        return found
    }

    /// The curve a link draws, or nil when either end is missing.
    static func path(
        for connection: ViewedConnection,
        boxes: [String: ComponentBox],
        avoiding zones: [Rect] = []
    ) -> ConnectionPath? {
        guard let source = boxes[connection.sourceComponentId],
              let target = boxes[connection.targetComponentId] else { return nil }
        let anchors = AnchorGeometry.nearestPair(
            from: source.rect.modelRect,
            to: target.rect.modelRect
        )
        return ConnectionPath(
            from: CGPoint(AnchorGeometry.point(anchors.source, of: source.rect.modelRect)),
            to: CGPoint(AnchorGeometry.point(anchors.target, of: target.rect.modelRect)),
            avoiding: zones
        )
    }

    /// The link under the point, or nil. A later link wins, so the one drawn
    /// on top is the one the click selects.
    static func connection(
        under modelPoint: CGPoint,
        connections: [ViewedConnection],
        boxes: [String: ComponentBox],
        components: [String: ViewedComponent] = [:],
        zones: [ViewedZone] = []
    ) -> String? {
        connections.last {
            path(
                for: $0,
                boxes: boxes,
                avoiding: Self.zonesToAvoid($0, components: components, zones: zones)
            )?.containsClick(at: modelPoint) == true
        }?.id
    }

    /// The zones a flow has nothing to do with, so it goes round them. A flow
    /// whose ends this build cannot place avoids nothing, and draws straight.
    static func zonesToAvoid(
        _ connection: ViewedConnection,
        components: [String: ViewedComponent],
        zones: [ViewedZone]
    ) -> [Rect] {
        let source = components[connection.sourceComponentId]?.zoneId
        let target = components[connection.targetComponentId]?.zoneId

        return zones
            .filter { $0.id != source && $0.id != target }
            .map { Rect(x: $0.x, y: $0.y, width: $0.width, height: $0.height) }
    }

    /// The component under the point, or nil. A later component wins.
    static func component(under modelPoint: CGPoint, components: [ViewedComponent]) -> String? {
        components.last { Self.box(for: $0).contains(modelPoint) }?.id
    }

    /// Where one component draws, with a drag applied. A component whose word
    /// this build does not hold draws as a process, the way the derivation
    /// treats an unknown technology.
    static func box(for component: ViewedComponent, shiftedBy shift: CGSize = .zero) -> ComponentBox {
        ComponentBox(
            x: component.x + shift.width,
            y: component.y + shift.height,
            shape: DiagramShape(rawValue: component.shapeId) ?? .process
        )
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
            let rect = Self.box(for: component).rect
            width = max(width, rect.maxX)
            height = max(height, rect.maxY)
        }
        for zone in zones {
            width = max(width, zone.x + zone.width)
            height = max(height, zone.y + zone.height)
        }

        return CGSize(width: width + contentMargin, height: height + contentMargin)
    }
}
