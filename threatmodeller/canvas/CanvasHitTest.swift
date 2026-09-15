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

    /// What a flow has to go round: the zones it has nothing to do with, and
    /// every node that is not one of its own ends. A flow whose ends this
    /// build cannot place avoids nothing, and draws straight.
    static func zonesToAvoid(
        _ connection: ViewedConnection,
        components: [String: ViewedComponent],
        zones: [ViewedZone],
        boxes: [String: ComponentBox] = [:]
    ) -> [Rect] {
        let source = components[connection.sourceComponentId]?.zoneId
        let target = components[connection.targetComponentId]?.zoneId

        return FlowRouting.obstacles(
            zones: zones
                .filter { $0.id != source && $0.id != target }
                .map { Rect(x: $0.x, y: $0.y, width: $0.width, height: $0.height) },
            nodes: boxes
                .filter {
                    $0.key != connection.sourceComponentId
                        && $0.key != connection.targetComponentId
                }
                .map(\.value.drawnRect)
        )
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
        drag: (zoneId: String, handle: ZoneHandle?, translation: CGSize)?,
        movingWith zoneIds: Set<String> = []
    ) -> CGRect {
        let box = ZoneBox(zone: zone)
        guard let drag else { return box.rect }
        // A move carries every zone in `zoneIds` with it, so a group of zones
        // draws where the whole group is going. A resize moves one zone only.
        let carried = drag.handle == nil && zoneIds.contains(zone.id)
        guard drag.zoneId == zone.id || carried else { return box.rect }
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
        contentRect(components: components, zones: zones).size
    }

    /// Where the drawing layer sits and how big it is, in model coordinates.
    ///
    /// This is a rectangle and not a size because a model reaches either way
    /// from the origin. A component the user drags up and to the left takes a
    /// negative coordinate, and a layer that starts at the origin does not
    /// hold it.
    static func contentRect(components: [ViewedComponent], zones: [ViewedZone]) -> CGRect {
        // The origin is always inside the layer, so an empty model still
        // draws around it.
        var minX = 0.0
        var minY = 0.0
        var maxX = minimumContentSize.width - contentMargin
        var maxY = minimumContentSize.height - contentMargin

        for component in components {
            let rect = Self.box(for: component).rect
            minX = min(minX, rect.minX)
            minY = min(minY, rect.minY)
            maxX = max(maxX, rect.maxX)
            maxY = max(maxY, rect.maxY)
        }
        for zone in zones {
            minX = min(minX, zone.x)
            minY = min(minY, zone.y)
            maxX = max(maxX, zone.x + zone.width)
            maxY = max(maxY, zone.y + zone.height)
        }

        // The margin goes on every side, so the user can drag a node past
        // whatever is farthest out in any direction, the origin included.
        return CGRect(
            x: minX - contentMargin,
            y: minY - contentMargin,
            width: (maxX - minX) + contentMargin * 2,
            height: (maxY - minY) + contentMargin * 2
        )
    }
}
