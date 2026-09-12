import SwiftUI
import ThreatModelKit

/// The diagram as a picture: zones, links and nodes, with no selection, no
/// gestures and no toolbar.
///
/// The canvas view itself cannot be used here. It reads a `CanvasState` for
/// selection and drag, it takes the space a split view offers, and it clips.
/// A picture takes the size the model needs and draws everything in it.
nonisolated struct CanvasPicture: View {
    let components: [ViewedComponent]
    let connections: [ViewedConnection]
    let zones: [ViewedZone]
    /// The risk of every element, by source id. Empty draws the diagram with
    /// no risk colour, which is what a model with no threats shows.
    let risks: [String: ElementRisk]
    /// Where the picture starts in model coordinates, so a node at x = 900
    /// draws inside the image rather than off its edge.
    let origin: CGPoint
    let size: CGSize

    private var boxes: [String: ComponentBox] {
        CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero)
    }

    private func zoneName(holding component: ViewedComponent) -> String? {
        guard let zoneId = component.zoneId else { return nil }
        return zones.first { $0.id == zoneId }?.name
    }

    private func node(_ component: ViewedComponent) -> some View {
        ComponentNodeView(
            component: component,
            risk: risks["component:\(component.id)"],
            isSelected: false,
            onSelect: { _ in },
            onDragChanged: { _ in },
            onDragEnded: { _ in },
            onAnchorDragChanged: { _ in },
            onAnchorDragEnded: { _ in },
            zoneName: zoneName(holding: component)
        )
        .position(
            x: component.x + Component.size.width / 2,
            y: component.y + Component.size.height / 2
        )
    }

    private func zoneShape(_ zone: ViewedZone) -> some View {
        ZoneView(
            zone: zone,
            risk: risks["zone:\(zone.id)"],
            size: CGSize(width: zone.width, height: zone.height),
            isSelected: false,
            onSelect: {},
            onDragChanged: { _, _ in },
            onDragEnded: { _, _ in }
        )
        .position(x: zone.x + zone.width / 2, y: zone.y + zone.height / 2)
    }

    var body: some View {
        ZStack(alignment: .topLeading) {
            Color(nsColor: .textBackgroundColor)

            diagram
                .offset(x: -origin.x, y: -origin.y)
        }
        .frame(width: size.width, height: size.height)
    }

    private var diagram: some View {
        ZStack(alignment: .topLeading) {
            ForEach(zones, id: \.id) { zone in
                zoneShape(zone)
            }

            ConnectionsLayer(
                connections: connections,
                boxes: boxes,
                risks: risks,
                outOfScopeComponentIds: Set(components.filter(\.threatsDisabled).map(\.id)),
                selectedConnectionIds: [],
                preview: nil
            )

            ForEach(components, id: \.id) { component in
                node(component)
            }
        }
    }
}
