import SwiftUI
import ThreatModelKit

/// One component on the canvas, with the four anchor handles a connection
/// drag starts from.
struct ComponentNodeView: View {
    let component: ViewedComponent
    let isSelected: Bool
    let onSelect: (_ addingToSelection: Bool) -> Void
    let onDragChanged: (CGSize) -> Void
    let onDragEnded: (CGSize) -> Void
    let onAnchorDragChanged: (CGPoint) -> Void
    let onAnchorDragEnded: (CGPoint) -> Void

    @State private var isHovering = false

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 10)
                .fill(Color(nsColor: .controlBackgroundColor))
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .strokeBorder(
                            isSelected ? Color.accentColor : Color.secondary.opacity(0.4),
                            lineWidth: isSelected ? 2.5 : 1
                        )
                )
                .shadow(radius: isSelected ? 4 : 1)

            VStack(alignment: .leading, spacing: 4) {
                Text(component.name)
                    .font(.headline)
                    .lineLimit(1)
                HStack(spacing: 6) {
                    Text(component.providerId.isEmpty ? "unknown" : component.providerId.uppercased())
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Text(component.sensitivityId.capitalized)
                        .font(.caption2)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(Color.secondary.opacity(0.15)))
                }
            }
            .frame(width: ComponentBox.size.width - 24, alignment: .leading)

            if isHovering || isSelected {
                ForEach(ConnectionAnchor.allCases, id: \.self) { anchor in
                    anchorHandle(anchor)
                }
            }
        }
        .frame(width: ComponentBox.size.width, height: ComponentBox.size.height)
        .contentShape(Rectangle())
        .onHover { isHovering = $0 }
        // Without an explicit element SwiftUI reports the node's texts
        // separately, and the identifier lands on each of them instead of the
        // node. A user interface test queries this identifier.
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("node-\(component.technologyId)")
        .gesture(
            SpatialTapGesture().modifiers(.shift).onEnded { _ in onSelect(true) }
                .exclusively(before: SpatialTapGesture().onEnded { _ in onSelect(false) })
        )
        .gesture(
            DragGesture(minimumDistance: 3, coordinateSpace: .named("canvas"))
                .onChanged { onDragChanged($0.translation) }
                .onEnded { onDragEnded($0.translation) }
        )
    }

    private func anchorHandle(_ anchor: ConnectionAnchor) -> some View {
        let point = AnchorGeometry.point(anchor, of: ComponentBox(x: 0, y: 0))

        return Circle()
            .fill(Color.accentColor)
            .frame(width: 9, height: 9)
            .position(x: point.x, y: point.y)
            .gesture(
                DragGesture(minimumDistance: 1, coordinateSpace: .named("canvas"))
                    .onChanged { onAnchorDragChanged($0.location) }
                    .onEnded { onAnchorDragEnded($0.location) }
            )
    }
}
