import SwiftUI
import ThreatModelKit

/// One zone: its outline, its header, and its resize grips when selected.
///
/// A public zone is drawn with a dashed outline, because it reduces nothing
/// and raises nothing — the difference has to be visible without reading the
/// panel.
struct ZoneView: View {
    let zone: ViewedZone
    /// The size to draw at. While a move or resize is in flight this is the
    /// size the drag produces, not the size the model holds, so the outline,
    /// the header and the grips all follow the pointer.
    let size: CGSize
    let isSelected: Bool
    let onSelect: () -> Void
    let onDragChanged: (_ handle: ZoneHandle?, _ translation: CGSize) -> Void
    let onDragEnded: (_ handle: ZoneHandle?, _ translation: CGSize) -> Void

    /// The zone drawn at the view's own origin, so a grip's position inside
    /// this view does not depend on where the zone sits on the canvas.
    private var box: ZoneBox {
        ZoneBox(x: 0, y: 0, width: size.width, height: size.height)
    }

    private var isPrivate: Bool { zone.networkZoneId == "private" }

    private var tint: Color { isPrivate ? .green : .orange }

    var body: some View {
        ZStack(alignment: .topLeading) {
            RoundedRectangle(cornerRadius: 12)
                .fill(tint.opacity(0.07))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .strokeBorder(
                            isSelected ? Color.accentColor : tint.opacity(0.7),
                            style: StrokeStyle(
                                lineWidth: isSelected ? 2.5 : 1.5,
                                dash: isPrivate ? [] : [6, 4]
                            )
                        )
                )

            header
        }
        .frame(width: size.width, height: size.height)
        .overlay(alignment: .topLeading) {
            if isSelected { grips }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("zone-\(zone.id)")
    }

    private var header: some View {
        HStack(spacing: 8) {
            Text(zone.name)
                .font(.headline)
                .lineLimit(1)
            if isPrivate && zone.riskReductionEnabled {
                Text("\u{2212}\(zone.riskReductionPercent)%")
                    .font(.caption2)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(tint.opacity(0.2)))
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .frame(width: size.width, height: ZoneBox.headerHeight, alignment: .leading)
        .contentShape(Rectangle())
        .onTapGesture { onSelect() }
        .gesture(
            DragGesture(minimumDistance: 3, coordinateSpace: .named("canvas"))
                .onChanged { onDragChanged(nil, $0.translation) }
                .onEnded { onDragEnded(nil, $0.translation) }
        )
    }

    private var grips: some View {
        ForEach(ZoneHandle.allCases, id: \.self) { handle in
            let rect = box.handleRect(handle)
            RoundedRectangle(cornerRadius: 2)
                .fill(Color.accentColor)
                .frame(width: rect.width, height: rect.height)
                .position(x: rect.midX, y: rect.midY)
                .gesture(
                    DragGesture(minimumDistance: 1, coordinateSpace: .named("canvas"))
                        .onChanged { onDragChanged(handle, $0.translation) }
                        .onEnded { onDragEnded(handle, $0.translation) }
                )
        }
    }
}
