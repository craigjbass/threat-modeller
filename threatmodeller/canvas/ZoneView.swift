import SwiftUI
import ThreatModelKit

/// One zone: its dashed boundary, its header, and its resize grips when
/// selected.
///
/// Every zone draws dashed, the way a trust boundary does. The stroke colour
/// states public against private, because the dash no longer can. The header
/// states the name, the risk reduction, whether the zone is a privilege
/// boundary, and how many threats on the zone no control answers.
struct ZoneView: View {
    let zone: ViewedZone
    /// What the zone itself carries, or nil when it raises nothing.
    let risk: ElementRisk?
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
                                lineWidth: isSelected ? 3 : 2,
                                dash: [8, 6]
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
            if zone.boundaryId == "privilege" {
                Text("Privilege")
                    .font(.caption2)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(Color.purple.opacity(0.2)))
            }
            if let risk, risk.openCount > 0 {
                Text("\(risk.openCount)")
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(
                        Capsule().fill(
                            RiskPalette.background(forLevelId: risk.highestLevelId ?? "")
                        )
                    )
                    .accessibilityIdentifier("zone-open-threats-\(zone.id)")
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
