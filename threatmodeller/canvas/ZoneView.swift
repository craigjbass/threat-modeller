import SwiftUI
import ThreatModelKit

/// One zone: its dashed boundary, its header, and its resize grips when
/// selected.
///
/// A resting zone draws quietly: a faint dotted outline that states where it
/// is and keeps it selectable. What a reader looks at is the dotted bow
/// `ConnectionsLayer` draws where a flow crosses the edge, which is the mark
/// OWASP Threat Dragon uses for a trust boundary.
///
/// A selected zone draws loudly, so the thing being dragged is never faint.
/// The stroke colour states public against private. The header states the
/// name, the risk reduction, whether the zone is a privilege boundary, and how
/// many threats on the zone no control answers.
struct ZoneView: View {
    let zone: ViewedZone
    /// What the zone itself carries, or nil when it raises nothing.
    let risk: ElementRisk?
    /// The size to draw at. While a move or resize is in flight this is the
    /// size the drag produces, not the size the model holds, so the outline,
    /// the header and the grips all follow the pointer.
    let size: CGSize
    let isSelected: Bool
    let onSelect: (_ addingToSelection: Bool) -> Void
    let onDragChanged: (_ handle: ZoneHandle?, _ translation: CGSize) -> Void
    let onDragEnded: (_ handle: ZoneHandle?, _ translation: CGSize) -> Void
    /// True while this zone's name is being edited in place. A picture of the
    /// canvas edits nothing, so it takes the defaults.
    var isEditingName = false
    var onStartEditingName: () -> Void = {}
    var onWriteName: (String) -> Void = { _ in }
    var onCancelName: () -> Void = {}
    /// What a secondary click offers, and what selects the zone before the
    /// menu opens. Empty in a picture that takes no clicks.
    var menu: () -> [ElementMenu.Row] = { [] }
    var onOpenMenu: () -> Void = {}

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
                .fill(tint.opacity(isSelected ? 0.07 : 0.04))
                .overlay(
                    RoundedRectangle(cornerRadius: 12)
                        .strokeBorder(
                            isSelected ? Color.accentColor : tint.opacity(0.35),
                            style: StrokeStyle(
                                lineWidth: isSelected ? 3 : 1,
                                dash: isSelected ? [8, 6] : [2, 4]
                            )
                        )
                )
                // The body is paint, not a control. A filled shape takes the
                // click from everything drawn behind it, and the canvas puts
                // its own gesture behind: the one that selects a flow, its
                // callout, or the zone itself. A zone that took the click
                // answered none of them, so a callout over a zone could not
                // be reached at all. The header and the grips are controls
                // and keep their gestures.
                .allowsHitTesting(false)

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
            if isEditingName {
                InlineNameField(
                    text: zone.name,
                    width: min(240, max(120, size.width - 40)),
                    identifier: "zone-name-field-\(zone.id)",
                    write: onWriteName,
                    cancel: onCancelName
                )
                .layoutPriority(1)
            } else {
                Text(zone.name)
                .font(.headline)
                .lineLimit(2)
                .minimumScaleFactor(0.65)
                .layoutPriority(1)
                .onTapGesture(count: 2) { onStartEditingName() }
            }
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
                    .help(HoverText.badge(risk))
                    .accessibilityIdentifier("zone-open-threats-\(zone.id)")
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 12)
        .frame(width: size.width, height: ZoneBox.headerHeight, alignment: .leading)
        .contentShape(Rectangle())
        .help(HoverText.zone(zone, risk: risk))
        // Shift adds the zone to the selection, so several zones move and
        // are deleted together.
        .gesture(
            SpatialTapGesture().modifiers(.shift).onEnded { _ in onSelect(true) }
                .exclusively(before: SpatialTapGesture().onEnded { _ in onSelect(false) })
        )
        .gesture(
            DragGesture(minimumDistance: 3, coordinateSpace: .named("canvas"))
                .onChanged { onDragChanged(nil, $0.translation) }
                .onEnded { onDragEnded(nil, $0.translation) }
        )
        .contextMenu {
            ElementMenuView(rows: menu())
                .onAppear { onOpenMenu() }
        }
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
