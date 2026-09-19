import SwiftUI
import ThreatModelKit

/// One component on the canvas: its data flow diagram shape, the risk it
/// carries, its chips, and the four anchor handles a connection drag starts
/// from.
///
/// The outline states the highest residual risk level on the component. The
/// badge states how many threats no control answers. A component that raises
/// nothing draws in the quiet secondary colour, and a component the user turned
/// threats off for draws grey and dashed, the way an out-of-scope element does.
/// A proposed component draws a broken outline and a Proposed chip, so a reader
/// tells a planned component from one that runs in Production today.
struct ComponentNodeView: View {
    let component: ViewedComponent
    /// What the component carries, or nil when it raises nothing.
    let risk: ElementRisk?
    let isSelected: Bool
    let onSelect: (_ addingToSelection: Bool) -> Void
    let onDragChanged: (CGSize) -> Void
    let onDragEnded: (CGSize) -> Void
    let onAnchorDragChanged: (CGPoint) -> Void
    let onAnchorDragEnded: (CGPoint) -> Void
    /// The display name of the zone holding this component, or nil. The rule
    /// is the component's centre inside the zone below its header, which is
    /// invisible without this badge.
    let zoneName: String?
    /// The names of the clients a user holds, for the hover. Empty for a
    /// technology component.
    var clientNames: [String] = []
    /// The colour the project's classification scheme states for this
    /// component's sensitivity, or nil to paint the chip in the quiet grey
    /// default.
    var classificationColour: Color? = nil
    /// True while this node's name is being edited in place. A picture of the
    /// canvas edits nothing, so it takes the defaults.
    var isEditingName = false
    var onStartEditingName: () -> Void = {}
    var onWriteName: (String) -> Void = { _ in }
    var onCancelName: () -> Void = {}
    /// What a secondary click offers, and what selects the node before the
    /// menu opens. Empty in a picture that takes no clicks.
    var menu: () -> [ElementMenu.Row] = { [] }
    var onOpenMenu: () -> Void = {}

    @State private var isHovering = false

    private var shape: DiagramShape {
        DiagramShape(rawValue: component.shapeId) ?? .process
    }

    /// The footprint, moved to the view's own origin.
    private var footprint: CGRect {
        CGRect(origin: .zero, size: ComponentBox(x: 0, y: 0, shape: shape).rect.size)
    }

    private var isOutOfScope: Bool { component.threatsDisabled }

    /// A component the file calls planned rather than deployed.
    private var isProposed: Bool {
        component.statusId == ComponentStatus.proposed.rawValue
    }

    private var outlineColour: Color {
        if isOutOfScope { return .secondary }
        if isSelected { return .accentColor }
        guard let levelId = risk?.highestLevelId else { return .secondary.opacity(0.4) }
        return RiskPalette.colour(forLevelId: levelId)
    }

    private var outlineStyle: StrokeStyle {
        StrokeStyle(
            lineWidth: isSelected ? 2.5 : 1.5,
            dash: isOutOfScope ? [6, 4] : (isProposed ? [3, 3] : [])
        )
    }

    private var openCount: Int { isOutOfScope ? 0 : (risk?.openCount ?? 0) }

    var body: some View {
        VStack(spacing: 4) {
            drawnShape
            chips
        }
        .opacity(isOutOfScope ? 0.45 : 1)
        .frame(width: ComponentBox.slotSize.width)
        .contentShape(Rectangle())
        .help(HoverText.node(component, zoneName: zoneName, risk: risk, clientNames: clientNames))
        .onHover { isHovering = $0 }
        // Without an explicit element SwiftUI reports the node's texts
        // separately, and the identifier lands on each of them instead of the
        // node. A user interface test queries this identifier.
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier(component.isUser ? "node-user" : "node-\(component.technologyId)")
        // A double-click anywhere on the node edits its name, so the target
        // is the whole node rather than the two lines of text on it.
        .gesture(
            TapGesture(count: 2).onEnded { onStartEditingName() }
                .exclusively(
                    before: SpatialTapGesture().modifiers(.shift).onEnded { _ in onSelect(true) }
                        .exclusively(before: SpatialTapGesture().onEnded { _ in onSelect(false) })
                )
        )
        .gesture(
            DragGesture(minimumDistance: 3, coordinateSpace: .named("canvas"))
                .onChanged { onDragChanged($0.translation) }
                .onEnded { onDragEnded($0.translation) }
        )
        .contextMenu {
            // The menu opens on the thing under the pointer, so the thing
            // under the pointer is what is selected.
            let rows = menu()
            ElementMenuView(rows: rows)
                .onAppear { onOpenMenu() }
        }
    }

    private var drawnShape: some View {
        ZStack {
            if let filled = ComponentShapePath.fill(for: shape, in: footprint) {
                filled.fill(Color(nsColor: .controlBackgroundColor))
            }

            ComponentShapePath.path(for: shape, in: footprint)
                .stroke(outlineColour, style: outlineStyle)

            if isEditingName {
                InlineNameField(
                    text: component.name,
                    width: footprint.width - 16,
                    identifier: "node-name-field-\(component.id)",
                    write: onWriteName,
                    cancel: onCancelName
                )
            } else {
                Text(component.name)
                    .font(.headline)
                    .lineLimit(2)
                    .multilineTextAlignment(.center)
                    .frame(width: footprint.width - 16)
            }

            if openCount > 0 { badge }

            if isHovering || isSelected {
                ForEach(ConnectionAnchor.allCases, id: \.self) { anchor in
                    anchorHandle(anchor)
                }
            }
        }
        .frame(width: footprint.width, height: footprint.height)
    }

    private var badge: some View {
        Text("\(openCount)")
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 5)
            .padding(.vertical, 1)
            .background(
                Capsule().fill(RiskPalette.background(forLevelId: risk?.highestLevelId ?? ""))
            )
            .overlay(Capsule().strokeBorder(outlineColour, lineWidth: 1))
            .position(x: footprint.maxX, y: footprint.minY)
            .help(HoverText.badge(risk))
            .accessibilityIdentifier("node-open-threats-\(component.id)")
    }

    /// The provider, the sensitivity and the zone sit below the shape. A
    /// 104 point circle cannot hold the name and the chips together, and one
    /// rule for all three shapes beats three rules.
    ///
    /// A user's row reads USER, the role, the access and a Threat actor chip
    /// when the user names one. The row is the mark that tells a user from a
    /// technology drawn with the actor shape. An adversary's row reads
    /// ADVERSARY in red in place of USER.
    private var chips: some View {
        HStack(spacing: 6) {
            if component.isUser {
                Text(component.isAdversary ? "ADVERSARY" : "USER")
                    .font(.caption2)
                    .lineLimit(1)
                    .foregroundStyle(component.isAdversary ? Color.red : Color.secondary)
                if component.role.isEmpty == false {
                    Text(component.role)
                        .font(.caption2)
                        .lineLimit(1)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(Color.secondary.opacity(0.15)))
                        .accessibilityIdentifier("node-role-\(component.id)")
                }
                Text(PrivilegeLevel(rawValue: component.runsAsId)?.label ?? component.runsAsId)
                    .font(.caption2)
                    .lineLimit(1)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(Color.blue.opacity(0.15)))
                if component.threatActorId != nil {
                    Text("Threat actor")
                        .font(.caption2)
                        .lineLimit(1)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(Color.red.opacity(0.2)))
                        .accessibilityIdentifier("node-threat-actor-\(component.id)")
                }
            } else {
                Text(component.providerId.isEmpty ? "unknown" : component.providerId.uppercased())
                    .font(.caption2)
                    .lineLimit(1)
                    .foregroundStyle(.secondary)
                Text(component.sensitivityId.capitalized)
                    .font(.caption2)
                    .lineLimit(1)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill((classificationColour ?? Color.secondary).opacity(0.15)))
                    .accessibilityIdentifier("node-sensitivity-\(component.id)")
            }
            if isProposed && !isOutOfScope {
                Text(ComponentStatus.proposed.label)
                    .font(.caption2)
                    .lineLimit(1)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(Color.orange.opacity(0.22)))
                    .accessibilityIdentifier("node-status-\(component.id)")
            }
            if let zoneName {
                Text(zoneName)
                    .font(.caption2)
                    .lineLimit(1)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 1)
                    .background(Capsule().fill(Color.green.opacity(0.18)))
            }
        }
        // The row stays inside the slot, so a chip never reaches the node
        // beside it. A long zone name truncates instead.
        .frame(width: ComponentBox.slotSize.width - 8)
    }

    private func anchorHandle(_ anchor: ConnectionAnchor) -> some View {
        let box = ComponentBox(x: 0, y: 0, shape: shape)
        let point = CGPoint(AnchorGeometry.point(anchor, of: box.rect.modelRect))
        let origin = box.rect.origin

        return Circle()
            .fill(Color.accentColor)
            .frame(width: 9, height: 9)
            .position(x: point.x - origin.x, y: point.y - origin.y)
            .gesture(
                DragGesture(minimumDistance: 1, coordinateSpace: .named("canvas"))
                    .onChanged { onAnchorDragChanged($0.location) }
                    .onEnded { onAnchorDragEnded($0.location) }
            )
    }
}
