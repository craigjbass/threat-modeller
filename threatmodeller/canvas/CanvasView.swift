import SwiftUI
import ThreatModelKit

/// The diagram. Painting order per spec section 9: background, then every
/// connection in one `Canvas` pass, then the component views.
///
/// This view holds layout. Gestures live in `CanvasGestures` and hit testing
/// in `CanvasHitTest`.
struct CanvasView: View {
    /// The margin the canvas keeps from the window's edge. The palette column
    /// collapses, and the canvas then starts at that edge itself.
    static let windowEdgeMargin: CGFloat = 16

    let session: ThreatModelSession
    let canvas: CanvasState

    private var gestures: CanvasGestures {
        CanvasGestures(session: session, canvas: canvas)
    }

    private var boxes: [String: ComponentBox] {
        CanvasHitTest.boxes(
            for: session.canvas.components,
            selected: canvas.selectedComponentIds,
            dragTranslation: canvas.dragTranslation ?? .zero
        )
    }

    var body: some View {
        // A GeometryReader takes the space the split view offers and never
        // reports its children's size back up. Without it the drawing layer,
        // which is thousands of points across, sizes the whole window.
        GeometryReader { _ in
            ZStack(alignment: .topLeading) {
                Color(nsColor: .textBackgroundColor)
                    .contentShape(Rectangle())
                    // The identifier sits on the background, not on the whole
                    // canvas: an identifier on a container overwrites the
                    // identifier of every element inside it.
                    .accessibilityIdentifier("canvas")
                    // The double-click is read first: a single tap selects,
                    // and a double-click on a flow edits its label.
                    .gesture(gestures.backgroundDoubleTap)
                    .gesture(gestures.backgroundTap)
                    .gesture(gestures.backgroundDrag)

                content
                    .scaleEffect(canvas.transform.zoom, anchor: .topLeading)
                    .offset(x: canvas.transform.pan.width, y: canvas.transform.pan.height)

                flowLabelField

                canvasToolbar
            }
        }
        .coordinateSpace(.named("canvas"))
        .clipped()
        // SwiftUI has no crosshair pointer; rectSelection is the one macOS
        // shows while a rectangle is being drawn.
        .pointerStyle(canvas.isDrawingZone ? .rectSelection : nil)
        .focusable()
        .focusEffectDisabled()
        .onKeyPress(.escape) {
            canvas.cancel() ? .handled : .ignored
        }
        .onKeyPress(.delete) {
            gestures.deleteSelection()
            return .handled
        }
        .onKeyPress(keys: [.leftArrow, .rightArrow, .upArrow, .downArrow]) { press in
            let step = press.modifiers.contains(.shift)
                ? CanvasGestures.fineNudgeStep
                : CanvasGestures.nudgeStep
            switch press.key {
            case .leftArrow: gestures.nudge(dx: -step, dy: 0)
            case .rightArrow: gestures.nudge(dx: step, dy: 0)
            case .upArrow: gestures.nudge(dx: 0, dy: -step)
            case .downArrow: gestures.nudge(dx: 0, dy: step)
            default: return .ignored
            }
            return .handled
        }
        .gesture(
            MagnifyGesture()
                .onChanged { value in
                    gestures.zoom(
                        by: 1 + (value.magnification - 1) * 0.3,
                        about: value.startLocation
                    )
                }
        )
        .safeAreaInset(edge: .bottom) {
            // One panel at a time. A node and a zone are never both the one
            // thing selected.
            if let pair = selectedPair {
                MitigatesPanel(session: session, source: pair.source, target: pair.target)
            } else if let component = selectedComponent {
                ComponentPanel(session: session, component: component)
            } else if let zone = selectedZone {
                ZonePanel(session: session, zone: zone)
            } else if let connection = selectedConnection {
                ConnectionPanel(session: session, connection: connection)
            }
        }
        .dropDestination(for: String.self) { technologyIds, location in
            guard let technologyId = technologyIds.first else { return false }
            let point = canvas.transform.modelPoint(location)
            session.add(
                technologyId: technologyId,
                x: point.x - Component.size.width / 2,
                y: point.y - Component.size.height / 2
            )
            return true
        }
    }

    private var content: some View {
        ZStack(alignment: .topLeading) {
            ForEach(session.canvas.zones, id: \.id) { zone in
                let rect = CanvasHitTest.rect(
                    for: zone,
                    drag: canvas.zoneDrag,
                    movingWith: canvas.selectedZoneIds
                )
                ZoneView(
                    zone: zone,
                    risk: session.elementRisks["zone:\(zone.id)"],
                    size: rect.size,
                    isSelected: canvas.isSelected(zoneId: zone.id),
                    onSelect: { canvas.select(zoneId: zone.id, addingToSelection: $0) },
                    onDragChanged: { gestures.zoneDragChanged(zone.id, handle: $0, translation: $1) },
                    onDragEnded: { gestures.zoneDragEnded(zone.id, handle: $0, translation: $1) },
                    isEditingName: canvas.isEditingName(.zone(zone.id)),
                    onStartEditingName: { canvas.startEditingName(.zone(zone.id)) },
                    onCommitName: { gestures.renameZone(zone.id, to: $0) },
                    onCancelName: { canvas.stopEditingName() }
                )
                .position(x: rect.midX, y: rect.midY)
            }

            if let draft = canvas.zoneDraftRect {
                RoundedRectangle(cornerRadius: 12)
                    .fill(Color.green.opacity(0.07))
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .strokeBorder(Color.accentColor, style: StrokeStyle(lineWidth: 2, dash: [6, 4]))
                    )
                    .frame(width: draft.width, height: draft.height)
                    .position(x: draft.midX, y: draft.midY)
                    .allowsHitTesting(false)
            }

            ConnectionsLayer(
                origin: contentRect.origin,
                connections: session.canvas.connections,
                boxes: boxes,
                componentsById: componentsById,
                zones: session.canvas.zones,
                risks: session.elementRisks,
                guards: session.elementGuards,
                outOfScopeComponentIds: outOfScopeComponentIds,
                selectedConnectionIds: canvas.selectedConnectionIds,
                preview: previewLine
            )
            .frame(width: contentRect.width, height: contentRect.height)
            // The layer starts back past the origin, so it is placed there
            // rather than at the origin the rest of this stack draws from.
            .offset(x: contentRect.minX, y: contentRect.minY)

            ForEach(session.canvas.components, id: \.id) { component in
                let componentBox = boxes[component.id] ?? ComponentBox(x: component.x, y: component.y)
                ComponentNodeView(
                    component: component,
                    risk: session.elementRisks["component:\(component.id)"],
                    isSelected: canvas.isSelected(componentId: component.id),
                    onSelect: { gestures.selectComponent(component.id, addingToSelection: $0) },
                    onDragChanged: { gestures.nodeDragChanged(component.id, $0) },
                    onDragEnded: { gestures.nodeDragEnded($0) },
                    onAnchorDragChanged: { gestures.anchorDragChanged(component.id, $0) },
                    onAnchorDragEnded: { gestures.anchorDragEnded(component.id, $0) },
                    zoneName: session.canvas.zones.first { $0.id == component.zoneId }?.name,
                    isEditingName: canvas.isEditingName(.component(component.id)),
                    onStartEditingName: { canvas.startEditingName(.component(component.id)) },
                    onCommitName: { gestures.renameComponent(component.id, to: $0) },
                    onCancelName: { canvas.stopEditingName() }
                )
                .position(x: componentBox.centre.x, y: componentBox.centre.y)
            }

            if let rect = canvas.marqueeRect {
                Rectangle()
                    .fill(Color.accentColor.opacity(0.12))
                    .overlay(Rectangle().strokeBorder(Color.accentColor, lineWidth: 1))
                    .frame(width: rect.width, height: rect.height)
                    .position(x: rect.midX, y: rect.midY)
                    .allowsHitTesting(false)
            }
        }
    }

    /// The field that edits a flow's label, drawn where the flow's label sits.
    @ViewBuilder
    private var flowLabelField: some View {
        if case .connection(let connectionId) = canvas.editingName,
           let rect = gestures.calloutRect(of: connectionId) {
            let connection = session.canvas.connections.first { $0.id == connectionId }
            InlineNameField(
                text: connection?.description ?? "",
                width: max(160, rect.width),
                identifier: "flow-label-field-\(connectionId)",
                commit: { gestures.labelConnection(connectionId, to: $0) },
                cancel: { canvas.stopEditingName() }
            )
            .scaleEffect(canvas.transform.zoom, anchor: .topLeading)
            .position(
                x: (rect.midX * canvas.transform.zoom) + canvas.transform.pan.width,
                y: (rect.midY * canvas.transform.zoom) + canvas.transform.pan.height
            )
        }
    }

    private var canvasToolbar: some View {
        HStack(spacing: 8) {
            Button {
                canvas.isDrawingZone ? canvas.stopDrawingZone() : canvas.startDrawingZone()
            } label: {
                Label("Draw zone", systemImage: "rectangle.dashed")
            }
            .tint(canvas.isDrawingZone ? Color.accentColor : nil)
            .accessibilityIdentifier("draw-zone")

            Divider().frame(height: 16)

            Button { gestures.zoom(by: 1 / 1.25, about: CGPoint(x: 400, y: 300)) } label: {
                Image(systemName: "minus.magnifyingglass")
            }
            .accessibilityIdentifier("zoom-out")
            Button { canvas.transform = CanvasTransform() } label: {
                Image(systemName: "1.magnifyingglass")
            }
            .accessibilityIdentifier("zoom-reset")
            Button { gestures.zoom(by: 1.25, about: CGPoint(x: 400, y: 300)) } label: {
                Image(systemName: "plus.magnifyingglass")
            }
            .accessibilityIdentifier("zoom-in")
        }
        .buttonStyle(.bordered)
        // Collapsing the palette column puts the canvas at the window's own
        // leading edge, so this margin is all that stands between the Draw
        // zone control and that edge.
        .padding(CanvasView.windowEdgeMargin)
    }

    /// The panel edits one zone at a time, so it appears only when exactly one
    /// is selected.
    private var selectedComponent: ViewedComponent? {
        guard canvas.selectedComponentIds.count == 1,
              let componentId = canvas.selectedComponentIds.first else { return nil }
        return session.canvas.components.first { $0.id == componentId }
    }

    /// The two components a mitigates edge would run between, in the order
    /// the model holds them. One component lowers a threat on another, so the
    /// bar needs both ends before it offers anything.
    private var selectedPair: (source: ViewedComponent, target: ViewedComponent)? {
        guard canvas.selectedComponentIds.count == 2 else { return nil }
        let both = session.canvas.components.filter { canvas.selectedComponentIds.contains($0.id) }
        guard both.count == 2 else { return nil }
        return (both[0], both[1])
    }

    private var selectedZone: ViewedZone? {
        guard canvas.selectedZoneIds.count == 1,
              let zoneId = canvas.selectedZoneIds.first else { return nil }
        return session.canvas.zones.first { $0.id == zoneId }
    }

    /// The one flow the panel edits, or nil while none or many are selected.
    private var selectedConnection: ViewedConnection? {
        guard canvas.selectedConnectionIds.count == 1,
              let connectionId = canvas.selectedConnectionIds.first else { return nil }
        return session.canvas.connections.first { $0.id == connectionId }
    }

    /// Every component by id, so the link layer can read the zone each end of
    /// a link sits in.
    private var componentsById: [String: ViewedComponent] {
        Dictionary(uniqueKeysWithValues: session.canvas.components.map { ($0.id, $0) })
    }

    /// The components the user turned threats off for. A flow either end of
    /// which is one of these is out of scope too.
    private var outOfScopeComponentIds: Set<String> {
        Set(session.canvas.components.filter(\.threatsDisabled).map(\.id))
    }

    /// The drawing layer follows the model, so a diagram that reaches far from
    /// the origin still draws its links, whichever way it reaches.
    private var contentRect: CGRect {
        CanvasHitTest.contentRect(
            components: session.canvas.components,
            zones: session.canvas.zones
        )
    }

    private var previewLine: (start: CGPoint, end: CGPoint)? {
        guard let drag = canvas.connectionDrag,
              let source = boxes[drag.sourceComponentId] else { return nil }
        return (start: source.centre, end: drag.currentPoint)
    }
}
