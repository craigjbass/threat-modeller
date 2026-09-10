import SwiftUI
import ThreatModelKit

/// The diagram. Painting order per spec section 9: background, then every
/// connection in one `Canvas` pass, then the component views.
///
/// This view holds layout. Gestures live in `CanvasGestures` and hit testing
/// in `CanvasHitTest`.
struct CanvasView: View {
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
                    .gesture(gestures.backgroundTap)
                    .gesture(gestures.backgroundDrag)

                content
                    .scaleEffect(canvas.transform.zoom, anchor: .topLeading)
                    .offset(x: canvas.transform.pan.width, y: canvas.transform.pan.height)

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
            if let component = selectedComponent {
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
                let rect = CanvasHitTest.rect(for: zone, drag: canvas.zoneDrag)
                ZoneView(
                    zone: zone,
                    size: rect.size,
                    isSelected: canvas.isSelected(zoneId: zone.id),
                    onSelect: { canvas.select(zoneId: zone.id) },
                    onDragChanged: { gestures.zoneDragChanged(zone.id, handle: $0, translation: $1) },
                    onDragEnded: { gestures.zoneDragEnded(zone.id, handle: $0, translation: $1) }
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
                connections: session.canvas.connections,
                boxes: boxes,
                selectedConnectionIds: canvas.selectedConnectionIds,
                preview: previewLine
            )
            .frame(width: contentSize.width, height: contentSize.height)

            ForEach(session.canvas.components, id: \.id) { component in
                let componentBox = boxes[component.id] ?? ComponentBox(x: component.x, y: component.y)
                ComponentNodeView(
                    component: component,
                    isSelected: canvas.isSelected(componentId: component.id),
                    onSelect: { gestures.selectComponent(component.id, addingToSelection: $0) },
                    onDragChanged: { gestures.nodeDragChanged(component.id, $0) },
                    onDragEnded: { gestures.nodeDragEnded($0) },
                    onAnchorDragChanged: { gestures.anchorDragChanged(component.id, $0) },
                    onAnchorDragEnded: { gestures.anchorDragEnded(component.id, $0) },
                    zoneName: session.canvas.zones.first { $0.id == component.zoneId }?.name
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
        .padding(8)
    }

    /// The panel edits one zone at a time, so it appears only when exactly one
    /// is selected.
    private var selectedComponent: ViewedComponent? {
        guard canvas.selectedComponentIds.count == 1,
              let componentId = canvas.selectedComponentIds.first else { return nil }
        return session.canvas.components.first { $0.id == componentId }
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

    /// The drawing layer follows the model, so a saved diagram that reaches
    /// far from the origin still draws its links.
    private var contentSize: CGSize {
        CanvasHitTest.contentSize(
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
