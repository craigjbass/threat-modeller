import SwiftUI
import ThreatModelKit

/// The diagram. Painting order per spec section 9: background, then every
/// connection in one `Canvas` pass, then the component views.
struct CanvasView: View {
    let session: ThreatModelSession
    let canvas: CanvasState

    /// The Command-drag translation already applied to the pan.
    @State private var lastPanTranslation: CGSize = .zero

    private var boxes: [String: ComponentBox] {
        var found: [String: ComponentBox] = [:]
        for component in session.canvas.components {
            found[component.id] = box(for: component)
        }
        return found
    }

    var body: some View {
        ZStack(alignment: .topLeading) {
            Color(nsColor: .textBackgroundColor)
                .contentShape(Rectangle())
                .gesture(backgroundTap)
                .gesture(backgroundDrag)

            content
                .scaleEffect(canvas.transform.zoom, anchor: .topLeading)
                .offset(x: canvas.transform.pan.width, y: canvas.transform.pan.height)

            zoomControls
        }
        .coordinateSpace(.named("canvas"))
        .clipped()
        .accessibilityIdentifier("canvas")
        .focusable()
        .focusEffectDisabled()
        .onKeyPress(.escape) {
            canvas.cancel() ? .handled : .ignored
        }
        .onKeyPress(.delete) {
            deleteSelection()
            return .handled
        }
        .gesture(
            MagnifyGesture()
                .onChanged { value in
                    canvas.transform = canvas.transform.zoomed(
                        by: 1 + (value.magnification - 1) * 0.3,
                        about: value.startLocation
                    )
                }
        )
        .dropDestination(for: String.self) { technologyIds, location in
            guard let technologyId = technologyIds.first else { return false }
            let point = canvas.transform.modelPoint(location)
            session.add(
                technologyId: technologyId,
                x: point.x - ComponentBox.size.width / 2,
                y: point.y - ComponentBox.size.height / 2
            )
            return true
        }
    }

    private var content: some View {
        ZStack(alignment: .topLeading) {
            ConnectionsLayer(
                connections: session.canvas.connections,
                boxes: boxes,
                selectedConnectionIds: canvas.selectedConnectionIds,
                preview: previewLine
            )
            .frame(width: 20000, height: 20000)

            ForEach(session.canvas.components, id: \.id) { component in
                let componentBox = box(for: component)
                ComponentNodeView(
                    component: component,
                    isSelected: canvas.isSelected(componentId: component.id),
                    onSelect: { addingToSelection in
                        canvas.select(componentId: component.id, addingToSelection: addingToSelection)
                    },
                    onDragChanged: { translation in
                        if canvas.isSelected(componentId: component.id) == false {
                            canvas.select(componentId: component.id, addingToSelection: false)
                        }
                        canvas.dragTranslation = canvas.transform.modelDistance(translation)
                    },
                    onDragEnded: { translation in
                        commitDrag(canvas.transform.modelDistance(translation))
                    },
                    onAnchorDragChanged: { location in
                        canvas.connectionDrag = (
                            sourceComponentId: component.id,
                            currentPoint: canvas.transform.modelPoint(location)
                        )
                    },
                    onAnchorDragEnded: { location in
                        commitConnection(from: component.id, to: canvas.transform.modelPoint(location))
                    }
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

    private var zoomControls: some View {
        HStack(spacing: 4) {
            Button { zoom(by: 1 / 1.25) } label: { Image(systemName: "minus.magnifyingglass") }
                .accessibilityIdentifier("zoom-out")
            Button { canvas.transform = CanvasTransform() } label: { Image(systemName: "1.magnifyingglass") }
                .accessibilityIdentifier("zoom-reset")
            Button { zoom(by: 1.25) } label: { Image(systemName: "plus.magnifyingglass") }
                .accessibilityIdentifier("zoom-in")
        }
        .buttonStyle(.bordered)
        .padding(8)
    }

    /// The component's position is the box's top-left corner; a drag in flight
    /// shifts every selected component by the same amount.
    private func box(for component: ViewedComponent) -> ComponentBox {
        let shift = canvas.isSelected(componentId: component.id)
            ? (canvas.dragTranslation ?? .zero)
            : .zero
        return ComponentBox(x: component.x + shift.width, y: component.y + shift.height)
    }

    private var previewLine: (start: CGPoint, end: CGPoint)? {
        guard let drag = canvas.connectionDrag,
              let source = boxes[drag.sourceComponentId] else { return nil }
        return (start: source.centre, end: drag.currentPoint)
    }

    private func zoom(by factor: CGFloat) {
        canvas.transform = canvas.transform.zoomed(by: factor, about: CGPoint(x: 400, y: 300))
    }

    private var backgroundTap: some Gesture {
        SpatialTapGesture(coordinateSpace: .named("canvas")).onEnded { value in
            let point = canvas.transform.modelPoint(value.location)
            if let connectionId = connection(under: point) {
                canvas.select(connectionId: connectionId, addingToSelection: false)
            } else {
                canvas.clearSelection()
            }
        }
    }

    private var backgroundDrag: some Gesture {
        // Command-drag pans; a plain drag draws the marquee. A drag reports the
        // translation from where it started, so the pan applies the step since
        // the last change, not the whole translation again.
        DragGesture(minimumDistance: 2, coordinateSpace: .named("canvas"))
            .modifiers(.command)
            .onChanged { value in
                let step = CGSize(
                    width: value.translation.width - lastPanTranslation.width,
                    height: value.translation.height - lastPanTranslation.height
                )
                lastPanTranslation = value.translation
                canvas.transform = canvas.transform.panned(by: step)
            }
            .onEnded { _ in lastPanTranslation = .zero }
            .exclusively(
                before: DragGesture(minimumDistance: 2, coordinateSpace: .named("canvas"))
                    .onChanged { value in
                        canvas.marquee = (
                            start: canvas.transform.modelPoint(value.startLocation),
                            end: canvas.transform.modelPoint(value.location)
                        )
                    }
                    .onEnded { _ in
                        if let rect = canvas.marqueeRect {
                            canvas.select(componentIds: MarqueeSelection.selected(
                                in: rect,
                                from: session.canvas.components.map {
                                    (id: $0.id, box: ComponentBox(x: $0.x, y: $0.y))
                                }
                            ))
                        }
                        canvas.marquee = nil
                    }
            )
    }

    private func connection(under modelPoint: CGPoint) -> String? {
        for connection in session.canvas.connections {
            guard let source = boxes[connection.sourceComponentId],
                  let target = boxes[connection.targetComponentId] else { continue }
            let anchors = AnchorGeometry.nearestPair(from: source, to: target)
            let path = ConnectionPath(
                from: AnchorGeometry.point(anchors.source, of: source),
                to: AnchorGeometry.point(anchors.target, of: target)
            )
            if path.containsClick(at: modelPoint) { return connection.id }
        }
        return nil
    }

    private func commitDrag(_ translation: CGSize) {
        let moves = session.canvas.components
            .filter { canvas.isSelected(componentId: $0.id) }
            .map {
                ComponentMove(
                    componentId: $0.id,
                    x: $0.x + translation.width,
                    y: $0.y + translation.height
                )
            }
        canvas.dragTranslation = nil
        guard moves.isEmpty == false else { return }
        session.move(moves)
    }

    private func commitConnection(from sourceComponentId: String, to modelPoint: CGPoint) {
        canvas.connectionDrag = nil
        guard let target = session.canvas.components.first(where: {
            ComponentBox(x: $0.x, y: $0.y).contains(modelPoint)
        }) else { return }
        session.connect(sourceComponentId: sourceComponentId, targetComponentId: target.id)
    }

    private func deleteSelection() {
        for connectionId in canvas.selectedConnectionIds {
            session.removeConnection(connectionId)
        }
        if canvas.selectedComponentIds.isEmpty == false {
            session.removeComponents(Array(canvas.selectedComponentIds))
        }
        canvas.retainOnly(
            componentIds: Set(session.canvas.components.map(\.id)),
            connectionIds: Set(session.canvas.connections.map(\.id))
        )
    }
}
