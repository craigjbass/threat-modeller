import SwiftUI
import ThreatModelKit

/// Every gesture the canvas installs, and what each one commits.
///
/// Split out of `CanvasView` so that view holds layout only. This type reads
/// the session and the canvas state and calls use cases through the session.
/// It draws nothing.
@MainActor
struct CanvasGestures {
    let session: ThreatModelSession
    let canvas: CanvasState

    private var boxes: [String: ComponentBox] {
        CanvasHitTest.boxes(
            for: session.canvas.components,
            selected: canvas.selectedComponentIds,
            dragTranslation: canvas.dragTranslation ?? .zero
        )
    }

    // MARK: background

    var backgroundTap: some Gesture {
        SpatialTapGesture(coordinateSpace: .named("canvas")).onEnded { value in
            let point = canvas.transform.modelPoint(value.location)
            if let connectionId = CanvasHitTest.connection(
                under: point,
                connections: session.canvas.connections,
                boxes: boxes
            ) {
                canvas.select(connectionId: connectionId, addingToSelection: false)
            } else {
                canvas.clearSelection()
            }
        }
    }

    var backgroundDrag: some Gesture {
        // Command-drag pans; a plain drag draws the marquee. A drag reports the
        // translation from where it started, so the pan applies the step since
        // the last change, not the whole translation again.
        DragGesture(minimumDistance: 2, coordinateSpace: .named("canvas"))
            .modifiers(.command)
            .onChanged { value in
                let step = CGSize(
                    width: value.translation.width - canvas.lastPanTranslation.width,
                    height: value.translation.height - canvas.lastPanTranslation.height
                )
                canvas.lastPanTranslation = value.translation
                canvas.transform = canvas.transform.panned(by: step)
            }
            .onEnded { _ in canvas.lastPanTranslation = .zero }
            .exclusively(before: marqueeDrag)
    }

    private var marqueeDrag: some Gesture {
        DragGesture(minimumDistance: 2, coordinateSpace: .named("canvas"))
            .onChanged { value in
                canvas.marquee = (
                    start: canvas.transform.modelPoint(value.startLocation),
                    end: canvas.transform.modelPoint(value.location)
                )
            }
            .onEnded { _ in commitMarquee() }
    }

    private func commitMarquee() {
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

    // MARK: nodes

    func selectComponent(_ componentId: String, addingToSelection: Bool) {
        canvas.select(componentId: componentId, addingToSelection: addingToSelection)
    }

    func nodeDragChanged(_ componentId: String, _ translation: CGSize) {
        if canvas.isSelected(componentId: componentId) == false {
            canvas.select(componentId: componentId, addingToSelection: false)
        }
        canvas.dragTranslation = canvas.transform.modelDistance(translation)
    }

    func nodeDragEnded(_ translation: CGSize) {
        let shift = canvas.transform.modelDistance(translation)
        let moves = session.canvas.components
            .filter { canvas.isSelected(componentId: $0.id) }
            .map {
                ComponentMove(
                    componentId: $0.id,
                    x: $0.x + shift.width,
                    y: $0.y + shift.height
                )
            }
        canvas.dragTranslation = nil
        guard moves.isEmpty == false else { return }
        session.move(moves)
    }

    func anchorDragChanged(_ componentId: String, _ location: CGPoint) {
        canvas.connectionDrag = (
            sourceComponentId: componentId,
            currentPoint: canvas.transform.modelPoint(location)
        )
    }

    func anchorDragEnded(_ componentId: String, _ location: CGPoint) {
        canvas.connectionDrag = nil
        let point = canvas.transform.modelPoint(location)
        guard let targetId = CanvasHitTest.component(
            under: point,
            components: session.canvas.components
        ) else { return }
        session.connect(sourceComponentId: componentId, targetComponentId: targetId)
    }

    // MARK: commands

    func deleteSelection() {
        for connectionId in canvas.selectedConnectionIds {
            session.removeConnection(connectionId)
        }
        for zoneId in canvas.selectedZoneIds {
            session.removeZone(zoneId)
        }
        if canvas.selectedComponentIds.isEmpty == false {
            session.removeComponents(Array(canvas.selectedComponentIds))
        }
        canvas.retainOnly(
            componentIds: Set(session.canvas.components.map(\.id)),
            connectionIds: Set(session.canvas.connections.map(\.id)),
            zoneIds: Set(session.canvas.zones.map(\.id))
        )
    }

    func zoom(by factor: CGFloat, about viewPoint: CGPoint) {
        canvas.transform = canvas.transform.zoomed(by: factor, about: viewPoint)
    }
}
