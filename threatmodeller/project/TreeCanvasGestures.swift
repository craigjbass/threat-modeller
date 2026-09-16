import AppKit
import CoreGraphics
import ThreatModelKit

/// Every gesture the tree canvas installs, and what each one commits.
///
/// Split out of `TreeCanvas` so that view holds layout only. This type reads
/// the editor and the canvas state, and changes the tree through the editor.
/// It draws nothing. The rules it shares with the architecture canvas come
/// from `ViewportGestures`; what is its own is which rectangles the nodes
/// take and what a drag on one does.
@MainActor
struct TreeCanvasGestures: CanvasZooming {
    let editor: TreeEditor
    let canvas: TreeCanvasState
    /// The elements the list beside the canvas offers, for what a drop makes.
    let elements: [TreeElement]

    static let nodeSize = CGSize(width: 190, height: 56)
    static let junctionSize = CGSize(width: 90, height: 40)
    static let horizontalGap: CGFloat = 56
    static let verticalGap: CGFloat = 28
    /// The room the derived layout keeps from the origin.
    static let margin: CGFloat = 32

    private var viewport: ViewportGestures { ViewportGestures(viewport: canvas) }

    // MARK: where everything sits, in model coordinates

    private var laidOut: [String: CGPoint] {
        editor.graph.positions(
            nodeSize: Self.nodeSize,
            horizontalGap: Self.horizontalGap,
            verticalGap: Self.verticalGap
        )
    }

    /// Every id the canvas draws: the nodes, then the pending elements.
    var everyId: [String] {
        editor.graph.nodes.map(\.id) + editor.pending.map(\.id)
    }

    func size(of id: String) -> CGSize {
        switch editor.graph.node(id)?.kind {
        case .allOf, .anyOf: Self.junctionSize
        default: Self.nodeSize
        }
    }

    /// The centre of one node: the derived layout, plus the hold a drag left,
    /// plus the drag in flight while the node is selected.
    func position(of id: String) -> CGPoint {
        let base: CGPoint
        if let pending = editor.pending.first(where: { $0.id == id }) {
            base = pending.point
        } else {
            let laid = laidOut[id] ?? .zero
            base = CGPoint(x: laid.x + Self.margin, y: laid.y + Self.margin)
        }
        let hold = canvas.held[id] ?? .zero
        let drag = canvas.isSelected(id) ? (canvas.dragTranslation ?? .zero) : .zero
        return CGPoint(
            x: base.x + hold.width + drag.width,
            y: base.y + hold.height + drag.height
        )
    }

    func rect(of id: String) -> CGRect {
        let centre = position(of: id)
        let size = size(of: id)
        return CGRect(
            x: centre.x - size.width / 2,
            y: centre.y - size.height / 2,
            width: size.width,
            height: size.height
        )
    }

    /// The node or pending element under a model point, or nil. The last
    /// drawn is the first found, the way the picture reads.
    func node(at point: CGPoint) -> String? {
        everyId.last { rect(of: $0).contains(point) }
    }

    /// The rectangle holding what is named, or nil for nothing.
    private func bounds(of ids: [String]) -> CGRect? {
        SelectionBounds.rect(
            components: ids.map {
                let rect = rect(of: $0)
                return (rect.minX, rect.minY, rect.width, rect.height)
            },
            zones: []
        )
    }

    // MARK: background

    func backgroundTap() {
        canvas.clearSelection()
    }

    /// A drag on the background: the marquee while Shift is down, and the pan
    /// otherwise. Internal so a test can walk the drag without SwiftUI's
    /// gesture plumbing.
    func backgroundDragChanged(
        from start: CGPoint,
        to end: CGPoint,
        by translation: CGSize,
        isShiftDown: Bool
    ) {
        if isShiftDown {
            viewport.marqueeDragChanged(from: start, to: end)
        } else {
            viewport.panDragChanged(by: translation)
        }
    }

    /// The end of either background drag. A marquee selects every node it
    /// touches.
    func backgroundDragEnded() {
        guard let rect = viewport.dragEnded() else { return }
        canvas.select(everyId.filter { rect.intersects(self.rect(of: $0)) })
    }

    func scroll(by delta: CGSize) {
        viewport.scroll(by: delta)
    }

    // MARK: nodes

    func selectNode(_ id: String, addingToSelection: Bool) {
        canvas.select(id, addingToSelection: addingToSelection)
    }

    func selectAll() {
        canvas.select(everyId)
    }

    /// A drag on a node moves the whole selection. A drag on a node outside
    /// the selection selects that one first.
    func nodeDragChanged(_ id: String, _ translation: CGSize) {
        if canvas.isSelected(id) == false {
            canvas.select(id, addingToSelection: false)
        }
        canvas.dragTranslation = canvas.transform.modelDistance(translation)
    }

    /// The drag holds every selected node where it ended, until Lay Out Tree
    /// or the next open lays it out again.
    func nodeDragEnded(_ translation: CGSize) {
        let shift = canvas.transform.modelDistance(translation)
        canvas.dragTranslation = nil
        for id in canvas.selectedIds {
            let hold = canvas.held[id] ?? .zero
            canvas.held[id] = CGSize(width: hold.width + shift.width, height: hold.height + shift.height)
        }
    }

    /// A drag from a node's join handle. The location is a view point.
    func joinDragChanged(_ id: String, _ location: CGPoint) {
        canvas.joining = (from: id, to: canvas.transform.modelPoint(location))
    }

    /// A join ending on another node makes an edge: the node it started from
    /// feeds the one it ended on. One ending anywhere else makes nothing.
    func joinDragEnded(_ id: String, _ location: CGPoint) {
        canvas.joining = nil
        let point = canvas.transform.modelPoint(location)
        guard let target = node(at: point), target != id,
              editor.graph.node(target) != nil else { return }
        editor.join(from: id, to: target)
    }

    /// Drops every hold, so the derived layout is drawn again.
    func layOutAgain() {
        canvas.layOutAgain()
    }

    // MARK: what a drop makes

    /// A drop lands at the model point under the pointer. A junction is laid
    /// out by the tree, so it is held at the drop point until the next lay
    /// out; a pending element sits where it was dropped.
    func drop(_ payloads: [String], at location: CGPoint) -> Bool {
        guard let payload = payloads.first else { return false }
        let point = canvas.transform.modelPoint(location)
        guard let id = editor.drop(payload, at: point, elements: elements) else { return false }
        if editor.graph.node(id) != nil {
            let laid = position(of: id)
            canvas.held[id] = CGSize(width: point.x - laid.x, height: point.y - laid.y)
        }
        canvas.select(id, addingToSelection: false)
        return true
    }

    // MARK: commands

    func deleteSelection() {
        guard canvas.hasSelection else { return }
        editor.remove(canvas.selectedIds)
        canvas.retainOnly(Set(everyId))
    }

    func zoom(by factor: CGFloat, about viewPoint: CGPoint) {
        viewport.zoom(by: factor, about: viewPoint)
    }

    func zoomAStep(in closer: Bool) {
        viewport.zoomAStep(in: closer)
    }

    func zoomToActualSize() {
        viewport.zoomToActualSize()
    }

    /// Fits every node in the visible canvas.
    func zoomToFit() {
        viewport.fit(bounds(of: everyId))
    }

    /// Fits the selected nodes in the visible canvas. With nothing selected
    /// it changes nothing.
    func zoomToSelection() {
        viewport.fit(bounds(of: everyId.filter { canvas.isSelected($0) }))
    }
}
