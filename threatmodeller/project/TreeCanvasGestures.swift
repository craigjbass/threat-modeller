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
    /// True while Space is held down over the canvas. The view counts the
    /// key, because AppKit states no modifier flag for Space.
    var isSpaceDown = false

    private var viewport: ViewportGestures { ViewportGestures(viewport: canvas) }

    // MARK: where everything sits, in model coordinates

    /// Every id the canvas draws: the nodes, then the pending elements.
    var everyId: [String] {
        editor.graph.nodes.map(\.id) + editor.pending.map(\.id)
    }

    func size(of id: String) -> CGSize {
        switch editor.graph.node(id)?.kind {
        case .allOf, .anyOf: TreeLayout.junctionSize
        default: TreeLayout.nodeSize
        }
    }

    /// The centre of one node: the point the editor holds for it, plus the
    /// drag in flight while the node is selected.
    func position(of id: String) -> CGPoint {
        let base: CGPoint
        if let pending = editor.pending.first(where: { $0.id == id }) {
            base = pending.point
        } else {
            base = editor.layout.point(of: id) ?? .zero
        }
        let drag = canvas.isSelected(id) ? (canvas.dragTranslation ?? .zero) : .zero
        return CGPoint(x: base.x + drag.width, y: base.y + drag.height)
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

    // MARK: where each join is drawn

    /// Where every join is drawn, in model coordinates.
    var edgeLines: [TreeEdgeLine] {
        editor.graph.edges.map { line(of: $0) }
    }

    /// Where one join is drawn: out of the right edge of the node it leaves,
    /// into the left edge of the node it feeds.
    func line(of edge: TreeGraph.Edge) -> TreeEdgeLine {
        let from = position(of: edge.from)
        let to = position(of: edge.to)
        return TreeEdgeLine(
            edge: edge,
            start: CGPoint(x: from.x + size(of: edge.from).width / 2, y: from.y),
            end: CGPoint(x: to.x - size(of: edge.to).width / 2, y: to.y)
        )
    }

    /// The join under a model point, or nil. The last drawn is the first
    /// found, the way the picture reads.
    func edge(at point: CGPoint) -> TreeGraph.Edge? {
        edgeLines.last { $0.containsClick(at: point) }?.edge
    }

    /// How far the join handle's hit region reaches from the node's right
    /// edge, in model units. The region is `TreeLayout.joinHandleHit` points
    /// on screen at every zoom.
    var joinHandleReach: CGFloat {
        TreeLayout.joinHandleHit / 2 / min(canvas.transform.zoom, 1)
    }

    /// The region a join drag starts in, in model coordinates.
    func joinHandleRect(of id: String) -> CGRect {
        let rect = rect(of: id)
        let reach = joinHandleReach
        return CGRect(
            x: rect.maxX - reach,
            y: rect.midY - reach,
            width: reach * 2,
            height: reach * 2
        )
    }

    // MARK: background

    /// A click the canvas takes. It selects the join under the pointer, and
    /// clears the selection where no join sits. The point is a view point.
    func canvasTap(at viewPoint: CGPoint, addingToSelection: Bool = false) {
        let point = canvas.transform.modelPoint(viewPoint)
        guard let edge = edge(at: point) else {
            if addingToSelection == false { canvas.clearSelection() }
            return
        }
        canvas.select(edge, addingToSelection: addingToSelection)
    }

    /// A drag on the background: the marquee while Shift is down, and the pan
    /// otherwise. Internal so a test can walk the drag without SwiftUI's
    /// gesture plumbing.
    func backgroundDragChanged(
        from start: CGPoint,
        to end: CGPoint,
        by translation: CGSize,
        isShiftDown: Bool,
        isSpaceDown: Bool = false
    ) {
        // Space held down pans, even while Shift is down. A mouse user needs
        // one gesture that always moves the picture.
        if isShiftDown && isSpaceDown == false {
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

    /// What one wheel event or one two finger scroll does, by pointer mode.
    /// The scroll monitor calls this.
    func wheel(by delta: CGSize, at viewPoint: CGPoint, isShiftDown: Bool, mode: PointerMode) {
        viewport.wheel(by: delta, at: viewPoint, isShiftDown: isShiftDown, mode: mode)
    }

    /// One step of a middle-button drag or a Space-drag.
    func panStep(by step: CGSize) {
        viewport.panStep(by: step)
    }

    /// The end of a middle-button drag or a Space-drag.
    func panStepEnded() {
        viewport.panStepEnded()
    }

    // MARK: nodes

    func selectNode(_ id: String, addingToSelection: Bool) {
        canvas.select(id, addingToSelection: addingToSelection)
    }

    func selectEdge(_ edge: TreeGraph.Edge, addingToSelection: Bool) {
        canvas.select(edge, addingToSelection: addingToSelection)
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

    /// The drag moves every selected node to where it ended. One drag is one
    /// undoable change.
    func nodeDragEnded(_ translation: CGSize) {
        let shift = canvas.transform.modelDistance(translation)
        canvas.dragTranslation = nil
        editor.move(canvas.selectedIds, by: shift)
    }

    /// A drag on a node. A drag that starts inside the join handle's region
    /// joins the node to another; every other drag moves the selection. The
    /// start and the location are view points.
    func dragChanged(on id: String, from start: CGPoint, to location: CGPoint, by translation: CGSize) {
        guard isJoining(id, from: start) else { return nodeDragChanged(id, translation) }
        joinDragChanged(id, location)
    }

    /// The end of a drag on a node: the join it drew, or the move it made.
    func dragEnded(on id: String, from start: CGPoint, to location: CGPoint, by translation: CGSize) {
        guard isJoining(id, from: start) else { return nodeDragEnded(translation) }
        joinDragEnded(id, location)
    }

    /// True while the drag that started at this view point draws a join. A
    /// drag that moved the node stays a move to its end.
    private func isJoining(_ id: String, from start: CGPoint) -> Bool {
        if canvas.joining != nil { return canvas.joining?.from == id }
        guard canvas.dragTranslation == nil else { return false }
        return joinHandleRect(of: id).contains(canvas.transform.modelPoint(start))
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

    /// Every node takes the point the layout states, as one undoable change.
    func layOutTree() {
        editor.layOutTree()
    }

    // MARK: what a drop makes

    /// A drop lands at the model point under the pointer. The editor places
    /// what the drop makes at that point, so the layout never runs for it.
    func drop(_ payloads: [String], at location: CGPoint) -> Bool {
        guard let payload = payloads.first else { return false }
        let point = canvas.transform.modelPoint(location)
        guard let id = editor.drop(payload, at: point, elements: elements) else { return false }
        canvas.select(id, addingToSelection: false)
        return true
    }

    // MARK: commands

    func deleteSelection() {
        guard canvas.hasSelection else { return }
        editor.remove(canvas.selectedIds, edges: Set(canvas.selectedEdges))
        canvas.retainOnly(Set(everyId), edges: Set(editor.graph.edges))
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
