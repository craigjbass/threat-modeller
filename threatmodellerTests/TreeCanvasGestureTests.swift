import CoreGraphics
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The gestures the tree canvas installs, each driven the way SwiftUI drives
/// it: through what the gesture's `onChanged` and `onEnded` call. The design
/// in `docs/superpowers/specs/2026-09-16-attack-tree-stage-design.md` states
/// the tree canvas shares these with the architecture canvas.
@MainActor
@Suite("Driving the tree canvas gestures")
struct TreeCanvasGestureTests {
    private func target(_ threat: String, on id: String) -> SourceTreeTarget {
        SourceTreeTarget(threatId: threat, sourceKind: "component", sourceId: id)
    }

    /// An editor holding a goal fed by one step, with no project to write to.
    private func drawn() -> (TreeEditor, TreeCanvasState, TreeCanvasGestures, String, String) {
        let editor = TreeEditor()
        editor.open(
            SourceAttackTree(
                id: "t",
                name: "T",
                description: nil,
                raisesRiskBy: 10,
                goal: target("exfiltration", on: "db"),
                root: .step(SourceTreeStep(target: target("ssrf", on: "api"), note: nil))
            ),
            threats: []
        )
        let canvas = TreeCanvasState()
        let gestures = TreeCanvasGestures(editor: editor, canvas: canvas, elements: [])
        let ids = editor.graph.nodes.map(\.id)
        return (editor, canvas, gestures, ids[0], ids[1])
    }

    // MARK: selection

    @Test func aPlainClickSelectsOnlyThatNode() {
        let (_, canvas, gestures, goal, step) = drawn()

        gestures.selectNode(goal, addingToSelection: false)
        gestures.selectNode(step, addingToSelection: false)

        #expect(canvas.selectedIds == [step])
    }

    @Test func aShiftClickAddsANodeToTheSelection() {
        let (_, canvas, gestures, goal, step) = drawn()

        gestures.selectNode(goal, addingToSelection: false)
        gestures.selectNode(step, addingToSelection: true)

        #expect(canvas.selectedIds == [goal, step])
    }

    @Test func aClickOnTheBackgroundClearsTheSelection() {
        let (_, canvas, gestures, goal, _) = drawn()
        gestures.selectNode(goal, addingToSelection: false)

        gestures.canvasTap(at: CGPoint(x: 4000, y: 4000))

        #expect(canvas.hasSelection == false)
    }

    // MARK: pan and marquee

    @Test func aPlainDragOnTheBackgroundPansTheCanvas() {
        let (_, canvas, gestures, _, _) = drawn()

        gestures.backgroundDragChanged(
            from: CGPoint(x: 10, y: 10),
            to: CGPoint(x: 40, y: 30),
            by: CGSize(width: 30, height: 20),
            isShiftDown: false
        )
        gestures.backgroundDragEnded()

        #expect(canvas.transform.pan == CGSize(width: 30, height: 20))
        #expect(canvas.isPanning == false)
    }

    @Test func aShiftDragSelectsTheNodesItTouches() {
        let (_, canvas, gestures, goal, step) = drawn()
        let stepRect = gestures.rect(of: step)
        let goalRect = gestures.rect(of: goal)
        #expect(stepRect.intersects(goalRect) == false)

        gestures.backgroundDragChanged(
            from: CGPoint(x: stepRect.minX - 5, y: stepRect.minY - 5),
            to: CGPoint(x: stepRect.midX, y: stepRect.midY),
            by: .zero,
            isShiftDown: true
        )
        #expect(canvas.marqueeRect != nil)
        gestures.backgroundDragEnded()

        #expect(canvas.selectedIds == [step])
        #expect(canvas.marqueeRect == nil)
    }

    @Test func aScrollPansTheCanvas() {
        let (_, canvas, gestures, _, _) = drawn()

        gestures.scroll(by: CGSize(width: 12, height: -8))

        #expect(canvas.transform.pan == CGSize(width: 12, height: -8))
    }

    // MARK: the pointer mode

    /// Trackpad mode is what the tree canvas always did: the wheel pans.
    @Test func aWheelInTrackpadModePansTheTreeCanvas() {
        let (_, canvas, gestures, _, _) = drawn()

        gestures.wheel(
            by: CGSize(width: 12, height: -8),
            at: CGPoint(x: 100, y: 100),
            isShiftDown: false,
            mode: .trackpad
        )

        #expect(canvas.transform.pan == CGSize(width: 12, height: -8))
    }

    @Test func aWheelInMouseModeZoomsTheTreeCanvasAboutThePointer() {
        let (_, canvas, gestures, _, _) = drawn()
        let pointer = CGPoint(x: 260, y: 140)
        let under = canvas.transform.modelPoint(pointer)

        gestures.wheel(by: CGSize(width: 0, height: 20), at: pointer, isShiftDown: false, mode: .mouse)

        #expect(canvas.transform.zoom > 1)
        let after = canvas.transform.modelPoint(pointer)
        #expect(abs(after.x - under.x) < 0.0001)
        #expect(abs(after.y - under.y) < 0.0001)
    }

    @Test func aShiftWheelInMouseModePansTheTreeCanvasSideways() {
        let (_, canvas, gestures, _, _) = drawn()

        gestures.wheel(by: CGSize(width: 0, height: 24), at: CGPoint(x: 260, y: 140), isShiftDown: true, mode: .mouse)

        #expect(canvas.transform.pan == CGSize(width: 24, height: 0))
        #expect(canvas.transform.zoom == 1)
    }

    /// `TreeCanvas`'s monitor is installed once and keeps running; the
    /// closure it calls reads `PointerModeBox.mode` at event time, not the
    /// mode the box held when the closure was made. A change to the box
    /// after it is made must still reach the next wheel.
    @Test func aWheelReadsThePointerModeABoxHoldsAfterItChanges() {
        let (_, canvas, gestures, _, _) = drawn()
        let pointerMode = PointerModeBox(.trackpad)

        pointerMode.mode = .mouse
        gestures.wheel(
            by: CGSize(width: 0, height: 20),
            at: CGPoint(x: 260, y: 140),
            isShiftDown: false,
            mode: pointerMode.mode
        )

        #expect(canvas.transform.zoom > 1)
        let panAfterTheZoom = canvas.transform.pan

        pointerMode.mode = .trackpad
        gestures.wheel(
            by: CGSize(width: 0, height: 20),
            at: CGPoint(x: 260, y: 140),
            isShiftDown: false,
            mode: pointerMode.mode
        )

        #expect(
            canvas.transform.pan
                == CGSize(width: panAfterTheZoom.width, height: panAfterTheZoom.height + 20)
        )
    }

    @Test func aMiddleButtonDragPansTheTreeCanvas() {
        let (_, canvas, gestures, _, _) = drawn()

        gestures.panStep(by: CGSize(width: 40, height: 25))

        #expect(canvas.transform.pan == CGSize(width: 40, height: 25))
        #expect(canvas.isPanning)

        gestures.panStepEnded()

        #expect(canvas.isPanning == false)
    }

    /// Space held down pans, even while Shift is down, so a mouse user never
    /// draws a marquee when they meant to move the picture.
    @Test func aSpaceDragPansTheTreeCanvas() {
        let (_, canvas, gestures, _, _) = drawn()

        gestures.backgroundDragChanged(
            from: CGPoint(x: 10, y: 10),
            to: CGPoint(x: 110, y: 70),
            by: CGSize(width: 100, height: 60),
            isShiftDown: true,
            isSpaceDown: true
        )

        #expect(canvas.transform.pan == CGSize(width: 100, height: 60))
        #expect(canvas.marquee == nil)
    }

    // MARK: node drag

    @Test func aNodeDragMovesEverySelectedNodeByTheModelDistance() {
        let (_, canvas, gestures, goal, step) = drawn()
        canvas.transform = CanvasTransform(zoom: 0.5)
        let goalBefore = gestures.position(of: goal)
        let stepBefore = gestures.position(of: step)
        gestures.selectNode(goal, addingToSelection: false)
        gestures.selectNode(step, addingToSelection: true)

        gestures.nodeDragChanged(step, CGSize(width: 50, height: 10))
        #expect(gestures.position(of: step).x == stepBefore.x + 100)
        gestures.nodeDragEnded(CGSize(width: 50, height: 10))

        #expect(gestures.position(of: goal) == CGPoint(x: goalBefore.x + 100, y: goalBefore.y + 20))
        #expect(gestures.position(of: step) == CGPoint(x: stepBefore.x + 100, y: stepBefore.y + 20))
        #expect(canvas.dragTranslation == nil)
    }

    @Test func aDragOnAnUnselectedNodeSelectsItFirst() {
        let (_, canvas, gestures, goal, step) = drawn()
        gestures.selectNode(goal, addingToSelection: false)

        gestures.nodeDragChanged(step, CGSize(width: 5, height: 5))
        gestures.nodeDragEnded(CGSize(width: 5, height: 5))

        #expect(canvas.selectedIds == [step])
    }

    @Test func layOutTreePutsEveryNodeBackOnTheLayoutPoint() {
        let (_, _, gestures, _, step) = drawn()
        let before = gestures.position(of: step)
        gestures.nodeDragChanged(step, CGSize(width: 50, height: 10))
        gestures.nodeDragEnded(CGSize(width: 50, height: 10))

        gestures.layOutTree()

        #expect(gestures.position(of: step) == before)
    }

    // MARK: join

    @Test func aJoinDragFromTheHandleToAnotherNodeMakesAnEdge() {
        let (editor, canvas, gestures, goal, step) = drawn()
        editor.cutOutgoingJoin(of: step)
        #expect(editor.graph.edges.isEmpty)
        let end = canvas.transform.viewPoint(gestures.position(of: goal))

        gestures.joinDragChanged(step, CGPoint(x: end.x - 40, y: end.y))
        #expect(canvas.joining?.from == step)
        gestures.joinDragEnded(step, end)

        #expect(editor.graph.edges == [TreeGraph.Edge(from: step, to: goal)])
        #expect(canvas.joining == nil)
    }

    @Test func aJoinDragEndingOnOpenCanvasMakesNoEdge() {
        let (editor, _, gestures, _, step) = drawn()
        editor.cutOutgoingJoin(of: step)

        gestures.joinDragChanged(step, CGPoint(x: 900, y: 900))
        gestures.joinDragEnded(step, CGPoint(x: 900, y: 900))

        #expect(editor.graph.edges.isEmpty)
    }

    // MARK: drop

    @Test func aDropLandsAtTheModelPointUnderThePointer() throws {
        let editor = TreeEditor()
        editor.addTree(among: [])
        let canvas = TreeCanvasState()
        canvas.transform = CanvasTransform(pan: CGSize(width: 100, height: 100), zoom: 2)
        let api = TreeElement(kind: "component", sourceId: "api", name: "api", threats: [])
        let gestures = TreeCanvasGestures(editor: editor, canvas: canvas, elements: [api])

        #expect(gestures.drop(["component:api"], at: CGPoint(x: 300, y: 200)))

        let dropped = try #require(editor.pending.first)
        #expect(dropped.point == CGPoint(x: 100, y: 50))
        #expect(gestures.position(of: dropped.id) == CGPoint(x: 100, y: 50))
    }

    @Test func aJunctionDropSitsWhereItWasDropped() throws {
        let (editor, _, gestures, _, _) = drawn()

        #expect(gestures.drop(["junction:all"], at: CGPoint(x: 500, y: 400)))

        let junction = try #require(editor.graph.nodes.last)
        #expect(junction.kind == .allOf)
        #expect(gestures.position(of: junction.id) == CGPoint(x: 500, y: 400))
    }

    // MARK: delete

    @Test func deleteRemovesTheSelectedNodes() {
        let (editor, canvas, gestures, _, step) = drawn()
        gestures.selectNode(step, addingToSelection: false)

        gestures.deleteSelection()

        #expect(editor.graph.nodes.map(\.id).contains(step) == false)
        #expect(canvas.hasSelection == false)
    }

    // MARK: every gesture the architecture canvas has, on one tree

    /// Pan, zoom, marquee, drag, undo, context menu and Zoom to Fit, in that
    /// order, on one tree.
    @Test func everyGestureTheArchitectureCanvasHasWorksOnATree() throws {
        let (editor, canvas, gestures, goal, step) = drawn()
        canvas.visibleSize = CGSize(width: 800, height: 600)
        let menu = TreeMenu(editor: editor, canvas: canvas, elements: [])

        // Pan.
        gestures.backgroundDragChanged(
            from: .zero, to: CGPoint(x: 20, y: 10), by: CGSize(width: 20, height: 10), isShiftDown: false
        )
        gestures.backgroundDragEnded()
        #expect(canvas.transform.pan == CGSize(width: 20, height: 10))

        // Zoom.
        gestures.zoomAStep(in: true)
        #expect(canvas.transform.zoom == CanvasTransform.zoomStep)

        // Marquee, over both nodes, at this pan and zoom.
        let corner = canvas.transform.viewPoint(CGPoint(x: 0, y: 0))
        let far = canvas.transform.viewPoint(CGPoint(x: 1000, y: 1000))
        gestures.backgroundDragChanged(from: corner, to: far, by: .zero, isShiftDown: true)
        gestures.backgroundDragEnded()
        #expect(canvas.selectedIds == [goal, step])

        // Drag: both move by the model distance.
        let before = gestures.position(of: goal)
        gestures.nodeDragChanged(goal, CGSize(width: 25, height: 0))
        gestures.nodeDragEnded(CGSize(width: 25, height: 0))
        #expect(gestures.position(of: goal).x == before.x + 25 / CanvasTransform.zoomStep)

        // Context menu: cut the join through the step's menu.
        canvas.clearSelection()
        menu.selectBeforeMenu(step)
        for row in menu.node(step) {
            if case .item(let id, _, _, _, let act) = row, id == "context-tree-cut-join" { act() }
        }
        #expect(editor.graph.edges.isEmpty)

        // Undo puts the join back.
        editor.undo()
        #expect(editor.graph.edges == [TreeGraph.Edge(from: step, to: goal)])

        // Zoom to Fit: both nodes inside the visible canvas.
        gestures.zoomToFit()
        let visible = CGRect(origin: .zero, size: canvas.visibleSize)
        for id in [goal, step] {
            let rect = gestures.rect(of: id)
            let shown = CGRect(
                origin: canvas.transform.viewPoint(rect.origin),
                size: CGSize(width: rect.width * canvas.transform.zoom, height: rect.height * canvas.transform.zoom)
            )
            #expect(visible.contains(shown), "\(id) draws at \(shown)")
        }
    }

    // MARK: zoom

    @Test func zoomToFitPutsEveryNodeInTheVisibleCanvas() {
        let (_, canvas, gestures, goal, step) = drawn()
        canvas.visibleSize = CGSize(width: 800, height: 600)
        canvas.transform = CanvasTransform(pan: CGSize(width: -5000, height: -5000), zoom: 1)

        gestures.zoomToFit()

        let visible = CGRect(origin: .zero, size: canvas.visibleSize)
        for id in [goal, step] {
            let rect = gestures.rect(of: id)
            let shown = CGRect(
                origin: canvas.transform.viewPoint(rect.origin),
                size: CGSize(width: rect.width * canvas.transform.zoom, height: rect.height * canvas.transform.zoom)
            )
            #expect(visible.contains(shown), "\(id) draws at \(shown)")
        }
    }

    @Test func zoomToSelectionFitsOnlyTheSelectedNodes() {
        let (_, canvas, gestures, _, step) = drawn()
        canvas.visibleSize = CGSize(width: 800, height: 600)
        gestures.selectNode(step, addingToSelection: false)

        gestures.zoomToSelection()

        let centre = canvas.transform.viewPoint(gestures.position(of: step))
        #expect(abs(centre.x - 400) < 0.5)
        #expect(abs(centre.y - 300) < 0.5)
    }

    // MARK: the join handle

    /// The handle's hit region is at least 24 by 24 points at every zoom, so
    /// a drag that starts 10 points from its centre joins and moves nothing.
    @Test func aDragTenPointsFromTheHandleJoinsAndMovesNoNode() {
        let (editor, canvas, gestures, goal, step) = drawn()
        editor.cutOutgoingJoin(of: step)
        let sat = gestures.position(of: step)
        let handle = gestures.joinHandleRect(of: step)
        let start = CGPoint(x: handle.midX + 10, y: handle.midY)
        let end = canvas.transform.viewPoint(gestures.position(of: goal))

        gestures.dragChanged(
            on: step,
            from: start,
            to: CGPoint(x: end.x - 40, y: end.y),
            by: CGSize(width: end.x - 40 - start.x, height: end.y - start.y)
        )
        #expect(canvas.joining?.from == step)
        gestures.dragEnded(
            on: step,
            from: start,
            to: end,
            by: CGSize(width: end.x - start.x, height: end.y - start.y)
        )

        #expect(editor.graph.edges == [TreeGraph.Edge(from: step, to: goal)])
        #expect(gestures.position(of: step) == sat)
        #expect(canvas.joining == nil)

        editor.undo()

        #expect(editor.graph.edges.isEmpty)
    }

    /// The region grows as the canvas zooms out, so it stays 24 points on
    /// screen.
    @Test func theHandleRegionIsTwentyFourPointsAtEveryZoom() {
        let (_, canvas, gestures, _, step) = drawn()

        #expect(gestures.joinHandleRect(of: step).width == 24)

        canvas.transform = CanvasTransform(zoom: 0.5)

        #expect(gestures.joinHandleRect(of: step).width == 48)
        #expect(gestures.joinHandleRect(of: step).width * canvas.transform.zoom == 24)
    }

    @Test func aDragThatStartsAwayFromTheHandleMovesTheNode() {
        let (editor, _, gestures, goal, step) = drawn()
        let sat = gestures.position(of: step)
        let start = sat
        let end = CGPoint(x: start.x + 30, y: start.y)

        gestures.dragChanged(on: step, from: start, to: end, by: CGSize(width: 30, height: 0))
        gestures.dragEnded(on: step, from: start, to: end, by: CGSize(width: 30, height: 0))

        #expect(gestures.position(of: step) == CGPoint(x: sat.x + 30, y: sat.y))
        #expect(editor.graph.edges == [TreeGraph.Edge(from: step, to: goal)])
    }

    // MARK: a join is an element

    private func middle(of line: TreeEdgeLine) -> CGPoint {
        CGPoint(x: (line.start.x + line.end.x) / 2, y: (line.start.y + line.end.y) / 2)
    }

    /// A click four points off the line selects that join alone, Delete
    /// removes it alone, and undo puts it back.
    @Test func aClickNearAJoinSelectsItAndDeleteRemovesItAlone() throws {
        let (editor, canvas, gestures, goal, step) = drawn()
        let junction = try #require(editor.drop("junction:all", at: CGPoint(x: 60, y: 600), elements: []))
        editor.join(from: junction, to: goal)
        let edge = TreeGraph.Edge(from: step, to: goal)
        let line = gestures.line(of: edge)
        let near = CGPoint(x: (line.start.x + line.end.x) / 2, y: (line.start.y + line.end.y) / 2 + 4)

        gestures.canvasTap(at: near)

        #expect(canvas.selectedEdges == [edge])
        #expect(canvas.selectedIds.isEmpty)

        gestures.deleteSelection()

        #expect(editor.graph.edges == [TreeGraph.Edge(from: junction, to: goal)])
        #expect(editor.graph.nodes.count == 3)
        #expect(canvas.hasSelection == false)

        editor.undo()

        #expect(editor.graph.edges.contains(edge))
    }

    @Test func aClickAwayFromEveryJoinClearsTheSelection() {
        let (_, canvas, gestures, _, step) = drawn()
        gestures.selectNode(step, addingToSelection: false)

        gestures.canvasTap(at: CGPoint(x: 4000, y: 4000))

        #expect(canvas.hasSelection == false)
    }

    @Test func aShiftClickAddsAJoinToTheSelection() throws {
        let (editor, canvas, gestures, goal, step) = drawn()
        let junction = try #require(editor.drop("junction:all", at: CGPoint(x: 60, y: 600), elements: []))
        editor.join(from: junction, to: goal)
        let first = gestures.line(of: TreeGraph.Edge(from: step, to: goal))
        let second = gestures.line(of: TreeGraph.Edge(from: junction, to: goal))

        gestures.canvasTap(at: middle(of: first), addingToSelection: false)
        gestures.canvasTap(at: middle(of: second), addingToSelection: true)

        #expect(canvas.selectedEdges.count == 2)
    }

    @Test func aClickOnAJoinSelectsNothingWhenTheClickIsFarFromTheLine() {
        let (_, canvas, gestures, goal, step) = drawn()
        let line = gestures.line(of: TreeGraph.Edge(from: step, to: goal))

        gestures.canvasTap(at: CGPoint(x: (line.start.x + line.end.x) / 2, y: line.start.y + 40))

        #expect(canvas.hasSelection == false)
    }
}
