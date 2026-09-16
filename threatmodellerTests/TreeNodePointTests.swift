import CoreGraphics
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Where a tree node sits. The design in
/// `docs/superpowers/specs/2026-09-16-tree-node-points-design.md` states the
/// rule: a node holds its own point, and the layout runs only on Lay Out
/// Tree and for a node with no point.
@MainActor
@Suite("A tree node sits at its own point")
struct TreeNodePointTests {
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

    /// One drag of one node, the way the canvas drives it.
    private func drag(_ gestures: TreeCanvasGestures, _ id: String, by shift: CGSize) {
        gestures.selectNode(id, addingToSelection: false)
        gestures.nodeDragChanged(id, shift)
        gestures.nodeDragEnded(shift)
    }

    private func points(
        _ gestures: TreeCanvasGestures,
        _ ids: [String]
    ) -> [String: CGPoint] {
        Dictionary(uniqueKeysWithValues: ids.map { ($0, gestures.position(of: $0)) })
    }

    /// Three nodes, each dragged to a place of its own, and no join left.
    private func placedByHand() throws -> (TreeEditor, TreeCanvasGestures, [String]) {
        let (editor, canvas, gestures, goal, step) = drawn()
        let junction = try #require(editor.drop("junction:all", at: CGPoint(x: 400, y: 300), elements: []))
        editor.cutOutgoingJoin(of: step)
        drag(gestures, goal, by: CGSize(width: 120, height: 40))
        drag(gestures, step, by: CGSize(width: -30, height: 90))
        drag(gestures, junction, by: CGSize(width: 15, height: -25))
        canvas.clearSelection()
        return (editor, gestures, [goal, step, junction])
    }

    // MARK: a change to the tree moves nothing

    @Test func aJoinMovesNoNodeThePersonDidNotDrag() throws {
        let (editor, gestures, ids) = try placedByHand()
        let before = points(gestures, ids)

        editor.join(from: ids[1], to: ids[2])

        #expect(points(gestures, ids) == before)
    }

    @Test func cuttingAJoinMovesNoNode() throws {
        let (editor, gestures, ids) = try placedByHand()
        let before = points(gestures, ids)

        editor.join(from: ids[1], to: ids[2])
        #expect(points(gestures, ids) == before)
        editor.cutOutgoingJoin(of: ids[1])

        #expect(points(gestures, ids) == before)
    }

    @Test func aDeleteAndASetAsGoalMoveNoNodeThatStands() throws {
        let (editor, gestures, ids) = try placedByHand()
        let before = points(gestures, ids)

        editor.setGoal(ids[1])
        #expect(points(gestures, ids) == before)
        editor.remove([ids[2]])

        #expect(points(gestures, [ids[0], ids[1]]) == before.filter { $0.key != ids[2] })
    }

    @Test func undoOfAJoinRestoresTheTreeAndMovesNoNode() throws {
        let (editor, gestures, ids) = try placedByHand()
        let before = points(gestures, ids)
        editor.join(from: ids[1], to: ids[2])

        editor.undo()

        #expect(editor.graph.edges.isEmpty)
        #expect(points(gestures, ids) == before)
    }

    // MARK: when the layout runs

    /// The file states no point, so the window places the nodes once, from
    /// the layout. A change to the tree keeps those points.
    @Test func anOpenedTreeTakesTheLayoutPointsOnce() {
        let (editor, _, gestures, goal, step) = drawn()
        let laid = editor.graph.positions(
            nodeSize: TreeLayout.nodeSize,
            horizontalGap: TreeLayout.horizontalGap,
            verticalGap: TreeLayout.verticalGap
        )

        for id in [goal, step] {
            let point = laid[id] ?? .zero
            #expect(gestures.position(of: id) == CGPoint(
                x: point.x + TreeLayout.margin,
                y: point.y + TreeLayout.margin
            ))
        }

        let before = points(gestures, [goal, step])
        editor.cutOutgoingJoin(of: step)

        #expect(points(gestures, [goal, step]) == before)
    }

    @Test func aDroppedJunctionSitsAtTheDropPoint() throws {
        let (editor, _, gestures, _, _) = drawn()

        let junction = try #require(editor.drop("junction:all", at: CGPoint(x: 640, y: 480), elements: []))

        #expect(gestures.position(of: junction) == CGPoint(x: 640, y: 480))
    }

    @Test func layOutTreeMovesTheNodesToTheLayoutPointsAndUndoPutsTheOldOnesBack() throws {
        let (editor, gestures, ids) = try placedByHand()
        let byHand = points(gestures, ids)
        let laid = editor.graph.positions(
            nodeSize: TreeLayout.nodeSize,
            horizontalGap: TreeLayout.horizontalGap,
            verticalGap: TreeLayout.verticalGap
        )

        gestures.layOutTree()

        for id in ids {
            let point = try #require(laid[id])
            #expect(gestures.position(of: id) == CGPoint(
                x: point.x + TreeLayout.margin,
                y: point.y + TreeLayout.margin
            ))
        }

        editor.undo()

        #expect(points(gestures, ids) == byHand)
    }

    /// The menu item a person picks is the one the test above drives.
    @Test func theBackgroundMenuLaysOutTheTree() throws {
        let (editor, canvas, gestures, _, step) = drawn()
        let menu = TreeMenu(editor: editor, canvas: canvas, elements: [])
        let before = gestures.position(of: step)
        drag(gestures, step, by: CGSize(width: 70, height: 20))
        #expect(gestures.position(of: step) != before)

        for row in menu.background() {
            if case .item(let id, _, _, _, let act) = row, id == "context-tree-lay-out" { act() }
        }

        #expect(gestures.position(of: step) == before)
    }
}
