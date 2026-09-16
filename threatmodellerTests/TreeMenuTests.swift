import CoreGraphics
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The context menus on the tree canvas. Each row is proved to call the same
/// editor verb the selection panel calls.
@MainActor
struct TreeMenuTests {
    private func target(_ threat: String, on id: String) -> SourceTreeTarget {
        SourceTreeTarget(threatId: threat, sourceKind: "component", sourceId: id)
    }

    private func drawn() -> (TreeEditor, TreeCanvasState, TreeMenu, String, String) {
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
        let menu = TreeMenu(editor: editor, canvas: canvas, elements: [])
        let ids = editor.graph.nodes.map(\.id)
        return (editor, canvas, menu, ids[0], ids[1])
    }

    private func run(_ rows: [ElementMenu.Row], _ id: String) {
        for row in rows {
            if case .item(let rowId, _, _, _, let act) = row, rowId == id { act() }
        }
    }

    private func titles(_ rows: [ElementMenu.Row]) -> [String] {
        rows.map(\.title).filter { $0.isEmpty == false }
    }

    @Test func aStepOffersSetAsGoalCutTheJoinAndDelete() {
        let (_, _, menu, _, step) = drawn()

        #expect(titles(menu.node(step)) == ["Set as Goal", "Cut the Outgoing Join", "Delete"])
    }

    @Test func theGoalOffersOnlyDelete() {
        let (_, _, menu, goal, _) = drawn()

        #expect(titles(menu.node(goal)) == ["Delete"])
    }

    @Test func setAsGoalMovesTheMark() {
        let (editor, _, menu, _, step) = drawn()

        run(menu.node(step), "context-tree-set-goal")

        #expect(editor.graph.goalId == step)
    }

    @Test func cutTheOutgoingJoinDropsTheEdge() {
        let (editor, _, menu, _, step) = drawn()

        run(menu.node(step), "context-tree-cut-join")

        #expect(editor.graph.edges.isEmpty)
    }

    @Test func deleteRemovesWhatTheClickSelected() {
        let (editor, canvas, menu, _, step) = drawn()

        menu.selectBeforeMenu(step)
        run(menu.node(step), "context-tree-delete")

        #expect(editor.graph.nodes.map(\.id) == [editor.graph.goalId])
        #expect(canvas.hasSelection == false)
    }

    @Test func aSecondaryClickOnASelectedNodeKeepsTheSelection() {
        let (_, canvas, menu, goal, step) = drawn()
        canvas.select(goal, addingToSelection: false)
        canvas.select(step, addingToSelection: true)

        menu.selectBeforeMenu(step)

        #expect(canvas.selectedIds == [goal, step])
    }

    @Test func aPendingElementOffersItsThreatsThenDelete() throws {
        let editor = TreeEditor()
        editor.addTree(among: [])
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let elements = TreeElement.list(
            threats: session.threats,
            components: session.canvas.components,
            connections: [],
            zones: []
        )
        let element = try #require(elements.first)
        let id = try #require(editor.drop(element.payload, at: .zero, elements: elements))
        let menu = TreeMenu(editor: editor, canvas: TreeCanvasState(), elements: elements)

        let rows = menu.pending(id)
        #expect(titles(rows) == element.threats.map(\.name) + ["Delete"])

        run(rows, "context-pending-\(try #require(element.threats.first).threatKey)")

        #expect(editor.pending.isEmpty)
        #expect(editor.graph.nodes.count == 1)
    }

    @Test func theBackgroundOffersSelectAllZoomToFitAndLayOutTree() {
        let (_, canvas, menu, goal, step) = drawn()
        canvas.visibleSize = CGSize(width: 800, height: 600)
        canvas.held[step] = CGSize(width: 40, height: 40)

        let rows = menu.background()
        #expect(titles(rows) == ["Select All", "Zoom to Fit", "Lay Out Tree"])

        run(rows, "context-tree-select-all")
        #expect(canvas.selectedIds == [goal, step])

        run(rows, "context-tree-lay-out")
        #expect(canvas.held.isEmpty)

        let before = canvas.transform
        run(rows, "context-tree-zoom-to-fit")
        #expect(canvas.transform != before)
    }
}
