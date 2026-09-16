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

    /// The rows of one submenu, by its identifier.
    private func submenu(_ rows: [ElementMenu.Row], _ id: String) -> [ElementMenu.Row] {
        for row in rows {
            if case .submenu(let rowId, _, let inner) = row, rowId == id { return inner }
        }
        return []
    }

    /// An editor holding the goal, one step that feeds nothing, and one
    /// junction that feeds nothing.
    private func loose() -> (TreeEditor, TreeCanvasState, TreeMenu, String, String, String) {
        let (editor, canvas, menu, goal, step) = drawn()
        editor.cutOutgoingJoin(of: step)
        let junction = editor.drop("junction:all", at: CGPoint(x: 400, y: 400), elements: []) ?? ""
        return (editor, canvas, menu, goal, step, junction)
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

    @Test func theBackgroundOffersSelectAllZoomToFitAndLayOutTree() throws {
        let (editor, canvas, menu, goal, step) = drawn()
        canvas.visibleSize = CGSize(width: 800, height: 600)
        let placed = try #require(editor.layout.point(of: step))
        editor.move([step], by: CGSize(width: 40, height: 40))

        let rows = menu.background()
        #expect(titles(rows) == ["Select All", "Zoom to Fit", "Lay Out Tree"])

        run(rows, "context-tree-select-all")
        #expect(canvas.selectedIds == [goal, step])

        run(rows, "context-tree-lay-out")
        #expect(editor.layout.point(of: step) == placed)

        let before = canvas.transform
        run(rows, "context-tree-zoom-to-fit")
        #expect(canvas.transform != before)
    }

    // MARK: Join to\u{2026}

    /// A step is offered each node it may feed by its title, and the node
    /// that may come before it as "From": a step takes one feeder.
    @Test func aStepIsOfferedEveryNodeItCanFeedAndTheNodeThatMayComeBeforeIt() {
        let (editor, _, menu, goal, step, junction) = loose()

        let rows = submenu(menu.node(step), "context-tree-join-to")

        #expect(titles(rows) == [
            editor.graph.node(goal)?.title ?? "",
            editor.graph.node(junction)?.title ?? "",
            "From " + (editor.graph.node(junction)?.title ?? "")
        ])
    }

    /// Joining a step from the step before it makes a chain, and the file
    /// states it as `then`.
    @Test func aStepIsOfferedTheStepThatMayComeBeforeIt() throws {
        let editor = TreeEditor()
        editor.open(
            SourceAttackTree(
                id: "t",
                name: "T",
                description: nil,
                raisesRiskBy: 10,
                goal: target("exfiltration", on: "db"),
                root: .all([
                    .step(SourceTreeStep(target: target("ssrf", on: "api"), note: nil)),
                    .step(SourceTreeStep(target: target("steal-x", on: "x"), note: nil))
                ])
            ),
            threats: []
        )
        let menu = TreeMenu(editor: editor, canvas: TreeCanvasState(), elements: [])
        let step = try #require(editor.graph.nodes.first { $0.title == "ssrf" }).id
        let before = try #require(editor.graph.nodes.first { $0.title == "steal-x" }).id
        editor.cutOutgoingJoin(of: before)

        let rows = submenu(menu.node(step), "context-tree-join-to")
        #expect(titles(rows) == ["From steal-x"])

        run(rows, "context-tree-join-from-\(before)")

        #expect(editor.graph.edges.contains(TreeGraph.Edge(from: before, to: step)))
        let written = try #require(editor.lastWritten)
        #expect(written.root == .all([
            .then([
                .step(SourceTreeStep(target: target("steal-x", on: "x"), note: nil)),
                .step(SourceTreeStep(target: target("ssrf", on: "api"), note: nil))
            ])
        ]))
    }

    @Test func joiningFromTheMenuDrawsTheEdgeAndUndoTakesItBack() {
        let (editor, _, menu, goal, step, _) = loose()

        run(submenu(menu.node(step), "context-tree-join-to"), "context-tree-join-to-\(goal)")

        #expect(editor.graph.edges == [TreeGraph.Edge(from: step, to: goal)])

        editor.undo()

        #expect(editor.graph.edges.isEmpty)
    }

    /// A junction takes what feeds it, so its submenu names the nodes that
    /// can feed it as well as the node it can feed.
    @Test func aJunctionIsOfferedTheNodesItCanTake() {
        let (editor, _, menu, goal, step, junction) = loose()

        let rows = submenu(menu.node(junction), "context-tree-join-to")

        #expect(titles(rows) == [
            editor.graph.node(goal)?.title ?? "",
            editor.graph.node(step)?.title ?? "",
            "From " + (editor.graph.node(step)?.title ?? "")
        ])

        run(rows, "context-tree-join-from-\(step)")

        #expect(editor.graph.edges == [TreeGraph.Edge(from: step, to: junction)])
    }

    @Test func aNodeThatFeedsOneNodeIsOfferedNoJoin() {
        let (_, _, menu, _, step) = drawn()

        #expect(submenu(menu.node(step), "context-tree-join-to").isEmpty)
    }

    /// Two selected nodes are joined from the first selected to the second.
    @Test func theBackgroundOffersJoinForTwoSelectedNodes() {
        let (editor, canvas, menu, goal, step, _) = loose()
        canvas.select(step, addingToSelection: false)
        canvas.select(goal, addingToSelection: true)

        run(menu.background(), "context-tree-join")

        #expect(editor.graph.edges == [TreeGraph.Edge(from: step, to: goal)])

        editor.undo()

        #expect(editor.graph.edges.isEmpty)
    }

    // MARK: cutting one join of several

    /// A junction that feeds three nodes names each edge by its far end, and
    /// cutting one leaves the other two.
    @Test func aNodeThatFeedsSeveralNamesEachEdgeByItsFarEnd() throws {
        let (editor, _, menu, goal, _, junction) = loose()
        let any = try #require(editor.drop("junction:any", at: CGPoint(x: 600, y: 600), elements: []))
        let second = try #require(editor.drop("junction:all", at: CGPoint(x: 800, y: 800), elements: []))
        editor.join(from: junction, to: goal)
        editor.join(from: junction, to: any)
        editor.join(from: junction, to: second)

        let rows = submenu(menu.node(junction), "context-tree-cut-join")
        #expect(titles(rows) == [
            editor.graph.node(goal)?.title ?? "",
            "ANY",
            "ALL",
            "Cut every Outgoing Join"
        ])

        run(rows, "context-tree-cut-join-\(any)")

        #expect(editor.graph.edges.filter { $0.from == junction }.count == 2)

        editor.undo()

        #expect(editor.graph.edges.filter { $0.from == junction }.count == 3)

        run(rows, "context-tree-cut-every-join")

        #expect(editor.graph.edges.contains { $0.from == junction } == false)
    }

    // MARK: the menu on one join

    @Test func theMenuOnAJoinCutsThatJoinAlone() {
        let (editor, _, menu, goal, step) = drawn()
        let edge = TreeGraph.Edge(from: step, to: goal)

        let rows = menu.edge(edge)
        #expect(titles(rows) == ["Cut this Join", "Delete"])

        run(rows, "context-tree-edge-cut")

        #expect(editor.graph.edges.isEmpty)
        #expect(editor.graph.nodes.count == 2)

        editor.undo()

        #expect(editor.graph.edges == [edge])
    }

    @Test func aSecondaryClickOnAJoinSelectsIt() {
        let (_, canvas, menu, goal, step) = drawn()
        let edge = TreeGraph.Edge(from: step, to: goal)

        menu.selectBeforeMenu(edge)

        #expect(canvas.selectedEdges == [edge])
    }

    @Test func deleteOnAJoinMenuRemovesTheSelectedJoin() {
        let (editor, _, menu, goal, step) = drawn()
        let edge = TreeGraph.Edge(from: step, to: goal)
        menu.selectBeforeMenu(edge)

        run(menu.edge(edge), "context-tree-edge-delete")

        #expect(editor.graph.edges.isEmpty)
        #expect(editor.graph.nodes.count == 2)
    }
}
