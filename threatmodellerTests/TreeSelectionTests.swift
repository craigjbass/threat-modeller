import CoreGraphics
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// What the right sidebar of the Attack Trees stage shows for what is
/// selected: the threat, the element and the score of one node.
@MainActor
struct TreeSelectionTests {
    private func target(_ threat: String, on id: String) -> SourceTreeTarget {
        SourceTreeTarget(threatId: threat, sourceKind: "component", sourceId: id)
    }

    private func drawn() -> (TreeEditor, TreeCanvasState, String, String) {
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
        let ids = editor.graph.nodes.map(\.id)
        return (editor, TreeCanvasState(), ids[0], ids[1])
    }

    private func bound(open: Bool) -> BoundAttackTree {
        BoundAttackTree(
            id: "t",
            name: "T",
            description: nil,
            raisesRiskBy: 10,
            goal: ThreatKey(threatId: "exfiltration", sourceId: "component:db"),
            goalName: "Exfiltration",
            goalSourceName: "db",
            steps: [
                BoundStep(
                    key: ThreatKey(threatId: "ssrf", sourceId: "component:api"),
                    threatName: "SSRF",
                    sourceName: "api",
                    state: open ? .open : .closed,
                    factor: 1
                )
            ],
            chainFactor: open ? 1 : 0,
            isOpen: open,
            isStale: false,
            scoreBefore: 40,
            score: open ? 44 : 40
        )
    }

    @Test func withNoTreeInFrontItSaysSo() {
        let editor = TreeEditor()

        #expect(TreeSelection.of(editor: editor, canvas: TreeCanvasState(), bound: nil) == .noTree)
    }

    @Test func aSelectedStepStatesItsThreatItsElementAndItsScore() throws {
        let (editor, canvas, _, step) = drawn()
        canvas.select(step, addingToSelection: false)

        guard case .node(let node) = TreeSelection.of(editor: editor, canvas: canvas, bound: bound(open: true)) else {
            Issue.record("the selection is not a node")
            return
        }
        #expect(node.threat == "ssrf")
        #expect(node.element == "component api")
        #expect(node.state == .open)
        #expect(node.score == "Open: nothing closes this step.")
        #expect(node.isGoal == false)
        #expect(node.canBecomeGoal)
        #expect(node.feedsANode)
    }

    @Test func aClosedStepReadsClosed() throws {
        let (editor, canvas, _, step) = drawn()
        canvas.select(step, addingToSelection: false)

        guard case .node(let node) = TreeSelection.of(editor: editor, canvas: canvas, bound: bound(open: false)) else {
            Issue.record("the selection is not a node")
            return
        }
        #expect(node.state == .closed)
        #expect(node.score == "Closed: a control answers this step.")
    }

    @Test func theGoalCannotBecomeTheGoalAgain() {
        let (editor, canvas, goal, _) = drawn()
        canvas.select(goal, addingToSelection: false)

        guard case .node(let node) = TreeSelection.of(editor: editor, canvas: canvas, bound: nil) else {
            Issue.record("the selection is not a node")
            return
        }
        #expect(node.isGoal)
        #expect(node.canBecomeGoal == false)
        #expect(node.score == "Not written yet.")
    }

    @Test func nothingSelectedShowsTheTreeAndItsScore() {
        let (editor, canvas, _, _) = drawn()

        let selection = TreeSelection.of(editor: editor, canvas: canvas, bound: bound(open: true))

        #expect(selection == .tree(TreeSelection.Tree(
            standing: "Open: the goal's score moves 40 \u{2192} 44.",
            isRefused: false
        )))
    }

    @Test func aRefusedGraphShowsTheRefusalInsteadOfAScore() {
        let (editor, canvas, _, step) = drawn()
        editor.cutOutgoingJoin(of: step)

        let selection = TreeSelection.of(editor: editor, canvas: canvas, bound: bound(open: true))

        #expect(selection == .tree(TreeSelection.Tree(
            standing: "Not written: \"ssrf\" reaches no goal.",
            isRefused: true
        )))
    }

    @Test func aSelectedJunctionStatesWhatFeedsIt() throws {
        let (editor, canvas, goal, step) = drawn()
        editor.cutOutgoingJoin(of: step)
        let all = try #require(editor.drop("junction:all", at: .zero, elements: []))
        editor.join(from: step, to: all)
        editor.join(from: all, to: goal)
        canvas.select(all, addingToSelection: false)

        guard case .node(let node) = TreeSelection.of(editor: editor, canvas: canvas, bound: nil) else {
            Issue.record("the selection is not a node")
            return
        }
        #expect(node.isJunction)
        #expect(node.threat == "Every step under it")
        #expect(node.element == "1 node feeds it")
    }

    @Test func aSelectedPendingElementIsOfferedItsThreats() throws {
        let editor = TreeEditor()
        editor.addTree(among: [])
        let api = TreeElement(kind: "component", sourceId: "api", name: "api", threats: [])
        let id = try #require(editor.drop("component:api", at: .zero, elements: [api]))
        let canvas = TreeCanvasState()
        canvas.select(id, addingToSelection: false)

        guard case .pending(let pending) = TreeSelection.of(editor: editor, canvas: canvas, bound: nil) else {
            Issue.record("the selection is not a pending element")
            return
        }
        #expect(pending.element == api)
    }

    @Test func severalSelectedNodesAreCounted() {
        let (editor, canvas, goal, step) = drawn()
        canvas.select([goal, step])

        #expect(TreeSelection.of(editor: editor, canvas: canvas, bound: nil) == .several(2))
    }
}
