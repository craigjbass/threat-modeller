import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Writing a tree in the window, end to end: the draft, the file the use
/// case writes, the score the model gives it, and the report. The tree is
/// drawn on the Attack Trees stage; the sheet it once opened in is gone.
@MainActor
@Suite("Writing an attack tree in the window")
struct AttackTreeEditorFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "db" {
        technology = "aws-rds"
        data       = "restricted"
      }

      flow api -> db
    }

    """

    private func aProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    // MARK: the draft

    /// A step names a threat by the key the assessment hands out, so a tree
    /// the window writes binds to the model.
    @Test func aDraftStatesTheTreeTheFileWillHold() throws {
        let draft = TreeDraft(
            id: "read-every-record",
            name: "Read every record",
            description: "How a caller reaches the table.",
            raisesRiskBy: 40,
            goalKey: "misconfiguration@component:db",
            steps: [TreeDraft.Step(key: "credential-theft@component:api", note: "IMDS")]
        )

        let tree = try #require(draft.source())
        #expect(tree.id == "read-every-record")
        #expect(tree.raisesRiskBy == 40)
        #expect(tree.goal.threatId == "misconfiguration")
        #expect(tree.goal.sourceKind == "component")
        #expect(tree.goal.sourceId == "db")
        #expect(tree.steps.map(\.target.threatId) == ["credential-theft"])
        #expect(tree.steps.first?.note == "IMDS")
    }

    /// A flow is a `flow` in the language and a `connection` in the
    /// assessment's own keys, and one rule reads both.
    @Test func aDraftReadsAFlowsOwnKey() throws {
        let draft = TreeDraft(
            id: "one",
            name: "One",
            description: "",
            raisesRiskBy: 0,
            goalKey: "connection-mitm@connection:api->db",
            steps: [TreeDraft.Step(key: "connection-mitm@connection:api->db", note: nil)]
        )

        let tree = try #require(draft.source())
        #expect(tree.goal.sourceKind == "flow")
        #expect(tree.goal.sourceId == "api->db")
        #expect(TreeDraft.key(of: tree.goal) == "connection-mitm@connection:api->db")
    }

    /// A tree body holds exactly one root, and a root of nothing is not a
    /// tree.
    @Test func aDraftWithNoStepStatesNoTree() {
        let draft = TreeDraft(
            id: "one",
            name: "One",
            description: "",
            raisesRiskBy: 0,
            goalKey: "misconfiguration@component:db",
            steps: []
        )

        #expect(draft.source() == nil)
    }

    // MARK: the window

    @Test func writesTheTreeAndTheModelScoresIt() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let goal = try #require(
            model.threats.first { $0.threatId == "misconfiguration" && $0.source.id == "component:db" }
        )
        let step = try #require(
            model.threats.first { $0.threatId == "credential-theft" }
        )

        let draft = TreeDraft(
            id: "read-every-record",
            name: "Read every record",
            description: "How a caller reaches the table.",
            raisesRiskBy: 40,
            goalKey: goal.threatKey,
            steps: [TreeDraft.Step(key: step.threatKey, note: nil)]
        )
        await session.writeAttackTree(try #require(draft.source()))

        let written = try #require(
            useCases.project.text(at: "/work/threatmodel/payments.attacktree")
        )
        #expect(written.contains("attack_trees for \"Payments\" {"))
        #expect(written.contains("tree \"read-every-record\" {"))
        #expect(written.contains("raises_risk_by = 40"))

        // The project read the files again, so the model holds the tree.
        let reloaded = try #require(session.model)
        let bound = try #require(reloaded.attackTrees.first)
        #expect(bound.id == "read-every-record")
        #expect(bound.isStale == false)
        #expect(session.errorMessage == nil)
    }

    @Test func theReportStatesTheTreeTheWindowWrote() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let goal = try #require(
            model.threats.first { $0.threatId == "misconfiguration" && $0.source.id == "component:db" }
        )

        let draft = TreeDraft(
            id: "read-every-record",
            name: "Read every record",
            description: "",
            raisesRiskBy: 40,
            goalKey: goal.threatKey,
            steps: [TreeDraft.Step(key: goal.threatKey, note: nil)]
        )
        await session.writeAttackTree(try #require(draft.source()))

        let reloaded = try #require(session.model)
        let markdown = try #require(reloaded.markdownExport())

        #expect(String(decoding: markdown.data, as: UTF8.self).contains("Read every record"))
    }

    @Test func deletesTheTreeAndTheFileStatesNone() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let goal = try #require(model.threats.first)
        let draft = TreeDraft(
            id: "one",
            name: "One",
            description: "",
            raisesRiskBy: 0,
            goalKey: goal.threatKey,
            steps: [TreeDraft.Step(key: goal.threatKey, note: nil)]
        )
        await session.writeAttackTree(try #require(draft.source()))

        await session.removeAttackTree("one")

        let written = try #require(
            useCases.project.text(at: "/work/threatmodel/payments.attacktree")
        )
        #expect(written.contains("tree \"one\"") == false)
        #expect(session.attackTreeSources.isEmpty)
    }

    @Test func theSidebarListsWhatTheFileStates() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let goal = try #require(model.threats.first)
        let draft = TreeDraft(
            id: "one",
            name: "One",
            description: "",
            raisesRiskBy: 0,
            goalKey: goal.threatKey,
            steps: [TreeDraft.Step(key: goal.threatKey, note: nil)]
        )
        await session.writeAttackTree(try #require(draft.source()))

        #expect(session.attackTreeSources.map(\.id) == ["one"])
    }

    // MARK: the canvas

    /// A tree drawn as a graph writes through the same use case, the model
    /// scores it, and the report states it.
    @Test func aGraphDrawnOnTheCanvasWritesAndTheModelScoresIt() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let goal = try #require(
            model.threats.first { $0.threatId == "misconfiguration" && $0.source.id == "component:db" }
        )
        let step = try #require(model.threats.first { $0.threatId == "credential-theft" })

        var graph = TreeGraph()
        let goalNode = graph.add(
            .step(target: try #require(TreeDraft.target(of: goal.threatKey)), note: nil),
            title: goal.name
        )
        graph.goalId = goalNode
        let all = graph.add(.allOf, title: "ALL")
        graph.join(from: all, to: goalNode)
        let stepNode = graph.add(
            .step(target: try #require(TreeDraft.target(of: step.threatKey)), note: nil),
            title: step.name
        )
        graph.join(from: stepNode, to: all)

        let tree = try graph.tree(
            id: "drawn-on-the-canvas",
            name: "Drawn on the canvas",
            description: nil,
            raisesRiskBy: 30
        ).get()
        await session.writeAttackTree(tree)

        let written = try #require(
            useCases.project.text(at: "/work/threatmodel/payments.attacktree")
        )
        #expect(written.contains("tree \"drawn-on-the-canvas\" {"))

        let reloaded = try #require(session.model)
        let bound = try #require(reloaded.attackTrees.first)
        #expect(bound.id == "drawn-on-the-canvas")
        #expect(bound.isStale == false)

        let markdown = try #require(reloaded.markdownExport())
        #expect(String(decoding: markdown.data, as: UTF8.self).contains("Drawn on the canvas"))
    }

    /// A tree drawn on the stage writes the same bytes the sheet wrote before
    /// it: both hand the same `SourceAttackTree` to `WriteAttackTree`, and
    /// the one writer states the shape.
    @Test func aTreeDrawnOnTheStageWritesTheBytesTheSheetWrote() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let elements = TreeElement.list(
            threats: model.threats,
            components: model.canvas.components,
            connections: model.canvas.connections,
            zones: model.canvas.zones
        )
        let db = try #require(elements.first { $0.payload == "component:db" })
        let api = try #require(elements.first { $0.payload == "component:api" })
        let editor = TreeEditor()
        editor.project = session
        editor.addTree(among: [])

        let goal = try #require(editor.drop(db.payload, at: .zero, elements: elements))
        editor.pick(try #require(db.threats.first), for: goal)
        let goalId = try #require(editor.graph.goalId)
        let step = try #require(editor.drop(api.payload, at: .zero, elements: elements))
        editor.pick(try #require(api.threats.first), for: step)
        let stepId = try #require(editor.graph.nodes.first { $0.id != goalId }).id
        editor.join(from: stepId, to: goalId)
        editor.setName("Read every record")
        editor.setRaisesRiskBy(40)
        await session.settle()

        // What the sheet wrote: the same source through the same use case.
        let sheetTree = try #require(editor.lastWritten)
        let sheetSession = await aProject()
        await sheetSession.0.writeAttackTree(sheetTree)

        let stageBytes = try #require(useCases.project.text(at: "/work/threatmodel/payments.attacktree"))
        let sheetBytes = try #require(sheetSession.1.project.text(at: "/work/threatmodel/payments.attacktree"))
        #expect(stageBytes == sheetBytes)
        #expect(stageBytes.contains("tree \"tree-1\" {"))
        #expect(stageBytes.contains("step \""))
    }

    /// The file the window writes is the file `threatmodeller format` writes:
    /// reading it back and writing it again changes nothing.
    @Test func aDrawnTreeAndAFormattedTreeAreTheSameBytes() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let goal = try #require(
            model.threats.first { $0.threatId == "misconfiguration" && $0.source.id == "component:db" }
        )

        var graph = TreeGraph()
        let goalNode = graph.add(
            .step(target: try #require(TreeDraft.target(of: goal.threatKey)), note: nil),
            title: goal.name
        )
        graph.goalId = goalNode
        let stepNode = graph.add(
            .step(target: try #require(TreeDraft.target(of: goal.threatKey)), note: "the route"),
            title: goal.name
        )
        graph.join(from: stepNode, to: goalNode)

        let tree = try graph.tree(
            id: "round-trip", name: nil, description: nil, raisesRiskBy: 10
        ).get()
        await session.writeAttackTree(tree)

        let written = try #require(
            useCases.project.text(at: "/work/threatmodel/payments.attacktree")
        )
        let gateway = HclAttackTreeSource()
        let read = gateway.read(written)
        #expect(read.hasErrors == false)
        let formatted = gateway.write(try #require(read.source))
        #expect(formatted == written)
    }

    /// A join picked from the node menu writes the bytes a drag-join writes:
    /// both call `TreeEditor.join`, and one writer states the file.
    @Test func aMenuJoinWritesTheBytesADragJoinWrites() async throws {
        let menuBytes = try await aTreeJoinedByTheMenu()
        let dragBytes = try await aTreeJoinedByTheDrag()

        #expect(menuBytes == dragBytes)
        #expect(menuBytes.contains("tree \"tree-1\" {"))
        #expect(menuBytes.contains("step \""))
    }

    /// A step joined to a step on the stage makes a chain, and the file the
    /// window writes holds it as `then`, first link first.
    @Test func aStepJoinedToAStepOnTheStageWritesAChain() async throws {
        let (session, useCases, editor, goal, step) = try await aTreeWaitingForAJoin()
        let model = try #require(session.model)
        let elements = TreeElement.list(
            threats: model.threats,
            components: model.canvas.components,
            connections: model.canvas.connections,
            zones: model.canvas.zones
        )
        let api = try #require(elements.first { $0.payload == "component:api" })
        let first = try #require(editor.drop(api.payload, at: CGPoint(x: -300, y: 60), elements: elements))
        let secondThreat = try #require(api.threats.dropFirst().first)
        editor.pick(secondThreat, for: first)
        let firstId = try #require(editor.graph.nodes.first { $0.id != goal && $0.id != step }).id

        // The first link feeds the second, and the second feeds the goal.
        let canvas = TreeCanvasState()
        let gestures = TreeCanvasGestures(editor: editor, canvas: canvas, elements: elements)
        let handle = gestures.joinHandleRect(of: firstId)
        let start = CGPoint(x: handle.midX, y: handle.midY)
        let end = canvas.transform.viewPoint(gestures.position(of: step))
        gestures.dragChanged(on: firstId, from: start, to: end, by: CGSize(width: end.x - start.x, height: end.y - start.y))
        gestures.dragEnded(on: firstId, from: start, to: end, by: CGSize(width: end.x - start.x, height: end.y - start.y))
        editor.join(from: step, to: goal)
        editor.setName("Two steps in order")
        await session.settle()

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.attacktree"))
        #expect(written.contains("""
            then {
              step "\(secondThreat.threatId)" on component "api"
              step "\(try #require(api.threats.first).threatId)" on component "api"
            }
        """))

        // The model reads the chain back and states each link's position.
        let reloaded = try #require(session.model)
        let bound = try #require(reloaded.attackTrees.first)
        #expect(bound.steps.map(\.position) == [1, 2])
        #expect(bound.isStale == false)
    }

    /// A tree of a goal and one step, with the step joined to the goal from
    /// the **Join to\u{2026}** submenu. Returns the file the project wrote.
    private func aTreeJoinedByTheMenu() async throws -> String {
        let (session, useCases, editor, goal, step) = try await aTreeWaitingForAJoin()
        let menu = TreeMenu(editor: editor, canvas: TreeCanvasState(), elements: [])
        var rows: [ElementMenu.Row] = []
        for row in menu.node(step) {
            if case .submenu(let id, _, let inner) = row, id == "context-tree-join-to" { rows = inner }
        }
        for row in rows {
            if case .item(let id, _, _, _, let act) = row, id == "context-tree-join-to-\(goal)" { act() }
        }
        editor.setName("Read every record")
        editor.setRaisesRiskBy(40)
        await session.settle()
        return try #require(useCases.project.text(at: "/work/threatmodel/payments.attacktree"))
    }

    /// The same tree, with the step joined to the goal by a drag from the
    /// join handle.
    private func aTreeJoinedByTheDrag() async throws -> String {
        let (session, useCases, editor, goal, step) = try await aTreeWaitingForAJoin()
        let canvas = TreeCanvasState()
        let gestures = TreeCanvasGestures(editor: editor, canvas: canvas, elements: [])
        let handle = gestures.joinHandleRect(of: step)
        let start = CGPoint(x: handle.midX, y: handle.midY)
        let end = canvas.transform.viewPoint(gestures.position(of: goal))
        gestures.dragChanged(on: step, from: start, to: end, by: CGSize(width: end.x - start.x, height: end.y - start.y))
        gestures.dragEnded(on: step, from: start, to: end, by: CGSize(width: end.x - start.x, height: end.y - start.y))
        editor.setName("Read every record")
        editor.setRaisesRiskBy(40)
        await session.settle()
        return try #require(useCases.project.text(at: "/work/threatmodel/payments.attacktree"))
    }

    /// A stage editor holding a goal and one step that feeds nothing yet.
    private func aTreeWaitingForAJoin() async throws
        -> (ProjectSession, TestDependencies, TreeEditor, String, String) {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let elements = TreeElement.list(
            threats: model.threats,
            components: model.canvas.components,
            connections: model.canvas.connections,
            zones: model.canvas.zones
        )
        let db = try #require(elements.first { $0.payload == "component:db" })
        let api = try #require(elements.first { $0.payload == "component:api" })
        let editor = TreeEditor()
        editor.project = session
        editor.addTree(among: [])

        let dropped = try #require(editor.drop(db.payload, at: CGPoint(x: 400, y: 60), elements: elements))
        editor.pick(try #require(db.threats.first), for: dropped)
        let goal = try #require(editor.graph.goalId)
        let waiting = try #require(editor.drop(api.payload, at: CGPoint(x: 100, y: 60), elements: elements))
        editor.pick(try #require(api.threats.first), for: waiting)
        let step = try #require(editor.graph.nodes.first { $0.id != goal }).id
        return (session, useCases, editor, goal, step)
    }
}
