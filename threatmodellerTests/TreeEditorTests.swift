import CoreGraphics
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The tree in front on the Attack Trees stage: what a change writes, what a
/// refusal holds back, and what undo and redo put back.
@MainActor
@Suite("The tree editor")
struct TreeEditorTests {
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

    private func elements(of project: ProjectSession) throws -> [TreeElement] {
        let model = try #require(project.model)
        return TreeElement.list(
            threats: model.threats,
            components: model.canvas.components,
            connections: model.canvas.connections,
            zones: model.canvas.zones
        )
    }

    private func written(_ useCases: TestDependencies) -> String {
        useCases.project.text(at: "/work/threatmodel/payments.attacktree") ?? ""
    }

    /// An editor with a new tree, one pending drop of `db`, and the project
    /// to write to.
    private func anEditorWithADrop() async throws -> (TreeEditor, ProjectSession, TestDependencies, PendingElement) {
        let (project, useCases) = await aProject()
        let editor = TreeEditor()
        editor.project = project
        editor.addTree(among: [])
        #expect(editor.drop("component:db", at: CGPoint(x: 10, y: 10), elements: try elements(of: project)) != nil)
        let pending = try #require(editor.pending.first)
        return (editor, project, useCases, pending)
    }

    // MARK: what a change writes

    @Test func aNewTreeStatesTheRefusalAndWritesNothing() async throws {
        let (project, useCases) = await aProject()
        let editor = TreeEditor()
        editor.project = project

        editor.addTree(among: [])

        #expect(editor.isEditing)
        #expect(editor.id == "tree-1")
        #expect(editor.refusal == TreeGraph.Refusal.noGoal.message)
        await project.settle()
        #expect(written(useCases).isEmpty)
    }

    @Test func addTreeTakesTheFirstFreeNumber() {
        let editor = TreeEditor()
        let taken = SourceAttackTree(
            id: "tree-1",
            name: nil,
            description: nil,
            raisesRiskBy: 0,
            goal: SourceTreeTarget(threatId: "t", sourceKind: "component", sourceId: "c"),
            root: .all([])
        )

        editor.addTree(among: [taken])

        #expect(editor.id == "tree-2")
    }

    @Test func pickingAThreatOnADroppedElementMakesTheGoalOfAnEmptyTree() async throws {
        let (editor, _, _, pending) = try await anEditorWithADrop()
        let threat = try #require(pending.element.threats.first)

        editor.pick(threat, for: pending.id)

        #expect(editor.pending.isEmpty)
        #expect(editor.graph.nodes.count == 1)
        #expect(editor.graph.goalId == editor.graph.nodes.first?.id)
        #expect(editor.refusal == TreeGraph.Refusal.noSteps.message)
    }

    /// A drop from the element list and a pick of one of its threats make a
    /// step on that element, and the written tree states it.
    @Test func aDropAndAPickMakeAStepForTheElement() async throws {
        let (editor, project, useCases, goal) = try await anEditorWithADrop()
        let elements = try elements(of: project)
        editor.pick(try #require(goal.element.threats.first), for: goal.id)
        let goalId = try #require(editor.graph.goalId)
        let api = try #require(elements.first { $0.payload == "component:api" })

        let dropped = try #require(editor.drop(api.payload, at: CGPoint(x: 40, y: 40), elements: elements))
        #expect(editor.pending.map(\.id) == [dropped])
        editor.pick(try #require(api.threats.first), for: dropped)
        let step = try #require(editor.graph.nodes.first { $0.id != goalId })
        editor.join(from: step.id, to: goalId)
        await project.settle()

        guard case .step(let target, _) = step.kind else {
            Issue.record("the pick made no step")
            return
        }
        #expect(target.sourceKind == "component")
        #expect(target.sourceId == "api")
        #expect(editor.lastWritten?.steps.map(\.target.sourceId) == ["api"])
        #expect(written(useCases).contains("on component \"api\""))
    }

    @Test func aGraphThatIsATreeWritesAtOnceAndTheModelScoresIt() async throws {
        let (editor, project, useCases, goal) = try await anEditorWithADrop()
        let elements = try elements(of: project)
        editor.pick(try #require(goal.element.threats.first), for: goal.id)
        let goalId = try #require(editor.graph.goalId)

        let api = try #require(editor.drop("component:api", at: CGPoint(x: 0, y: 0), elements: elements))
        let apiElement = try #require(elements.first { $0.payload == "component:api" })
        editor.pick(try #require(apiElement.threats.first), for: api)
        let step = try #require(editor.graph.nodes.first { $0.id != goalId })
        editor.join(from: step.id, to: goalId)
        await project.settle()

        #expect(editor.refusal == nil)
        #expect(written(useCases).contains("tree \"tree-1\" {"))
        #expect(project.model?.attackTrees.first?.id == "tree-1")
        #expect(project.errorMessage == nil)
    }

    @Test func aChangeThatBreaksTheTreeWritesNothingMore() async throws {
        let (editor, project, useCases, goal) = try await anEditorWithADrop()
        let elements = try elements(of: project)
        editor.pick(try #require(goal.element.threats.first), for: goal.id)
        let goalId = try #require(editor.graph.goalId)
        let api = try #require(editor.drop("component:api", at: .zero, elements: elements))
        let apiElement = try #require(elements.first { $0.payload == "component:api" })
        editor.pick(try #require(apiElement.threats.first), for: api)
        let step = try #require(editor.graph.nodes.first { $0.id != goalId })
        editor.join(from: step.id, to: goalId)
        await project.settle()
        let before = written(useCases)

        editor.cutOutgoingJoin(of: step.id)
        await project.settle()

        #expect(editor.refusal == TreeGraph.Refusal.reachesNoGoal(node: step.title).message)
        #expect(written(useCases) == before)
    }

    @Test func theNameAndTheRiskWriteThroughTheSamePath() async throws {
        let (editor, project, useCases, goal) = try await anEditorWithADrop()
        let elements = try elements(of: project)
        editor.pick(try #require(goal.element.threats.first), for: goal.id)
        let goalId = try #require(editor.graph.goalId)
        let api = try #require(editor.drop("component:api", at: .zero, elements: elements))
        let apiElement = try #require(elements.first { $0.payload == "component:api" })
        editor.pick(try #require(apiElement.threats.first), for: api)
        let step = try #require(editor.graph.nodes.first { $0.id != goalId })
        editor.join(from: step.id, to: goalId)

        editor.setName("Read every record")
        editor.setRaisesRiskBy(40)
        await project.settle()

        #expect(written(useCases).contains("\"Read every record\""))
        #expect(written(useCases).contains("raises_risk_by = 40"))
    }

    // MARK: undo and redo

    @Test func anUndoPutsTheGraphBackAndARedoPutsTheChangeBack() async throws {
        let (editor, project, useCases, goal) = try await anEditorWithADrop()
        let elements = try elements(of: project)
        editor.pick(try #require(goal.element.threats.first), for: goal.id)
        let goalId = try #require(editor.graph.goalId)
        let api = try #require(editor.drop("component:api", at: .zero, elements: elements))
        let apiElement = try #require(elements.first { $0.payload == "component:api" })
        editor.pick(try #require(apiElement.threats.first), for: api)
        let step = try #require(editor.graph.nodes.first { $0.id != goalId })
        editor.join(from: step.id, to: goalId)
        await project.settle()
        let joined = written(useCases)
        #expect(editor.undoLabel == "Join")

        editor.undo()
        await project.settle()

        #expect(editor.graph.edges.isEmpty)
        #expect(editor.refusal != nil)
        #expect(written(useCases) == joined)
        #expect(editor.canRedo)
        #expect(editor.redoLabel == "Join")

        editor.redo()
        await project.settle()

        #expect(editor.graph.edges == [TreeGraph.Edge(from: step.id, to: goalId)])
        #expect(editor.refusal == nil)
    }

    @Test func anUndoOfADeleteWritesTheStepBack() async throws {
        let (editor, project, useCases, goal) = try await anEditorWithADrop()
        let elements = try elements(of: project)
        editor.pick(try #require(goal.element.threats.first), for: goal.id)
        let goalId = try #require(editor.graph.goalId)
        let api = try #require(editor.drop("component:api", at: .zero, elements: elements))
        let apiElement = try #require(elements.first { $0.payload == "component:api" })
        editor.pick(try #require(apiElement.threats.first), for: api)
        let step = try #require(editor.graph.nodes.first { $0.id != goalId })
        editor.join(from: step.id, to: goalId)
        await project.settle()
        let whole = written(useCases)

        editor.remove([step.id])
        await project.settle()
        #expect(editor.graph.nodes.count == 1)

        editor.undo()
        await project.settle()

        #expect(editor.graph.nodes.count == 2)
        #expect(written(useCases) == whole)
    }

    @Test func aNewChangeDropsTheRedoHistory() async throws {
        let (editor, _, _, goal) = try await anEditorWithADrop()
        editor.pick(try #require(goal.element.threats.first), for: goal.id)
        editor.undo()
        #expect(editor.canRedo)

        editor.drop("junction:all", at: .zero, elements: [])

        #expect(editor.canRedo == false)
    }

    @Test func thereIsNothingToUndoBeforeAChange() async throws {
        let (project, _) = await aProject()
        let editor = TreeEditor()
        editor.project = project
        let key = try #require(project.model?.threats.first?.threatKey)
        let tree = try #require(TreeDraft(
            id: "one", name: "One", description: "", raisesRiskBy: 0,
            goalKey: key,
            steps: [TreeDraft.Step(key: key, note: nil)]
        ).source())

        editor.open(tree, threats: project.model?.threats ?? [])

        #expect(editor.canUndo == false)
        #expect(editor.canRedo == false)
        #expect(editor.undoLabel == nil)
        #expect(editor.isEditing)
        #expect(editor.name == "One")
    }

    // MARK: closing and deleting

    @Test func deleteTreeRemovesItFromTheFileAndClosesTheEditor() async throws {
        let (editor, project, useCases, goal) = try await anEditorWithADrop()
        let elements = try elements(of: project)
        editor.pick(try #require(goal.element.threats.first), for: goal.id)
        let goalId = try #require(editor.graph.goalId)
        let api = try #require(editor.drop("component:api", at: .zero, elements: elements))
        let apiElement = try #require(elements.first { $0.payload == "component:api" })
        editor.pick(try #require(apiElement.threats.first), for: api)
        let step = try #require(editor.graph.nodes.first { $0.id != goalId })
        editor.join(from: step.id, to: goalId)
        await project.settle()
        #expect(project.attackTreeSources.map(\.id) == ["tree-1"])

        editor.deleteTree()
        await project.settle()

        #expect(project.attackTreeSources.isEmpty)
        #expect(editor.isEditing == false)
    }

    /// A pick makes a node where the pending element sat, and the node the
    /// person placed before it does not move.
    @Test func aThreatPickPlacesTheNodeAtTheDropPointAndMovesNoOtherNode() async throws {
        let (editor, project, _, goal) = try await anEditorWithADrop()
        let elements = try elements(of: project)
        editor.pick(try #require(goal.element.threats.first), for: goal.id)
        let goalId = try #require(editor.graph.goalId)
        let goalPoint = try #require(editor.layout.point(of: goalId))
        let api = try #require(editor.drop("component:api", at: CGPoint(x: 400, y: 250), elements: elements))
        let apiElement = try #require(elements.first { $0.payload == "component:api" })

        editor.pick(try #require(apiElement.threats.first), for: api)

        let step = try #require(editor.graph.nodes.first { $0.id != goalId })
        #expect(editor.layout.point(of: step.id) == CGPoint(x: 400, y: 250))
        #expect(editor.layout.point(of: goalId) == goalPoint)
    }

    @Test func closeLeavesNoTreeInFront() async throws {
        let (editor, _, _, _) = try await anEditorWithADrop()

        editor.close()

        #expect(editor.isEditing == false)
        #expect(editor.pending.isEmpty)
        #expect(editor.graph.nodes.isEmpty)
        #expect(editor.canUndo == false)
    }
}
