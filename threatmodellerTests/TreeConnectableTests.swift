import CoreGraphics
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// What a tree node can connect to, and the box that waits for an element.
/// The design in
/// `docs/superpowers/specs/2026-09-16-tree-connectable-elements-design.md`
/// states the rules these tests read.
@MainActor
@Suite("What a tree node can connect to")
struct TreeConnectableTests {
    /// Three components and two flows: `api` reaches `db` and `cache`, and
    /// `db` and `cache` do not reach each other.
    private let shop = """
    system "Shop" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "db" {
        technology = "aws-rds"
        data       = "restricted"
      }

      component "cache" {
        technology = "aws-ec2"
        data       = "internal"
      }

      flow api -> db
      flow api -> cache
    }

    """

    private func aProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(shop, at: "/work/threatmodel/shop.arch")
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
        useCases.project.text(at: "/work/threatmodel/shop.attacktree") ?? ""
    }

    private func element(_ payload: String, in elements: [TreeElement]) throws -> TreeElement {
        try #require(elements.first { $0.payload == payload })
    }

    /// An editor on a new tree whose goal is a threat on `db`, with the
    /// project it writes to.
    private func anEditorWithAGoal() async throws -> (TreeEditor, ProjectSession, TestDependencies, [TreeElement], String) {
        let (project, useCases) = await aProject()
        let elements = try elements(of: project)
        let editor = TreeEditor()
        editor.project = project
        editor.addTree(among: [])
        let db = try element("component:db", in: elements)
        let dropped = try #require(editor.drop(db.payload, at: .zero, elements: elements))
        editor.pick(try #require(db.threats.first), for: dropped)
        let goalId = try #require(editor.graph.goalId)
        return (editor, project, useCases, elements, goalId)
    }

    /// A step on one element, joined to the goal.
    private func aStep(
        on payload: String,
        feeding goalId: String,
        in editor: TreeEditor,
        elements: [TreeElement]
    ) throws -> String {
        let element = try element(payload, in: elements)
        let dropped = try #require(editor.drop(element.payload, at: CGPoint(x: 300, y: 300), elements: elements))
        editor.pick(try #require(element.threats.first), for: dropped)
        let step = try #require(editor.graph.nodes.first { node in
            guard case .step(let target, _) = node.kind else { return false }
            return "\(target.sourceKind):\(target.sourceId)" == payload
        }).id
        editor.join(from: step, to: goalId)
        return step
    }

    // MARK: what an element reaches

    @Test func aComponentReachesItselfTheComponentsItFlowsToAndItsFlows() async throws {
        let (project, _) = await aProject()
        let elements = try elements(of: project)

        let api = try element("component:api", in: elements)
        #expect(api.neighbours == [
            "component:api", "component:db", "component:cache", "flow:api->db", "flow:api->cache"
        ])

        let db = try element("component:db", in: elements)
        #expect(db.neighbours == ["component:db", "component:api", "flow:api->db"])

        let flow = try element("flow:api->db", in: elements)
        #expect(flow.neighbours == ["flow:api->db", "component:api", "component:db"])
    }

    /// The rank for a node on `api` marks the two joined components and the
    /// two flows, and puts every marked element before every unmarked one.
    @Test func theSidebarMarksWhatTheSelectedNodeReachesAndPutsItFirst() async throws {
        let (editor, _, _, elements, goalId) = try await anEditorWithAGoal()
        let api = try aStep(on: "component:api", feeding: goalId, in: editor, elements: elements)
        let canvas = TreeCanvasState()
        canvas.select(api, addingToSelection: false)

        let rows = TreeConnectable.sidebarRows(editor: editor, canvas: canvas, elements: elements)

        let marked = rows.filter(\.isConnectable).map(\.element.payload)
        #expect(Set(marked) == [
            "component:api", "component:db", "component:cache", "flow:api->db", "flow:api->cache"
        ])
        #expect(rows.firstIndex { $0.isConnectable == false } == marked.count)
        #expect(rows.count == elements.count)

        let counts = rows.filter(\.isConnectable).map(\.element.threats.count)
        #expect(counts == counts.sorted(by: >))
    }

    @Test func withNothingSelectedTheSidebarMarksNothingAndKeepsTheModelOrder() async throws {
        let (editor, _, _, elements, _) = try await anEditorWithAGoal()

        let rows = TreeConnectable.sidebarRows(editor: editor, canvas: TreeCanvasState(), elements: elements)

        #expect(rows.map(\.element) == elements)
        #expect(rows.contains { $0.isConnectable } == false)
    }

    /// A junction has no element; it takes the anchor of the node it feeds.
    @Test func aSelectedJunctionAnchorsOnTheNodeItFeeds() async throws {
        let (editor, _, _, elements, goalId) = try await anEditorWithAGoal()
        let all = try #require(editor.drop("junction:all", at: .zero, elements: elements))
        editor.join(from: all, to: goalId)
        let canvas = TreeCanvasState()
        canvas.select(all, addingToSelection: false)

        let rows = TreeConnectable.sidebarRows(editor: editor, canvas: canvas, elements: elements)

        #expect(Set(rows.filter(\.isConnectable).map(\.element.payload)) == [
            "component:db", "component:api", "flow:api->db"
        ])
    }

    // MARK: the box and its search

    @Test func aBoxDropsAsANodeWithNoElement() async throws {
        let (editor, _, _, elements, _) = try await anEditorWithAGoal()

        let box = try #require(editor.drop("placeholder", at: CGPoint(x: 50, y: 60), elements: elements))

        #expect(editor.graph.node(box)?.kind == .placeholder(element: nil))
        #expect(editor.graph.node(box)?.title == "Any element")
        #expect(editor.layout.point(of: box) == CGPoint(x: 50, y: 60))
        #expect(editor.pending.isEmpty)
    }

    /// A box takes one feeder and feeds one node, the way a step does.
    @Test func aBoxJoinsTheWayAStepJoins() async throws {
        let (editor, _, _, elements, goalId) = try await anEditorWithAGoal()
        let box = try #require(editor.drop("placeholder", at: .zero, elements: elements))
        let all = try #require(editor.drop("junction:all", at: .zero, elements: elements))
        let any = try #require(editor.drop("junction:any", at: .zero, elements: elements))

        #expect(editor.graph.canJoin(from: box, to: goalId))
        #expect(editor.graph.canJoin(from: all, to: box))
        editor.join(from: all, to: box)
        #expect(editor.graph.canJoin(from: any, to: box) == false)
    }

    /// The search after a join lists only the elements the known end
    /// reaches, ranked by the threats each raises.
    @Test func aJoinToAKnownNodeSearchesWhatThatNodeReaches() async throws {
        let (editor, _, _, elements, goalId) = try await anEditorWithAGoal()
        let canvas = TreeCanvasState()
        let gestures = TreeCanvasGestures(editor: editor, canvas: canvas, elements: elements)
        let box = try #require(editor.drop("placeholder", at: .zero, elements: elements))

        gestures.join(from: box, to: goalId)

        #expect(canvas.selectedIds == [box])
        guard case .box(let selected) = TreeSelection.of(editor: editor, canvas: canvas, bound: nil, elements: elements) else {
            Issue.record("the selection is not a box")
            return
        }
        #expect(selected.id == box)
        #expect(selected.element == nil)
        #expect(selected.anchor == "component:db")
        #expect(selected.knownEnd == (try element("component:db", in: elements)).name)

        let found = TreeConnectable.search(elements, from: selected.anchor, query: "", everyElement: false)
        #expect(Set(found.map(\.payload)) == ["component:db", "component:api", "flow:api->db"])
        let counts = found.map(\.threats.count)
        #expect(counts == counts.sorted(by: >))
    }

    @Test func theSearchReadsTheQueryAndOffersEveryElementOnRequest() async throws {
        let (project, _) = await aProject()
        let elements = try elements(of: project)
        let cache = try element("component:cache", in: elements)

        let matching = TreeConnectable.search(elements, from: "component:db", query: "api", everyElement: false)
        #expect(matching.map(\.payload) == ["component:api", "flow:api->db"])

        #expect(TreeConnectable.search(elements, from: "component:db", query: cache.name, everyElement: false).isEmpty)

        let every = TreeConnectable.search(elements, from: "component:db", query: cache.name, everyElement: true)
        #expect(every.contains(cache))

        let unjoined = TreeConnectable.search(elements, from: nil, query: "", everyElement: false)
        #expect(Set(unjoined) == Set(elements))
    }

    /// Picking an element fills the box, picking a threat makes it a step on
    /// that element, and the file holds the bytes the sheet-era writer wrote.
    @Test func anElementPickedFromTheSearchMakesAStepAndTheFileHoldsTheSheetsBytes() async throws {
        let (editor, project, useCases, elements, goalId) = try await anEditorWithAGoal()
        let box = try #require(editor.drop("placeholder", at: CGPoint(x: 20, y: 20), elements: elements))
        editor.join(from: box, to: goalId)
        let api = try element("component:api", in: elements)

        editor.fill(box, with: api)

        #expect(editor.graph.node(box)?.kind == .placeholder(element: api))
        #expect(editor.refusal == TreeGraph.Refusal.boxNamesNoThreat(element: api.name).message)
        guard case .box(let filled) = TreeSelection.of(editor: editor, canvas: selecting(box), bound: nil, elements: elements) else {
            Issue.record("the selection is not a box")
            return
        }
        #expect(filled.element == api)

        editor.pick(try #require(api.threats.first), for: box)
        editor.setName("Read every record")
        editor.setRaisesRiskBy(40)
        await project.settle()

        let step = try #require(editor.graph.node(box))
        guard case .step(let target, _) = step.kind else {
            Issue.record("the pick made no step")
            return
        }
        #expect(target.sourceKind == "component")
        #expect(target.sourceId == "api")
        #expect(editor.graph.edges == [TreeGraph.Edge(from: box, to: goalId)])
        #expect(editor.layout.point(of: box) == CGPoint(x: 20, y: 20))
        #expect(editor.refusal == nil)

        let sheetTree = try #require(editor.lastWritten)
        let sheetSession = await aProject()
        await sheetSession.0.writeAttackTree(sheetTree)

        let stageBytes = written(useCases)
        let sheetBytes = sheetSession.1.project.text(at: "/work/threatmodel/shop.attacktree") ?? ""
        #expect(stageBytes == sheetBytes)
        #expect(stageBytes.contains("on component \"api\""))
    }

    @Test func aFilledBoxCanBeEmptiedAgainAndUndoPutsTheElementBack() async throws {
        let (editor, _, _, elements, _) = try await anEditorWithAGoal()
        let box = try #require(editor.drop("placeholder", at: .zero, elements: elements))
        let api = try element("component:api", in: elements)
        editor.fill(box, with: api)

        editor.fill(box, with: nil)
        #expect(editor.graph.node(box)?.kind == .placeholder(element: nil))

        editor.undo()
        #expect(editor.graph.node(box)?.kind == .placeholder(element: api))
    }

    // MARK: a box holds the save

    @Test func aTreeWithAnUnfilledBoxIsNotWrittenAndThePanelSaysWhy() async throws {
        let (editor, project, useCases, elements, goalId) = try await anEditorWithAGoal()
        _ = try aStep(on: "component:api", feeding: goalId, in: editor, elements: elements)
        await project.settle()
        let before = written(useCases)
        #expect(before.contains("tree \"tree-1\" {"))

        let box = try #require(editor.drop("placeholder", at: .zero, elements: elements))
        await project.settle()

        #expect(editor.refusal == TreeGraph.Refusal.unfilledBox.message)
        #expect(editor.refusal == "a box holds no element yet; pick one, or delete the box")
        #expect(written(useCases) == before)

        let standing = TreeSelection.of(editor: editor, canvas: TreeCanvasState(), bound: nil, elements: elements)
        #expect(standing == .tree(TreeSelection.Tree(
            standing: "Not written: a box holds no element yet; pick one, or delete the box.",
            isRefused: true
        )))

        guard case .box(let selected) = TreeSelection.of(editor: editor, canvas: selecting(box), bound: nil, elements: elements) else {
            Issue.record("the selection is not a box")
            return
        }
        #expect(selected.anchor == nil)
        #expect(TreeSelection.Box.notWritten
            == "This box is not written. The tree is not saved until you pick an element, or delete the box.")

        editor.remove([box])
        await project.settle()
        #expect(editor.refusal == nil)
    }

    // MARK: a join outside the connectable set

    /// A join the flows do not support is written, and the step says so.
    @Test func aJoinOutsideTheConnectableSetIsWrittenWithAWarningOnTheStep() async throws {
        let (editor, project, useCases, elements, goalId) = try await anEditorWithAGoal()
        let cache = try aStep(on: "component:cache", feeding: goalId, in: editor, elements: elements)
        await project.settle()

        #expect(editor.refusal == nil)
        #expect(written(useCases).contains("on component \"cache\""))

        guard case .node(let node) = TreeSelection.of(editor: editor, canvas: selecting(cache), bound: nil, elements: elements) else {
            Issue.record("the selection is not a node")
            return
        }
        let cacheName = try element("component:cache", in: elements).name
        let dbName = try element("component:db", in: elements).name
        #expect(node.warning == "No flow or zone joins \(cacheName) to \(dbName).")
        #expect(TreeConnectable.outsideJoin(from: cache, in: editor.graph, elements: elements) != nil)
    }

    @Test func aJoinInsideTheConnectableSetCarriesNoWarning() async throws {
        let (editor, _, _, elements, goalId) = try await anEditorWithAGoal()
        let api = try aStep(on: "component:api", feeding: goalId, in: editor, elements: elements)

        guard case .node(let node) = TreeSelection.of(editor: editor, canvas: selecting(api), bound: nil, elements: elements) else {
            Issue.record("the selection is not a node")
            return
        }
        #expect(node.warning == nil)
        #expect(TreeConnectable.outsideJoin(from: api, in: editor.graph, elements: elements) == nil)
    }

    // MARK: the menu on a filled box

    @Test func theMenuOnAFilledBoxOffersItsThreatsThenDelete() async throws {
        let (editor, _, _, elements, _) = try await anEditorWithAGoal()
        let box = try #require(editor.drop("placeholder", at: .zero, elements: elements))
        let api = try element("component:api", in: elements)
        editor.fill(box, with: api)
        let menu = TreeMenu(editor: editor, canvas: TreeCanvasState(), elements: elements)

        let rows = menu.node(box)
        let titles = rows.map(\.title).filter { $0.isEmpty == false }
        #expect(titles == api.threats.map(\.name) + ["Delete"])

        let first = try #require(api.threats.first)
        for row in rows {
            if case .item(let id, _, _, _, let act) = row, id == "context-box-\(first.threatKey)" { act() }
        }
        guard case .step(let target, _) = editor.graph.node(box)?.kind else {
            Issue.record("the pick made no step")
            return
        }
        #expect(target.sourceId == "api")
    }

    private func selecting(_ id: String) -> TreeCanvasState {
        let canvas = TreeCanvasState()
        canvas.select(id, addingToSelection: false)
        return canvas
    }
}
