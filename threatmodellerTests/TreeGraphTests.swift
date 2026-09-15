import Foundation
import TestSupport
import Testing
import ThreatModelKit
@testable import threatmodeller

/// The graph a person draws becomes the tree the language states, or is
/// refused with the node named. One test per refusal in the design's table.
@MainActor
struct TreeGraphTests {
    private func target(_ threat: String, on id: String) -> SourceTreeTarget {
        SourceTreeTarget(threatId: threat, sourceKind: "component", sourceId: id)
    }

    private func step(_ threat: String, on id: String) -> TreeGraph.Kind {
        .step(target: target(threat, on: id), note: nil)
    }

    private func convert(_ graph: TreeGraph) -> Result<SourceAttackTree, TreeGraph.Refusal> {
        graph.tree(id: "t", name: nil, description: nil, raisesRiskBy: 10)
    }

    // MARK: what converts

    @Test func aStepFeedingTheGoalIsTheRoot() throws {
        var graph = TreeGraph()
        let goal = graph.add(step("exfiltration", on: "db"), title: "Exfiltration")
        graph.goalId = goal
        let ssrf = graph.add(step("ssrf", on: "api"), title: "SSRF")
        graph.join(from: ssrf, to: goal)

        let tree = try convert(graph).get()
        #expect(tree.goal == target("exfiltration", on: "db"))
        #expect(tree.root == .step(SourceTreeStep(target: target("ssrf", on: "api"), note: nil)))
    }

    @Test func junctionsNestTheWayTheLanguageStates() throws {
        var graph = TreeGraph()
        let goal = graph.add(step("exfiltration", on: "db"), title: "Exfiltration")
        graph.goalId = goal
        let all = graph.add(.allOf, title: "ALL")
        graph.join(from: all, to: goal)
        let ssrf = graph.add(step("ssrf", on: "api"), title: "SSRF")
        graph.join(from: ssrf, to: all)
        let any = graph.add(.anyOf, title: "ANY")
        graph.join(from: any, to: all)
        let theft = graph.add(step("credential-theft", on: "api"), title: "Theft")
        graph.join(from: theft, to: any)

        let tree = try convert(graph).get()
        #expect(tree.root == .all([
            .step(SourceTreeStep(target: target("ssrf", on: "api"), note: nil)),
            .any([.step(SourceTreeStep(target: target("credential-theft", on: "api"), note: nil))])
        ]))
    }

    // MARK: what is refused, one row each

    @Test func aGraphWithNoGoalIsRefused() {
        var graph = TreeGraph()
        graph.add(step("ssrf", on: "api"), title: "SSRF")
        #expect(convert(graph) == .failure(.noGoal))
        #expect(TreeGraph.Refusal.noGoal.message == "the tree states no goal")
    }

    @Test func aJunctionAsTheGoalIsRefused() {
        var graph = TreeGraph()
        let all = graph.add(.allOf, title: "ALL")
        graph.goalId = all
        #expect(convert(graph) == .failure(.junctionGoal))
    }

    @Test func aNodeFeedingTwoNodesIsRefused() {
        var graph = TreeGraph()
        let goal = graph.add(step("exfiltration", on: "db"), title: "Exfiltration")
        graph.goalId = goal
        let all = graph.add(.allOf, title: "ALL")
        let any = graph.add(.anyOf, title: "ANY")
        graph.join(from: all, to: goal)
        graph.join(from: any, to: all)
        let ssrf = graph.add(step("ssrf", on: "api"), title: "SSRF")
        graph.join(from: ssrf, to: all)
        graph.join(from: ssrf, to: any)

        #expect(convert(graph) == .failure(.feedsTwo(node: "SSRF")))
    }

    @Test func aNodeFeedingAStepIsRefused() {
        var graph = TreeGraph()
        let goal = graph.add(step("exfiltration", on: "db"), title: "Exfiltration")
        graph.goalId = goal
        let theft = graph.add(step("credential-theft", on: "api"), title: "Theft")
        graph.join(from: theft, to: goal)
        let ssrf = graph.add(step("ssrf", on: "api"), title: "SSRF")
        graph.join(from: ssrf, to: theft)

        #expect(convert(graph) == .failure(.feedsAStep(node: "SSRF")))
    }

    @Test func aCycleIsRefused() {
        var graph = TreeGraph()
        let goal = graph.add(step("exfiltration", on: "db"), title: "Exfiltration")
        graph.goalId = goal
        let all = graph.add(.allOf, title: "ALL")
        let any = graph.add(.anyOf, title: "ANY")
        graph.join(from: all, to: any)
        graph.join(from: any, to: all)

        guard case .failure(let refusal) = convert(graph) else {
            Issue.record("a cycle converted")
            return
        }
        guard case .cycle = refusal else {
            Issue.record("the refusal is \(refusal), not a cycle")
            return
        }
    }

    @Test func aNodeReachingNoGoalIsRefused() {
        var graph = TreeGraph()
        let goal = graph.add(step("exfiltration", on: "db"), title: "Exfiltration")
        graph.goalId = goal
        let root = graph.add(.allOf, title: "ALL")
        graph.join(from: root, to: goal)
        let ssrf = graph.add(step("ssrf", on: "api"), title: "SSRF")
        graph.join(from: ssrf, to: root)
        graph.add(step("stranded", on: "api"), title: "Stranded")

        #expect(convert(graph) == .failure(.reachesNoGoal(node: "Stranded")))
    }

    @Test func aGoalNothingFeedsIsRefused() {
        var graph = TreeGraph()
        let goal = graph.add(step("exfiltration", on: "db"), title: "Exfiltration")
        graph.goalId = goal
        #expect(convert(graph) == .failure(.noSteps))
    }

    @Test func twoNodesFeedingTheGoalAreRefused() {
        var graph = TreeGraph()
        let goal = graph.add(step("exfiltration", on: "db"), title: "Exfiltration")
        graph.goalId = goal
        let ssrf = graph.add(step("ssrf", on: "api"), title: "SSRF")
        let theft = graph.add(step("credential-theft", on: "api"), title: "Theft")
        graph.join(from: ssrf, to: goal)
        graph.join(from: theft, to: goal)

        #expect(convert(graph) == .failure(.twoRoots))
    }

    @Test func aJunctionNothingFeedsIsRefused() {
        var graph = TreeGraph()
        let goal = graph.add(step("exfiltration", on: "db"), title: "Exfiltration")
        graph.goalId = goal
        let all = graph.add(.allOf, title: "ALL")
        graph.join(from: all, to: goal)

        #expect(convert(graph) == .failure(.junctionHoldsNothing(kind: "all_of")))
    }

    // MARK: the graph of a tree, and back

    @Test func aTreeBecomesTheGraphAndTheGraphBecomesTheSameTree() throws {
        let written = SourceAttackTree(
            id: "read-records",
            name: "Read every record",
            description: nil,
            raisesRiskBy: 40,
            goal: target("exfiltration", on: "db"),
            root: .all([
                .step(SourceTreeStep(target: target("ssrf", on: "api"), note: "the import")),
                .any([
                    .step(SourceTreeStep(target: target("credential-theft", on: "api"), note: nil))
                ])
            ])
        )

        let graph = TreeGraph.graph(of: written)
        let back = try graph.tree(
            id: "read-records",
            name: "Read every record",
            description: nil,
            raisesRiskBy: 40
        ).get()

        #expect(back == written)
    }

    // MARK: edits

    @Test func removingANodeDropsItsEdgesAndItsGoalMark() {
        var graph = TreeGraph()
        let goal = graph.add(step("exfiltration", on: "db"), title: "Exfiltration")
        graph.goalId = goal
        let ssrf = graph.add(step("ssrf", on: "api"), title: "SSRF")
        graph.join(from: ssrf, to: goal)

        graph.remove(goal)
        #expect(graph.goalId == nil)
        #expect(graph.edges.isEmpty)
        #expect(graph.nodes.map(\.id) == [ssrf])
    }

    @Test func joiningTwiceOrToItselfChangesNothing() {
        var graph = TreeGraph()
        let a = graph.add(.allOf, title: "ALL")
        let b = graph.add(.anyOf, title: "ANY")
        graph.join(from: a, to: b)
        graph.join(from: a, to: b)
        graph.join(from: a, to: a)
        #expect(graph.edges == [TreeGraph.Edge(from: a, to: b)])
    }

    // MARK: where a node sits

    @Test func theGoalSitsInTheRightmostColumnAndTheLayoutRepeats() {
        var graph = TreeGraph()
        let goal = graph.add(step("exfiltration", on: "db"), title: "Exfiltration")
        graph.goalId = goal
        let all = graph.add(.allOf, title: "ALL")
        graph.join(from: all, to: goal)
        let ssrf = graph.add(step("ssrf", on: "api"), title: "SSRF")
        graph.join(from: ssrf, to: all)
        let theft = graph.add(step("credential-theft", on: "api"), title: "Theft")
        graph.join(from: theft, to: all)

        let size = CGSize(width: 180, height: 56)
        let first = graph.positions(nodeSize: size, horizontalGap: 60, verticalGap: 24)
        let second = graph.positions(nodeSize: size, horizontalGap: 60, verticalGap: 24)
        #expect(first == second)

        let goalX = first[goal]?.x ?? 0
        for (id, point) in first where id != goal {
            #expect(point.x < goalX, "\(id) sits at or right of the goal")
        }
        #expect(first[ssrf]?.x == first[theft]?.x)
        #expect(first[ssrf]?.y != first[theft]?.y)
    }
}

/// The element list beside the canvas: every element the model states, with
/// the threats raised on it, so a drop offers a step and an element raising
/// no threat says so and makes none.
@MainActor
struct TreeElementTests {
    @Test func listsEveryElementWithItsThreats() throws {
        let model = ThreatModelSession(useCases: TestDependencies())
        model.add(technologyId: "aws-ec2", x: 0, y: 0)
        model.add(technologyId: "aws-rds", x: 400, y: 0)
        let components = model.canvas.components
        model.connect(
            sourceComponentId: components[0].id,
            targetComponentId: components[1].id
        )
        _ = model.addZone(x: 0, y: 0, width: 400, height: 300)

        let rows = TreeElement.list(
            threats: model.threats,
            components: model.canvas.components,
            connections: model.canvas.connections,
            zones: model.canvas.zones
        )

        #expect(rows.count == 4)
        #expect(rows.filter { $0.kind == "component" }.count == 2)
        #expect(rows.filter { $0.kind == "flow" }.count == 1)
        #expect(rows.filter { $0.kind == "zone" }.count == 1)

        // A component with a technology raises threats; the row carries them
        // so a drop offers a step.
        let api = try #require(rows.first { $0.kind == "component" })
        #expect(api.threats.isEmpty == false)
        for threat in api.threats {
            #expect(threat.source.id == "component:\(api.sourceId)")
        }

        // A zone raises its own threats, so its row carries them too.
        let zone = try #require(rows.first { $0.kind == "zone" })
        #expect(zone.threats.isEmpty == false)

        // An element the assessment raises nothing on carries no threat: the
        // canvas then says "raises no threat" and makes no step of it.
        let bare = TreeElement.list(
            threats: [],
            components: model.canvas.components,
            connections: model.canvas.connections,
            zones: model.canvas.zones
        )
        #expect(bare.count == 4)
        #expect(bare.allSatisfy { $0.threats.isEmpty })
    }
}
