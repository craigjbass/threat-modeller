import Testing
import ThreatModelKit
import TestSupport

/// Given a system and the routes a person wrote through it
/// When I assess, compile, check and report
/// Then the goal of an open route scores higher and a broken route fails the build
struct ModellingAnAttackTreeTests {
    private let app = TestDependencies()

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    @Test func assessesAModelThatStatesNoTree() throws {
        app.project.put(payments, at: "/work/threatmodel/payments.arch")
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        let assessed = app.assessThreatModel().execute(AssessThreatModelRequest())

        #expect(assessed.attackTrees.isEmpty)
        #expect(assessed.threats.isEmpty == false)
    }

    /// `OpenSystem` does not read a `.attacktree` file yet, so this test builds
    /// the model directly into an `InMemoryThreatModelGateway`, the way
    /// `CompileControls` does, rather than through a project file.
    @Test func raisesTheGoalOfAnOpenTreeAboveTheSameModelWithNoTree() throws {
        let catalogue = CatalogueFixture.catalogue()
        let api = Component(
            id: ComponentId("api"),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .confidential
        )

        // The same model, once with no tree, so the comparison is against what
        // this exact model scores when Task 9's wiring is skipped entirely.
        let withNoTree = AssessThreatModel(
            models: InMemoryThreatModelGateway(ThreatModel(components: [api])),
            catalogue: catalogue
        ).execute(AssessThreatModelRequest())
        let baselineScore = try #require(
            withNoTree.threats.first { $0.threatId == "credential-theft" }
        ).riskScore

        // The goal is credential-theft on the api component; the one step is
        // misconfiguration on the same component, which nothing has closed, so
        // the tree is open and raises its goal.
        let tree = SourceAttackTree(
            id: "credential-route",
            raisesRiskBy: 50,
            goal: SourceTreeTarget(threatId: "credential-theft", sourceKind: "component", sourceId: "api"),
            root: .step(SourceTreeStep(
                target: SourceTreeTarget(threatId: "misconfiguration", sourceKind: "component", sourceId: "api")
            ))
        )
        let response = AssessThreatModel(
            models: InMemoryThreatModelGateway(ThreatModel(components: [api], attackTrees: [tree])),
            catalogue: catalogue
        ).execute(AssessThreatModelRequest())

        let goal = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(goal.riskScore > baselineScore)

        #expect(response.attackTrees.count == 1)
        let bound = try #require(response.attackTrees.first { $0.id == "credential-route" })
        #expect(bound.isOpen)
        #expect(bound.isStale == false)
        #expect(bound.scoreBefore == baselineScore)
        #expect(bound.score == goal.riskScore)
    }
}
