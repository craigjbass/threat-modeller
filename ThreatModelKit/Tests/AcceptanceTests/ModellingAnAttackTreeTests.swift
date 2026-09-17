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

    /// A sufficient control that is implemented closes the tree, and the
    /// goal's assessed threat says so, for the threat card.
    @Test func namesTheClosingTreeAndControlOnTheGoalsThreat() throws {
        let catalogue = CatalogueFixture.catalogue()
        let api = Component(
            id: ComponentId("api"),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .confidential
        )
        let control = "Enforce IMDSv2 to block SSRF-based credential theft"
        let tree = SourceAttackTree(
            id: "credential-route",
            name: "The credential route",
            raisesRiskBy: 50,
            closedBy: [control],
            goal: SourceTreeTarget(threatId: "misconfiguration", sourceKind: "component", sourceId: "api"),
            root: .step(SourceTreeStep(
                target: SourceTreeTarget(threatId: "credential-theft", sourceKind: "component", sourceId: "api")
            ))
        )
        var model = ThreatModel(components: [api], attackTrees: [tree])
        model.controlStatuses[
            ControlIdentity.componentControl(
                componentId: api.id,
                threatId: ThreatId("credential-theft"),
                description: control,
                isTechnologySpecific: true
            )
        ] = .implemented

        let response = AssessThreatModel(
            models: InMemoryThreatModelGateway(model),
            catalogue: catalogue
        ).execute(AssessThreatModelRequest())

        let goal = try #require(response.threats.first { $0.threatId == "misconfiguration" })
        #expect(goal.closedByTrees == [AssessedTreeClosure(treeName: "The credential route", control: control)])
        let step = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(step.closedByTrees.isEmpty)
        #expect(try #require(response.attackTrees.first).closedBy == control)
    }

    // The report names the tree on the threat it raised.

    private let twoTier = """
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

    private let oneTree = """
    attack_trees for "Payments" {
      tree "read-every-customer-record" {
        name           = "Read every customer record"
        raises_risk_by = 40

        goal "misconfiguration" on component "db"

        step "credential-theft" on component "api"
      }
    }

    """

    private func reportOfTheOpenSystem() -> String {
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        return app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
    }

    @Test func namesTheTreeOnTheThreatItRaised() {
        app.project.put(twoTier, at: "/work/threatmodel/payments.arch")
        app.project.put(oneTree, at: "/work/threatmodel/payments.attacktree")

        let report = reportOfTheOpenSystem()

        #expect(report.contains("## Attack trees"))
        #expect(report.contains("- Raised by the tree: Read every customer record"))
        #expect(report.contains("- Before the attack tree: "))
    }

    @Test func namesNoTreeOnAThreatNoTreeRaised() {
        app.project.put(twoTier, at: "/work/threatmodel/payments.arch")
        app.project.put(oneTree, at: "/work/threatmodel/payments.attacktree")

        let report = reportOfTheOpenSystem()

        // The tree names one goal, so every other threat's stanza states no
        // tree at all.
        let stanzas = report.components(separatedBy: "### ")
        let untouched = stanzas.filter { $0.contains("Credential Theft") }
        #expect(untouched.isEmpty == false)
        #expect(untouched.allSatisfy { $0.contains("Raised by the tree") == false })
    }

    @Test func writesNoTreeSectionForASystemWithNoTreeFile() {
        app.project.put(twoTier, at: "/work/threatmodel/payments.arch")

        let report = reportOfTheOpenSystem()

        #expect(report.contains("## Attack trees") == false)
        #expect(report.contains("Raised by the tree") == false)
    }

    @Test func opensASystemWhoseTreeFileSitsBesideIt() {
        app.project.put(twoTier, at: "/work/threatmodel/payments.arch")
        app.project.put(oneTree, at: "/work/threatmodel/payments.attacktree")

        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        #expect(app.modelStore.current().attackTrees.map(\.id) == ["read-every-customer-record"])
    }

}
