import Testing
import ThreatModelKit
import TestSupport

struct ComponentMitigationTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func component(_ id: String, _ technology: String = "aws-ec2") -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId(technology),
            position: Point(x: 0, y: 0),
            sensitivity: .confidential
        )
    }

    private func model(_ edges: [MitigatesEdge]) -> ThreatModel {
        ThreatModel(
            name: "S",
            components: [component("guard", "aws-waf"), component("store")],
            mitigatesEdges: edges
        )
    }

    private func credentialTheft(_ model: ThreatModel) -> ResolvedThreat {
        ThreatResolver(model: model, catalogue: catalogue).resolve()
            .first { $0.threat.id == ThreatId("credential-theft") && $0.source.id == "component:store" }!
    }

    @Test func noEdgeLeavesTheScoreAlone() {
        #expect(credentialTheft(model([])).score.value == 12)
    }

    @Test func anEdgeLowersTheThreatItNamesOnTheComponentItProtects() {
        let threat = credentialTheft(model([
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("store"),
                threatIds: [ThreatId("credential-theft")],
                reducesRiskBy: 75
            )
        ]))
        #expect(threat.score.value == 3)
        #expect(threat.mitigatedByComponents.first?.protectorName == "WAF")
        #expect(threat.mitigatedByComponents.first?.reducesRiskBy == 75)
    }

    @Test func anEdgeNamingAnotherThreatChangesNothing() {
        let threat = credentialTheft(model([
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("store"),
                threatIds: [ThreatId("dos-attack")],
                reducesRiskBy: 75
            )
        ]))
        #expect(threat.score.value == 12)
    }

    @Test func twoEdgesGiveTheStrongerAndNotTheSum() {
        let threat = credentialTheft(model([
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("store"),
                threatIds: [ThreatId("credential-theft")],
                reducesRiskBy: 25
            ),
            MitigatesEdge(
                source: ComponentId("store"),
                target: ComponentId("store"),
                threatIds: [ThreatId("credential-theft")],
                reducesRiskBy: 50
            )
        ]))
        #expect(threat.score.value == 6)
    }

    @Test func theScoreNeverFallsBelowOne() {
        let threat = credentialTheft(model([
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("store"),
                threatIds: [ThreatId("credential-theft")],
                reducesRiskBy: 100
            )
        ]))
        #expect(threat.score.value == 1)
    }

    @Test func theAssessmentNamesWhatTheReductionRestsOn() throws {
        let held = model([
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("store"),
                threatIds: [ThreatId("credential-theft")],
                reducesRiskBy: 75
            )
        ])
        let response = AssessThreatModel(
            models: InMemoryThreatModelGateway(held),
            catalogue: catalogue
        ).execute(AssessThreatModelRequest())

        let dependency = try #require(response.protectionDependencies.first)
        #expect(dependency.protectorName == "WAF")
        #expect(dependency.protects == ["credential-theft on store"])
        #expect(dependency.unanswered.isEmpty)
        #expect(response.warnings.isEmpty)
    }

    @Test func anUnansweredThreatOnTheProtectorIsAWarning() throws {
        let held = ThreatModel(
            name: "S",
            components: [component("guard"), component("store")],
            mitigatesEdges: [
                MitigatesEdge(
                    source: ComponentId("guard"),
                    target: ComponentId("store"),
                    threatIds: [ThreatId("credential-theft")],
                    reducesRiskBy: 75
                )
            ]
        )
        let response = AssessThreatModel(
            models: InMemoryThreatModelGateway(held),
            catalogue: catalogue
        ).execute(AssessThreatModelRequest())

        #expect(response.protectionDependencies.first?.unanswered.isEmpty == false)
        #expect(response.warnings.contains {
            $0.contains("risk reductions depend on") && $0.contains("EC2")
        })
    }
}
