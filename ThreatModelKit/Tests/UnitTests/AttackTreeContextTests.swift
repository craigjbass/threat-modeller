import Testing
import ThreatModelKit
import TestSupport

@Suite("The evidence level a tree is judged at")
struct AttackTreeContextTests {
    private func context(archLevel: RiskLevel? = nil, policyLevel: RiskLevel? = nil) -> AttackTreeContext {
        let policy = policyLevel.map { PolicySource(implementedRequiresEvidenceAbove: $0) }
        let model = ThreatModel(policy: policy, requiresEvidenceAbove: archLevel)
        return AttackTreeContext(model: model, catalogue: CatalogueFixture.catalogue())
    }

    private func target(_ threatId: String, _ componentId: String) -> SourceTreeTarget {
        SourceTreeTarget(threatId: threatId, sourceKind: "component", sourceId: componentId)
    }

    private func resolvedThreat(_ threatId: String, _ componentId: String, score: Int = 8) -> ResolvedThreat {
        ResolvedThreatFixture.make(
            threatId: threatId,
            componentId: componentId,
            score: score,
            statuses: [.notImplemented],
            compensating: [],
            likelihood: .commodity
        )
    }

    @Test func demandsNoEvidenceWhenNeitherFileSetsALevel() {
        #expect(context().evidenceDemandedAbove == nil)
    }

    @Test func demandsTheArchLevelWhenOnlyTheArchFileSetsIt() {
        #expect(context(archLevel: .medium).evidenceDemandedAbove == .medium)
    }

    @Test func demandsThePolicyLevelWhenOnlyThePolicyFileSetsIt() {
        #expect(context(policyLevel: .medium).evidenceDemandedAbove == .medium)
    }

    @Test func combinesToTheLowerRankWhenTheArchDemandsMoreThanThePolicy() {
        #expect(context(archLevel: .high, policyLevel: .medium).evidenceDemandedAbove == .medium)
    }

    @Test func combinesToTheLowerRankWhenThePolicyDemandsMoreThanTheArch() {
        #expect(context(archLevel: .medium, policyLevel: .high).evidenceDemandedAbove == .medium)
    }

    @Test func combinesToTheSharedLevelWhenBothFilesAgree() {
        #expect(context(archLevel: .high, policyLevel: .high).evidenceDemandedAbove == .high)
    }

    @Test func aDemandCarriedByThePolicyFileAloneMakesASufficientControlReportEvidenceMissing() throws {
        let context = context(policyLevel: .high)
        let tree = SourceAttackTree(
            id: "t",
            raisesRiskBy: 40,
            closedBy: ["Rotate credentials regularly"],
            goal: target("credential-theft", "c1"),
            root: .step(SourceTreeStep(target: target("misconfiguration", "c2")))
        )
        let threats = [
            resolvedThreat("credential-theft", "c1"),
            resolvedThreat("misconfiguration", "c2"),
            ResolvedThreatFixture.make(
                threatId: "answer",
                componentId: "c3",
                score: 4,
                statuses: [.implemented],
                compensating: [],
                likelihood: .commodity,
                descriptions: ["Rotate credentials regularly"]
            )
        ]

        let bound = try #require(AttackTreeBinding.bind(trees: [tree], to: threats, context: context).first)

        #expect(bound.sufficientControls.map(\.state) == [.unevidenced])
    }
}
