import Testing
import ThreatModelKit
import TestSupport

struct SummariseRiskTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func summarise(_ model: ThreatModel) -> SummariseRiskResponse {
        SummariseRisk(models: InMemoryThreatModelGateway(model), catalogue: catalogue)
            .execute(SummariseRiskRequest())
    }

    private func ec2(_ id: String, sensitivity: DataSensitivity = .confidential) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: sensitivity
        )
    }

    @Test func summarisesAnEmptyModelAsNothing() {
        let summary = summarise(ThreatModel())

        #expect(summary.totalThreats == 0)
        #expect(summary.byLevel.allSatisfy { $0.count == 0 })
        #expect(summary.byStride.allSatisfy { $0.count == 0 })
        #expect(summary.controlsOffered == 0)
        #expect(summary.controlsRecorded == 0)
    }

    @Test func countsEveryLevelWorstFirst() {
        // EC2 at confidential raises credential-theft 12 (critical),
        // misconfiguration 6 (medium) and dos-attack 3 (low).
        let summary = summarise(ThreatModel(components: [ec2("c1")]))

        #expect(summary.totalThreats == 3)
        #expect(summary.byLevel.map(\.levelId) == ["critical", "high", "medium", "low"])
        #expect(summary.byLevel.map(\.label) == ["Critical", "High", "Medium", "Low"])
        #expect(summary.byLevel.map(\.count) == [1, 0, 1, 1])
    }

    @Test func countsEveryStrideCategoryInTaxonomyOrder() {
        let summary = summarise(ThreatModel(components: [ec2("c1")]))

        #expect(summary.byStride.map(\.strideId) == catalogue.taxonomy().stride.map(\.id.value))
        #expect(summary.byStride.map(\.label) == catalogue.taxonomy().stride.map(\.label))

        let counts = Dictionary(
            uniqueKeysWithValues: summary.byStride.map { ($0.strideId, $0.count) }
        )
        #expect(counts["spoofing"] == 1)
        #expect(counts["tampering"] == 1)
        #expect(counts["denial-of-service"] == 1)
        #expect(counts["repudiation"] == 0)
    }

    @Test func countsAThreatOnceInEveryCategoryItCarries() {
        // connection-mitm carries both tampering and information-disclosure.
        let summary = summarise(
            ThreatModel(
                components: [ec2("c1", sensitivity: .internalData), ec2("c2", sensitivity: .internalData)],
                connections: [Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c2"))]
            )
        )

        let counts = Dictionary(
            uniqueKeysWithValues: summary.byStride.map { ($0.strideId, $0.count) }
        )
        #expect(counts["information-disclosure"] == 1)
        #expect((counts["tampering"] ?? 0) >= 1)
    }

    @Test func talliesTheControlsOfferedAndTheOnesRecorded() {
        let plain = summarise(ThreatModel(components: [ec2("c1")]))
        #expect(plain.controlsOffered > 0)
        #expect(plain.controlsRecorded == 0)

        let key = ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: "Use IAM roles with minimal permissions",
            isTechnologySpecific: true
        )
        let recorded = summarise(
            ThreatModel(components: [ec2("c1")], implementedControls: [key])
        )
        #expect(recorded.controlsOffered == plain.controlsOffered)
        #expect(recorded.controlsRecorded == 1)
    }

    @Test func agreesWithWhatTheSidebarLists() {
        let model = ThreatModel(
            components: [ec2("c1"), ec2("c2", sensitivity: .publicData)],
            zones: [Zone(id: ZoneId("z1"), rect: Rect(x: -100, y: -100, width: 800, height: 700))]
        )
        let listed = AssessThreatModel(models: InMemoryThreatModelGateway(model), catalogue: catalogue)
            .execute(AssessThreatModelRequest()).threats

        #expect(summarise(model).totalThreats == listed.count)
    }
}
