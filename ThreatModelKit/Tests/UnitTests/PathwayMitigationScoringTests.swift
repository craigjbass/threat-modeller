import Testing
import ThreatModelKit
import TestSupport

/// What the resolver does with more than one mitigation on one threat, and
/// with a mitigation a zone's own components provide.
@Suite("Scoring a threat more than one mitigation answers")
struct PathwayMitigationScoringTests {
    /// Two mitigations answer `credential-theft`, and one answers the zone
    /// threat `lateral-movement`. The WAF provides all three.
    private let catalogue = InMemoryTechnologyCatalogue(
        technologies: [
            CatalogueFixture.ec2(), CatalogueFixture.rds(), CatalogueFixture.waf()
        ],
        threats: CatalogueFixture.ec2Threats() + CatalogueFixture.connectionThreats()
            + CatalogueFixture.zoneThreats(),
        taxonomy: CatalogueFixture.taxonomy(),
        providers: CatalogueFixture.providers(),
        pathwayMitigations: [
            PathwayMitigationDefinition(
                id: PathwayMitigationId("waf-protection"),
                label: "WAF Protection",
                description: "",
                mitigatesThreatIds: [ThreatId("credential-theft")],
                technologyIds: [TechnologyId("aws-waf")]
            ),
            PathwayMitigationDefinition(
                id: PathwayMitigationId("secret-rotation"),
                label: "Secret Rotation",
                description: "",
                mitigatesThreatIds: [ThreatId("credential-theft")],
                technologyIds: [TechnologyId("aws-waf")]
            ),
            PathwayMitigationDefinition(
                id: PathwayMitigationId("network-firewall"),
                label: "Network Firewall",
                description: "",
                mitigatesThreatIds: [ThreatId("lateral-movement")],
                technologyIds: [TechnologyId("aws-waf")]
            )
        ]
    )

    private func assess(_ model: ThreatModel) -> AssessThreatModelResponse {
        let model = model.withZoneMembershipFromGeometry()
        return AssessThreatModel(models: InMemoryThreatModelGateway(model), catalogue: catalogue)
            .execute(AssessThreatModelRequest())
    }

    private func waf(_ id: String = "w1", position: Point = Point(x: 0, y: 0)) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-waf"),
            position: position,
            sensitivity: .internalData
        )
    }

    private func ec2(_ id: String = "c1", position: Point = Point(x: 0, y: 0)) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: position,
            sensitivity: .confidential
        )
    }

    private func settings(
        _ percents: [String: Int],
        mode: PathwayMitigationMode = .reduce
    ) -> PathwayMitigationSettings {
        PathwayMitigationSettings(
            isMasterEnabled: true,
            configs: Dictionary(
                uniqueKeysWithValues: percents.map {
                    (
                        PathwayMitigationId($0.key),
                        PathwayMitigationConfig(isEnabled: true, mode: mode, reductionPercent: $0.value)
                    )
                }
            )
        )
    }

    @Test func compoundsTwoMitigationsRatherThanTakingTheStronger() throws {
        // Credential theft on confidential data scores 12. A half reduction
        // leaves 6, and a quarter reduction of that 6 leaves 4.5, which floors
        // to 4. The stronger one alone would leave 6.
        let response = assess(
            ThreatModel(
                components: [waf(), ec2()],
                connections: [
                    Connection(id: ConnectionId("k1"), source: ComponentId("w1"), target: ComponentId("c1"))
                ],
                pathwayMitigations: settings(["waf-protection": 50, "secret-rotation": 25])
            )
        )

        let theft = try #require(response.threats.first {
            $0.threatId == "credential-theft" && $0.source.id == "component:c1"
        })
        #expect(theft.scoreBeforePathwayMitigation == 12)
        #expect(theft.riskScore == 4)
        #expect(theft.pathwayMitigationLabels.sorted() == ["Secret Rotation", "WAF Protection"])
    }

    @Test func lowersAZoneThreatAMitigationInsideThatZoneAnswers() throws {
        // A firewall in the zone answers the threats about moving inside it.
        // Lateral movement is high (3) against internal data (2), which is 6,
        // and a private zone's default 20 per cent reduction leaves 5. A half
        // reduction of that leaves 2.5, which floors to 2.
        let zone = Zone(
            id: ZoneId("z1"),
            rect: Rect(x: -100, y: -100, width: 800, height: 700),
            networkZone: .privateZone
        )

        let response = assess(
            ThreatModel(
                components: [waf()],
                zones: [zone],
                pathwayMitigations: settings(["network-firewall": 50])
            )
        )

        let movement = try #require(response.threats.first {
            $0.threatId == "lateral-movement" && $0.source.id == "zone:z1"
        })
        #expect(movement.scoreBeforePathwayMitigation == 5)
        #expect(movement.riskScore == 2)
        #expect(movement.pathwayMitigationLabels == ["Network Firewall"])
    }

    @Test func removesAZoneThreatAMitigationInsideThatZoneRemoves() {
        let zone = Zone(
            id: ZoneId("z1"),
            rect: Rect(x: -100, y: -100, width: 800, height: 700),
            networkZone: .privateZone
        )

        let response = assess(
            ThreatModel(
                components: [waf()],
                zones: [zone],
                pathwayMitigations: settings(["network-firewall": 50], mode: .remove)
            )
        )

        #expect(response.threats.contains { $0.threatId == "lateral-movement" } == false)
    }

    @Test func leavesAZoneThreatAloneWhenTheProviderSitsOutsideThatZone() throws {
        let zone = Zone(
            id: ZoneId("z1"),
            rect: Rect(x: -100, y: -100, width: 400, height: 400),
            networkZone: .privateZone
        )

        let response = assess(
            ThreatModel(
                components: [waf("w1", position: Point(x: 2_000, y: 2_000))],
                zones: [zone],
                pathwayMitigations: settings(["network-firewall": 50])
            )
        )

        let movement = try #require(response.threats.first {
            $0.threatId == "lateral-movement" && $0.source.id == "zone:z1"
        })
        #expect(movement.riskScore == movement.scoreBeforePathwayMitigation)
        #expect(movement.pathwayMitigationLabels.isEmpty)
    }
}
