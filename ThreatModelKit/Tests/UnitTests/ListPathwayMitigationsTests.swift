import Testing
import ThreatModelKit
import TestSupport

struct ListPathwayMitigationsTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func list(_ model: ThreatModel) -> ListPathwayMitigationsResponse {
        ListPathwayMitigations(models: InMemoryThreatModelGateway(model), catalogue: catalogue)
            .execute(ListPathwayMitigationsRequest())
    }

    private func component(_ id: String, _ technologyId: String) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId(technologyId),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData
        )
    }

    @Test func listsEveryMitigationTheCatalogueDefines() throws {
        let listed = list(ThreatModel())

        #expect(listed.mitigations.map(\.id) == ["waf-protection"])
        let waf = try #require(listed.mitigations.first)
        #expect(waf.label == "WAF Protection")
        #expect(waf.description.isEmpty == false)
    }

    @Test func startsWithTheMasterToggleOffAndEachMitigationOn() throws {
        let listed = list(ThreatModel())

        #expect(listed.isMasterEnabled == false)
        let waf = try #require(listed.mitigations.first)
        #expect(waf.isEnabled)
        #expect(waf.mode == "reduce")
        #expect(waf.reductionPercent == 50)
    }

    @Test func showsWhatTheUserSet() throws {
        let listed = list(
            ThreatModel(
                pathwayMitigations: PathwayMitigationSettings(
                    isMasterEnabled: true,
                    configs: [
                        PathwayMitigationId("waf-protection"):
                            PathwayMitigationConfig(isEnabled: false, mode: .remove, reductionPercent: 90)
                    ]
                )
            )
        )

        #expect(listed.isMasterEnabled)
        let waf = try #require(listed.mitigations.first)
        #expect(waf.isEnabled == false)
        #expect(waf.mode == "remove")
        #expect(waf.reductionPercent == 90)
    }

    @Test func namesWhatProvidesItAndWhatItAnswers() throws {
        let waf = try #require(list(ThreatModel()).mitigations.first)

        #expect(waf.providedByTechnologyNames == ["WAF"])
        #expect(waf.mitigatedThreatNames.sorted() == ["Connection Flooding", "Credential Theft"])
    }

    @Test func saysWhenNothingOnThisModelProvidesIt() throws {
        // A switch the user turns on that nothing provides changes no score.
        // The screen says so rather than leaving them guessing.
        #expect(try #require(list(ThreatModel()).mitigations.first).isProvidedOnThisModel == false)

        let withWaf = list(ThreatModel(components: [component("c1", "aws-waf")]))
        #expect(try #require(withWaf.mitigations.first).isProvidedOnThisModel)

        let withoutWaf = list(ThreatModel(components: [component("c1", "aws-ec2")]))
        #expect(try #require(withoutWaf.mitigations.first).isProvidedOnThisModel == false)
    }
}
