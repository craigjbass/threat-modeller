import Testing
import ThreatModelKit
import TestSupport

/// What the actors a system faces do to a score. Spec section 4.3.
@Suite("Scoring a model that faces threat actors")
struct FacingThreatActorsTests {
    private let insider = ThreatActor(
        id: ThreatActorId("acme-insider"),
        name: "Disgruntled operator",
        capability: .targeted,
        intent: "sabotage",
        performs: [ThreatId("credential-theft")]
    )

    private func catalogue(_ actors: [ThreatActor]) -> InMemoryTechnologyCatalogue {
        InMemoryTechnologyCatalogue(
            technologies: [CatalogueFixture.ec2()],
            threats: CatalogueFixture.ec2Threats() + CatalogueFixture.connectionThreats()
                + CatalogueFixture.zoneThreats(),
            taxonomy: CatalogueFixture.taxonomy(),
            providers: CatalogueFixture.providers(),
            threatActors: CatalogueFixture.threatActors() + actors
        )
    }

    private func ec2() -> Component {
        Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .confidential
        )
    }

    private func assess(
        _ model: ThreatModel,
        actors: [ThreatActor] = []
    ) -> AssessThreatModelResponse {
        AssessThreatModel(
            models: InMemoryThreatModelGateway(model),
            catalogue: catalogue(actors)
        ).execute(AssessThreatModelRequest())
    }

    private func theft(_ response: AssessThreatModelResponse) throws -> AssessedThreat {
        try #require(response.threats.first { $0.threatId == "credential-theft" })
    }

    @Test func scoresAModelThatFacesNobodyTheWayItAlwaysDid() throws {
        let response = assess(ThreatModel(components: [ec2()]))

        let found = try theft(response)
        #expect(found.riskScore == 12)
        #expect(found.likelihoodId == "commodity")
        #expect(found.likelihoodReason == "from the catalogue")
        #expect(found.performedByLabels.isEmpty)
    }

    @Test func lowersAThreatToTheCapabilityOfTheActorThatPerformsIt() throws {
        let response = assess(
            ThreatModel(components: [ec2()], facedActorIds: ["acme-insider"]),
            actors: [insider]
        )

        // Credential theft scores 12, and a targeted actor's factor is 0.6.
        let found = try theft(response)
        #expect(found.likelihoodId == "targeted")
        #expect(found.likelihoodReason == "set by Disgruntled operator")
        #expect(found.performedByLabels == ["Disgruntled operator"])
        #expect(found.scoreBeforeLikelihood == 12)
        #expect(found.riskScore == 7)
    }

    @Test func keepsTheCataloguesTierForAThreatNoFacedActorPerforms() throws {
        let response = assess(
            ThreatModel(components: [ec2()], facedActorIds: ["acme-insider"]),
            actors: [insider]
        )

        let misconfiguration = try #require(
            response.threats.first { $0.threatId == "misconfiguration" }
        )
        #expect(misconfiguration.likelihoodReason == "from the catalogue")
        #expect(misconfiguration.performedByLabels.isEmpty)
    }

    @Test func letsAFindingBeatTheActors() throws {
        let response = assess(
            ThreatModel(
                components: [ec2()],
                likelihoodFindings: [
                    ThreatKey(threatId: "credential-theft", sourceId: "component:c1"):
                        LikelihoodFinding(
                            label: "no in-the-wild use",
                            likelihood: .research,
                            rationale: "every report is researcher-found"
                        )
                ],
                facedActorIds: ["acme-insider"]
            ),
            actors: [insider]
        )

        let found = try theft(response)
        #expect(found.likelihoodId == "research")
        #expect(found.likelihoodReason == "no in-the-wild use")
    }

    @Test func facesTheBuiltInActorAndKeepsEveryScore() throws {
        let response = assess(
            ThreatModel(components: [ec2()], facedActorIds: ["commodity-crimeware"])
        )

        // Every threat the catalogue marks commodity keeps the factor 1.0.
        let found = try theft(response)
        #expect(found.riskScore == 12)
        #expect(found.performedByLabels == ["Commodity crimeware"])
    }

    @Test func letsALocalActorOverrideALibraryActorWhole() throws {
        let local = ThreatActor(
            id: ThreatActorId("acme-insider"),
            name: "Our own operator",
            capability: .research,
            performs: [ThreatId("credential-theft")]
        )

        let response = assess(
            ThreatModel(components: [ec2()], facedActorIds: ["acme-insider"], localActors: [local]),
            actors: [insider]
        )

        let found = try theft(response)
        #expect(found.likelihoodId == "research")
        #expect(found.performedByLabels == ["Our own operator"])
    }

    @Test func takesTheHighestCapabilityAmongThePerformers() throws {
        let response = assess(
            ThreatModel(
                components: [ec2()],
                facedActorIds: ["acme-insider", "commodity-crimeware"]
            ),
            actors: [insider]
        )

        let found = try theft(response)
        #expect(found.likelihoodId == "commodity")
        #expect(found.riskScore == 12)
        #expect(found.performedByLabels.sorted() == ["Commodity crimeware", "Disgruntled operator"])
    }
}
