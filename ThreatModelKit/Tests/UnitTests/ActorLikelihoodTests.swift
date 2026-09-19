import Testing
import ThreatModelKit
import TestSupport

/// The rule that turns the actors a system faces into one likelihood per
/// threat. Spec section 4.2.
@Suite("The likelihood the faced actors give")
struct ActorLikelihoodTests {
    private func threat(
        _ id: String = "credential-theft",
        likelihood: Likelihood = .commodity,
        techniques: [String] = []
    ) -> Threat {
        Threat(
            id: ThreatId(id),
            name: "Credential Theft",
            description: "",
            severity: CatalogueFixture.critical,
            mitreTechniques: techniques.map {
                MitreTechnique(id: $0, name: "", tactic: "")
            },
            likelihood: likelihood
        )
    }

    private func crimeware() -> ThreatActor {
        ThreatActor(
            id: ThreatActorId("commodity-crimeware"),
            name: "Commodity crimeware",
            capability: .commodity,
            performsCatalogueTier: .commodity
        )
    }

    private func fin7(performs: [String] = ["credential-theft"], techniques: [String] = [])
        -> ThreatActor {
        ThreatActor(
            id: ThreatActorId("mitre-g0046"),
            name: "FIN7",
            capability: .targeted,
            performs: performs.map(ThreatId.init),
            techniques: techniques
        )
    }

    // The five rows of the table in section 4.2, each as one test.

    @Test func takesTheHighestFactorWhenTwoActorsPerformIt() {
        let source = ActorLikelihood.likelihood(
            of: threat(likelihood: .commodity),
            faced: [crimeware(), fin7()]
        )

        #expect(source.likelihood == .commodity)
        #expect(source.reason == "set by Commodity crimeware")
    }

    @Test func lowersACommodityThreatToTheOneActorThatPerformsIt() {
        let source = ActorLikelihood.likelihood(of: threat(likelihood: .commodity), faced: [fin7()])

        #expect(source.likelihood == .targeted)
        #expect(source.reason == "set by FIN7")
    }

    @Test func raisesAResearchThreatToTheActorThatPerformsIt() {
        let source = ActorLikelihood.likelihood(of: threat(likelihood: .research), faced: [fin7()])

        #expect(source.likelihood == .targeted)
    }

    /// The rule that keeps this design safe: a short or wrong actor list never
    /// lowers a score by leaving a threat out.
    @Test func keepsTheCataloguesTierWhenNoFacedActorPerformsIt() {
        let source = ActorLikelihood.likelihood(
            of: threat("dos-attack", likelihood: .commodity),
            faced: [fin7(performs: ["credential-theft"])]
        )

        #expect(source == .catalogue(.commodity))
        #expect(source.reason == "from the catalogue")
    }

    @Test func keepsTheCataloguesTierWhenTheSystemFacesNobody() {
        #expect(
            ActorLikelihood.likelihood(of: threat(likelihood: .commodity), faced: [])
                == .catalogue(.commodity)
        )
    }

    // The three tests of `performers`.

    @Test func aProfilesSubTechniquePerformsAThreatThatNamesTheParent() {
        let performers = ActorLikelihood.performers(
            of: threat(techniques: ["T1550"]),
            among: [fin7(performs: [], techniques: ["T1550.001"])]
        )

        #expect(performers.map(\.id.value) == ["mitre-g0046"])
    }

    @Test func aThreatsSubTechniqueIsPerformedByAProfileThatNamesTheParent() {
        let performers = ActorLikelihood.performers(
            of: threat(techniques: ["T1550.001"]),
            among: [fin7(performs: [], techniques: ["T1550"])]
        )

        #expect(performers.map(\.id.value) == ["mitre-g0046"])
    }

    @Test func aCatalogueTierPerformsEveryThreatAtThatTierAndNoOther() {
        let commodity = threat("dos-attack", likelihood: .commodity)
        let research = threat("supply-chain", likelihood: .research)

        #expect(ActorLikelihood.performers(of: commodity, among: [crimeware()]).count == 1)
        #expect(ActorLikelihood.performers(of: research, among: [crimeware()]).isEmpty)
    }

    @Test func anInsiderCatalogueTierPerformsEveryInsiderThreat() {
        let insider = ThreatActor(
            id: ThreatActorId("acme-insider"),
            name: "Disgruntled operator",
            capability: .insider,
            performsCatalogueTier: .insider
        )
        let byAnInsider = threat("key-copying", likelihood: .insider)
        let byAnybody = threat("dos-attack", likelihood: .commodity)

        #expect(ActorLikelihood.performers(of: byAnInsider, among: [insider]).count == 1)
        #expect(ActorLikelihood.performers(of: byAnybody, among: [insider]).isEmpty)
    }

    @Test func lowersACommodityThreatToTheInsiderThatPerformsIt() {
        let insider = ThreatActor(
            id: ThreatActorId("acme-insider"),
            name: "Disgruntled operator",
            capability: .insider,
            performs: [ThreatId("credential-theft")]
        )

        let source = ActorLikelihood.likelihood(
            of: threat(likelihood: .commodity),
            faced: [insider]
        )

        #expect(source.likelihood == .insider)
        #expect(source.likelihood.factor == 0.6)
        #expect(source.reason == "set by Disgruntled operator")
    }

    @Test func readsAParentTechniqueId() {
        #expect(ActorLikelihood.parent(of: "T1550.001") == "T1550")
        #expect(ActorLikelihood.parent(of: "T1550") == "T1550")
    }
}
