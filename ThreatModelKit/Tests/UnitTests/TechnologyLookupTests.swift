import Testing
import ThreatModelKit
import TestSupport

struct TechnologyLookupTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func custom(
        _ id: String = "own-billing",
        name: String = "Billing",
        threatIds: [String] = ["credential-theft"]
    ) -> CustomTechnology {
        CustomTechnology(
            id: TechnologyId(id),
            name: name,
            provider: ProviderId("custom"),
            category: CategoryId("compute"),
            description: "Our own billing service",
            threatIds: threatIds.map(ThreatId.init)
        )
    }

    private func lookup(_ model: ThreatModel) -> TechnologyLookup {
        TechnologyLookup(model: model, catalogue: catalogue)
    }

    @Test func findsWhatTheCatalogueHolds() throws {
        let found = try #require(lookup(ThreatModel()).findById(TechnologyId("aws-ec2")))

        #expect(found.name == "EC2")
    }

    @Test func findsWhatTheModelDefines() throws {
        let model = ThreatModel(customTechnologies: [custom()])

        let found = try #require(lookup(model).findById(TechnologyId("own-billing")))
        #expect(found.name == "Billing")
        #expect(found.provider == ProviderId("custom"))
    }

    @Test func findsNothingForAnIdNeitherHolds() {
        #expect(lookup(ThreatModel()).findById(TechnologyId("own-billing")) == nil)
    }

    @Test func letsTheModelWinOverTheCatalogue() throws {
        // A user who names their own technology `aws-ec2` means theirs. The
        // model is the document in front of them; the catalogue is a library.
        let model = ThreatModel(customTechnologies: [custom("aws-ec2", name: "Our EC2")])

        #expect(try #require(lookup(model).findById(TechnologyId("aws-ec2"))).name == "Our EC2")
    }

    @Test func givesACustomTechnologyTheThreatsItNamed() {
        let model = ThreatModel(customTechnologies: [custom()])

        let threats = lookup(model).threatsFor(technologyId: TechnologyId("own-billing"))
        #expect(threats.map(\.id.value) == ["credential-theft"])
    }

    @Test func ignoresAThreatTheCatalogueDoesNotHold() {
        let model = ThreatModel(customTechnologies: [custom(threatIds: ["credential-theft", "invented"])])

        let threats = lookup(model).threatsFor(technologyId: TechnologyId("own-billing"))
        #expect(threats.map(\.id.value) == ["credential-theft"])
    }

    @Test func offersBothWhenAskedForEverything() {
        let model = ThreatModel(customTechnologies: [custom()])

        let all = lookup(model).all().map(\.id.value)
        #expect(all.contains("aws-ec2"))
        #expect(all.contains("own-billing"))
        // The model's own come first, so a user's own work is at hand.
        #expect(all.first == "own-billing")
    }
}
