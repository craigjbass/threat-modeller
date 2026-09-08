import Testing
import ThreatModelKit
import TestSupport

struct ListTechnologiesTests {
    private let useCase = ListTechnologies(models: InMemoryThreatModelGateway(), catalogue: CatalogueFixture.catalogue())

    @Test func groupsTechnologiesUnderTheirProvider() {
        let response = useCase.execute(ListTechnologiesRequest())
        #expect(response.providers.map(\.id) == ["aws", "gcp", "actor"])
        #expect(response.providers.first?.displayName == "Amazon Web Services")
    }

    @Test func groupsTechnologiesUnderTheirCategoryInTaxonomyOrder() throws {
        let response = useCase.execute(ListTechnologiesRequest())
        let aws = try #require(response.providers.first { $0.id == "aws" })
        #expect(aws.categories.map(\.id) == ["compute", "database"])
        #expect(aws.categories.first?.label == "Compute")
    }

    @Test func omitsCategoriesWithNoTechnologies() throws {
        let response = useCase.execute(ListTechnologiesRequest())
        let gcp = try #require(response.providers.first { $0.id == "gcp" })
        #expect(gcp.categories.map(\.id) == ["database"])
    }

    @Test func listsTechnologiesByName() throws {
        let catalogue = InMemoryTechnologyCatalogue(
            technologies: [
                Technology(
                    id: TechnologyId("aws-zeta"),
                    name: "Zeta",
                    provider: ProviderId("aws"),
                    category: CategoryId("compute"),
                    description: "Last"
                ),
                Technology(
                    id: TechnologyId("aws-alpha"),
                    name: "alpha",
                    provider: ProviderId("aws"),
                    category: CategoryId("compute"),
                    description: "First"
                )
            ],
            threats: [],
            taxonomy: CatalogueFixture.taxonomy(),
            providers: CatalogueFixture.providers()
        )

        let response = ListTechnologies(models: InMemoryThreatModelGateway(), catalogue: catalogue).execute(ListTechnologiesRequest())
        let compute = try #require(response.providers.first?.categories.first)
        #expect(compute.technologies.map(\.name) == ["alpha", "Zeta"])
        #expect(compute.technologies.first?.id == "aws-alpha")
        #expect(compute.technologies.first?.description == "First")
    }

    @Test func omitsProvidersWithNoTechnologies() {
        let catalogue = InMemoryTechnologyCatalogue(
            technologies: [],
            threats: [],
            taxonomy: CatalogueFixture.taxonomy(),
            providers: CatalogueFixture.providers()
        )
        let response = ListTechnologies(models: InMemoryThreatModelGateway(), catalogue: catalogue).execute(ListTechnologiesRequest())
        #expect(response.providers.isEmpty)
    }
}
