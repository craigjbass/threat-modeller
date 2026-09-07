import ThreatModelKit

/// The composition root for tests. Mirrors the application's own `Dependencies`
/// but wires use cases to fakes. Gateways are deliberately private: an
/// acceptance test may only speak to the use case boundary.
public final class TestDependencies {
    private let catalogue: InMemoryTechnologyCatalogue
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator

    public init() {
        self.catalogue = CatalogueFixture.catalogue()
        self.models = InMemoryThreatModelGateway()
        self.ids = SequentialIdentityGenerator()
    }

    public func listTechnologies() -> ListTechnologiesUseCase {
        ListTechnologies(catalogue: catalogue)
    }

    public func addComponent() -> AddComponentUseCase {
        AddComponent(models: models, catalogue: catalogue, ids: ids)
    }

    public func assessThreatModel() -> AssessThreatModelUseCase {
        AssessThreatModel(models: models, catalogue: catalogue)
    }
}
