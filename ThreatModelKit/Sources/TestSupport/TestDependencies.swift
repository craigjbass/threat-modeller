import ThreatModelKit

/// The composition root for tests. Mirrors the application's own `Dependencies`
/// but wires use cases to fakes. Gateways are deliberately private: an
/// acceptance test may only speak to the use case boundary.
public final class TestDependencies: UseCaseFactory {
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

    public func viewThreatModel() -> ViewThreatModelUseCase {
        ViewThreatModel(models: models, catalogue: catalogue)
    }

    public func addComponent() -> AddComponentUseCase {
        AddComponent(models: models, catalogue: catalogue, ids: ids)
    }

    public func moveComponents() -> MoveComponentsUseCase {
        MoveComponents(models: models)
    }

    public func removeComponents() -> RemoveComponentsUseCase {
        RemoveComponents(models: models)
    }

    public func connectComponents() -> ConnectComponentsUseCase {
        ConnectComponents(models: models, ids: ids)
    }

    public func removeConnection() -> RemoveConnectionUseCase {
        RemoveConnection(models: models)
    }

    public func assessThreatModel() -> AssessThreatModelUseCase {
        AssessThreatModel(models: models, catalogue: catalogue)
    }
}
