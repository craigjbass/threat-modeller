import CatalogueGateways
import ThreatModelKit

/// Everything the delivery mechanism is allowed to know about: use cases.
protocol UseCaseFactory {
    func listTechnologies() -> ListTechnologiesUseCase
    func addComponent() -> AddComponentUseCase
    func assessThreatModel() -> AssessThreatModelUseCase
}

/// The composition root. One graph per open model; from Milestone 6 that means
/// one per document window.
final class Dependencies: UseCaseFactory {
    private let catalogue: TechnologyCatalogue
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator

    init() throws {
        catalogue = try BundledTechnologyCatalogue()
        models = InMemoryThreatModelGateway()
        ids = UUIDIdentityGenerator()
    }

    func listTechnologies() -> ListTechnologiesUseCase {
        ListTechnologies(catalogue: catalogue)
    }

    func addComponent() -> AddComponentUseCase {
        AddComponent(models: models, catalogue: catalogue, ids: ids)
    }

    func assessThreatModel() -> AssessThreatModelUseCase {
        AssessThreatModel(models: models, catalogue: catalogue)
    }
}
