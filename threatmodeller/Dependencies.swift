import CatalogueGateways
import ThreatModelKit

/// The composition root. One graph per open model; from Milestone 6 that means
/// one per document window. `UseCaseFactory` lives in the core so this root and
/// `TestDependencies` cannot drift apart.
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

    func viewThreatModel() -> ViewThreatModelUseCase {
        ViewThreatModel(models: models, catalogue: catalogue)
    }

    func addComponent() -> AddComponentUseCase {
        AddComponent(models: models, catalogue: catalogue, ids: ids)
    }

    func moveComponents() -> MoveComponentsUseCase {
        MoveComponents(models: models)
    }

    func removeComponents() -> RemoveComponentsUseCase {
        RemoveComponents(models: models)
    }

    func connectComponents() -> ConnectComponentsUseCase {
        ConnectComponents(models: models, ids: ids)
    }

    func removeConnection() -> RemoveConnectionUseCase {
        RemoveConnection(models: models)
    }

    func addZone() -> AddZoneUseCase {
        AddZone(models: models, ids: ids)
    }

    func resizeZone() -> ResizeZoneUseCase {
        ResizeZone(models: models)
    }

    func setZoneProperties() -> SetZonePropertiesUseCase {
        SetZoneProperties(models: models)
    }

    func removeZone() -> RemoveZoneUseCase {
        RemoveZone(models: models)
    }

    func overrideThreatSeverity() -> OverrideThreatSeverityUseCase {
        OverrideThreatSeverity(models: models, catalogue: catalogue)
    }

    func clearSeverityOverride() -> ClearSeverityOverrideUseCase {
        ClearSeverityOverride(models: models)
    }

    func recordControlImplemented() -> RecordControlImplementedUseCase {
        RecordControlImplemented(models: models)
    }

    func recordControlNotImplemented() -> RecordControlNotImplementedUseCase {
        RecordControlNotImplemented(models: models)
    }

    func summariseRisk() -> SummariseRiskUseCase {
        SummariseRisk(models: models, catalogue: catalogue)
    }

    func assessThreatModel() -> AssessThreatModelUseCase {
        AssessThreatModel(models: models, catalogue: catalogue)
    }
}
