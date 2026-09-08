import ThreatModelKit
import FileGateways

/// The composition root for tests. Mirrors the application's own `Dependencies`
/// but wires use cases to fakes. Gateways are deliberately private: an
/// acceptance test may only speak to the use case boundary.
public final class TestDependencies: UseCaseFactory {
    private let catalogue: InMemoryTechnologyCatalogue
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator
    private let files: ThreatModelFileGateway = ThreatModelCodec()
    private let clock = FixedClock()
    /// The clock this root runs on, so an acceptance test can move time.
    public var time: FixedClock { clock }

    public init() {
        self.catalogue = CatalogueFixture.catalogue()
        self.models = InMemoryThreatModelGateway()
        self.ids = SequentialIdentityGenerator()
    }

    public func createThreatModel() -> CreateThreatModelUseCase {
        CreateThreatModel(models: models, catalogue: catalogue, clock: clock)
    }

    public func openThreatModel() -> OpenThreatModelUseCase {
        OpenThreatModel(models: models, catalogue: catalogue, files: files)
    }

    public func saveThreatModel() -> SaveThreatModelUseCase {
        SaveThreatModel(models: models, catalogue: catalogue, clock: clock, files: files)
    }

    public func renameThreatModel() -> RenameThreatModelUseCase {
        RenameThreatModel(models: models, clock: clock)
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

    public func addZone() -> AddZoneUseCase {
        AddZone(models: models, ids: ids)
    }

    public func resizeZone() -> ResizeZoneUseCase {
        ResizeZone(models: models)
    }

    public func setZoneProperties() -> SetZonePropertiesUseCase {
        SetZoneProperties(models: models)
    }

    public func removeZone() -> RemoveZoneUseCase {
        RemoveZone(models: models)
    }

    public func overrideThreatSeverity() -> OverrideThreatSeverityUseCase {
        OverrideThreatSeverity(models: models, catalogue: catalogue)
    }

    public func clearSeverityOverride() -> ClearSeverityOverrideUseCase {
        ClearSeverityOverride(models: models)
    }

    public func recordControlImplemented() -> RecordControlImplementedUseCase {
        RecordControlImplemented(models: models)
    }

    public func recordControlNotImplemented() -> RecordControlNotImplementedUseCase {
        RecordControlNotImplemented(models: models)
    }

    public func summariseRisk() -> SummariseRiskUseCase {
        SummariseRisk(models: models, catalogue: catalogue)
    }

    public func listPathwayMitigations() -> ListPathwayMitigationsUseCase {
        ListPathwayMitigations(models: models, catalogue: catalogue)
    }

    public func configurePathwayMitigations() -> ConfigurePathwayMitigationsUseCase {
        ConfigurePathwayMitigations(models: models, catalogue: catalogue)
    }

    public func assessThreatModel() -> AssessThreatModelUseCase {
        AssessThreatModel(models: models, catalogue: catalogue)
    }
}
