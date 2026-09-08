public protocol ImportArchitectureUseCase {
    func execute(_ request: ImportArchitectureRequest) -> ImportArchitectureResponse
}

public struct ImportArchitectureRequest: Equatable, Sendable {
    public let text: String
    public init(text: String) { self.text = text }
}

public enum ImportArchitectureResponse: Equatable, Sendable {
    case imported(name: String, warnings: [Diagnostic])
    case refused(diagnostics: [Diagnostic])
}

/// Draws what an architecture file describes.
///
/// The whole import is one change on the gateway, so one undo takes it back. A
/// technology neither the catalogue nor the file holds is a warning and the
/// component is still placed: the diagram shows what the file says, and the
/// sidebar says what it could not score.
public struct ImportArchitecture: ImportArchitectureUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let sources: ArchitectureSourceGateway
    private let layout: LayOutModelUseCase

    public init(
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        sources: ArchitectureSourceGateway,
        layout: LayOutModelUseCase
    ) {
        self.models = models
        self.catalogue = catalogue
        self.sources = sources
        self.layout = layout
    }

    public func execute(_ request: ImportArchitectureRequest) -> ImportArchitectureResponse {
        let read = sources.read(request.text)
        guard let source = read.source, read.hasErrors == false else {
            return .refused(diagnostics: read.diagnostics)
        }

        let placed = layout.execute(LayOutModelRequest(source: source))
        let positions = Dictionary(
            uniqueKeysWithValues: placed.components.map { ($0.id, Point(x: $0.x, y: $0.y)) }
        )

        let customTechnologies = source.technologies.map { technology in
            CustomTechnology(
                id: TechnologyId(technology.id),
                name: technology.name,
                category: CategoryId(technology.category),
                description: technology.description,
                threatIds: technology.threatIds.map(ThreatId.init),
                enforcesEncryption: technology.encrypts
            )
        }

        var model = ThreatModel(
            name: source.systemName,
            customTechnologies: customTechnologies,
            catalogueVersion: source.catalogueTag.map {
                CatalogueVersion(repository: catalogue.version().repository, tag: $0)
            }
        )

        for component in source.everyComponent {
            model.components.append(
                Component(
                    id: ComponentId(component.id),
                    technologyId: TechnologyId(component.technologyId),
                    position: positions[component.id] ?? Point(x: 0, y: 0),
                    sensitivity: DataSensitivity(rawValue: component.data) ?? .internalData,
                    customName: component.name,
                    threatsDisabled: component.raisesThreats == false
                )
            )
        }

        for zone in source.zones {
            guard let rectangle = placed.zones.first(where: { $0.id == zone.id }) else { continue }
            model.zones.append(
                Zone(
                    id: ZoneId(zone.id),
                    rect: Rect(
                        x: rectangle.x,
                        y: rectangle.y,
                        width: rectangle.width,
                        height: rectangle.height
                    ),
                    name: zone.name,
                    networkZone: NetworkZone(rawValue: zone.kind) ?? .privateZone,
                    networkType: ZoneNetworkType(rawValue: zone.network) ?? .generic,
                    riskReductionEnabled: zone.reducesRisk,
                    riskReductionPercent: zone.reducesRiskBy ?? Zone.defaultRiskReductionPercent
                )
            )
        }

        for flow in source.flows {
            model.connections.append(
                Connection(
                    id: ConnectionId(flow.id),
                    source: ComponentId(flow.sourceId),
                    target: ComponentId(flow.targetId)
                )
            )
        }

        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        var warnings = read.warnings
        for component in source.everyComponent
        where lookup.findById(TechnologyId(component.technologyId)) == nil {
            warnings.append(
                Diagnostic(
                    severity: .warning,
                    line: 1,
                    column: 1,
                    message: "\"\(component.technologyId)\" is neither in this file nor in the "
                        + "catalogue, so \"\(component.id)\" raises no threats"
                )
            )
        }

        let imported = model
        return models.mutate { current in
            current = imported
            return .imported(name: imported.name, warnings: warnings)
        }
    }
}
