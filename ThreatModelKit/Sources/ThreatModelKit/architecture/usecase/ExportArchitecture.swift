public protocol ExportArchitectureUseCase {
    func execute(_ request: ExportArchitectureRequest) -> ExportArchitectureResponse
}

public struct ExportArchitectureRequest: Equatable, Sendable {
    public init() {}
}

public struct ExportArchitectureResponse: Equatable, Sendable {
    public let text: String
    public let fileName: String

    public init(text: String, fileName: String) {
        self.text = text
        self.fileName = fileName
    }
}

/// Writes the model as an architecture file.
///
/// Structure only. A component's zone comes from the containment rule, which is
/// derived from the geometry, and no coordinate is written: the picture is
/// drawn from declaration order every time.
public struct ExportArchitecture: ExportArchitectureUseCase {
    private let models: ThreatModelGateway
    private let sources: ArchitectureSourceGateway

    public init(models: ThreatModelGateway, sources: ArchitectureSourceGateway) {
        self.models = models
        self.sources = sources
    }

    public func execute(_ request: ExportArchitectureRequest) -> ExportArchitectureResponse {
        let model = models.current()

        var inZone: [ZoneId: [SourceComponent]] = [:]
        var loose: [SourceComponent] = []
        for component in model.components {
            let written = SourceComponent(
                id: component.id.value,
                technologyId: component.technologyId.value,
                name: component.customName,
                data: component.sensitivity.rawValue,
                raisesThreats: component.threatsDisabled == false
            )
            if let zone = ZoneContainment.zone(holding: component.centre, in: model.zones) {
                inZone[zone.id, default: []].append(written)
            } else {
                loose.append(written)
            }
        }

        let source = ArchitectureSource(
            systemName: model.name,
            catalogueTag: model.catalogueVersion?.tag,
            technologies: model.customTechnologies.map { technology in
                SourceTechnology(
                    id: technology.id.value,
                    name: technology.name,
                    category: technology.category.value,
                    description: technology.description,
                    threatIds: technology.threatIds.map(\.value),
                    encrypts: technology.enforcesEncryption
                )
            },
            zones: model.zones.map { zone in
                SourceZone(
                    id: zone.id.value,
                    kind: zone.networkZone.rawValue,
                    network: zone.networkType.rawValue,
                    name: zone.name,
                    reducesRisk: zone.riskReductionEnabled,
                    reducesRiskBy: zone.riskReductionPercent,
                    components: inZone[zone.id] ?? []
                )
            },
            components: loose,
            flows: model.connections.map {
                SourceFlow(sourceId: $0.source.value, targetId: $0.target.value)
            }
        )

        return ExportArchitectureResponse(
            text: sources.write(source),
            fileName: "\(FileNaming.stem(from: model.name)).arch"
        )
    }
}
