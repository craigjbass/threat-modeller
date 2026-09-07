import Foundation
import ThreatModelKit

public enum CatalogueLoadError: Error, Equatable {
    case unknownSeverity(threatId: String, severity: String)
}

/// Reads the catalogue vendored into this target's resource bundle.
public final class BundledTechnologyCatalogue: TechnologyCatalogue {
    private static let providerFiles = [
        "aws", "azure", "gcp", "saas", "self-hosted"
    ]

    private let taxonomyValue: Taxonomy
    private let providersValue: [Provider]
    private let technologies: [Technology]
    private let technologiesById: [TechnologyId: Technology]
    private let threatsById: [ThreatId: Threat]

    public init() throws {
        let decoder = JSONDecoder()

        let taxonomyJSON = try decoder.decode(
            TaxonomyJSON.self,
            from: try LibraryResources.data(named: "taxonomy.json")
        )
        taxonomyValue = Taxonomy(
            stride: taxonomyJSON.stride.map {
                StrideCategory(id: StrideId($0.id), label: $0.label)
            },
            severities: taxonomyJSON.severities.enumerated().map { index, entry in
                ThreatSeverity(id: entry.id, label: entry.label, rank: index + 1)
            },
            categories: taxonomyJSON.categories.map {
                ServiceCategory(
                    id: CategoryId($0.id),
                    label: $0.label,
                    presetThreatIds: $0.presetThreatIds.map(ThreatId.init)
                )
            }
        )

        let threatsJSON = try decoder.decode(
            ThreatsFileJSON.self,
            from: try LibraryResources.data(named: "threats/common-threats.json")
        )
        var threats: [ThreatId: Threat] = [:]
        for entry in threatsJSON.threats {
            guard let severity = taxonomyValue.severity(id: entry.severity) else {
                throw CatalogueLoadError.unknownSeverity(threatId: entry.id, severity: entry.severity)
            }
            threats[ThreatId(entry.id)] = Threat(
                id: ThreatId(entry.id),
                name: entry.name,
                description: entry.description,
                severity: severity,
                stride: entry.stride.map(StrideId.init),
                mitreTechniques: entry.mitreTechniques.map {
                    MitreTechnique(id: $0.id, name: $0.name, tactic: $0.tactic)
                },
                controls: entry.controls.map {
                    Control(id: $0.id, description: $0.description)
                },
                isConnectionThreat: entry.isConnectionThreat ?? false,
                isZoneThreat: entry.isZoneThreat ?? false,
                isPathwayThreat: entry.isPathwayThreat ?? false,
                zoneContext: entry.zoneContext
            )
        }
        threatsById = threats

        var providers: [Provider] = []
        var loaded: [Technology] = []
        for file in Self.providerFiles.sorted() {
            let providerJSON = try decoder.decode(
                ProviderFileJSON.self,
                from: try LibraryResources.data(named: "technologies/\(file).json")
            )
            providers.append(
                Provider(id: ProviderId(providerJSON.provider), displayName: providerJSON.displayName)
            )
            loaded.append(contentsOf: providerJSON.services.map(Self.technology(from:)))
        }
        providersValue = providers
        technologies = loaded
        technologiesById = Dictionary(uniqueKeysWithValues: loaded.map { ($0.id, $0) })
    }

    private static func technology(from service: ServiceJSON) -> Technology {
        Technology(
            id: TechnologyId(service.id),
            name: service.name,
            provider: ProviderId(service.provider),
            category: CategoryId(service.category),
            description: service.description,
            threatIds: service.threatIds.map(ThreatId.init),
            enforcesEncryption: service.connectionSecurity?.enforcesEncryption ?? false,
            internalOnly: service.connectionSecurity?.internalOnly ?? false,
            threatContext: Dictionary(
                uniqueKeysWithValues: (service.threatContext ?? [:]).map { (ThreatId($0.key), $0.value) }
            ),
            threatMitigations: Dictionary(
                uniqueKeysWithValues: (service.threatMitigations ?? [:]).map { (ThreatId($0.key), $0.value) }
            )
        )
    }

    public func all() -> [Technology] { technologies }

    public func findById(_ id: TechnologyId) -> Technology? { technologiesById[id] }

    public func threatsFor(technologyId: TechnologyId) -> [Threat] {
        guard let technology = technologiesById[technologyId] else { return [] }
        return technology.threatIds.compactMap { threatsById[$0] }
    }

    public func taxonomy() -> Taxonomy { taxonomyValue }

    public func providers() -> [Provider] { providersValue }
}
