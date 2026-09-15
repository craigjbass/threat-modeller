import Foundation
import ThreatModelKit

public enum CatalogueLoadError: Error, Equatable {
    case unknownSeverity(threatId: String, severity: String)
}

/// Where a catalogue gateway reads its files from.
public protocol CatalogueResourceReader: Sendable {
    /// A file inside the vendored library, named relative to `Library/`.
    func data(named name: String) throws -> Data
    /// A file this application owns, named relative to `Actors/`.
    func appOwnedData(named name: String) throws -> Data
}

/// Reads the files this target vendors, or the directory `CatalogueLocation`
/// names.
public struct VendoredCatalogueResources: CatalogueResourceReader {
    public init() {}

    public func data(named name: String) throws -> Data {
        try LibraryResources.data(named: name)
    }

    public func appOwnedData(named name: String) throws -> Data {
        try LibraryResources.appOwnedData(named: name)
    }
}

/// Reads a catalogue laid out on disk the way a release tarball lays it out:
/// `Library/` and `Actors/` inside one directory.
public struct CatalogueDirectoryResources: CatalogueResourceReader {
    private let directory: String

    public init(directory: String) {
        self.directory = directory
    }

    public func data(named name: String) throws -> Data {
        try read("Library/\(name)")
    }

    public func appOwnedData(named name: String) throws -> Data {
        try read("Actors/\(name)")
    }

    private func read(_ path: String) throws -> Data {
        let url = URL(fileURLWithPath: directory).appendingPathComponent(path)
        guard let data = try? Data(contentsOf: url) else {
            throw LibraryResourceError.notFound(url.path)
        }
        return data
    }
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
    /// Every threat, in catalogue order, built once as the file is read.
    private let everyThreatValue: [Threat]
    private let connectionThreatsValue: [Threat]
    private let zoneThreatsValue: [Threat]
    private let pathwayMitigationsValue: [PathwayMitigationDefinition]
    private let versionValue: CatalogueVersion
    private let threatActorsValue: [ThreatActor]
    private let faultsValue: [CatalogueFault]

    public convenience init() throws {
        try self.init(resources: VendoredCatalogueResources())
    }

    /// Reads a catalogue laid out on disk, for a test and for a tool that
    /// checks a catalogue tag before it is vendored.
    public convenience init(directory: String) throws {
        try self.init(resources: CatalogueDirectoryResources(directory: directory))
    }

    public init(resources: CatalogueResourceReader) throws {
        let decoder = JSONDecoder()

        // Application-owned, and read first so the taxonomy can hold the
        // actors' own categories.
        let actorsJSON = try decoder.decode(
            ActorsFileJSON.self,
            from: try resources.appOwnedData(named: "actors.json")
        )

        let taxonomyJSON = try decoder.decode(
            TaxonomyJSON.self,
            from: try resources.data(named: "taxonomy.json")
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
            } + actorsJSON.categories.map {
                ServiceCategory(id: CategoryId($0.id), label: $0.label, presetThreatIds: [])
            }
        )

        let threatsJSON = try decoder.decode(
            ThreatsFileJSON.self,
            from: try resources.data(named: "threats/common-threats.json")
        )
        var threats: [ThreatId: Threat] = [:]
        var everyThreatList: [Threat] = []
        var connectionThreatList: [Threat] = []
        var zoneThreatList: [Threat] = []
        for entry in threatsJSON.threats {
            guard let severity = taxonomyValue.severity(id: entry.severity) else {
                throw CatalogueLoadError.unknownSeverity(threatId: entry.id, severity: entry.severity)
            }
            let threat = Threat(
                id: ThreatId(entry.id),
                name: entry.name,
                description: entry.description,
                severity: severity,
                stride: entry.stride.map(StrideId.init),
                impacts: (entry.impacts ?? []).compactMap(ThreatImpact.init(rawValue:)),
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
            threats[threat.id] = threat
            everyThreatList.append(threat)
            if threat.isConnectionThreat {
                connectionThreatList.append(threat)
            }
            if threat.isZoneThreat {
                zoneThreatList.append(threat)
            }
        }
        threatsById = threats
        everyThreatValue = everyThreatList
        connectionThreatsValue = connectionThreatList
        zoneThreatsValue = zoneThreatList

        var providers: [Provider] = []
        var loaded: [Technology] = []
        for file in Self.providerFiles.sorted() {
            let providerJSON = try decoder.decode(
                ProviderFileJSON.self,
                from: try resources.data(named: "technologies/\(file).json")
            )
            providers.append(
                Provider(id: ProviderId(providerJSON.provider), displayName: providerJSON.displayName)
            )
            loaded.append(contentsOf: providerJSON.services.map(Self.technology(from:)))
        }
        // The people and systems outside the boundary. An actor raises no
        // threats of its own; a link to one raises the connection threats like
        // any other link.
        let actorProvider = ProviderId(actorsJSON.provider)
        loaded.append(contentsOf: actorsJSON.actors.map {
            Technology(
                id: TechnologyId($0.id),
                name: $0.name,
                provider: actorProvider,
                category: CategoryId($0.category),
                description: $0.description,
                threatIds: []
            )
        })
        providers.append(Provider(id: actorProvider, displayName: actorsJSON.displayName))

        providersValue = providers
        // A duplicate technology id is a fault in the catalogue, not a reason
        // to stop. The first entry read is kept, and the fault names the id.
        let audit = CatalogueAudit.deduplicate(loaded)
        technologies = audit.kept
        technologiesById = Dictionary(uniqueKeysWithValues: audit.kept.map { ($0.id, $0) })
        faultsValue = CatalogueAudit.faults(
            technologies: loaded,
            declaredThreatIds: Set(threats.keys)
        )

        // Application-owned, like the external actors: the vendored library
        // states no adversary.
        let threatActorsJSON = try decoder.decode(
            ThreatActorsFileJSON.self,
            from: try resources.appOwnedData(named: "threat-actors.json")
        )
        threatActorsValue = threatActorsJSON.threatActors.map {
            ThreatActor(
                id: ThreatActorId($0.id),
                name: $0.name,
                description: $0.description ?? "",
                aliases: $0.aliases ?? [],
                capability: $0.capability.flatMap(Likelihood.init(rawValue:)) ?? .targeted,
                intent: $0.intent ?? "",
                performs: ($0.performs ?? []).map(ThreatId.init),
                techniques: $0.techniques ?? [],
                performsCatalogueTier: $0.performsCatalogueTier.flatMap(Likelihood.init(rawValue:))
            )
        }

        let mitigationsJSON = try decoder.decode(
            PathwayMitigationsFileJSON.self,
            from: try resources.data(named: "mitigations/pathway-mitigations.json")
        )
        let lockJSON = try decoder.decode(
            LockFileJSON.self,
            from: try resources.data(named: "library.lock.json")
        )
        versionValue = CatalogueVersion(repository: lockJSON.repository, tag: lockJSON.tag)

        pathwayMitigationsValue = mitigationsJSON.mitigations.map {
            PathwayMitigationDefinition(
                id: PathwayMitigationId($0.id),
                label: $0.label,
                description: $0.description,
                mitigatesThreatIds: $0.mitigatesThreatIds.map(ThreatId.init),
                technologyIds: $0.technologyIds.map(TechnologyId.init),
                reducesRiskBy: $0.reducesRiskBy,
                defaultMode: $0.mode.flatMap(PathwayMitigationMode.init(rawValue:))
            )
        }
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

    public func everyThreat() -> [Threat] { everyThreatValue }

    public func connectionThreats() -> [Threat] { connectionThreatsValue }

    public func zoneThreats() -> [Threat] { zoneThreatsValue }

    public func pathwayMitigations() -> [PathwayMitigationDefinition] { pathwayMitigationsValue }

    public func version() -> CatalogueVersion { versionValue }

    public func taxonomy() -> Taxonomy { taxonomyValue }

    public func providers() -> [Provider] { providersValue }

    public func threatActors() -> [ThreatActor] { threatActorsValue }

    public func findActor(_ id: ThreatActorId) -> ThreatActor? {
        threatActorsValue.first { $0.id == id }
    }

    public func faults() -> [CatalogueFault] { faultsValue }
}
