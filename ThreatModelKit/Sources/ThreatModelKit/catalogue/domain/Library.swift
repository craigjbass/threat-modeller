/// One library, said the way the rest of the application says it.
///
/// Every id it holds is already prefixed by its label, so nothing downstream
/// has to know a library entry from a vendored one.
public struct Library: Equatable, Sendable {
    /// The label of the `library` block. It is the provider id as well.
    public let label: String
    public let provider: Provider
    public let technologies: [Technology]
    public let threats: [Threat]

    public init(label: String, provider: Provider, technologies: [Technology], threats: [Threat]) {
        self.label = label
        self.provider = provider
        self.technologies = technologies
        self.threats = threats
    }
}

/// A value a library states that the taxonomy does not hold.
public enum LibraryBuildFault: Equatable, Sendable {
    case unknownCategory(technologyId: String, value: String)
    case unknownSeverity(threatId: String, value: String)
    case unknownStride(threatId: String, value: String)

    public var message: String {
        switch self {
        case .unknownCategory(let technologyId, let value):
            "the technology \"\(technologyId)\" is in the category \"\(value)\", "
                + "which the taxonomy does not hold"
        case .unknownSeverity(let threatId, let value):
            "the threat \"\(threatId)\" has the severity \"\(value)\", "
                + "which the taxonomy does not hold"
        case .unknownStride(let threatId, let value):
            "the threat \"\(threatId)\" names the stride category \"\(value)\", "
                + "which the taxonomy does not hold"
        }
    }
}

public extension Library {
    /// Mints the prefixed ids and checks every value against the taxonomy.
    ///
    /// It returns no library when it finds a fault, because half a library
    /// draws a diagram nobody can trust.
    static func build(
        from source: LibrarySource,
        taxonomy: Taxonomy
    ) -> (library: Library?, faults: [LibraryBuildFault]) {
        var faults: [LibraryBuildFault] = []
        let declared = Set(source.threats.map(\.id))

        func prefixed(_ id: String) -> String { "\(source.label)-\(id)" }

        let technologies = source.technologies.map { technology -> Technology in
            if taxonomy.category(id: CategoryId(technology.category)) == nil {
                faults.append(
                    .unknownCategory(technologyId: technology.id, value: technology.category)
                )
            }
            return Technology(
                id: TechnologyId(prefixed(technology.id)),
                name: technology.name,
                provider: ProviderId(source.label),
                category: CategoryId(technology.category),
                description: technology.description,
                // An id this library declares is its own. Any other id belongs
                // to the vendored catalogue, so it stays bare.
                threatIds: technology.threatIds.map {
                    ThreatId(declared.contains($0) ? prefixed($0) : $0)
                },
                enforcesEncryption: technology.encrypts
            )
        }

        let threats = source.threats.map { threat -> Threat in
            let severity = taxonomy.severity(id: threat.severityLabel)
            if severity == nil {
                faults.append(.unknownSeverity(threatId: threat.id, value: threat.severityLabel))
            }
            for stride in threat.strideIds
            where taxonomy.strideCategory(id: StrideId(stride)) == nil {
                faults.append(.unknownStride(threatId: threat.id, value: stride))
            }
            return Threat(
                id: ThreatId(prefixed(threat.id)),
                name: threat.name,
                description: threat.description,
                severity: severity
                    ?? ThreatSeverity(id: threat.severityLabel, label: threat.severityLabel, rank: 1),
                stride: threat.strideIds.map(StrideId.init),
                mitreTechniques: threat.mitre.map {
                    MitreTechnique(id: $0.id, name: $0.name, tactic: $0.tactic)
                },
                controls: threat.controlDescriptions.enumerated().map {
                    Control(id: "\(prefixed(threat.id))-\($0.offset)", description: $0.element)
                },
                isConnectionThreat: threat.isConnectionThreat,
                isZoneThreat: threat.isZoneThreat,
                zoneContext: threat.zoneContext
            )
        }

        guard faults.isEmpty else { return (nil, faults) }
        return (
            Library(
                label: source.label,
                provider: Provider(
                    id: ProviderId(source.label),
                    displayName: source.displayName ?? source.label
                ),
                technologies: technologies,
                threats: threats
            ),
            []
        )
    }
}
