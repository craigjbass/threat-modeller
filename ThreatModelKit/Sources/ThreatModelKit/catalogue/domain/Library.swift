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
    public let pathwayMitigations: [PathwayMitigationDefinition]
    public let threatActors: [ThreatActor]
    /// What this library adds to the vendored taxonomy: a domain the vendored
    /// categories do not name, a severity a team words its own way, or a
    /// stride category their own method holds.
    public let categories: [ServiceCategory]
    public let severities: [ThreatSeverity]
    public let strides: [StrideCategory]
    /// What this library changes about a threat the catalogue already holds,
    /// by that threat's id.
    public let overrides: [ThreatId: ThreatOverride]
    /// The classification scheme this library states, or nil when it states
    /// none and the standard four stand.
    public let classifications: ClassificationScheme?

    public init(
        label: String,
        provider: Provider,
        technologies: [Technology],
        threats: [Threat],
        pathwayMitigations: [PathwayMitigationDefinition] = [],
        threatActors: [ThreatActor] = [],
        categories: [ServiceCategory] = [],
        severities: [ThreatSeverity] = [],
        strides: [StrideCategory] = [],
        overrides: [ThreatId: ThreatOverride] = [:],
        classifications: ClassificationScheme? = nil
    ) {
        self.label = label
        self.provider = provider
        self.technologies = technologies
        self.threats = threats
        self.pathwayMitigations = pathwayMitigations
        self.threatActors = threatActors
        self.categories = categories
        self.severities = severities
        self.strides = strides
        self.overrides = overrides
        self.classifications = classifications
    }
}

/// What a library changes about a threat the catalogue holds, and which
/// library changed it.
///
/// The report names the library, so a reader can tell an overridden value from
/// the catalogue's own.
public struct ThreatOverride: Equatable, Sendable {
    public let libraryLabel: String
    public let severity: ThreatSeverity?
    public let likelihood: Likelihood?
    public let description: String?
    public let controls: [Control]

    public init(
        libraryLabel: String,
        severity: ThreatSeverity? = nil,
        likelihood: Likelihood? = nil,
        description: String? = nil,
        controls: [Control] = []
    ) {
        self.libraryLabel = libraryLabel
        self.severity = severity
        self.likelihood = likelihood
        self.description = description
        self.controls = controls
    }

    /// The threat as this override states it.
    public func applied(to threat: Threat) -> Threat {
        Threat(
            id: threat.id,
            name: threat.name,
            description: description ?? threat.description,
            severity: severity ?? threat.severity,
            stride: threat.stride,
            mitreTechniques: threat.mitreTechniques,
            controls: controls.isEmpty ? threat.controls : controls,
            isConnectionThreat: threat.isConnectionThreat,
            isZoneThreat: threat.isZoneThreat,
            isPathwayThreat: threat.isPathwayThreat,
            zoneContext: threat.zoneContext,
            appliesToFlowKinds: threat.appliesToFlowKinds,
            boundary: threat.boundary,
            appliesToPrivilegeLevels: threat.appliesToPrivilegeLevels,
            likelihood: likelihood ?? threat.likelihood
        )
    }
}

/// A value a library states that the taxonomy does not hold.
public enum LibraryBuildFault: Equatable, Sendable {
    case unknownCategory(technologyId: String, value: String)
    case unknownSeverity(threatId: String, value: String)
    case unknownStride(threatId: String, value: String)
    case unknownFlowKind(threatId: String, value: String)
    case unknownBoundary(threatId: String, value: String)
    case unknownPrivilegeLevel(threatId: String, value: String)

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
        case .unknownFlowKind(let threatId, let value):
            "the threat \"\(threatId)\" applies to the flow kind \"\(value)\", "
                + "which the application does not hold"
        case .unknownBoundary(let threatId, let value):
            "the threat \"\(threatId)\" names the boundary \"\(value)\", "
                + "which the application does not hold"
        case .unknownPrivilegeLevel(let threatId, let value):
            "the threat \"\(threatId)\" applies to the privilege level \"\(value)\", "
                + "which the application does not hold"
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
        // A library's own words count as known: a technology may name a
        // category this library declares, and a threat a severity it declares.
        let ownCategories = source.categories.map {
            ServiceCategory(id: CategoryId($0.id), label: $0.label, presetThreatIds: [])
        }
        let ownStrides = source.strides.map { StrideCategory(id: StrideId($0.id), label: $0.label) }
        let ownSeverities = source.severities.enumerated().map { position, entry in
            // A library severity ranks above every vendored one: a team that
            // words its own severity means something the vendored scale does
            // not hold.
            ThreatSeverity(
                id: entry.id,
                label: entry.label,
                rank: taxonomy.severities.count + position + 1
            )
        }
        let taxonomy = Taxonomy(
            stride: taxonomy.stride + ownStrides,
            severities: taxonomy.severities + ownSeverities,
            categories: taxonomy.categories + ownCategories
        )
        let declared = Set(source.threats.map(\.id))
        let declaredTechnologies = Set(source.technologies.map(\.id))

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
                enforcesEncryption: technology.encrypts,
                // A control the library states on the technology answers every
                // threat that technology carries.
                threatMitigations: Dictionary(
                    uniqueKeysWithValues: technology.threatIds.map {
                        (
                            ThreatId(declared.contains($0) ? prefixed($0) : $0),
                            technology.controlDescriptions
                        )
                    }
                )
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
            let flowKinds = threat.appliesTo.compactMap { raw -> FlowKind? in
                guard let kind = FlowKind(rawValue: raw) else {
                    faults.append(.unknownFlowKind(threatId: threat.id, value: raw))
                    return nil
                }
                return kind
            }
            let levels = threat.runsAs.compactMap { raw -> PrivilegeLevel? in
                guard let level = PrivilegeLevel(rawValue: raw) else {
                    faults.append(.unknownPrivilegeLevel(threatId: threat.id, value: raw))
                    return nil
                }
                return level
            }
            var boundary: ZoneBoundary?
            if let raw = threat.boundary {
                boundary = ZoneBoundary(rawValue: raw)
                if boundary == nil {
                    faults.append(.unknownBoundary(threatId: threat.id, value: raw))
                }
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
                isPathwayThreat: threat.isPathwayThreat,
                zoneContext: threat.zoneContext,
                appliesToFlowKinds: flowKinds,
                boundary: boundary,
                appliesToPrivilegeLevels: levels,
                likelihood: threat.likelihood.flatMap(Self.likelihood(from:)) ?? .commodity
            )
        }

        let mitigations = source.mitigations.map { mitigation in
            PathwayMitigationDefinition(
                id: PathwayMitigationId(prefixed(mitigation.id)),
                label: mitigation.name,
                description: mitigation.description,
                mitigatesThreatIds: mitigation.mitigatesThreatIds.map {
                    ThreatId(declared.contains($0) ? prefixed($0) : $0)
                },
                technologyIds: mitigation.technologyIds.map {
                    TechnologyId(declaredTechnologies.contains($0) ? prefixed($0) : $0)
                },
                reducesRiskBy: mitigation.reducesRiskBy,
                defaultMode: mitigation.mode.flatMap(PathwayMitigationMode.init(rawValue:)),
                libraryLabel: source.displayName ?? source.label
            )
        }

        // An override names a threat the catalogue holds. A library's own
        // threat is stated by its `threat` block, not overridden here, so an
        // id this library declares and an id nothing holds are both faults.
        var overrides: [ThreatId: ThreatOverride] = [:]
        for override in source.overrides {
            let severity = override.severityLabel.flatMap { taxonomy.severity(id: $0) }
            if let stated = override.severityLabel, severity == nil {
                faults.append(.unknownSeverity(threatId: override.threatId, value: stated))
            }
            overrides[ThreatId(override.threatId)] = ThreatOverride(
                libraryLabel: source.displayName ?? source.label,
                severity: severity,
                likelihood: override.likelihood.flatMap(Likelihood.init(rawValue:)),
                description: override.description,
                controls: override.controlDescriptions.enumerated().map {
                    Control(
                        id: "\(source.label)-\(override.threatId)-override-\($0.offset)",
                        description: $0.element
                    )
                }
            )
        }

        // Spec section 3.3: a library's actor id is minted the way a
        // technology id and a threat id are.
        let actors = source.threatActors.map { actor in
            ThreatActor(
                id: ThreatActorId(prefixed(actor.id)),
                name: actor.name,
                description: actor.description,
                aliases: actor.aliases,
                capability: actor.capability.flatMap(Likelihood.init(rawValue:)) ?? .targeted,
                intent: actor.intent,
                performs: actor.performs.map {
                    ThreatId(declared.contains($0) ? prefixed($0) : $0)
                },
                techniques: actor.techniques,
                performsCatalogueTier: actor.performsCatalogueTier
                    .flatMap(Likelihood.init(rawValue:))
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
                threats: threats,
                pathwayMitigations: mitigations,
                threatActors: actors,
                categories: ownCategories,
                severities: ownSeverities,
                strides: ownStrides,
                overrides: overrides,
                classifications: source.classifications.isEmpty
                    ? nil
                    : ClassificationScheme(
                        levels: source.classifications.map {
                            Classification(id: $0.id, label: $0.label, colour: $0.colour)
                        },
                        libraryLabel: source.displayName ?? source.label
                    )
            ),
            []
        )
    }

    /// A tier id, or a whole number, or nil for neither.
    private static func likelihood(from raw: String) -> Likelihood? {
        if let tier = Likelihood(rawValue: raw) { return tier }
        guard let prior = Int(raw) else { return nil }
        return Likelihood(prior: prior)
    }
}
