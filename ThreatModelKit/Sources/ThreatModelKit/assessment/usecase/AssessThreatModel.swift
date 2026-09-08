public protocol AssessThreatModelUseCase {
    func execute(_ request: AssessThreatModelRequest) -> AssessThreatModelResponse
}

public struct AssessThreatModelRequest: Equatable, Sendable {
    public init() {}
}

public struct AssessThreatModelResponse: Equatable, Sendable {
    public let threats: [AssessedThreat]

    public init(threats: [AssessedThreat]) {
        self.threats = threats
    }
}

public struct AssessedMitreTechnique: Hashable, Sendable {
    public let id: String
    public let name: String
    public let tactic: String

    public init(id: String, name: String, tactic: String) {
        self.id = id
        self.name = name
        self.tactic = tactic
    }
}

public struct AssessedControl: Hashable, Sendable {
    public let description: String
    /// True when the control came from the technology rather than the threat.
    public let isTechnologySpecific: Bool

    public init(description: String, isTechnologySpecific: Bool) {
        self.description = description
        self.isTechnologySpecific = isTechnologySpecific
    }
}

/// What raised a threat.
///
/// Milestone 3 adds a `zone` case. Every call site handles the cases
/// exhaustively, so a new case is a compile error rather than a silent gap.
public enum AssessedThreatSource: Hashable, Sendable {
    case component(id: String, name: String, providerId: String)
    case connection(id: String, sourceName: String, targetName: String)
    case zone(id: String, name: String)

    /// The label the user reads on the threat row.
    public var displayName: String {
        switch self {
        case .component(_, let name, _):
            name
        case .connection(_, let sourceName, let targetName):
            "\(sourceName) \u{2192} \(targetName)"
        case .zone(_, let name):
            name
        }
    }

    /// Identifies the source across kinds. Two sources of different kinds never
    /// share one. Used to order rows and to raise a duplicate pair once.
    public var id: String {
        switch self {
        case .component(let id, _, _):
            "component:\(id)"
        case .connection(let id, _, _):
            "connection:\(id)"
        case .zone(let id, _):
            "zone:\(id)"
        }
    }
}

public struct AssessedThreat: Hashable, Sendable {
    public let threatId: String
    public let name: String
    public let description: String
    public let severityId: String
    public let severityLabel: String
    public let stride: [String]
    public let mitreTechniques: [AssessedMitreTechnique]
    public let controls: [AssessedControl]
    public let source: AssessedThreatSource
    public let sensitivityId: String
    public let riskScore: Int
    public let riskLevel: String
    public let context: String?
    /// True when the threat is one TLS mitigates and an endpoint technology
    /// enforces encryption. Display only. It never changes `riskScore`.
    public let isTlsMitigated: Bool

    public init(
        threatId: String,
        name: String,
        description: String,
        severityId: String,
        severityLabel: String,
        stride: [String],
        mitreTechniques: [AssessedMitreTechnique],
        controls: [AssessedControl],
        source: AssessedThreatSource,
        sensitivityId: String,
        riskScore: Int,
        riskLevel: String,
        context: String?,
        isTlsMitigated: Bool
    ) {
        self.threatId = threatId
        self.name = name
        self.description = description
        self.severityId = severityId
        self.severityLabel = severityLabel
        self.stride = stride
        self.mitreTechniques = mitreTechniques
        self.controls = controls
        self.source = source
        self.sensitivityId = sensitivityId
        self.riskScore = riskScore
        self.riskLevel = riskLevel
        self.context = context
        self.isTlsMitigated = isTlsMitigated
    }
}

/// Resolves every threat the model raises, and scores each one.
///
/// Component threats come from the component's technology. Connection threats
/// come from the catalogue and belong to the link, not to either end. Zone
/// threats and the zone multiplier arrive in Milestone 3; every score here is
/// the base score.
public struct AssessThreatModel: AssessThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: AssessThreatModelRequest) -> AssessThreatModelResponse {
        let model = models.current()
        var assessed: [AssessedThreat] = []
        // Spec section 5.3: a duplicate threat and source pair is raised once.
        var raised: Set<String> = []

        func raise(_ threat: AssessedThreat) {
            let pair = "\(threat.threatId)@\(threat.source.id)"
            guard raised.contains(pair) == false else { return }
            raised.insert(pair)
            assessed.append(threat)
        }

        // Derived, never stored. Spec section 5.2.
        var zonesByComponent: [ComponentId: Zone] = [:]
        for component in model.components {
            zonesByComponent[component.id] = ZoneContainment.zone(
                holding: component.centre,
                in: model.zones
            )
        }

        for component in model.components {
            guard component.threatsDisabled == false else { continue }
            guard let technology = catalogue.findById(component.technologyId) else { continue }

            let multiplier = ZoneMultiplier.value(for: zonesByComponent[component.id])

            for threat in catalogue.threatsFor(technologyId: component.technologyId) {
                let base = RiskScore(severity: threat.severity, sensitivity: component.sensitivity)
                let score = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard score.value > 0 else { continue }

                raise(
                    AssessedThreat(
                        threatId: threat.id.value,
                        name: threat.name,
                        description: threat.description,
                        severityId: threat.severity.id,
                        severityLabel: threat.severity.label,
                        stride: threat.stride.map(\.value),
                        mitreTechniques: threat.mitreTechniques.map {
                            AssessedMitreTechnique(id: $0.id, name: $0.name, tactic: $0.tactic)
                        },
                        controls: Self.controls(for: threat, on: technology),
                        source: .component(
                            id: component.id.value,
                            name: component.customName ?? technology.name,
                            providerId: technology.provider.value
                        ),
                        sensitivityId: component.sensitivity.rawValue,
                        riskScore: score.value,
                        riskLevel: score.level.rawValue,
                        context: technology.threatContext[threat.id],
                        isTlsMitigated: false
                    )
                )
            }
        }

        for connection in model.connections {
            guard let source = model.component(connection.source),
                  let target = model.component(connection.target) else { continue }
            guard source.threatsDisabled == false, target.threatsDisabled == false else { continue }

            let sourceTechnology = catalogue.findById(source.technologyId)
            let targetTechnology = catalogue.findById(target.technologyId)
            let sensitivity = SensitivityLadder.higher(source.sensitivity, target.sensitivity)
            let multiplier = ZoneMultiplier.valueForConnection(
                sourceZone: zonesByComponent[source.id],
                targetZone: zonesByComponent[target.id]
            )

            for threat in catalogue.connectionThreats() {
                let base = RiskScore(severity: threat.severity, sensitivity: sensitivity)
                let score = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard score.value > 0 else { continue }

                raise(
                    AssessedThreat(
                        threatId: threat.id.value,
                        name: threat.name,
                        description: threat.description,
                        severityId: threat.severity.id,
                        severityLabel: threat.severity.label,
                        stride: threat.stride.map(\.value),
                        mitreTechniques: threat.mitreTechniques.map {
                            AssessedMitreTechnique(id: $0.id, name: $0.name, tactic: $0.tactic)
                        },
                        // Spec section 5.3: a link always uses the threat's own
                        // controls, never a technology's mitigations.
                        controls: threat.controls.map {
                            AssessedControl(description: $0.description, isTechnologySpecific: false)
                        },
                        source: .connection(
                            id: connection.id.value,
                            sourceName: Self.name(of: source, as: sourceTechnology),
                            targetName: Self.name(of: target, as: targetTechnology)
                        ),
                        sensitivityId: sensitivity.rawValue,
                        riskScore: score.value,
                        riskLevel: score.level.rawValue,
                        context: nil,
                        isTlsMitigated: ConnectionEncryption.isTlsMitigated(
                            threat: threat,
                            source: sourceTechnology,
                            target: targetTechnology
                        )
                    )
                )
            }
        }

        // Spec section 5.3: raised once per private zone, scored against a
        // fixed internal sensitivity, and reduced by that zone's own
        // multiplier. A public zone raises none.
        for zone in model.zones where zone.networkZone == .privateZone {
            let multiplier = ZoneMultiplier.value(for: zone)

            for threat in catalogue.zoneThreats() {
                let base = RiskScore(severity: threat.severity, sensitivity: .internalData)
                let score = RiskScore(value: ZoneMultiplier.apply(multiplier, to: base.value))
                guard score.value > 0 else { continue }

                raise(
                    AssessedThreat(
                        threatId: threat.id.value,
                        name: threat.name,
                        description: threat.description,
                        severityId: threat.severity.id,
                        severityLabel: threat.severity.label,
                        stride: threat.stride.map(\.value),
                        mitreTechniques: threat.mitreTechniques.map {
                            AssessedMitreTechnique(id: $0.id, name: $0.name, tactic: $0.tactic)
                        },
                        // Spec section 5.3: a zone always uses the threat's own
                        // controls, never a technology's mitigations.
                        controls: threat.controls.map {
                            AssessedControl(description: $0.description, isTechnologySpecific: false)
                        },
                        source: .zone(id: zone.id.value, name: zone.displayName),
                        sensitivityId: DataSensitivity.internalData.rawValue,
                        riskScore: score.value,
                        riskLevel: score.level.rawValue,
                        context: threat.zoneContext,
                        isTlsMitigated: false
                    )
                )
            }
        }

        return AssessThreatModelResponse(threats: assessed.sorted(by: Self.ordering))
    }

    /// A link still raises its threats when an end's technology has left the
    /// catalogue: the threats belong to the link, and the sensitivity is stored
    /// on the component. The technology id stands in for the missing name.
    private static func name(of component: Component, as technology: Technology?) -> String {
        component.customName ?? technology?.name ?? component.technologyId.value
    }

    private static func controls(for threat: Threat, on technology: Technology) -> [AssessedControl] {
        if let specific = technology.threatMitigations[threat.id], specific.isEmpty == false {
            return specific.map { AssessedControl(description: $0, isTechnologySpecific: true) }
        }
        return threat.controls.map {
            AssessedControl(description: $0.description, isTechnologySpecific: false)
        }
    }

    private static func ordering(_ a: AssessedThreat, _ b: AssessedThreat) -> Bool {
        if a.riskScore != b.riskScore { return a.riskScore > b.riskScore }
        if a.threatId != b.threatId { return a.threatId < b.threatId }
        return a.source.id < b.source.id
    }
}
