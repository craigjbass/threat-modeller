public protocol AssessThreatModelUseCase {
    func execute(_ request: AssessThreatModelRequest) -> AssessThreatModelResponse
}

public struct AssessThreatModelRequest: Equatable, Sendable {
    public init() {}
}

/// A severity the user can override a threat to. In taxonomy order, weakest
/// first, which is the order the ranks run in.
public struct AssessedSeverity: Equatable, Sendable {
    public let id: String
    public let label: String

    public init(id: String, label: String) {
        self.id = id
        self.label = label
    }
}

public struct AssessThreatModelResponse: Equatable, Sendable {
    public let threats: [AssessedThreat]
    /// Every severity the override menu offers, in taxonomy order.
    public let severities: [AssessedSeverity]
    /// What each `mitigates` edge rests on. Empty when the model draws none.
    public let protectionDependencies: [ProtectionDependency]
    /// What a reader must know before they trust a reduction.
    public let warnings: [String]

    public init(
        threats: [AssessedThreat],
        severities: [AssessedSeverity] = [],
        protectionDependencies: [ProtectionDependency] = [],
        warnings: [String] = []
    ) {
        self.threats = threats
        self.severities = severities
        self.protectionDependencies = protectionDependencies
        self.warnings = warnings
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
    /// What the user said about it: implemented, not_implemented,
    /// not_applicable or accepted.
    public let statusId: String
    public let statusLabel: String
    /// The key `RecordControlImplemented` takes. Minted by the core.
    public let key: String
    public let isImplemented: Bool

    public init(
        description: String,
        isTechnologySpecific: Bool,
        key: String,
        isImplemented: Bool,
        statusId: String? = nil,
        statusLabel: String? = nil
    ) {
        self.description = description
        self.isTechnologySpecific = isTechnologySpecific
        self.key = key
        self.isImplemented = isImplemented
        let status = statusId.flatMap(ControlStatus.init(rawValue:))
            ?? (isImplemented ? ControlStatus.implemented : .notImplemented)
        self.statusId = status.rawValue
        self.statusLabel = statusLabel ?? status.label
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
    /// The key `OverrideThreatSeverity` takes. Minted by the core.
    public let overrideKey: String
    /// The severity id the user overrode this threat to, or nil.
    public let overriddenSeverityId: String?
    /// The pathway mitigations that answered this threat, by label. Empty when
    /// none did.
    public let pathwayMitigationLabels: [String]
    /// The score before any pathway mitigation. Equal to `riskScore` when none
    /// applied, so a card can show what the mitigation bought.
    public let scoreBeforePathwayMitigation: Int
    /// What compensates this threat, from the controls file, by label.
    public let compensatingLabels: [String]
    /// The score before the compensating control. Equal to `riskScore` when
    /// none applied.
    public let scoreBeforeCompensation: Int
    /// The score before the implemented controls lowered it. Equal to
    /// `riskScore` when nothing was implemented.
    public let inherentScore: Int
    /// The components whose `mitigates` edges lowered this threat, by label.
    /// Empty when none did.
    public let mitigatedByComponentLabels: [String]
    /// The likelihood tier the score used, and what a reader sees.
    public let likelihoodId: String
    public let likelihoodLabel: String
    /// The score before the likelihood stage. Equal to `riskScore` when the
    /// likelihood is `commodity`.
    public let scoreBeforeLikelihood: Int
    /// Why the likelihood is what it is, from the controls file, or nil when
    /// the library's prior stands.
    public let likelihoodRationale: String?
    /// Where the likelihood finding comes from. Empty when the library's
    /// prior stands.
    public let likelihoodSources: [String]

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
        isTlsMitigated: Bool,
        overrideKey: String,
        overriddenSeverityId: String?,
        pathwayMitigationLabels: [String] = [],
        scoreBeforePathwayMitigation: Int = 0,
        compensatingLabels: [String] = [],
        scoreBeforeCompensation: Int? = nil,
        inherentScore: Int? = nil,
        mitigatedByComponentLabels: [String] = [],
        likelihoodId: String = Likelihood.commodity.id,
        likelihoodLabel: String = Likelihood.commodity.label,
        scoreBeforeLikelihood: Int? = nil,
        likelihoodRationale: String? = nil,
        likelihoodSources: [String] = []
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
        self.overrideKey = overrideKey
        self.overriddenSeverityId = overriddenSeverityId
        self.pathwayMitigationLabels = pathwayMitigationLabels
        self.scoreBeforePathwayMitigation = scoreBeforePathwayMitigation
        self.compensatingLabels = compensatingLabels
        self.scoreBeforeCompensation = scoreBeforeCompensation ?? riskScore
        self.inherentScore = inherentScore ?? riskScore
        self.mitigatedByComponentLabels = mitigatedByComponentLabels
        self.likelihoodId = likelihoodId
        self.likelihoodLabel = likelihoodLabel
        self.scoreBeforeLikelihood = scoreBeforeLikelihood ?? riskScore
        self.likelihoodRationale = likelihoodRationale
        self.likelihoodSources = likelihoodSources
    }
}

/// Resolves every threat the model raises, and scores each one.
///
/// Component threats come from the component's technology. Connection threats
/// come from the catalogue and belong to the link, not to either end. Zone
/// threats and the zone multiplier arrive in Milestone 3; every score here is
/// the base score.
/// Lists every threat the model raises, as plain values.
public struct AssessThreatModel: AssessThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: AssessThreatModelRequest) -> AssessThreatModelResponse {
        let model = models.current()
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        let resolved = ThreatResolver(model: model, catalogue: catalogue).resolve()
        let nameOf: (ComponentId) -> String = { id in
            guard let component = model.components.first(where: { $0.id == id }) else {
                return id.value
            }
            return component.customName
                ?? lookup.findById(component.technologyId)?.name
                ?? component.technologyId.value
        }
        let dependencies = ProtectionDependencies.derive(
            from: resolved,
            edges: model.mitigatesEdges,
            nameOf: nameOf
        )

        return AssessThreatModelResponse(
            threats: resolved.map { threat in
                AssessedThreat(
                    threatId: threat.threat.id.value,
                    name: threat.threat.name,
                    description: threat.threat.description,
                    severityId: threat.severity.id,
                    severityLabel: threat.severity.label,
                    stride: threat.threat.stride.map(\.value),
                    mitreTechniques: threat.threat.mitreTechniques.map {
                        AssessedMitreTechnique(id: $0.id, name: $0.name, tactic: $0.tactic)
                    },
                    controls: threat.controls.map {
                        AssessedControl(
                            description: $0.description,
                            isTechnologySpecific: $0.isTechnologySpecific,
                            key: $0.key.value,
                            isImplemented: $0.isImplemented,
                            statusId: $0.status.rawValue
                        )
                    },
                    source: Self.source(threat.source),
                    sensitivityId: threat.sensitivity.rawValue,
                    riskScore: threat.score.value,
                    riskLevel: threat.score.level.rawValue,
                    context: threat.context,
                    isTlsMitigated: threat.isTlsMitigated,
                    overrideKey: threat.overrideKey.value,
                    overriddenSeverityId: threat.overriddenSeverityId,
                    pathwayMitigationLabels: threat.mitigatedBy.map(\.label),
                    scoreBeforePathwayMitigation: threat.scoreBeforePathwayMitigation,
                    compensatingLabels: threat.compensating.map(\.label),
                    scoreBeforeCompensation: threat.scoreBeforeCompensation,
                    inherentScore: threat.scoreBeforeControls,
                    mitigatedByComponentLabels: threat.mitigatedByComponents.map(\.protectorName),
                    likelihoodId: threat.likelihood.id,
                    likelihoodLabel: threat.likelihood.label,
                    scoreBeforeLikelihood: threat.scoreBeforeLikelihood,
                    likelihoodRationale: threat.likelihoodFinding?.rationale,
                    likelihoodSources: threat.likelihoodFinding?.sources ?? []
                )
            },
            severities: catalogue.taxonomy().severities.map {
                AssessedSeverity(id: $0.id, label: $0.label)
            },
            protectionDependencies: dependencies,
            warnings: ProtectionDependencies.warnings(for: dependencies)
        )
    }

    private static func source(_ source: ResolvedSource) -> AssessedThreatSource {
        switch source {
        case .component(let id, let name, let providerId):
            .component(id: id.value, name: name, providerId: providerId.value)
        case .connection(let id, let sourceName, let targetName):
            .connection(id: id.value, sourceName: sourceName, targetName: targetName)
        case .zone(let id, let name):
            .zone(id: id.value, name: name)
        }
    }
}
