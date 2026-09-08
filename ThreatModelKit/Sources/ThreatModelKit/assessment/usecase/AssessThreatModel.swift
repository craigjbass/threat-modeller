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

    /// The label the user reads on the threat row.
    public var displayName: String {
        switch self {
        case .component(_, let name, _):
            name
        case .connection(_, let sourceName, let targetName):
            "\(sourceName) \u{2192} \(targetName)"
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
        context: String?
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
    }
}

public struct AssessThreatModel: AssessThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: AssessThreatModelRequest) -> AssessThreatModelResponse {
        var assessed: [AssessedThreat] = []

        for component in models.current().components {
            guard component.threatsDisabled == false else { continue }
            guard let technology = catalogue.findById(component.technologyId) else { continue }

            for threat in catalogue.threatsFor(technologyId: component.technologyId) {
                let score = RiskScore(severity: threat.severity, sensitivity: component.sensitivity)
                guard score.value > 0 else { continue }

                assessed.append(
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
                        context: technology.threatContext[threat.id]
                    )
                )
            }
        }

        return AssessThreatModelResponse(threats: assessed.sorted(by: Self.ordering))
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
