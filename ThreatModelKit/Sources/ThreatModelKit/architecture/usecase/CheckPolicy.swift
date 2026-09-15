public protocol CheckPolicyUseCase {
    func execute(_ request: CheckPolicyRequest) -> CheckPolicyResponse
}

public struct CheckPolicyRequest: Equatable, Sendable {
    /// The rules the project states, or nil when it holds no policy file.
    public let policyText: String?
    /// The answers the controls compile wrote.
    public let controlsText: String
    /// The governance beside them, or nil.
    public let governanceText: String?
    /// The architecture, for the rules about zones, assumptions and the owner.
    public let architectureText: String
    /// The threats the model raises, with the score each one had before its
    /// controls, so a rule can read a level the controls have not lowered.
    public let threats: [PolicyThreat]

    public init(
        policyText: String?,
        controlsText: String,
        governanceText: String? = nil,
        architectureText: String,
        threats: [PolicyThreat] = []
    ) {
        self.policyText = policyText
        self.controlsText = controlsText
        self.governanceText = governanceText
        self.architectureText = architectureText
        self.threats = threats
    }
}

/// One threat, as a policy rule reads it.
public struct PolicyThreat: Equatable, Sendable {
    public let key: ThreatKey
    public let threatId: String
    public let sourceKind: String
    public let sourceId: String
    public let riskLevel: RiskLevel
    /// The level before the controls lowered the score.
    public let levelBeforeControls: RiskLevel

    public init(
        key: ThreatKey,
        threatId: String,
        sourceKind: String,
        sourceId: String,
        riskLevel: RiskLevel,
        levelBeforeControls: RiskLevel
    ) {
        self.key = key
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
        self.riskLevel = riskLevel
        self.levelBeforeControls = levelBeforeControls
    }
}

/// One rule and whether this system keeps it.
public struct PolicyRuleResult: Equatable, Sendable {
    public let name: String
    public let asks: String
    public let breaches: [String]

    public init(name: String, asks: String, breaches: [String]) {
        self.name = name
        self.asks = asks
        self.breaches = breaches
    }

    public var holds: Bool { breaches.isEmpty }
}

public enum CheckPolicyResponse: Equatable, Sendable {
    /// Every rule in force, and what breached it. Empty for a project with no
    /// policy file.
    case checked(rules: [PolicyRuleResult])
    case refused(diagnostics: [Diagnostic])
}

/// Evaluates the rules a project states for itself.
///
/// One function per rule, and each one names the rule first in the line it
/// prints, because a person reading a build log is looking for which rule they
/// broke.
public struct CheckPolicy: CheckPolicyUseCase {
    private let policies: PolicySourceGateway
    private let controlsSources: ControlsSourceGateway
    private let governanceSources: GovernanceSourceGateway
    private let architectureSources: ArchitectureSourceGateway

    public init(
        policies: PolicySourceGateway,
        controlsSources: ControlsSourceGateway,
        governanceSources: GovernanceSourceGateway,
        architectureSources: ArchitectureSourceGateway
    ) {
        self.policies = policies
        self.controlsSources = controlsSources
        self.governanceSources = governanceSources
        self.architectureSources = architectureSources
    }

    public func execute(_ request: CheckPolicyRequest) -> CheckPolicyResponse {
        guard let policyText = request.policyText, policyText.isEmpty == false else {
            return .checked(rules: [])
        }
        let read = policies.read(policyText)
        guard let policy = read.source, read.hasErrors == false else {
            return .refused(diagnostics: read.diagnostics)
        }

        let answersRead = controlsSources.read(request.controlsText)
        guard let answers = answersRead.source, answersRead.hasErrors == false else {
            return .refused(diagnostics: answersRead.diagnostics)
        }

        var governance: GovernanceSource?
        if let governanceText = request.governanceText, governanceText.isEmpty == false {
            let read = governanceSources.read(governanceText)
            guard let source = read.source, read.hasErrors == false else {
                return .refused(diagnostics: read.diagnostics)
            }
            governance = source
        }

        let architectureRead = architectureSources.read(request.architectureText)
        guard let architecture = architectureRead.source, architectureRead.hasErrors == false else {
            return .refused(diagnostics: architectureRead.diagnostics)
        }

        let reading = PolicyRules.Reading(
            threats: Self.threats(answers: answers, threats: request.threats),
            elements: Self.elements(architecture),
            acceptedRisks: Self.acceptedRisks(governance),
            assumptions: architecture.assumptions.map { ($0.label, $0.owner ?? "") },
            systemOwner: architecture.owner ?? ""
        )

        return .checked(rules: PolicyRules.evaluate(policy, reading: reading))
    }

    /// The threats a rule reads, from the compiled answers.
    static func threats(
        answers: ControlsSource,
        threats: [PolicyThreat]
    ) -> [PolicyRules.Threat] {
        let tolerance = answers.riskTolerance.flatMap(RiskLevel.init(rawValue:)) ?? .low

        return threats.map { threat in
            let answer = answers.answer(for: threat.key)
            return PolicyRules.Threat(
                key: threat.key,
                threatId: threat.threatId,
                sourceKind: threat.sourceKind,
                sourceId: threat.sourceId,
                riskLevel: threat.riskLevel,
                levelBeforeControls: threat.levelBeforeControls,
                isAnswered: answer?.isAnswered(within: tolerance) ?? false,
                unevidencedControls: (answer?.controls ?? [])
                    .filter { $0.status == .implemented && $0.proof.evidence == nil }
                    .map(\.description),
                acceptedControls: (answer?.controls ?? [])
                    .filter { $0.status == .accepted }
                    .map(\.description)
            )
        }
    }

    /// Every component the file declares, and the zone it sits in.
    static func elements(_ architecture: ArchitectureSource) -> [PolicyRules.Element] {
        var elements: [PolicyRules.Element] = []
        for zone in architecture.zones {
            for component in zone.components {
                elements.append(
                    PolicyRules.Element(
                        id: component.id,
                        sensitivity: DataSensitivity(component.data ?? "internal"),
                        zone: NetworkZone(rawValue: zone.kind)
                    )
                )
            }
        }
        for component in architecture.components {
            elements.append(
                PolicyRules.Element(
                    id: component.id,
                    sensitivity: DataSensitivity(component.data ?? "internal"),
                    zone: nil
                )
            )
        }
        return elements
    }

    /// What the governance file states, as the rules read it.
    static func acceptedRisks(_ governance: GovernanceSource?) -> [ThreatKey: [RiskAcceptance]] {
        var risks: [ThreatKey: [RiskAcceptance]] = [:]
        for threat in governance?.threats ?? [] where threat.isStale == false {
            risks[threat.key] = threat.accepted
                .filter { $0.isStale == false }
                .map {
                    RiskAcceptance(
                        control: $0.control,
                        owner: $0.owner,
                        acceptedOn: $0.acceptedOn.flatMap { try? GovernanceDate.read($0).get() },
                        reviewBy: $0.reviewBy.flatMap { try? GovernanceDate.read($0).get() },
                        rationale: $0.rationale,
                        sources: $0.sources
                    )
                }
        }
        return risks
    }
}
