import Foundation

public protocol CheckControlAnswersUseCase {
    func execute(_ request: CheckControlAnswersRequest) -> CheckControlAnswersResponse
}

public struct CheckControlAnswersRequest: Equatable, Sendable {
    public let architectureText: String
    public let controlsText: String?
    /// The trees a person wrote, or nil when the project holds no such file.
    public let attackTreeText: String?
    /// Who carries each accepted risk, or nil when the project holds no such
    /// file.
    public let governanceText: String?
    /// The rules the project states for itself, or nil when it holds no
    /// policy file.
    public let policyText: String?
    /// A risk level that overrides what the architecture file states, or nil.
    public let tolerance: String?
    /// Every architecture file of a split system, and every controls file.
    public let architectureParts: [SourcePart]
    public let directoryName: String?
    public let controlsParts: [String: String]
    public let attackTreeTexts: [String]
    /// Where the architecture file is, so a warning about a component names
    /// the file it sits in. Empty when the caller does not say.
    public let architecturePath: String
    /// The facts about the CVEs the project names, or nil when it holds no
    /// lock file.
    public let vulnerabilityLockText: String?

    public init(
        architectureText: String,
        controlsText: String? = nil,
        attackTreeText: String? = nil,
        governanceText: String? = nil,
        policyText: String? = nil,
        tolerance: String? = nil,
        architectureParts: [SourcePart] = [],
        directoryName: String? = nil,
        controlsParts: [String: String] = [:],
        attackTreeTexts: [String] = [],
        architecturePath: String = "",
        vulnerabilityLockText: String? = nil
    ) {
        self.architecturePath = architecturePath
        self.vulnerabilityLockText = vulnerabilityLockText
        self.architectureParts = architectureParts
        self.directoryName = directoryName
        self.controlsParts = controlsParts
        self.attackTreeTexts = attackTreeTexts
        self.architectureText = architectureText
        self.controlsText = controlsText
        self.attackTreeText = attackTreeText
        self.governanceText = governanceText
        self.policyText = policyText
        self.tolerance = tolerance
    }
}

public struct UnansweredThreat: Equatable, Sendable {
    public let threatId: String
    public let sourceKind: String
    public let sourceId: String
    public let riskLevel: String

    public init(threatId: String, sourceKind: String, sourceId: String, riskLevel: String) {
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
        self.riskLevel = riskLevel
    }

    public var described: String {
        "\(threatId) on \(sourceKind) \"\(sourceId)\" (\(riskLevel)) has no answer"
    }
}

public enum CheckControlAnswersResponse: Equatable, Sendable {
    case checked(
        unanswered: [UnansweredThreat],
        stale: [String],
        staleTrees: [String],
        governance: [String],
        diagnostics: [Diagnostic],
        tolerance: String
    )
    case refused(diagnostics: [Diagnostic])

    public var isClean: Bool {
        guard case .checked(
            let unanswered,
            let stale,
            let staleTrees,
            let governance,
            _,
            _
        ) = self else {
            return false
        }
        return unanswered.isEmpty && stale.isEmpty && staleTrees.isEmpty && governance.isEmpty
    }
}

/// Says what a pull request has not answered.
///
/// The executable's exit code reads this and nothing else does.
public struct CheckControlAnswers: CheckControlAnswersUseCase {
    private let compiles: CompileControlsUseCase
    private let sources: ControlsSourceGateway
    private let governance: CheckGovernanceUseCase?
    private let policy: CheckPolicyUseCase?
    private let vulnerabilities: CheckVulnerabilitiesUseCase?

    public init(
        compiles: CompileControlsUseCase,
        sources: ControlsSourceGateway,
        governance: CheckGovernanceUseCase? = nil,
        policy: CheckPolicyUseCase? = nil,
        vulnerabilities: CheckVulnerabilitiesUseCase? = nil
    ) {
        self.compiles = compiles
        self.sources = sources
        self.governance = governance
        self.policy = policy
        self.vulnerabilities = vulnerabilities
    }

    public func execute(_ request: CheckControlAnswersRequest) -> CheckControlAnswersResponse {
        // Checking is compiling and reading the result, so the two can never
        // disagree about what a threat needs.
        let compiled = compiles.execute(
            CompileControlsRequest(
                architectureText: request.architectureText,
                controlsText: request.controlsText,
                attackTreeText: request.attackTreeText,
                architectureParts: request.architectureParts,
                directoryName: request.directoryName,
                controlsParts: request.controlsParts,
                attackTreeTexts: request.attackTreeTexts
            )
        )

        guard case .compiled(
            let text,
            _,
            _,
            _,
            _,
            let unevidenced,
            let compileWarnings
        ) = compiled else {
            guard case .refused(let diagnostics) = compiled else {
                return .refused(diagnostics: [])
            }
            return .refused(diagnostics: diagnostics)
        }

        let read = sources.read(text)
        guard let source = read.source else {
            return .refused(diagnostics: read.diagnostics)
        }

        let tolerance = request.tolerance.flatMap(RiskLevel.init(rawValue:))
            ?? source.riskTolerance.flatMap(RiskLevel.init(rawValue:))
            ?? .low

        var unanswered: [UnansweredThreat] = []
        var stale: [String] = []

        for answer in source.answers {
            if answer.isStale {
                stale.append(answer.key.value)
                continue
            }
            guard answer.isAnswered(within: tolerance) == false else { continue }
            unanswered.append(
                UnansweredThreat(
                    threatId: answer.threatId,
                    sourceKind: answer.sourceKind,
                    sourceId: answer.sourceId,
                    riskLevel: answer.severityLabel ?? "unknown"
                )
            )
        }

        // A tree whose goal or whose step no longer binds is work for a
        // person: the route it describes is a claim about a system that is no
        // longer there.
        let staleTrees = source.trees
            .filter(\.isStale)
            .map { StaleTree(treeId: $0.treeId, stepCount: $0.steps.count).described }

        // An accepted risk with no owner and no review date is not a
        // decision, so the same run that says what has no answer says what has
        // no owner.
        var governanceFailures: [String] = []
        if let governance {
            let checked = governance.execute(
                CheckGovernanceRequest(
                    controlsText: text,
                    governanceText: request.governanceText
                )
            )
            switch checked {
            case .checked(let failures):
                governanceFailures = failures
            case .refused(let diagnostics):
                return .refused(diagnostics: diagnostics)
            }
        }

        // The rules a project states for itself. A breach the governance
        // check already printed is not printed twice: the two rules that
        // restate it are dropped here.
        var policyBreaches: [String] = []
        if let policy {
            let checked = policy.execute(
                CheckPolicyRequest(
                    policyText: request.policyText,
                    controlsText: text,
                    governanceText: request.governanceText,
                    architectureText: request.architectureText,
                    threats: source.answers.compactMap(Self.policyThreat)
                )
            )
            switch checked {
            case .checked(let rules):
                for rule in rules {
                    let alreadyPrinted = governance != nil
                        && (rule.name == "accepted_requires_owner"
                            || rule.name == "accepted_requires_review_by")
                    guard alreadyPrinted == false else { continue }
                    policyBreaches += rule.breaches.map { "\(rule.name): \($0)" }
                }
            case .refused(let diagnostics):
                return .refused(diagnostics: diagnostics)
            }
        }

        // A CVE the lock file does not hold is a warning: a fact the model
        // does not yet hold, not a wrong answer.
        var unsynchronised: [Diagnostic] = []
        if let vulnerabilities {
            let parts = request.architectureParts.isEmpty
                ? [SourcePart(file: request.architecturePath, text: request.architectureText)]
                : request.architectureParts
            unsynchronised = vulnerabilities.execute(
                CheckVulnerabilitiesRequest(
                    parts: parts,
                    directoryName: request.directoryName,
                    lockText: request.vulnerabilityLockText
                )
            )
        }

        return .checked(
            unanswered: unanswered,
            stale: stale,
            staleTrees: staleTrees,
            governance: governanceFailures + unevidenced + policyBreaches,
            diagnostics: read.warnings + compileWarnings + unsynchronised,
            tolerance: tolerance.rawValue
        )
    }
    /// One compiled answer, as a policy rule reads it.
    ///
    /// The compiled file states the residual score. A rule that reads the
    /// level before the controls reads it from the same file, because a
    /// compile writes what a check reads and the two must never disagree.
    static func policyThreat(_ answer: SourceThreatAnswer) -> PolicyThreat? {
        let level = answer.score.map { RiskScore(value: $0).level } ?? .low
        return PolicyThreat(
            key: answer.key,
            threatId: answer.threatId,
            sourceKind: answer.sourceKind,
            sourceId: answer.sourceId,
            riskLevel: level,
            levelBeforeControls: level
        )
    }

}
