/// Reading and writing one `likelihood` block of a system's `.controls`
/// file.
///
/// The window's likelihood sheet writes through this, the way the severity
/// decision sheet writes through `WriteSeverityDecision`. Each reads the
/// file, changes one block and writes every other block back unchanged,
/// because a person recording one finding decides nothing about the rest.
///
/// `SaveSystemAnswers` keeps every `likelihood` block a file already holds
/// as it stands. This writer is the one place that changes a `likelihood`
/// block, so the two never disagree about the same block.
public protocol WriteLikelihoodFindingUseCase {
    func execute(_ request: WriteLikelihoodFindingRequest) -> WriteLikelihoodFindingResponse
}

public struct WriteLikelihoodFindingRequest: Equatable, Sendable {
    public let root: String
    /// The system's own file name, which names the file to write.
    public let systemName: String
    /// The name the system states for itself, which a new file's header
    /// names. Nil writes the file name.
    public let systemDisplayName: String?
    /// The threat the finding names, the way the controls file states it.
    public let threatId: String
    /// `component`, `zone` or `flow`.
    public let sourceKind: String
    public let sourceId: String
    /// What the finding says.
    public let label: String
    /// A band the likelihood tiers hold. A finding states this
    /// or a prior, never both.
    public let tier: String?
    /// A percentage a person measured or estimated directly, 0 to 100.
    public let prior: Int?
    public let rationale: String
    public let sources: [String]

    public init(
        root: String,
        systemName: String,
        systemDisplayName: String? = nil,
        threatId: String,
        sourceKind: String,
        sourceId: String,
        label: String,
        tier: String? = nil,
        prior: Int? = nil,
        rationale: String,
        sources: [String] = []
    ) {
        self.root = root
        self.systemName = systemName
        self.systemDisplayName = systemDisplayName
        self.threatId = threatId
        self.sourceKind = sourceKind
        self.sourceId = sourceId
        self.label = label
        self.tier = tier
        self.prior = prior
        self.rationale = rationale
        self.sources = sources
    }
}

public enum WriteLikelihoodFindingResponse: Equatable, Sendable {
    case written(path: String)
    case noSuchSystem
    /// Why the block is not one the application would apply.
    case refused(reason: String)
    case cannotWrite(reason: String)

    public func describe(into message: inout String?) {
        switch self {
        case .written:
            message = nil
        case .noSuchSystem:
            message = "This project no longer holds that system."
        case .refused(let reason):
            message = "That finding was not written: \(reason)."
        case .cannotWrite(let reason):
            message = "That finding could not be written: \(reason)"
        }
    }
}

public struct WriteLikelihoodFinding: WriteLikelihoodFindingUseCase {
    private let projects: ProjectSourceGateway
    private let sources: ControlsSourceGateway

    public init(projects: ProjectSourceGateway, sources: ControlsSourceGateway) {
        self.projects = projects
        self.sources = sources
    }

    public func execute(_ request: WriteLikelihoodFindingRequest) -> WriteLikelihoodFindingResponse {
        let label = request.label.trimmingWhitespace()
        let rationale = request.rationale.trimmingWhitespace()
        let tier = request.tier?.trimmingWhitespace()
        let named = tier?.isEmpty == false ? tier : nil

        guard label.isEmpty == false else {
            return .refused(reason: "a likelihood finding needs to say what it found")
        }
        guard rationale.isEmpty == false else {
            return .refused(reason: "a likelihood finding needs a rationale")
        }

        let likelihood: Likelihood
        switch (named, request.prior) {
        case (.some, .some):
            return .refused(reason: "a finding states a tier or a prior; it states one")
        case (nil, nil):
            return .refused(reason: "a finding states a tier or a prior")
        case (.some(let raw), nil):
            guard let tier = Likelihood(rawValue: raw) else {
                return .refused(
                    reason: "this application holds \(Likelihood.quotedTierWords)"
                )
            }
            likelihood = tier
        case (nil, .some(let prior)):
            guard let measured = Likelihood(prior: prior) else {
                return .refused(reason: "a prior runs from 0 to 100")
            }
            likelihood = measured
        }

        let held: ControlsFile.Held
        switch ControlsFile.read(
            root: request.root,
            systemName: request.systemName,
            named: request.systemDisplayName,
            key: ThreatKey(
                threatId: request.threatId,
                sourceId: "\(SourceThreatAnswer.resolverKind(request.sourceKind)):\(request.sourceId)"
            ),
            projects: projects,
            sources: sources
        ) {
        case .held(let found):
            held = found
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        let finding = LikelihoodFinding(
            label: label,
            likelihood: likelihood,
            rationale: rationale,
            sources: request.sources.filter { $0.trimmingWhitespace().isEmpty == false }
        )

        var answers = held.source.answers
        if let already = held.answerIndex {
            answers[already] = ControlsFile.changing(answers[already], likelihoodTo: finding)
        } else {
            // The compile writes a block for every threat the architecture
            // raises. A file without one is behind it; the finding still
            // lands, and the next compile fills the rest in.
            answers.append(
                SourceThreatAnswer(
                    threatId: request.threatId,
                    sourceKind: request.sourceKind,
                    sourceId: request.sourceId,
                    likelihood: finding
                )
            )
        }

        do {
            try projects.write(
                sources.write(ControlsFile.replacing(answers: answers, in: held.source)),
                to: held.path
            )
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        return .written(path: held.path)
    }
}
