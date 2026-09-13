public protocol SetLikelihoodFindingUseCase {
    func execute(_ request: SetLikelihoodFindingRequest) -> SetLikelihoodFindingResponse
}

public struct SetLikelihoodFindingRequest: Equatable, Sendable {
    public let threatKey: String
    /// What the finding says.
    public let label: String
    /// A band: `commodity`, `targeted` or `research`. A finding states this or
    /// a prior, never both.
    public let tier: String?
    /// A percentage a person measured or estimated directly, 0 to 100.
    public let prior: Int?
    public let rationale: String
    public let sources: [String]

    public init(
        threatKey: String,
        label: String,
        tier: String? = nil,
        prior: Int? = nil,
        rationale: String,
        sources: [String] = []
    ) {
        self.threatKey = threatKey
        self.label = label
        self.tier = tier
        self.prior = prior
        self.rationale = rationale
        self.sources = sources
    }
}

public enum SetLikelihoodFindingResponse: Equatable, Sendable {
    case recorded
    case noLabel
    case noRationale
    case statesBoth
    case statesNeither
    case unknownTier
    case priorOutOfRange

    public func describe(into message: inout String?) {
        switch self {
        case .recorded:
            message = nil
        case .noLabel:
            message = "A likelihood finding needs to say what it found."
        case .noRationale:
            message = "A likelihood finding needs a rationale."
        case .statesBoth:
            message = "A finding states a tier or a prior; it states one."
        case .statesNeither:
            message = "A finding states a tier or a prior."
        case .unknownTier:
            message = "This application holds \"commodity\", \"targeted\" and \"research\"."
        case .priorOutOfRange:
            message = "A prior runs from 0 to 100."
        }
    }
}

/// Records what a person learned about how often an attack of this kind
/// happens, and why.
///
/// Language guide section 5.7. It is evidence, not a control: it multiplies
/// the score rather than answering the threat outright. A threat holds one
/// finding, so writing a second changes the first.
///
/// A finding nobody can justify is not one, which is why a rationale is
/// required.
public struct SetLikelihoodFinding: SetLikelihoodFindingUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetLikelihoodFindingRequest) -> SetLikelihoodFindingResponse {
        let label = request.label.trimmingWhitespace()
        let rationale = request.rationale.trimmingWhitespace()
        let tier = request.tier?.trimmingWhitespace()
        let named = tier?.isEmpty == false ? tier : nil

        guard label.isEmpty == false else { return .noLabel }
        guard rationale.isEmpty == false else { return .noRationale }

        let likelihood: Likelihood
        switch (named, request.prior) {
        case (.some, .some):
            return .statesBoth
        case (nil, nil):
            return .statesNeither
        case (.some(let raw), nil):
            guard let tier = Likelihood(rawValue: raw) else { return .unknownTier }
            likelihood = tier
        case (nil, .some(let prior)):
            guard let measured = Likelihood(prior: prior) else { return .priorOutOfRange }
            likelihood = measured
        }

        return models.mutate { model in
            model.likelihoodFindings[ThreatKey(request.threatKey)] = LikelihoodFinding(
                label: label,
                likelihood: likelihood,
                rationale: rationale,
                sources: request.sources.filter { $0.trimmingWhitespace().isEmpty == false }
            )
            return .recorded
        }
    }
}

public protocol RemoveLikelihoodFindingUseCase {
    func execute(_ request: RemoveLikelihoodFindingRequest) -> RemoveLikelihoodFindingResponse
}

public struct RemoveLikelihoodFindingRequest: Equatable, Sendable {
    public let threatKey: String

    public init(threatKey: String) {
        self.threatKey = threatKey
    }
}

public enum RemoveLikelihoodFindingResponse: Equatable, Sendable {
    case removed
    case noSuchFinding

    public func describe(into message: inout String?) {
        switch self {
        case .removed: message = nil
        case .noSuchFinding: message = "This threat holds no likelihood finding."
        }
    }
}

public struct RemoveLikelihoodFinding: RemoveLikelihoodFindingUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveLikelihoodFindingRequest) -> RemoveLikelihoodFindingResponse {
        let key = ThreatKey(request.threatKey)

        return models.mutate { model in
            guard model.likelihoodFindings[key] != nil else { return .noSuchFinding }
            model.likelihoodFindings[key] = nil
            return .removed
        }
    }
}
