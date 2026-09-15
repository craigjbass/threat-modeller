public protocol SetExclusionUseCase {
    func execute(_ request: SetExclusionRequest) -> SetExclusionResponse
}

public struct SetExclusionRequest: Equatable, Sendable {
    /// Names the exclusion. Writing the same label again changes the one that
    /// is there.
    public let label: String
    public let text: String
    public let rationale: String

    public init(label: String, text: String, rationale: String) {
        self.label = label
        self.text = text
        self.rationale = rationale
    }
}

public enum SetExclusionResponse: Equatable, Sendable {
    case recorded
    case noLabel
    case noText
    case noRationale

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .noLabel: message = "An exclusion needs a label."
        case .noText: message = "An exclusion needs to say what the model does not cover."
        case .noRationale:
            message = "An exclusion needs a reason. An exclusion with no reason is a gap."
        }
    }
}

/// Writes down what this model does not cover, and why it does not.
///
/// Language guide section 4.2. A rationale is required: a reader cannot tell a
/// decision from an oversight when an exclusion states no reason.
public struct SetExclusion: SetExclusionUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetExclusionRequest) -> SetExclusionResponse {
        let label = request.label.trimmingWhitespace()
        let text = request.text.trimmingWhitespace()
        let rationale = request.rationale.trimmingWhitespace()

        guard label.isEmpty == false else { return .noLabel }
        guard text.isEmpty == false else { return .noText }
        guard rationale.isEmpty == false else { return .noRationale }

        return models.mutate(label: ChangeLabel.setExclusion) { model in
            let written = SystemExclusion(label: label, text: text, rationale: rationale)
            if let already = model.exclusions.firstIndex(where: { $0.label == label }) {
                model.exclusions[already] = written
            } else {
                model.exclusions.append(written)
            }
            return .recorded
        }
    }
}

public protocol RemoveExclusionUseCase {
    func execute(_ request: RemoveExclusionRequest) -> RemoveExclusionResponse
}

public struct RemoveExclusionRequest: Equatable, Sendable {
    public let label: String

    public init(label: String) {
        self.label = label
    }
}

public enum RemoveExclusionResponse: Equatable, Sendable {
    case removed
    case noSuchExclusion

    public func describe(into message: inout String?) {
        switch self {
        case .removed: message = nil
        case .noSuchExclusion: message = "This system holds no such exclusion."
        }
    }
}

/// Takes an exclusion off the system.
public struct RemoveExclusion: RemoveExclusionUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveExclusionRequest) -> RemoveExclusionResponse {
        let label = request.label.trimmingWhitespace()

        return models.mutate(label: ChangeLabel.removeExclusion) { model in
            guard let found = model.exclusions.firstIndex(where: { $0.label == label }) else {
                return .noSuchExclusion
            }
            model.exclusions.remove(at: found)
            return .removed
        }
    }
}
