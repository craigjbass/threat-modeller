public protocol SetAssumptionUseCase {
    func execute(_ request: SetAssumptionRequest) -> SetAssumptionResponse
}

public struct SetAssumptionRequest: Equatable, Sendable {
    /// Names the assumption. Writing the same label again changes the one
    /// that is there.
    public let label: String
    public let text: String
    public let owner: String?

    public init(label: String, text: String, owner: String? = nil) {
        self.label = label
        self.text = text
        self.owner = owner
    }
}

public enum SetAssumptionResponse: Equatable, Sendable {
    case recorded
    case noLabel
    case noText

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .noLabel: message = "An assumption needs a label."
        case .noText: message = "An assumption needs to say something."
        }
    }
}

/// Writes down a fact the team accepts without proof.
///
/// Language guide section 4.2. The label names it, so writing the same label
/// again changes what is there rather than adding a second. The report gives
/// every assumption a section, which is why one that says nothing is refused.
public struct SetAssumption: SetAssumptionUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetAssumptionRequest) -> SetAssumptionResponse {
        let label = request.label.trimmingWhitespace()
        let text = request.text.trimmingWhitespace()
        let owner = request.owner?.trimmingWhitespace()

        guard label.isEmpty == false else { return .noLabel }
        guard text.isEmpty == false else { return .noText }

        return models.mutate(label: ChangeLabel.setAssumption) { model in
            let written = SystemAssumption(
                label: label,
                text: text,
                owner: owner?.isEmpty == true ? nil : owner
            )
            if let already = model.assumptions.firstIndex(where: { $0.label == label }) {
                model.assumptions[already] = written
            } else {
                model.assumptions.append(written)
            }
            return .recorded
        }
    }
}

public protocol RemoveAssumptionUseCase {
    func execute(_ request: RemoveAssumptionRequest) -> RemoveAssumptionResponse
}

public struct RemoveAssumptionRequest: Equatable, Sendable {
    public let label: String

    public init(label: String) {
        self.label = label
    }
}

public enum RemoveAssumptionResponse: Equatable, Sendable {
    case removed
    case noSuchAssumption

    public func describe(into message: inout String?) {
        switch self {
        case .removed: message = nil
        case .noSuchAssumption: message = "This system holds no such assumption."
        }
    }
}

/// Takes an assumption off the system. A `mitigates` edge may name one in
/// `blocked_by`, and the edge keeps that name: the language reads it, and a
/// person deciding to drop an assumption is not deciding to drop the edges
/// that waited on it.
public struct RemoveAssumption: RemoveAssumptionUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveAssumptionRequest) -> RemoveAssumptionResponse {
        let label = request.label.trimmingWhitespace()

        return models.mutate(label: ChangeLabel.setAssumption) { model in
            guard let found = model.assumptions.firstIndex(where: { $0.label == label }) else {
                return .noSuchAssumption
            }
            model.assumptions.remove(at: found)
            return .removed
        }
    }
}
