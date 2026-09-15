public protocol SetSystemUseCaseUseCase {
    func execute(_ request: SetSystemUseCaseRequest) -> SetSystemUseCaseResponse
}

public struct SetSystemUseCaseRequest: Equatable, Sendable {
    /// Names the use case. Writing the same label again changes the one that
    /// is there.
    public let label: String
    public let text: String

    public init(label: String, text: String) {
        self.label = label
        self.text = text
    }
}

public enum SetSystemUseCaseResponse: Equatable, Sendable {
    case recorded
    case noLabel
    case noText

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .noLabel: message = "A use case needs a label."
        case .noText: message = "A use case needs to say what a person does."
        }
    }
}

/// Writes down what a person does with the system.
///
/// Language guide section 4.2. The label names it, so writing the same label
/// again changes what is there rather than adding a second.
public struct SetSystemUseCase: SetSystemUseCaseUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetSystemUseCaseRequest) -> SetSystemUseCaseResponse {
        let label = request.label.trimmingWhitespace()
        let text = request.text.trimmingWhitespace()

        guard label.isEmpty == false else { return .noLabel }
        guard text.isEmpty == false else { return .noText }

        return models.mutate(label: ChangeLabel.setUseCase) { model in
            let written = SystemUseCase(label: label, text: text)
            if let already = model.useCases.firstIndex(where: { $0.label == label }) {
                model.useCases[already] = written
            } else {
                model.useCases.append(written)
            }
            return .recorded
        }
    }
}

public protocol RemoveSystemUseCaseUseCase {
    func execute(_ request: RemoveSystemUseCaseRequest) -> RemoveSystemUseCaseResponse
}

public struct RemoveSystemUseCaseRequest: Equatable, Sendable {
    public let label: String

    public init(label: String) {
        self.label = label
    }
}

public enum RemoveSystemUseCaseResponse: Equatable, Sendable {
    case removed
    case noSuchUseCase

    public func describe(into message: inout String?) {
        switch self {
        case .removed: message = nil
        case .noSuchUseCase: message = "This system holds no such use case."
        }
    }
}

/// Takes a use case off the system.
public struct RemoveSystemUseCase: RemoveSystemUseCaseUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveSystemUseCaseRequest) -> RemoveSystemUseCaseResponse {
        let label = request.label.trimmingWhitespace()

        return models.mutate(label: ChangeLabel.removeUseCase) { model in
            guard let found = model.useCases.firstIndex(where: { $0.label == label }) else {
                return .noSuchUseCase
            }
            model.useCases.remove(at: found)
            return .removed
        }
    }
}
