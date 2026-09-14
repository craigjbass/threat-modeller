public protocol ApplyPolicyUseCase {
    func execute(_ request: ApplyPolicyRequest) -> ApplyPolicyResponse
}

public struct ApplyPolicyRequest: Equatable, Sendable {
    public let text: String

    public init(text: String) {
        self.text = text
    }
}

public enum ApplyPolicyResponse: Equatable, Sendable {
    case applied(rules: Int)
    case refused(diagnostics: [Diagnostic])
}

/// Puts the rules a project states for itself onto the model.
///
/// The report reads them and says whether this system keeps each one, so a
/// reader sees what the team enforces and not only what it failed.
public struct ApplyPolicy: ApplyPolicyUseCase {
    private let models: ThreatModelGateway
    private let sources: PolicySourceGateway

    public init(models: ThreatModelGateway, sources: PolicySourceGateway) {
        self.models = models
        self.sources = sources
    }

    public func execute(_ request: ApplyPolicyRequest) -> ApplyPolicyResponse {
        let read = sources.read(request.text)
        guard let policy = read.source, read.hasErrors == false else {
            return .refused(diagnostics: read.diagnostics)
        }

        return models.mutate(label: ChangeLabel.applyAnswers) { model in
            model.policy = policy
            return .applied(rules: policy.inForce.count)
        }
    }
}
