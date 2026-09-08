public protocol RecordControlImplementedUseCase {
    func execute(_ request: RecordControlImplementedRequest) -> RecordControlImplementedResponse
}

public struct RecordControlImplementedRequest: Equatable, Sendable {
    /// A key `AssessThreatModel` handed out.
    public let controlKey: String

    public init(controlKey: String) {
        self.controlKey = controlKey
    }
}

public enum RecordControlImplementedResponse: Equatable, Sendable {
    case recorded
}

/// Records that a control is in place.
///
/// Idempotent, and it cannot fail: the key came from the assessment, and
/// recording something twice is recording it once. Spec section 5.3 gives a
/// control no scoring rule, so this changes no score.
public struct RecordControlImplemented: RecordControlImplementedUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RecordControlImplementedRequest) -> RecordControlImplementedResponse {
        return models.mutate { model in
            model.implementedControls.insert(ControlKey(request.controlKey))
            return .recorded
        }
    }
}
