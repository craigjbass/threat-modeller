public protocol RecordControlNotImplementedUseCase {
    func execute(_ request: RecordControlNotImplementedRequest) -> RecordControlNotImplementedResponse
}

public struct RecordControlNotImplementedRequest: Equatable, Sendable {
    public let controlKey: String

    public init(controlKey: String) {
        self.controlKey = controlKey
    }
}

public enum RecordControlNotImplementedResponse: Equatable, Sendable {
    case recorded
}

/// Records that a control is not in place.
///
/// Idempotent, and it cannot fail: taking out something never recorded leaves
/// the model as it was.
public struct RecordControlNotImplemented: RecordControlNotImplementedUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(
        _ request: RecordControlNotImplementedRequest
    ) -> RecordControlNotImplementedResponse {
        var model = models.current()
        model.implementedControls.remove(ControlKey(request.controlKey))
        models.save(model)

        return .recorded
    }
}
