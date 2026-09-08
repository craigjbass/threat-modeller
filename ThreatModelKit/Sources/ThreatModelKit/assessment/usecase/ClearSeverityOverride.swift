public protocol ClearSeverityOverrideUseCase {
    func execute(_ request: ClearSeverityOverrideRequest) -> ClearSeverityOverrideResponse
}

public struct ClearSeverityOverrideRequest: Equatable, Sendable {
    public let overrideKey: String

    public init(overrideKey: String) {
        self.overrideKey = overrideKey
    }
}

public enum ClearSeverityOverrideResponse: Equatable, Sendable {
    case cleared
    case noOverride
}

/// Puts a threat back to the severity the catalogue gives it.
public struct ClearSeverityOverride: ClearSeverityOverrideUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: ClearSeverityOverrideRequest) -> ClearSeverityOverrideResponse {
        let key = SeverityOverrideKey(request.overrideKey)

        var model = models.current()
        guard model.severityOverrides[key] != nil else { return .noOverride }

        model.severityOverrides[key] = nil
        models.save(model)

        return .cleared
    }
}
