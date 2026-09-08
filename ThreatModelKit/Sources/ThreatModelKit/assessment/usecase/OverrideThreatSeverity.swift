public protocol OverrideThreatSeverityUseCase {
    func execute(_ request: OverrideThreatSeverityRequest) -> OverrideThreatSeverityResponse
}

public struct OverrideThreatSeverityRequest: Equatable, Sendable {
    /// A key `AssessThreatModel` handed out. The core mints every key, so a
    /// delivery mechanism only ever echoes one it was given.
    public let overrideKey: String
    public let severityId: String

    public init(overrideKey: String, severityId: String) {
        self.overrideKey = overrideKey
        self.severityId = severityId
    }
}

public enum OverrideThreatSeverityResponse: Equatable, Sendable {
    case overridden
    case unknownSeverity
}

/// Records the severity the user judges a threat to carry on their system.
///
/// WARNING: spec section 5.3 keys a component threat by its technology, so one
/// override applies to every component of that technology, and a link or zone
/// override applies to every link or every zone. The key comes from the
/// response, so this use case simply records what it is given.
public struct OverrideThreatSeverity: OverrideThreatSeverityUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: OverrideThreatSeverityRequest) -> OverrideThreatSeverityResponse {
        guard catalogue.taxonomy().severity(id: request.severityId) != nil else {
            return .unknownSeverity
        }

        var model = models.current()
        model.severityOverrides[SeverityOverrideKey(request.overrideKey)] = request.severityId
        models.save(model)

        return .overridden
    }
}
