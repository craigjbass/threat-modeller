public protocol ConfigurePathwayMitigationsUseCase {
    func execute(_ request: ConfigurePathwayMitigationsRequest) -> ConfigurePathwayMitigationsResponse
}

public struct ConfigurePathwayMitigationsRequest: Equatable, Sendable {
    public let isMasterEnabled: Bool
    /// Nil to set only the master toggle. Otherwise the mitigation to set, and
    /// the three values below apply to it.
    public let mitigationId: String?
    public let isEnabled: Bool
    public let mode: String
    /// 0 to 100 inclusive.
    public let reductionPercent: Int

    public init(
        isMasterEnabled: Bool,
        mitigationId: String?,
        isEnabled: Bool,
        mode: String,
        reductionPercent: Int
    ) {
        self.isMasterEnabled = isMasterEnabled
        self.mitigationId = mitigationId
        self.isEnabled = isEnabled
        self.mode = mode
        self.reductionPercent = reductionPercent
    }
}

public enum ConfigurePathwayMitigationsResponse: Equatable, Sendable {
    case configured
    case unknownMitigation
    case unknownMode
    case reductionOutOfRange
}

/// Sets the master toggle, and one mitigation at a time.
///
/// All or nothing: one bad value leaves every setting as it was, so a rejected
/// form never half-applies. Turning the master toggle off keeps the
/// per-mitigation settings, so turning it back on restores what the user had.
public struct ConfigurePathwayMitigations: ConfigurePathwayMitigationsUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(
        _ request: ConfigurePathwayMitigationsRequest
    ) -> ConfigurePathwayMitigationsResponse {
        var model = models.current()

        if let rawId = request.mitigationId {
            let id = PathwayMitigationId(rawId)
            guard catalogue.pathwayMitigations().contains(where: { $0.id == id }) else {
                return .unknownMitigation
            }
            guard let mode = PathwayMitigationMode(rawValue: request.mode) else {
                return .unknownMode
            }
            guard (0...100).contains(request.reductionPercent) else {
                return .reductionOutOfRange
            }

            model.pathwayMitigations.configs[id] = PathwayMitigationConfig(
                isEnabled: request.isEnabled,
                mode: mode,
                reductionPercent: request.reductionPercent
            )
        }

        model.pathwayMitigations.isMasterEnabled = request.isMasterEnabled
        models.save(model)

        return .configured
    }
}
