public protocol SetClearanceUseCase {
    func execute(_ request: SetClearanceRequest) -> SetClearanceResponse
}

public struct SetClearanceRequest: Equatable, Sendable {
    /// Names the clearance. Writing the same id again changes the block that
    /// is there.
    public let id: String
    public let name: String
    public let description: String
    /// 0 to 100.
    public let reducesInsiderRiskBy: Int
    public let rationale: String
    public let sources: [String]

    public init(
        id: String,
        name: String,
        description: String = "",
        reducesInsiderRiskBy: Int,
        rationale: String,
        sources: [String] = []
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.reducesInsiderRiskBy = reducesInsiderRiskBy
        self.rationale = rationale
        self.sources = sources
    }
}

public enum SetClearanceResponse: Equatable, Sendable {
    case recorded
    case noId
    case noName
    case noRationale
    case reductionOutOfRange

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .noId: message = "A clearance needs an identifier."
        case .noName: message = "A clearance needs a name."
        case .noRationale:
            message = "A clearance needs a rationale: a reduction nobody can justify is not one."
        case .reductionOutOfRange:
            message = "A clearance reduces insider risk by 0 to 100 percent."
        }
    }
}

/// Writes one `clearance` block into this system's architecture file.
///
/// Issue #259. The team writing the model defines the levels, so the
/// application checks the shape of a level and never its words.
public struct SetClearance: SetClearanceUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetClearanceRequest) -> SetClearanceResponse {
        let id = request.id.trimmingWhitespace()
        let name = request.name.trimmingWhitespace()
        let rationale = request.rationale.trimmingWhitespace()

        guard id.isEmpty == false else { return .noId }
        guard name.isEmpty == false else { return .noName }
        guard rationale.isEmpty == false else { return .noRationale }
        guard (0...Clearance.widestReduction).contains(request.reducesInsiderRiskBy) else {
            return .reductionOutOfRange
        }

        return models.mutate(label: ChangeLabel.setClearance) { model in
            let written = Clearance(
                id: id,
                name: name,
                description: request.description.trimmingWhitespace(),
                reducesInsiderRiskBy: request.reducesInsiderRiskBy,
                rationale: rationale,
                sources: request.sources
                    .map { $0.trimmingWhitespace() }
                    .filter { $0.isEmpty == false }
            )
            if let already = model.clearances.firstIndex(where: { $0.id == written.id }) {
                model.clearances[already] = written
            } else {
                model.clearances.append(written)
            }
            return .recorded
        }
    }
}

public protocol RemoveClearanceUseCase {
    func execute(_ request: RemoveClearanceRequest) -> RemoveClearanceResponse
}

public struct RemoveClearanceRequest: Equatable, Sendable {
    public let id: String

    public init(id: String) {
        self.id = id
    }
}

public enum RemoveClearanceResponse: Equatable, Sendable {
    case removed
    case noSuchClearance

    public func describe(into message: inout String?) {
        switch self {
        case .removed: message = nil
        case .noSuchClearance: message = "This system declares no such clearance."
        }
    }
}

/// Takes a `clearance` block off this system, and off every user that named
/// it.
///
/// A user left naming a clearance nothing declares is a file the next open
/// refuses, so the user loses the attribute in the same change.
public struct RemoveClearance: RemoveClearanceUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveClearanceRequest) -> RemoveClearanceResponse {
        let id = request.id.trimmingWhitespace()

        return models.mutate(label: ChangeLabel.removeClearance) { model in
            guard let found = model.clearances.firstIndex(where: { $0.id == id }) else {
                return .noSuchClearance
            }
            model.clearances.remove(at: found)
            for index in model.components.indices
            where model.components[index].user?.clearanceId == id {
                model.components[index].user?.clearanceId = nil
            }
            return .removed
        }
    }
}
