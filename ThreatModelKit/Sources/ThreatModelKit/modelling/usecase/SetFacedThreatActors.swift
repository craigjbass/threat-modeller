public protocol SetFacedThreatActorsUseCase {
    func execute(_ request: SetFacedThreatActorsRequest) -> SetFacedThreatActorsResponse
}

public struct SetFacedThreatActorsRequest: Equatable, Sendable {
    /// The whole list, in the order the file states it. Writing it again
    /// replaces the list that is there.
    public let actorIds: [String]

    public init(actorIds: [String]) {
        self.actorIds = actorIds
    }
}

public enum SetFacedThreatActorsResponse: Equatable, Sendable {
    case recorded
    case unknownActor(String)

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .unknownActor(let id):
            message = "This project holds no threat actor called \"\(id)\"."
        }
    }
}

/// States which threat actors this system faces.
///
/// Threat actors design section 3.2. The list sets the likelihood of every
/// threat at once, so it is the widest line in the architecture file.
///
/// WARNING: an id nothing holds is refused. The parser states the same fault
/// as an error that stops the project opening, so the window must never write
/// a `faces` entry the next open refuses.
public struct SetFacedThreatActors: SetFacedThreatActorsUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: SetFacedThreatActorsRequest) -> SetFacedThreatActorsResponse {
        var seen = Set<String>()
        let wanted = request.actorIds
            .map { $0.trimmingWhitespace() }
            .filter { $0.isEmpty == false && seen.insert($0).inserted }

        let lookup = ThreatActorLookup(model: models.current(), catalogue: catalogue)
        for id in wanted where lookup.findById(ThreatActorId(id)) == nil {
            return .unknownActor(id)
        }

        return models.mutate(label: ChangeLabel.setFacedThreatActors) { model in
            model.facedActorIds = wanted
            return .recorded
        }
    }
}
