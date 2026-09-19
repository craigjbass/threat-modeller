public protocol SetUserPropertiesUseCase {
    func execute(_ request: SetUserPropertiesRequest) -> SetUserPropertiesResponse
}

public struct SetUserPropertiesRequest: Equatable, Sendable {
    public let componentId: String
    /// What the user is called, or nil to go back to the id. An empty name is
    /// the same as nil.
    public let name: String?
    /// What the person does with the system. Empty states none.
    public let role: String
    /// The privilege the user holds: user, admin, root, system or kernel.
    public let access: String
    /// The component ids of the clients the user holds.
    public let uses: [String]
    /// The component ids the user reaches.
    public let reaches: [String]
    /// The threat actor this user is, or nil.
    public let threatActorId: String?
    /// True to write the user as an adversary, false to write a legitimate
    /// user.
    public let isAdversary: Bool
    /// The id of the clearance this user holds, or nil.
    public let clearanceId: String?

    public init(
        componentId: String,
        name: String?,
        role: String,
        access: String,
        uses: [String] = [],
        reaches: [String],
        threatActorId: String?,
        isAdversary: Bool = false,
        clearanceId: String? = nil
    ) {
        self.clearanceId = clearanceId
        self.componentId = componentId
        self.name = name
        self.role = role
        self.access = access
        self.uses = uses
        self.reaches = reaches
        self.threatActorId = threatActorId
        self.isAdversary = isAdversary
    }
}

public enum SetUserPropertiesResponse: Equatable, Sendable {
    case updated
    case unknownUser
    case unknownAccessLevel
    /// A reach or a client names no component of this model, or names a
    /// user.
    case unknownComponent(String)
    /// The threat actor names nothing this project holds.
    case unknownActor(String)
    /// The clearance names nothing this system declares.
    case unknownClearance(String)
}

/// Changes what a user is called, what the user does, what privilege the user
/// holds, what the user reaches, which threat actor the user is, and whether
/// the user is an adversary.
///
/// One use case for all five, the way `SetComponentProperties` does it: the
/// panel writes what a person sees, and the model takes it or refuses it
/// whole.
///
/// WARNING: a reach naming nothing and an actor nothing holds are refused,
/// because the parser refuses both as errors that stop the project opening,
/// and the window must never write a file the next open refuses.
public struct SetUserProperties: SetUserPropertiesUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: SetUserPropertiesRequest) -> SetUserPropertiesResponse {
        let componentId = ComponentId(request.componentId)
        guard let access = PrivilegeLevel(rawValue: request.access) else {
            return .unknownAccessLevel
        }
        let name = request.name?.trimmingWhitespace() ?? ""
        let role = request.role.trimmingWhitespace()
        let actorId = request.threatActorId?.trimmingWhitespace()

        let model = models.current()
        guard let index = model.components.firstIndex(where: { $0.id == componentId }),
              model.components[index].isUser else {
            return .unknownUser
        }
        let reachable = Set(model.components.filter { $0.isUser == false }.map(\.id.value))
        var seen: Set<String> = []
        let reaches = request.reaches.filter { seen.insert($0).inserted }
        for reached in reaches where reachable.contains(reached) == false {
            return .unknownComponent(reached)
        }
        var held: Set<String> = []
        let uses = request.uses.filter { held.insert($0).inserted }
        for client in uses where reachable.contains(client) == false {
            return .unknownComponent(client)
        }
        let clearanceId = request.clearanceId?.trimmingWhitespace()
        if let clearanceId, clearanceId.isEmpty == false,
           model.clearances.contains(where: { $0.id == clearanceId }) == false {
            return .unknownClearance(clearanceId)
        }
        if let actorId, actorId.isEmpty == false {
            let lookup = ThreatActorLookup(model: model, catalogue: catalogue)
            guard lookup.findById(ThreatActorId(actorId)) != nil else {
                return .unknownActor(actorId)
            }
        }

        return models.mutate(label: ChangeLabel.setUserProperties) { model in
            guard let index = model.components.firstIndex(where: { $0.id == componentId }) else {
                return .unknownUser
            }
            model.components[index].customName = name.isEmpty ? nil : name
            model.components[index].runsAs = access
            model.components[index].user = UserFacts(
                role: role,
                uses: uses,
                reaches: reaches,
                threatActorId: (actorId?.isEmpty ?? true) ? nil : actorId,
                isAdversary: request.isAdversary,
                clearanceId: (clearanceId?.isEmpty ?? true) ? nil : clearanceId
            )
            return .updated
        }
    }
}
