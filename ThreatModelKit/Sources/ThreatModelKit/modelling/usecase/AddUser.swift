public protocol AddUserUseCase {
    func execute(_ request: AddUserRequest) -> AddUserResponse
}

public struct AddUserRequest: Equatable, Sendable {
    public let x: Double
    public let y: Double

    public init(x: Double, y: Double) {
        self.x = x
        self.y = y
    }
}

public enum AddUserResponse: Equatable, Sendable {
    case added(componentId: String)
}

/// Puts a user on the diagram: a human with no technology, named User, with
/// no role, `user` access, no reaches and no threat actor. The user block
/// design states it. The save writes a `user` block and no `component`
/// block.
public struct AddUser: AddUserUseCase {
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator

    public init(models: ThreatModelGateway, ids: IdentityGenerator) {
        self.models = models
        self.ids = ids
    }

    public func execute(_ request: AddUserRequest) -> AddUserResponse {
        let user = Component(
            id: ComponentId(ids.next()),
            technologyId: Component.userTechnologyId,
            position: Point(x: request.x, y: request.y),
            sensitivity: .internalData,
            customName: Component.userDefaultName,
            statesOwnSensitivity: false,
            user: UserFacts()
        )

        return models.mutate(label: ChangeLabel.addUser) { model in
            model.components.append(user)
            return .added(componentId: user.id.value)
        }
    }
}
